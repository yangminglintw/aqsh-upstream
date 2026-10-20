package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type RenewalConfig struct {
	Namespace      string        `yaml:"namespace"`
	ServiceAccount string        `yaml:"service_account"`
	Audiences      []string      `yaml:"audiences"`
	TokenDuration  time.Duration `yaml:"token_duration"`
	RenewBefore    time.Duration `yaml:"renew_before"`
}

// Persistence requires an existing Secret. No Secret creation or broad list/watch
// permission is needed; only get/patch on this one configured resource.
type PersistenceConfig struct {
	APIServer string `yaml:"api_server"`
	CAFile    string `yaml:"ca_file"`
	TokenFile string `yaml:"token_file"`
	Namespace string `yaml:"namespace"`
	Secret    string `yaml:"secret"`
}

type tokenSource struct {
	mu      sync.RWMutex
	path    string
	managed string
}

func (s *tokenSource) token() (string, error) {
	s.mu.RLock()
	token := s.managed
	s.mu.RUnlock()
	if token != "" {
		return token, nil
	}
	return readToken(s.path)
}

func (s *tokenSource) set(token string) { s.mu.Lock(); s.managed = token; s.mu.Unlock() }

type credentialManager struct {
	interval time.Duration
	storage  *cluster
	path     string
	cancel   context.CancelFunc
	done     chan struct{}
}

// Start loads opt-in persisted credentials before serving requests, then manages
// renewal under the API lifetime. Mounted-only mode starts no background loop.
func (k *Kubernetes) Start(ctx context.Context) error {
	m := k.credentials
	if m == nil {
		return nil
	}
	if m.done != nil {
		return fmt.Errorf("credential manager already started")
	}
	if m.storage != nil {
		loadCtx, cancel := context.WithTimeout(ctx, k.timeout)
		err := k.loadPersisted(loadCtx)
		cancel()
		if err != nil {
			return fmt.Errorf("loading reviewer credentials: %w", err)
		}
	}
	ctx, m.cancel = context.WithCancel(ctx)
	m.done = make(chan struct{})
	go func() {
		defer close(m.done)
		k.renewCredentials(ctx)
		ticker := time.NewTicker(m.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				k.renewCredentials(ctx)
			}
		}
	}()
	return nil
}

func (k *Kubernetes) renewCredentials(ctx context.Context) {
	for _, c := range k.clusters {
		if c.config.Renewal == nil {
			continue
		}
		if ctx.Err() != nil {
			return
		}
		callCtx, cancel := context.WithTimeout(ctx, k.timeout)
		err := k.renewCredential(callCtx, c)
		cancel()
		if err != nil && ctx.Err() == nil {
			slog.Warn("reviewer credential renewal failed", "cluster", c.id, "error", err)
		}
	}
}

func (k *Kubernetes) renewCredential(ctx context.Context, c *cluster) error {
	r := c.config.Renewal
	current, err := c.tokens.token()
	if err != nil {
		return ErrUnavailable
	}
	expiry := tokenExpiry(current)
	if !expiry.IsZero() && time.Until(expiry) > r.RenewBefore {
		return nil
	}
	var request struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Spec       struct {
			Audiences         []string `json:"audiences"`
			ExpirationSeconds int64    `json:"expirationSeconds"`
		} `json:"spec"`
	}
	request.APIVersion, request.Kind = "authentication.k8s.io/v1", "TokenRequest"
	request.Spec.Audiences, request.Spec.ExpirationSeconds = r.Audiences, int64(r.TokenDuration/time.Second)
	body, _ := json.Marshal(request)
	path := "/api/v1/namespaces/" + url.PathEscape(r.Namespace) + "/serviceaccounts/" + url.PathEscape(r.ServiceAccount) + "/token"
	data, err := c.call(ctx, "POST", path, "application/json", body, current)
	if err != nil {
		// A rotated bootstrap file can recover an expired persisted reviewer token.
		bootstrap, readErr := readToken(c.config.TokenFile)
		if readErr != nil || bootstrap == current {
			return ErrUnavailable
		}
		data, err = c.call(ctx, "POST", path, "application/json", body, bootstrap)
		if err != nil {
			return ErrUnavailable
		}
	}
	var response struct {
		Status struct {
			Token               string    `json:"token"`
			ExpirationTimestamp time.Time `json:"expirationTimestamp"`
		} `json:"status"`
	}
	if json.Unmarshal(data, &response) != nil || !time.Now().Before(response.Status.ExpirationTimestamp) || !validManagedToken(response.Status.Token, r) {
		return ErrUnavailable
	}
	// Persist before adopting the token. A failed write is retried next cycle and
	// never overwrites an otherwise working in-memory snapshot.
	if k.credentials.storage != nil {
		payload, _ := json.Marshal(map[string]any{"data": map[string]string{c.id + "-token": base64.StdEncoding.EncodeToString([]byte(response.Status.Token))}})
		storage := k.credentials.storage
		token, err := storage.tokens.token()
		if err != nil {
			return ErrUnavailable
		}
		if _, err := storage.call(ctx, "PATCH", k.credentials.path, "application/merge-patch+json", payload, token); err != nil {
			return ErrUnavailable
		}
	}
	c.tokens.set(response.Status.Token)
	slog.Info("reviewer credential renewed", "cluster", c.id, "expires", response.Status.ExpirationTimestamp)
	return nil
}

func validManagedToken(token string, r *RenewalConfig) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var claims struct {
		Subject    string `json:"sub"`
		Kubernetes struct {
			Pod json.RawMessage `json:"pod"`
		} `json:"kubernetes.io"`
	}
	if json.Unmarshal(payload, &claims) != nil || claims.Subject != "system:serviceaccount:"+r.Namespace+":"+r.ServiceAccount || len(claims.Kubernetes.Pod) != 0 {
		return false
	}
	expiry := tokenExpiry(token)
	return !expiry.IsZero() && time.Now().Before(expiry) && !strings.ContainsAny(token, "\r\n \t")
}

func (k *Kubernetes) loadPersisted(ctx context.Context) error {
	m := k.credentials
	token, err := m.storage.tokens.token()
	if err != nil {
		return ErrUnavailable
	}
	data, err := m.storage.call(ctx, "GET", m.path, "", nil, token)
	if err != nil {
		return ErrUnavailable
	}
	var secret struct {
		Data map[string][]byte `json:"data"`
	}
	if json.Unmarshal(data, &secret) != nil {
		return ErrUnavailable
	}
	for _, c := range k.clusters {
		if c.config.Renewal == nil {
			continue
		}
		token := string(secret.Data[c.id+"-token"])
		// Ignore expired/foreign/pod-bound tokens and use the mounted bootstrap.
		if validManagedToken(token, c.config.Renewal) {
			c.tokens.set(token)
		}
	}
	return nil
}

func (c *cluster) call(ctx context.Context, method, path, contentType string, body []byte, token string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.config.APIServer, "/")+path, bytes.NewReader(body))
	if err != nil {
		return nil, ErrUnavailable
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, ErrUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return nil, ErrUnavailable
	}
	return data, nil
}
