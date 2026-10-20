package auth

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/go-jose/go-jose/v4"
	"io"
	"net/http"
	"os"
	"slices"
	"sort"
	"strings"
	"time"
)

type Kubernetes struct {
	clusters    []*cluster
	audiences   []string
	audienceKey string
	timeout     time.Duration
	cache       *reviewCache
}

type cluster struct {
	id     string
	config ClusterConfig
	client *http.Client
	keys   *keyCache
}

type tokenReview struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Spec       struct {
		Token     string   `json:"token"`
		Audiences []string `json:"audiences"`
	} `json:"spec"`
	Status struct {
		Authenticated bool     `json:"authenticated"`
		Audiences     []string `json:"audiences"`
		User          userInfo `json:"user"`
		Error         string   `json:"error"`
	} `json:"status,omitempty"`
}

type userInfo struct {
	Username string   `json:"username"`
	UID      string   `json:"uid"`
	Groups   []string `json:"groups"`
}

func New(cfg Config) (*Kubernetes, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	k := &Kubernetes{audiences: append([]string(nil), cfg.Audiences...), timeout: cfg.RequestTimeout, cache: newReviewCache(cfg.CacheSize, cfg.CacheTTL)}
	sort.Strings(k.audiences)
	key, _ := json.Marshal(k.audiences)
	k.audienceKey = string(key)
	ids := make([]string, 0, len(cfg.Clusters))
	for id := range cfg.Clusters {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		cc := cfg.Clusters[id]
		client, err := newClient(cc.CAFile, cfg)
		if err != nil {
			k.Close()
			return nil, fmt.Errorf("cluster %q: %w", id, err)
		}
		if _, err := readToken(cc.TokenFile); err != nil {
			client.CloseIdleConnections()
			k.Close()
			return nil, fmt.Errorf("cluster %q: %w", id, err)
		}
		k.clusters = append(k.clusters, &cluster{id: id, config: cc, client: client, keys: &keyCache{}})
	}
	return k, nil
}

func newClient(caFile string, cfg Config) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		ca, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("reading CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return nil, fmt.Errorf("invalid CA certificate")
		}
		transport.TLSClientConfig.RootCAs = pool
	}
	return &http.Client{
		Transport: transport,
		Timeout:   cfg.RequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

func readToken(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading reviewer token: %w", err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" || strings.ContainsAny(token, "\r\n \t") {
		return "", fmt.Errorf("empty or malformed reviewer token")
	}
	return token, nil
}

func (k *Kubernetes) Authenticate(ctx context.Context, token string) (Principal, error) {
	ctx, cancel := context.WithTimeout(ctx, k.timeout)
	defer cancel()
	c, expiry, err := k.route(ctx, token)
	if err != nil {
		return Principal{}, err
	}
	key := reviewKey{Cluster: c.id, Token: tokenHash(token), Audiences: k.audienceKey}
	if p, ok := k.cache.get(key); ok {
		return p, nil
	}
	p, err := k.review(ctx, c, token)
	if err == nil {
		k.cache.put(key, p, expiry)
	}
	return p, err
}

func (k *Kubernetes) review(ctx context.Context, c *cluster, token string) (Principal, error) {
	reviewer, err := readToken(c.config.TokenFile)
	if err != nil {
		return Principal{}, ErrUnavailable
	}
	tr := tokenReview{APIVersion: "authentication.k8s.io/v1", Kind: "TokenReview"}
	tr.Spec.Token, tr.Spec.Audiences = token, k.audiences
	body, _ := json.Marshal(tr)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.config.APIServer, "/")+"/apis/authentication.k8s.io/v1/tokenreviews", bytes.NewReader(body))
	if err != nil {
		return Principal{}, ErrUnavailable
	}
	req.Header.Set("Authorization", "Bearer "+reviewer)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return Principal{}, ErrUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Principal{}, ErrUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	var result tokenReview
	if err != nil || len(data) > 1<<20 || json.Unmarshal(data, &result) != nil {
		return Principal{}, ErrUnavailable
	}
	status := result.Status
	// Existing task environments and values_url represent groups as CSV. Reject
	// ambiguous names rather than turn one verified group into multiple groups.
	for _, group := range status.User.Groups {
		if group == "" || strings.TrimSpace(group) != group || strings.ContainsAny(group, ",\r\n") {
			return Principal{}, ErrUnauthenticated
		}
	}
	if !status.Authenticated || status.Error != "" || status.User.Username == "" || status.User.UID == "" {
		return Principal{}, ErrUnauthenticated
	}
	if !slices.ContainsFunc(status.Audiences, func(a string) bool { return slices.Contains(k.audiences, a) }) {
		return Principal{}, ErrUnauthenticated
	}
	return Principal{Provider: "kubernetes", Cluster: c.id, Username: status.User.Username, UID: status.User.UID, Groups: status.User.Groups}, nil
}

func (k *Kubernetes) Close() {
	for _, c := range k.clusters {
		c.client.CloseIdleConnections()
	}
}

func (k *Kubernetes) route(ctx context.Context, token string) (*cluster, time.Time, error) {
	if len(k.clusters) == 1 && k.clusters[0].config.JWKSURL == "" {
		return k.clusters[0], tokenExpiry(token), nil
	}
	jws, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256, jose.ES256, jose.ES384, jose.ES512, jose.EdDSA})
	if err != nil || len(jws.Signatures) != 1 {
		return nil, time.Time{}, ErrUnauthenticated
	}
	var matched *cluster
	var expiry time.Time
	unavailable := false
	for _, c := range k.clusters {
		payload, err := c.verify(ctx, jws)
		if err != nil {
			unavailable = true
			continue
		}
		if payload == nil {
			continue
		}
		exp, valid := validTimes(payload, time.Now())
		if !valid || matched != nil {
			return nil, time.Time{}, ErrUnauthenticated
		}
		matched, expiry = c, exp
	}
	if unavailable {
		return nil, time.Time{}, ErrUnavailable
	}
	if matched == nil {
		return nil, time.Time{}, ErrUnauthenticated
	}
	return matched, expiry, nil
}
