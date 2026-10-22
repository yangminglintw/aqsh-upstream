package credentials

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/rophy/aqsh/internal/kubefederatedauth/config"
)

// VerifierInvalidator is an interface for invalidating cached verifiers
type VerifierInvalidator interface {
	InvalidateVerifier(clusterName string)
}

// tokenSource indicates where a token came from, which determines renewal behavior.
type tokenSource int

const (
	tokenMounted   tokenSource = iota // from file, renewed by re-reading
	tokenPersisted                    // from Secret/renewal, renewed by TokenRequest
)

// Credentials holds the token and CA certificate for a cluster
type Credentials struct {
	Token  string
	CACert []byte
	source tokenSource
}

// clientFactory creates a Kubernetes client for a remote cluster.
type clientFactory func(cfg config.ClusterConfig, creds *Credentials) (kubernetes.Interface, error)

// Store manages credentials for remote clusters.
// It loads credentials from Kubernetes Secrets and config files,
// handles token renewal, and persists renewed tokens.
type Store struct {
	mu            sync.RWMutex
	credentials   map[string]*Credentials
	config        *config.Config
	client        kubernetes.Interface
	namespace     string
	secretName    string
	verifier      VerifierInvalidator
	newClient     clientFactory
	renewalTotal  *prometheus.CounterVec // optional, nil-safe
	expirySeconds *prometheus.GaugeVec   // optional, nil-safe
}

// SetMetrics sets the optional Prometheus metrics for credential renewal and expiry.
func (s *Store) SetMetrics(renewalTotal *prometheus.CounterVec, expirySeconds *prometheus.GaugeVec) {
	s.renewalTotal = renewalTotal
	s.expirySeconds = expirySeconds
}

// NewStore creates a credential store and loads all credentials:
// 1. Try to create an in-cluster K8s client
// 2. Load persisted tokens from Kubernetes Secret
// 3. Load CA certs and bootstrap tokens from config files
func NewStore(cfg *config.Config, secretName string) (*Store, error) {
	s := &Store{
		credentials: make(map[string]*Credentials),
		config:      cfg,
		secretName:  secretName,
	}
	s.newClient = s.createClient

	// Try to create in-cluster client
	restConfig, err := rest.InClusterConfig()
	if err != nil {
		slog.Info("not running in cluster, credentials will not be persisted", "error", err)
	} else {
		client, err := kubernetes.NewForConfig(restConfig)
		if err != nil {
			slog.Warn("failed to create kubernetes client, credentials will not be persisted", "error", err)
		} else {
			s.client = client
			s.namespace = detectNamespace()
		}
	}

	// Load persisted tokens from Secret (takes priority over bootstrap tokens)
	if err := s.loadFromSecret(context.Background()); err != nil {
		slog.Warn("failed to load credentials from secret", "error", err)
	}

	// Load CA certs and bootstrap tokens from config files
	for clusterName, clusterCfg := range cfg.Clusters {
		if clusterCfg.CACert != "" {
			ca, err := os.ReadFile(clusterCfg.CACert)
			if err != nil {
				slog.Warn("could not load CA cert", "cluster", clusterName, "error", err)
			} else {
				s.SetCACert(clusterName, ca)
				slog.Info("loaded CA cert from file", "cluster", clusterName)
			}
		}
		if clusterCfg.TokenPath != "" {
			// Only load bootstrap token if no persisted token exists
			if existing, ok := s.credentials[clusterName]; !ok || existing.Token == "" {
				token, err := os.ReadFile(clusterCfg.TokenPath)
				if err != nil {
					slog.Warn("could not load bootstrap token", "cluster", clusterName, "error", err)
				} else {
					s.SetToken(clusterName, string(token))
					// Mark as mounted since it came from a file
					s.mu.Lock()
					s.credentials[clusterName].source = tokenMounted
					s.mu.Unlock()
					slog.Info("loaded bootstrap token from file", "cluster", clusterName)
				}
			} else {
				slog.Info("token already present, skipping bootstrap", "cluster", clusterName)
			}
		}
	}

	// Fallback: if any cluster still has no token, try the pod's own SA token
	const podTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	for clusterName := range cfg.Clusters {
		if existing, ok := s.credentials[clusterName]; ok && existing.Token != "" {
			continue
		}
		token, err := os.ReadFile(podTokenPath)
		if err != nil {
			slog.Warn("cluster has no credentials and pod token not available",
				"cluster", clusterName, "error", err)
			continue
		}
		slog.Warn("cluster has no credentials, falling back to pod-mounted token",
			"cluster", clusterName)
		s.SetToken(clusterName, string(token))
		s.mu.Lock()
		s.credentials[clusterName].source = tokenMounted
		s.mu.Unlock()
	}

	return s, nil
}

// Get returns credentials for a cluster
func (s *Store) Get(cluster string) (*Credentials, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	creds, ok := s.credentials[cluster]
	return creds, ok
}

// SetToken updates a cluster's token in-memory.
func (s *Store) SetToken(cluster, token string) {
	// Mounted token files may end in a newline; HTTP header values may not.
	token = strings.TrimSpace(token)
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.credentials[cluster]; ok {
		existing.Token = token
	} else {
		s.credentials[cluster] = &Credentials{Token: token}
	}
}

// ClearToken removes a cluster's token from memory, forcing fallback to token_path.
func (s *Store) ClearToken(cluster string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.credentials[cluster]; ok {
		existing.Token = ""
		existing.source = tokenMounted
	}
}

// SetCACert updates a cluster's CA cert in-memory.
func (s *Store) SetCACert(cluster string, caCert []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.credentials[cluster]; ok {
		existing.CACert = caCert
	} else {
		s.credentials[cluster] = &Credentials{CACert: caCert}
	}
}

// Start begins the periodic token renewal loop.
// The verifier is passed here (not the constructor) to avoid circular dependency with server.New.
func (s *Store) Start(ctx context.Context, verifier VerifierInvalidator) {
	s.verifier = verifier
	interval := s.config.GetRenewalInterval()
	slog.Info("starting credential renewal", "interval", interval)
	go s.renewLoop(ctx, interval)
}

func (s *Store) renewLoop(ctx context.Context, interval time.Duration) {
	// Initial renewal
	s.tryRenew(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.tryRenew(ctx)
		case <-ctx.Done():
			slog.Info("stopping credential renewal loop")
			return
		}
	}
}

// tryRenew checks all clusters and renews tokens that need renewal, then saves to Secret.
func (s *Store) tryRenew(ctx context.Context) {
	renewed := false

	for cluster, cfg := range s.config.Clusters {
		s.mu.RLock()
		creds, ok := s.credentials[cluster]
		s.mu.RUnlock()
		if !ok || creds.Token == "" {
			continue
		}

		// Check CA certificate expiration
		checkCACertExpiration(cluster, creds.CACert)

		// Check if token needs renewal
		renewBefore := s.config.GetRenewalRenewBefore()
		if exp, err := getTokenExpiration(creds.Token); err == nil {
			timeUntilExpiry := time.Until(exp)
			if s.expirySeconds != nil {
				s.expirySeconds.WithLabelValues(cluster).Set(timeUntilExpiry.Seconds())
			}
			if timeUntilExpiry > renewBefore {
				slog.Debug("skipping renewal", "cluster", cluster,
					"expires_in", timeUntilExpiry.Round(time.Minute), "threshold", renewBefore)
				continue
			}
			slog.Info("renewing credentials", "cluster", cluster,
				"expires_in", timeUntilExpiry.Round(time.Minute), "threshold", renewBefore)
		} else {
			slog.Info("renewing credentials", "cluster", cluster, "reason", err)
		}

		if err := s.renewToken(ctx, cluster, cfg); err != nil {
			slog.Error("credential renewal failed", "cluster", cluster, "error", err)
			if s.renewalTotal != nil {
				s.renewalTotal.WithLabelValues(cluster, "failure").Inc()
			}
			continue
		}

		if s.renewalTotal != nil {
			s.renewalTotal.WithLabelValues(cluster, "success").Inc()
		}

		renewed = true
		if s.verifier != nil {
			s.verifier.InvalidateVerifier(cluster)
		}
	}

	if renewed {
		if err := s.saveToSecret(ctx); err != nil {
			slog.Error("failed to persist credentials to secret", "error", err)
		}
	}
}

// renewToken refreshes a single cluster's token based on its source.
func (s *Store) renewToken(ctx context.Context, cluster string, cfg config.ClusterConfig) error {
	s.mu.RLock()
	creds := s.credentials[cluster]
	source := creds.source
	s.mu.RUnlock()

	switch source {
	case tokenMounted:
		return s.renewMountedToken(cluster, cfg)
	case tokenPersisted:
		return s.renewPersistedToken(ctx, cluster, cfg, creds)
	default:
		return fmt.Errorf("unknown token source for cluster %s", cluster)
	}
}

// renewMountedToken re-reads the token from the configured file path.
func (s *Store) renewMountedToken(cluster string, cfg config.ClusterConfig) error {
	if cfg.TokenPath == "" {
		return fmt.Errorf("no token_path configured for cluster %s", cluster)
	}

	token, err := os.ReadFile(cfg.TokenPath)
	if err != nil {
		return fmt.Errorf("reading token file: %w", err)
	}

	s.SetToken(cluster, string(token))
	// Keep source as mounted
	s.mu.Lock()
	s.credentials[cluster].source = tokenMounted
	s.mu.Unlock()

	slog.Info("reloaded mounted token from file", "cluster", cluster)
	return nil
}

// renewPersistedToken calls the remote cluster's TokenRequest API to get a fresh token.
func (s *Store) renewPersistedToken(ctx context.Context, cluster string, cfg config.ClusterConfig, creds *Credentials) error {
	if err := s.requestNewToken(ctx, cluster, cfg, creds); err != nil {
		// If renewal failed and bootstrap credentials are available, retry with bootstrap
		if cfg.TokenPath != "" {
			slog.Warn("token renewal failed, retrying with bootstrap", "cluster", cluster, "error", err)
			token, readErr := os.ReadFile(cfg.TokenPath)
			if readErr != nil {
				slog.Error("failed to read bootstrap token", "cluster", cluster, "path", cfg.TokenPath, "error", readErr)
				return fmt.Errorf("requesting token: %w (bootstrap fallback also failed: %v)", err, readErr)
			}

			bootstrapCreds := &Credentials{
				Token:  string(token),
				CACert: creds.CACert,
			}
			if retryErr := s.requestNewToken(ctx, cluster, cfg, bootstrapCreds); retryErr != nil {
				slog.Error("bootstrap token is invalid or expired", "cluster", cluster, "path", cfg.TokenPath, "error", retryErr)
				return fmt.Errorf("requesting token with bootstrap credentials: %w", retryErr)
			}
		} else {
			slog.Error("token renewal failed, set token_path with bootstrap token", "cluster", cluster)
			return fmt.Errorf("requesting token: %w", err)
		}
	}

	return nil
}

// requestNewToken calls the Kubernetes TokenRequest API to get a fresh token.
func (s *Store) requestNewToken(ctx context.Context, cluster string, cfg config.ClusterConfig, creds *Credentials) error {
	namespace, serviceAccount, err := parseServiceAccountFromToken(creds.Token)
	if err != nil {
		return fmt.Errorf("parsing token subject: %w", err)
	}

	client, err := s.newClient(cfg, creds)
	if err != nil {
		return fmt.Errorf("creating k8s client: %w", err)
	}

	tokenDuration := s.config.GetRenewalTokenDuration()
	expirationSeconds := int64(tokenDuration.Seconds())
	tokenRequest := &authv1.TokenRequest{
		Spec: authv1.TokenRequestSpec{
			ExpirationSeconds: &expirationSeconds,
		},
	}

	token, err := client.CoreV1().ServiceAccounts(namespace).CreateToken(
		ctx,
		serviceAccount,
		tokenRequest,
		metav1.CreateOptions{},
	)
	if err != nil {
		return err
	}

	s.mu.Lock()
	if existing, ok := s.credentials[cluster]; ok {
		existing.Token = token.Status.Token
		existing.source = tokenPersisted
	} else {
		s.credentials[cluster] = &Credentials{
			Token:  token.Status.Token,
			CACert: creds.CACert,
			source: tokenPersisted,
		}
	}
	s.mu.Unlock()

	slog.Info("successfully renewed credentials", "cluster", cluster,
		"expires", token.Status.ExpirationTimestamp.Format(time.RFC3339))

	return nil
}

func (s *Store) createClient(cfg config.ClusterConfig, creds *Credentials) (kubernetes.Interface, error) {
	restConfig := &rest.Config{
		Host: cfg.APIServer,
	}
	if creds != nil {
		restConfig.BearerToken = creds.Token
		restConfig.TLSClientConfig.CAData = creds.CACert
	}
	return kubernetes.NewForConfig(restConfig)
}

// loadFromSecret loads persisted tokens from the Kubernetes Secret.
func (s *Store) loadFromSecret(ctx context.Context) error {
	if s.secretName == "" || s.client == nil {
		return nil
	}

	slog.Info("loading credentials from secret", "namespace", s.namespace, "secret", s.secretName)

	secret, err := s.client.CoreV1().Secrets(s.namespace).Get(ctx, s.secretName, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			slog.Info("credentials secret not found, starting fresh", "namespace", s.namespace, "secret", s.secretName)
			return nil
		}
		return fmt.Errorf("getting secret: %w", err)
	}

	slog.Info("found credentials secret", "namespace", s.namespace, "secret", s.secretName, "keys", len(secret.Data))

	for key, value := range secret.Data {
		if !strings.HasSuffix(key, "-token") {
			slog.Debug("skipping secret key", "key", key, "reason", "no -token suffix")
			continue
		}
		cluster := strings.TrimSuffix(key, "-token")
		token := string(value)
		if token == "" {
			slog.Warn("secret key has empty token", "key", key)
			continue
		}
		if isTokenPodBound(token) {
			slog.Error("skipping pod-bound token from secret (will use bootstrap token instead)",
				"key", key, "cluster", cluster)
			continue
		}
		exp, err := getTokenExpiration(token)
		if err != nil {
			slog.Warn("secret key has invalid token", "key", key, "error", err)
		} else {
			slog.Info("loaded token from secret", "cluster", cluster, "expires", exp.Format(time.RFC3339))
		}
		s.credentials[cluster] = &Credentials{
			Token:  token,
			source: tokenPersisted,
		}
	}

	return nil
}

// saveToSecret persists only tokenPersisted tokens to the Kubernetes Secret.
func (s *Store) saveToSecret(ctx context.Context) error {
	if s.secretName == "" || s.client == nil {
		return nil
	}

	s.mu.RLock()
	data := make(map[string][]byte)
	for cluster, creds := range s.credentials {
		if creds.source != tokenPersisted {
			continue
		}
		data[fmt.Sprintf("%s-token", cluster)] = []byte(creds.Token)
	}
	s.mu.RUnlock()

	if len(data) == 0 {
		return nil
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      s.secretName,
			Namespace: s.namespace,
		},
		Data: data,
	}

	_, err := s.client.CoreV1().Secrets(s.namespace).Update(ctx, secret, metav1.UpdateOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			_, err = s.client.CoreV1().Secrets(s.namespace).Create(ctx, secret, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("creating secret: %w", err)
			}
			slog.Info("created credentials secret", "namespace", s.namespace, "secret", s.secretName)
			return nil
		}
		return fmt.Errorf("updating secret: %w", err)
	}

	slog.Info("updated credentials secret", "namespace", s.namespace, "secret", s.secretName)
	return nil
}

func detectNamespace() string {
	if ns, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
		return string(ns)
	}
	return "kube-federated-auth"
}

// isTokenPodBound checks if a JWT token is bound to a specific pod.
// Pod-bound tokens contain a "kubernetes.io" claim with a "pod" field,
// and become invalid when that pod is deleted.
func isTokenPodBound(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}

	var claims struct {
		Kubernetes struct {
			Pod *json.RawMessage `json:"pod"`
		} `json:"kubernetes.io"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return false
	}

	return claims.Kubernetes.Pod != nil
}

// parseServiceAccountFromToken extracts namespace and service account name from JWT token.
// The subject claim format is: system:serviceaccount:<namespace>:<name>
func parseServiceAccountFromToken(token string) (namespace, serviceAccount string, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", fmt.Errorf("invalid JWT format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", fmt.Errorf("decoding JWT payload: %w", err)
	}

	var claims struct {
		Subject string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", "", fmt.Errorf("parsing JWT claims: %w", err)
	}

	// Parse: system:serviceaccount:<namespace>:<name>
	subParts := strings.Split(claims.Subject, ":")
	if len(subParts) != 4 || subParts[0] != "system" || subParts[1] != "serviceaccount" {
		return "", "", fmt.Errorf("unexpected subject format: %s", claims.Subject)
	}

	return subParts[2], subParts[3], nil
}

// getTokenExpiration extracts the expiration time from a JWT token
func getTokenExpiration(token string) (time.Time, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, fmt.Errorf("invalid JWT format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, fmt.Errorf("decoding JWT payload: %w", err)
	}

	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return time.Time{}, fmt.Errorf("parsing JWT claims: %w", err)
	}

	if claims.Exp == 0 {
		return time.Time{}, fmt.Errorf("token has no expiration claim")
	}

	return time.Unix(claims.Exp, 0), nil
}

// checkCACertExpiration logs a warning if the CA certificate is within the last 20% of its lifetime.
func checkCACertExpiration(cluster string, caCertPEM []byte) {
	if len(caCertPEM) == 0 {
		return
	}

	block, _ := pem.Decode(caCertPEM)
	if block == nil {
		slog.Warn("failed to decode CA certificate PEM", "cluster", cluster)
		return
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		slog.Warn("failed to parse CA certificate", "cluster", cluster, "error", err)
		return
	}

	lifetime := cert.NotAfter.Sub(cert.NotBefore)
	threshold := lifetime / 5 // 20% of lifetime
	timeUntilExpiry := time.Until(cert.NotAfter)
	if timeUntilExpiry < threshold {
		slog.Warn("CA certificate expiring soon", "cluster", cluster,
			"days_remaining", int(timeUntilExpiry.Hours()/24), "expires", cert.NotAfter.Format(time.RFC3339))
	}
}
