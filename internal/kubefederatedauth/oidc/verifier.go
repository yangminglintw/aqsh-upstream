package oidc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rophy/aqsh/internal/kubefederatedauth/config"
	"github.com/rophy/aqsh/internal/kubefederatedauth/credentials"
)

type Claims struct {
	Cluster    string         `json:"cluster"`
	Issuer     string         `json:"iss"`
	Subject    string         `json:"sub"`
	Audience   []string       `json:"aud"`
	Expiry     int64          `json:"exp"`
	IssuedAt   int64          `json:"iat"`
	NotBefore  int64          `json:"nbf,omitempty"`
	Kubernetes map[string]any `json:"kubernetes.io,omitempty"`
}

type VerifierManager struct {
	mu              sync.RWMutex
	verifiers       map[string]*oidc.IDTokenVerifier
	kidToCluster    map[string]string // kid → clusterName
	degraded        map[string]string // cluster → error message
	config          *config.Config
	credStore       *credentials.Store
	testHTTPClients map[string]*http.Client // for testing only
	degradedGauge   *prometheus.GaugeVec    // optional, nil-safe
}

func NewVerifierManager(cfg *config.Config, credStore *credentials.Store) *VerifierManager {
	return &VerifierManager{
		verifiers:    make(map[string]*oidc.IDTokenVerifier),
		kidToCluster: make(map[string]string),
		degraded:     make(map[string]string),
		config:       cfg,
		credStore:    credStore,
	}
}

// SetMetrics sets the optional Prometheus gauge for cluster degraded state.
func (m *VerifierManager) SetMetrics(degradedGauge *prometheus.GaugeVec) {
	m.degradedGauge = degradedGauge
}

// WarmUp eagerly creates verifiers for all configured clusters.
// Failures are recorded as degraded and logged, but do not prevent startup.
func (m *VerifierManager) WarmUp(ctx context.Context) {
	for name, cfg := range m.config.Clusters {
		if _, err := m.getOrCreateVerifier(ctx, name, cfg); err != nil {
			slog.Error("warmup: failed to create verifier", "cluster", name, "error", err)
		} else {
			slog.Info("warmup: verifier ready", "cluster", name)
		}
	}
}

// DegradedClusters returns a copy of the degraded clusters map.
func (m *VerifierManager) DegradedClusters() map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.degraded) == 0 {
		return nil
	}
	result := make(map[string]string, len(m.degraded))
	for k, v := range m.degraded {
		result[k] = v
	}
	return result
}

// InvalidateVerifier removes a cached verifier, forcing recreation with new credentials
func (m *VerifierManager) InvalidateVerifier(clusterName string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.verifiers, clusterName)
	for kid, owner := range m.kidToCluster {
		if owner == clusterName {
			delete(m.kidToCluster, kid)
		}
	}
}

func (m *VerifierManager) Verify(ctx context.Context, clusterName, rawToken string) (*Claims, error) {
	clusterCfg, ok := m.config.Clusters[clusterName]
	if !ok {
		return nil, fmt.Errorf("cluster not found: %s", clusterName)
	}

	// KID-based short-circuit: skip go-oidc verification if the token's kid
	// is known to belong to a different cluster
	kid := extractKID(rawToken)
	if kid != "" {
		m.mu.RLock()
		owner, known := m.kidToCluster[kid]
		m.mu.RUnlock()
		if known && owner != clusterName {
			return nil, fmt.Errorf("kid %q belongs to cluster %s, not %s", kid, owner, clusterName)
		}
	}

	verifier, err := m.getOrCreateVerifier(ctx, clusterName, clusterCfg)
	if err != nil {
		return nil, fmt.Errorf("creating verifier: %w", err)
	}

	token, err := verifier.Verify(ctx, rawToken)
	if err != nil {
		return nil, fmt.Errorf("verifying token: %w", err)
	}

	// Manual expiry check: go-oidc SkipExpiryCheck is enabled to support legacy SA tokens
	// (which have no exp claim). If exp IS present and the token is expired, reject it.
	if !token.Expiry.IsZero() && token.Expiry.Before(time.Now()) {
		return nil, fmt.Errorf("verifying token: token is expired")
	}

	// After successful verification, learn the kid→cluster mapping
	if kid != "" {
		m.mu.Lock()
		if _, known := m.kidToCluster[kid]; !known {
			m.kidToCluster[kid] = clusterName
		}
		m.mu.Unlock()
	}

	var rawClaims struct {
		Issuer     string         `json:"iss"`
		Subject    string         `json:"sub"`
		Expiry     int64          `json:"exp"`
		IssuedAt   int64          `json:"iat"`
		NotBefore  int64          `json:"nbf"`
		Kubernetes map[string]any `json:"kubernetes.io"`
	}
	if err := token.Claims(&rawClaims); err != nil {
		return nil, fmt.Errorf("parsing claims: %w", err)
	}

	return &Claims{
		Cluster:    clusterName,
		Issuer:     rawClaims.Issuer,
		Subject:    rawClaims.Subject,
		Audience:   token.Audience,
		Expiry:     rawClaims.Expiry,
		IssuedAt:   rawClaims.IssuedAt,
		NotBefore:  rawClaims.NotBefore,
		Kubernetes: rawClaims.Kubernetes,
	}, nil
}

// extractKID extracts the "kid" (Key ID) from a JWT header without performing
// any cryptographic verification. Returns "" if the token is malformed or has no kid.
func extractKID(rawToken string) string {
	parts := strings.SplitN(rawToken, ".", 3)
	if len(parts) < 2 {
		return ""
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return ""
	}
	var header struct {
		KID string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return ""
	}
	return header.KID
}

// jwksResponse represents the minimal structure of a JWKS endpoint response.
type jwksResponse struct {
	Keys []struct {
		KID string `json:"kid"`
	} `json:"keys"`
}

// fetchKIDs fetches the JWKS URL and returns all kid values from the key set.
func fetchKIDs(ctx context.Context, client *http.Client, jwksURL string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating JWKS request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("JWKS returned status %d: %s", resp.StatusCode, string(body))
	}

	var jwks jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("decoding JWKS: %w", err)
	}

	var kids []string
	for _, key := range jwks.Keys {
		if key.KID != "" {
			kids = append(kids, key.KID)
		}
	}
	return kids, nil
}

// oidcDiscovery represents the OIDC discovery document
type oidcDiscovery struct {
	Issuer  string `json:"issuer"`
	JWKSURL string `json:"jwks_uri"`
}

func (m *VerifierManager) getOrCreateVerifier(ctx context.Context, name string, cfg config.ClusterConfig) (*oidc.IDTokenVerifier, error) {
	m.mu.RLock()
	if v, ok := m.verifiers[name]; ok {
		m.mu.RUnlock()
		return v, nil
	}
	m.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check after acquiring write lock
	if v, ok := m.verifiers[name]; ok {
		return v, nil
	}

	httpClient, err := m.createHTTPClient(name, cfg)
	if err != nil {
		errMsg := err.Error()
		slog.Error("failed to create HTTP client for OIDC verifier", "cluster", name, "error", err)
		m.degraded[name] = errMsg
		if m.degradedGauge != nil {
			m.degradedGauge.WithLabelValues(name).Set(1)
		}
		return nil, err
	}

	// For remote clusters, the discovery URL (api_server) differs from the issuer
	// We need to manually fetch discovery from api_server but validate tokens with the actual issuer
	discoveryURL := cfg.DiscoveryURL()

	// Fetch OIDC discovery document from the discovery URL
	discovery, err := m.fetchDiscovery(ctx, httpClient, discoveryURL)
	if err != nil {
		// If discovery fails and a token_path is available, the stored token may be stale.
		// Retry with the mounted token as a fallback.
		if cfg.TokenPath != "" {
			slog.Warn("OIDC discovery failed with stored token, retrying with mounted token",
				"cluster", name, "token_path", cfg.TokenPath, "error", err)
			fallbackClient, fbErr := m.createHTTPClientFromTokenPath(cfg)
			if fbErr == nil {
				discovery, err = m.fetchDiscovery(ctx, fallbackClient, discoveryURL)
				if err == nil {
					httpClient = fallbackClient
					// Clear the stale token so future requests use token_path
					if m.credStore != nil {
						m.credStore.ClearToken(name)
						slog.Info("cleared stale token from credential store", "cluster", name)
					}
				}
			} else {
				slog.Error("failed to create fallback HTTP client", "cluster", name, "error", fbErr)
			}
		}
		if err != nil {
			errMsg := fmt.Sprintf("fetching OIDC discovery from %s: %v", discoveryURL, err)
			slog.Error("OIDC verifier creation failed", "cluster", name, "error", errMsg)
			m.degraded[name] = errMsg
			if m.degradedGauge != nil {
				m.degradedGauge.WithLabelValues(name).Set(1)
			}
			return nil, fmt.Errorf("%s", errMsg)
		}
	}

	// Create a remote key set that fetches JWKS from the discovery URL's JWKS endpoint
	// The JWKS URL from discovery might use the issuer's hostname, so we may need to rewrite it
	jwksURL := discovery.JWKSURL
	if cfg.APIServer != "" {
		// Rewrite JWKS URL to use the API server instead of the internal issuer hostname
		jwksURL = rewriteJWKSURL(discovery.JWKSURL, cfg.APIServer)
	}

	// Pre-fetch KIDs from JWKS to enable kid-based short-circuit optimization
	kids, err := fetchKIDs(ctx, httpClient, jwksURL)
	if err != nil {
		slog.Warn("failed to pre-fetch KIDs (optimization disabled for this cluster)",
			"cluster", name, "error", err)
	} else {
		for _, kid := range kids {
			m.kidToCluster[kid] = name
		}
	}

	ctx = oidc.ClientContext(ctx, httpClient)
	keySet := oidc.NewRemoteKeySet(ctx, jwksURL)

	// Create verifier with the actual issuer from the token (not the discovery URL).
	// SkipIssuerCheck: legacy SA tokens have issuer "kubernetes/serviceaccount" instead of
	// the OIDC issuer. JWKS keys provide the real trust boundary.
	// SkipExpiryCheck: legacy SA tokens have no exp claim (go-oidc treats zero time as expired).
	// We manually check expiry in Verify() for tokens that DO have exp.
	verifier := oidc.NewVerifier(cfg.Issuer, keySet, &oidc.Config{
		SkipClientIDCheck: true,
		SkipIssuerCheck:   true,
		SkipExpiryCheck:   true,
	})

	m.verifiers[name] = verifier
	delete(m.degraded, name) // Recovery: clear degraded state on success
	if m.degradedGauge != nil {
		m.degradedGauge.WithLabelValues(name).Set(0)
	}
	return verifier, nil
}

// fetchDiscovery fetches the OIDC discovery document from the given URL
func (m *VerifierManager) fetchDiscovery(ctx context.Context, client *http.Client, baseURL string) (*oidcDiscovery, error) {
	wellKnownURL := strings.TrimSuffix(baseURL, "/") + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, "GET", wellKnownURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching discovery: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("discovery returned status %d: %s", resp.StatusCode, string(body))
	}

	var discovery oidcDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return nil, fmt.Errorf("decoding discovery: %w", err)
	}

	return &discovery, nil
}

// rewriteJWKSURL rewrites the JWKS URL to use the API server host instead of the internal issuer host
func rewriteJWKSURL(jwksURL, apiServer string) string {
	// The JWKS URL from k8s discovery typically looks like:
	// https://kubernetes.default.svc.cluster.local/openid/v1/jwks
	// We need to rewrite it to use the API server:
	// https://<api-server>/openid/v1/jwks

	// Find the path part after the host
	const pathPrefix = "/openid/v1/jwks"
	if strings.Contains(jwksURL, pathPrefix) {
		return strings.TrimSuffix(apiServer, "/") + pathPrefix
	}

	// Fallback: just use the original URL
	return jwksURL
}

// createHTTPClientFromTokenPath creates an HTTP client that reads the token from
// a file on each request, bypassing the credential store. Used as a fallback when
// the stored token is stale.
func (m *VerifierManager) createHTTPClientFromTokenPath(cfg config.ClusterConfig) (*http.Client, error) {
	var transport http.RoundTripper = http.DefaultTransport

	if cfg.CACert != "" {
		caCert, err := os.ReadFile(cfg.CACert)
		if err != nil {
			return nil, fmt.Errorf("reading CA cert: %w", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA cert")
		}
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
		}
	}

	transport = &tokenRoundTripper{
		transport: transport,
		tokenPath: cfg.TokenPath,
	}

	return &http.Client{Transport: transport}, nil
}

func (m *VerifierManager) createHTTPClient(clusterName string, cfg config.ClusterConfig) (*http.Client, error) {
	// Test hook: use injected client if available
	if m.testHTTPClients != nil {
		if c, ok := m.testHTTPClients[clusterName]; ok {
			return c, nil
		}
	}

	var transport http.RoundTripper = http.DefaultTransport

	var caCert []byte
	var token string

	if m.credStore != nil {
		if creds, ok := m.credStore.Get(clusterName); ok {
			caCert = creds.CACert
			token = creds.Token
		}
	}

	if caCert != nil {
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA cert")
		}

		transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
		}
	}

	// Use dynamic token if available, otherwise use token file
	if token != "" {
		transport = &staticTokenRoundTripper{
			transport: transport,
			token:     token,
		}
	} else if cfg.TokenPath != "" {
		transport = &tokenRoundTripper{
			transport: transport,
			tokenPath: cfg.TokenPath,
		}
	}

	return &http.Client{Transport: transport}, nil
}

type tokenRoundTripper struct {
	transport http.RoundTripper
	tokenPath string
}

func (t *tokenRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	token, err := os.ReadFile(t.tokenPath)
	if err != nil {
		return nil, fmt.Errorf("reading token: %w", err)
	}

	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))

	return t.transport.RoundTrip(req)
}

type staticTokenRoundTripper struct {
	transport http.RoundTripper
	token     string
}

func (t *staticTokenRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+t.token)
	return t.transport.RoundTrip(req)
}
