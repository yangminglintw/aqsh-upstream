package credentials

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	kubefake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/rophy/aqsh/internal/kubefederatedauth/config"
)

// captureLogs sets slog default to write to a buffer and returns a cleanup function.
func captureLogs(t *testing.T) (*bytes.Buffer, func()) {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	return &buf, func() { slog.SetDefault(prev) }
}

// makeJWT creates a minimal JWT with the given claims for testing.
func makeJWT(sub string, exp time.Time) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	claims := map[string]interface{}{
		"sub": sub,
		"exp": exp.Unix(),
	}
	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	return header + "." + payload + ".sig"
}

// fakeClientFactory returns a clientFactory that always returns the given fake client.
func fakeClientFactory(client *kubefake.Clientset) clientFactory {
	return func(_ config.ClusterConfig, _ *Credentials) (kubernetes.Interface, error) {
		return client, nil
	}
}

func generateCACert(notBefore, notAfter time.Time) []byte {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-ca"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		IsCA:         true,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

// --- CA cert expiration tests ---

func TestCheckCACertExpiration_WarnsWhenExpiringSoon(t *testing.T) {
	notBefore := time.Now().Add(-10*365*24*time.Hour + 30*24*time.Hour)
	cert := generateCACert(notBefore, time.Now().Add(30*24*time.Hour))

	buf, cleanup := captureLogs(t)
	defer cleanup()

	checkCACertExpiration("test-cluster", cert)

	output := buf.String()
	if !strings.Contains(output, "CA certificate expiring soon") {
		t.Errorf("expected warning log, got: %s", output)
	}
}

func TestCheckCACertExpiration_NoWarningWhenFarFromExpiry(t *testing.T) {
	cert := generateCACert(time.Now(), time.Now().Add(10*365*24*time.Hour))

	buf, cleanup := captureLogs(t)
	defer cleanup()

	checkCACertExpiration("test-cluster", cert)

	if buf.Len() > 0 {
		t.Errorf("expected no log output, got: %s", buf.String())
	}
}

func TestCheckCACertExpiration_InvalidPEM(t *testing.T) {
	buf, cleanup := captureLogs(t)
	defer cleanup()

	checkCACertExpiration("test-cluster", []byte("not a pem"))

	if !strings.Contains(buf.String(), "failed to decode CA certificate PEM") {
		t.Errorf("expected decode error log, got: %s", buf.String())
	}
}

func TestCheckCACertExpiration_EmptyCert(t *testing.T) {
	buf, cleanup := captureLogs(t)
	defer cleanup()

	checkCACertExpiration("test-cluster", nil)

	if buf.Len() > 0 {
		t.Errorf("expected no log output, got: %s", buf.String())
	}
}

// --- Token renewal tests ---

func setupFakeClient(t *testing.T, responseToken string) *kubefake.Clientset {
	t.Helper()
	fakeClient := kubefake.NewSimpleClientset()
	fakeClient.PrependReactor("create", "serviceaccounts/token", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, &authv1.TokenRequest{
			Status: authv1.TokenRequestStatus{
				Token:               responseToken,
				ExpirationTimestamp: metav1.NewTime(time.Now().Add(168 * time.Hour)),
			},
		}, nil
	})
	return fakeClient
}

func setupFailingClient(t *testing.T) *kubefake.Clientset {
	t.Helper()
	fakeClient := kubefake.NewSimpleClientset()
	fakeClient.PrependReactor("create", "serviceaccounts/token", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, fmt.Errorf("Unauthorized")
	})
	return fakeClient
}

func defaultConfig() *config.Config {
	return &config.Config{
		Clusters: map[string]config.ClusterConfig{
			"cluster-b": {
				Issuer:    "https://kubernetes.default.svc.cluster.local",
				APIServer: "https://10.0.0.1:6443",
			},
		},
	}
}

func newTestStoreWithConfig(cfg *config.Config) *Store {
	return &Store{
		credentials: make(map[string]*Credentials),
		config:      cfg,
	}
}

func TestRenewPersistedToken_Success(t *testing.T) {
	storedToken := makeJWT("system:serviceaccount:kube-federated-auth:reader", time.Now().Add(1*time.Hour))
	renewedToken := makeJWT("system:serviceaccount:kube-federated-auth:reader", time.Now().Add(168*time.Hour))

	cfg := defaultConfig()
	cfg.Renewal = &config.RenewalSettings{RenewBefore: 8760 * time.Hour}

	store := newTestStoreWithConfig(cfg)
	store.credentials["cluster-b"] = &Credentials{Token: storedToken, CACert: []byte("ca"), source: tokenPersisted}
	store.newClient = fakeClientFactory(setupFakeClient(t, renewedToken))

	creds := store.credentials["cluster-b"]
	err := store.renewPersistedToken(context.Background(), "cluster-b", cfg.Clusters["cluster-b"], creds)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	got, _ := store.Get("cluster-b")
	if got.Token != renewedToken {
		t.Errorf("expected renewed token, got: %s", got.Token[:50])
	}
	if got.source != tokenPersisted {
		t.Errorf("expected source tokenPersisted, got %d", got.source)
	}
}

func TestTryRenew_SkipsWhenTokenNotExpiring(t *testing.T) {
	storedToken := makeJWT("system:serviceaccount:kube-federated-auth:reader", time.Now().Add(168*time.Hour))

	cfg := defaultConfig()
	store := newTestStoreWithConfig(cfg)
	store.credentials["cluster-b"] = &Credentials{Token: storedToken, CACert: []byte("ca"), source: tokenPersisted}
	store.newClient = fakeClientFactory(setupFakeClient(t, "should-not-be-used"))

	buf, cleanup := captureLogs(t)
	defer cleanup()

	store.tryRenew(context.Background())

	if !strings.Contains(buf.String(), "skipping renewal") {
		t.Errorf("expected 'skipping renewal' log, got: %s", buf.String())
	}

	creds, _ := store.Get("cluster-b")
	if creds.Token != storedToken {
		t.Error("token should not have been replaced")
	}
}

func TestRenewPersistedToken_FallsBackToBootstrap(t *testing.T) {
	invalidToken := "invalid.token.here"
	bootstrapToken := makeJWT("system:serviceaccount:kube-federated-auth:reader", time.Now().Add(1*time.Hour))
	renewedToken := makeJWT("system:serviceaccount:kube-federated-auth:reader", time.Now().Add(168*time.Hour))

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	os.WriteFile(tokenPath, []byte(bootstrapToken), 0644)

	cfg := defaultConfig()
	cfg.Clusters["cluster-b"] = config.ClusterConfig{
		Issuer:    "https://kubernetes.default.svc.cluster.local",
		APIServer: "https://10.0.0.1:6443",
		TokenPath: tokenPath,
	}
	cfg.Renewal = &config.RenewalSettings{RenewBefore: 8760 * time.Hour}

	store := newTestStoreWithConfig(cfg)
	store.credentials["cluster-b"] = &Credentials{Token: invalidToken, CACert: []byte("ca"), source: tokenPersisted}
	store.newClient = fakeClientFactory(setupFakeClient(t, renewedToken))

	buf, cleanup := captureLogs(t)
	defer cleanup()

	creds := store.credentials["cluster-b"]
	err := store.renewPersistedToken(context.Background(), "cluster-b", cfg.Clusters["cluster-b"], creds)
	if err != nil {
		t.Fatalf("expected successful fallback, got error: %v", err)
	}

	if !strings.Contains(buf.String(), "retrying with bootstrap") {
		t.Errorf("expected bootstrap fallback log, got: %s", buf.String())
	}

	got, _ := store.Get("cluster-b")
	if got.Token != renewedToken {
		t.Error("expected renewed token from bootstrap fallback")
	}
}

func TestRenewPersistedToken_BothStoredAndBootstrapFail(t *testing.T) {
	invalidToken := "invalid.token.here"
	bootstrapToken := makeJWT("system:serviceaccount:kube-federated-auth:reader", time.Now().Add(1*time.Hour))

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	os.WriteFile(tokenPath, []byte(bootstrapToken), 0644)

	cfg := defaultConfig()
	cfg.Clusters["cluster-b"] = config.ClusterConfig{
		Issuer:    "https://kubernetes.default.svc.cluster.local",
		APIServer: "https://10.0.0.1:6443",
		TokenPath: tokenPath,
	}
	cfg.Renewal = &config.RenewalSettings{RenewBefore: 8760 * time.Hour}

	store := newTestStoreWithConfig(cfg)
	store.credentials["cluster-b"] = &Credentials{Token: invalidToken, CACert: []byte("ca"), source: tokenPersisted}
	store.newClient = fakeClientFactory(setupFailingClient(t))

	buf, cleanup := captureLogs(t)
	defer cleanup()

	creds := store.credentials["cluster-b"]
	err := store.renewPersistedToken(context.Background(), "cluster-b", cfg.Clusters["cluster-b"], creds)
	if err == nil {
		t.Fatal("expected error when both stored and bootstrap tokens fail")
	}

	if !strings.Contains(buf.String(), "bootstrap token is invalid or expired") {
		t.Errorf("expected 'bootstrap token is invalid or expired' log, got: %s", buf.String())
	}
}

func TestRenewPersistedToken_NoTokenPath(t *testing.T) {
	invalidToken := "invalid.token.here"

	cfg := defaultConfig()
	cfg.Renewal = &config.RenewalSettings{RenewBefore: 8760 * time.Hour}

	store := newTestStoreWithConfig(cfg)
	store.credentials["cluster-b"] = &Credentials{Token: invalidToken, CACert: []byte("ca"), source: tokenPersisted}
	store.newClient = fakeClientFactory(setupFailingClient(t))

	buf, cleanup := captureLogs(t)
	defer cleanup()

	creds := store.credentials["cluster-b"]
	err := store.renewPersistedToken(context.Background(), "cluster-b", cfg.Clusters["cluster-b"], creds)
	if err == nil {
		t.Fatal("expected error when no token_path configured")
	}

	if !strings.Contains(buf.String(), "token renewal failed, set token_path") {
		t.Errorf("expected 'set token_path' log, got: %s", buf.String())
	}
}

func TestRenewPersistedToken_BootstrapFileNotReadable(t *testing.T) {
	invalidToken := "invalid.token.here"

	cfg := defaultConfig()
	cfg.Clusters["cluster-b"] = config.ClusterConfig{
		Issuer:    "https://kubernetes.default.svc.cluster.local",
		APIServer: "https://10.0.0.1:6443",
		TokenPath: "/nonexistent/token",
	}
	cfg.Renewal = &config.RenewalSettings{RenewBefore: 8760 * time.Hour}

	store := newTestStoreWithConfig(cfg)
	store.credentials["cluster-b"] = &Credentials{Token: invalidToken, CACert: []byte("ca"), source: tokenPersisted}
	store.newClient = fakeClientFactory(setupFailingClient(t))

	buf, cleanup := captureLogs(t)
	defer cleanup()

	creds := store.credentials["cluster-b"]
	err := store.renewPersistedToken(context.Background(), "cluster-b", cfg.Clusters["cluster-b"], creds)
	if err == nil {
		t.Fatal("expected error when bootstrap file not readable")
	}

	if !strings.Contains(buf.String(), "failed to read bootstrap token") {
		t.Errorf("expected 'failed to read' log, got: %s", buf.String())
	}
}
