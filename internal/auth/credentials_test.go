package auth

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func reviewerJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return "e30." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

func managedJWT(t *testing.T, expires time.Time) string {
	return reviewerJWT(t, map[string]any{"sub": "system:serviceaccount:auth:reviewer", "exp": expires.Unix()})
}

func renewal() *RenewalConfig {
	return &RenewalConfig{Namespace: "auth", ServiceAccount: "reviewer", Audiences: []string{"kube-api"}}
}

func TestManagedRenewalPersistenceAndLiveReviewerReplacement(t *testing.T) {
	expiry := time.Now().Add(time.Hour)
	minted := managedJWT(t, expiry)
	var tokenRequests atomic.Int32
	var lastReviewer atomic.Value
	lastReviewer.Store("")
	remote, _ := testCluster(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			tokenRequests.Add(1)
			var req struct {
				Spec struct {
					Audiences         []string
					ExpirationSeconds int64
				}
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Error(err)
			}
			if len(req.Spec.Audiences) != 1 || req.Spec.Audiences[0] != "kube-api" || req.Spec.ExpirationSeconds != 3600 {
				t.Error("wrong reviewer TokenRequest audience/duration")
			}
			json.NewEncoder(w).Encode(map[string]any{"status": map[string]any{"token": minted, "expirationTimestamp": expiry}})
			return
		}
		lastReviewer.Store(r.Header.Get("Authorization"))
		successReview(w)
	})
	remote.Renewal = renewal()
	var patchFails atomic.Bool
	patchFails.Store(true)
	var mu sync.Mutex
	stored := map[string][]byte{"unrelated": []byte("preserve")}
	storage, _ := testCluster(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/namespaces/auth/secrets/reviewer-tokens" {
			t.Error("wrong Secret path")
		}
		if r.Method == "PATCH" {
			if r.Header.Get("Content-Type") != "application/merge-patch+json" {
				t.Error("not a merge patch")
			}
			if patchFails.Load() {
				w.WriteHeader(500)
				return
			}
			var patch struct{ Data map[string][]byte }
			json.NewDecoder(r.Body).Decode(&patch)
			if len(patch.Data) != 1 || string(patch.Data["a-token"]) != minted {
				t.Error("wrong Secret keys")
			}
			mu.Lock()
			for key, value := range patch.Data {
				stored[key] = value
			}
			mu.Unlock()
		}
		mu.Lock()
		defer mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"data": stored})
	})
	cfg := Config{Audiences: []string{"aqsh"}, Clusters: map[string]ClusterConfig{"a": remote}, Persistence: &PersistenceConfig{APIServer: storage.APIServer, CAFile: storage.CAFile, TokenFile: storage.TokenFile, Namespace: "auth", Secret: "reviewer-tokens"}}
	k, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	c := k.clusters[0]
	if _, err := k.Authenticate(context.Background(), "caller"); err != nil {
		t.Fatal(err)
	}
	if err := k.renewCredential(context.Background(), c); err == nil {
		t.Fatal("failed Secret write accepted")
	}
	current, _ := c.tokens.token()
	if current != "reviewer-one" {
		t.Fatal("adopted unpersisted credential")
	}
	patchFails.Store(false)
	if err := k.renewCredential(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Authenticate(context.Background(), "caller"); err != nil {
		t.Fatal(err)
	}
	if lastReviewer.Load().(string) != "Bearer "+minted {
		t.Fatal("cached client retained old reviewer credential")
	}
	if err := k.renewCredential(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if tokenRequests.Load() != 2 {
		t.Fatal("renewed before threshold")
	}
	mu.Lock()
	if string(stored["unrelated"]) != "preserve" {
		t.Fatal("replaced unrelated Secret data")
	}
	mu.Unlock()

	// A new API instance resumes the persisted token without minting another one.
	restarted, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Authenticate(context.Background(), "caller"); err != nil {
		t.Fatal(err)
	}
	restarted.Close()
	if tokenRequests.Load() != 2 || lastReviewer.Load().(string) != "Bearer "+minted {
		t.Fatal("persisted token not resumed")
	}
}

func TestRenewalRecoversUsingRotatedBootstrap(t *testing.T) {
	expiry := time.Now().Add(time.Hour)
	minted := managedJWT(t, expiry)
	var calls atomic.Int32
	remote, _ := testCluster(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer reviewer-one" {
			w.WriteHeader(401)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"status": map[string]any{"token": minted, "expirationTimestamp": expiry}})
	})
	remote.Renewal = renewal()
	k, err := New(Config{Audiences: []string{"aqsh"}, Clusters: map[string]ClusterConfig{"a": remote}})
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	c := k.clusters[0]
	c.tokens.set(managedJWT(t, time.Now().Add(time.Minute)))
	if err := k.renewCredential(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatal("did not retry using mounted bootstrap")
	}
	token, _ := c.tokens.token()
	if token != minted {
		t.Fatal("recovered token not adopted")
	}
}

func TestManagedTokensRejectWrongSubjectPodBindingAndExpiry(t *testing.T) {
	for _, claims := range []map[string]any{
		{"sub": "system:serviceaccount:other:reviewer", "exp": time.Now().Add(time.Hour).Unix()},
		{"sub": "system:serviceaccount:auth:reviewer", "exp": time.Now().Add(time.Hour).Unix(), "kubernetes.io": map[string]any{"pod": map[string]string{"uid": "pod"}}},
		{"sub": "system:serviceaccount:auth:reviewer", "exp": time.Now().Add(-time.Hour).Unix()},
		{"sub": "system:serviceaccount:auth:reviewer"},
	} {
		if validManagedToken(reviewerJWT(t, claims), renewal()) {
			t.Fatal("unsafe persisted credential accepted")
		}
	}
}

func TestMountedCAChangesReplaceTransportAndFailClosed(t *testing.T) {
	cfg, _ := testCluster(t, func(w http.ResponseWriter, r *http.Request) { successReview(w) })
	k, err := New(Config{Audiences: []string{"aqsh"}, Clusters: map[string]ClusterConfig{"a": cfg}})
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	if _, err := k.Authenticate(context.Background(), "caller"); err != nil {
		t.Fatal(err)
	}
	f := k.clusters[0].client.Transport.(*fileTransport)
	old, _ := f.transport()
	original, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	key := signingKey(t)
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "rotated-root"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	newBundle := append(append([]byte(nil), original...), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	if err := os.WriteFile(cfg.CAFile, newBundle, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Authenticate(context.Background(), "caller"); err != nil {
		t.Fatal(err)
	}
	updated, err := f.transport()
	if err != nil || updated == old || len(updated.TLSClientConfig.RootCAs.Subjects()) != 2 {
		t.Fatal("CA update did not refresh client")
	}
	if err := os.WriteFile(cfg.CAFile, []byte("invalid CA"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Authenticate(context.Background(), "caller"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("invalid CA silently reused old trust")
	}
	if err := os.WriteFile(cfg.CAFile, original, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Authenticate(context.Background(), "caller"); err != nil {
		t.Fatal(err)
	}
}

func TestCredentialManagerStopsWithAPIContext(t *testing.T) {
	remote, _ := testCluster(t, func(w http.ResponseWriter, r *http.Request) { t.Error("unexpected renewal"); w.WriteHeader(500) })
	if err := os.WriteFile(remote.TokenFile, []byte(managedJWT(t, time.Now().Add(time.Hour))), 0600); err != nil {
		t.Fatal(err)
	}
	remote.Renewal = renewal()
	k, err := New(Config{Audiences: []string{"aqsh"}, Clusters: map[string]ClusterConfig{"a": remote}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := k.Start(ctx); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-k.credentials.done:
	case <-time.After(time.Second):
		t.Fatal("renewal outlived API")
	}
	k.Close()
}
