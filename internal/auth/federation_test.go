package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	authv1 "k8s.io/api/authentication/v1"
	"k8s.io/client-go/kubernetes/scheme"
)

func federationFixture(t *testing.T, id string, allow bool, reviews *atomic.Int32, reviewer ...*atomic.Value) (string, func() string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var endpoint string
	c, srv := testCluster(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, endpoint, endpoint+"/openid/v1/jwks")
		case "/openid/v1/jwks":
			json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: id, Algorithm: "RS256", Use: "sig"}}})
		case "/apis/authentication.k8s.io/v1/tokenreviews":
			reviews.Add(1)
			wantReviewer := "reviewer-one"
			if len(reviewer) != 0 {
				wantReviewer = reviewer[0].Load().(string)
			}
			if r.Header.Get("Authorization") != "Bearer "+wantReviewer {
				if len(reviewer) == 0 {
					t.Error("reviewer credential was not reused")
				}
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			var tr authv1.TokenReview
			body, _ := io.ReadAll(r.Body)
			if _, _, err := scheme.Codecs.UniversalDeserializer().Decode(body, nil, &tr); err != nil {
				t.Error(err)
			}
			if len(tr.Spec.Audiences) != 1 || tr.Spec.Audiences[0] != "aqsh" {
				t.Error("audiences not forwarded")
			}
			json.NewEncoder(w).Encode(map[string]any{"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview", "status": map[string]any{
				"authenticated": allow, "audiences": []string{"aqsh"}, "user": map[string]any{"username": "system:serviceaccount:team:caller", "uid": id, "groups": []string{"team"}},
			}})
		default:
			w.WriteHeader(404)
		}
	})
	endpoint = srv.URL
	cluster := fmt.Sprintf("    issuer: %s\n    api_server: %s\n    ca_cert: %s\n    token_path: %s\n", endpoint, endpoint, c.CAFile, c.TokenFile)
	mint := func() string {
		header := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"alg":"RS256","kid":%q}`, id)))
		payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"iss":%q,"sub":"system:serviceaccount:team:caller","aud":["aqsh"],"exp":%d}`, endpoint, time.Now().Add(time.Minute).Unix())))
		data := header + "." + payload
		hash := sha256.Sum256([]byte(data))
		signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
		if err != nil {
			t.Fatal(err)
		}
		return data + "." + base64.RawURLEncoding.EncodeToString(signature)
	}
	return cluster, mint
}

func TestFederationUsesPortedHandlerAndSourceIdentity(t *testing.T) {
	var a, b atomic.Int32
	clusterA, mintA := federationFixture(t, "uid-a", true, &a)
	clusterB, mintB := federationFixture(t, "uid-b", false, &b)
	file := filepath.Join(t.TempDir(), "clusters.yaml")
	// This is the existing kube-federated-auth schema, not a new aqsh schema.
	if err := os.WriteFile(file, []byte("cache:\n  ttl: 0\n  max_entries: 0\nclusters:\n  a:\n"+clusterA+"  b:\n"+clusterB), 0600); err != nil {
		t.Fatal(err)
	}
	k, err := New(Config{Audiences: []string{"aqsh"}, FederationConfig: file})
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	p, err := k.Authenticate(context.Background(), mintA())
	if err != nil || p.Cluster != "a" || p.UID != "uid-a" || p.Username != "system:serviceaccount:team:caller" {
		t.Fatalf("principal=%+v err=%v", p, err)
	}
	if _, err := k.Authenticate(context.Background(), mintB()); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("signature bypassed online denial: %v", err)
	}
	if _, err := k.Authenticate(context.Background(), "not-a-jwt"); err == nil {
		t.Fatal("malformed token accepted")
	}
	if a.Load() != 1 || b.Load() != 1 {
		t.Fatalf("unexpected forwarding: %d %d", a.Load(), b.Load())
	}
}

func TestFederationRejectsMixedConfiguration(t *testing.T) {
	cfg := Config{Audiences: []string{"aqsh"}, FederationConfig: "clusters.yaml", Clusters: map[string]ClusterConfig{"a": {}}}
	if cfg.validate() == nil {
		t.Fatal("mixed configuration accepted")
	}
	if _, err := New(Config{Audiences: []string{"aqsh"}, FederationConfig: "/does-not-exist"}); err == nil {
		t.Fatal("missing original config accepted")
	}
}
