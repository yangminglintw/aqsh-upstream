package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func signingKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func signedToken(t *testing.T, key *ecdsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "same-kid"))
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(claims)
	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	token, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func federatedCluster(t *testing.T, key *ecdsa.PrivateKey, uid string, reviews *atomic.Int32, allow bool) ClusterConfig {
	t.Helper()
	c, srv := testCluster(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openid/v1/jwks":
			json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "same-kid", Algorithm: "ES256", Use: "sig"}}})
		case "/apis/authentication.k8s.io/v1/tokenreviews":
			reviews.Add(1)
			var tr tokenReview
			json.NewDecoder(r.Body).Decode(&tr)
			tr.Spec.Token = ""
			tr.Status.Authenticated = allow
			tr.Status.Audiences = []string{"aqsh"}
			tr.Status.User = userInfo{Username: "system:serviceaccount:shared:caller", UID: uid}
			json.NewEncoder(w).Encode(tr)
		default:
			t.Errorf("unconfigured discovery requested: %s", r.URL.Path)
			w.WriteHeader(404)
		}
	})
	c.JWKSURL = srv.URL + "/openid/v1/jwks"
	return c
}

func TestFederationRoutesCollidingKidsAndPreservesSource(t *testing.T) {
	keyA, keyB := signingKey(t), signingKey(t)
	var countA, countB atomic.Int32
	cfg := Config{Audiences: []string{"aqsh"}, CacheTTL: 10 * time.Second, Clusters: map[string]ClusterConfig{
		"cluster-a": federatedCluster(t, keyA, "uid-a", &countA, true),
		"cluster-b": federatedCluster(t, keyB, "uid-b", &countB, true),
	}}
	k, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	for i := 0; i < 2; i++ {
		for _, tc := range []struct {
			key          *ecdsa.PrivateKey
			cluster, uid string
		}{{keyA, "cluster-a", "uid-a"}, {keyB, "cluster-b", "uid-b"}} {
			token := signedToken(t, tc.key, map[string]any{"exp": time.Now().Add(time.Minute).Unix(), "iss": "https://untrusted.invalid", "cluster": "forged", "sub": "forged"})
			p, err := k.Authenticate(context.Background(), token)
			if err != nil || p.Cluster != tc.cluster || p.UID != tc.uid || p.Username != "system:serviceaccount:shared:caller" {
				t.Fatalf("principal=%+v err=%v", p, err)
			}
			// Reusing exactly the same signed token exercises the success cache.
			if _, err := k.Authenticate(context.Background(), token); err != nil {
				t.Fatal(err)
			}
		}
	}
	if countA.Load() != 2 || countB.Load() != 2 {
		t.Fatalf("unexpected review counts a=%d b=%d", countA.Load(), countB.Load())
	}
}

func TestFederationRequiresOnlineReview(t *testing.T) {
	key := signingKey(t)
	var reviews atomic.Int32
	c := federatedCluster(t, key, "uid", &reviews, false)
	k, err := New(Config{Audiences: []string{"aqsh"}, Clusters: map[string]ClusterConfig{"a": c}})
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	token := signedToken(t, key, map[string]any{"exp": time.Now().Add(time.Minute).Unix()})
	for i := 0; i < 2; i++ {
		if _, err := k.Authenticate(context.Background(), token); !errors.Is(err, ErrUnauthenticated) {
			t.Fatal("signature alone authenticated caller")
		}
	}
	if reviews.Load() != 2 {
		t.Fatal("negative authentication was cached")
	}
}

func TestFederationRejectsAmbiguousAndUntrustedKeys(t *testing.T) {
	key := signingKey(t)
	var reviews atomic.Int32
	k, err := New(Config{Audiences: []string{"aqsh"}, Clusters: map[string]ClusterConfig{
		"a": federatedCluster(t, key, "uid-a", &reviews, true), "b": federatedCluster(t, key, "uid-b", &reviews, true),
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	for _, signing := range []*ecdsa.PrivateKey{key, signingKey(t)} {
		token := signedToken(t, signing, map[string]any{"exp": time.Now().Add(time.Minute).Unix()})
		if _, err := k.Authenticate(context.Background(), token); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("ambiguous/untrusted key accepted: %v", err)
		}
	}
	if reviews.Load() != 0 {
		t.Fatal("caller token forwarded without unique trusted source")
	}
}

func TestFederationChecksExpiryAndNotBefore(t *testing.T) {
	key := signingKey(t)
	var reviews atomic.Int32
	k, err := New(Config{Audiences: []string{"aqsh"}, Clusters: map[string]ClusterConfig{"a": federatedCluster(t, key, "uid", &reviews, true)}})
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	for _, claims := range []map[string]any{
		{"exp": time.Now().Add(-time.Minute).Unix()}, {"exp": time.Now().Add(time.Minute).Unix(), "nbf": time.Now().Add(time.Minute).Unix()}, {"exp": "invalid"},
	} {
		if _, err := k.Authenticate(context.Background(), signedToken(t, key, claims)); !errors.Is(err, ErrUnauthenticated) {
			t.Fatal("invalid times accepted")
		}
	}
	if reviews.Load() != 0 {
		t.Fatal("invalid JWT was forwarded")
	}
}

func TestReviewCacheIsolationBoundsAndExpiry(t *testing.T) {
	c := newReviewCache(1, time.Minute)
	a := reviewKey{Cluster: "a", Token: tokenHash("secret"), Audiences: `["audience-a"]`}
	p := Principal{Username: "caller", Groups: []string{"group"}}
	c.put(a, p, time.Time{})
	for _, other := range []reviewKey{{Cluster: "a", Token: a.Token, Audiences: `["audience-b"]`}, {Cluster: "b", Token: a.Token, Audiences: a.Audiences}, {Cluster: "a", Token: tokenHash("other"), Audiences: a.Audiences}} {
		if _, ok := c.get(other); ok {
			t.Fatal("cache crossed cluster, token or audience boundary")
		}
	}
	p.Groups[0] = "mutated"
	got, ok := c.get(a)
	if !ok || got.Groups[0] != "group" {
		t.Fatal("cache aliases input")
	}
	got.Groups[0] = "mutated"
	got, _ = c.get(a)
	if got.Groups[0] != "group" {
		t.Fatal("cache aliases output")
	}
	b := a
	b.Cluster = "b"
	c.put(b, p, time.Time{})
	if _, ok := c.get(a); ok || c.order.Len() != 1 {
		t.Fatal("capacity not bounded")
	}
	c.put(b, p, time.Now().Add(10*time.Millisecond))
	time.Sleep(20 * time.Millisecond)
	if _, ok := c.get(b); ok {
		t.Fatal("cached identity outlived caller token")
	}
	disabled := newReviewCache(1, 0)
	disabled.put(a, p, time.Time{})
	if _, ok := disabled.get(a); ok {
		t.Fatal("disabled cache retained a review")
	}
}
