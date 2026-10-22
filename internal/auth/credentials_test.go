package auth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestPortedRenewalRefreshesLiveReviewerAndStops(t *testing.T) {
	var reviews atomic.Int32
	var expected atomic.Value
	expected.Store("reviewer-one")
	cluster, mint := federationFixture(t, "reviewer-rotation", true, &reviews, &expected)
	file := filepath.Join(t.TempDir(), "clusters.yaml")
	if err := os.WriteFile(file, []byte("renewal:\n  interval: 10ms\ncache:\n  ttl: 0\n  max_entries: 0\nclusters:\n  a:\n"+cluster), 0600); err != nil {
		t.Fatal(err)
	}
	k, err := New(Config{Audiences: []string{"aqsh"}, FederationConfig: file})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.Close)
	token := mint()
	if _, err := k.Authenticate(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	expected.Store("reviewer-two")
	if err := os.WriteFile(k.federation.config.Clusters["a"].TokenPath, []byte("reviewer-two\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// Before the original renewal loop starts, the cached client is stale.
	if _, err := k.Authenticate(context.Background(), token); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected stale reviewer rejection, got %v", err)
	}
	if err := k.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if k.Start(context.Background()) == nil {
		t.Fatal("duplicate renewal loop started")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := k.Authenticate(context.Background(), token); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("renewed credential never reached the cached TokenReview client")
		}
		time.Sleep(10 * time.Millisecond)
	}
	k.Close()
	select {
	case <-k.done:
	default:
		t.Fatal("Close did not wait for renewal to stop")
	}
}
