package cache

import (
	"sync"
	"testing"
	"time"
)

func TestGet_Miss(t *testing.T) {
	c := New[string](time.Minute, 10)
	_, ok := c.Get("missing")
	if ok {
		t.Error("expected miss for non-existent key")
	}
}

func TestSetAndGet_Hit(t *testing.T) {
	c := New[string](time.Minute, 10)
	c.Set("key", "value")

	v, ok := c.Get("key")
	if !ok {
		t.Fatal("expected hit")
	}
	if v != "value" {
		t.Errorf("got %q, want %q", v, "value")
	}
}

func TestTTLExpiry(t *testing.T) {
	now := time.Now()
	c := New[string](time.Minute, 10)
	c.now = func() time.Time { return now }

	c.Set("key", "value")

	// Still valid
	_, ok := c.Get("key")
	if !ok {
		t.Fatal("expected hit before expiry")
	}

	// Advance past TTL
	c.now = func() time.Time { return now.Add(2 * time.Minute) }

	_, ok = c.Get("key")
	if ok {
		t.Error("expected miss after TTL expiry")
	}
}

func TestLRUEviction(t *testing.T) {
	c := New[string](time.Minute, 3)
	c.Set("a", "1")
	c.Set("b", "2")
	c.Set("c", "3")

	// Adding a 4th should evict "a" (least recently used)
	c.Set("d", "4")

	if _, ok := c.Get("a"); ok {
		t.Error("expected 'a' to be evicted")
	}
	if _, ok := c.Get("b"); !ok {
		t.Error("expected 'b' to still exist")
	}
}

func TestAccessUpdatesLRU(t *testing.T) {
	c := New[string](time.Minute, 3)
	c.Set("a", "1")
	c.Set("b", "2")
	c.Set("c", "3")

	// Access "a" to make it recently used
	c.Get("a")

	// Adding "d" should evict "b" (now LRU), not "a"
	c.Set("d", "4")

	if _, ok := c.Get("a"); !ok {
		t.Error("expected 'a' to survive (was accessed)")
	}
	if _, ok := c.Get("b"); ok {
		t.Error("expected 'b' to be evicted (LRU)")
	}
}

func TestExpiredCleanupDuringEviction(t *testing.T) {
	now := time.Now()
	c := New[string](time.Minute, 3)
	c.now = func() time.Time { return now }

	c.Set("old", "1")
	c.Set("fresh", "2")
	c.Set("fresh2", "3")

	// Advance so "old" expires but others don't
	c.now = func() time.Time { return now.Add(2 * time.Minute) }

	// "fresh" entries also expire with 1min TTL, so let's do it differently
	// Reset: all entries set, then only "old" expires
	now2 := time.Now()
	c2 := New[string](5*time.Minute, 3)
	c2.now = func() time.Time { return now2 }

	c2.Set("old", "1")

	// Advance 3 minutes, then add 2 more entries
	c2.now = func() time.Time { return now2.Add(3 * time.Minute) }
	c2.Set("fresh", "2")
	c2.Set("fresh2", "3")

	// Advance to 6 minutes: "old" (set at 0, expires at 5) is expired, others are not
	c2.now = func() time.Time { return now2.Add(6 * time.Minute) }

	// Adding a new entry should evict expired "old" instead of LRU "fresh"
	c2.Set("new", "4")

	if _, ok := c2.Get("old"); ok {
		t.Error("expected 'old' to be cleaned up (expired)")
	}
	if _, ok := c2.Get("fresh"); !ok {
		t.Error("expected 'fresh' to survive")
	}
	if _, ok := c2.Get("new"); !ok {
		t.Error("expected 'new' to exist")
	}
}

func TestDisabled_ZeroTTL(t *testing.T) {
	c := New[string](0, 10)
	if c.Enabled() {
		t.Error("expected cache to be disabled with TTL=0")
	}

	c.Set("key", "value")
	_, ok := c.Get("key")
	if ok {
		t.Error("expected miss when cache is disabled")
	}
}

func TestDisabled_ZeroMaxEntries(t *testing.T) {
	c := New[string](time.Minute, 0)
	if c.Enabled() {
		t.Error("expected cache to be disabled with maxEntries=0")
	}

	c.Set("key", "value")
	_, ok := c.Get("key")
	if ok {
		t.Error("expected miss when cache is disabled")
	}
}

func TestUpdateExistingKey(t *testing.T) {
	c := New[string](time.Minute, 10)
	c.Set("key", "old")
	c.Set("key", "new")

	v, ok := c.Get("key")
	if !ok {
		t.Fatal("expected hit")
	}
	if v != "new" {
		t.Errorf("got %q, want %q", v, "new")
	}
}

func TestConcurrentAccess(t *testing.T) {
	c := New[int](time.Minute, 100)
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			key := HashKey("key", string(rune(n)))
			c.Set(key, n)
			c.Get(key)
		}(i)
	}

	wg.Wait()
}

func TestLen(t *testing.T) {
	c := New[string](time.Minute, 10)
	if c.Len() != 0 {
		t.Errorf("Len() = %d, want 0", c.Len())
	}

	c.Set("a", "1")
	c.Set("b", "2")
	if c.Len() != 2 {
		t.Errorf("Len() = %d, want 2", c.Len())
	}

	// Update existing key should not change length
	c.Set("a", "updated")
	if c.Len() != 2 {
		t.Errorf("Len() = %d after update, want 2", c.Len())
	}
}

func TestLen_AfterEviction(t *testing.T) {
	c := New[string](time.Minute, 2)
	c.Set("a", "1")
	c.Set("b", "2")
	c.Set("c", "3") // evicts "a"

	if c.Len() != 2 {
		t.Errorf("Len() = %d after eviction, want 2", c.Len())
	}
}

func TestHashKey(t *testing.T) {
	k1 := HashKey("cluster-a", "token123")
	k2 := HashKey("cluster-a", "token123")
	k3 := HashKey("cluster-b", "token123")

	if k1 != k2 {
		t.Error("same inputs should produce same hash")
	}
	if k1 == k3 {
		t.Error("different inputs should produce different hash")
	}
	if len(k1) != 64 {
		t.Errorf("expected 64-char hex string, got %d chars", len(k1))
	}
}
