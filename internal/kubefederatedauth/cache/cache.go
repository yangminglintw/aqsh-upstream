package cache

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

// Cache is a thread-safe LRU cache with TTL expiry.
// It is disabled (Get always misses, Set is no-op) when TTL or MaxEntries is 0.
type Cache[V any] struct {
	mu         sync.Mutex
	ttl        time.Duration
	maxEntries int
	items      map[string]*list.Element
	order      *list.List // front = most recently used
	now        func() time.Time
}

type entry[V any] struct {
	key       string
	value     V
	expiresAt time.Time
}

// New creates a new Cache. If ttl or maxEntries is 0, the cache is disabled.
func New[V any](ttl time.Duration, maxEntries int) *Cache[V] {
	return &Cache[V]{
		ttl:        ttl,
		maxEntries: maxEntries,
		items:      make(map[string]*list.Element),
		order:      list.New(),
		now:        time.Now,
	}
}

// Enabled returns true if the cache is active.
func (c *Cache[V]) Enabled() bool {
	return c.ttl > 0 && c.maxEntries > 0
}

// Get retrieves a value by key. Returns the value and true on hit, zero value and false on miss.
// Expired entries are removed on access.
func (c *Cache[V]) Get(key string) (V, bool) {
	var zero V
	if !c.Enabled() {
		return zero, false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.items[key]
	if !ok {
		return zero, false
	}

	e := el.Value.(*entry[V])
	if c.now().After(e.expiresAt) {
		c.removeLocked(el)
		return zero, false
	}

	c.order.MoveToFront(el)
	return e.value, true
}

// Set stores a value with the configured TTL. If the cache is at capacity,
// the least-recently-used entry is evicted.
func (c *Cache[V]) Set(key string, value V) {
	c.SetWithTTL(key, value, c.ttl)
}

// SetWithTTL stores a value with a custom TTL. If the cache is at capacity,
// the least-recently-used entry is evicted.
func (c *Cache[V]) SetWithTTL(key string, value V, ttl time.Duration) {
	if !c.Enabled() || ttl <= 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Update existing entry
	if el, ok := c.items[key]; ok {
		e := el.Value.(*entry[V])
		e.value = value
		e.expiresAt = c.now().Add(ttl)
		c.order.MoveToFront(el)
		return
	}

	// Evict if at capacity
	for c.order.Len() >= c.maxEntries {
		c.evictLocked()
	}

	e := &entry[V]{
		key:       key,
		value:     value,
		expiresAt: c.now().Add(ttl),
	}
	el := c.order.PushFront(e)
	c.items[key] = el
}

// evictLocked removes the least-recently-used entry, skipping expired entries first.
func (c *Cache[V]) evictLocked() {
	// Remove expired entries from the back first
	for el := c.order.Back(); el != nil; {
		e := el.Value.(*entry[V])
		if c.now().After(e.expiresAt) {
			prev := el.Prev()
			c.removeLocked(el)
			el = prev
			if c.order.Len() < c.maxEntries {
				return
			}
		} else {
			el = el.Prev()
		}
	}

	// Remove LRU entry (back of list)
	if el := c.order.Back(); el != nil {
		c.removeLocked(el)
	}
}

// Len returns the number of entries currently in the cache.
func (c *Cache[V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}

func (c *Cache[V]) removeLocked(el *list.Element) {
	e := el.Value.(*entry[V])
	delete(c.items, e.key)
	c.order.Remove(el)
}

// HashKey builds a deterministic cache key from parts using SHA-256.
func HashKey(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:])
}
