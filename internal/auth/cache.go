package auth

import (
	"container/list"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"time"
)

type reviewKey struct {
	Cluster, Audiences string
	Token              [32]byte
}

type reviewEntry struct {
	key     reviewKey
	p       Principal
	expires time.Time
}

// Only successful reviews are cached. The key includes the complete audience set
// and cluster; bearer credentials are not retained in cache keys.
type reviewCache struct {
	mu       sync.Mutex
	entries  map[reviewKey]*list.Element
	order    *list.List
	capacity int
	ttl      time.Duration
}

func tokenHash(token string) [32]byte { return sha256.Sum256([]byte(token)) }

func newReviewCache(capacity int, ttl time.Duration) *reviewCache {
	return &reviewCache{entries: make(map[reviewKey]*list.Element), order: list.New(), capacity: capacity, ttl: ttl}
}

func (c *reviewCache) get(key reviewKey) (Principal, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.entries[key]
	if e == nil {
		return Principal{}, false
	}
	entry := e.Value.(reviewEntry)
	if !time.Now().Before(entry.expires) {
		delete(c.entries, key)
		c.order.Remove(e)
		return Principal{}, false
	}
	c.order.MoveToFront(e)
	p := entry.p
	p.Groups = append([]string(nil), p.Groups...)
	return p, true
}

func (c *reviewCache) put(key reviewKey, p Principal, tokenExpiry time.Time) {
	if c.ttl == 0 {
		return
	}
	expires := time.Now().Add(c.ttl)
	if !tokenExpiry.IsZero() && tokenExpiry.Before(expires) {
		expires = tokenExpiry
	}
	if !time.Now().Before(expires) {
		return
	}
	p.Groups = append([]string(nil), p.Groups...)
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := reviewEntry{key: key, p: p, expires: expires}
	if e := c.entries[key]; e != nil {
		e.Value = entry
		c.order.MoveToFront(e)
		return
	}
	c.entries[key] = c.order.PushFront(entry)
	if c.order.Len() > c.capacity {
		e := c.order.Back()
		delete(c.entries, e.Value.(reviewEntry).key)
		c.order.Remove(e)
	}
}

type tokenTimes struct {
	Expiry    *int64 `json:"exp"`
	NotBefore *int64 `json:"nbf"`
}

func validTimes(payload []byte, now time.Time) (time.Time, bool) {
	var claims tokenTimes
	if json.Unmarshal(payload, &claims) != nil {
		return time.Time{}, false
	}
	var expiry time.Time
	if claims.Expiry != nil {
		expiry = time.Unix(*claims.Expiry, 0)
		if !now.Before(expiry) {
			return expiry, false
		}
	}
	return expiry, claims.NotBefore == nil || !now.Before(time.Unix(*claims.NotBefore, 0))
}

// Unverified expiry may only shorten a successful online review's cache lifetime.
func tokenExpiry(token string) time.Time {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}
	}
	var claims tokenTimes
	if json.Unmarshal(payload, &claims) != nil || claims.Expiry == nil {
		return time.Time{}
	}
	return time.Unix(*claims.Expiry, 0)
}
