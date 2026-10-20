package auth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Each cluster owns a key set. kid values never select a global cluster owner.
type keyCache struct {
	mu           sync.Mutex
	keys         []jose.JSONWebKey
	expires      time.Time
	refreshAfter time.Time
	inflight     chan struct{}
	err          error
}

func (c *cluster) verify(ctx context.Context, jws *jose.JSONWebSignature) ([]byte, error) {
	keys, err := c.loadKeys(ctx, false)
	if err != nil {
		return nil, err
	}
	if payload := verifyKeys(keys, jws); payload != nil {
		return payload, nil
	}
	keys, err = c.loadKeys(ctx, true)
	if err != nil {
		return nil, err
	}
	return verifyKeys(keys, jws), nil
}

func verifyKeys(keys []jose.JSONWebKey, jws *jose.JSONWebSignature) []byte {
	header := jws.Signatures[0].Header
	for _, key := range keys {
		if (header.KeyID != "" && key.KeyID != header.KeyID) || (key.Algorithm != "" && key.Algorithm != header.Algorithm) || (key.Use != "" && key.Use != "sig") {
			continue
		}
		if payload, err := jws.Verify(key.Key); err == nil {
			return payload
		}
	}
	return nil
}

func (c *cluster) loadKeys(ctx context.Context, force bool) ([]jose.JSONWebKey, error) {
	k := c.keys
	k.mu.Lock()
	now := time.Now()
	if (!force && now.Before(k.expires)) || ((force || k.err != nil) && now.Before(k.refreshAfter)) {
		keys, err := k.keys, k.err
		k.mu.Unlock()
		return keys, err
	}
	if done := k.inflight; done != nil {
		k.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-done:
		}
		k.mu.Lock()
		keys, err := k.keys, k.err
		k.mu.Unlock()
		return keys, err
	}
	done := make(chan struct{})
	k.inflight = done
	k.mu.Unlock()
	keys, err := c.fetchKeys(ctx)
	k.mu.Lock()
	if err == nil {
		k.keys = keys
		k.expires = time.Now().Add(5 * time.Minute)
	} else {
		k.expires = time.Time{}
	}
	k.err = err
	k.refreshAfter = time.Now().Add(5 * time.Second)
	k.inflight = nil
	close(done)
	k.mu.Unlock()
	return keys, err
}

func (c *cluster) fetchKeys(ctx context.Context) ([]jose.JSONWebKey, error) {
	reviewer, err := c.tokens.token()
	if err != nil {
		return nil, ErrUnavailable
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.config.JWKSURL, nil)
	if err != nil {
		return nil, ErrUnavailable
	}
	req.Header.Set("Authorization", "Bearer "+reviewer)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, ErrUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	var set jose.JSONWebKeySet
	if err != nil || len(data) > 1<<20 || json.Unmarshal(data, &set) != nil || len(set.Keys) == 0 || len(set.Keys) > 128 {
		return nil, ErrUnavailable
	}
	for _, key := range set.Keys {
		if !key.IsPublic() || !key.Valid() {
			return nil, ErrUnavailable
		}
	}
	return set.Keys, nil
}
