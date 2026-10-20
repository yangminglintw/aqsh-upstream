package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

type Kubernetes struct {
	clusters    []*cluster
	audiences   []string
	audienceKey string
	timeout     time.Duration
	cache       *reviewCache
	credentials *credentialManager
}

type cluster struct {
	id     string
	config ClusterConfig
	client *http.Client
	keys   *keyCache
	tokens *tokenSource
}

type tokenReview struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Spec       struct {
		Token     string   `json:"token"`
		Audiences []string `json:"audiences"`
	} `json:"spec"`
	Status struct {
		Authenticated bool     `json:"authenticated"`
		Audiences     []string `json:"audiences"`
		User          userInfo `json:"user"`
		Error         string   `json:"error"`
	} `json:"status,omitempty"`
}

type userInfo struct {
	Username string   `json:"username"`
	UID      string   `json:"uid"`
	Groups   []string `json:"groups"`
}

func New(cfg Config) (*Kubernetes, error) {
	// Freeze caller-owned maps, slices and renewal settings before applying defaults.
	clusters := make(map[string]ClusterConfig, len(cfg.Clusters))
	for id, c := range cfg.Clusters {
		if c.Renewal != nil {
			r := *c.Renewal
			r.Audiences = append([]string(nil), r.Audiences...)
			c.Renewal = &r
		}
		clusters[id] = c
	}
	cfg.Clusters = clusters
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	k := &Kubernetes{audiences: append([]string(nil), cfg.Audiences...), timeout: cfg.RequestTimeout, cache: newReviewCache(cfg.CacheSize, cfg.CacheTTL)}
	sort.Strings(k.audiences)
	key, _ := json.Marshal(k.audiences)
	k.audienceKey = string(key)
	ids := make([]string, 0, len(cfg.Clusters))
	for id := range cfg.Clusters {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		cc := cfg.Clusters[id]
		client, err := newClient(cc.CAFile, cfg)
		if err != nil {
			k.Close()
			return nil, fmt.Errorf("cluster %q: %w", id, err)
		}
		if _, err := readToken(cc.TokenFile); err != nil {
			client.CloseIdleConnections()
			k.Close()
			return nil, fmt.Errorf("cluster %q: %w", id, err)
		}
		k.clusters = append(k.clusters, &cluster{id: id, config: cc, client: client, keys: &keyCache{}, tokens: &tokenSource{path: cc.TokenFile}})
	}
	for _, c := range k.clusters {
		if c.config.Renewal != nil {
			k.credentials = &credentialManager{interval: cfg.RenewalInterval}
			break
		}
	}
	if p := cfg.Persistence; p != nil {
		client, err := newClient(p.CAFile, cfg)
		if err != nil {
			k.Close()
			return nil, err
		}
		if _, err := readToken(p.TokenFile); err != nil {
			client.CloseIdleConnections()
			k.Close()
			return nil, err
		}
		k.credentials.storage = &cluster{config: ClusterConfig{APIServer: p.APIServer}, client: client, tokens: &tokenSource{path: p.TokenFile}}
		k.credentials.path = "/api/v1/namespaces/" + p.Namespace + "/secrets/" + p.Secret
	}
	return k, nil
}

func newClient(caFile string, cfg Config) (*http.Client, error) {
	transport := &fileTransport{path: caFile}
	if _, err := transport.transport(); err != nil {
		return nil, err
	}
	return &http.Client{
		Transport: transport,
		Timeout:   cfg.RequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

func readToken(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading reviewer token: %w", err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" || strings.ContainsAny(token, "\r\n \t") {
		return "", fmt.Errorf("empty or malformed reviewer token")
	}
	return token, nil
}

func (k *Kubernetes) Authenticate(ctx context.Context, token string) (Principal, error) {
	ctx, cancel := context.WithTimeout(ctx, k.timeout)
	defer cancel()
	c, expiry, err := k.route(ctx, token)
	if err != nil {
		return Principal{}, err
	}
	key := reviewKey{Cluster: c.id, Token: tokenHash(token), Audiences: k.audienceKey}
	if p, ok := k.cache.get(key); ok {
		return p, nil
	}
	p, err := k.review(ctx, c, token)
	if err == nil {
		k.cache.put(key, p, expiry)
	}
	return p, err
}

func (k *Kubernetes) review(ctx context.Context, c *cluster, token string) (Principal, error) {
	reviewer, err := c.tokens.token()
	if err != nil {
		return Principal{}, ErrUnavailable
	}
	tr := tokenReview{APIVersion: "authentication.k8s.io/v1", Kind: "TokenReview"}
	tr.Spec.Token, tr.Spec.Audiences = token, k.audiences
	body, _ := json.Marshal(tr)
	data, err := c.call(ctx, http.MethodPost, "/apis/authentication.k8s.io/v1/tokenreviews", "application/json", body, reviewer)
	var result tokenReview
	if err != nil || json.Unmarshal(data, &result) != nil {
		return Principal{}, ErrUnavailable
	}
	status := result.Status
	// Existing task environments and values_url represent groups as CSV. Reject
	// ambiguous names rather than turn one verified group into multiple groups.
	for _, group := range status.User.Groups {
		if group == "" || strings.TrimSpace(group) != group || strings.ContainsAny(group, ",\r\n") {
			return Principal{}, ErrUnauthenticated
		}
	}
	if !status.Authenticated || status.Error != "" || status.User.Username == "" || status.User.UID == "" {
		return Principal{}, ErrUnauthenticated
	}
	if !slices.ContainsFunc(status.Audiences, func(a string) bool { return slices.Contains(k.audiences, a) }) {
		return Principal{}, ErrUnauthenticated
	}
	return Principal{Provider: "kubernetes", Cluster: c.id, Username: status.User.Username, UID: status.User.UID, Groups: status.User.Groups}, nil
}

func (k *Kubernetes) Close() {
	if m := k.credentials; m != nil {
		if m.cancel != nil {
			m.cancel()
			<-m.done
		}
		if m.storage != nil {
			m.storage.client.CloseIdleConnections()
		}
	}
	for _, c := range k.clusters {
		c.client.CloseIdleConnections()
	}
}

func (k *Kubernetes) route(ctx context.Context, token string) (*cluster, time.Time, error) {
	if len(k.clusters) == 1 && k.clusters[0].config.JWKSURL == "" {
		return k.clusters[0], tokenExpiry(token), nil
	}
	jws, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256, jose.ES256, jose.ES384, jose.ES512, jose.EdDSA})
	if err != nil || len(jws.Signatures) != 1 {
		return nil, time.Time{}, ErrUnauthenticated
	}
	var matched *cluster
	var expiry time.Time
	unavailable := false
	for _, c := range k.clusters {
		payload, err := c.verify(ctx, jws)
		if err != nil {
			unavailable = true
			continue
		}
		if payload == nil {
			continue
		}
		exp, valid := validTimes(payload, time.Now())
		if !valid || matched != nil {
			return nil, time.Time{}, ErrUnauthenticated
		}
		matched, expiry = c, exp
	}
	if unavailable {
		return nil, time.Time{}, ErrUnavailable
	}
	if matched == nil {
		return nil, time.Time{}, ErrUnauthenticated
	}
	return matched, expiry, nil
}
