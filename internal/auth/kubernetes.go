package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	proxy "github.com/rophy/aqsh/internal/kubeauthproxy"
)

type Kubernetes struct {
	cluster    string
	config     ClusterConfig
	audiences  []string
	client     *http.Client
	reviewer   proxy.TokenReviewer
	timeout    time.Duration
	federation *federatedReviewer
	cancel     context.CancelFunc
	done       chan struct{}
}

func New(cfg Config) (*Kubernetes, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	k := &Kubernetes{audiences: append([]string(nil), cfg.Audiences...), timeout: cfg.RequestTimeout}
	if cfg.FederationConfig != "" {
		reviewer, err := newFederatedReviewer(cfg)
		if err != nil {
			return nil, err
		}
		k.reviewer, k.federation = reviewer, reviewer
		return k, nil
	}
	for id, cluster := range cfg.Clusters {
		client, err := newClient(cluster.CAFile, cfg)
		if err != nil {
			return nil, fmt.Errorf("cluster %q: %w", id, err)
		}
		if _, err := readToken(cluster.TokenFile); err != nil {
			return nil, fmt.Errorf("cluster %q: %w", id, err)
		}
		k.cluster, k.config, k.client = id, cluster, client
		k.reviewer = proxy.NewHTTPTokenReviewer(strings.TrimRight(cluster.APIServer, "/")+"/apis/authentication.k8s.io/v1/tokenreviews", client, cluster.TokenFile, k.audiences)
	}
	return k, nil
}

func newClient(caFile string, cfg Config) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		ca, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("reading CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return nil, fmt.Errorf("invalid CA certificate")
		}
		transport.TLSClientConfig.RootCAs = pool
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
	result, err := k.reviewer.Review(ctx, token)
	if err != nil {
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
	cluster := k.cluster
	if k.federation != nil {
		source := status.User.Extra[proxy.ExtraKeyClusterName]
		if len(source) != 1 {
			return Principal{}, ErrUnauthenticated
		}
		if _, ok := k.federation.config.Clusters[source[0]]; !ok {
			return Principal{}, ErrUnauthenticated
		}
		cluster = source[0]
	}
	return Principal{Provider: "kubernetes", Cluster: cluster, Username: status.User.Username, UID: status.User.UID, Groups: status.User.Groups}, nil
}

// Start connects the original renewal loop to the API lifetime.
func (k *Kubernetes) Start(ctx context.Context) error {
	if k.federation == nil {
		return nil
	}
	if k.cancel != nil {
		return fmt.Errorf("credential renewal already started")
	}
	ctx, k.cancel = context.WithCancel(ctx)
	k.done = make(chan struct{})
	go func() {
		defer close(k.done)
		k.federation.store.Run(ctx, k.federation)
	}()
	return nil
}

func (k *Kubernetes) Close() {
	if k.cancel != nil {
		k.cancel()
		<-k.done
	}
	if k.client != nil {
		k.client.CloseIdleConnections()
	}
}
