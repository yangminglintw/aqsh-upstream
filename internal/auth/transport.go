package auth

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"sync"
)

// fileTransport swaps immutable TLS transports when a mounted CA bundle changes.
// A missing/invalid new bundle fails closed instead of retaining stale trust.
type fileTransport struct {
	mu      sync.Mutex
	path    string
	digest  [32]byte
	current *http.Transport
}

func (f *fileTransport) transport() (*http.Transport, error) {
	var ca []byte
	if f.path != "" {
		var err error
		ca, err = os.ReadFile(f.path)
		if err != nil {
			return nil, fmt.Errorf("reading reviewer CA: %w", err)
		}
	}
	digest := sha256.Sum256(ca)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.current != nil && f.digest == digest {
		return f.current, nil
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if f.path != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return nil, fmt.Errorf("invalid reviewer CA certificate")
		}
		t.TLSClientConfig.RootCAs = pool
	}
	if f.current != nil {
		f.current.CloseIdleConnections()
	}
	f.current, f.digest = t, digest
	return t, nil
}

func (f *fileTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t, err := f.transport()
	if err != nil {
		return nil, err
	}
	return t.RoundTrip(r)
}

func (f *fileTransport) CloseIdleConnections() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.current != nil {
		f.current.CloseIdleConnections()
	}
}
