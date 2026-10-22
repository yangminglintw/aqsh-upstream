package server

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rophy/aqsh/internal/kubefederatedauth/config"
	"github.com/rophy/aqsh/internal/kubefederatedauth/credentials"
	"github.com/rophy/aqsh/internal/kubefederatedauth/handler"
	"github.com/rophy/aqsh/internal/kubefederatedauth/metrics"
	mw "github.com/rophy/aqsh/internal/kubefederatedauth/middleware"
	"github.com/rophy/aqsh/internal/kubefederatedauth/oidc"
)

// Server holds the HTTP handler and verifier manager
type Server struct {
	Handler  http.Handler
	Verifier *oidc.VerifierManager
}

func New(cfg *config.Config, credStore *credentials.Store, version string) *Server {
	m := metrics.New(version, cfg.ClientMetricsEnabled())

	verifier := oidc.NewVerifierManager(cfg, credStore)
	verifier.SetMetrics(m.ClusterDegraded)
	verifier.WarmUp(context.Background())

	credStore.SetMetrics(m.CredentialRenewalTotal, m.CredentialExpirySeconds)

	logged := mw.RequestLogger(slog.Default())
	metricsMiddleware := mw.MetricsMiddleware(m.HTTPRequestsTotal, m.HTTPRequestDuration)

	trHandler := handler.NewTokenReviewHandler(verifier, cfg, credStore, verifier)
	trHandler.SetMetrics(m.CacheRequestsTotal, m.CacheEntries)
	trHandler.SetTokenReviewMetrics(m)

	mux := http.NewServeMux()

	// Metrics endpoint without request logging or metrics middleware
	mux.Handle("GET /metrics", promhttp.Handler())

	// Health endpoint without request logging to avoid spam from probes
	mux.Handle("GET /health", metricsMiddleware(handler.NewHealthHandler(version, verifier)))

	// Routes with slog-based request logging and metrics
	mux.Handle("GET /clusters", metricsMiddleware(logged(handler.NewClustersHandler(cfg, credStore))))
	mux.Handle("POST /apis/authentication.k8s.io/v1/tokenreviews", metricsMiddleware(logged(trHandler)))

	return &Server{
		Handler:  mw.Recoverer(mux),
		Verifier: verifier,
	}
}
