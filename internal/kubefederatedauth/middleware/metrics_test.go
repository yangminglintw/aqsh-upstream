package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func counterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	m := &dto.Metric{}
	if err := c.(prometheus.Metric).Write(m); err != nil {
		t.Fatalf("failed to write metric: %v", err)
	}
	return m.Counter.GetValue()
}

func TestMetricsMiddleware(t *testing.T) {
	requestsTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "test_http_requests_total",
	}, []string{"method", "path", "status"})
	requestDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "test_http_request_duration_seconds",
	}, []string{"method", "path"})

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := MetricsMiddleware(requestsTotal, requestDuration)(inner)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	c, err := requestsTotal.GetMetricWithLabelValues("GET", "/health", "200")
	if err != nil {
		t.Fatalf("failed to get metric: %v", err)
	}
	if v := counterValue(t, c); v != 1 {
		t.Errorf("counter = %v, want 1", v)
	}
}

func TestMetricsMiddleware_RecordsStatus(t *testing.T) {
	requestsTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "test2_http_requests_total",
	}, []string{"method", "path", "status"})
	requestDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "test2_http_request_duration_seconds",
	}, []string{"method", "path"})

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	handler := MetricsMiddleware(requestsTotal, requestDuration)(inner)

	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	c, err := requestsTotal.GetMetricWithLabelValues("POST", "/test", "404")
	if err != nil {
		t.Fatalf("failed to get metric: %v", err)
	}
	if v := counterValue(t, c); v != 1 {
		t.Errorf("counter = %v, want 1", v)
	}
}
