package handler

import (
	"encoding/json"
	"net/http"
)

// ClusterStatusProvider reports which clusters are in a degraded state.
type ClusterStatusProvider interface {
	DegradedClusters() map[string]string
}

type HealthResponse struct {
	Status   string            `json:"status"`
	Version  string            `json:"version"`
	Clusters map[string]string `json:"clusters,omitempty"`
}

type HealthHandler struct {
	version  string
	provider ClusterStatusProvider
}

func NewHealthHandler(version string, provider ClusterStatusProvider) *HealthHandler {
	return &HealthHandler{version: version, provider: provider}
}

func (h *HealthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	status := "ok"
	var clusters map[string]string
	if h.provider != nil {
		if degraded := h.provider.DegradedClusters(); len(degraded) > 0 {
			status = "degraded"
			clusters = degraded
		}
	}

	json.NewEncoder(w).Encode(HealthResponse{
		Status:   status,
		Version:  h.version,
		Clusters: clusters,
	})
}
