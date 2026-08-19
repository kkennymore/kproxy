// Package server hosts the kproxyd control plane: the versioned REST API
// (/api/v1/...) consumed by the admin CLI and the dashboard, plus the embedded
// React dashboard itself.
package server

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"time"

	"kproxy/internal/admin"
	"kproxy/internal/relay"
	"kproxy/internal/store"
)

//go:embed dashboard
var dashboardFS embed.FS

// NewHandler builds the control-plane handler: key CRUD (delegated to
// internal/admin), live tunnel/request endpoints, and the embedded dashboard.
func NewHandler(rly *relay.Server, st *store.Store, adminKey string) (http.Handler, error) {
	sub, err := fs.Sub(dashboardFS, "dashboard")
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	keys := admin.NewHandler(st, adminKey)
	mux.Handle("/api/v1/keys", keys)
	mux.Handle("/api/v1/keys/", keys)
	mux.Handle("GET /api/v1/tunnels", admin.Auth(http.HandlerFunc(handleTunnels(rly)), adminKey))
	mux.Handle("GET /api/v1/tunnels/stream", admin.Auth(http.HandlerFunc(handleStream(rly)), adminKey))
	mux.Handle("GET /api/v1/status", admin.Auth(http.HandlerFunc(handleStatus(rly)), adminKey))
	mux.Handle("GET /api/v1/domains/{domain}/token", admin.Auth(http.HandlerFunc(handleDomainToken(rly)), adminKey))
	mux.Handle("GET /metrics", admin.Auth(rly.MetricsHandler(), adminKey))
	mux.Handle("/", http.FileServerFS(sub))
	return mux, nil
}

func handleStatus(rly *relay.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, rly.Status())
	}
}

// handleDomainToken returns the DNS TXT verification token an operator sets
// at _kproxy.<domain> to prove they control a custom domain.
func handleDomainToken(rly *relay.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		domain := r.PathValue("domain")
		if domain == "" {
			http.Error(w, "missing domain", http.StatusBadRequest)
			return
		}
		token := rly.VerifyToken(domain)
		if token == "" {
			http.Error(w, "domain verification is disabled (set --verify-key)", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"domain": domain, "token": token})
	}
}

func handleTunnels(rly *relay.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"tunnels": rly.Tunnels()})
	}
}

// handleStream serves relay events as Server-Sent Events. Auth is applied via
// the ?token= query parameter because EventSource cannot set headers.
func handleStream(rly *relay.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming not supported", http.StatusInternalServerError)
			return
		}
		ch, unsub := rly.Subscribe()
		defer unsub()

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(http.StatusOK)
		flusher.Flush()

		heartbeat := time.NewTicker(15 * time.Second)
		defer heartbeat.Stop()

		for {
			select {
			case <-r.Context().Done():
				return
			case <-heartbeat.C:
				_, _ = io.WriteString(w, ": heartbeat\n\n")
				flusher.Flush()
			case e := <-ch:
				b, err := json.Marshal(e)
				if err != nil {
					continue
				}
				_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", e.Type, b)
				flusher.Flush()
			}
		}
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
