// Package admin implements the kproxyd admin API and its client. The admin
// API issues, revokes and lists API keys, authenticated with a shared admin
// key via Bearer tokens. It is served on a separate listener (loopback by
// default) so it never mixes with public tunnel traffic.
package admin

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"kproxy/internal/relay"
	"kproxy/internal/store"
	"kproxy/internal/units"
)

// ParseTTL parses a duration string. It accepts Go durations plus the "d"
// (days) and "w" (weeks) suffixes. An empty, "0" or "none" value means no
// expiry.
func ParseTTL(s string) (time.Duration, error) {
	return units.ParseTTL(s)
}

// ParseSize parses a byte size such as "512kb", "1mb" or "2.5gb" (binary
// units). An empty value means zero. A bare number is treated as bytes.
func ParseSize(s string) (int64, error) {
	return units.ParseSize(s)
}

// NewHandler returns the admin HTTP handler for the key API. adminKey
// authenticates every request; an empty adminKey disables the API (503).
func NewHandler(st *store.Store, adminKey string) http.Handler {
	return Auth(KeyRoutes(st), adminKey)
}

// KeyRoutes mounts the key CRUD endpoints under /api/v1/keys without any
// authentication. Wrap it with Auth (or NewHandler) before exposing it.
func KeyRoutes(st *store.Store) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/keys", handleCreate(st))
	mux.HandleFunc("DELETE /api/v1/keys/{id}", handleRevoke(st))
	mux.HandleFunc("GET /api/v1/keys", handleList(st))
	return mux
}

// Auth wraps next with Bearer-token authentication against adminKey. The token
// may come from the Authorization header or the ?token= query parameter (for
// SSE, where EventSource cannot set headers).
func Auth(next http.Handler, adminKey string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if adminKey == "" {
			http.Error(w, "admin api disabled (no --admin-key)", http.StatusServiceUnavailable)
			return
		}
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token == "" {
			token = r.URL.Query().Get("token")
		}
		if subtle.ConstantTimeCompare([]byte(token), []byte(adminKey)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type createRequest struct {
	Name       string   `json:"name"`
	TTL        string   `json:"ttl,omitempty"`
	Rate       int      `json:"rate,omitempty"`
	Bandwidth  string   `json:"bandwidth,omitempty"`
	Subdomains []string `json:"subdomains,omitempty"`
}

func handleCreate(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req createRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		ttl, err := ParseTTL(req.TTL)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		bw, err := ParseSize(req.Bandwidth)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		limits := store.Limits{
			RequestsPerSec:    req.Rate,
			BandwidthPerSec:   bw,
			AllowedSubdomains: req.Subdomains,
		}
		info, secret, err := st.Create(req.Name, ttl, limits)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"key":    info,
			"secret": secret,
		})
	}
}

func handleRevoke(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := st.Revoke(id); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func handleList(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"keys": st.List()})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Client talks to a kproxyd admin API.

// CreateOptions describes a key to create. Empty fields mean "no limit".
type CreateOptions struct {
	Name       string
	TTL        string
	Rate       int
	Bandwidth  string
	Subdomains []string
}

// CreateKey issues a new key. Returns the public info and the plaintext
// secret.
func CreateKey(baseURL, adminKey string, opts CreateOptions) (store.KeyInfo, string, error) {
	body, _ := json.Marshal(createRequest{
		Name:       opts.Name,
		TTL:        opts.TTL,
		Rate:       opts.Rate,
		Bandwidth:  opts.Bandwidth,
		Subdomains: opts.Subdomains,
	})
	resp, err := doJSON(baseURL, adminKey, "POST", "/api/v1/keys", body)
	if err != nil {
		return store.KeyInfo{}, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return store.KeyInfo{}, "", apiError(resp)
	}
	var out struct {
		Key    store.KeyInfo `json:"key"`
		Secret string        `json:"secret"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return store.KeyInfo{}, "", err
	}
	return out.Key, out.Secret, nil
}

// RevokeKey revokes a key by ID.
func RevokeKey(baseURL, adminKey, id string) error {
	resp, err := doJSON(baseURL, adminKey, "DELETE", "/api/v1/keys/"+id, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return apiError(resp)
	}
	return nil
}

// ListKeys returns all keys.
func ListKeys(baseURL, adminKey string) ([]store.KeyInfo, error) {
	resp, err := doJSON(baseURL, adminKey, "GET", "/api/v1/keys", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, apiError(resp)
	}
	var out struct {
		Keys []store.KeyInfo `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Keys, nil
}

// DomainToken returns the DNS TXT verification token for a custom domain.
func DomainToken(baseURL, adminKey, domain string) (string, error) {
	resp, err := doJSON(baseURL, adminKey, "GET", "/api/v1/domains/"+domain+"/token", nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", apiError(resp)
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.Token, nil
}

// ListRequests returns up to limit recently proxied requests (newest first)
// from the relay's bounded replay log. A limit of 0 returns all retained
// entries.
func ListRequests(baseURL, adminKey string, limit int) ([]relay.RequestInfo, error) {
	path := "/api/v1/requests"
	if limit > 0 {
		path += "?limit=" + strconv.Itoa(limit)
	}
	resp, err := doJSON(baseURL, adminKey, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, apiError(resp)
	}
	var out struct {
		Requests []relay.RequestInfo `json:"requests"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Requests, nil
}

func doJSON(baseURL, adminKey, method, path string, body []byte) (*http.Response, error) {
	req, err := http.NewRequest(method, strings.TrimRight(baseURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+adminKey)
	req.Header.Set("Content-Type", "application/json")
	return http.DefaultClient.Do(req)
}

func apiError(resp *http.Response) error {
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	text := strings.TrimSpace(string(msg))
	if text == "" {
		text = resp.Status
	}
	return errors.New(text)
}
