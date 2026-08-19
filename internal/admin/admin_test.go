package admin

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"kproxy/internal/store"
)

func newServer(t *testing.T, adminKey string) *httptest.Server {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(NewHandler(st, adminKey))
	t.Cleanup(ts.Close)
	return ts
}

func do(t *testing.T, url, adminKey, method, path, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+adminKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestCreateRequiresAuth(t *testing.T) {
	ts := newServer(t, "boot-secret")
	resp := do(t, ts.URL, "", "POST", "/api/v1/keys", `{"name":"x"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestAdminDisabled(t *testing.T) {
	ts := newServer(t, "")
	resp := do(t, ts.URL, "boot-secret", "GET", "/api/v1/keys", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
}

func TestCreateListRevoke(t *testing.T) {
	ts := newServer(t, "boot-secret")

	resp := do(t, ts.URL, "boot-secret", "POST", "/api/v1/keys", `{"name":"alice","ttl":"30d"}`)
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create status = %d body=%s", resp.StatusCode, b)
	}
	var created struct {
		Key    store.KeyInfo `json:"key"`
		Secret string        `json:"secret"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !strings.HasPrefix(created.Secret, "kproxy_") {
		t.Fatalf("secret = %q", created.Secret)
	}
	if created.Key.ExpiresAt.IsZero() {
		t.Fatal("expected expires_at for ttl=30d")
	}

	resp = do(t, ts.URL, "boot-secret", "GET", "/api/v1/keys", "")
	var listed struct {
		Keys []store.KeyInfo `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listed); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(listed.Keys) != 1 || listed.Keys[0].ID != created.Key.ID {
		t.Fatalf("listed keys = %+v", listed.Keys)
	}

	resp = do(t, ts.URL, "boot-secret", "DELETE", "/api/v1/keys/"+created.Key.ID, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke status = %d, want 204", resp.StatusCode)
	}

	resp = do(t, ts.URL, "boot-secret", "DELETE", "/v1/keys/k_doesnotexist", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("revoke unknown status = %d, want 404", resp.StatusCode)
	}
}

func TestParseTTL(t *testing.T) {
	cases := []struct {
		in   string
		want string
		err  bool
	}{
		{"", "0s", false},
		{"0", "0s", false},
		{"none", "0s", false},
		{"24h", "24h0m0s", false},
		{"30d", "720h0m0s", false},
		{"2w", "336h0m0s", false},
		{"90", "0s", true},
		{"soon", "0s", true},
		{"-1h", "0s", true},
	}
	for _, c := range cases {
		got, err := ParseTTL(c.in)
		if c.err {
			if err == nil {
				t.Fatalf("ParseTTL(%q) expected error", c.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ParseTTL(%q): %v", c.in, err)
		}
		if got.String() != c.want {
			t.Fatalf("ParseTTL(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestCreateWithLimits(t *testing.T) {
	ts := newServer(t, "boot-secret")
	resp := do(t, ts.URL, "boot-secret", "POST", "/api/v1/keys",
		`{"name":"limited","rate":50,"bandwidth":"1mb","subdomains":["api","staging"]}`)
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create status = %d body=%s", resp.StatusCode, b)
	}
	var created struct {
		Key store.KeyInfo `json:"key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if created.Key.Limits.RequestsPerSec != 50 {
		t.Fatalf("requests_per_sec = %d", created.Key.Limits.RequestsPerSec)
	}
	if created.Key.Limits.BandwidthPerSec != 1<<20 {
		t.Fatalf("bandwidth_per_sec = %d", created.Key.Limits.BandwidthPerSec)
	}
	if len(created.Key.Limits.AllowedSubdomains) != 2 || created.Key.Limits.AllowedSubdomains[0] != "api" {
		t.Fatalf("allowed_subdomains = %v", created.Key.Limits.AllowedSubdomains)
	}

	resp = do(t, ts.URL, "boot-secret", "POST", "/api/v1/keys", `{"name":"b","bandwidth":"bogus"}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad bandwidth status = %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestParseSize(t *testing.T) {
	cases := []struct {
		in   string
		want int64
		err  bool
	}{
		{"", 0, false},
		{"512kb", 512 << 10, false},
		{"1mb", 1 << 20, false},
		{"2.5gb", int64(2.5 * (1 << 30)), false},
		{"100", 100, false},
		{"nope", 0, true},
	}
	for _, c := range cases {
		got, err := ParseSize(c.in)
		if c.err {
			if err == nil {
				t.Fatalf("ParseSize(%q) expected error", c.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ParseSize(%q): %v", c.in, err)
		}
		if got != c.want {
			t.Fatalf("ParseSize(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}
