package server_test

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kproxy/internal/agent"
	"kproxy/internal/protocol"
	"kproxy/internal/relay"
	"kproxy/internal/server"
	"kproxy/internal/store"
)

func TestControlAPI(t *testing.T) {
	keyStore, err := store.Open(filepath.Join(t.TempDir(), "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	_, secret, err := keyStore.Create("tester", 0, store.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	srv := relay.New(relay.Config{
		Domain:   "kproxy.test",
		Scheme:   "http",
		TCPStart: 30000,
		TCPEnd:   39999,
		Keys:     keyStore,
	})
	h, err := server.NewHandler(srv, keyStore, "boot-secret")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(h)
	defer ts.Close()

	// Unauthorized requests are rejected.
	resp, err := http.Get(ts.URL + "/api/v1/tunnels")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d, want 401", resp.StatusCode)
	}

	// Authorized list is empty initially.
	resp = doAuth(t, ts.URL, "boot-secret", "GET", "/api/v1/tunnels", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("tunnels status = %d", resp.StatusCode)
	}
	var listing struct {
		Tunnels []relay.TunnelInfo `json:"tunnels"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listing); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(listing.Tunnels) != 0 {
		t.Fatalf("expected no tunnels, got %+v", listing.Tunnels)
	}

	// Key CRUD over the versioned API.
	resp = doAuth(t, ts.URL, "boot-secret", "POST", "/api/v1/keys", strings.NewReader(`{"name":"bob"}`))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create key status = %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Bring up a live agent so the tunnels list and event stream have data.
	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer httpLn.Close()
	hs := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go hs.Serve(httpLn)
	t.Cleanup(func() { hs.Close() })

	ctrlLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ctrlLn.Close()
	go func() {
		for {
			conn, err := ctrlLn.Accept()
			if err != nil {
				return
			}
			go srv.HandleAgent(conn)
		}
	}()

	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer local.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	welCh := make(chan protocol.Welcome, 1)
	ag := agent.New(agent.Config{
		ServerURL: "http://" + ctrlLn.Addr().String(),
		APIKey:    secret,
		Tunnels:   []protocol.TunnelSpec{{ID: "main", Proto: "http", Local: strings.TrimPrefix(local.URL, "http://")}},
		OnWelcome: func(w protocol.Welcome) { welCh <- w },
	})
	go ag.Run(ctx)
	var w protocol.Welcome
	select {
	case w = <-welCh:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for welcome")
	}
	host := strings.TrimPrefix(w.Tunnels[0].PublicURL, "http://")

	// Tunnels list now shows the tunnel.
	resp = doAuth(t, ts.URL, "boot-secret", "GET", "/api/v1/tunnels", nil)
	if err := json.NewDecoder(resp.Body).Decode(&listing); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(listing.Tunnels) != 1 || listing.Tunnels[0].Host != host {
		t.Fatalf("tunnels = %+v, want host %s", listing.Tunnels, host)
	}

	// SSE stream (token via query) receives a request event.
	streamResp, err := http.Get(ts.URL + "/api/v1/tunnels/stream?token=boot-secret")
	if err != nil {
		t.Fatal(err)
	}
	defer streamResp.Body.Close()
	if ct := streamResp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("stream content-type = %q", ct)
	}
	events := make(chan string, 16)
	go func() {
		sc := bufio.NewScanner(streamResp.Body)
		for sc.Scan() {
			if line := sc.Text(); strings.HasPrefix(line, "event: ") {
				events <- strings.TrimPrefix(line, "event: ")
			}
		}
	}()

	req, err := http.NewRequest("GET", "http://"+httpLn.Addr().String()+"/hit", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = host
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()

	select {
	case ev := <-events:
		if ev != "request" {
			t.Fatalf("expected request event, got %q", ev)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for request event on SSE stream")
	}
}

func doAuth(t *testing.T, baseURL, key, method, path string, body io.Reader) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, baseURL+path, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestStatusAndDomainToken(t *testing.T) {
	keyStore, err := store.Open(filepath.Join(t.TempDir(), "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv := relay.New(relay.Config{Domain: "kproxy.test", VerifyKey: "verify-secret", Keys: keyStore})
	h, err := server.NewHandler(srv, keyStore, "boot-secret")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(h)
	defer ts.Close()

	// Status requires admin auth.
	resp := doAuth(t, ts.URL, "boot-secret", "GET", "/api/v1/status", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status status = %d", resp.StatusCode)
	}
	var st relay.Status
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if st.Uptime < 0 || st.Tunnels != 0 || st.Agents != 0 || st.Requests != 0 || st.Bytes != 0 {
		t.Fatalf("status = %+v", st)
	}

	resp = httpGet(t, ts.URL, "/api/v1/status")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	// Domain token is issued when verification is enabled.
	resp = doAuth(t, ts.URL, "boot-secret", "GET", "/api/v1/domains/example.com/token", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token status = %d", resp.StatusCode)
	}
	var tok struct {
		Domain string `json:"domain"`
		Token  string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if tok.Domain != "example.com" || !strings.HasPrefix(tok.Token, "kproxy-verify-") {
		t.Fatalf("token payload = %+v", tok)
	}
	// Same domain yields a stable token (deterministic derivation).
	resp2 := doAuth(t, ts.URL, "boot-secret", "GET", "/api/v1/domains/example.com/token", nil)
	var tok2 struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&tok2); err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if tok2.Token != tok.Token {
		t.Fatalf("token not stable: %q vs %q", tok.Token, tok2.Token)
	}

	// Missing domain is a client error.
	resp = doAuth(t, ts.URL, "boot-secret", "GET", "/api/v1/domains//token", nil)
	if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusNotFound {
		t.Fatalf("missing-domain status = %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Verification disabled => 503 with a hint.
	srv2 := relay.New(relay.Config{Domain: "kproxy.test", Keys: keyStore})
	defer srv2.Close()
	h2, err := server.NewHandler(srv2, keyStore, "boot-secret")
	if err != nil {
		t.Fatal(err)
	}
	ts2 := httptest.NewServer(h2)
	defer ts2.Close()
	resp = doAuth(t, ts2.URL, "boot-secret", "GET", "/api/v1/domains/example.com/token", nil)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("disabled status = %d, want 503", resp.StatusCode)
	}
	resp.Body.Close()
}

func httpGet(t *testing.T, baseURL, path string) *http.Response {
	t.Helper()
	resp, err := http.Get(baseURL + path)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}
