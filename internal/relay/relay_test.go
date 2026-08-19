package relay_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kproxy/internal/agent"
	"kproxy/internal/protocol"
	"kproxy/internal/relay"
)

type testEnv struct {
	t           *testing.T
	srv         *relay.Server
	httpAddr    string
	controlAddr string
	httpSrv     *http.Server
	ctrlLn      net.Listener
}

func newEnv(t *testing.T) *testEnv {
	t.Helper()
	srv := relay.New(relay.Config{
		Domain:   "kproxy.test",
		Scheme:   "http",
		TCPStart: 30000,
		TCPEnd:   39999,
	})

	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go hs.Serve(httpLn)

	ctrlLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ctrlLn.Accept()
			if err != nil {
				return
			}
			go srv.HandleAgent(conn)
		}
	}()

	e := &testEnv{t: t, srv: srv, httpAddr: httpLn.Addr().String(), controlAddr: ctrlLn.Addr().String(), httpSrv: hs, ctrlLn: ctrlLn}
	t.Cleanup(func() {
		ctrlLn.Close()
		hs.Close()
		_ = srv.Close()
	})
	return e
}

func (e *testEnv) startAgent(t *testing.T, tunnels []protocol.TunnelSpec) <-chan protocol.Welcome {
	t.Helper()
	wel := make(chan protocol.Welcome, 1)
	ag := agent.New(agent.Config{
		ServerURL: "http://" + e.controlAddr,
		Tunnels:   tunnels,
		OnWelcome: func(w protocol.Welcome) { wel <- w },
	})
	ctx, cancel := context.WithCancel(context.Background())
	go ag.Run(ctx)
	t.Cleanup(func() { cancel(); ag.Close() })
	return wel
}

func (e *testEnv) waitWelcome(wel <-chan protocol.Welcome) protocol.Welcome {
	e.t.Helper()
	select {
	case w := <-wel:
		return w
	case <-time.After(10 * time.Second):
		e.t.Fatal("timed out waiting for agent welcome")
		return protocol.Welcome{}
	}
}

func (e *testEnv) do(method, host, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, "http://"+e.httpAddr+path, body)
	if err != nil {
		return nil, err
	}
	req.Host = host
	return http.DefaultClient.Do(req)
}

func TestHTTPTunnel(t *testing.T) {
	e := newEnv(t)
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "path=%s", r.URL.Path)
	}))
	defer local.Close()

	wel := e.startAgent(t, []protocol.TunnelSpec{{ID: "main", Proto: "http", Local: strings.TrimPrefix(local.URL, "http://")}})
	w := e.waitWelcome(wel)
	if len(w.Tunnels) != 1 {
		t.Fatalf("got %d tunnels, want 1", len(w.Tunnels))
	}
	host := strings.TrimPrefix(w.Tunnels[0].PublicURL, "http://")
	if !strings.HasSuffix(host, ".kproxy.test") {
		t.Fatalf("public url host = %q, want suffix .kproxy.test", host)
	}

	resp, err := e.do("GET", host, "/hello", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(b) != "path=/hello" {
		t.Fatalf("status=%d body=%q", resp.StatusCode, b)
	}
}

func TestHTTPTunnelBodyAndHeaders(t *testing.T) {
	e := newEnv(t)
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Origin", "local")
		fmt.Fprintf(w, "method=%s body=%s ct=%s", r.Method, b, r.Header.Get("Content-Type"))
	}))
	defer local.Close()

	wel := e.startAgent(t, []protocol.TunnelSpec{{ID: "main", Proto: "http", Local: strings.TrimPrefix(local.URL, "http://")}})
	host := strings.TrimPrefix(e.waitWelcome(wel).Tunnels[0].PublicURL, "http://")

	req, err := http.NewRequest("POST", "http://"+e.httpAddr+"/submit", strings.NewReader("payload-123"))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = host
	req.Header.Set("Content-Type", "application/x-test")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	want := "method=POST body=payload-123 ct=application/x-test"
	if string(b) != want {
		t.Fatalf("got %q, want %q", b, want)
	}
	if resp.Header.Get("X-Origin") != "local" {
		t.Fatalf("missing X-Origin header")
	}
}

func TestHTTPCustomSubdomain(t *testing.T) {
	e := newEnv(t)
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer local.Close()

	wel := e.startAgent(t, []protocol.TunnelSpec{{
		ID: "main", Proto: "http", Local: strings.TrimPrefix(local.URL, "http://"), Subdomain: "myapp",
	}})
	host := strings.TrimPrefix(e.waitWelcome(wel).Tunnels[0].PublicURL, "http://")
	if host != "myapp.kproxy.test" {
		t.Fatalf("host = %q, want myapp.kproxy.test", host)
	}

	resp, err := e.do("GET", host, "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestHTTPCustomDomain(t *testing.T) {
	e := newEnv(t)
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer local.Close()

	wel := e.startAgent(t, []protocol.TunnelSpec{{
		ID: "main", Proto: "http", Local: strings.TrimPrefix(local.URL, "http://"), Domain: "app.customer.com",
	}})
	host := strings.TrimPrefix(e.waitWelcome(wel).Tunnels[0].PublicURL, "http://")
	if host != "app.customer.com" {
		t.Fatalf("host = %q, want app.customer.com", host)
	}

	resp, err := e.do("GET", host, "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestTCPTunnel(t *testing.T) {
	e := newEnv(t)
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					if _, err := c.Write(buf[:n]); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	wel := e.startAgent(t, []protocol.TunnelSpec{{ID: "main", Proto: "tcp", Local: echoLn.Addr().String()}})
	url := e.waitWelcome(wel).Tunnels[0].PublicURL
	if !strings.HasPrefix(url, "tcp://") {
		t.Fatalf("public url = %q, want tcp:// prefix", url)
	}
	_, port, err := net.SplitHostPort(strings.TrimPrefix(url, "tcp://"))
	if err != nil {
		t.Fatalf("parse public url: %v", err)
	}

	conn, err := net.Dial("tcp", "127.0.0.1:"+port)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	msg := []byte("hello over tcp")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("got %q, want %q", got, msg)
	}
}

func TestUpgradeTunnel(t *testing.T) {
	e := newEnv(t)
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upLn.Close()
	go func() {
		for {
			conn, err := upLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				if _, err := c.Read(buf); err != nil {
					return
				}
				_, _ = c.Write([]byte("HTTP/1.1 101 Switching Protocols\r\n" +
					"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
					"Sec-WebSocket-Accept: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"))
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					if _, err := c.Write(buf[:n]); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	wel := e.startAgent(t, []protocol.TunnelSpec{{ID: "main", Proto: "http", Local: upLn.Addr().String()}})
	host := strings.TrimPrefix(e.waitWelcome(wel).Tunnels[0].PublicURL, "http://")

	conn, err := net.Dial("tcp", e.httpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	req := "GET /socket HTTP/1.1\r\nHost: " + host + "\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}

	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "101") {
		t.Fatalf("status line = %q, want 101", status)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}

	frame := []byte{0x81, 0x02, 'h', 'i'}
	if _, err := conn.Write(frame); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, len(frame))
	if _, err := io.ReadFull(br, echo); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(echo, frame) {
		t.Fatalf("echo = %v, want %v", echo, frame)
	}
}

func TestHandshakeRejectsBadKey(t *testing.T) {
	srv := relay.New(relay.Config{Domain: "kproxy.test", AdminKey: "correct-horse"})
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

	conn, err := net.Dial("tcp", ctrlLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	m := protocol.NewMux(conn)
	go m.Run()
	hello, _ := protocol.MarshalControl(protocol.Hello{
		Type:    protocol.TypeHello,
		Version: "0.1.0",
		APIKey:  "wrong",
		Tunnels: []protocol.TunnelSpec{{ID: "main", Proto: "http", Local: "127.0.0.1:1"}},
	})
	if err := m.SendControl(hello); err != nil {
		t.Fatal(err)
	}
	select {
	case b := <-m.Control():
		if msg := protocol.UnmarshalError(b); msg == "" {
			t.Fatalf("expected error control message, got %q", b)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for error")
	}
}
