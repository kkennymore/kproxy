package relay_test

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"kproxy/internal/agent"
	"kproxy/internal/protocol"
	"kproxy/internal/relay"
	"kproxy/internal/store"
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
	return newEnvWith(t, relay.Config{})
}

func newEnvWith(t *testing.T, cfg relay.Config) *testEnv {
	t.Helper()
	cfg.Domain = "kproxy.test"
	cfg.Scheme = "http"
	if cfg.TCPStart == 0 {
		cfg.TCPStart = 30000
	}
	if cfg.TCPEnd == 0 {
		cfg.TCPEnd = 39999
	}
	srv := relay.New(cfg)

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

func TestTCPTunnelPinnedPort(t *testing.T) {
	e := newEnv(t)
	echoLn := newEchoListener(t)
	defer echoLn.Close()

	const wantPort = 30123
	wel := e.startAgent(t, []protocol.TunnelSpec{{ID: "main", Proto: "tcp", Local: echoLn.Addr().String(), Port: wantPort}})
	url := e.waitWelcome(wel).Tunnels[0].PublicURL
	if !strings.HasSuffix(url, ":"+strconv.Itoa(wantPort)) {
		t.Fatalf("public url = %q, want suffix :%d", url, wantPort)
	}

	conn, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(wantPort))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	msg := []byte("pinned")
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

func TestTCPTunnelPinnedPortConflict(t *testing.T) {
	srv := relay.New(relay.Config{Domain: "kproxy.test", TCPStart: 30000, TCPEnd: 39999})
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

	conflict, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer conflict.Close()
	port := conflict.Addr().(*net.TCPAddr).Port

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
		Tunnels: []protocol.TunnelSpec{{ID: "main", Proto: "tcp", Local: "127.0.0.1:1", Port: port}},
	})
	if err := m.SendControl(hello); err != nil {
		t.Fatal(err)
	}
	select {
	case b := <-m.Control():
		if msg := protocol.UnmarshalError(b); msg == "" || !strings.Contains(msg, "port") {
			t.Fatalf("expected port error, got %q", b)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for error")
	}
}

func TestMultiTunnel(t *testing.T) {
	e := newEnv(t)

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "api-ok")
	}))
	defer api.Close()
	www := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "www-ok")
	}))
	defer www.Close()
	echoLn := newEchoListener(t)
	defer echoLn.Close()

	specs := []protocol.TunnelSpec{
		{ID: "api", Proto: "http", Local: strings.TrimPrefix(api.URL, "http://"), Subdomain: "api"},
		{ID: "www", Proto: "http", Local: strings.TrimPrefix(www.URL, "http://")},
		{ID: "db", Proto: "tcp", Local: echoLn.Addr().String()},
	}
	wel := e.startAgent(t, specs)
	w := e.waitWelcome(wel)
	if len(w.Tunnels) != 3 {
		t.Fatalf("got %d tunnels, want 3", len(w.Tunnels))
	}

	assigns := make(map[string]string)
	for _, a := range w.Tunnels {
		assigns[a.ID] = a.PublicURL
	}

	apiHost := strings.TrimPrefix(assigns["api"], "http://")
	if apiHost != "api.kproxy.test" {
		t.Fatalf("api host = %q, want api.kproxy.test", apiHost)
	}
	resp, err := e.do("GET", apiHost, "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "api-ok" {
		t.Fatalf("api body = %q, want api-ok", b)
	}

	wwwHost := strings.TrimPrefix(assigns["www"], "http://")
	resp, err = e.do("GET", wwwHost, "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "www-ok" {
		t.Fatalf("www body = %q, want www-ok", b)
	}

	_, port, err := net.SplitHostPort(strings.TrimPrefix(assigns["db"], "tcp://"))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", "127.0.0.1:"+port)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	msg := []byte("multi")
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

func newEchoListener(t *testing.T) net.Listener {
	t.Helper()
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
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
	return echoLn
}

func TestCloseAddRoundTrip(t *testing.T) {
	srv := relay.New(relay.Config{Domain: "kproxy.test", Scheme: "http", TCPStart: 30000, TCPEnd: 39999})
	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer httpLn.Close()
	hs := &http.Server{Handler: srv.Handler()}
	go hs.Serve(httpLn)

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

	echoLn := newEchoListener(t)
	defer echoLn.Close()
	localWeb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "web-ok")
	}))
	defer localWeb.Close()
	localWebAddr := strings.TrimPrefix(localWeb.URL, "http://")

	conn, err := net.Dial("tcp", ctrlLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	m := protocol.NewMux(conn)
	go m.Run()

	locals := map[string]string{"web": localWebAddr, "db": echoLn.Addr().String()}
	go func() {
		for {
			st, err := m.Accept()
			if err != nil {
				return
			}
			local := locals[string(st.Meta())]
			if local == "" {
				st.Close()
				continue
			}
			go func() {
				target, err := net.DialTimeout("tcp", local, 5*time.Second)
				if err != nil {
					st.Close()
					return
				}
				protocol.Bridge(st, target)
			}()
		}
	}()

	const pinned = 30250
	hello, _ := protocol.MarshalControl(protocol.Hello{
		Type:    protocol.TypeHello,
		Version: "0.1.0",
		Tunnels: []protocol.TunnelSpec{
			{ID: "web", Proto: "http", Local: localWebAddr, Subdomain: "closeapp"},
			{ID: "db", Proto: "tcp", Local: echoLn.Addr().String(), Port: pinned},
		},
	})
	if err := m.SendControl(hello); err != nil {
		t.Fatal(err)
	}
	var wel protocol.Welcome
	select {
	case b := <-m.Control():
		if err := protocol.UnmarshalControl(b, &wel); err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for welcome")
	}
	if len(wel.Tunnels) != 2 {
		t.Fatalf("got %d tunnels, want 2", len(wel.Tunnels))
	}

	httpAddr := httpLn.Addr().String()
	doReq := func(t *testing.T, host string, wantStatus int) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			req, err := http.NewRequest("GET", "http://"+httpAddr+"/", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Host = host
			resp, err := http.DefaultClient.Do(req)
			if err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode == wantStatus {
					return
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for status %d from %s", wantStatus, host)
	}
	doEcho := func(t *testing.T, wantOK bool) {
		t.Helper()
		addr := "127.0.0.1:" + strconv.Itoa(pinned)
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			cc, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
			if err != nil {
				if !wantOK {
					return
				}
				time.Sleep(100 * time.Millisecond)
				continue
			}
			if !wantOK {
				cc.Close()
				t.Fatal("expected port to be closed, but it accepts connections")
			}
			msg := []byte("roundtrip")
			cc.Write(msg)
			got := make([]byte, len(msg))
			if _, err := io.ReadFull(cc, got); err != nil || !bytes.Equal(got, msg) {
				cc.Close()
				t.Fatalf("echo failed: %v", err)
			}
			cc.Close()
			return
		}
		if wantOK {
			t.Fatal("timed out waiting for port to accept connections")
		}
	}

	doReq(t, "closeapp.kproxy.test", 200)
	doEcho(t, true)

	closeMsg, _ := protocol.MarshalControl(protocol.CloseMsg{Type: protocol.TypeClose, Tunnels: []string{"web", "db"}})
	if err := m.SendControl(closeMsg); err != nil {
		t.Fatal(err)
	}

	doReq(t, "closeapp.kproxy.test", 404) // host freed
	doEcho(t, false)                      // tcp listener released

	// Re-open both tunnels after the close.
	addMsg, _ := protocol.MarshalControl(protocol.AddMsg{
		Type: "add",
		Tunnels: []protocol.TunnelSpec{
			{ID: "web", Proto: "http", Local: localWebAddr, Subdomain: "closeapp"},
			{ID: "db", Proto: "tcp", Local: echoLn.Addr().String(), Port: pinned},
		},
	})
	if err := m.SendControl(addMsg); err != nil {
		t.Fatal(err)
	}
	var assigned protocol.AssignedMsg
	select {
	case b := <-m.Control():
		if err := protocol.UnmarshalControl(b, &assigned); err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for assignments")
	}
	if assigned.Type != protocol.TypeAssigned || len(assigned.Tunnels) != 2 {
		t.Fatalf("assigned = %+v", assigned)
	}
	if assigned.Tunnels[0].PublicURL != "http://closeapp.kproxy.test" {
		t.Fatalf("assigned url = %q", assigned.Tunnels[0].PublicURL)
	}

	doReq(t, "closeapp.kproxy.test", 200) // http tunnel works again
	doEcho(t, true)                       // tcp listener rebound on the same pinned port
}

func TestLocalTargetFailureCloseAndRecover(t *testing.T) {
	e := newEnv(t)

	const localPort = 41051
	localAddr := "127.0.0.1:" + strconv.Itoa(localPort)
	startEcho := func(t *testing.T) net.Listener {
		t.Helper()
		ln, err := net.Listen("tcp", localAddr)
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) {
					defer c.Close()
					io.Copy(c, c)
				}(conn)
			}
		}()
		return ln
	}
	ln := startEcho(t)

	const pinned = 30260
	welCh := make(chan protocol.Welcome, 1)
	ag := agent.New(agent.Config{
		ServerURL:          "http://" + e.controlAddr,
		Tunnels:            []protocol.TunnelSpec{{ID: "db", Proto: "tcp", Local: localAddr, Port: pinned}},
		OnWelcome:          func(w protocol.Welcome) { welCh <- w },
		HealthEvery:        200 * time.Millisecond,
		LocalFailThreshold: 2,
	})
	ctx, cancel := context.WithCancel(context.Background())
	go ag.Run(ctx)
	t.Cleanup(func() { cancel(); ag.Close() })

	publicAddr := "127.0.0.1:" + strconv.Itoa(pinned)
	waitPort(t, publicAddr, true)

	// Local target goes down: the agent should gracefully close the tunnel and
	// the public port should stop accepting connections.
	ln.Close()
	waitPort(t, publicAddr, false)

	// Local target recovers on the same address: the agent reopens the tunnel
	// on the same pinned port and it echoes again.
	ln = startEcho(t)
	defer ln.Close()
	waitPort(t, publicAddr, true)

	conn, err := net.Dial("tcp", publicAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	msg := []byte("recovered")
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

func waitPort(t *testing.T, addr string, wantOK bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			if wantOK {
				return
			}
		} else if !wantOK {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	if wantOK {
		t.Fatalf("timed out waiting for %s to accept connections", addr)
	}
	t.Fatalf("timed out waiting for %s to stop accepting connections", addr)
}

func TestHandshakeRejectsBadKey(t *testing.T) {
	srv := relay.New(relay.Config{
		Domain: "kproxy.test",
		Keys:   fakeValidator{"correct-horse"},
	})
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

type fakeValidator struct{ want string }

func (f fakeValidator) ValidateKey(key string) (*store.KeyIdentity, error) {
	if key != f.want {
		return nil, errors.New("invalid api key")
	}
	return &store.KeyIdentity{ID: "fake"}, nil
}

func TestStoreBackedAgentAuth(t *testing.T) {
	keyStore, err := store.Open(filepath.Join(t.TempDir(), "keys.json"))
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

	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer httpLn.Close()
	hs := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go hs.Serve(httpLn)

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

	_, secret, err := keyStore.Create("tester", 0, store.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "authed")
	}))
	defer local.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	welCh := make(chan protocol.Welcome, 1)
	good := agent.New(agent.Config{
		ServerURL: "http://" + ctrlLn.Addr().String(),
		APIKey:    secret,
		Tunnels:   []protocol.TunnelSpec{{ID: "main", Proto: "http", Local: strings.TrimPrefix(local.URL, "http://")}},
		OnWelcome: func(w protocol.Welcome) { welCh <- w },
	})
	go good.Run(ctx)
	select {
	case w := <-welCh:
		if len(w.Tunnels) != 1 {
			t.Fatalf("got %d tunnels, want 1", len(w.Tunnels))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for welcome")
	}

	// A bad key must be rejected outright (no reconnect loop).
	bad := agent.New(agent.Config{
		ServerURL: "http://" + ctrlLn.Addr().String(),
		APIKey:    "nope",
		Tunnels:   []protocol.TunnelSpec{{ID: "main", Proto: "http", Local: "127.0.0.1:1"}},
	})
	err = bad.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "invalid api key") {
		t.Fatalf("bad key error = %v, want invalid api key", err)
	}
}

// startStoreBacked brings up a store-authenticated relay plus public HTTP and
// control listeners. Returns the HTTP and control addresses.
func startStoreBacked(t *testing.T, keyStore *store.Store) (string, string) {
	t.Helper()
	srv := relay.New(relay.Config{
		Domain:   "kproxy.test",
		Scheme:   "http",
		TCPStart: 30000,
		TCPEnd:   39999,
		Keys:     keyStore,
	})
	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go hs.Serve(httpLn)
	t.Cleanup(func() { hs.Close() })

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
	t.Cleanup(func() { ctrlLn.Close() })
	return httpLn.Addr().String(), ctrlLn.Addr().String()
}

// connect runs an agent against ctrlAddr and waits for its welcome (or the
// rejection). It returns the welcome; a nil return means the agent was
// rejected and Run returned the given error.
func connect(t *testing.T, ctrlAddr, apiKey string, specs []protocol.TunnelSpec) (*protocol.Welcome, error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	welCh := make(chan protocol.Welcome, 1)
	runCh := make(chan error, 1)
	ag := agent.New(agent.Config{
		ServerURL: "http://" + ctrlAddr,
		APIKey:    apiKey,
		Tunnels:   specs,
		OnWelcome: func(w protocol.Welcome) { welCh <- w },
	})
	go func() { runCh <- ag.Run(ctx) }()
	select {
	case w := <-welCh:
		return &w, nil
	case err := <-runCh:
		return nil, err
	case <-time.After(10 * time.Second):
		return nil, errors.New("timed out waiting for welcome or rejection")
	}
}

func TestSubdomainRestriction(t *testing.T) {
	keyStore, err := store.Open(filepath.Join(t.TempDir(), "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	_, secret, err := keyStore.Create("limited", 0, store.Limits{AllowedSubdomains: []string{"api"}})
	if err != nil {
		t.Fatal(err)
	}
	_, ctrlAddr := startStoreBacked(t, keyStore)

	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer local.Close()

	allowed := []protocol.TunnelSpec{{ID: "ok", Proto: "http", Local: strings.TrimPrefix(local.URL, "http://"), Subdomain: "api"}}
	w, err := connect(t, ctrlAddr, secret, allowed)
	if err != nil {
		t.Fatal(err)
	}
	if len(w.Tunnels) != 1 || !strings.Contains(w.Tunnels[0].PublicURL, "api.kproxy.test") {
		t.Fatalf("unexpected welcome: %+v", w)
	}

	denied := []protocol.TunnelSpec{{ID: "nope", Proto: "http", Local: "127.0.0.1:1", Subdomain: "other"}}
	w, err = connect(t, ctrlAddr, secret, denied)
	if err == nil {
		t.Fatal("expected rejection for disallowed subdomain")
	}
	if !strings.Contains(err.Error(), "not allowed for this key") {
		t.Fatalf("rejection error = %v, want subdomain not allowed", err)
	}
}

func TestRequestRateLimit(t *testing.T) {
	keyStore, err := store.Open(filepath.Join(t.TempDir(), "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	_, secret, err := keyStore.Create("limited", 0, store.Limits{RequestsPerSec: 1})
	if err != nil {
		t.Fatal(err)
	}
	httpAddr, ctrlAddr := startStoreBacked(t, keyStore)

	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer local.Close()

	spec := []protocol.TunnelSpec{{ID: "main", Proto: "http", Local: strings.TrimPrefix(local.URL, "http://")}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	welCh := make(chan protocol.Welcome, 1)
	ag := agent.New(agent.Config{
		ServerURL: "http://" + ctrlAddr,
		APIKey:    secret,
		Tunnels:   spec,
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
	// First request consumes the single token.
	req, err := http.NewRequest("GET", "http://"+httpAddr, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = host
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(b) != "ok" {
		t.Fatalf("first request: status=%d body=%q, want 200 ok", resp.StatusCode, b)
	}
	// Second request must hit the 429 limit.
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second request status = %d, want 429", resp.StatusCode)
	}
}

func TestSubscribeEvents(t *testing.T) {
	e := newEnv(t)
	ch, unsub := e.srv.Subscribe()
	defer unsub()

	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hi")
	}))
	defer local.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	welCh := make(chan protocol.Welcome, 1)
	ag := agent.New(agent.Config{
		ServerURL: "http://" + e.controlAddr,
		Tunnels:   []protocol.TunnelSpec{{ID: "main", Proto: "http", Local: strings.TrimPrefix(local.URL, "http://")}},
		OnWelcome: func(w protocol.Welcome) { welCh <- w },
	})
	go ag.Run(ctx)
	w := e.waitWelcome(welCh)
	host := strings.TrimPrefix(w.Tunnels[0].PublicURL, "http://")

	ev := nextRelayEvent(t, ch)
	if ev.Type != "tunnel_open" || ev.Tunnel == nil || ev.Tunnel.PublicURL != w.Tunnels[0].PublicURL {
		t.Fatalf("tunnel_open event = %+v", ev)
	}

	resp, err := e.do("GET", host, "/hello", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	ev = nextRelayEvent(t, ch)
	if ev.Type != "request" || ev.Request == nil || ev.Request.Path != "/hello" || ev.Request.Status != http.StatusOK {
		t.Fatalf("request event = %+v", ev)
	}

	cancel()
	ag.Close()
	ev = nextRelayEvent(t, ch)
	if ev.Type != "tunnel_close" || ev.Tunnel == nil {
		t.Fatalf("tunnel_close event = %+v", ev)
	}
}

func nextRelayEvent(t *testing.T, ch <-chan relay.Event) relay.Event {
	t.Helper()
	select {
	case ev := <-ch:
		return ev
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for relay event")
		return relay.Event{}
	}
}

func TestBasicAuth(t *testing.T) {
	e := newEnv(t)
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer local.Close()
	spec := []protocol.TunnelSpec{{
		ID:        "main",
		Proto:     "http",
		Local:     strings.TrimPrefix(local.URL, "http://"),
		BasicAuth: "user:secret",
	}}
	w := e.waitWelcome(e.startAgent(t, spec))
	host := strings.TrimPrefix(w.Tunnels[0].PublicURL, "http://")

	// No credentials -> 401 with a Basic challenge.
	resp, err := e.do("GET", host, "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no-cred status = %d, want 401", resp.StatusCode)
	}
	if got := resp.Header.Get("WWW-Authenticate"); got != `Basic realm="kproxy"` {
		t.Fatalf("WWW-Authenticate = %q", got)
	}

	// Wrong credentials -> 401.
	req, _ := http.NewRequest("GET", "http://"+e.httpAddr+"/", nil)
	req.Host = host
	req.SetBasicAuth("user", "wrong")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong-cred status = %d, want 401", resp.StatusCode)
	}

	// Correct credentials -> 200.
	req.SetBasicAuth("user", "secret")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(b) != "ok" {
		t.Fatalf("good-cred status=%d body=%q", resp.StatusCode, b)
	}
}

func TestIPAllowDeny(t *testing.T) {
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer local.Close()

	cases := []struct {
		name string
		opts protocol.TunnelSpec
		want int
	}{
		{"deny loopback", protocol.TunnelSpec{IPDeny: []string{"127.0.0.1"}}, http.StatusForbidden},
		{"allow other subnet", protocol.TunnelSpec{IPAllow: []string{"10.0.0.0/8"}}, http.StatusForbidden},
		{"allow loopback", protocol.TunnelSpec{IPAllow: []string{"127.0.0.1"}}, http.StatusOK},
		{"allow v4 mask", protocol.TunnelSpec{IPAllow: []string{"127.0.0.0/8"}}, http.StatusOK},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			c.opts.ID = "main"
			c.opts.Proto = "http"
			c.opts.Local = strings.TrimPrefix(local.URL, "http://")
			w := e.waitWelcome(e.startAgent(t, []protocol.TunnelSpec{c.opts}))
			host := strings.TrimPrefix(w.Tunnels[0].PublicURL, "http://")
			resp, err := e.do("GET", host, "/", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != c.want {
				t.Fatalf("status = %d, want %d", resp.StatusCode, c.want)
			}
		})
	}
}

func TestMaxRequestSize(t *testing.T) {
	e := newEnv(t)
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "len=%d", len(b))
	}))
	defer local.Close()
	spec := []protocol.TunnelSpec{{
		ID:             "main",
		Proto:          "http",
		Local:          strings.TrimPrefix(local.URL, "http://"),
		MaxRequestSize: "64",
	}}
	w := e.waitWelcome(e.startAgent(t, spec))
	host := strings.TrimPrefix(w.Tunnels[0].PublicURL, "http://")

	// Known Content-Length above the limit -> 413 without touching the tunnel.
	req, _ := http.NewRequest("POST", "http://"+e.httpAddr+"/", strings.NewReader(strings.Repeat("x", 100)))
	req.Host = host
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("large known body status = %d, want 413", resp.StatusCode)
	}

	// Chunked body above the limit -> 413.
	req, _ = http.NewRequest("POST", "http://"+e.httpAddr+"/", io.NopCloser(strings.NewReader(strings.Repeat("y", 100))))
	req.ContentLength = -1
	req.Host = host
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("large chunked body status = %d, want 413", resp.StatusCode)
	}

	// Body within the limit -> 200.
	req, _ = http.NewRequest("POST", "http://"+e.httpAddr+"/", strings.NewReader("tiny"))
	req.Host = host
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(b) != "len=4" {
		t.Fatalf("small body status=%d body=%q", resp.StatusCode, b)
	}
}

func TestRequestTimeout(t *testing.T) {
	e := newEnv(t)
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		io.WriteString(w, "late")
	}))
	defer local.Close()
	spec := []protocol.TunnelSpec{{
		ID:             "main",
		Proto:          "http",
		Local:          strings.TrimPrefix(local.URL, "http://"),
		RequestTimeout: "200ms",
	}}
	w := e.waitWelcome(e.startAgent(t, spec))
	host := strings.TrimPrefix(w.Tunnels[0].PublicURL, "http://")

	start := time.Now()
	resp, err := e.do("GET", host, "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("timeout did not fire early: took %v", elapsed)
	}
}

func TestRequestID(t *testing.T) {
	e := newEnv(t)
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.Header.Get("X-Request-Id"))
	}))
	defer local.Close()
	w := e.waitWelcome(e.startAgent(t, []protocol.TunnelSpec{{
		ID:    "main",
		Proto: "http",
		Local: strings.TrimPrefix(local.URL, "http://"),
	}}))
	host := strings.TrimPrefix(w.Tunnels[0].PublicURL, "http://")

	resp, err := e.do("GET", host, "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	rid := resp.Header.Get("X-Request-Id")
	if rid == "" {
		t.Fatal("missing X-Request-Id response header")
	}
	if string(got) != rid {
		t.Fatalf("origin saw request id %q, response header %q", got, rid)
	}
}

func TestTunnelUsageCounters(t *testing.T) {
	e := newEnv(t)
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello world")
	}))
	defer local.Close()
	w := e.waitWelcome(e.startAgent(t, []protocol.TunnelSpec{{
		ID:    "main",
		Proto: "http",
		Local: strings.TrimPrefix(local.URL, "http://"),
	}}))
	host := strings.TrimPrefix(w.Tunnels[0].PublicURL, "http://")

	if resp, err := e.do("GET", host, "/a", nil); err != nil {
		t.Fatal(err)
	} else {
		resp.Body.Close()
	}
	if resp, err := e.do("GET", host, "/b", nil); err != nil {
		t.Fatal(err)
	} else {
		resp.Body.Close()
	}

	tunnels := e.srv.Tunnels()
	if len(tunnels) != 1 {
		t.Fatalf("got %d tunnels", len(tunnels))
	}
	if tunnels[0].Requests != 2 {
		t.Fatalf("requests = %d, want 2", tunnels[0].Requests)
	}
	if tunnels[0].Bytes <= 0 {
		t.Fatalf("bytes = %d, want > 0", tunnels[0].Bytes)
	}
	if tunnels[0].LastActive.IsZero() || tunnels[0].AgentConnected.IsZero() {
		t.Fatalf("timestamps missing: %+v", tunnels[0])
	}
	if st := e.srv.Status(); st.Tunnels != 1 || st.Requests != 2 || st.Bytes <= 0 {
		t.Fatalf("status = %+v", st)
	}
}

func TestInvalidTunnelOptionsRejected(t *testing.T) {
	e := newEnv(t)
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer local.Close()
	base := protocol.TunnelSpec{Proto: "http", Local: strings.TrimPrefix(local.URL, "http://")}

	cases := []struct {
		name string
		mut  func(*protocol.TunnelSpec)
		want string
	}{
		{"basic auth no colon", func(s *protocol.TunnelSpec) { s.BasicAuth = "nocolon" }, "user:pass"},
		{"bad cidr", func(s *protocol.TunnelSpec) { s.IPAllow = []string{"bogus"} }, "invalid ip or cidr"},
		{"bad size", func(s *protocol.TunnelSpec) { s.MaxRequestSize = "huge" }, "invalid max request size"},
		{"bad timeout", func(s *protocol.TunnelSpec) { s.RequestTimeout = "nope" }, "invalid request timeout"},
		{"basic auth on tcp", func(s *protocol.TunnelSpec) { s.Proto = "tcp"; s.BasicAuth = "u:p" }, "only applies to http"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spec := base
			spec.ID = "main"
			c.mut(&spec)
			_, err := connect(t, e.controlAddr, "", []protocol.TunnelSpec{spec})
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want containing %q", err, c.want)
			}
		})
	}
}

func TestDomainVerification(t *testing.T) {
	keyStore, err := store.Open(filepath.Join(t.TempDir(), "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv := relay.New(relay.Config{
		Domain:    "kproxy.test",
		Scheme:    "http",
		TCPStart:  30000,
		TCPEnd:    39999,
		VerifyKey: "verify-secret",
	})
	token := srv.VerifyToken("trusted.kproxy.test")
	if !strings.HasPrefix(token, "kproxy-verify-") {
		t.Fatalf("token shape = %q", token)
	}
	srv.Close()

	lookup := func(ctx context.Context, name string) ([]string, error) {
		if name == "_kproxy.trusted.kproxy.test" {
			return []string{"some-other-record", token}, nil
		}
		return nil, &net.DNSError{Err: "nxdomain", Name: name, IsNotFound: true}
	}
	srv = relay.New(relay.Config{
		Domain:    "kproxy.test",
		Scheme:    "http",
		TCPStart:  30000,
		TCPEnd:    39999,
		Keys:      keyStore,
		VerifyKey: "verify-secret",
		TXTLookup: lookup,
	})
	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer httpLn.Close()
	hs := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go hs.Serve(httpLn)
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
	_, secret, err := keyStore.Create("tester", 0, store.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer local.Close()

	// A verified custom domain is honored.
	ok := []protocol.TunnelSpec{{
		ID:     "ok",
		Proto:  "http",
		Local:  strings.TrimPrefix(local.URL, "http://"),
		Domain: "trusted.kproxy.test",
	}}
	w, err := connect(t, ctrlLn.Addr().String(), secret, ok)
	if err != nil {
		t.Fatalf("verified domain rejected: %v", err)
	}
	if len(w.Tunnels) != 1 || w.Tunnels[0].PublicURL != "http://trusted.kproxy.test" {
		t.Fatalf("welcome = %+v", w)
	}

	// An unverified custom domain is rejected with the TXT hint.
	bad := []protocol.TunnelSpec{{
		ID:     "nope",
		Proto:  "http",
		Local:  strings.TrimPrefix(local.URL, "http://"),
		Domain: "other.kproxy.test",
	}}
	_, err = connect(t, ctrlLn.Addr().String(), secret, bad)
	if err == nil || !strings.Contains(err.Error(), "TXT record") || !strings.Contains(err.Error(), "other.kproxy.test") {
		t.Fatalf("unverified domain err = %v, want TXT hint", err)
	}

	// Verification disabled yields no token.
	srv2 := relay.New(relay.Config{Domain: "x.test"})
	defer srv2.Close()
	if got := srv2.VerifyToken("a.com"); got != "" {
		t.Fatalf("disabled verification returned token %q", got)
	}
}

// TestLoadBalancedHTTPTunnels verifies that two agents claiming the same
// subdomain both receive traffic (least-connections / round-robin) and that
// the survivor keeps serving after one agent disconnects.
func TestLoadBalancedHTTPTunnels(t *testing.T) {
	e := newEnv(t)

	mk := func(body string) string {
		ls := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, body)
		}))
		t.Cleanup(ls.Close)
		return strings.TrimPrefix(ls.URL, "http://")
	}
	targetA, targetB := mk("A"), mk("B")

	runAgent := func(target string) *agent.Agent {
		ag := agent.New(agent.Config{
			ServerURL: "http://" + e.controlAddr,
			Tunnels: []protocol.TunnelSpec{
				{ID: "main", Proto: "http", Local: target, Subdomain: "lb"},
			},
		})
		ctx, cancel := context.WithCancel(context.Background())
		go ag.Run(ctx)
		t.Cleanup(func() { cancel(); ag.Close() })
		return ag
	}
	agA := runAgent(targetA)
	agB := runAgent(targetB)

	// Poll until both agents are registered on the same host.
	var host string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for _, tn := range e.srv.Tunnels() {
			if tn.Host == "lb.kproxy.test" {
				host = tn.Host
			}
		}
		if e.srv.Tunnels() != nil && len(e.srv.Tunnels()) == 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if host != "lb.kproxy.test" {
		t.Fatalf("load-balanced host not registered")
	}
	if got := len(e.srv.Tunnels()); got != 2 {
		t.Fatalf("tunnels = %d, want 2", got)
	}

	counts := map[string]int{}
	for i := 0; i < 8; i++ {
		resp, err := e.do("GET", host, "/", nil)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("status = %d", resp.StatusCode)
		}
		counts[string(b)]++
	}
	if counts["A"] == 0 || counts["B"] == 0 {
		t.Fatalf("expected both agents to serve traffic, got %v", counts)
	}

	// Kill agent A: requests must still succeed via agent B.
	agA.Close()
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if len(e.srv.Tunnels()) == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	for i := 0; i < 3; i++ {
		resp, err := e.do("GET", host, "/", nil)
		if err != nil {
			t.Fatalf("request after failover: %v", err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || string(b) != "B" {
			t.Fatalf("failover response = %d %q, want 200 B", resp.StatusCode, b)
		}
	}
	_ = agB
}

func TestRequestLogRetention(t *testing.T) {
	e := newEnvWith(t, relay.Config{RequestLogSize: 3})

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	t.Cleanup(target.Close)

	wel := e.startAgent(t, []protocol.TunnelSpec{
		{ID: "main", Proto: "http", Local: strings.TrimPrefix(target.URL, "http://"), Subdomain: "log"},
	})
	e.waitWelcome(wel)

	do := func(path string) {
		t.Helper()
		req, err := http.NewRequest("GET", "http://"+e.httpAddr+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "log.kproxy.test"
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("status = %d", resp.StatusCode)
		}
	}

	// The query string must never be captured in the request log.
	do("/a/b?token=supersecret")
	reqs := e.srv.Requests(0)
	if len(reqs) != 1 {
		t.Fatalf("Requests(0) = %d entries, want 1", len(reqs))
	}
	if reqs[0].Path != "/a/b" {
		t.Fatalf("captured path = %q, want /a/b (query redacted)", reqs[0].Path)
	}
	if reqs[0].Host != "log.kproxy.test" || reqs[0].Method != "GET" || reqs[0].Status != 200 {
		t.Fatalf("unexpected entry: %+v", reqs[0])
	}

	// Ring is bounded and returns newest first.
	do("/one")
	do("/two")
	do("/three")
	reqs = e.srv.Requests(0)
	if len(reqs) != 3 {
		t.Fatalf("Requests(0) = %d entries, want 3 (bounded at 3)", len(reqs))
	}
	want := []string{"/three", "/two", "/one"}
	for i, w := range want {
		if reqs[i].Path != w {
			t.Fatalf("Requests(0)[%d] = %q, want %q (newest first)", i, reqs[i].Path, w)
		}
	}
	if got := len(e.srv.Requests(2)); got != 2 {
		t.Fatalf("Requests(2) = %d, want 2", got)
	}
}

func TestRequestLogDisabled(t *testing.T) {
	e := newEnv(t) // RequestLogSize zero => retention disabled

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(target.Close)

	wel := e.startAgent(t, []protocol.TunnelSpec{
		{ID: "main", Proto: "http", Local: strings.TrimPrefix(target.URL, "http://"), Subdomain: "nolog"},
	})
	e.waitWelcome(wel)

	resp, err := e.do("GET", "nolog.kproxy.test", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := len(e.srv.Requests(0)); got != 0 {
		t.Fatalf("Requests(0) = %d, want 0 with retention disabled", got)
	}
}
