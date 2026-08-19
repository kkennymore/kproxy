// Package relay implements the kproxyd side of the tunnel: it accepts agent
// control connections, assigns public endpoints, and routes incoming client
// traffic over the agent's multiplexed connection.
package relay

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"kproxy/internal/protocol"
)

const (
	defaultTCPStart = 20000
	defaultTCPEnd   = 29999
	helloTimeout    = 15 * time.Second
	keepAliveEvery  = 30 * time.Second
	keepAliveDead   = 90 * time.Second
	pingTimeout     = 5 * time.Second
)

// Config configures a relay Server.
type Config struct {
	// Domain is the base domain under which subdomains are allocated. It is
	// also used to build the public host of TCP tunnels.
	Domain string
	// Scheme is the scheme used in generated public URLs ("http" or "https").
	Scheme string
	// AdminKey is a shared secret agents must present. Empty disables the
	// check (development only).
	AdminKey string
	// TCPStart and TCPEnd bound the public port range for TCP tunnels.
	TCPStart int
	TCPEnd   int
	// Logger receives relay logs.
	Logger *slog.Logger
}

// Server routes client traffic to the agent that owns each tunnel.
type Server struct {
	cfg Config
	log *slog.Logger

	mu           sync.RWMutex
	httpTunnels  map[string]*tunnel
	tcpTunnels   map[string]*tunnel
	tcpListeners map[int]net.Listener
	agents       map[*client]struct{}

	closed    chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

type tunnel struct {
	id        string
	proto     string
	local     string
	host      string
	port      int
	publicURL string
	client    *client
}

type client struct {
	id      string
	mux     *protocol.Mux
	server  *Server
	tunnels map[string]*tunnel

	closed    chan struct{}
	closeOnce sync.Once
}

// New creates a relay server.
func New(cfg Config) *Server {
	if cfg.Scheme == "" {
		cfg.Scheme = "http"
	}
	if cfg.TCPStart == 0 {
		cfg.TCPStart = defaultTCPStart
	}
	if cfg.TCPEnd == 0 {
		cfg.TCPEnd = defaultTCPEnd
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Server{
		cfg:          cfg,
		log:          cfg.Logger,
		httpTunnels:  make(map[string]*tunnel),
		tcpTunnels:   make(map[string]*tunnel),
		tcpListeners: make(map[int]net.Listener),
		agents:       make(map[*client]struct{}),
		closed:       make(chan struct{}),
	}
}

// Handler returns the public HTTP handler serving tunnel traffic.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(s.serveHTTP)
}

// HandleAgent accepts a new agent control connection. It runs the handshake
// and manages the connection until it closes.
func (s *Server) HandleAgent(conn net.Conn) {
	s.wg.Add(1)
	defer s.wg.Done()

	m := protocol.NewMux(conn)
	c := &client{
		id:      newID(6),
		mux:     m,
		server:  s,
		tunnels: make(map[string]*tunnel),
		closed:  make(chan struct{}),
	}
	m.SetOnClose(c.disconnected)
	go m.Run()

	var hello protocol.Hello
	select {
	case b := <-m.Control():
		if err := protocol.UnmarshalControl(b, &hello); err != nil {
			s.sendError(c, "malformed hello")
			m.Close()
			return
		}
	case <-c.closed:
		return
	case <-time.After(helloTimeout):
		m.Close()
		return
	}

	if hello.Type != protocol.TypeHello {
		s.sendError(c, "expected hello")
		m.Close()
		return
	}
	if s.cfg.AdminKey != "" && hello.APIKey != s.cfg.AdminKey {
		s.log.Warn("agent rejected: bad api key", "agent", c.id)
		s.sendError(c, "invalid api key")
		m.Close()
		return
	}

	welcome, err := s.register(c, hello)
	if err != nil {
		s.log.Warn("agent rejected", "agent", c.id, "error", err)
		s.sendError(c, err.Error())
		m.Close()
		return
	}

	b, err := protocol.MarshalControl(welcome)
	if err != nil {
		m.Close()
		return
	}
	if err := m.SendControl(b); err != nil {
		m.Close()
		return
	}

	s.log.Info("agent connected", "agent", c.id, "tunnels", len(welcome.Tunnels))
	s.mu.Lock()
	s.agents[c] = struct{}{}
	s.mu.Unlock()

	go s.keepAlive(c)
	for {
		select {
		case <-c.closed:
			return
		case <-m.Control():
		}
	}
}

func (s *Server) register(c *client, hello protocol.Hello) (*protocol.Welcome, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	welcome := &protocol.Welcome{Type: protocol.TypeWelcome, Version: hello.Version, Server: s.cfg.Domain}
	for _, spec := range hello.Tunnels {
		switch spec.Proto {
		case protocol.ProtoHTTP:
			host, err := s.allocateHTTPHostLocked(spec)
			if err != nil {
				return nil, err
			}
			t := &tunnel{
				id:        spec.ID,
				proto:     spec.Proto,
				local:     spec.Local,
				host:      host,
				publicURL: s.cfg.Scheme + "://" + host,
				client:    c,
			}
			s.httpTunnels[host] = t
			c.tunnels[spec.ID] = t
			welcome.Tunnels = append(welcome.Tunnels, protocol.TunnelAssign{ID: spec.ID, PublicURL: t.publicURL})

		case protocol.ProtoTCP:
			port, ln, err := s.allocateTCPPortLocked()
			if err != nil {
				return nil, err
			}
			t := &tunnel{
				id:        spec.ID,
				proto:     spec.Proto,
				local:     spec.Local,
				port:      port,
				publicURL: "tcp://" + s.publicHost() + ":" + strconv.Itoa(port),
				client:    c,
			}
			s.tcpTunnels[spec.ID] = t
			s.tcpListeners[port] = ln
			c.tunnels[spec.ID] = t
			go s.acceptTCP(t, ln)
			welcome.Tunnels = append(welcome.Tunnels, protocol.TunnelAssign{ID: spec.ID, PublicURL: t.publicURL})

		default:
			return nil, fmt.Errorf("unsupported tunnel protocol %q", spec.Proto)
		}
	}
	return welcome, nil
}

func (s *Server) allocateHTTPHostLocked(spec protocol.TunnelSpec) (string, error) {
	var host string
	switch {
	case spec.Domain != "":
		host = hostOnly(spec.Domain)
	case spec.Subdomain != "":
		host = strings.ToLower(spec.Subdomain) + "." + s.cfg.Domain
	default:
		for i := 0; i < 10; i++ {
			candidate := newID(8) + "." + s.cfg.Domain
			if _, taken := s.httpTunnels[candidate]; !taken {
				return candidate, nil
			}
		}
		return "", errors.New("failed to allocate a unique host")
	}
	if host == "" {
		return "", errors.New("cannot allocate host without a domain or subdomain")
	}
	if _, taken := s.httpTunnels[host]; taken {
		return "", fmt.Errorf("host %q already in use", host)
	}
	return host, nil
}

func (s *Server) allocateTCPPortLocked() (int, net.Listener, error) {
	for port := s.cfg.TCPStart; port <= s.cfg.TCPEnd; port++ {
		if _, inUse := s.tcpListeners[port]; inUse {
			continue
		}
		ln, err := net.Listen("tcp", ":"+strconv.Itoa(port))
		if err != nil {
			continue
		}
		return port, ln, nil
	}
	return 0, nil, errors.New("no free tcp ports available")
}

func (s *Server) publicHost() string {
	if s.cfg.Domain == "" {
		return "localhost"
	}
	return s.cfg.Domain
}

func (s *Server) acceptTCP(t *tunnel, ln net.Listener) {
	s.wg.Add(1)
	defer s.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			st, err := t.client.openStream(t.id)
			if err != nil {
				conn.Close()
				return
			}
			protocol.Bridge(st, conn)
		}()
	}
}

func (c *client) openStream(tunnelID string) (*protocol.Stream, error) {
	return c.mux.Open([]byte(tunnelID))
}

func (c *client) disconnected() {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.server.detach(c)
	})
}

func (s *Server) detach(c *client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.agents, c)

	for host, t := range s.httpTunnels {
		if t.client == c {
			delete(s.httpTunnels, host)
			s.log.Info("tunnel offline", "host", host, "agent", c.id)
		}
	}
	for id, t := range s.tcpTunnels {
		if t.client == c {
			if ln, ok := s.tcpListeners[t.port]; ok {
				ln.Close()
				delete(s.tcpListeners, t.port)
			}
			delete(s.tcpTunnels, id)
			s.log.Info("tunnel offline", "tcp_port", t.port, "agent", c.id)
		}
	}
}

func (s *Server) keepAlive(c *client) {
	ticker := time.NewTicker(keepAliveEvery)
	defer ticker.Stop()
	for {
		select {
		case <-c.closed:
			return
		case <-s.closed:
			return
		case <-ticker.C:
			if err := c.mux.Ping(pingTimeout); err != nil {
				c.mux.Close()
				return
			}
			if time.Since(c.mux.LastRead()) > keepAliveDead {
				c.mux.Close()
				return
			}
		}
	}
}

func (s *Server) sendError(c *client, message string) {
	b, err := protocol.MarshalControl(protocol.ErrorMsg{Type: protocol.TypeError, Message: message})
	if err != nil {
		return
	}
	_ = c.mux.SendControl(b)
}

// serveHTTP routes public requests to the owning tunnel.
func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ok"}`)
		return
	}

	host := hostOnly(r.Host)
	s.mu.RLock()
	t := s.httpTunnels[host]
	s.mu.RUnlock()
	if t == nil {
		if host == s.cfg.Domain || host == "" {
			s.serveLanding(w, r)
			return
		}
		http.NotFound(w, r)
		return
	}
	s.proxyHTTP(t, w, r)
}

func (s *Server) serveLanding(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, "<html><body><h1>kproxy</h1><p>server is online</p></body></html>")
}

// proxyHTTP relays a single public HTTP request over a tunnel stream.
func (s *Server) proxyHTTP(t *tunnel, w http.ResponseWriter, r *http.Request) {
	if isUpgrade(r) {
		s.proxyHTTPUpgrade(t, w, r)
		return
	}

	st, err := t.client.openStream(t.id)
	if err != nil {
		http.Error(w, "tunnel offline", http.StatusBadGateway)
		return
	}
	defer st.Close()

	if err := r.Write(st); err != nil {
		return
	}
	resp, err := http.ReadResponse(bufio.NewReader(st), r)
	if err != nil {
		http.Error(w, "tunnel error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// proxyHTTPUpgrade relays a WebSocket or other upgrade request by hijacking
// the client connection and tunneling raw bytes in both directions.
func (s *Server) proxyHTTPUpgrade(t *tunnel, w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, rw, err := hj.Hijack()
	if err != nil {
		return
	}

	st, err := t.client.openStream(t.id)
	if err != nil {
		clientConn.Close()
		return
	}

	if err := r.Write(st); err != nil {
		clientConn.Close()
		st.Close()
		return
	}
	resp, err := http.ReadResponse(bufio.NewReader(st), r)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		_, _ = io.WriteString(clientConn, "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
		clientConn.Close()
		st.Close()
		return
	}
	if err := resp.Write(rw); err != nil {
		clientConn.Close()
		st.Close()
		return
	}
	rw.Flush()
	protocol.Bridge(st, clientConn)
}

func isUpgrade(r *http.Request) bool {
	return strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// Close shuts the server down, closing all agent connections and listeners.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		close(s.closed)
		s.mu.Lock()
		agents := make([]*client, 0, len(s.agents))
		for c := range s.agents {
			agents = append(agents, c)
		}
		for _, ln := range s.tcpListeners {
			ln.Close()
		}
		s.mu.Unlock()
		for _, c := range agents {
			c.mux.Close()
		}
	})
	s.wg.Wait()
	return nil
}

func newID(chars int) string {
	b := make([]byte, chars)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)[:chars]
}

func hostOnly(h string) string {
	if h == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		return strings.ToLower(host)
	}
	return strings.ToLower(h)
}
