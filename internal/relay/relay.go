// Package relay implements the kproxyd side of the tunnel: it accepts agent
// control connections, assigns public endpoints, and routes incoming client
// traffic over the agent's multiplexed connection.
package relay

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"kproxy/internal/metrics"
	"kproxy/internal/protocol"
	"kproxy/internal/ratelimit"
	"kproxy/internal/store"
	"kproxy/internal/units"
)

const (
	defaultTCPStart = 20000
	defaultTCPEnd   = 29999
	helloTimeout    = 15 * time.Second
	keepAliveEvery  = 30 * time.Second
	keepAliveDead   = 90 * time.Second
	pingTimeout     = 5 * time.Second
	verifyTimeout   = 5 * time.Second
)

// KeyValidator authenticates an agent api key during registration and returns
// the key's identity (ID + policy limits) for per-key enforcement. The store
// package implements it; nil disables authentication (development).
type KeyValidator interface {
	ValidateKey(apiKey string) (*store.KeyIdentity, error)
}

// Config configures a relay Server.
type Config struct {
	// Domain is the base domain under which subdomains are allocated. It is
	// also used to build the public host of TCP tunnels.
	Domain string
	// Scheme is the scheme used in generated public URLs ("http" or "https").
	Scheme string
	// Keys validates agent api keys during registration. Nil allows all
	// keys (development only).
	Keys KeyValidator
	// TCPStart and TCPEnd bound the public port range for TCP tunnels.
	TCPStart int
	TCPEnd   int
	// VerifyKey is a secret used to derive per-domain verification tokens.
	// When non-empty, custom domains must be proven by setting a DNS TXT
	// record at _kproxy.<domain> before they are honored. Empty disables
	// verification (all custom domains are accepted).
	VerifyKey string
	// TXTLookup resolves TXT records for domain verification. Nil uses the
	// default resolver. Tests inject a fake.
	TXTLookup func(ctx context.Context, name string) ([]string, error)
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
	verified     map[string]struct{}
	events       broadcaster

	metrics  *metrics.Registry
	mReq     *metrics.Metric // kproxy_requests_total
	mBytes   *metrics.Metric // kproxy_tunnel_bytes_total
	mTunnels *metrics.Metric // kproxy_tunnels
	mAgents  *metrics.Metric // kproxy_agents
	mUptime  *metrics.Metric // kproxy_uptime_seconds
	mVersion *metrics.Metric // kproxy_version_info

	started   time.Time
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
	openedAt  time.Time
	client    *client

	basicAuth      string
	ipAllow        []*net.IPNet
	ipDeny         []*net.IPNet
	maxRequestSize int64
	requestTimeout time.Duration
	requests       atomic.Int64
	bytes          atomic.Int64
	lastActive     atomic.Int64 // unix nanos, 0 = none
	labels         []string     // metric label values: [tunnel, proto]
}

type client struct {
	id          string
	mux         *protocol.Mux
	server      *Server
	tunnels     map[string]*tunnel
	identity    *store.KeyIdentity
	requests    *ratelimit.Bucket // HTTP request rate, nil if unlimited
	bandwidth   *ratelimit.Bucket // tunnel bandwidth, nil if unlimited
	connectedAt time.Time

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
	reg := metrics.NewRegistry()
	return &Server{
		cfg:          cfg,
		log:          cfg.Logger,
		httpTunnels:  make(map[string]*tunnel),
		tcpTunnels:   make(map[string]*tunnel),
		tcpListeners: make(map[int]net.Listener),
		agents:       make(map[*client]struct{}),
		verified:     make(map[string]struct{}),
		metrics:      reg,
		mReq:         reg.Counter("kproxy_requests_total", "HTTP requests and TCP connections proxied.", "tunnel", "proto"),
		mBytes:       reg.Counter("kproxy_tunnel_bytes_total", "Bytes transferred through tunnels (both directions).", "tunnel", "proto"),
		mTunnels:     reg.Gauge("kproxy_tunnels", "Currently registered tunnels.", "proto"),
		mAgents:      reg.Gauge("kproxy_agents", "Connected agents."),
		mUptime:      reg.Gauge("kproxy_uptime_seconds", "Seconds since the relay started."),
		mVersion:     reg.Gauge("kproxy_version_info", "Relay version.", "version"),
		started:      time.Now(),
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
		id:          newID(6),
		mux:         m,
		server:      s,
		tunnels:     make(map[string]*tunnel),
		connectedAt: time.Now(),
		closed:      make(chan struct{}),
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
	if s.cfg.Keys != nil {
		identity, err := s.cfg.Keys.ValidateKey(hello.APIKey)
		if err != nil {
			s.log.Warn("agent rejected", "agent", c.id, "error", err)
			s.sendError(c, err.Error())
			m.Close()
			return
		}
		c.identity = identity
		c.requests, c.bandwidth = bucketsFor(identity.Limits)
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
		case b := <-m.Control():
			s.handleControl(c, b)
		}
	}
}

// handleControl processes a control message sent by an agent after
// registration.
func (s *Server) handleControl(c *client, b []byte) {
	var hdr struct {
		Type string `json:"type"`
	}
	if err := protocol.UnmarshalControl(b, &hdr); err != nil {
		return
	}
	switch hdr.Type {
	case protocol.TypeClose:
		var msg protocol.CloseMsg
		if err := protocol.UnmarshalControl(b, &msg); err == nil {
			s.closeTunnels(c, msg.Tunnels)
		}
	case protocol.TypeAdd:
		var msg protocol.AddMsg
		if err := protocol.UnmarshalControl(b, &msg); err == nil {
			s.addTunnels(c, msg.Tunnels)
		}
	}
}

// closeTunnels unregisters the given tunnels for a connected agent, freeing
// their public endpoints immediately. Unknown IDs are ignored.
func (s *Server) closeTunnels(c *client, ids []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range ids {
		t, ok := c.tunnels[id]
		if !ok {
			continue
		}
		delete(c.tunnels, id)
		info := t.info()
		switch t.proto {
		case protocol.ProtoHTTP:
			delete(s.httpTunnels, t.host)
			s.log.Info("tunnel closed", "host", t.host, "agent", c.id)
		case protocol.ProtoTCP:
			if ln, ok := s.tcpListeners[t.port]; ok {
				ln.Close()
				delete(s.tcpListeners, t.port)
			}
			delete(s.tcpTunnels, t.id)
			s.log.Info("tunnel closed", "tcp_port", t.port, "agent", c.id)
		}
		s.publish(Event{Type: "tunnel_close", Tunnel: &info})
	}
}

// addTunnels allocates additional tunnels for a connected agent and replies
// with their public assignments. On failure the whole batch is rejected with
// an error message; the connection stays up.
func (s *Server) addTunnels(c *client, specs []protocol.TunnelSpec) {
	if err := s.verifyCustomDomains(specs); err != nil {
		s.sendError(c, err.Error())
		return
	}
	s.mu.Lock()
	assigned := &protocol.AssignedMsg{Type: protocol.TypeAssigned}
	for _, spec := range specs {
		if _, exists := c.tunnels[spec.ID]; exists {
			s.mu.Unlock()
			s.sendError(c, "tunnel "+spec.ID+" already registered")
			return
		}
		t, err := s.registerSpecLocked(c, spec)
		if err != nil {
			s.mu.Unlock()
			s.sendError(c, err.Error())
			return
		}
		assigned.Tunnels = append(assigned.Tunnels, protocol.TunnelAssign{ID: t.id, PublicURL: t.publicURL})
	}
	s.mu.Unlock()

	b, err := protocol.MarshalControl(assigned)
	if err != nil {
		return
	}
	if err := c.mux.SendControl(b); err != nil {
		s.log.Warn("failed to send assignments", "agent", c.id, "error", err)
	}
}

func (s *Server) register(c *client, hello protocol.Hello) (*protocol.Welcome, error) {
	if err := s.verifyCustomDomains(hello.Tunnels); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	welcome := &protocol.Welcome{Type: protocol.TypeWelcome, Version: hello.Version, Server: s.cfg.Domain}
	for _, spec := range hello.Tunnels {
		t, err := s.registerSpecLocked(c, spec)
		if err != nil {
			return nil, err
		}
		welcome.Tunnels = append(welcome.Tunnels, protocol.TunnelAssign{ID: t.id, PublicURL: t.publicURL})
	}
	return welcome, nil
}

// registerSpecLocked allocates the public endpoint for one tunnel and stores
// it. The caller must hold s.mu.
func (s *Server) registerSpecLocked(c *client, spec protocol.TunnelSpec) (*tunnel, error) {
	var t *tunnel
	switch spec.Proto {
	case protocol.ProtoHTTP:
		if err := s.checkSubdomainAllowed(c, spec); err != nil {
			return nil, err
		}
		if spec.Domain != "" && s.cfg.VerifyKey != "" {
			if _, ok := s.verified[hostOnly(spec.Domain)]; !ok {
				return nil, fmt.Errorf("domain %q is not verified", hostOnly(spec.Domain))
			}
		}
		host, err := s.allocateHTTPHostLocked(spec)
		if err != nil {
			return nil, err
		}
		t = &tunnel{
			id:        spec.ID,
			proto:     spec.Proto,
			local:     spec.Local,
			host:      host,
			publicURL: s.cfg.Scheme + "://" + host,
			openedAt:  time.Now(),
			client:    c,
		}
		s.httpTunnels[host] = t
		info := t.info()
		s.publish(Event{Type: "tunnel_open", Tunnel: &info})

	case protocol.ProtoTCP:
		port, ln, err := s.allocateTCPPortLocked(spec)
		if err != nil {
			return nil, err
		}
		t = &tunnel{
			id:        spec.ID,
			proto:     spec.Proto,
			local:     spec.Local,
			port:      port,
			publicURL: "tcp://" + s.publicHost() + ":" + strconv.Itoa(port),
			openedAt:  time.Now(),
			client:    c,
		}
		s.tcpTunnels[spec.ID] = t
		s.tcpListeners[port] = ln
		go s.acceptTCP(t, ln)
		info := t.info()
		s.publish(Event{Type: "tunnel_open", Tunnel: &info})

	default:
		return nil, fmt.Errorf("unsupported tunnel protocol %q", spec.Proto)
	}
	if err := applySpecOptions(t, spec); err != nil {
		delete(s.httpTunnels, t.host)
		delete(s.tcpTunnels, t.id)
		if t.port != 0 {
			if ln, ok := s.tcpListeners[t.port]; ok {
				ln.Close()
				delete(s.tcpListeners, t.port)
			}
		}
		return nil, err
	}
	if t.proto == protocol.ProtoTCP {
		t.labels = []string{strconv.Itoa(t.port), t.proto}
	} else {
		t.labels = []string{t.host, t.proto}
	}
	c.tunnels[spec.ID] = t
	return t, nil
}

// verifyCustomDomains proves ownership of requested custom domains before
// registration. It runs outside the server lock (DNS lookups can be slow).
// Verified domains are cached for the lifetime of the server. When
// verification is disabled (no VerifyKey) it is a no-op.
func (s *Server) verifyCustomDomains(specs []protocol.TunnelSpec) error {
	if s.cfg.VerifyKey == "" {
		return nil
	}
	for _, spec := range specs {
		if spec.Proto != protocol.ProtoHTTP || spec.Domain == "" {
			continue
		}
		host := hostOnly(spec.Domain)
		s.mu.RLock()
		_, verified := s.verified[host]
		s.mu.RUnlock()
		if verified {
			continue
		}
		lookup := s.cfg.TXTLookup
		if lookup == nil {
			lookup = net.DefaultResolver.LookupTXT
		}
		ctx, cancel := context.WithTimeout(context.Background(), verifyTimeout)
		records, err := lookup(ctx, "_kproxy."+host)
		cancel()
		if err != nil {
			var dnsErr *net.DNSError
			if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
				token := verifyToken(s.cfg.VerifyKey, host)
				return fmt.Errorf("domain %q is not verified; set a TXT record at _kproxy.%s with value %q", host, host, token)
			}
			return fmt.Errorf("domain %q verification lookup failed: %w", host, err)
		}
		token := verifyToken(s.cfg.VerifyKey, host)
		if !slices.Contains(records, token) {
			return fmt.Errorf("domain %q is not verified; set a TXT record at _kproxy.%s with value %q", host, host, token)
		}
		s.mu.Lock()
		s.verified[host] = struct{}{}
		s.mu.Unlock()
	}
	return nil
}

// VerifyToken returns the DNS TXT verification token for a custom domain, or
// an empty string when domain verification is disabled.
func (s *Server) VerifyToken(domain string) string {
	if s.cfg.VerifyKey == "" {
		return ""
	}
	return verifyToken(s.cfg.VerifyKey, hostOnly(domain))
}

// verifyToken derives a deterministic per-domain token from the server's
// verify key, so the operator can set the TXT record before any agent asks
// for the domain.
func verifyToken(key, domain string) string {
	h := sha256.Sum256([]byte(domain + "|" + key))
	return "kproxy-verify-" + hex.EncodeToString(h[:8])
}

// applySpecOptions parses and stores a tunnel's security options, validating
// them server-side (the agent is not trusted).
func applySpecOptions(t *tunnel, spec protocol.TunnelSpec) error {
	if spec.BasicAuth != "" {
		if t.proto != protocol.ProtoHTTP {
			return errors.New("basic auth only applies to http tunnels")
		}
		if !strings.Contains(spec.BasicAuth, ":") {
			return errors.New("basic auth must be in user:pass form")
		}
		t.basicAuth = spec.BasicAuth
	}
	if len(spec.IPAllow) > 0 {
		nets, err := parseIPNets(spec.IPAllow)
		if err != nil {
			return err
		}
		t.ipAllow = nets
	}
	if len(spec.IPDeny) > 0 {
		nets, err := parseIPNets(spec.IPDeny)
		if err != nil {
			return err
		}
		t.ipDeny = nets
	}
	if spec.MaxRequestSize != "" {
		if t.proto != protocol.ProtoHTTP {
			return errors.New("max request size only applies to http tunnels")
		}
		n, err := units.ParseSize(spec.MaxRequestSize)
		if err != nil || n <= 0 {
			return fmt.Errorf("invalid max request size %q", spec.MaxRequestSize)
		}
		t.maxRequestSize = n
	}
	if spec.RequestTimeout != "" {
		if t.proto != protocol.ProtoHTTP {
			return errors.New("request timeout only applies to http tunnels")
		}
		d, err := units.ParseTTL(spec.RequestTimeout)
		if err != nil || d <= 0 {
			return fmt.Errorf("invalid request timeout %q", spec.RequestTimeout)
		}
		t.requestTimeout = d
	}
	return nil
}

func parseIPNets(items []string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ipnet, err := net.ParseCIDR(item); err == nil {
			out = append(out, ipnet)
			continue
		}
		ip := net.ParseIP(item)
		if ip == nil {
			return nil, fmt.Errorf("invalid ip or cidr %q", item)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return out, nil
}

// ipAllowed applies a tunnel's IP allow/deny lists. Deny wins over allow; an
// empty allow list admits everyone not denied.
func (t *tunnel) ipAllowed(ip net.IP) bool {
	for _, n := range t.ipDeny {
		if n.Contains(ip) {
			return false
		}
	}
	if len(t.ipAllow) == 0 {
		return true
	}
	for _, n := range t.ipAllow {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// authOK checks HTTP Basic credentials against the tunnel's basic auth
// configuration. Tunnels without basic auth admit everyone.
func (t *tunnel) authOK(r *http.Request) bool {
	if t.basicAuth == "" {
		return true
	}
	user, pass, ok := r.BasicAuth()
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(user+":"+pass), []byte(t.basicAuth)) == 1
}

// markRequest records a handled connection/request against the tunnel so the
// control plane can report per-tunnel usage.
func (t *tunnel) markRequest(bytes int64) {
	t.requests.Add(1)
	t.bytes.Add(bytes)
	t.lastActive.Store(time.Now().UnixNano())
}

func (t *tunnel) lastActiveTime() time.Time {
	if n := t.lastActive.Load(); n > 0 {
		return time.Unix(0, n)
	}
	return time.Time{}
}

func remoteIP(s string) net.IP {
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		return net.ParseIP(s)
	}
	return net.ParseIP(host)
}

// checkSubdomainAllowed enforces a key's allowed-subdomain list. Random-hash
// tunnels are always allowed; claimed subdomains and custom domains must be in
// the list when one is configured.
func (s *Server) checkSubdomainAllowed(c *client, spec protocol.TunnelSpec) error {
	if c.identity == nil {
		return nil
	}
	allowed := c.identity.Limits.AllowedSubdomains
	if len(allowed) == 0 {
		return nil
	}
	switch {
	case spec.Domain != "":
		h := hostOnly(spec.Domain)
		if !slices.Contains(allowed, h) {
			return fmt.Errorf("domain %q not allowed for this key", h)
		}
	case spec.Subdomain != "":
		if !slices.Contains(allowed, strings.ToLower(spec.Subdomain)) {
			return fmt.Errorf("subdomain %q not allowed for this key", spec.Subdomain)
		}
	}
	return nil
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

// allocateTCPPortLocked binds the public listener for a TCP tunnel. A
// requested port (spec.Port) is honored exactly when free; otherwise a port is
// picked from the configured range.
func (s *Server) allocateTCPPortLocked(spec protocol.TunnelSpec) (int, net.Listener, error) {
	if spec.Port != 0 {
		if _, taken := s.tcpListeners[spec.Port]; taken {
			return 0, nil, fmt.Errorf("port %d already in use", spec.Port)
		}
		ln, err := net.Listen("tcp", ":"+strconv.Itoa(spec.Port))
		if err != nil {
			return 0, nil, fmt.Errorf("cannot bind requested port %d: %w", spec.Port, err)
		}
		return spec.Port, ln, nil
	}
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
			if !t.ipAllowed(remoteIP(conn.RemoteAddr().String())) {
				conn.Close()
				return
			}
			t.markRequest(0)
			s.mReq.Inc(t.labels...)
			st, err := t.client.openStream(t.id)
			if err != nil {
				conn.Close()
				return
			}
			count := &countConn{}
			protocol.Bridge(
				t.client.pace(count.wrap(st, t)),
				t.client.pace(count.wrap(conn, t)),
			)
		}()
	}
}

// countConn wraps a net.Conn so bytes written through it count toward a
// tunnel's usage totals.
type countConn struct{}

func (countConn) wrap(conn net.Conn, t *tunnel) net.Conn {
	return &countingConn{Conn: conn, t: t}
}

type countingConn struct {
	net.Conn
	t *tunnel
}

func (c *countingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.t.bytes.Add(int64(n))
		c.t.lastActive.Store(time.Now().UnixNano())
		c.t.client.server.mBytes.Add(int64(n), c.t.labels...)
	}
	return n, err
}

func (c *client) openStream(tunnelID string) (*protocol.Stream, error) {
	return c.mux.Open([]byte(tunnelID))
}

// pace wraps a net.Conn so its writes are throttled by the client's bandwidth
// bucket. Unlimited clients pass through untouched.
func (c *client) pace(conn net.Conn) net.Conn {
	if c.bandwidth == nil {
		return conn
	}
	return &pacedConn{Conn: conn, pw: &pacedWriter{w: conn, b: c.bandwidth}}
}

// paceWriter wraps an io.Writer (e.g. an HTTP response) with the client's
// bandwidth bucket.
func (c *client) paceWriter(w io.Writer) io.Writer {
	if c.bandwidth == nil {
		return w
	}
	return &pacedWriter{w: w, b: c.bandwidth}
}

// bucketsFor builds the request-rate and bandwidth buckets for a key's limits.
// A zero limit yields a nil bucket (unlimited).
func bucketsFor(l store.Limits) (*ratelimit.Bucket, *ratelimit.Bucket) {
	var requests, bandwidth *ratelimit.Bucket
	if l.RequestsPerSec > 0 {
		r := float64(l.RequestsPerSec)
		requests = ratelimit.New(r, r)
	}
	if l.BandwidthPerSec > 0 {
		b := float64(l.BandwidthPerSec)
		bandwidth = ratelimit.New(b, b)
	}
	return requests, bandwidth
}

// pacedConn preserves the net.Conn read side of the wrapped connection while
// throttling writes.
type pacedConn struct {
	net.Conn
	pw *pacedWriter
}

func (p *pacedConn) Write(b []byte) (int, error) {
	return p.pw.Write(b)
}

// pacedWriter throttles writes through a shared token bucket.
type pacedWriter struct {
	w io.Writer
	b *ratelimit.Bucket
}

func (p *pacedWriter) Write(b []byte) (int, error) {
	p.b.Wait(float64(len(b)))
	return p.w.Write(b)
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
			info := t.info()
			s.publish(Event{Type: "tunnel_close", Tunnel: &info})
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
			info := t.info()
			s.publish(Event{Type: "tunnel_close", Tunnel: &info})
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
	if !t.ipAllowed(remoteIP(r.RemoteAddr)) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if !t.authOK(r) {
		w.Header().Set("WWW-Authenticate", `Basic realm="kproxy"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if t.client.requests != nil && !t.client.requests.Take(1) {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	if t.maxRequestSize > 0 {
		if r.ContentLength > t.maxRequestSize {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = &sizeLimited{ReadCloser: r.Body, limit: t.maxRequestSize}
	}
	rid := newID(8)
	r.Header.Set("X-Request-Id", rid)
	if t.requestTimeout > 0 {
		http.TimeoutHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.proxyHTTP(t, w, r, rid)
		}), t.requestTimeout, "request timed out").ServeHTTP(w, r)
		return
	}
	s.proxyHTTP(t, w, r, rid)
}

func (s *Server) serveLanding(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, "<html><body><h1>kproxy</h1><p>server is online</p></body></html>")
}

// proxyHTTP relays a single public HTTP request over a tunnel stream and
// publishes a request event to control-plane subscribers.
func (s *Server) proxyHTTP(t *tunnel, w http.ResponseWriter, r *http.Request, rid string) {
	start := time.Now()
	if isUpgrade(r) {
		s.proxyHTTPUpgrade(t, w, r, start, rid)
		return
	}
	sw := &statusWriter{ResponseWriter: w}
	w.Header().Set("X-Request-Id", rid)
	s.proxy(t, sw, r)
	t.markRequest(sw.bytes)
	s.mReq.Inc(t.labels...)
	s.mBytes.Add(sw.bytes, t.labels...)
	s.publishRequestEvent(t, r, start, sw.statusCode(), sw.bytes, rid)
}

func (s *Server) publishRequestEvent(t *tunnel, r *http.Request, start time.Time, status int, bytes int64, rid string) {
	s.publish(Event{Type: "request", Request: &RequestInfo{
		Time:      start,
		Host:      t.host,
		Method:    r.Method,
		Path:      r.URL.Path,
		Status:    status,
		Duration:  time.Since(start),
		Bytes:     bytes,
		RequestID: rid,
	}})
}

// statusWriter records the response status and bytes written so the request
// inspector can display them.
type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (sw *statusWriter) WriteHeader(code int) {
	if sw.status == 0 {
		sw.status = code
	}
	sw.ResponseWriter.WriteHeader(code)
}

func (sw *statusWriter) Write(b []byte) (int, error) {
	if sw.status == 0 {
		sw.status = http.StatusOK
	}
	n, err := sw.ResponseWriter.Write(b)
	sw.bytes += int64(n)
	return n, err
}

func (sw *statusWriter) statusCode() int {
	if sw.status == 0 {
		return http.StatusOK
	}
	return sw.status
}

// proxy relays one request over the tunnel stream without instrumentation.
func (s *Server) proxy(t *tunnel, w http.ResponseWriter, r *http.Request) {
	st, err := t.client.openStream(t.id)
	if err != nil {
		http.Error(w, "tunnel offline", http.StatusBadGateway)
		return
	}
	defer st.Close()

	if err := r.Write(t.client.pace(st)); err != nil {
		if isBodyTooLarge(err) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		}
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
	_, _ = io.Copy(t.client.paceWriter(w), resp.Body)
}

// sizeLimited caps the number of bytes read from a request body, returning
// errBodyTooLarge once the cap is crossed so the relay can answer 413 without
// trusting the client's Content-Length.
type sizeLimited struct {
	io.ReadCloser
	limit    int64
	n        int64
	tooLarge bool
}

var errBodyTooLarge = errors.New("request body too large")

// isBodyTooLarge reports whether err (or an error it wraps) is errBodyTooLarge.
// http.Request.Write wraps body-read errors in an unexported type that does not
// implement Unwrap, so a message comparison is used as a fallback.
func isBodyTooLarge(err error) bool {
	if errors.Is(err, errBodyTooLarge) {
		return true
	}
	return err != nil && err.Error() == errBodyTooLarge.Error()
}

func (s *sizeLimited) Read(p []byte) (int, error) {
	if s.tooLarge {
		return 0, errBodyTooLarge
	}
	if remaining := s.limit + 1 - s.n; int64(len(p)) > remaining {
		p = p[:remaining]
	}
	n, err := s.ReadCloser.Read(p)
	s.n += int64(n)
	if s.n > s.limit {
		s.tooLarge = true
		return n, errBodyTooLarge
	}
	return n, err
}

// proxyHTTPUpgrade relays a WebSocket or other upgrade request by hijacking
// the client connection and tunneling raw bytes in both directions.
func (s *Server) proxyHTTPUpgrade(t *tunnel, w http.ResponseWriter, r *http.Request, start time.Time, rid string) {
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

	if err := r.Write(t.client.pace(st)); err != nil {
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
	resp.Header.Set("X-Request-Id", rid)
	if err := resp.Write(rw); err != nil {
		clientConn.Close()
		st.Close()
		return
	}
	rw.Flush()
	t.markRequest(0)
	s.mReq.Inc(t.labels...)
	s.publishRequestEvent(t, r, start, http.StatusSwitchingProtocols, 0, rid)
	count := &countConn{}
	protocol.Bridge(
		t.client.pace(count.wrap(st, t)),
		t.client.pace(count.wrap(clientConn, t)),
	)
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
