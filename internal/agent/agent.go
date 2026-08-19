// Package agent implements the kproxy client. It maintains a persistent
// connection to the relay server, reconnects with exponential backoff, and
// bridges tunneled streams to local services.
package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"kproxy/internal/protocol"
)

const (
	handshakeTimeout   = 15 * time.Second
	dialTimeout        = 10 * time.Second
	heartbeatEvery     = 30 * time.Second
	pingTimeout        = 5 * time.Second
	healthEveryDefault = 5 * time.Second
	probeTimeout       = 2 * time.Second
	localFailThreshold = 3
	defaultBase        = 1 * time.Second
	defaultMax         = 30 * time.Second
)

// Config configures an Agent.
type Config struct {
	// ServerURL is the relay endpoint, e.g. "https://relay.example.com:55555".
	ServerURL string
	// APIKey is presented during registration.
	APIKey string
	// Tunnels to open on each connection.
	Tunnels []protocol.TunnelSpec
	// OnWelcome is invoked after the server assigns public endpoints.
	OnWelcome func(protocol.Welcome)
	// OnAssigned is invoked when the server assigns additional tunnels after
	// registration (e.g. a recovered local target).
	OnAssigned func([]protocol.TunnelAssign)
	// HealthEvery is how often local tunnel targets are probed for liveness.
	HealthEvery time.Duration
	// LocalFailThreshold is the number of consecutive failed probes or dials
	// before a tunnel is gracefully closed. Zero uses the default.
	LocalFailThreshold int
	// Logger receives agent logs.
	Logger *slog.Logger
}

// Agent maintains one tunnel connection at a time and reconnects on failure.
type Agent struct {
	cfg Config
	log *slog.Logger

	reconnectBase time.Duration
	reconnectMax  time.Duration
	healthEvery   time.Duration
	failThreshold int
	tr            *tracker

	mu     sync.Mutex
	active *protocol.Mux
	closed bool
}

// New creates an agent.
func New(cfg Config) *Agent {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	healthEvery := cfg.HealthEvery
	if healthEvery == 0 {
		healthEvery = healthEveryDefault
	}
	failThreshold := cfg.LocalFailThreshold
	if failThreshold == 0 {
		failThreshold = localFailThreshold
	}
	return &Agent{
		cfg:           cfg,
		log:           cfg.Logger,
		reconnectBase: defaultBase,
		reconnectMax:  defaultMax,
		healthEvery:   healthEvery,
		failThreshold: failThreshold,
		tr:            newTracker(cfg.Tunnels),
	}
}

// ServerRejected marks a fatal rejection by the server (bad, revoked or
// expired api key, occupied resource) that should not be retried.
type ServerRejected struct{ Msg string }

func (e *ServerRejected) Error() string { return "server: " + e.Msg }

// Run connects to the server and keeps the tunnels alive until ctx is
// cancelled. It never returns a transient error; disconnects are retried
// with exponential backoff. It returns nil on clean shutdown and a
// *ServerRejected error for permanent rejections.
func (a *Agent) Run(ctx context.Context) error {
	backoff := a.reconnectBase
	for {
		err := a.runOnce(ctx)
		a.mu.Lock()
		closed := a.closed
		a.mu.Unlock()
		if closed {
			return nil
		}
		if err == nil || errors.Is(err, context.Canceled) {
			return nil
		}
		var rejected *ServerRejected
		if errors.As(err, &rejected) {
			return err
		}
		a.log.Warn("connection lost; reconnecting", "error", err, "in", backoff)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > a.reconnectMax {
			backoff = a.reconnectMax
		}
	}
}

func (a *Agent) runOnce(ctx context.Context) error {
	conn, err := a.dial(ctx)
	if err != nil {
		return err
	}
	m := protocol.NewMux(conn)

	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		m.Close()
		return nil
	}
	a.active = m
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		if a.active == m {
			a.active = nil
		}
		a.mu.Unlock()
	}()

	runErr := make(chan error, 1)
	go func() { runErr <- m.Run() }()

	hello, err := protocol.MarshalControl(protocol.Hello{
		Type:    protocol.TypeHello,
		Version: "0.1.0",
		APIKey:  a.cfg.APIKey,
		Tunnels: a.cfg.Tunnels,
	})
	if err != nil {
		m.Close()
		return err
	}
	if err := m.SendControl(hello); err != nil {
		m.Close()
		return err
	}

	var welcome protocol.Welcome
	select {
	case b := <-m.Control():
		if e := protocol.UnmarshalError(b); e != "" {
			m.Close()
			return &ServerRejected{Msg: e}
		}
		if err := protocol.UnmarshalControl(b, &welcome); err != nil {
			m.Close()
			return err
		}
	case err := <-runErr:
		return err
	case <-ctx.Done():
		m.Close()
		return ctx.Err()
	case <-time.After(handshakeTimeout):
		m.Close()
		return errors.New("handshake timeout")
	}

	a.log.Info("connected to relay", "server", a.cfg.ServerURL)
	if a.cfg.OnWelcome != nil {
		a.cfg.OnWelcome(welcome)
	}
	a.tr.reset()

	go a.heartbeat(ctx, m)
	go a.acceptLoop(ctx, m)
	go a.healthLoop(ctx, m)
	go a.controlLoop(ctx, m)

	select {
	case err := <-runErr:
		m.Close()
		return err
	case <-ctx.Done():
		a.sendClose(m, a.cfgTunnelIDs())
		m.Close()
		return ctx.Err()
	}
}

func (a *Agent) acceptLoop(ctx context.Context, m *protocol.Mux) {
	locals := make(map[string]string, len(a.cfg.Tunnels))
	for _, t := range a.cfg.Tunnels {
		locals[t.ID] = t.Local
	}
	for {
		st, err := m.Accept()
		if err != nil {
			return
		}
		id := string(st.Meta())
		local := locals[id]
		if local == "" {
			st.Close()
			continue
		}
		go func() {
			target, err := net.DialTimeout("tcp", local, dialTimeout)
			if err != nil {
				a.log.Warn("dial local target failed", "local", local, "error", err)
				if a.tr.markFailure(id, a.failThreshold) {
					a.log.Warn("local target down; closing tunnel", "tunnel", id, "local", local)
					a.sendClose(m, []string{id})
				}
				st.Close()
				return
			}
			protocol.Bridge(st, target)
		}()
	}
}

// controlLoop consumes control frames from the server after registration.
func (a *Agent) controlLoop(ctx context.Context, m *protocol.Mux) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.Done():
			return
		case b := <-m.Control():
			var hdr struct {
				Type string `json:"type"`
			}
			if err := protocol.UnmarshalControl(b, &hdr); err != nil {
				continue
			}
			switch hdr.Type {
			case protocol.TypeAssigned:
				var msg protocol.AssignedMsg
				if err := protocol.UnmarshalControl(b, &msg); err != nil {
					continue
				}
				a.log.Info("tunnels assigned", "count", len(msg.Tunnels))
				if a.cfg.OnAssigned != nil {
					a.cfg.OnAssigned(msg.Tunnels)
				}
			case protocol.TypeError:
				var msg protocol.ErrorMsg
				if err := protocol.UnmarshalControl(b, &msg); err != nil {
					continue
				}
				a.log.Warn("server", "error", msg.Message)
			}
		}
	}
}

// healthLoop probes local tunnel targets and gracefully closes tunnels whose
// target is down, reopening them when the target recovers.
func (a *Agent) healthLoop(ctx context.Context, m *protocol.Mux) {
	ticker := time.NewTicker(a.healthEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.Done():
			return
		case <-ticker.C:
			a.probeLocalTargets(m)
		}
	}
}

func (a *Agent) probeLocalTargets(m *protocol.Mux) {
	for _, t := range a.cfg.Tunnels {
		select {
		case <-m.Done():
			return
		default:
		}
		conn, err := net.DialTimeout("tcp", t.Local, probeTimeout)
		if err != nil {
			if a.tr.markFailure(t.ID, a.failThreshold) {
				a.log.Warn("local target down; closing tunnel", "tunnel", t.ID, "local", t.Local, "error", err)
				a.sendClose(m, []string{t.ID})
			}
			continue
		}
		conn.Close()
		if a.tr.markRecovered(t.ID) {
			a.log.Info("local target recovered; reopening tunnel", "tunnel", t.ID, "local", t.Local)
			a.sendAdd(m, []protocol.TunnelSpec{t})
		}
	}
}

func (a *Agent) sendClose(m *protocol.Mux, ids []string) {
	if m == nil || len(ids) == 0 {
		return
	}
	b, err := protocol.MarshalControl(protocol.CloseMsg{Type: protocol.TypeClose, Tunnels: ids})
	if err != nil {
		return
	}
	_ = m.SendControl(b)
}

func (a *Agent) sendAdd(m *protocol.Mux, specs []protocol.TunnelSpec) {
	if m == nil || len(specs) == 0 {
		return
	}
	b, err := protocol.MarshalControl(protocol.AddMsg{Type: protocol.TypeAdd, Tunnels: specs})
	if err != nil {
		return
	}
	_ = m.SendControl(b)
}

func (a *Agent) cfgTunnelIDs() []string {
	ids := make([]string, 0, len(a.cfg.Tunnels))
	for _, t := range a.cfg.Tunnels {
		ids = append(ids, t.ID)
	}
	return ids
}

func (a *Agent) heartbeat(ctx context.Context, m *protocol.Mux) {
	ticker := time.NewTicker(heartbeatEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.Ping(pingTimeout); err != nil {
				a.log.Warn("keepalive failed", "error", err)
				m.Close()
				return
			}
		}
	}
}

func (a *Agent) dial(ctx context.Context) (net.Conn, error) {
	u, err := url.Parse(a.cfg.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("invalid server url: %w", err)
	}
	addr := u.Host
	if u.Port() == "" {
		switch strings.ToLower(u.Scheme) {
		case "https":
			addr += ":443"
		default:
			addr += ":80"
		}
	}

	d := net.Dialer{Timeout: dialTimeout}
	switch strings.ToLower(u.Scheme) {
	case "http":
		return d.DialContext(ctx, "tcp", addr)
	case "https", "tls":
		raw, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		tc := tls.Client(raw, &tls.Config{ServerName: u.Hostname()})
		if err := tc.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, err
		}
		return tc, nil
	default:
		return nil, fmt.Errorf("unsupported server scheme %q", u.Scheme)
	}
}

// Close shuts the agent down gracefully, notifying the server to release all
// tunnels before tearing down the connection.
func (a *Agent) Close() {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	a.closed = true
	m := a.active
	a.mu.Unlock()
	if m != nil {
		a.sendClose(m, a.cfgTunnelIDs())
		m.Close()
	}
}

// tracker tracks the health of each configured local target so tunnels can be
// closed and reopened gracefully as their targets go up and down.
type tracker struct {
	mu   sync.Mutex
	up   map[string]bool
	fail map[string]int
}

func newTracker(specs []protocol.TunnelSpec) *tracker {
	tr := &tracker{
		up:   make(map[string]bool, len(specs)),
		fail: make(map[string]int, len(specs)),
	}
	for _, t := range specs {
		tr.up[t.ID] = true
	}
	return tr
}

// reset marks every tunnel healthy. Called when a connection (re)registers all
// tunnels via hello.
func (t *tracker) reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for id := range t.up {
		t.up[id] = true
		t.fail[id] = 0
	}
}

// markFailure records a failed dial or probe for id. It returns true when the
// failure count crosses the threshold while the tunnel was healthy, meaning
// the caller should close the tunnel. The tunnel is marked down on that
// transition.
func (t *tracker) markFailure(id string, threshold int) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.up[id] {
		return false
	}
	t.fail[id]++
	if t.fail[id] < threshold {
		return false
	}
	t.up[id] = false
	t.fail[id] = 0
	return true
}

// markRecovered records a successful probe. It returns true when the tunnel
// transitions from down to up, meaning the caller should reopen it.
func (t *tracker) markRecovered(id string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.fail[id] = 0
	if !t.up[id] {
		t.up[id] = true
		return true
	}
	return false
}
