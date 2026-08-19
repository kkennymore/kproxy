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
	handshakeTimeout = 15 * time.Second
	dialTimeout      = 10 * time.Second
	heartbeatEvery   = 30 * time.Second
	pingTimeout      = 5 * time.Second
	defaultBase      = 1 * time.Second
	defaultMax       = 30 * time.Second
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
	// Logger receives agent logs.
	Logger *slog.Logger
}

// Agent maintains one tunnel connection at a time and reconnects on failure.
type Agent struct {
	cfg Config
	log *slog.Logger

	reconnectBase time.Duration
	reconnectMax  time.Duration

	mu     sync.Mutex
	active *protocol.Mux
	closed bool
}

// New creates an agent.
func New(cfg Config) *Agent {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Agent{
		cfg:           cfg,
		log:           cfg.Logger,
		reconnectBase: defaultBase,
		reconnectMax:  defaultMax,
	}
}

// Run connects to the server and keeps the tunnels alive until ctx is
// cancelled. It never returns a transient error; disconnects are retried
// with exponential backoff. It returns nil on clean shutdown.
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
			return fmt.Errorf("server: %s", e)
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

	go a.heartbeat(ctx, m)
	go a.acceptLoop(ctx, m)

	select {
	case err := <-runErr:
		m.Close()
		return err
	case <-ctx.Done():
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
		local := locals[string(st.Meta())]
		if local == "" {
			st.Close()
			continue
		}
		go func() {
			target, err := net.DialTimeout("tcp", local, dialTimeout)
			if err != nil {
				a.log.Warn("dial local target failed", "local", local, "error", err)
				st.Close()
				return
			}
			protocol.Bridge(st, target)
		}()
	}
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

// Close shuts the agent down and closes any active connection.
func (a *Agent) Close() {
	a.mu.Lock()
	a.closed = true
	m := a.active
	a.mu.Unlock()
	if m != nil {
		m.Close()
	}
}
