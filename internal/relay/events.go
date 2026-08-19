package relay

import (
	"net/http"
	"sync"
	"time"

	"kproxy/internal/protocol"
	"kproxy/internal/version"
)

// TunnelInfo is a snapshot of an active tunnel for the control plane.
type TunnelInfo struct {
	ID        string    `json:"id"`
	Proto     string    `json:"proto"`
	Local     string    `json:"local"`
	Host      string    `json:"host,omitempty"`
	Port      int       `json:"port,omitempty"`
	PublicURL string    `json:"public_url"`
	AgentID   string    `json:"agent_id"`
	OpenedAt  time.Time `json:"opened_at"`
	// Requests and Bytes are per-tunnel usage since the tunnel opened.
	Requests       int64     `json:"requests"`
	Bytes          int64     `json:"bytes"`
	LastActive     time.Time `json:"last_active,omitempty"`
	AgentConnected time.Time `json:"agent_connected_at,omitempty"`
}

// RequestInfo describes one proxied HTTP request for the request inspector.
type RequestInfo struct {
	Time      time.Time     `json:"time"`
	Host      string        `json:"host"`
	Method    string        `json:"method"`
	Path      string        `json:"path"`
	Status    int           `json:"status"`
	Duration  time.Duration `json:"duration"`
	Bytes     int64         `json:"bytes"`
	RequestID string        `json:"request_id,omitempty"`
}

// Event is streamed to control-plane subscribers (the dashboard's SSE feed).
type Event struct {
	Type    string       `json:"type"` // tunnel_open | tunnel_close | request
	Tunnel  *TunnelInfo  `json:"tunnel,omitempty"`
	Request *RequestInfo `json:"request,omitempty"`
}

// Subscribe registers a channel that receives relay events. The returned
// function unsubscribes. Subscribers that fall behind silently drop events.
func (s *Server) Subscribe() (<-chan Event, func()) {
	s.events.mu.Lock()
	defer s.events.mu.Unlock()
	ch := make(chan Event, 64)
	if s.events.subs == nil {
		s.events.subs = make(map[chan Event]struct{})
	}
	s.events.subs[ch] = struct{}{}
	return ch, func() {
		s.events.mu.Lock()
		delete(s.events.subs, ch)
		s.events.mu.Unlock()
	}
}

// publish fans an event out to all subscribers without blocking callers.
func (s *Server) publish(e Event) {
	s.events.mu.Lock()
	defer s.events.mu.Unlock()
	for ch := range s.events.subs {
		select {
		case ch <- e:
		default:
		}
	}
}

// Tunnels returns a snapshot of all currently registered tunnels.
func (s *Server) Tunnels() []TunnelInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]TunnelInfo, 0, len(s.httpTunnels)+len(s.tcpTunnels))
	for _, t := range s.httpTunnels {
		out = append(out, t.info())
	}
	for _, t := range s.tcpTunnels {
		out = append(out, t.info())
	}
	return out
}

func (t *tunnel) info() TunnelInfo {
	return TunnelInfo{
		ID:             t.id,
		Proto:          t.proto,
		Local:          t.local,
		Host:           t.host,
		Port:           t.port,
		PublicURL:      t.publicURL,
		AgentID:        t.client.id,
		OpenedAt:       t.openedAt,
		Requests:       t.requests.Load(),
		Bytes:          t.bytes.Load(),
		LastActive:     t.lastActiveTime(),
		AgentConnected: t.client.connectedAt,
	}
}

// Status is an aggregate snapshot of the relay for a status endpoint.
type Status struct {
	Uptime   time.Duration `json:"uptime"`
	Tunnels  int           `json:"tunnels"`
	Agents   int           `json:"agents"`
	Requests int64         `json:"requests_total"`
	Bytes    int64         `json:"bytes_total"`
}

// Status returns aggregate relay statistics.
func (s *Server) Status() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st := Status{
		Uptime:  time.Since(s.started),
		Tunnels: len(s.httpTunnels) + len(s.tcpTunnels),
		Agents:  len(s.agents),
	}
	for _, t := range s.httpTunnels {
		st.Requests += t.requests.Load()
		st.Bytes += t.bytes.Load()
	}
	for _, t := range s.tcpTunnels {
		st.Requests += t.requests.Load()
		st.Bytes += t.bytes.Load()
	}
	return st
}

type broadcaster struct {
	mu   sync.Mutex
	subs map[chan Event]struct{}
}

// MetricsHandler returns an http.Handler that serves the relay's metrics in
// the Prometheus text exposition format.
func (s *Server) MetricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		s.refreshGauges()
		_ = s.metrics.Render(w)
	})
}

// refreshGauges derives the gauge metrics from the current relay state. Counters
// are cumulative and are incremented in the request paths directly.
func (s *Server) refreshGauges() {
	s.mu.RLock()
	httpN, tcpN := 0, 0
	for range s.httpTunnels {
		httpN++
	}
	for range s.tcpTunnels {
		tcpN++
	}
	agents := len(s.agents)
	s.mu.RUnlock()
	s.mTunnels.Set(int64(httpN), protocol.ProtoHTTP)
	s.mTunnels.Set(int64(tcpN), protocol.ProtoTCP)
	s.mAgents.Set(int64(agents))
	s.mUptime.Set(int64(time.Since(s.started).Seconds()))
	s.mVersion.Set(1, version.String())
}
