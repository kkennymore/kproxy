// Package protocol implements the wire protocol between a kproxy agent and
// the kproxyd relay server.
//
// A single persistent connection is shared by many concurrent logical
// streams. Each stream carries the raw bytes of one proxied client
// connection (HTTP or TCP). Control messages (registration, tunnel
// assignment) travel out of band as JSON frames.
//
// Streams use a sliding window for flow control: each side advertises an
// implicit initial window and grants more credit with FrameWindow frames as
// the application consumes bytes. A slow reader on one stream therefore
// applies backpressure only to that stream, never stalling the others
// multiplexed on the same connection.
package protocol

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// frameHeaderSize is the fixed length of every frame header.
	frameHeaderSize = 13
	// maxFrameSize caps a single payload to bound memory usage.
	maxFrameSize = 16 << 20
	// incomingCap bounds queued peer-opened streams awaiting acceptance.
	incomingCap = 128
	// controlCap bounds queued control frames awaiting processing.
	controlCap = 64

	// streamWindowSize is the initial per-stream send/receive window in bytes.
	streamWindowSize = 256 << 10
	// streamWindowHalf is the threshold at which the receiver grants credit
	// back to the sender.
	streamWindowHalf = streamWindowSize / 2
	// streamBufMax bounds a stream's receive buffer. Window-respecting peers
	// never exceed it; only a peer that ignores our window can, and then the
	// reader loop blocks (or drops frames once the stream is closing).
	streamBufMax = 2 * streamWindowSize
)

// FrameType identifies the kind of frame in the wire protocol.
type FrameType byte

const (
	FrameData    FrameType = 1
	FrameOpen    FrameType = 2
	FrameClose   FrameType = 3
	FrameControl FrameType = 4
	FramePing    FrameType = 5
	FramePong    FrameType = 6
	FrameWindow  FrameType = 7
)

var (
	ErrMuxClosed     = errors.New("protocol: mux is closed")
	ErrStreamClosed  = errors.New("protocol: stream is closed")
	errFrameTooLarge = errors.New("protocol: frame exceeds max size")
)

// Mux multiplexes concurrent streams over one net.Conn.
type Mux struct {
	conn net.Conn

	wmu     sync.Mutex
	closed  chan struct{}
	onClose func()
	once    sync.Once

	mu       sync.Mutex
	nextID   uint64
	streams  map[uint64]*Stream
	incoming chan *Stream
	control  chan []byte

	lastRead atomic.Int64
	lastPong atomic.Int64
}

// NewMux wraps conn in a mux. Run must be called in a goroutine to start the
// read loop; Close releases all resources.
func NewMux(conn net.Conn) *Mux {
	m := &Mux{
		conn:     conn,
		closed:   make(chan struct{}),
		streams:  make(map[uint64]*Stream),
		incoming: make(chan *Stream, incomingCap),
		control:  make(chan []byte, controlCap),
	}
	now := time.Now().UnixNano()
	m.lastRead.Store(now)
	m.lastPong.Store(now)
	return m
}

// SetOnClose registers fn to run once when the mux is closed or fails.
func (m *Mux) SetOnClose(fn func()) {
	m.onClose = fn
}

// Run consumes frames from the underlying connection until it closes or a
// protocol error occurs. It returns nil on clean EOF.
func (m *Mux) Run() error {
	r := bufio.NewReaderSize(m.conn, 32<<10)
	for {
		typ, id, payload, err := readFrame(r)
		if err != nil {
			m.Close()
			return err
		}
		m.touchRead()
		m.dispatch(typ, id, payload)
	}
}

// readFrame reads one frame: 4-byte big-endian length, 1-byte type, 8-byte
// stream id, then the payload.
func readFrame(r io.Reader) (FrameType, uint64, []byte, error) {
	var hdr [frameHeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, 0, nil, err
	}
	length := binary.BigEndian.Uint32(hdr[0:4])
	typ := FrameType(hdr[4])
	id := binary.BigEndian.Uint64(hdr[5:13])
	if length > maxFrameSize {
		return 0, 0, nil, fmt.Errorf("%w: %d", errFrameTooLarge, length)
	}
	var payload []byte
	if length > 0 {
		payload = make([]byte, length)
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, 0, nil, err
		}
	}
	return typ, id, payload, nil
}

func (m *Mux) dispatch(typ FrameType, id uint64, payload []byte) {
	switch typ {
	case FrameData:
		m.handleData(id, payload)
	case FrameOpen:
		m.handleOpen(id, payload)
	case FrameClose:
		m.handleClose(id)
	case FrameWindow:
		m.handleWindow(id, payload)
	case FrameControl:
		select {
		case m.control <- payload:
		case <-m.closed:
		}
	case FramePing:
		_ = m.writeFrame(FramePong, 0, payload)
	case FramePong:
		m.lastPong.Store(time.Now().UnixNano())
	}
}

func (m *Mux) handleOpen(id uint64, payload []byte) {
	s := newStream(m, id, payload)
	m.mu.Lock()
	if m.isClosed() {
		m.mu.Unlock()
		return
	}
	m.streams[id] = s
	m.mu.Unlock()

	select {
	case m.incoming <- s:
	case <-m.closed:
	}
}

func (m *Mux) handleData(id uint64, payload []byte) {
	m.mu.Lock()
	s := m.streams[id]
	m.mu.Unlock()
	if s == nil {
		return
	}
	s.push(payload)
}

func (m *Mux) handleClose(id uint64) {
	m.mu.Lock()
	s := m.streams[id]
	m.mu.Unlock()
	if s != nil {
		s.remoteClosed()
	}
}

// handleWindow grants a stream additional send credit.
func (m *Mux) handleWindow(id uint64, payload []byte) {
	m.mu.Lock()
	s := m.streams[id]
	m.mu.Unlock()
	if s == nil {
		return
	}
	inc := uint32(0)
	if len(payload) >= 4 {
		inc = binary.BigEndian.Uint32(payload)
	}
	s.mu.Lock()
	s.sendWin += int64(inc)
	s.winCond.Broadcast()
	s.mu.Unlock()
}

// Open allocates a new stream addressed to the peer. The metadata payload is
// delivered to the remote side in the open frame.
func (m *Mux) Open(payload []byte) (*Stream, error) {
	m.mu.Lock()
	if m.isClosed() {
		m.mu.Unlock()
		return nil, ErrMuxClosed
	}
	id := m.allocID()
	s := newStream(m, id, payload)
	m.streams[id] = s
	m.mu.Unlock()

	if err := m.writeFrame(FrameOpen, id, payload); err != nil {
		m.mu.Lock()
		delete(m.streams, id)
		m.mu.Unlock()
		s.terminate()
		return nil, err
	}
	return s, nil
}

// Accept returns the next stream opened by the peer.
func (m *Mux) Accept() (*Stream, error) {
	select {
	case s := <-m.incoming:
		return s, nil
	case <-m.closed:
		return nil, ErrMuxClosed
	}
}

// Control returns the channel of control frames received from the peer.
func (m *Mux) Control() <-chan []byte {
	return m.control
}

// Done returns a channel closed when the mux is torn down.
func (m *Mux) Done() <-chan struct{} {
	return m.closed
}

// SendControl sends a control frame to the peer.
func (m *Mux) SendControl(payload []byte) error {
	return m.writeFrame(FrameControl, 0, payload)
}

// Ping sends a keepalive probe and blocks until the matching pong arrives,
// the mux closes, or timeout elapses.
func (m *Mux) Ping(timeout time.Duration) error {
	if err := m.writeFrame(FramePing, 0, nil); err != nil {
		return err
	}
	mark := time.Now().UnixNano()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if m.lastPong.Load() >= mark {
			return nil
		}
		select {
		case <-m.closed:
			return ErrMuxClosed
		default:
			time.Sleep(20 * time.Millisecond)
		}
	}
	return errors.New("protocol: ping timeout")
}

// LastRead returns the time of the last frame received from the peer.
func (m *Mux) LastRead() time.Time {
	return time.Unix(0, m.lastRead.Load())
}

func (m *Mux) writeFrame(typ FrameType, id uint64, payload []byte) error {
	if m.isClosed() {
		return ErrMuxClosed
	}
	hdr := make([]byte, frameHeaderSize)
	binary.BigEndian.PutUint32(hdr[0:4], uint32(len(payload)))
	hdr[4] = byte(typ)
	binary.BigEndian.PutUint64(hdr[5:13], id)

	m.wmu.Lock()
	defer m.wmu.Unlock()
	if _, err := m.conn.Write(hdr); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := m.conn.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

func (m *Mux) allocID() uint64 {
	for {
		m.nextID++
		if m.nextID == 0 {
			m.nextID = 1
		}
		if _, exists := m.streams[m.nextID]; !exists {
			return m.nextID
		}
	}
}

func (m *Mux) touchRead() {
	m.lastRead.Store(time.Now().UnixNano())
}

func (m *Mux) isClosed() bool {
	select {
	case <-m.closed:
		return true
	default:
		return false
	}
}

// Close tears down the mux and all live streams.
func (m *Mux) Close() {
	m.once.Do(func() {
		close(m.closed)
		m.mu.Lock()
		streams := make([]*Stream, 0, len(m.streams))
		for _, s := range m.streams {
			streams = append(streams, s)
		}
		m.streams = make(map[uint64]*Stream)
		m.mu.Unlock()
		for _, s := range streams {
			s.terminate()
		}
		_ = m.conn.Close()
		if m.onClose != nil {
			m.onClose()
		}
	})
}

// Stream is a bidirectional byte channel multiplexed over a Mux. It
// implements net.Conn so it can be passed to io.Copy and friends.
//
// Flow control: both ends start with streamWindowSize credits. Writes reserve
// credit and block (per stream) once it is exhausted; the reader grants more
// credit with FrameWindow frames as the application consumes data. The
// receive side is a byte buffer, so a slow reader only ever backs up its own
// stream.
type Stream struct {
	mux  *Mux
	id   uint64
	meta []byte

	mu      sync.Mutex
	cond    *sync.Cond // buffer data available / space available
	winCond *sync.Cond // send credit available
	buf     []byte
	bufEOF  bool

	sendWin      int64
	recvConsumed int64
	closedBy     uint8
}

// newStream returns an unregistered stream. The caller decides whether it was
// initiated locally or by the peer.
func newStream(m *Mux, id uint64, meta []byte) *Stream {
	s := &Stream{
		mux:     m,
		id:      id,
		meta:    meta,
		sendWin: streamWindowSize,
	}
	s.cond = sync.NewCond(&s.mu)
	s.winCond = sync.NewCond(&s.mu)
	return s
}

// ID returns the stream identifier.
func (s *Stream) ID() uint64 { return s.id }

// Meta returns the payload carried by the open frame (e.g. the target tunnel
// id).
func (s *Stream) Meta() []byte { return s.meta }

// push appends data received from the peer. It is called from the mux read
// loop. Window-respecting peers never fill the buffer, so push returns
// immediately for them; a peer that ignores our window blocks the read loop
// until the reader drains (bounded memory) or drops frames once the stream is
// closing.
func (s *Stream) push(b []byte) {
	s.mu.Lock()
	for len(s.buf)+len(b) > streamBufMax && !s.bufEOF && !s.mux.isClosed() {
		s.cond.Wait()
	}
	if s.bufEOF || s.mux.isClosed() {
		s.cond.Broadcast()
		s.mu.Unlock()
		return
	}
	s.buf = append(s.buf, b...)
	s.cond.Broadcast()
	s.mu.Unlock()
}

// Read implements io.Reader. It returns io.EOF once the peer has closed the
// stream and buffered data is drained.
func (s *Stream) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		if len(s.buf) > 0 {
			n := copy(p, s.buf)
			s.buf = s.buf[n:]
			s.recvConsumed += int64(n)
			s.cond.Broadcast() // wake a blocked push
			s.maybeGrant()
			return n, nil
		}
		if s.bufEOF {
			return 0, io.EOF
		}
		s.cond.Wait()
	}
}

// maybeGrant sends a FrameWindow once the reader has consumed half a window,
// so the peer can send more. The caller must hold s.mu.
func (s *Stream) maybeGrant() {
	if s.recvConsumed < streamWindowHalf {
		return
	}
	inc := uint32(s.recvConsumed)
	s.recvConsumed = 0
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, inc)
	_ = s.mux.writeFrame(FrameWindow, s.id, payload)
}

// Write implements io.Writer. It chunks the payload to the current send
// window, blocking (per stream) when the peer has not consumed enough data to
// grant more credit.
func (s *Stream) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		s.mu.Lock()
		for s.sendWin <= 0 && s.closedBy&1 == 0 && !s.mux.isClosed() {
			s.winCond.Wait()
		}
		if s.closedBy&1 != 0 {
			s.mu.Unlock()
			if total > 0 {
				return total, nil
			}
			return 0, ErrStreamClosed
		}
		if s.mux.isClosed() {
			s.mu.Unlock()
			if total > 0 {
				return total, nil
			}
			return 0, ErrMuxClosed
		}
		chunk := int64(len(p))
		if chunk > s.sendWin {
			chunk = s.sendWin
		}
		if chunk == 0 {
			s.mu.Unlock()
			continue
		}
		s.sendWin -= chunk
		s.mu.Unlock()

		if err := s.mux.writeFrame(FrameData, s.id, p[:chunk]); err != nil {
			s.mu.Lock()
			s.sendWin += chunk
			s.mu.Unlock()
			return int(total), err
		}
		total += int(chunk)
		p = p[chunk:]
	}
	return total, nil
}

// Close marks the local side closed and notifies the peer.
func (s *Stream) Close() error {
	s.mu.Lock()
	if s.closedBy&1 != 0 {
		s.mu.Unlock()
		return nil
	}
	s.closedBy |= 1
	both := s.closedBy == 3
	s.winCond.Broadcast()
	s.mu.Unlock()
	_ = s.mux.writeFrame(FrameClose, s.id, nil)
	if both {
		s.remove()
	}
	return nil
}

func (s *Stream) remoteClosed() {
	s.mu.Lock()
	if s.closedBy&2 != 0 {
		s.mu.Unlock()
		return
	}
	s.closedBy |= 2
	both := s.closedBy == 3
	s.bufEOF = true
	s.cond.Broadcast()
	s.mu.Unlock()
	if both {
		s.remove()
	}
}

func (s *Stream) remove() {
	s.mux.mu.Lock()
	if _, ok := s.mux.streams[s.id]; ok {
		delete(s.mux.streams, s.id)
	}
	s.mux.mu.Unlock()
}

// terminate force-closes the stream without signaling the peer. Used on mux
// shutdown.
func (s *Stream) terminate() {
	s.mu.Lock()
	s.closedBy |= 3
	s.bufEOF = true
	s.cond.Broadcast()
	s.winCond.Broadcast()
	s.mu.Unlock()
	s.remove()
}

var streamAddr = &dummyAddr{"kproxy"}

type dummyAddr struct{ s string }

func (a *dummyAddr) Network() string { return "kproxy" }
func (a *dummyAddr) String() string  { return a.s }

// LocalAddr implements net.Conn.
func (s *Stream) LocalAddr() net.Addr { return streamAddr }

// RemoteAddr implements net.Conn.
func (s *Stream) RemoteAddr() net.Addr { return streamAddr }

func (s *Stream) SetDeadline(t time.Time) error      { return nil }
func (s *Stream) SetReadDeadline(t time.Time) error  { return nil }
func (s *Stream) SetWriteDeadline(t time.Time) error { return nil }
