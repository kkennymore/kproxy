// Package protocol implements the wire protocol between a kproxy agent and
// the kproxyd relay server.
//
// A single persistent connection is shared by many concurrent logical
// streams. Each stream carries the raw bytes of one proxied client
// connection (HTTP or TCP). Control messages (registration, tunnel
// assignment) travel out of band as JSON frames.
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
	// streamRecvCap bounds buffered chunks queued per stream before the mux
	// read loop applies backpressure.
	streamRecvCap = 256
	// incomingCap bounds queued peer-opened streams awaiting acceptance.
	incomingCap = 128
	// controlCap bounds queued control frames awaiting processing.
	controlCap = 64
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
		var hdr [frameHeaderSize]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			m.Close()
			return err
		}
		length := binary.BigEndian.Uint32(hdr[0:4])
		typ := FrameType(hdr[4])
		id := binary.BigEndian.Uint64(hdr[5:13])

		if length > maxFrameSize {
			m.Close()
			return fmt.Errorf("%w: %d", errFrameTooLarge, length)
		}

		var payload []byte
		if length > 0 {
			payload = make([]byte, length)
			if _, err := io.ReadFull(r, payload); err != nil {
				m.Close()
				return err
			}
		}

		m.touchRead()
		m.dispatch(typ, id, payload)
	}
}

func (m *Mux) dispatch(typ FrameType, id uint64, payload []byte) {
	switch typ {
	case FrameData:
		m.handleData(id, payload)
	case FrameOpen:
		m.handleOpen(id, payload)
	case FrameClose:
		m.handleClose(id)
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
type Stream struct {
	mux  *Mux
	id   uint64
	meta []byte
	recv chan []byte

	sig      sync.Once
	closed   chan struct{}
	mu       sync.Mutex
	closedBy uint8
	readBuf  []byte
}

// newStream returns an unregistered stream. The caller decides whether it was
// initiated locally or by the peer.
func newStream(m *Mux, id uint64, meta []byte) *Stream {
	return &Stream{
		mux:    m,
		id:     id,
		meta:   meta,
		recv:   make(chan []byte, streamRecvCap),
		closed: make(chan struct{}),
	}
}

// ID returns the stream identifier.
func (s *Stream) ID() uint64 { return s.id }

// Meta returns the payload carried by the open frame (e.g. the target tunnel
// id).
func (s *Stream) Meta() []byte { return s.meta }

func (s *Stream) push(b []byte) {
	select {
	case s.recv <- b:
	case <-s.closed:
	}
}

// Read implements io.Reader. It returns io.EOF once the peer has closed the
// stream and buffered data is drained.
func (s *Stream) Read(p []byte) (int, error) {
	for {
		s.mu.Lock()
		if len(s.readBuf) > 0 {
			n := copy(p, s.readBuf)
			s.readBuf = s.readBuf[n:]
			s.mu.Unlock()
			return n, nil
		}
		s.mu.Unlock()

		select {
		case b, ok := <-s.recv:
			if !ok {
				return 0, io.EOF
			}
			n := copy(p, b)
			if n < len(b) {
				s.mu.Lock()
				s.readBuf = b[n:]
				s.mu.Unlock()
			}
			return n, nil
		case <-s.closed:
			for {
				select {
				case b := <-s.recv:
					n := copy(p, b)
					if n < len(b) {
						s.mu.Lock()
						s.readBuf = b[n:]
						s.mu.Unlock()
					}
					return n, nil
				default:
					return 0, io.EOF
				}
			}
		}
	}
}

// Write implements io.Writer.
func (s *Stream) Write(p []byte) (int, error) {
	s.mu.Lock()
	if s.closedBy != 0 {
		s.mu.Unlock()
		return 0, ErrStreamClosed
	}
	s.mu.Unlock()
	if err := s.mux.writeFrame(FrameData, s.id, p); err != nil {
		return 0, err
	}
	return len(p), nil
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
	s.mu.Unlock()
	s.sig.Do(func() { close(s.closed) })
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
	s.mu.Unlock()
	s.remove()
	s.sig.Do(func() { close(s.closed) })
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
