package protocol

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func newMuxPair(t *testing.T) (*Mux, *Mux) {
	t.Helper()
	c1, c2 := net.Pipe()
	m1 := NewMux(c1)
	m2 := NewMux(c2)
	go m1.Run()
	go m2.Run()
	t.Cleanup(func() { m1.Close(); m2.Close() })
	return m1, m2
}

func TestStreamBidirectional(t *testing.T) {
	m1, m2 := newMuxPair(t)

	s1, err := m1.Open([]byte("tunnel:main"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	s2, err := m2.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if string(s2.Meta()) != "tunnel:main" {
		t.Fatalf("meta = %q, want tunnel:main", s2.Meta())
	}

	msg := []byte("hello from agent side")
	if _, err := s2.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(s1, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("got %q, want %q", got, msg)
	}

	msg2 := []byte("and from the server side")
	if _, err := s1.Write(msg2); err != nil {
		t.Fatalf("write: %v", err)
	}
	got2 := make([]byte, len(msg2))
	if _, err := io.ReadFull(s2, got2); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got2, msg2) {
		t.Fatalf("got %q, want %q", got2, msg2)
	}
}

func TestStreamCloseSignalsEOF(t *testing.T) {
	m1, m2 := newMuxPair(t)
	s1, err := m1.Open(nil)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := m2.Accept()
	if err != nil {
		t.Fatal(err)
	}

	if err := s1.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	got, err := io.ReadAll(s2)
	if err != nil {
		t.Fatalf("read all: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d bytes after close, want 0", len(got))
	}
}

func TestDataFlushedBeforeEOF(t *testing.T) {
	m1, m2 := newMuxPair(t)
	s1, err := m1.Open(nil)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := m2.Accept()
	if err != nil {
		t.Fatal(err)
	}

	payload := bytes.Repeat([]byte("x"), 4096)
	if _, err := s1.Write(payload); err != nil {
		t.Fatal(err)
	}
	// The peer writes then closes immediately; the reader must still observe
	// every byte before EOF.
	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(s2)
	if err != nil {
		t.Fatalf("read all: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("got %d bytes, want %d", len(got), len(payload))
	}
}

func TestConcurrentStreams(t *testing.T) {
	m1, m2 := newMuxPair(t)
	const streams = 32
	const rounds = 200

	opened := make([]*Stream, 0, streams)
	for i := 0; i < streams; i++ {
		s, err := m1.Open([]byte("t"))
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		opened = append(opened, s)
	}
	accepted := make([]*Stream, 0, streams)
	for i := 0; i < streams; i++ {
		s, err := m2.Accept()
		if err != nil {
			t.Fatalf("accept %d: %v", i, err)
		}
		accepted = append(accepted, s)
	}

	pairs := make(map[uint64]*Stream, streams)
	for _, s := range accepted {
		pairs[s.ID()] = s
	}

	var wg sync.WaitGroup
	for i, s1 := range opened {
		s2, ok := pairs[s1.ID()]
		if !ok {
			t.Fatalf("stream %d has no peer", s1.ID())
		}
		wg.Add(1)
		go func(i int, s1, s2 *Stream) {
			defer wg.Done()
			for j := 0; j < rounds; j++ {
				msg := fmt.Sprintf("s%d-r%d", i, j)
				if _, err := s1.Write([]byte(msg)); err != nil {
					t.Errorf("write %d/%d: %v", i, j, err)
					return
				}
				buf := make([]byte, len(msg))
				if _, err := io.ReadFull(s2, buf); err != nil {
					t.Errorf("read %d/%d: %v", i, j, err)
					return
				}
				if string(buf) != msg {
					t.Errorf("stream %d got %q, want %q", i, buf, msg)
					return
				}
			}
			s1.Close()
			s2.Close()
		}(i, s1, s2)
	}
	wg.Wait()
}

func TestControlFrames(t *testing.T) {
	m1, m2 := newMuxPair(t)
	payload := []byte(`{"type":"hello","api_key":"secret"}`)
	if err := m1.SendControl(payload); err != nil {
		t.Fatalf("send control: %v", err)
	}
	select {
	case got := <-m2.Control():
		if !bytes.Equal(got, payload) {
			t.Fatalf("got %q, want %q", got, payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for control frame")
	}
}

func TestPing(t *testing.T) {
	m1, _ := newMuxPair(t)
	if err := m1.Ping(2 * time.Second); err != nil {
		t.Fatalf("ping: %v", err)
	}
}

func TestMuxCloseTerminatesStreams(t *testing.T) {
	m1, m2 := newMuxPair(t)
	s1, err := m1.Open(nil)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := m2.Accept()
	if err != nil {
		t.Fatal(err)
	}

	m2.Close()

	buf := make([]byte, 16)
	if _, err := s1.Read(buf); err == nil {
		t.Fatal("expected read error after mux close")
	}
	if _, err := s2.Read(buf); err == nil {
		t.Fatal("expected read error after mux close")
	}
}

func TestBridgeEcho(t *testing.T) {
	testA, testB := net.Pipe()
	echoA, echoB := net.Pipe()
	defer testB.Close()
	defer echoA.Close()
	defer echoB.Close()

	go Bridge(testB, echoA)

	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := echoB.Read(buf)
			if err != nil {
				return
			}
			if _, err := echoB.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	written := []byte("ping-msg")
	if _, err := testA.Write(written); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(written))
	if _, err := io.ReadFull(testA, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, written) {
		t.Fatalf("got %q, want %q", got, written)
	}
}

// TestSlowStreamDoesNotBlockOthers verifies that exhausting one stream's flow
// window does not stall a second stream multiplexed on the same connection.
func TestSlowStreamDoesNotBlockOthers(t *testing.T) {
	m1, m2 := newMuxPair(t)
	open := func(m *Mux) *Stream {
		s, err := m.Open(nil)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		return s
	}
	a1, b1 := open(m1), open(m1)
	a2, err := m2.Accept()
	if err != nil {
		t.Fatal(err)
	}
	b2, err := m2.Accept()
	if err != nil {
		t.Fatal(err)
	}

	// Flood stream A from m1 without m2 reading it. The writer blocks once the
	// window is exhausted rather than consuming the underlying connection.
	fill := make(chan error, 1)
	go func() {
		_, err := io.Copy(a1, bytes.NewReader(bytes.Repeat([]byte("x"), 4*streamWindowSize)))
		a1.Close()
		fill <- err
	}()

	time.Sleep(50 * time.Millisecond)

	// Stream B must still carry data end-to-end.
	msg := []byte("b-still-works")
	if _, err := b1.Write(msg); err != nil {
		t.Fatalf("write on b: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(b2, got); err != nil {
		t.Fatalf("read on b: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("got %q, want %q", got, msg)
	}

	// Now drain stream A; the blocked writer must finish.
	if _, err := io.Copy(io.Discard, a2); err != nil {
		t.Fatalf("drain a: %v", err)
	}
	select {
	case err := <-fill:
		if err != nil {
			t.Fatalf("fill: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("writer did not resume after drain")
	}
}

// TestWriteBlocksOnExhaustedWindow verifies that a writer stalls exactly at
// the window boundary and resumes once the reader consumes data and grants
// more credit.
func TestWriteBlocksOnExhaustedWindow(t *testing.T) {
	m1, m2 := newMuxPair(t)
	s1, err := m1.Open(nil)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := m2.Accept()
	if err != nil {
		t.Fatal(err)
	}

	const total = 3 * streamWindowSize
	payload := bytes.Repeat([]byte("z"), total)
	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(s1, bytes.NewReader(payload))
		s1.Close()
		done <- err
	}()

	// Read half a window first: the writer should still be mid-window, then
	// block once its window runs out.
	buf := make([]byte, streamWindowHalf)
	if _, err := io.ReadFull(s2, buf); err != nil {
		t.Fatalf("first read: %v", err)
	}
	if !bytes.Equal(buf, payload[:streamWindowHalf]) {
		t.Fatal("first half mismatch")
	}

	select {
	case err := <-done:
		t.Fatalf("writer finished before window exhausted: %v", err)
	case <-time.After(300 * time.Millisecond):
	}

	// Drain everything; the writer must complete with the exact bytes.
	rest, err := io.ReadAll(s2)
	if err != nil {
		t.Fatalf("read all: %v", err)
	}
	if len(rest) != total-streamWindowHalf {
		t.Fatalf("got %d bytes, want %d", len(rest), total-streamWindowHalf)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("writer: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("writer did not resume")
	}
}

// TestLargeTransferRoundTrip pushes a multi-window payload in both directions
// and verifies byte-for-byte integrity under flow control.
func TestLargeTransferRoundTrip(t *testing.T) {
	m1, m2 := newMuxPair(t)
	s1, err := m1.Open(nil)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := m2.Accept()
	if err != nil {
		t.Fatal(err)
	}

	up := bytes.Repeat([]byte("A"), 5*streamWindowSize)
	down := bytes.Repeat([]byte("B"), 3*streamWindowSize)

	errc := make(chan error, 2)
	go func() { _, err := io.Copy(s1, bytes.NewReader(up)); s1.Close(); errc <- err }()
	go func() { _, err := io.Copy(s2, bytes.NewReader(down)); s2.Close(); errc <- err }()

	gotUp, err := io.ReadAll(s2)
	if err != nil {
		t.Fatalf("read up: %v", err)
	}
	gotDown, err := io.ReadAll(s1)
	if err != nil {
		t.Fatalf("read down: %v", err)
	}
	if !bytes.Equal(gotUp, up) {
		t.Fatalf("up mismatch: got %d, want %d", len(gotUp), len(up))
	}
	if !bytes.Equal(gotDown, down) {
		t.Fatalf("down mismatch: got %d, want %d", len(gotDown), len(down))
	}
	for i := 0; i < 2; i++ {
		if err := <-errc; err != nil {
			t.Fatalf("copy: %v", err)
		}
	}
}
