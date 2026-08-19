package protocol

import (
	"io"
	"net"
	"sync"
)

// Bridge copies bytes bidirectionally between two net.Conns until either
// side closes, then closes both. It is the workhorse of the byte-bridge
// tunnel used by both the agent and the relay.
func Bridge(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(a, b)
		a.Close()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(b, a)
		b.Close()
	}()
	wg.Wait()
}
