package aether

// AE-L-15 regression tests: ConnectionConn must satisfy the net.Conn concurrency
// contract. SetDeadline may be called concurrently with an in-flight Read/Write,
// and concurrent Read callers must not race on the internal buffer. All race
// tests pass only under `go test -race` (the detector aborts on any data race).
// Every symbol here is prefixed ael15/AEL15 so it cannot collide with another
// agent's test file in the same package.

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// ael15Conn is a minimal aether.Connection fake. When blockRecv is false,
// Receive returns a copy of payload immediately (used by the deadline/buf race
// tests so every Read returns promptly). When blockRecv is true, Receive blocks
// until the context is cancelled or Close is called (used by the behavioural
// timeout tests).
type ael15Conn struct {
	payload   []byte
	blockRecv bool
	closeOnce sync.Once
	closeCh   chan struct{}
}

func newAEL15Conn(payload []byte, block bool) *ael15Conn {
	return &ael15Conn{payload: payload, blockRecv: block, closeCh: make(chan struct{})}
}

func (c *ael15Conn) Send(ctx context.Context, payload []byte) error { return nil }

func (c *ael15Conn) Receive(ctx context.Context) ([]byte, error) {
	if c.blockRecv {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-c.closeCh:
			return nil, io.EOF
		}
	}
	out := make([]byte, len(c.payload))
	copy(out, c.payload)
	return out, nil
}

func (c *ael15Conn) Close() error {
	c.closeOnce.Do(func() { close(c.closeCh) })
	return nil
}

func (c *ael15Conn) RemoteAddr() net.Addr   { return &net.TCPAddr{} }
func (c *ael15Conn) RemoteNodeID() NodeID    { return NodeID("") }
func (c *ael15Conn) NetConn() net.Conn       { return nil }
func (c *ael15Conn) Protocol() Protocol       { return Protocol(0) }
func (c *ael15Conn) OnClose(fn func())        {}

// TestAEL15_DeadlineSetRace hammers the three Set*Deadline setters concurrently
// with in-flight Read and Write calls. Pre-fix this reports a data race on
// c.deadline (a multi-word time.Time written without synchronisation while
// Read/Write read it). Post-fix the deadline is an atomic.Pointer, so the run
// completes cleanly under -race.
func TestAEL15_DeadlineSetRace(t *testing.T) {
	c := NewConnectionConn(newAEL15Conn([]byte{0}, false))
	const iters = 2000
	var wg sync.WaitGroup
	wg.Add(4)
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			_ = c.SetReadDeadline(time.Now().Add(time.Hour))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			_ = c.SetWriteDeadline(time.Now().Add(time.Millisecond))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			_, _ = c.Read(make([]byte, 16))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			_, _ = c.Write([]byte("x"))
		}
	}()
	wg.Wait()
}

// TestAEL15_ConcurrentReadBufRace runs two concurrent readers against a fake
// whose Receive returns a payload larger than the caller's buffer, so the
// overflow is stored in c.buf. Pre-fix the two readers race on c.buf (slice
// header read at Read's drain check vs writes when draining/refilling).
// Post-fix readMu serialises readers, so the run is race-free.
func TestAEL15_ConcurrentReadBufRace(t *testing.T) {
	c := NewConnectionConn(newAEL15Conn(make([]byte, 32), false))
	const iters = 2000
	var wg sync.WaitGroup
	wg.Add(2)
	for g := 0; g < 2; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				_, _ = c.Read(make([]byte, 4))
			}
		}()
	}
	wg.Wait()
}

// TestAEL15_SetReadDeadlinePastReturnsTimeout confirms the atomic swap preserves
// semantics: a deadline in the past yields an immediate *net.OpError wrapping
// context.DeadlineExceeded, without touching the underlying Receive.
func TestAEL15_SetReadDeadlinePastReturnsTimeout(t *testing.T) {
	c := NewConnectionConn(newAEL15Conn(nil, true))
	if err := c.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	n, err := c.Read(make([]byte, 8))
	if n != 0 {
		t.Fatalf("expected n==0 on expired deadline, got %d", n)
	}
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		t.Fatalf("expected *net.OpError, got %T (%v)", err, err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected wrapped context.DeadlineExceeded, got %v", err)
	}
}

// TestAEL15_ZeroDeadlineDisablesTimeout confirms a zero-value deadline disables
// the timeout: Read must block in Receive rather than return immediately.
func TestAEL15_ZeroDeadlineDisablesTimeout(t *testing.T) {
	fake := newAEL15Conn(nil, true)
	c := NewConnectionConn(fake)
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	done := make(chan struct{})
	go func() {
		_, _ = c.Read(make([]byte, 8))
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("Read returned early; a zero deadline must disable the timeout and block on Receive")
	case <-time.After(100 * time.Millisecond):
		// expected: still blocked on Receive
	}
	// Unblock the parked Read so the goroutine exits cleanly.
	_ = c.Close()
	<-done
}
