//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// failWriteConn is a net.Conn whose Write always errors — modelling a dead
// peer / a write-deadline timeout — so connWrite hits its teardown branch.
// Read blocks until Close so no phantom read loop spins; every other method
// is an inert no-op. SetWriteDeadline is present so the conn satisfies
// writeDeadlineConn (writeFrame's optional deadline bound).
type failWriteConn struct {
	writeErr error
	done     chan struct{}
	once     sync.Once
}

func (c *failWriteConn) Read(b []byte) (int, error) {
	<-c.done
	return 0, errors.New("closed")
}
func (c *failWriteConn) Write(b []byte) (int, error) { return 0, c.writeErr }
func (c *failWriteConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return nil
}
func (c *failWriteConn) LocalAddr() net.Addr                { return noiseCloseTestAddr{} }
func (c *failWriteConn) RemoteAddr() net.Addr               { return noiseCloseTestAddr{} }
func (c *failWriteConn) SetDeadline(t time.Time) error      { return nil }
func (c *failWriteConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *failWriteConn) SetWriteDeadline(t time.Time) error { return nil }

type noiseCloseTestAddr struct{}

func (noiseCloseTestAddr) Network() string { return "fake" }
func (noiseCloseTestAddr) String() string  { return "fake" }

// TestConnWriteErrorDoesNotDeadlockWriteMu is the AE-H-02 regression guard.
//
// connWrite runs only while writeFrame holds s.writeMu. On a write error it
// tears the session down via CloseWithError, whose connGrantDebouncer flush
// re-enters writeFrame (sendWindowUpdate). If that teardown were called
// synchronously it would re-acquire the non-reentrant writeMu on the same
// goroutine and self-deadlock — wedging every other writeFrame caller and
// leaking the fd. The fix dispatches CloseWithError on its own goroutine.
//
// Here we prime the conn-level grant debouncer with pending consume so the
// teardown's flush actually re-enters writeFrame (the exact deadlock path),
// then drive one writeFrame over a conn whose Write always fails. Pre-fix
// the writeFrame call never returns (deadlock, caught by the timeout);
// post-fix it returns promptly, the session closes on the spawned goroutine,
// and writeMu is released rather than held by a wedged goroutine.
func TestConnWriteErrorDoesNotDeadlockWriteMu(t *testing.T) {
	const deadline = 2 * time.Second

	conn := &failWriteConn{writeErr: errors.New("write boom"), done: make(chan struct{})}
	s := NewNoiseSession(
		conn,
		aether.NodeID("vl1_local_node_id_aehq02_abcdef"),
		aether.NodeID("vl1_remote_node_id_aehq02_ghijk"),
		aether.DefaultSessionOptions(),
	)

	// Prime the conn-level grant debouncer with pending consume WITHOUT going
	// through Record() — set the field directly (same package) so no coalesce
	// timer or watchdog sweep flushes it early. CloseWithError's
	// connGrantDebouncer.Close() will then flush this pending, emit a grant,
	// and re-enter writeFrame via sendWindowUpdate — the re-entrant writeMu
	// acquisition that self-deadlocked before the fix.
	s.connGrantDebouncer.mu.Lock()
	s.connGrantDebouncer.pending = 1 << 20
	s.connGrantDebouncer.mu.Unlock()

	// writeFrame acquires writeMu, encodes, then connWrite hits the failing
	// Write and triggers teardown. Run it on its own goroutine so a pre-fix
	// deadlock is observable via the timeout instead of hanging the test.
	done := make(chan error, 1)
	go func() {
		done <- s.writeFrame(&aether.Frame{Type: aether.TypePING, StreamID: s.layout.Control})
	}()

	select {
	case <-done:
		// Returned — no self-deadlock. (writeFrame surfaces the write error;
		// we assert only that it returned, not the specific error value.)
	case <-time.After(deadline):
		t.Fatal("AE-H-02 regression: writeFrame deadlocked on write-error teardown — " +
			"connWrite must dispatch CloseWithError on its own goroutine")
	}

	// Teardown must have run: SignalClose fires at the top of CloseWithError,
	// so a closed CloseSignal proves the deferred goroutine executed.
	select {
	case <-s.CloseSignal():
	case <-time.After(deadline):
		t.Fatal("AE-H-02 regression: session CloseSignal never closed — async teardown did not run")
	}

	// writeMu must be free again. A teardown goroutine wedged mid-re-entry
	// (or the original goroutine never unwinding) would hold it, and this
	// Lock/Unlock would block past the deadline.
	relocked := make(chan struct{})
	go func() {
		s.writeMu.Lock()
		s.writeMu.Unlock()
		close(relocked)
	}()
	select {
	case <-relocked:
	case <-time.After(deadline):
		t.Fatal("AE-H-02 regression: writeMu still held after teardown — the teardown goroutine wedged holding it")
	}
}
