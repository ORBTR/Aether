/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/ORBTR/aether"
)

// StreamConn bridges an Aether Stream to the net.Conn interface.
// This is the single canonical net.Conn adapter for Aether streams, used by
// gossip, PingableConn, and any consumer that needs byte-stream semantics
// over Aether's message-oriented streams.
//
// Key capabilities:
//   - Read/Write with message-to-byte-stream buffering (partial reads)
//   - SetReadDeadline bounds Receive with a context.WithDeadline;
//     SetWriteDeadline bounds Send through writeDeadline
//   - Parent context propagation (cancelled when connection dies)
//   - StreamID accessor for debug logging
//   - net.Conn compliant (verified by interface assertion)
type StreamConn struct {
	stream     aether.Stream
	parentCtx  context.Context
	readCtx    context.Context    // per-exchange deadline context
	readCancel context.CancelFunc // cancels readCtx
	buf        []byte             // read buffer for partial message reads
	writeDL    writeDeadline      // bounds Write; see SetWriteDeadline
}

// Ensure net.Conn compliance at compile time.
var _ net.Conn = (*StreamConn)(nil)

// NewStreamConn creates a net.Conn wrapper around an Aether Stream.
// The parent context controls the connection lifetime — when cancelled,
// all blocked Read/Write operations return immediately.
// If no parent context is provided, context.Background() is used.
func NewStreamConn(stream aether.Stream, parentCtx ...context.Context) *StreamConn {
	ctx := context.Background()
	if len(parentCtx) > 0 && parentCtx[0] != nil {
		ctx = parentCtx[0]
	}
	return &StreamConn{
		stream:    stream,
		parentCtx: ctx,
	}
}

// Read implements net.Conn. Reads data from the Aether stream.
// Aether streams are message-oriented (Receive returns a complete message).
// This method buffers partial reads so callers can use io.ReadFull and
// other byte-stream patterns.
//
// Uses readCtx (set by SetReadDeadline or SetDeadline) if available,
// otherwise parentCtx.
// Not concurrent-safe — callers must not call Read from multiple goroutines.
func (c *StreamConn) Read(p []byte) (int, error) {
	// Return buffered data from a previous oversized Receive
	if len(c.buf) > 0 {
		n := copy(p, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}

	ctx := c.activeCtx()
	data, err := c.stream.Receive(ctx)
	if err != nil {
		return 0, err
	}

	n := copy(p, data)
	if n < len(data) {
		c.buf = data[n:]
	}
	return n, nil
}

// Write implements net.Conn. Sends data on the Aether stream as a single message.
// On Aether, Send() enqueues to the scheduler and returns immediately (non-blocking
// for TCP/WS). For Noise-UDP, flow control may block until credit is available.
//
// Send is message-atomic, so a Write either sends all of p or none of it.
// Under a write deadline that has passed, or that passes while Send is
// blocked, Write returns 0 and os.ErrDeadlineExceeded. After Close, or when
// Close ends a blocked Send, it returns 0 and net.ErrClosed.
func (c *StreamConn) Write(p []byte) (int, error) {
	ctx, end, err := c.writeDL.begin(c.parentCtx)
	if err != nil {
		return 0, err
	}
	defer end()
	if err := c.stream.Send(ctx, p); err != nil {
		if ended := c.writeDL.ended(); ended != nil {
			return 0, ended
		}
		return 0, err
	}
	return len(p), nil
}

// Close cancels the read deadline's context, ends every Write blocked in
// Send and refuses later ones, then closes the underlying Aether stream.
// net.Conn requires Close to unblock a blocked Write, and the stream's
// Close alone does not: noiseStream.Close leaves a Send waiting for
// flow-control credit until flow.ConsumeTimeout.
func (c *StreamConn) Close() error {
	if c.readCancel != nil {
		c.readCancel()
		c.readCancel = nil
		c.readCtx = nil
	}
	c.writeDL.close()
	return c.stream.Close()
}

// SetDeadline sets the read and the write deadline, as net.Conn defines.
func (c *StreamConn) SetDeadline(t time.Time) error {
	c.setReadDeadline(t)
	c.writeDL.set(t)
	return nil
}

// SetReadDeadline creates a per-exchange context with the given deadline.
// When the deadline fires, any blocked Read (stream.Receive) is cancelled.
// This prevents goroutine leaks when callers use concurrent read patterns
// with timeout-based fallback (e.g., GossipOverConn).
//
// Pass time.Time{} (zero) to clear the deadline and revert to parentCtx.
func (c *StreamConn) SetReadDeadline(t time.Time) error {
	c.setReadDeadline(t)
	return nil
}

// SetWriteDeadline bounds every Write that starts before t and every
// Write already blocked in Send; a zero t clears it. Extending it while a
// Write is blocked extends that Write too. Callers that run a byte
// protocol over the view (yamux, gossip) need a Write that cannot hold
// their send goroutine forever when the peer stops granting credit.
func (c *StreamConn) SetWriteDeadline(t time.Time) error {
	c.writeDL.set(t)
	return nil
}

// setReadDeadline replaces readCtx with one bounded at t (none for a zero
// t), cancelling the previous one.
func (c *StreamConn) setReadDeadline(t time.Time) {
	// Cancel any previous deadline
	if c.readCancel != nil {
		c.readCancel()
	}
	// Flush stale read buffer from any previous failed exchange.
	// Without this, a partial payload from a timed-out exchange remains
	// in buf and is read as the next exchange's magic header — causing
	// "invalid magic 0xXXXX" errors (JSON fragments misread as headers).
	c.buf = nil
	if t.IsZero() {
		c.readCtx = nil
		c.readCancel = nil
		return
	}
	c.readCtx, c.readCancel = context.WithDeadline(c.parentCtx, t)
}

// LocalAddr implements net.Conn with a placeholder Aether address.
func (c *StreamConn) LocalAddr() net.Addr {
	return streamConnAddr{fmt.Sprintf("aether-stream-%d-local", c.stream.StreamID())}
}

// RemoteAddr implements net.Conn with a placeholder Aether address.
func (c *StreamConn) RemoteAddr() net.Addr {
	return streamConnAddr{fmt.Sprintf("aether-stream-%d-remote", c.stream.StreamID())}
}

// StreamID returns the underlying Aether stream ID for debug logging.
func (c *StreamConn) StreamID() uint64 { return c.stream.StreamID() }

// AvailableCredit returns the send-side flow-control credit currently
// available on the underlying stream, or -1 if the stream doesn't expose
// flow control (e.g. QUIC, which has its own native flow control and
// bypasses the Aether credit layer).
//
// Callers (notably gossip) use this to self-throttle: when credit is low,
// prefer a delta sync over a full sync to avoid guaranteed ConsumeTimeout
// stalls. This is an agnostic check — any stream type that exposes an
// `AvailableCredit() int64` method via the underlying adapter is picked up.
func (c *StreamConn) AvailableCredit() int64 {
	type avail interface{ AvailableCredit() int64 }
	if a, ok := c.stream.(avail); ok {
		return a.AvailableCredit()
	}
	return -1
}

// ParentContext returns the connection-level context. Useful for callers
// that need to derive sub-contexts tied to the connection lifetime.
func (c *StreamConn) ParentContext() context.Context { return c.parentCtx }

// activeCtx returns readCtx if a read deadline is set, otherwise parentCtx.
func (c *StreamConn) activeCtx() context.Context {
	if c.readCtx != nil {
		return c.readCtx
	}
	return c.parentCtx
}

// streamConnAddr implements net.Addr for StreamConn.
type streamConnAddr struct{ s string }

func (a streamConnAddr) Network() string { return "aether" }
func (a streamConnAddr) String() string  { return a.s }

// writeDeadline is StreamConn's write deadline and its close. Each Write
// registers the cancel of the context its Send runs under; the deadline
// passing, or close, cancels every registered Send, and a Write that
// starts after either is refused before Send. Re-setting the deadline
// re-arms the timer without cancelling a running Send, so an extended or
// cleared deadline applies to a Write already blocked, as net.Conn
// requires. gen discards a timer that fired after a later set replaced it.
// Safe for concurrent use.
type writeDeadline struct {
	mu      sync.Mutex
	timer   *time.Timer
	gen     uint64
	expired bool
	closed  bool
	running map[uint64]context.CancelFunc
	nextID  uint64
}

// set arms the deadline at t; a zero t clears it. After close it does
// nothing: begin refuses every Write, so a timer would guard none.
func (d *writeDeadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return
	}
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	d.gen++
	d.expired = false
	if t.IsZero() {
		return
	}
	wait := time.Until(t)
	if wait <= 0 {
		d.expireLocked()
		return
	}
	gen := d.gen
	d.timer = time.AfterFunc(wait, func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.gen == gen {
			d.expireLocked()
		}
	})
}

func (d *writeDeadline) expireLocked() {
	d.expired = true
	d.cancelRunningLocked()
}

func (d *writeDeadline) cancelRunningLocked() {
	for _, cancel := range d.running {
		cancel()
	}
}

// close stops the timer, cancels every registered Send and makes every
// later begin refuse with net.ErrClosed.
func (d *writeDeadline) close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	d.gen++
	d.closed = true
	d.cancelRunningLocked()
}

// begin returns the context one Write's Send runs under and the func that
// releases it, or the error Write returns without calling Send: net.ErrClosed
// after close, os.ErrDeadlineExceeded once the deadline has passed.
func (d *writeDeadline) begin(parent context.Context) (ctx context.Context, end func(), err error) {
	ctx, cancel := context.WithCancel(parent)
	d.mu.Lock()
	if err := d.endedLocked(); err != nil {
		d.mu.Unlock()
		cancel()
		return nil, nil, err
	}
	if d.running == nil {
		d.running = make(map[uint64]context.CancelFunc)
	}
	id := d.nextID
	d.nextID++
	d.running[id] = cancel
	d.mu.Unlock()
	return ctx, func() {
		d.mu.Lock()
		delete(d.running, id)
		d.mu.Unlock()
		cancel()
	}, nil
}

// ended returns net.ErrClosed after close, os.ErrDeadlineExceeded while the
// deadline has passed and not been re-set, and nil otherwise. Write reads
// it to tell a Send that close or the deadline ended from one that failed
// on its own.
func (d *writeDeadline) ended() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.endedLocked()
}

func (d *writeDeadline) endedLocked() error {
	if d.closed {
		return net.ErrClosed
	}
	if d.expired {
		return os.ErrDeadlineExceeded
	}
	return nil
}

// sendGate admits one Send at a time on a stream whose Send bounds its
// write by cancelling it from outside: quicStream sets the stream-wide
// QUIC write deadline, and GrpcStreamAdapter leaves a send function
// running past its caller. A second Send sharing that write would be cut
// short by the first one's context, or would run its send function beside
// one still in flight. A waiting Send gives up when its own context ends.
// The zero value is ready for use.
type sendGate struct {
	once sync.Once
	slot chan struct{}
}

// acquire takes the gate, or returns ctx's error if ctx ends first.
func (g *sendGate) acquire(ctx context.Context) error {
	g.once.Do(func() { g.slot = make(chan struct{}, 1) })
	select {
	case g.slot <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// release frees the gate acquire took.
func (g *sendGate) release() { <-g.slot }
