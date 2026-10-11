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
//   - SetReadDeadline bounds Receive and SetWriteDeadline bounds Send,
//     each through a connDeadline
//   - Parent context propagation (cancelled when connection dies)
//   - StreamID accessor for debug logging
//   - net.Conn compliant (verified by interface assertion)
type StreamConn struct {
	stream    aether.Stream
	parentCtx context.Context
	bufMu     sync.Mutex   // guards buf, which Read and the deadline setters share
	buf       []byte       // the rest of a message a Read returned in part
	readDL    connDeadline // bounds Read; see SetReadDeadline
	writeDL   connDeadline // bounds Write; see SetWriteDeadline
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
// A Read that has to wait does so in Receive under a context of its own,
// which the read deadline and Close end. So a deadline set, moved or
// cleared while the Read waits applies to that Read, as net.Conn requires,
// and Close unblocks it. Under a read deadline that has passed, or that
// passes while Receive waits, Read returns 0 and os.ErrDeadlineExceeded;
// after Close, or when Close ends a waiting Read, it returns 0 and
// net.ErrClosed. Write returns the same two errors. The rest of a message
// an earlier Read returned in part comes back without waiting, whatever
// the deadline: that message has already left the stream, and
// SetReadDeadline is what drops it.
//
// Not concurrent-safe — callers must not call Read from multiple goroutines.
func (c *StreamConn) Read(p []byte) (int, error) {
	if c.readDL.isClosed() {
		return 0, net.ErrClosed
	}
	if n, ok := c.takeBuffered(p); ok {
		return n, nil
	}
	ctx, end, err := c.readDL.begin(c.parentCtx)
	if err != nil {
		return 0, err
	}
	defer end()
	data, err := c.stream.Receive(ctx)
	if err != nil {
		if ended := c.readDL.ended(); ended != nil {
			return 0, ended
		}
		return 0, err
	}

	n := copy(p, data)
	if n < len(data) {
		c.bufMu.Lock()
		c.buf = data[n:]
		c.bufMu.Unlock()
	}
	return n, nil
}

// takeBuffered copies the rest of a message an earlier Read returned in
// part into p, and reports whether there was any.
func (c *StreamConn) takeBuffered(p []byte) (int, bool) {
	c.bufMu.Lock()
	defer c.bufMu.Unlock()
	if len(c.buf) == 0 {
		return 0, false
	}
	n := copy(p, c.buf)
	c.buf = c.buf[n:]
	return n, true
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

// Close ends every Read waiting in Receive and every Write blocked in
// Send, refuses later ones with net.ErrClosed, then closes the underlying
// Aether stream. net.Conn requires Close to unblock a blocked Read or
// Write, and the stream's Close alone does neither on every adapter:
// noiseStream.Close leaves a Send waiting for flow-control credit until
// flow.ConsumeTimeout, and quicStream.Close closes only the send side, so
// a Receive on it would go on waiting for the peer.
func (c *StreamConn) Close() error {
	c.readDL.close()
	c.writeDL.close()
	return c.stream.Close()
}

// SetDeadline sets the read and the write deadline, as net.Conn defines.
func (c *StreamConn) SetDeadline(t time.Time) error {
	c.setReadDeadline(t)
	c.writeDL.set(t)
	return nil
}

// SetReadDeadline bounds every Read that starts before t and every Read
// already waiting in Receive; a zero t clears it. Moving or clearing it
// while a Read waits moves or clears that Read's bound without ending the
// Read.
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

// setReadDeadline sets the read deadline to t and drops the rest of any
// message an earlier Read returned in part. A caller that sets a deadline
// for each exchange and gives up on an exchange at its deadline would
// otherwise read that exchange's leftover bytes as the start of the next
// one, so the setters, which open the next exchange, drop them.
func (c *StreamConn) setReadDeadline(t time.Time) {
	c.bufMu.Lock()
	c.buf = nil
	c.bufMu.Unlock()
	c.readDL.set(t)
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

// streamConnAddr implements net.Addr for StreamConn.
type streamConnAddr struct{ s string }

func (a streamConnAddr) Network() string { return "aether" }
func (a streamConnAddr) String() string  { return a.s }

// connDeadline is one direction's deadline on a StreamConn, and the conn's
// close: StreamConn holds one for Read and one for Write. Each Read or
// Write registers the cancel of the context its Receive or Send runs
// under; the deadline passing, or close, cancels every registered call,
// and a call that starts after either is refused before Receive or Send.
// Re-setting the deadline re-arms the timer without cancelling a running
// call, so an extended or cleared deadline applies to a Read or Write
// already waiting, as net.Conn requires. gen discards a timer that fired
// after a later set replaced it. Safe for concurrent use.
type connDeadline struct {
	mu      sync.Mutex
	timer   *time.Timer
	gen     uint64
	expired bool
	closed  bool
	running map[uint64]context.CancelFunc
	nextID  uint64
}

// set arms the deadline at t; a zero t clears it. After close it does
// nothing: begin refuses every call, so a timer would guard none.
func (d *connDeadline) set(t time.Time) {
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

func (d *connDeadline) expireLocked() {
	d.expired = true
	d.cancelRunningLocked()
}

func (d *connDeadline) cancelRunningLocked() {
	for _, cancel := range d.running {
		cancel()
	}
}

// close stops the timer, cancels every registered call and makes every
// later begin refuse with net.ErrClosed.
func (d *connDeadline) close() {
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

// begin returns the context one Read's Receive or one Write's Send runs
// under and the func that releases it, or the error the Read or Write
// returns without making the call: net.ErrClosed after close,
// os.ErrDeadlineExceeded once the deadline has passed.
func (d *connDeadline) begin(parent context.Context) (ctx context.Context, end func(), err error) {
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
// deadline has passed and not been re-set, and nil otherwise. Read and
// Write read it to tell a call that close or the deadline ended from one
// that failed on its own.
func (d *connDeadline) ended() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.endedLocked()
}

// isClosed reports whether close has run. Read asks it before it returns
// buffered bytes, which it does whatever the deadline but never after
// Close.
func (d *connDeadline) isClosed() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.closed
}

func (d *connDeadline) endedLocked() error {
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
