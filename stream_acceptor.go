/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package aether

import (
	"context"
	"sync"
	"time"
)

// MaxByIDBacklogPerStream bounds the number of unclaimed streams parked
// on a per-ID backlog before incoming streams for that ID fall through
// to the StreamAcceptor's FIFO. Mesh consumers normally pre-arm
// AcceptStreamByID for every well-known stream before the peer can open
// them, so the backlog should rarely exceed 1 in practice; the cap exists
// to bound worst-case memory on a misbehaving peer that floods opens for
// a single ID with no claimant waiting.
//
// Exported so transport adapters in the adapter package can reference it
// when wiring StreamAcceptor — they do not need their own duplicate.
const MaxByIDBacklogPerStream = 4

// ByIDBacklogGrace is how long an arrived stream parks on the per-ID
// backlog waiting for an AcceptStreamByID claim before falling through
// to the StreamAcceptor's FIFO. Short enough that legacy AcceptStream
// consumers (e.g. dynamic RPC streams 10+) do not observe a perceptible
// delay, long enough to absorb the typical scheduling skew between a
// stream arriving on the wire and the consuming goroutine calling
// AcceptStreamByID.
//
// Bypassed entirely when a waiter is already armed at notify time.
const ByIDBacklogGrace = 100 * time.Millisecond

// AcceptChDefaultBuffer is the default FIFO depth used when
// StreamAcceptorConfig.BufferSize is zero. Sized to absorb a small
// burst of OPENs that arrive while the consumer goroutine is between
// AcceptStream calls without dropping under steady load.
const AcceptChDefaultBuffer = 16

// PushMode determines how StreamAcceptor.Notify delivers a stream to
// the FIFO when neither a pinned AcceptStreamByID waiter nor a backlog
// slot accepted it.
//
//   - NonBlockingDrop: select-default; if the FIFO is full the stream
//     is dropped silently. Used by transports where the application is
//     responsible for keeping AcceptStream calls hot (Noise, TCP).
//   - BlockUntilClose: blocks until either the consumer accepts the
//     stream or the session closes. Used by QUIC where the adapter
//     wraps quic-go's own backpressure-aware accept channel and the
//     accept loop is allowed to stall when the application is slow.
type PushMode int

const (
	NonBlockingDrop PushMode = iota
	BlockUntilClose
)

// StreamAcceptorConfig configures a StreamAcceptor at construction time.
// BufferSize zero falls back to AcceptChDefaultBuffer. ErrClosed nil
// falls back to ErrSessionClosed. Closed is the session's teardown
// signal; AcceptByID and Accept select on it so blocked callers return
// ErrClosed when the session goes down. Mode controls FIFO push
// semantics — see PushMode.
type StreamAcceptorConfig struct {
	BufferSize int
	Mode       PushMode
	Closed     <-chan struct{}
	ErrClosed  error
}

// StreamAcceptor is the transport-agnostic per-StreamID accept dispatch
// plus FIFO ownership. Embedded into each transport-adapter session so
// the "wait for a specific StreamID" semantics AND the legacy
// AcceptStream FIFO live in one place rather than being re-implemented
// per transport.
//
// The adapter calls Notify(stream) when a stream is ready to be handed
// to a consumer (OPEN frame parsed, QUIC AcceptStream returned, etc.);
// the acceptor picks between a pinned ByID waiter, a per-ID backlog
// slot, or the internal FIFO using the configured PushMode. Adapter
// AcceptStream becomes a one-line delegate to Accept(ctx).
//
// Lifecycle: construct once per session via NewStreamAcceptor, call
// Notify on every accepted stream, call AcceptByID for pinned
// consumers and Accept for legacy FIFO consumers, call Close on
// session teardown. Safe for concurrent use.
type StreamAcceptor struct {
	mu      sync.Mutex
	waiters map[uint64]chan Stream
	backlog map[uint64][]Stream
	// fifo is the legacy AcceptStream channel. Owned by the acceptor —
	// pre-refactor each transport adapter carried its own copy of this
	// channel plus a pushToAcceptCh shim. mode selects between the two
	// observed push policies (NonBlockingDrop / BlockUntilClose).
	fifo chan Stream
	mode PushMode
	// closed signals session teardown; AcceptByID, Accept, and the
	// BlockUntilClose push path all select on it so blocked callers
	// return errClosed when the session goes down.
	closed <-chan struct{}
	// errClosed is returned by AcceptByID and Accept when the session
	// closes. Defaults to ErrSessionClosed if cfg.ErrClosed was nil.
	errClosed error
	// isClosed mirrors `closed` for the Close() shutdown path so we can
	// reject Notify calls that race with teardown without depending on
	// the caller to provide a non-nil closed channel.
	isClosed bool
}

// NewStreamAcceptor constructs a StreamAcceptor wired to a transport
// adapter. cfg.Mode selects the FIFO push policy (NonBlockingDrop for
// Noise + TCP; BlockUntilClose for QUIC). cfg.BufferSize zero falls
// back to AcceptChDefaultBuffer. cfg.ErrClosed nil falls back to
// ErrSessionClosed. cfg.Closed is the session's teardown signal — may
// be nil in tests that drive Close directly.
func NewStreamAcceptor(cfg StreamAcceptorConfig) *StreamAcceptor {
	if cfg.ErrClosed == nil {
		cfg.ErrClosed = ErrSessionClosed
	}
	buf := cfg.BufferSize
	if buf <= 0 {
		buf = AcceptChDefaultBuffer
	}
	return &StreamAcceptor{
		waiters:   make(map[uint64]chan Stream),
		backlog:   make(map[uint64][]Stream),
		fifo:      make(chan Stream, buf),
		mode:      cfg.Mode,
		closed:    cfg.Closed,
		errClosed: cfg.ErrClosed,
	}
}

// Notify is called by the adapter when a stream is ready to be handed
// to a consumer. Delivery priority:
//
//  1. A pinned AcceptStreamByID waiter for this StreamID — claimed
//     immediately (out-of-order wire arrival cannot mis-route).
//  2. The per-ID backlog if it has room (< MaxByIDBacklogPerStream).
//     A ByIDBacklogGrace timer is armed; if no AcceptStreamByID claim
//     arrives in that window the entry is removed from the backlog and
//     pushed onto the FIFO.
//  3. The internal FIFO — Accept reads from it. Push semantics depend
//     on the configured PushMode (drop-on-full or block-until-close).
//
// Returns true when the stream was delivered (waiter, backlog, or FIFO
// accepted under BlockUntilClose). Returns false when the acceptor is
// already closed OR when NonBlockingDrop dropped the stream because
// the FIFO was full.
func (a *StreamAcceptor) Notify(st Stream) bool {
	a.mu.Lock()
	if a.isClosed {
		a.mu.Unlock()
		return false
	}
	id := st.StreamID()
	if ch, ok := a.waiters[id]; ok {
		delete(a.waiters, id)
		a.mu.Unlock()
		// Buffered channel (cap 1) — never blocks.
		ch <- st
		return true
	}
	backlog := a.backlog[id]
	if len(backlog) < MaxByIDBacklogPerStream {
		a.backlog[id] = append(backlog, st)
		a.mu.Unlock()
		time.AfterFunc(ByIDBacklogGrace, func() { a.flushBacklogEntry(st) })
		return true
	}
	a.mu.Unlock()
	return a.pushFIFO(st)
}

// pushFIFO delivers a stream onto the internal FIFO using the
// configured push mode. Returns true when the FIFO accepted it.
// NonBlockingDrop drops silently on full; BlockUntilClose blocks until
// the consumer accepts OR the session closes.
func (a *StreamAcceptor) pushFIFO(st Stream) bool {
	switch a.mode {
	case BlockUntilClose:
		select {
		case a.fifo <- st:
			return true
		case <-a.closed:
			return false
		}
	default:
		select {
		case a.fifo <- st:
			return true
		default:
			return false
		}
	}
}

// Accept returns the next stream from the FIFO. Blocks until either a
// stream arrives, ctx is cancelled, or the session closes. Drives the
// adapter's Session.AcceptStream surface — pre-refactor each adapter
// owned its own select on (acceptCh, ctx.Done, CloseSignal); now the
// select lives here once.
func (a *StreamAcceptor) Accept(ctx context.Context) (Stream, error) {
	select {
	case st := <-a.fifo:
		return st, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-a.closed:
		return nil, a.errClosed
	}
}

// AcceptByID blocks until a stream with exactly streamID arrives, or
// ctx is cancelled, or the session closes. Drain order:
//
//  1. If a stream for this ID is already on the backlog, pop and return
//     it without ever registering a waiter.
//  2. Otherwise register a waiter channel and block on it.
//
// Only one waiter per streamID is supported — a second concurrent
// AcceptByID(id) call closes the previous waiter so its caller returns
// errClosed rather than hanging forever. The "last caller wins"
// semantics match what the adapter-local implementations did before
// this dispatch was consolidated.
//
// Race-safe context cancel: when ctx fires we re-check the waiter map
// under a.mu and consume any in-flight delivery so the stream is not
// orphaned. The matching Notify may have grabbed our slot in the gap
// between ctx firing and us re-acquiring the lock.
func (a *StreamAcceptor) AcceptByID(ctx context.Context, streamID uint64) (Stream, error) {
	a.mu.Lock()
	if backlog := a.backlog[streamID]; len(backlog) > 0 {
		st := backlog[0]
		if len(backlog) == 1 {
			delete(a.backlog, streamID)
		} else {
			a.backlog[streamID] = backlog[1:]
		}
		a.mu.Unlock()
		return st, nil
	}
	if old, ok := a.waiters[streamID]; ok {
		// Supersede the previous waiter — last caller wins. The
		// previous caller's select returns ok=false → errClosed.
		close(old)
	}
	ch := make(chan Stream, 1)
	a.waiters[streamID] = ch
	a.mu.Unlock()

	select {
	case st, ok := <-ch:
		if !ok {
			return nil, a.errClosed
		}
		return st, nil
	case <-ctx.Done():
		a.mu.Lock()
		// Only deregister if we are still the registered waiter — a
		// concurrent Notify may have already pushed a stream onto ch
		// while we were waiting for the lock; in that case consume it
		// so the stream is not orphaned.
		if cur, ok := a.waiters[streamID]; ok && cur == ch {
			delete(a.waiters, streamID)
			a.mu.Unlock()
			return nil, ctx.Err()
		}
		a.mu.Unlock()
		select {
		case st, ok := <-ch:
			if !ok {
				return nil, a.errClosed
			}
			return st, nil
		default:
			return nil, ctx.Err()
		}
	case <-a.closed:
		return nil, a.errClosed
	}
}

// Close drains the backlog and signals all waiters that the session
// is gone. Streams still parked on the backlog are returned via the
// drained slice so the caller (session teardown) can Reset them — the
// reset semantics are transport-specific (each adapter's stream
// implementation has its own Reset path) so we surface the streams
// rather than calling Reset here. Streams already in the FIFO are NOT
// drained — Accept() callers will observe ErrSessionClosed via the
// closed-channel select instead.
//
// Waiter channels are closed without a value so blocked AcceptByID
// callers return errClosed via the ok=false branch.
//
// Idempotent: a second Close returns nil. Safe to call concurrently
// with Notify / AcceptByID / Accept — a Notify racing Close ignores
// the stream (returns false); AcceptByID and Accept racing Close
// return errClosed either via the `closed` channel select or via the
// waiter-close branch.
func (a *StreamAcceptor) Close() []Stream {
	a.mu.Lock()
	if a.isClosed {
		a.mu.Unlock()
		return nil
	}
	a.isClosed = true
	for id, ch := range a.waiters {
		close(ch)
		delete(a.waiters, id)
	}
	var drained []Stream
	for id, queue := range a.backlog {
		drained = append(drained, queue...)
		delete(a.backlog, id)
	}
	a.mu.Unlock()
	return drained
}

// flushBacklogEntry runs when the per-stream grace timer fires. If the
// stream is still parked on the backlog (no AcceptByID claimed it) it
// is removed and pushed onto the FIFO so any legacy AcceptStream
// consumer can pick it up. A no-op when the stream was already drained
// by AcceptByID or by Close.
func (a *StreamAcceptor) flushBacklogEntry(st Stream) {
	id := st.StreamID()
	a.mu.Lock()
	if a.isClosed {
		a.mu.Unlock()
		return
	}
	backlog := a.backlog[id]
	idx := -1
	for i, q := range backlog {
		if q == st {
			idx = i
			break
		}
	}
	if idx < 0 {
		a.mu.Unlock()
		return
	}
	a.backlog[id] = append(backlog[:idx], backlog[idx+1:]...)
	if len(a.backlog[id]) == 0 {
		delete(a.backlog, id)
	}
	a.mu.Unlock()
	a.pushFIFO(st)
}
