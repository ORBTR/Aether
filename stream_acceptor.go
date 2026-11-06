/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
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
// backlog, where only an AcceptStreamByID claim takes it, before it joins
// the StreamAcceptor's FIFO, where Accept and a later AcceptStreamByID of
// its ID both take it. Short enough that FIFO AcceptStream consumers (e.g.
// dynamic RPC streams 10+) do not observe a perceptible delay, long enough
// to absorb the typical scheduling skew between a stream arriving on the
// wire and the consuming goroutine calling AcceptStreamByID while an
// Accept loop is running.
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
//   - NonBlockingDrop: if the FIFO is full the stream is not queued and
//     Notify returns false. Used by transports where the application is
//     responsible for keeping AcceptStream calls hot (Noise, TCP).
//   - BlockUntilClose: blocks until Accept or AcceptByID makes room in
//     the FIFO or the session closes. Used by QUIC where the adapter
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
// the "wait for a specific StreamID" semantics AND the AcceptStream
// FIFO live in one place rather than being re-implemented
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
// consumers and Accept for FIFO consumers, call Close on
// session teardown. Safe for concurrent use.
type StreamAcceptor struct {
	mu      sync.Mutex
	waiters map[uint64]chan Stream
	backlog map[uint64][]Stream
	// fifo holds, in arrival order and at most fifoCap of them, the streams
	// Accept reads: those no waiter or backlog slot took, and backlog entries
	// whose grace ran out. AcceptByID takes the first one of its ID out of
	// it, so a stream that aged out of the backlog before its claimant armed
	// is still the claimant's unless Accept took it first: a responder that
	// claims its setup streams one after another by ID, with no Accept
	// running, gets every one of them whatever its scheduling delay. The
	// acceptor owns it so the Noise, TCP and QUIC adapters share one. mode
	// selects what a push onto a full fifo does (NonBlockingDrop /
	// BlockUntilClose). Guarded by mu.
	fifo    []Stream
	fifoCap int
	// changed is closed and replaced, under mu, whenever fifo gains or loses
	// a stream and when the acceptor closes, waking every Accept waiting for
	// a stream and every BlockUntilClose push waiting for room.
	changed chan struct{}
	mode    PushMode
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
		fifoCap:   buf,
		changed:   make(chan struct{}),
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
//     pushed onto the FIFO, where a later AcceptStreamByID of its ID
//     still finds it.
//  3. The internal FIFO — Accept reads from it, and AcceptByID takes
//     streams of its ID from it. Push semantics depend on the configured
//     PushMode (refuse-on-full or block-until-close).
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
// NonBlockingDrop refuses on full; BlockUntilClose waits until Accept or
// AcceptByID makes room OR the session closes. An acceptor that has
// closed takes nothing: Close has handed back what it held.
func (a *StreamAcceptor) pushFIFO(st Stream) bool {
	for {
		a.mu.Lock()
		if a.isClosed {
			a.mu.Unlock()
			return false
		}
		if len(a.fifo) < a.fifoCap {
			a.fifo = append(a.fifo, st)
			a.changedLocked()
			a.mu.Unlock()
			return true
		}
		if a.mode != BlockUntilClose {
			a.mu.Unlock()
			return false
		}
		wake := a.changed
		a.mu.Unlock()
		select {
		case <-wake:
		case <-a.closed:
			return false
		}
	}
}

// changedLocked wakes everything waiting on the FIFO (Accept, a
// BlockUntilClose push). Caller holds mu.
func (a *StreamAcceptor) changedLocked() {
	close(a.changed)
	a.changed = make(chan struct{})
}

// takeFIFOLocked removes and returns the FIFO's i'th stream, keeping the
// others in arrival order. Caller holds mu.
func (a *StreamAcceptor) takeFIFOLocked(i int) Stream {
	st := a.fifo[i]
	copy(a.fifo[i:], a.fifo[i+1:])
	a.fifo[len(a.fifo)-1] = nil
	a.fifo = a.fifo[:len(a.fifo)-1]
	a.changedLocked()
	return st
}

// Accept returns the next stream from the FIFO. Blocks until either a
// stream arrives, ctx is cancelled, or the session closes. Drives the
// adapter's Session.AcceptStream surface: the Noise, TCP and QUIC
// adapters' AcceptStream each delegate here, so the wait on (fifo,
// ctx.Done, closed) exists once.
func (a *StreamAcceptor) Accept(ctx context.Context) (Stream, error) {
	for {
		a.mu.Lock()
		if len(a.fifo) > 0 {
			st := a.takeFIFOLocked(0)
			a.mu.Unlock()
			return st, nil
		}
		if a.isClosed {
			a.mu.Unlock()
			return nil, a.errClosed
		}
		wake := a.changed
		a.mu.Unlock()
		select {
		case <-wake:
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-a.closed:
			return nil, a.errClosed
		}
	}
}

// AcceptByID blocks until a stream with exactly streamID arrives, or
// ctx is cancelled, or the session closes. Drain order:
//
//  1. If a stream for this ID is already on the backlog, pop and return
//     it without ever registering a waiter.
//  2. Otherwise, if the FIFO holds one (its grace ran out before this
//     call, and no Accept took it), take the first and return it.
//  3. Otherwise register a waiter channel and block on it.
//
// Only one waiter per streamID is supported — a second concurrent
// AcceptByID(id) call closes the previous waiter so its caller returns
// errClosed rather than hanging forever (last caller wins), which is the
// contract every adapter's AcceptStreamByID delegates to.
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
	for i, q := range a.fifo {
		if q.StreamID() == streamID {
			st := a.takeFIFOLocked(i)
			a.mu.Unlock()
			return st, nil
		}
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
		// Notify already claimed our slot (deleted it from the map) and is
		// committed to sending on ch (buffered, cap 1) — it just hasn't
		// executed the send yet. A non-blocking recv here would race that
		// window and return ctx.Err() while the committed stream sat unconsumed
		// in ch, orphaning it (Notify reported delivered; no Reset ever sent). BLOCK
		// briefly to receive it; the timeout is only a safety backstop.
		select {
		case st, ok := <-ch:
			if !ok {
				return nil, a.errClosed
			}
			return st, nil
		case <-time.After(byIDNotifyDrainTimeout):
			return nil, ctx.Err()
		}
	case <-a.closed:
		// Mirror the ctx.Done() drain above. Session teardown
		// closes `closed` (via SignalClose) BEFORE calling the acceptor's
		// Close() that sets isClosed, so a Notify racing teardown still
		// takes the waiter fast-path, deletes our slot, and buffers the
		// stream into ch. When this branch wins the select that stream
		// would be orphaned — Notify reported it delivered, Close() cannot
		// surface it (already removed from the waiters map), and no Reset
		// is ever sent. Re-check the map: if we are still the registered
		// waiter nothing is in flight; otherwise consume the buffered
		// stream and hand it back so the caller can use or Reset it.
		a.mu.Lock()
		if cur, ok := a.waiters[streamID]; ok && cur == ch {
			delete(a.waiters, streamID)
			a.mu.Unlock()
			return nil, a.errClosed
		}
		a.mu.Unlock()
		// Same committed-send window as the ctx.Done() drain above —
		// block briefly for the stream Notify is committed to sending.
		select {
		case st, ok := <-ch:
			if !ok {
				return nil, a.errClosed
			}
			return st, nil
		case <-time.After(byIDNotifyDrainTimeout):
			return nil, a.errClosed
		}
	}
}

// byIDNotifyDrainTimeout bounds how long AcceptByID blocks to consume a stream
// that Notify has already committed to delivering. The send happens
// microseconds after Notify releases the lock, so this is only a backstop.
const byIDNotifyDrainTimeout = 1 * time.Second

// Close drains the backlog and the FIFO and signals all waiters that the
// session is gone. Streams still parked on either are returned via the
// drained slice so the caller (session teardown) can Reset them — the
// reset semantics are transport-specific (each adapter's stream
// implementation has its own Reset path) so we surface the streams
// rather than calling Reset here. Accept() callers observe
// ErrSessionClosed.
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
	drained = append(drained, a.fifo...)
	a.fifo = nil
	a.changedLocked()
	a.mu.Unlock()
	return drained
}

// flushBacklogEntry runs when the per-stream grace timer fires. If the
// stream is still parked on the backlog (no AcceptByID claimed it) it
// is removed and pushed onto the FIFO so any FIFO AcceptStream
// consumer, or a later AcceptByID of its ID, can pick it up. A no-op
// when the stream was already drained by AcceptByID or by Close.
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
