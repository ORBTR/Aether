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
// on a per-ID backlog before incoming streams for that ID fall through to
// the transport's FIFO acceptCh. Mesh consumers normally pre-arm
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
// to the transport's FIFO acceptCh. Short enough that legacy
// AcceptStream consumers (e.g. dynamic RPC streams 10+) do not observe
// a perceptible delay, long enough to absorb the typical scheduling
// skew between a stream arriving on the wire and the consuming
// goroutine calling AcceptStreamByID.
//
// Bypassed entirely when a waiter is already armed at notify time.
const ByIDBacklogGrace = 100 * time.Millisecond

// AcceptFallbackFunc is invoked by StreamAcceptor when neither a pinned
// waiter nor a backlog slot accepted a notified stream. The transport
// adapter forwards the stream to its FIFO acceptCh — the exact
// blocking/non-blocking semantics live in the adapter because that is
// where the FIFO channel and its session-close signal live.
type AcceptFallbackFunc func(Stream)

// StreamAcceptor is the transport-agnostic per-StreamID accept dispatch.
// Embedded into each transport-adapter session so the "wait for a
// specific StreamID" semantics live in one place rather than being
// re-implemented per transport.
//
// The adapter only needs to call Notify(stream) when a stream is ready
// to be handed to a consumer (OPEN frame parsed, QUIC AcceptStream
// returned, etc.); the acceptor decides between a pinned ByID waiter,
// a per-ID backlog slot, or the FIFO fallback the adapter wired in via
// the fallback callback.
//
// Lifecycle: construct once per session via NewStreamAcceptor, call
// Notify on every accepted stream, call AcceptByID for pinned
// consumers, call Close on session teardown. Safe for concurrent use.
type StreamAcceptor struct {
	mu      sync.Mutex
	waiters map[uint64]chan Stream
	backlog map[uint64][]Stream
	// fallback delivers streams that neither a waiter nor a backlog
	// slot accepted. Transport adapter wires this to its FIFO acceptCh
	// push (blocking or non-blocking — adapter's choice).
	fallback AcceptFallbackFunc
	// closed signals session teardown; AcceptByID returns errClosed
	// when this channel is closed.
	closed <-chan struct{}
	// errClosed is returned by AcceptByID when the session closes.
	// Defaults to ErrSessionClosed if nil; left configurable so unit
	// tests can use a sentinel of their own.
	errClosed error
	// isClosed mirrors `closed` for the Close() shutdown path so we can
	// reject Notify calls that race with teardown without depending on
	// the caller to provide a non-nil closed channel.
	isClosed bool
}

// NewStreamAcceptor constructs a StreamAcceptor wired to a transport
// adapter. The fallback callback is invoked whenever a notified stream
// cannot be claimed by a waiter or parked on the backlog — the adapter
// forwards to its FIFO acceptCh there. `closed` is the session's
// teardown signal; AcceptByID selects on it so blocked callers return
// errClosed when the session goes down. `errClosed` may be nil to use
// the package default (ErrSessionClosed).
func NewStreamAcceptor(fallback AcceptFallbackFunc, closed <-chan struct{}, errClosed error) *StreamAcceptor {
	if errClosed == nil {
		errClosed = ErrSessionClosed
	}
	return &StreamAcceptor{
		waiters:   make(map[uint64]chan Stream),
		backlog:   make(map[uint64][]Stream),
		fallback:  fallback,
		closed:    closed,
		errClosed: errClosed,
	}
}

// Notify is called by the adapter when a stream is ready to be handed
// to a consumer. Delivery priority:
//
//  1. A pinned AcceptStreamByID waiter for this StreamID — claimed
//     immediately (out-of-order wire arrival cannot mis-route).
//  2. The per-ID backlog if it has room (< MaxByIDBacklogPerStream).
//     A ByIDBacklogGrace timer is armed; if no AcceptStreamByID claim
//     arrives in that window the entry is removed from the backlog
//     and handed to the fallback callback.
//  3. The fallback callback — adapter pushes to FIFO acceptCh.
//
// Returns true when the stream was delivered (waiter or backlog) so
// the caller can short-circuit. Returns false when the fallback was
// invoked OR when the acceptor is already closed; in the closed case
// the stream is dropped because nobody will ever pick it up.
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
	if a.fallback != nil {
		a.fallback(st)
	}
	return false
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
// this refactor.
//
// Race-safe context cancel: when ctx fires we re-check the waiter map
// under a.mu and consume any in-flight delivery so the stream is not
// orphaned. The matching notifyStreamAccepted may have grabbed our
// slot in the gap between ctx firing and us re-acquiring the lock.
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
// rather than calling Reset here.
//
// Waiter channels are closed without a value so blocked AcceptByID
// callers return errClosed via the ok=false branch.
//
// Idempotent: a second Close returns nil. Safe to call concurrently
// with Notify / AcceptByID — a Notify racing Close ignores the stream
// (returns false); an AcceptByID racing Close returns errClosed
// either via the `closed` channel select or via the waiter-close
// branch.
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
// is removed and handed to the fallback callback so any legacy
// AcceptStream consumer on the FIFO acceptCh can pick it up. A no-op
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
	if a.fallback != nil {
		a.fallback(st)
	}
}
