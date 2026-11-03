/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"fmt"
	"math"
	"sync"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/flow"
)

// sessionCreditCeiling is the most receive credit a session's streams may hold
// admitted at once: its stream cap (MaxConcurrentStreams) at the default
// stream credit, the two derived together, so streams opened at the default
// credit meet the stream cap first and the credit ceiling binds when streams
// declare more than the default. It bounds what streams are promised; what the
// receive queues may hold in memory is bounded apart from it, by the
// connection window's ceilings (receiveCeilings).
func sessionCreditCeiling(opts aether.SessionOptions) int64 {
	streams := int64(opts.MaxConcurrentStreams)
	if streams <= 0 {
		streams = aether.DefaultMaxConcurrentStreams
	}
	if streams > math.MaxInt64/flow.DefaultStreamCredit {
		return math.MaxInt64
	}
	return streams * flow.DefaultStreamCredit
}

// streamCreditCeiling is the most credit one stream's window may hold: the
// growth ceiling cfg.MaxCredit sets, or flow.MaxGrowableWindow when it sets
// none, the same capacity flow.NewStreamWindowWithCap builds the window with.
// OpenStream refuses an initial credit above it.
func streamCreditCeiling(cfg aether.StreamConfig) int64 {
	if cfg.MaxCredit > 0 {
		return cfg.MaxCredit
	}
	return flow.MaxGrowableWindow
}

// peerCreditCeiling is the most receive credit the streams of every session to
// one peer may hold admitted at once, given a session's ceiling: one session's
// ceiling and half of another's, so a second session to the same peer has room
// beside one at its own ceiling, and no number of sessions to that peer brings
// it a fresh session ceiling each.
func peerCreditCeiling(sessionCeiling int64) int64 {
	if sessionCeiling > math.MaxInt64/3*2 {
		return math.MaxInt64
	}
	return sessionCeiling + sessionCeiling/2
}

// creditLedger counts the receive credit that admitted streams hold against
// a ceiling. A NoiseSession has one for its own streams (its admitted field),
// whose parent is the ledger of every session to the same peer, so a stream
// is admitted only when its credit fits both. createStream reserves a stream's
// credit here before it publishes the stream in s.streams, and the stream's
// departure from s.streams gives it back (noiseStream.releaseReservation).
//
// Lock order: a session's ledger, then its parent; nothing takes them the
// other way round.
type creditLedger struct {
	mu       sync.Mutex
	ceiling  int64
	reserved int64
	// closed is set when the session ends: what it still held has gone back
	// to the parent, so later releases stop at this ledger and later
	// reservations are refused.
	closed bool
	parent *creditLedger
	// scope names the ceiling in a refusal ("session" or "peer").
	scope string
}

func newCreditLedger(scope string, ceiling int64, parent *creditLedger) *creditLedger {
	return &creditLedger{scope: scope, ceiling: ceiling, parent: parent}
}

// reserve takes n from this ledger and from its parent, or from neither.
// The comparison is written as n > ceiling-reserved so a stream credit near
// the int64 limit cannot wrap past the ceiling.
func (l *creditLedger) reserve(n int64) error {
	if n <= 0 {
		return fmt.Errorf("stream credit %d: %w", n, aether.ErrStreamCreditRefused)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return aether.ErrSessionClosed
	}
	if n > l.ceiling-l.reserved {
		return fmt.Errorf("%s ceiling %d holds %d admitted, stream asks %d: %w",
			l.scope, l.ceiling, l.reserved, n, aether.ErrStreamCreditRefused)
	}
	if l.parent != nil {
		if err := l.parent.reserve(n); err != nil {
			return err
		}
	}
	l.reserved += n
	return nil
}

// release gives back n a stream reserved. After close the parent already has
// this ledger's share back, so only this ledger's count moves.
func (l *creditLedger) release(n int64) {
	if n <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.reserved -= n
	if l.reserved < 0 {
		l.reserved = 0
	}
	if !l.closed && l.parent != nil {
		l.parent.release(n)
	}
}

// close ends the ledger with its session: everything its streams still hold
// goes back to the parent at once, since CloseWithError does not take each
// stream out of s.streams. Idempotent.
func (l *creditLedger) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return
	}
	l.closed = true
	if l.parent != nil {
		l.parent.release(l.reserved)
	}
}

// held returns the credit this ledger's streams hold admitted.
func (l *creditLedger) held() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.reserved
}

// peerLedgers holds one creditLedger per remote node ID for every
// NoiseSession whose NewNoiseSession call names that peer, counted by the
// sessions using it, so the per-peer ceiling covers all of a peer's sessions
// in this process. The first session to join sets the entry's ceiling; the
// entry goes when the last of them closes.
type peerLedgers struct {
	mu sync.Mutex
	m  map[aether.NodeID]*peerLedgerEntry
}

type peerLedgerEntry struct {
	ledger   *creditLedger
	sessions int
}

// sessionPeerLedgers is the process's registry: the per-peer ceiling holds
// across every session this package builds for a peer, whoever builds it.
var sessionPeerLedgers = &peerLedgers{m: make(map[aether.NodeID]*peerLedgerEntry)}

// join returns the peer's ledger and counts one more session using it; a new
// entry takes ceiling.
func (r *peerLedgers) join(peer aether.NodeID, ceiling int64) *creditLedger {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.m[peer]
	if e == nil {
		e = &peerLedgerEntry{ledger: newCreditLedger("peer", ceiling, nil)}
		r.m[peer] = e
	}
	e.sessions++
	return e.ledger
}

// leave counts one session fewer on the peer's ledger, dropping the entry with
// the last one. The leaving session has closed its own ledger first, which
// gave the peer's ledger its share back.
func (r *peerLedgers) leave(peer aether.NodeID, ledger *creditLedger) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.m[peer]
	if e == nil || e.ledger != ledger {
		return
	}
	e.sessions--
	if e.sessions <= 0 {
		delete(r.m, peer)
	}
}
