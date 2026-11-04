/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ORBTR/aether"
)

// wireVersionsPrefaceTimeout bounds a preface exchange: a peer whose preface has
// not arrived by then has the session closed with errWireVersionsPrefaceTimeout.
// NewTCPSession and NewQuicSession copy it into the session (prefaceTimeout), so a
// test can shorten it for the sessions it builds without racing sessions already
// running.
var wireVersionsPrefaceTimeout = 10 * time.Second

// errWireVersionsPrefaceTimeout is the close reason of a session whose peer sent
// no complete preface within wireVersionsPrefaceTimeout.
var errWireVersionsPrefaceTimeout = fmt.Errorf("%w: peer sent no preface within the deadline", aether.ErrHandshakeFailed)

// wireResult is the outcome of a session's preface exchange: the set both offers
// chose, or the reason there is none.
type wireResult struct {
	chosen aether.NegotiatedWireVersions
	err    error
}

// wireExchange is the state of one session's preface exchange over a natively
// reliable transport, which TCPSession and QUICSession embed; their writers and
// readers differ, and what waits on the outcome does not. wireDone closes when the
// exchange ends: the peer's preface was read and the choice made, or the exchange
// failed or the session closed first. wireResult then holds the chosen set or the
// reason. OpenStream waits on it and nothing decodes a frame before it, which is
// what puts the refusal of a mismatched peer ahead of every stream. wireTimer ends
// an exchange the peer leaves unanswered; it is atomic because its own callback can
// run finishWireVersions before the session has finished storing it.
type wireExchange struct {
	wireDone   chan struct{}
	wireOnce   sync.Once
	wireResult atomic.Pointer[wireResult]
	wireTimer  atomic.Pointer[time.Timer]
}

func newWireExchange() wireExchange {
	return wireExchange{wireDone: make(chan struct{})}
}

// finishWireVersions records the outcome of the preface exchange once and releases
// everything waiting on wireDone. It reports whether this call was the one that
// ended the exchange.
func (x *wireExchange) finishWireVersions(chosen aether.NegotiatedWireVersions, err error) bool {
	first := false
	x.wireOnce.Do(func() {
		first = true
		x.wireResult.Store(&wireResult{chosen: chosen, err: err})
		if t := x.wireTimer.Load(); t != nil {
			t.Stop()
		}
		close(x.wireDone)
	})
	return first
}

// awaitWire blocks until the preface exchange has ended, returning its refusal,
// the caller's context error, or ErrSessionClosed once closed, the session's close
// signal, fires. OpenStream calls it before creating any stream state.
func (x *wireExchange) awaitWire(ctx context.Context, closed <-chan struct{}) error {
	select {
	case <-x.wireDone:
	case <-closed:
		if err := x.wireRefusal(); err != nil {
			return err
		}
		return aether.ErrSessionClosed
	case <-ctx.Done():
		return ctx.Err()
	}
	if r := x.wireResult.Load(); r.err != nil {
		return r.err
	}
	return nil
}

// wireRefusal returns why the preface exchange produced no set, or nil when it
// chose one or the session was simply closed. AcceptStream and AcceptStreamByID
// return it in place of the acceptor's ErrSessionClosed so a caller sees the
// mismatch that closed the session.
func (x *wireExchange) wireRefusal() error {
	if r := x.wireResult.Load(); r != nil && r.err != nil && r.err != aether.ErrSessionClosed {
		return r.err
	}
	return nil
}

// chosenWire returns the set the preface exchange chose. It waits for the exchange
// to end, which wireVersionsPrefaceTimeout bounds, and returns the empty set for a
// session that refused its peer or closed first.
func (x *wireExchange) chosenWire(closed <-chan struct{}) aether.NegotiatedWireVersions {
	select {
	case <-x.wireDone:
	case <-closed:
	}
	if r := x.wireResult.Load(); r != nil {
		return r.chosen
	}
	return aether.NegotiatedWireVersions{}
}
