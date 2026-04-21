/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
)

// BytePipe is the minimum surface PairSessions needs from each side.
// Both aether.Connection and aether.Stream satisfy this interface,
// letting the relay pair a browser-side Connection (from
// noise.AcceptOverConn) with an agent-side Stream opened on the
// relay's existing mesh session to the target agent. Keeping this
// interface local to the relay package sidesteps the
// two-readers-on-one-session race that would happen if we tried to
// pair against an aether.Session's underlying net.Conn.
type BytePipe interface {
	Send(ctx context.Context, payload []byte) error
	Receive(ctx context.Context) ([]byte, error)
	Close() error
}

// PairSessions links two BytePipe endpoints into a bidirectional
// Aether circuit. Payloads read from a are forwarded to b and vice
// versa, preserving full Aether framing. The relay never decrypts,
// inspects, or modifies frames.
//
// This is the 5.3 half of the browser-transport architecture plan.
// On relay.orbtr.io's `/mesh/aether-ws` accept path, the browser-side
// argument is an aether.Connection produced by noise.AcceptOverConn;
// the agent-side argument is an aether.Stream opened on the relay's
// existing mesh session to the target agent. Both satisfy BytePipe.
//
// Lifecycle:
//   - Blocks until EITHER direction errors or ctx is cancelled.
//   - On return, BOTH sides are closed (idempotent).
//   - Returns ctx.Err() when cancelled externally; otherwise returns
//     the first non-EOF error observed by either forward pump, or nil
//     if both sides closed cleanly.
func PairSessions(ctx context.Context, a, b BytePipe, tag string) error {
	if a == nil || b == nil {
		return fmt.Errorf("relay: PairSessions: nil pipe (a=%v b=%v)", a != nil, b != nil)
	}

	// Derived context drives both pumps; first side to error or ctx
	// expiration cancels both.
	pumpCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		wg       sync.WaitGroup
		firstErr error
		errMu    sync.Mutex
	)
	setFirstErr := func(err error) {
		if err == nil || errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
			return
		}
		errMu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		errMu.Unlock()
	}

	wg.Add(2)
	go func() {
		defer wg.Done()
		defer cancel()
		setFirstErr(forwardLoop(pumpCtx, a, b, tag+" a→b"))
	}()
	go func() {
		defer wg.Done()
		defer cancel()
		setFirstErr(forwardLoop(pumpCtx, b, a, tag+" b→a"))
	}()

	wg.Wait()

	// Tear down both sides symmetrically. Errors ignored — Close is
	// best-effort and the actual failure (if any) is in firstErr.
	_ = a.Close()
	_ = b.Close()

	errMu.Lock()
	defer errMu.Unlock()
	if firstErr != nil {
		return fmt.Errorf("relay pair %q: %w", tag, firstErr)
	}
	return ctx.Err()
}

// forwardLoop pumps payloads src → dst until either side fails or ctx
// is cancelled. Each payload is Received from src and Sent verbatim to
// dst — no framing changes, no decryption, no inspection.
//
// Performance note: this is the hot path when the browser streams
// terminal / file / gossip data through the relay. A single-goroutine
// per direction is fine at the expected fan-out (≤ a few concurrent
// browser sessions per relay instance); scaling the relay to higher
// fan-out would add per-pair queue metrics or cooperative scheduling,
// but that's out of scope here.
func forwardLoop(ctx context.Context, src, dst BytePipe, label string) error {
	for {
		payload, err := src.Receive(ctx)
		if err != nil {
			return fmt.Errorf("%s: receive: %w", label, err)
		}
		if err := dst.Send(ctx, payload); err != nil {
			return fmt.Errorf("%s: send: %w", label, err)
		}
	}
}
