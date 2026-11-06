/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package aether

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ORBTR/aether/quality"
)

// ErrKeepaliveDeadline is the close error RunKeepalive ends a session with when the peer
// answered none of a plan's Strikes probes in a row: the peer is gone or its path carries
// nothing, and the session is let go at the plan's DeadPeerBound rather than at the idle
// eviction's SessionIdleTimeout.
var ErrKeepaliveDeadline = errors.New("aether: the peer answered no keepalive probe within the dead-peer deadline")

// KeepalivePlanFor is the keepalive plan quality.Keepalive derives for s from its health
// monitor's SRTT, RTO and sample count. A session with no monitor yet gets the plan for
// a path with nothing measured. RunKeepalive reads it before every wait and every probe,
// so each probe cycle follows what the previous answers measured.
func KeepalivePlanFor(s Session) quality.KeepalivePlan {
	var in quality.KeepaliveInputs
	if h := s.Health(); h != nil {
		in = quality.KeepaliveInputs{SRTT: h.SRTT(), RTO: h.RTO(), Samples: h.SampleCount()}
	}
	return quality.Keepalive(in)
}

// RunKeepalive probes s on its keepalive stream until ctx ends or s closes, and ends s
// with ErrKeepaliveDeadline once the peer has answered none of Strikes probes in a row.
// Every probe is a Session.Ping: a PING frame on the session's keepalive stream, answered
// by the peer's control handler with a PONG, so every probe and every answer is an inbound
// frame the idle eviction on each side counts, and an idle healthy session is never
// reaped while it runs.
//
// It sleeps the plan's Interval between probes on a healthy session, and RetryGap between
// probes once one has gone unanswered, so a peer that stops answering is let go within the
// plan's DeadPeerBound of the last frame heard from it.
//
// CONSUMED BY the composer that holds a session no node runtime runs a keepalive on: the
// worker edge (cortex workeraccept) runs it beside each held worker session. A session
// must run one keepalive: health.Monitor holds one pending probe sequence, so a second
// keepalive probing the same session would take the other's answers.
//
// It answers nil when ctx ends or s closes by other means, and ErrKeepaliveDeadline when it
// closed s. It starts no goroutine, so it returns as soon as ctx ends between probes, and
// within one ProbeTimeout when ctx ends during one.
func RunKeepalive(ctx context.Context, s Session) error {
	closing := sessionCloseSignal(s)
	for {
		if !waitKeepalive(ctx, s, closing, KeepalivePlanFor(s).Interval) {
			return nil
		}
		missed := 0
		silentSince := time.Now()
		for {
			plan := KeepalivePlanFor(s)
			probeCtx, cancel := context.WithTimeout(ctx, plan.ProbeTimeout)
			_, err := s.Ping(probeCtx)
			cancel()
			if ctx.Err() != nil || s.IsClosed() {
				return nil
			}
			if err == nil {
				break
			}
			missed++
			if missed >= plan.Strikes {
				closeSessionWithError(s, fmt.Errorf("%w: %d probes unanswered over %s",
					ErrKeepaliveDeadline, missed, time.Since(silentSince).Round(time.Millisecond)))
				return ErrKeepaliveDeadline
			}
			if !waitKeepalive(ctx, s, closing, plan.RetryGap) {
				return nil
			}
		}
	}
}

// waitKeepalive waits d and reports whether the keepalive should go on: false once ctx
// has ended or s has closed.
func waitKeepalive(ctx context.Context, s Session, closing <-chan struct{}, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-closing:
		return false
	case <-timer.C:
	}
	return ctx.Err() == nil && !s.IsClosed()
}

// sessionCloseSignal is s's close channel when its adapter exposes one (every adapter
// embedding BaseSession does), so a wait ends at the close rather than at its timer. A
// session without one returns nil, whose receive never fires, and the IsClosed check after
// each wait ends the keepalive instead.
func sessionCloseSignal(s Session) <-chan struct{} {
	if c, ok := s.(interface{ CloseSignal() <-chan struct{} }); ok {
		return c.CloseSignal()
	}
	return nil
}

// closeSessionWithError closes s with err as its close reason where the adapter records
// one (CloseWithError on every adapter session), and with Close otherwise.
func closeSessionWithError(s Session, err error) {
	if c, ok := s.(interface{ CloseWithError(error) error }); ok {
		_ = c.CloseWithError(err)
		return
	}
	_ = s.Close()
}
