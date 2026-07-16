/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package aether

import (
	"context"
	"fmt"
	"time"

	"github.com/ORBTR/aether/health"
)

// PingDefaultDeadline is the wall-clock ceiling waitForActivityPing waits
// for any inbound frame after sending a PING. Clamped further by the
// caller's ctx deadline when ctx is shorter.
const PingDefaultDeadline = 2 * time.Second

// pingActivityPollInterval is how frequently waitForActivityPing wakes
// to re-check the health monitor's LastActivity timestamp. 50 ms is short
// enough that healthy paths report RTT promptly and long enough that an
// idle session does not spin the goroutine.
const pingActivityPollInterval = 50 * time.Millisecond

// PingFrameWriter is the per-adapter callback that emits a PING frame on
// the underlying transport. The adapter constructs the frame (so the
// session-specific PeerID, Keepalive stream, and SeqNo policy live where
// they belong) and the helper handles the post-send polling.
type PingFrameWriter func(seqNo uint32) error

// WaitForActivityPing emits a PING via writeFrame and waits for inbound
// activity on the session. Returns the health monitor's averaged RTT once
// LastActivity advances past the snapshot taken before the PING was sent.
//
// Behaviour shared between the Noise and TCP adapters — they have
// identical zombie-session detection requirements: writeFrame can succeed
// against a torn-down peer because the kernel buffers the datagram, so
// returning the cached RTT immediately after a successful send is unsafe.
// The two adapters used to maintain byte-identical copies of this loop;
// the helper consolidates them so both transports observe one definition
// of "the peer is alive" — any inbound frame counts, so a peer that sends
// other traffic within deadline counts as alive even if a PONG never
// arrives (acceptable for keepalive; the goal is detecting silence).
//
// QUIC's Ping intentionally does NOT use this helper — it returns the
// cached RTT without writing an aether PING frame because QUIC has its
// own transport-level keepalive that fires session-close on idle. Keep
// that asymmetry in mind before generalising.
//
// closeSignal is the session's IsClosed channel. The loop fast-fails the
// moment that signal fires so callers do not get a stuck-send ping report
// against a session whose readLoop has already exited.
func WaitForActivityPing(
	ctx context.Context,
	hm *health.Monitor,
	closeSignal <-chan struct{},
	writePing PingFrameWriter,
) (time.Duration, error) {
	select {
	case <-closeSignal:
		return 0, ErrSessionClosed
	default:
	}
	before := hm.LastActivity()
	start := time.Now()
	// Derive a non-zero seqNo (RecordPongRecv rejects seq==0). UnixNano
	// rarely produces a zero low-word, but a defensive bump avoids the
	// pathological case where the very Pong we depend on for SRTT is
	// silently discarded.
	seqNo := uint32(start.UnixNano() & 0xFFFFFFFF)
	if seqNo == 0 {
		seqNo = 1
	}
	// Arm the Monitor's pendingPingSeq BEFORE writePing so the inbound
	// Pong's RecordPongRecv finds a non-zero pendingPingSeq and feeds
	// the SRTT estimator. Without this arming the Pong's seq comparison
	// fails the `seq != 0 && seq == m.pendingPingSeq` gate and the RTT
	// estimator never updates — every health.Monitor SRTT read returns
	// 0 even though Pongs are arriving correctly.
	hm.RecordPingSent(seqNo)
	if err := writePing(seqNo); err != nil {
		return 0, err
	}
	// Honour the caller's ctx deadline as the authoritative budget. Only
	// fall back to PingDefaultDeadline when the caller hasn't set one.
	// Earlier revisions capped the deadline at the smaller of the two,
	// which meant a caller wanting a 5 s budget on a slow path was
	// silently clamped to the 2 s PingDefaultDeadline. The keepalive
	// loop passes an explicit adaptiveKeepaliveTimeout(RTO) ctx; that
	// budget MUST be the one that fires.
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(PingDefaultDeadline)
	}
	pollTicker := time.NewTicker(pingActivityPollInterval)
	defer pollTicker.Stop()
	for {
		select {
		case <-closeSignal:
			return 0, ErrSessionClosed
		default:
		}
		// A real Pong is the gold standard: it proves the round-trip AND
		// feeds the SRTT estimator via RecordPongRecv. Prefer it — on a
		// healthy path the Pong arrives well inside the deadline and we
		// return the measured RTT, unchanged from prior behaviour.
		// Requiring the Pong here (rather than any inbound frame) keeps the
		// SeqNo/SRTT correlation honest for chatty sessions, which is why
		// the earlier "any inbound counts" fast-path was removed.
		if hm.LastPongReceived().After(before) {
			_, avg := hm.RTT()
			return avg, nil
		}
		if !time.Now().Before(deadline) {
			// Deadline reached with no Pong. The noise-UDP keepalive stream
			// is UnreliableSequenced (FEC-1), so a single dropped Pong
			// datagram is expected on a lossy path and must NOT tear down a
			// session that is otherwise alive and carrying gossip/RPC —
			// that PONG-required teardown was the same-org noise-UDP
			// persistence bug (healthy sessions killed by lost Pongs, then
			// parked in the 30-min address dead-cooldown). Honour the
			// documented liveness contract as a deadline fallback: if ANY
			// inbound frame arrived since the ping was sent, the return
			// path works and the peer is alive. No SRTT sample this round
			// (SRTT is fed by RecordPongRecv, not this return, so a zero
			// RTT here cannot corrupt the estimator). Only genuine silence
			// — no Pong AND no other inbound activity within the deadline —
			// counts as a ping failure toward the keepalive death budget.
			if hm.LastActivity().After(before) {
				// Alive via other inbound traffic. Reuse the cached SRTT
				// rather than returning a bogus 0 ms so a future RTT
				// consumer never mistakes the liveness signal for a
				// measured zero (both current callers discard it; the
				// estimator is untouched either way).
				_, avg := hm.RTT()
				return avg, nil
			}
			return 0, fmt.Errorf("aether: ping timeout (no inbound activity)")
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-pollTicker.C:
		}
	}
}
