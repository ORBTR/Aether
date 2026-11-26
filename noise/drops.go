//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 *
 * Drop accounting for the noise receive path.
 */
package noise

import "sync/atomic"

// DropReason identifies why the listener discarded or diverted an inbound
// datagram.
//
// The rule this file exists to enforce: NO SILENT DROPS. A branch of
// runReader or handleHandshake that discards or diverts a datagram counts
// it by reason before its `continue` or return (noiseListener.drops,
// dropCounters.count), and DropSnapshot reads the tally by reason name, so
// a datagram that leaves the Noise path is visible by the branch that took
// it rather than gone without trace. The reasons are per branch, not per
// fault, because from outside the process every diversion presents as
// silence: a datagram answered with a retry cookie (DropRetryTokenIssued),
// one handed to quic-go (DropQUICDemux, a branch classified by first byte
// alone) and one refused by the first-contact limiter (DropSourceLimit)
// each look like a handshake that never completes, and only a count per
// reason separates them. DropForwarderConsumed and DropSessionDeliver name
// the forwarder-consumed and established-session hand-offs, which
// runReader does not count. TODO: count those two hand-offs and the
// 0.5-RTT resume hand-off (handleResumePacket) at their `continue`.
type DropReason uint8

const (
	DropResumeSourceLimit      DropReason = iota // 0.5-RTT resume throttled per-source
	DropResumeGlobalLimit                        // 0.5-RTT resume throttled globally
	DropQUICDemux                                // classified PacketQUIC and handed to quic-go
	DropSTUN                                     // classified PacketSTUN and handed to the STUN handler
	DropForwarderConsumed                        // cross-origin forwarder claimed the frame
	DropSessionDeliver                           // delivered to an established session (AEAD result discarded)
	DropSourceLimit                              // first-contact per-source flood limit
	DropGlobalLimit                              // first-contact global flood limit
	DropPendingDial                              // routed to a waiting dial's channel
	DropRetryCookieInvalid                       // retry cookie failed ValidateAndStrip — msg1 discarded
	DropRetryTokenIssued                         // answered msg1 with a RETRY cookie, no handshake yet
	DropHandshakeKeyUnresolved                   // resolveHandshakeKey rejected the inner msg1
	DropHandshakeStateErr                        // could not build/advance the Noise handshake state
	DropNodeInfoInvalid                          // peer NodeInfo failed verification
	DropWireVersionMismatch                      // peer's wire version offer refused before a session existed
	listenerDropReasonCount
)

// String names the reason for logs and metric labels. Values are wire/metric
// identifiers — keep them stable; operators grep these.
func (r DropReason) String() string {
	switch r {
	case DropResumeSourceLimit:
		return "resume_source_limit"
	case DropResumeGlobalLimit:
		return "resume_global_limit"
	case DropQUICDemux:
		return "quic_demux"
	case DropSTUN:
		return "stun"
	case DropForwarderConsumed:
		return "forwarder_consumed"
	case DropSessionDeliver:
		return "session_deliver"
	case DropSourceLimit:
		return "source_limit"
	case DropGlobalLimit:
		return "global_limit"
	case DropPendingDial:
		return "pending_dial"
	case DropRetryCookieInvalid:
		return "retry_cookie_invalid"
	case DropRetryTokenIssued:
		return "retry_token_issued"
	case DropHandshakeKeyUnresolved:
		return "handshake_key_unresolved"
	case DropHandshakeStateErr:
		return "handshake_state_err"
	case DropNodeInfoInvalid:
		return "nodeinfo_invalid"
	case DropWireVersionMismatch:
		return "wire_version_mismatch"
	default:
		return "unknown"
	}
}

// NOTE: distinct from inner_relay.go's unexported dropReason, which counts
// drops on the cross-origin FORWARDER path. This one covers the listener receive
// path. Both exist because a drop is only diagnosable if it says WHERE it died.
//
// dropCounters is a fixed-size lock-free tally, one slot per DropReason.
// Sized at compile time so the hot receive path never allocates or locks —
// accounting must never be a reason to skip accounting.
type dropCounters [listenerDropReasonCount]atomic.Uint64

// count records one dropped/diverted datagram.
//
// Not every reason is a fault: quic_demux, stun and pending_dial are normal
// routing outcomes (forwarder_consumed and session_deliver name two more
// that runReader does not count, see DropReason). The healthy outcomes are
// counted too: a normal-looking outcome can fire on traffic that is not
// its own (the QUIC-demux branch takes any first byte in 0x40-0xBF, see
// runReader), and only a count that includes the healthy paths lets
// DropSnapshot's reader see one of them run away.
func (d *dropCounters) count(r DropReason) {
	if int(r) < len(d) {
		d[r].Add(1)
	}
}

// DropSnapshot returns the current per-reason counts keyed by reason name.
// Cumulative since listener start — read twice and difference for a rate.
//
// Rate is what matters: quic_demux climbing while noise-UDP links fail is the
// exact signature of ciphertext being misrouted into quic-go, and it is
// otherwise invisible from the outside.
func (l *noiseListener) DropSnapshot() map[string]uint64 {
	out := make(map[string]uint64, listenerDropReasonCount)
	for i := 0; i < int(listenerDropReasonCount); i++ {
		if v := l.drops[i].Load(); v > 0 {
			out[DropReason(i).String()] = v
		}
	}
	return out
}
