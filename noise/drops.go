//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 *
 * Drop accounting for the noise receive path.
 */
package noise

import "sync/atomic"

// DropReason identifies why the listener discarded an inbound datagram.
//
// WHY THIS EXISTS: every drop on the receive path was a bare `continue` — no
// log, no counter, nothing. A fleet-wide noise-UDP outage took nine hours to
// root-cause because the decisive fact ("~50% of msg3 is being handed to the
// QUIC demux and destroyed") was invisible: the packets simply stopped
// existing, and no instrument anywhere counted them. Three separate real bugs
// (retry-token mis-read as msg2, cached msg2 answered with a stale nonce,
// msg3 coin-flipped into quic-go) all presented identically from the outside —
// as silence.
//
// A single reason-tagged counter would have collapsed that investigation to one
// lookup. The rule this file exists to enforce: NO SILENT DROPS. Every path
// that discards a packet names why, and the count is readable at runtime.
type DropReason uint8

const (
	DropResumeSourceLimit      DropReason = iota // 0.5-RTT resume throttled per-source
	DropResumeGlobalLimit                        // 0.5-RTT resume throttled globally
	DropQUICDemux                                // classified PacketQUIC and handed to quic-go
	DropSTUN                                     // classified PacketSTUN and handed to the STUN handler
	DropForwarderConsumed                        // cross-org forwarder claimed the frame
	DropSessionDeliver                           // delivered to an established session (AEAD result discarded)
	DropSourceLimit                              // first-contact per-source flood limit
	DropGlobalLimit                              // first-contact global flood limit
	DropPendingDial                              // routed to a waiting dial's channel
	DropRetryCookieInvalid                       // retry cookie failed ValidateAndStrip — msg1 discarded
	DropRetryTokenIssued                         // answered msg1 with a RETRY cookie, no handshake yet
	DropHandshakeKeyUnresolved                   // resolveHandshakeKey rejected the inner msg1
	DropHandshakeStateErr                        // could not build/advance the Noise handshake state
	DropNodeInfoInvalid                          // peer NodeInfo failed verification
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
	default:
		return "unknown"
	}
}

// NOTE: distinct from inner_relay.go's unexported dropReason, which counts
// drops on the cross-org FORWARDER path. This one covers the listener receive
// path. Both exist because a drop is only diagnosable if it says WHERE it died.
//
// dropCounters is a fixed-size lock-free tally, one slot per DropReason.
// Sized at compile time so the hot receive path never allocates or locks —
// accounting must never be a reason to skip accounting.
type dropCounters [listenerDropReasonCount]atomic.Uint64

// count records one dropped/diverted datagram.
//
// Not every reason is a fault: quic_demux, stun, forwarder_consumed,
// session_deliver and pending_dial are normal routing outcomes. They are
// counted anyway, because the bug that cost nine hours was a NORMAL-looking
// outcome (quic_demux) firing on traffic that was never QUIC. Only a count that
// includes the healthy paths lets you see one of them run away.
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
