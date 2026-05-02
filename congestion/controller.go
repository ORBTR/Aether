/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

// Package congestion implements congestion control algorithms for Aether.
// Used by Noise-UDP aether. Skipped for QUIC/TCP/WS (native congestion).
package congestion

import "time"

// Controller is the interface for congestion control algorithms.
// Both CUBIC and BBR implement this interface.
type Controller interface {
	// OnAck is called when an ACK is received.
	// ackedBytes: number of bytes acknowledged.
	// rtt: round-trip time for this ACK.
	OnAck(ackedBytes int64, rtt time.Duration)

	// OnAckWithPipe is the PRR-aware variant. pipeBytes is the current
	// in-flight byte count, consulted by CUBIC during fast recovery to
	// run RFC 6937 Proportional Rate Reduction. Controllers that don't
	// implement PRR (e.g. BBR's bandwidth-driven model) may treat this
	// as equivalent to OnAck and ignore pipeBytes.
	OnAckWithPipe(ackedBytes int64, rtt time.Duration, pipeBytes int64)

	// OnLoss is called when packet loss is detected (timeout or NACK).
	OnLoss()

	// OnLossWithPipe is the PRR-aware variant. pipeBytes is the current
	// in-flight byte count at the moment loss was confirmed; CUBIC seeds
	// PRR's recoverFS from it. Idempotent within a recovery epoch — repeat
	// calls during the same recovery don't compound cwnd reductions.
	OnLossWithPipe(pipeBytes int64)

	// OnCE is called when the receiver reports CE-marked packets via the
	// ECN extension on a Composite ACK. bytesMarked is the cumulative
	// CE-byte count observed since the last ACK. Implementations should
	// react like a mild loss signal (CWND reduction) without retransmit.
	//
	// The receive-side socket plumbing (IP_RECVTOS / IPV6_RECVTCLASS +
	// per-OS cmsg parsing) is platform-specific and lives in build-tagged
	// noise/socket_ecn_*.go files.
	OnCE(bytesMarked int64)

	// OnSend is called by the adapter after each transmission so PRR can
	// track prr_out (RFC 6937 §3.1). BBR also uses OnSend as its delivery
	// rate sample point and stamps the returned DeliveryRateSample on the
	// SendEntry so the matching ACK can drive OnAckSampled. CUBIC has no
	// notion of delivery-rate samples and returns a zero-value sample.
	OnSend(sentBytes int64) DeliveryRateSample

	// ResetCWND restores the controller to a known-clean state — cwnd =
	// initialCWND, ssthresh cleared, recovery state cleared, slow-start
	// re-engaged. Called by the adapter when the probe-before-close path
	// confirms the network is alive: prior OnLoss reductions were
	// over-zealous, the cwnd-collapsed deadlock should be broken.
	ResetCWND()

	// CWND returns the current congestion window in bytes.
	CWND() int64

	// CanSend returns true if more data can be sent given the in-flight bytes.
	CanSend(inFlight int64) bool

	// PacingRate returns the target send rate in bytes/second.
	// Returns 0 if pacing is not applicable (CUBIC doesn't pace).
	PacingRate() float64

	// SetMSS updates the maximum segment size from PMTU discovery.
	// Called when the path MTU changes (e.g., after a successful probe).
	SetMSS(mss int)
}
