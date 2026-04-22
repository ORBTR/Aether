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

	// OnLoss is called when packet loss is detected (timeout or NACK).
	OnLoss()

	// OnCE is called when the receiver reports CE-marked packets via the
	// ECN extension on a Composite ACK. bytesMarked is the cumulative
	// CE-byte count observed since the last ACK. Implementations should
	// react like a mild loss signal (CWND reduction) without retransmit.
	//
	// The receive-side socket plumbing (IP_RECVTOS / IPV6_RECVTCLASS +
	// per-OS cmsg parsing) is platform-specific and lives in build-tagged
	// noise/socket_ecn_*.go files.
	OnCE(bytesMarked int64)

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
