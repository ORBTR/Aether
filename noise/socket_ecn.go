//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

// ECN (Explicit Congestion Notification) receive-side plumbing for the
// Noise-UDP transport — Concern #15, receive-side.
//
// Protocol layer (wired earlier): `NoiseSession.RecordCEBytes(n)` folds
// CE-marked byte counts into the next outbound CompositeACK via the
// CACKHasECN flag + CEBytes field. The remote sender's adapter calls
// `congestion.Controller.OnCE(bytes)`, which CUBIC/BBR use to react one
// RTT before queue overflow.
//
// Socket layer (this file and the build-tag siblings): on the receive
// path the kernel must deliver the IP TOS byte alongside each datagram.
// The per-OS dance (setsockopt IP_RECVTOS on Linux/Darwin, WSAIoctl on
// Windows) lives in socket_ecn_{unix,windows,js}.go. All paths converge
// on the same `ecnReader` API below.
//
// RFC 3168 ECN codepoints live in the bottom two bits of IP TOS /
// IPv6 Traffic Class:
//
//	0b00  Not-ECT — non-ECN-capable traffic
//	0b01  ECT(1)
//	0b10  ECT(0)
//	0b11  CE      — congestion experienced (the thing we count)
package noise

import "net"

// ecnCE is the RFC 3168 "Congestion Experienced" codepoint.
const ecnCE = 0x03

// isCEMarked returns true when the TOS / traffic-class byte carries the
// CE codepoint. Accepts any int; only the bottom two bits are consulted.
func isCEMarked(tos int) bool {
	return tos&0x03 == ecnCE
}

// ecnReader wraps a *net.UDPConn with TOS / traffic-class delivery
// enabled. Construct once per listener; the underlying socket is
// mutated (IP_RECVTOS / IPV6_RECVTCLASS). Failure to enable cmsg
// delivery is non-fatal — the reader silently falls back to legacy
// ReadFromUDP semantics and reports TOS=0 for every datagram.
type ecnReader struct {
	conn    *net.UDPConn
	oob     []byte // control-message scratch buffer; reused per read
	enabled bool
}

// newECNReader enables TOS delivery on the given UDP socket. Never
// returns an error — construction always succeeds; Enabled() reports
// whether ECN is actually available on the current platform + kernel.
func newECNReader(conn *net.UDPConn) *ecnReader {
	r := &ecnReader{conn: conn, oob: make([]byte, 128)}
	r.enabled = enableECN(conn)
	return r
}

// Enabled reports whether ECN cmsg delivery is active on this reader.
// Useful for metrics + startup logging so operators can tell whether
// the kernel is cooperating with CE observation.
func (r *ecnReader) Enabled() bool { return r.enabled }
