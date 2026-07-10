//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"net"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// ─── AE-M-17 — TCP batch sub-frames pass the structural gate ──────────────
//
// The TCP readLoop's single-frame path calls frame.Validate() and
// reportAbuse(ReasonMalformedFrame) on failure, but the 0x85 batch branch
// dispatched every decoded sub-frame WITHOUT that gate. A peer could smuggle
// unknown Type bytes / oversize Length / undersized control payloads inside a
// batch, reaching the dispatch switch AND evading the abuse signal that feeds
// the S7 circuit breaker. The fix validates each batch sub-frame with the
// same gate as the single-frame path (parity with the Noise adapter).
//
// This drives a real TCPSession.readLoop with a hand-built 0x85 batch whose
// first sub-frame carries an invalid frame type (outside the [0x01,0x14]
// valid range) and whose second is a well-formed control frame. The
// sub-frames are full-header encoded, so the batch decoder routes each via
// its peek byte = SenderID[0] = 0x00 (not a short indicator) to the
// full-header decoder, reconstructing the invalid type verbatim. Pre-fix the
// abuse score stays 0; post-fix reportAbuse fires for the malformed sub-frame.
func TestAEM17_TCPBatchSubFrameValidated(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	client := NewTCPSession(clientConn, "vl1_client", "vl1_server", aether.ProtoTCP, aether.DefaultSessionOptions())
	server := NewTCPSession(serverConn, "vl1_server", "vl1_client", aether.ProtoTCP, aether.DefaultSessionOptions())
	defer client.Close()
	defer server.Close()

	// Sub-frame 1: invalid frame type (0xFF is outside [TypeDATA, TypeCONGESTION]).
	// Zero SenderID → wire first byte 0x00 → batch decoder full-header path.
	malformed := &aether.Frame{Type: aether.FrameType(0xFF), StreamID: 7}
	// Sub-frame 2: a well-formed PING (no min-payload requirement) — proves
	// valid sub-frames still flow; only the malformed one is dropped.
	valid := &aether.Frame{Type: aether.TypePING, StreamID: 7}

	wire := []byte{aether.ShortBatchIndicator, 0x02}
	wire = append(wire, aether.EncodeFrameToBytes(malformed)...)
	wire = append(wire, aether.EncodeFrameToBytes(valid)...)

	// net.Pipe Write blocks until the server readLoop has consumed the bytes.
	if _, err := clientConn.Write(wire); err != nil {
		t.Fatalf("write batch to wire: %v", err)
	}

	// reportAbuse(ReasonMalformedFrame) must have fired for the malformed
	// sub-frame. A single malformed frame raises the score without tripping
	// the breaker, so the session stays up and the score is observable.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if server.PeerAbuseScore() > 0 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if got := server.PeerAbuseScore(); got <= 0 {
		t.Fatalf("AE-M-17 regressed: PeerAbuseScore = %v, want > 0 — a malformed "+
			"batch sub-frame bypassed Frame.Validate() and the ReasonMalformedFrame "+
			"abuse signal", got)
	}
}
