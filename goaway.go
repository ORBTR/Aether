/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package aether

import (
	"fmt"
	"log"
)

// FrameWriter is the adapter-supplied callback that emits a single frame
// on the underlying transport. Shared by every transport-agnostic helper
// in the root package that needs to send a control frame without owning
// the per-transport writeMu / compression / encryption pipeline. The
// adapter is responsible for serialising concurrent calls (the Noise and
// TCP adapters both wrap their writeFrame with a per-session writeMu).
type FrameWriter func(*Frame) error

// BuildGoAwayFrame constructs a GOAWAY frame for emission on the given
// control stream. Pulled out of the Noise and TCP adapters because both
// adapters built byte-identical frames — only the SenderID / ReceiverID /
// StreamID inputs differed, and those now flow in as arguments. The
// frame is returned (not sent) so the adapter can choose its own write
// path (writeFrame vs scheduler enqueue vs direct conn.Write during
// teardown).
func BuildGoAwayFrame(sender, receiver PeerID, controlStreamID uint64, reason GoAwayReason, message string) *Frame {
	payload := EncodeGoAway(reason, message)
	return &Frame{
		SenderID:   sender,
		ReceiverID: receiver,
		StreamID:   controlStreamID,
		Type:       TypeGOAWAY,
		Length:     uint32(len(payload)),
		Payload:    payload,
	}
}

// SendGoAway constructs and writes a GOAWAY frame via the supplied
// writer. Pure convenience wrapper around BuildGoAwayFrame + writer —
// kept separate so adapters that need to inspect or batch the frame
// (e.g. include in a final flush sequence) can call the builder
// directly. Returns whatever the writer returns; the helper never
// generates errors of its own.
func SendGoAway(writer FrameWriter, sender, receiver PeerID, controlStreamID uint64, reason GoAwayReason, message string) error {
	return writer(BuildGoAwayFrame(sender, receiver, controlStreamID, reason, message))
}

// HandleGoAwayFrame is the shared inbound-GOAWAY handler — decode +
// log + close-with-error. `proto` labels the adapter in the log line
// (e.g. "noise", "tcp") so operators can attribute peer-initiated
// teardowns to the right transport without re-parsing the call site.
// `remoteShort` is the truncated peer NodeID already prepared by the
// caller (typically nodeID.Short()). closeWithErr is the session's
// CloseWithError so the inbound GOAWAY tears the session down with the
// peer-supplied reason as the close cause. Adapters used to inline this
// 4-line body each; one definition keeps the log format stable across
// transports.
func HandleGoAwayFrame(closeWithErr func(error) error, remoteShort, proto string, frame *Frame) {
	reason, message := DecodeGoAway(frame.Payload)
	// %q Go-quotes the peer-supplied message, neutralising log-injection
	// via embedded newlines / ANSI escapes that would otherwise forge
	// fake log lines in aggregators.
	log.Printf("[AETHER-%s] GOAWAY from %s: reason=%d msg=%q", proto, remoteShort, reason, message)
	_ = closeWithErr(fmt.Errorf("peer sent GOAWAY (reason=%d): %s", reason, message))
}
