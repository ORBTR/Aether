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
// control stream. SendGoAway, which both adapters' GoAway call, builds its
// frame here, so the two differ only in the SenderID / ReceiverID /
// StreamID they pass. The frame is returned (not sent) so the adapter can
// choose its own write path (writeFrame vs scheduler enqueue vs direct
// conn.Write during teardown).
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
// peer-supplied reason as the close cause. Both adapters' handleGoAway
// call it, so one definition keeps the log format stable across
// transports.
func HandleGoAwayFrame(closeWithErr func(error) error, remoteShort, proto string, frame *Frame) {
	reason, message := DecodeGoAway(frame.Payload)
	// %q Go-quotes the peer-supplied message, neutralising log-injection
	// via embedded newlines / ANSI escapes that would otherwise forge
	// fake log lines in aggregators.
	log.Printf("[AETHER-%s] GOAWAY from %s: reason=%d msg=%q", proto, remoteShort, reason, message)
	// Only GoAwayError is a genuine failure. Normal (graceful shutdown),
	// Migration (moving to a better transport), and Overload (load
	// shedding) are intentional peer actions — a non-nil cause for them would
	// make the upper-layer churn/fallback logic misread a graceful shutdown as
	// a session failure and thrash. Close cleanly for those so no
	// new streams open but the teardown is not scored as a failure.
	if reason == GoAwayError {
		_ = closeWithErr(fmt.Errorf("peer sent GOAWAY (reason=%d): %s", reason, message))
		return
	}
	_ = closeWithErr(nil)
}
