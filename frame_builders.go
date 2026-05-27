/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package aether

// BuildWindowUpdateFrame constructs a WINDOW_UPDATE frame granting
// `credit` additional bytes on the stream identified by streamID. Use
// StreamConnectionLevel for the conn-level window.
//
// Pulled out of the Noise + TCP adapters because both built the same
// frame with the same payload encoding — the only adapter-specific
// concern is the writeFrame path, which stays in the adapter (TCP wraps
// writeMu, Noise wraps writeMu + encryption pipeline). Adapter callers
// pass the result to their own writeFrame.
func BuildWindowUpdateFrame(sender, receiver PeerID, streamID uint64, credit uint64) *Frame {
	payload := EncodeWindowUpdate(credit)
	return &Frame{
		SenderID:   sender,
		ReceiverID: receiver,
		StreamID:   streamID,
		Type:       TypeWINDOW,
		Length:     uint32(len(payload)),
		Payload:    payload,
	}
}

// BuildCongestionFrame constructs a CONGESTION frame carrying the
// supplied throttle hint payload. Always emitted on
// StreamConnectionLevel — the throttle is a session-wide signal.
//
// Pulled out of the Noise + TCP adapters which built identical frames.
func BuildCongestionFrame(sender, receiver PeerID, p CongestionPayload) *Frame {
	payload := EncodeCongestion(p)
	return &Frame{
		SenderID:   sender,
		ReceiverID: receiver,
		StreamID:   StreamConnectionLevel,
		Type:       TypeCONGESTION,
		Length:     uint32(len(payload)),
		Payload:    payload,
	}
}

// HandleCongestionFrame applies an inbound CONGESTION-hint frame to the
// session-wide throttle. Adapter callers used to inline the same
// Decode + Apply two-liner each; pulled here so the wire-format
// handling lives in exactly one place. The caller still owns its own
// per-adapter debug logging — that's adapter-specific tracing rather
// than wire behaviour.
func HandleCongestionFrame(throttle *CongestionThrottle, frame *Frame) CongestionPayload {
	p := DecodeCongestion(frame.Payload)
	throttle.Apply(p)
	return p
}
