/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package aether

// BuildWindowUpdateFrame constructs a WINDOW_UPDATE frame granting
// `credit` additional bytes on the stream identified by streamID. Use
// StreamConnectionLevel for the conn-level window.
//
// The Noise adapter's sendWindowUpdate builds its frame here; the adapter-specific
// concern is the writeFrame path, which stays in the adapter (writeMu +
// encryption pipeline). A byte-stream session runs no credit and writes none.
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
// Both adapters' SendCongestion build their frame here.
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
// session-wide throttle. Both adapters' handleCongestion call it, so the
// wire-format handling lives in exactly one place. The caller still owns
// its own per-adapter debug logging — that's adapter-specific tracing
// rather than wire behaviour.
func HandleCongestionFrame(throttle *CongestionThrottle, frame *Frame) CongestionPayload {
	p := DecodeCongestion(frame.Payload)
	throttle.Apply(p)
	return p
}
