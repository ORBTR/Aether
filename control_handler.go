/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package aether

import (
	"github.com/ORBTR/aether/flow"
	"github.com/ORBTR/aether/health"
)

// ControlScheduler is the minimal scheduler surface ControlFrameHandler
// needs — set a stream's priority weight, and optionally wake a writer
// that is stalled on a flow-control consume. Declared here as a local
// interface (rather than importing the concrete *scheduler.Scheduler)
// to avoid a control_handler.go → scheduler → aether import cycle.
// *scheduler.Scheduler satisfies this surface natively.
type ControlScheduler interface {
	SetWeight(streamID uint64, weight uint8)
	Wake()
}

// StreamWindowLookup is the per-transport closure that resolves a
// StreamID into the live flow.StreamWindow under the adapter's local
// session mutex. Used by ControlFrameHandler.HandleWindowUpdate to
// route credit to the right stream without the helper needing to know
// the adapter's stream-map type or its locking discipline. Returns nil
// when the StreamID is unknown.
type StreamWindowLookup func(streamID uint64) *flow.StreamWindow

// ControlFrameHandler dispatches the four protocol-level control frames
// (PING / PONG / PRIORITY / WINDOW_UPDATE) that every transport adapter
// handles identically. The adapter wires up the streamWindowLookup
// closure to map streamID→*flow.StreamWindow under its local lock, and
// supplies a frame writer + health monitor + scheduler.
//
// The Noise and TCP adapters build one of these per call (their
// controlHandler methods), so PING-echo, PONG-record and SetWeight behave the
// same on both transports from one definition. Only the Noise adapter dispatches
// WINDOW_UPDATE through it: TCPSession's dispatchFrame acts on none, and sets
// neither ConnWindow nor StreamWindowLookup, which HandleWindowUpdate reads.
//
// QUIC's WindowUpdate handling is part of its native QUIC machinery,
// so QUICSession deliberately does NOT use this helper.
type ControlFrameHandler struct {
	HealthMon          *health.Monitor
	Sched              ControlScheduler
	ConnWindow         *flow.ConnWindow
	StreamWindowLookup StreamWindowLookup
	Writer             FrameWriter
	Sender, Receiver   PeerID
	KeepaliveStreamID  uint64
	// WakeScheduler controls whether HandleWindowUpdate calls
	// Sched.Wake() after applying credit. Noise sets true so a stalled
	// writeLoop blocked on Consume unblocks the moment credit arrives.
	// TCPSession leaves it false: it never calls HandleWindowUpdate.
	WakeScheduler bool
}

// HandlePing emits a PONG for the inbound PING. The PONG echoes the
// PING's SeqNo so the sender can derive RTT on receipt. Errors from the
// frame writer are swallowed: a failed PONG just means the next keepalive
// cycle will retry, and the readLoop that calls this has no caller to
// return the error to.
func (h *ControlFrameHandler) HandlePing(frame *Frame) {
	_ = h.Writer(&Frame{
		SenderID:   h.Sender,
		ReceiverID: h.Receiver,
		StreamID:   h.KeepaliveStreamID,
		Type:       TypePONG,
		SeqNo:      frame.SeqNo,
	})
}

// HandlePong records inbound activity + feeds the SRTT update.
//
// sentAt comes from the local Monitor's PingSentAt(), not from any
// timestamp encoded in the frame. The PONG SeqNo is the seq parameter
// RecordPongRecv uses to match against pendingPingSeq; reconstructing
// the send time from SeqNo would require carrying the full 64-bit
// UnixNano on the wire, but only the low 32 bits fit in the frame
// header — round-tripping that as time.Unix(0, low32) gives a 1970-
// epoch garbage value and sample = now - 1970 produces ~Unix-ms
// nonsense in m.lastRTT. The local PingSentAt() is the authoritative
// stamp.
func (h *ControlFrameHandler) HandlePong(frame *Frame) {
	h.HealthMon.RecordActivity()
	h.HealthMon.RecordPongRecv(frame.SeqNo, h.HealthMon.PingSentAt())
}

// HandlePriority applies a peer-initiated stream weight change to the
// scheduler. Pure passthrough to the wfq scheduler; every transport
// handles PRIORITY the same way, so the one body is here.
func (h *ControlFrameHandler) HandlePriority(frame *Frame) {
	// A peer must not set the scheduling weight of our own keepalive
	// stream. A hostile peer could otherwise send PRIORITY(keepalive, weight=1)
	// to down-weight our liveness traffic within its latency class. Class-based
	// dequeue bounds the impact, but the peer should have no influence over our
	// reserved control streams at all.
	if h.KeepaliveStreamID != 0 && frame.StreamID == h.KeepaliveStreamID {
		return
	}
	p := DecodePriority(frame.Payload)
	h.Sched.SetWeight(frame.StreamID, p.Weight)
}

// HandleWindowUpdate applies an inbound credit grant to the
// connection-level window or to the per-stream window identified by
// frame.StreamID. Unknown stream IDs are dropped: a WINDOW_UPDATE for a
// stream that is gone is a benign late grant. When WakeScheduler is true
// and the applied credit > 0, the scheduler is woken so a writeLoop
// stalled on Consume re-evaluates immediately.
func (h *ControlFrameHandler) HandleWindowUpdate(frame *Frame) {
	credit := DecodeWindowUpdate(frame.Payload)
	if frame.StreamID == StreamConnectionLevel {
		h.ConnWindow.ApplyUpdate(int64(credit))
	} else if h.StreamWindowLookup != nil {
		if w := h.StreamWindowLookup(frame.StreamID); w != nil {
			w.ApplyUpdate(int64(credit))
		}
	}
	if h.WakeScheduler && credit > 0 {
		h.Sched.Wake()
	}
}
