/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package aether

import (
	"time"

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
// The Noise and TCP adapters used to inline the same ~50 lines of
// PING-echo / PONG-record / SetWeight / ApplyUpdate plumbing each;
// consolidating them here keeps the behaviour of those four frame
// types in lockstep between transports.
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
	// TCP sets false because its writeLoop runs on a 2ms ticker and the
	// scheduler wake is not needed (and was not invoked in the pre-
	// refactor handler).
	WakeScheduler bool
}

// HandlePing emits a PONG for the inbound PING. The PONG echoes the
// PING's SeqNo so the sender can derive RTT on receipt. Errors from the
// frame writer are swallowed because the pre-refactor handlers in both
// adapters did the same — a failed PONG just means the next keepalive
// cycle will retry.
func (h *ControlFrameHandler) HandlePing(frame *Frame) {
	_ = h.Writer(&Frame{
		SenderID:   h.Sender,
		ReceiverID: h.Receiver,
		StreamID:   h.KeepaliveStreamID,
		Type:       TypePONG,
		SeqNo:      frame.SeqNo,
	})
}

// HandlePong records inbound activity + feeds the PONG SeqNo +
// timestamp pair into the health monitor for SRTT update. SeqNo carries
// the low 32 bits of the PING's UnixNano send time so the monitor can
// derive the round-trip without per-session bookkeeping.
func (h *ControlFrameHandler) HandlePong(frame *Frame) {
	h.HealthMon.RecordActivity()
	sentAt := time.Unix(0, int64(frame.SeqNo))
	h.HealthMon.RecordPongRecv(frame.SeqNo, sentAt)
}

// HandlePriority applies a peer-initiated stream weight change to the
// scheduler.  Pure passthrough to the wfq scheduler — the adapter
// originally inlined the two-line body each, but every transport
// handles PRIORITY the same way so it belongs here.
func (h *ControlFrameHandler) HandlePriority(frame *Frame) {
	p := DecodePriority(frame.Payload)
	h.Sched.SetWeight(frame.StreamID, p.Weight)
}

// HandleWindowUpdate applies an inbound credit grant to the
// connection-level window or to the per-stream window identified by
// frame.StreamID. Unknown stream IDs are dropped (matches pre-refactor
// behaviour — receiving a WINDOW_UPDATE for a stream that no longer
// exists is a benign late grant). When WakeScheduler is true and the
// applied credit > 0, the scheduler is woken so a writeLoop stalled on
// Consume re-evaluates immediately.
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
