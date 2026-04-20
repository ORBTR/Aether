/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package aether

// Envelope wraps any typed frame for wire encoding/decoding.
// The Type field determines which concrete frame is in the Payload field.
// Wire format is identical to the existing 50-byte header — only the Go
// API changes, not the bytes on the wire.
//
// Usage:
//
//	env := Envelope{
//	    SenderID:   myPeerID,
//	    ReceiverID: peerID,
//	    Type:       TypeDATA,
//	    Frame:      &DataFrame{StreamID: 1, Data: []byte("hello")},
//	}
//	EncodeEnvelope(w, env) // same bytes as EncodeFrame
//
//	env, _ := DecodeEnvelope(r) // same bytes as DecodeFrame
//	switch f := env.Frame.(type) {
//	case *DataFrame:
//	    fmt.Println("data on stream", f.StreamID, string(f.Data))
//	case *WindowUpdate:
//	    fmt.Println("credit grant", f.Credit)
//	}
type Envelope struct {
	SenderID   PeerID
	ReceiverID PeerID
	Type       FrameType
	Flags      FrameFlags
	Nonce      Nonce
	Frame      FramePayload // one of the typed frame structs below
}

// FramePayload is the interface satisfied by all typed frame structs.
type FramePayload interface {
	framePayload() // marker method — prevents external implementation
	StreamID() uint64
}

// ────────────────────────────────────────────────────────────────────────────
// Typed Frame Variants
// ────────────────────────────────────────────────────────────────────────────

// DataPayload carries application data on a stream.
type DataFrame struct {
	Stream uint64
	SeqNo  uint32
	Data   []byte
}

func (d *DataFrame) framePayload() {}
func (d *DataFrame) StreamID() uint64 { return d.Stream }

// Ack acknowledges received data frames.
type AckFrame struct {
	Stream uint64
	AckNo  uint32
	Ranges []SACKBlock // optional selective ACK ranges
}

func (a *AckFrame) framePayload() {}
func (a *AckFrame) StreamID() uint64 { return a.Stream }

// WindowUpdate grants additional flow control credit.
type WindowUpdateFrame struct {
	Stream uint64
	Credit uint64 // cumulative total of credit granted since stream start
}

func (w *WindowUpdateFrame) framePayload() {}
func (w *WindowUpdateFrame) StreamID() uint64 { return w.Stream }

// StreamOpen requests opening a new stream.
type OpenFrame struct {
	Stream      uint64
	Reliability Reliability
	Priority    uint8
	Dependency  uint64
}

func (o *OpenFrame) framePayload() {}
func (o *OpenFrame) StreamID() uint64 { return o.Stream }

// StreamClose gracefully closes a stream.
type CloseFrame struct {
	Stream uint64
}

func (c *CloseFrame) framePayload() {}
func (c *CloseFrame) StreamID() uint64 { return c.Stream }

// StreamReset abruptly terminates a stream with a reason.
type ResetFrame struct {
	Stream uint64
	Reason ResetReason
}

func (r *ResetFrame) framePayload() {}
func (r *ResetFrame) StreamID() uint64 { return r.Stream }

// Ping requests a liveness check.
type PingFrame struct {
	Stream uint64
	Nonce  [8]byte
}

func (p *PingFrame) framePayload() {}
func (p *PingFrame) StreamID() uint64 { return p.Stream }

// Pong responds to a Ping.
type PongFrame struct {
	Stream uint64
	Nonce  [8]byte
}

func (p *PongFrame) framePayload() {}
func (p *PongFrame) StreamID() uint64 { return p.Stream }

// GoAway signals the peer should stop sending.
type GoAwayFrame struct {
	Reason  GoAwayReason
	Message string
}

func (g *GoAwayFrame) framePayload() {}
func (g *GoAwayFrame) StreamID() uint64 { return 0 }

// FECRepair carries a forward error correction repair frame.
type FECRepairFrame struct {
	Stream    uint64
	GroupID   uint32
	GroupSize uint16
	Repair    []byte
}

func (f *FECRepairFrame) framePayload() {}
func (f *FECRepairFrame) StreamID() uint64 { return f.Stream }

// PriorityUpdate changes a stream's scheduling weight.
type PriorityFrame struct {
	Stream     uint64
	Weight     uint8
	Dependency uint64
}

func (p *PriorityFrame) framePayload() {}
func (p *PriorityFrame) StreamID() uint64 { return p.Stream }

// PathProbe tests connectivity on a specific path.
type PathProbeFrame struct {
	ProbeID uint32
	Padding []byte // padding to test MTU
	IsReply bool
}

func (p *PathProbeFrame) framePayload() {}
func (p *PathProbeFrame) StreamID() uint64 { return 0 }

// ControlMessage carries protocol-level control data (handshake, key rotation, migration).
type ControlFrame struct {
	Stream uint64
	Data   []byte
}

func (c *ControlFrame) framePayload() {}
func (c *ControlFrame) StreamID() uint64 { return c.Stream }

// ────────────────────────────────────────────────────────────────────────────
// Envelope ↔ Frame conversion (Bidirectional conversion between Envelope and Frame.)
// ────────────────────────────────────────────────────────────────────────────

// ToFrame converts an Envelope to the Frame struct.
// Adapters can work with either type.
func (e *Envelope) ToFrame() *Frame {
	f := &Frame{
		SenderID:   e.SenderID,
		ReceiverID: e.ReceiverID,
		Type:       e.Type,
		Flags:      e.Flags,
		Nonce:      e.Nonce,
	}
	if e.Frame != nil {
		f.StreamID = e.Frame.StreamID()
	}
	switch p := e.Frame.(type) {
	case *DataFrame:
		f.SeqNo = p.SeqNo
		f.Payload = p.Data
		f.Length = uint32(len(p.Data))
	case *AckFrame:
		f.AckNo = p.AckNo
	case *WindowUpdateFrame:
		f.Payload = EncodeWindowUpdate(p.Credit)
		f.Length = uint32(len(f.Payload))
	case *OpenFrame:
		f.Payload = EncodeOpenPayload(OpenPayload{
			Reliability: p.Reliability,
			Priority:    p.Priority,
			Dependency:  p.Dependency,
		})
		f.Length = uint32(len(f.Payload))
	case *GoAwayFrame:
		f.Payload = EncodeGoAway(p.Reason, p.Message)
		f.Length = uint32(len(f.Payload))
	case *ControlFrame:
		f.Payload = p.Data
		f.Length = uint32(len(p.Data))
	}
	return f
}

// EnvelopeFromFrame converts a Frame to an Envelope.
// Both types can be used interchangeably.
func EnvelopeFromFrame(f *Frame) Envelope {
	env := Envelope{
		SenderID:   f.SenderID,
		ReceiverID: f.ReceiverID,
		Type:       f.Type,
		Flags:      f.Flags,
		Nonce:      f.Nonce,
	}
	switch f.Type {
	case TypeDATA:
		env.Frame = &DataFrame{Stream: f.StreamID, SeqNo: f.SeqNo, Data: f.Payload}
	case TypeACK:
		env.Frame = &AckFrame{Stream: f.StreamID, AckNo: f.AckNo}
	case TypeWINDOW:
		credit := DecodeWindowUpdate(f.Payload)
		env.Frame = &WindowUpdateFrame{Stream: f.StreamID, Credit: credit}
	case TypeOPEN:
		p := DecodeOpenPayload(f.Payload)
		env.Frame = &OpenFrame{Stream: f.StreamID, Reliability: p.Reliability, Priority: p.Priority, Dependency: p.Dependency}
	case TypeCLOSE:
		env.Frame = &CloseFrame{Stream: f.StreamID}
	case TypeRESET:
		env.Frame = &ResetFrame{Stream: f.StreamID}
	case TypePING:
		env.Frame = &PingFrame{Stream: f.StreamID}
	case TypePONG:
		env.Frame = &PongFrame{Stream: f.StreamID}
	case TypeGOAWAY:
		env.Frame = &GoAwayFrame{}
	case TypeFEC_REPAIR:
		env.Frame = &FECRepairFrame{Stream: f.StreamID, Repair: f.Payload}
	case TypePRIORITY:
		env.Frame = &PriorityFrame{Stream: f.StreamID}
	case TypePATH_PROBE:
		env.Frame = &PathProbeFrame{}
	default:
		env.Frame = &ControlFrame{Stream: f.StreamID, Data: f.Payload}
	}
	return env
}
