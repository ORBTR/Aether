/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

// Engine composes all per-stream reliability components into a single
// state machine. This is the integration layer that adapters use instead
// of wiring SendWindow, RecvWindow, RetransmitQueue, RTTEstimator,
// FECEncoder, and ReplayWindow individually.

package reliability

import (
	"sync"
	"time"

	"github.com/ORBTR/aether"
)

// Engine manages the full reliability lifecycle for a single stream.
// It orchestrates: sequence assignment, ACK/SACK processing, retransmission,
// RTT estimation, FEC encoding/decoding, and anti-replay protection.
//
// FEC mode (Concern #8): when EngineConfig.FECMode == FECReedSolomon,
// `RSEnc` / `RSDec` are populated and the XOR `FEC`/`FECDec` fields stay
// nil. When the mode is FECBasicXOR (or zero), the legacy XOR fields are
// populated and `RSEnc`/`RSDec` stay nil. Callers that touch these fields
// directly should check both.
//
// Locking model (Concern #10): split into send-side and recv-side locks
// so a busy receiver doesn't block the sender (and vice-versa) on
// high-throughput streams. Each sub-component still has its own internal
// lock — these mutexes only protect the engine-level orchestration that
// touches multiple sub-components in one critical section.
//
//   sendMu — protects orchestration around SendWin / RetransmitQ
//   recvMu — protects orchestration around RecvWin / Replay
//   RTT     — internally synchronised; either lock may read/write it
type Engine struct {
	sendMu sync.Mutex
	recvMu sync.Mutex

	StreamID    uint64
	Reliability aether.Reliability

	// Core components (all created by NewEngine)
	SendWin     *SendWindow
	RecvWin     *RecvWindow
	RetransmitQ *RetransmitQueue
	RTT         *RTTEstimator
	FEC         *FECEncoder // populated when FECMode is XOR or zero
	FECDec      *FECDecoder
	RSEnc       *RSEncoder  // populated when FECMode == FECReedSolomon
	RSDec       *RSDecoder
	Replay      *ReplayWindow

	// Configuration
	maxAge time.Duration // 0 = no deadline (reliable forever)
}

// EngineConfig holds configuration for creating a reliability engine.
type EngineConfig struct {
	StreamID     uint64
	Reliability  aether.Reliability
	WindowSize   int           // send/recv window size (default: 256)
	MaxRetries   int           // 0 = unlimited
	MaxAge       time.Duration // 0 = no deadline
	FECGroupSize int           // 0 = no FEC, >0 = XOR group size
	// FECMode selects the FEC implementation. Defaults to FECBasicXOR
	// when FECGroupSize > 0. Set to FECReedSolomon to switch the engine
	// to k=FECGroupSize, m=FECParityShards Reed-Solomon (Concern #8).
	FECMode FECLevel
	// FECParityShards is the m parameter for Reed-Solomon. Ignored when
	// FECMode != FECReedSolomon. Default: DefaultRSParityShards.
	FECParityShards int
}

// NewEngine creates a reliability engine with the given configuration.
// The engine owns all sub-components and provides a unified API.
func NewEngine(cfg EngineConfig) *Engine {
	windowSize := cfg.WindowSize
	if windowSize <= 0 {
		windowSize = 256
	}

	rtt := NewRTTEstimator()

	e := &Engine{
		StreamID:    cfg.StreamID,
		Reliability: cfg.Reliability,
		SendWin:     NewSendWindow(windowSize),
		RecvWin:     NewRecvWindow(windowSize),
		RetransmitQ: NewRetransmitQueue(rtt, cfg.MaxRetries),
		RTT:         rtt,
		Replay:      NewReplayWindow(),
		maxAge:      cfg.MaxAge,
	}

	// FECGroupSize 0 = FEC disabled (gossip, keepalive, control streams).
	// FECGroupSize > 0 = FEC enabled with the specified mode + group size.
	if cfg.FECGroupSize > 0 {
		switch cfg.FECMode {
		case FECReedSolomon:
			parity := cfg.FECParityShards
			if parity <= 0 {
				parity = DefaultRSParityShards
			}
			if rs, err := NewRSEncoder(cfg.FECGroupSize, parity); err == nil {
				e.RSEnc = rs
			}
			if rs, err := NewRSDecoder(cfg.FECGroupSize, parity); err == nil {
				e.RSDec = rs
			}
		default:
			e.FEC = NewFECEncoder(cfg.FECGroupSize)
			e.FECDec = NewFECDecoder()
		}
	}

	if cfg.MaxAge > 0 {
		e.RetransmitQ.SetMaxAge(cfg.MaxAge)
		e.RecvWin.SetMaxAge(cfg.MaxAge)
	}

	return e
}

// Send prepares a frame for sending: assigns SeqNo, enqueues for retransmission,
// generates FEC repair if applicable. Returns the assigned SeqNo.
// Send-path orchestration → sendMu.
func (e *Engine) Send(frame *aether.Frame) uint32 {
	e.sendMu.Lock()
	defer e.sendMu.Unlock()

	seqNo := e.SendWin.Add(frame)
	frame.SeqNo = seqNo

	// Enqueue for retransmission (unless unreliable/best-effort)
	if e.Reliability == aether.ReliableOrdered || e.Reliability == aether.ReliableUnordered {
		e.RetransmitQ.Enqueue(frame)
	}

	return seqNo
}

// Receive processes an incoming data frame: anti-replay check, insert into
// receive window for reordering, return in-order payloads ready for delivery.
// Recv-path orchestration → recvMu.
func (e *Engine) Receive(seqNo uint32, payload []byte, hasAntiReplay bool) [][]byte {
	e.recvMu.Lock()
	defer e.recvMu.Unlock()

	if hasAntiReplay {
		if !e.Replay.Check(seqNo) {
			return nil // replayed frame
		}
	}

	return e.RecvWin.Insert(seqNo, payload)
}

// ProcessACK handles an incoming ACK frame. Returns the RTT sample (if valid)
// and any SACK-acked entries for congestion control feedback.
// ACK frames mutate the send side (SendWin + RetransmitQ) → sendMu.
// RTT.Update is internally synchronised so it doesn't need either lock.
func (e *Engine) ProcessACK(ackNo uint32, sackBlocks []aether.SACKBlock) (rttSample time.Duration, ackedBytes int64) {
	e.sendMu.Lock()
	defer e.sendMu.Unlock()

	// Cumulative ACK
	entry := e.SendWin.Ack(ackNo)
	if entry != nil {
		if entry.Retries == 0 {
			rttSample = time.Since(entry.SentAt)
			e.RTT.Update(rttSample)
		}
		ackedBytes += int64(entry.Frame.Length)
		e.RetransmitQ.Remove(ackNo)
	}

	// SACK blocks
	for _, block := range sackBlocks {
		count := e.SendWin.AckRange(block.Start, block.End)
		ackedBytes += int64(count) * int64(aether.HeaderSize)
		for seq := block.Start; seq <= block.End; seq++ {
			e.RetransmitQ.Remove(seq)
		}
	}

	return rttSample, ackedBytes
}

// Tick checks for retransmission timeouts. Returns a frame to retransmit (or nil).
// Should be called periodically (e.g., every 10ms). Send-path → sendMu.
func (e *Engine) Tick() *aether.Frame {
	e.sendMu.Lock()
	defer e.sendMu.Unlock()

	frame := e.RetransmitQ.Dequeue()
	if frame != nil {
		e.RTT.BackoffRTO()
	}
	return frame
}

// GenerateSACKInfo returns the cumulative ACK point and SACK blocks for
// sending an ACK frame back to the sender. Recv-path → recvMu.
func (e *Engine) GenerateSACKInfo() (expectedSeqNo uint32, blocks []aether.SACKBlock) {
	e.recvMu.Lock()
	defer e.recvMu.Unlock()

	return e.RecvWin.ExpectedSeqNo(), e.RecvWin.MissingRanges()
}

// SRTT returns the current smoothed RTT estimate.
func (e *Engine) SRTT() time.Duration {
	return e.RTT.SRTT()
}

// RTO returns the current retransmission timeout.
func (e *Engine) RTO() time.Duration {
	return e.RTT.RTO()
}

// Close releases all resources held by the engine. Acquire both locks
// to make sure no Send/Receive is in flight when we drop the references.
func (e *Engine) Close() {
	e.sendMu.Lock()
	defer e.sendMu.Unlock()
	e.recvMu.Lock()
	defer e.recvMu.Unlock()
	// Components don't have explicit Close methods, but clear references
	e.SendWin = nil
	e.RecvWin = nil
	e.RetransmitQ = nil
}
