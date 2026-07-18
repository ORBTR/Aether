/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
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
// FEC mode: when EngineConfig.FECMode == FECReedSolomon, `RSEnc` /
// `RSDec` are populated and the XOR `FEC`/`FECDec` fields stay nil.
// When the mode is FECBasicXOR (or zero), the XOR fields are populated
// and `RSEnc`/`RSDec` stay nil. Callers that touch these fields
// directly should check both.
//
// Locking model: split into send-side and recv-side locks so a busy
// receiver doesn't block the sender (and vice-versa) on high-throughput
// streams. Each sub-component still has its own internal lock — these
// mutexes only protect the engine-level orchestration that touches
// multiple sub-components in one critical section.
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

	// closed guards post-Close use. AER-069: Close no longer nils the
	// component pointers (which panicked on any later call); it flips this
	// flag under both locks instead. Guarded by sendMu (Close takes both).
	closed bool
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
	// to k=FECGroupSize, m=FECParityShards Reed-Solomon.
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

	seqNo, entry := e.SendWin.AddEntry(frame)
	frame.SeqNo = seqNo

	// Enqueue for retransmission (unless unreliable/best-effort). Share
	// the send-side entry so both queues reference one backing struct
	// instead of two — saves an allocation per send and keeps metadata
	// (BBRSample, Retries) consistent across the ACK/retransmit paths.
	if e.Reliability == aether.ReliableOrdered || e.Reliability == aether.ReliableUnordered {
		e.RetransmitQ.EnqueueFromSend(entry)
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

	// Cumulative ACK: ackNo acknowledges EVERY outstanding seq in
	// [base, ackNo], not just ackNo itself. AER-069: the old code acked and
	// removed only `ackNo`, stranding every lower unacked seq in both the
	// send window and the retransmit queue forever — they never left the
	// retransmit heap, so they fired spurious duplicate retransmits and the
	// send window never advanced past them. Walk base..ackNo, acking each.
	//
	// Bound the walk by maxAckRangeSpan exactly as the SACK path below and
	// SendWindow.AckRange do: ackNo is peer-controlled, so base..ackNo can be
	// a ~4B span for a stale or malicious value (ackNo < base underflows to a
	// huge span). An oversize span is skipped entirely — a real cumulative
	// ACK never covers that many seqs at once.
	base := e.SendWin.Base()
	if span := uint64(ackNo - base); span <= maxAckRangeSpan {
		var sample *SendEntry
		seq := base
		for i := uint64(0); i <= span; i++ {
			if entry := e.SendWin.Ack(seq); entry != nil {
				ackedBytes += int64(entry.Frame.Length)
				e.RetransmitQ.Remove(seq)
				// AER-064: sample RTT from the largest-acked non-retransmitted
				// entry (RFC 9002 §5.1), consistent with the noise dispatch
				// path — sampling the oldest instead inflates SRTT/RTO.
				if entry.Retries == 0 && (sample == nil || entry.SentAt.After(sample.SentAt)) {
					sample = entry
				}
			}
			seq++
		}
		if sample != nil {
			rttSample = time.Since(sample.SentAt)
			e.RTT.Update(rttSample)
		}
	}

	// SACK blocks
	for _, block := range sackBlocks {
		count := e.SendWin.AckRange(block.Start, block.End)
		ackedBytes += int64(count) * int64(aether.HeaderSize)
		// AE-P-23: bound the retransmit-removal scan the same way
		// SendWindow.AckRange does. block.End is peer-controlled; the naive
		// `for seq := Start; seq <= End; seq++` never terminates when
		// End=0xFFFFFFFF (seq wraps to 0 and stays <= End) and runs ~4B
		// Remove() calls when End<Start — either wedges the send side under
		// e.sendMu. Skip spans larger than a real ACK ever covers (matching
		// AckRange, which returns 0 for the same input so nothing was acked
		// there either), then iterate a fixed count with wrap-safe increment.
		span := uint64(block.End - block.Start)
		if span > maxAckRangeSpan {
			continue
		}
		seq := block.Start
		for i := uint64(0); i <= span; i++ {
			e.RetransmitQ.Remove(seq)
			seq++
		}
	}

	return rttSample, ackedBytes
}

// Tick checks for retransmission timeouts and returns every frame that is due
// this tick. Should be called periodically (e.g., every 10ms). Send-path →
// sendMu.
//
// AER-069: the old signature returned a single frame and called BackoffRTO
// once per returned frame. A caller draining all due frames (the only correct
// use) therefore looped Tick and backed the RTO estimator off once *per due
// frame* — an N-frame timeout burst multiplied the RTO by 2^N, freezing the
// send side. Drain the whole due set here and back the estimator off at most
// once, since a single detection instant is one loss signal regardless of how
// many frames it covers.
func (e *Engine) Tick() []*aether.Frame {
	e.sendMu.Lock()
	defer e.sendMu.Unlock()

	var due []*aether.Frame
	for {
		frame := e.RetransmitQ.Dequeue()
		if frame == nil {
			break
		}
		due = append(due, frame)
	}
	if len(due) > 0 {
		e.RTT.BackoffRTO()
	}
	return due
}

// GenerateSACKInfo returns the cumulative ACK point and SACK blocks for
// sending an ACK frame back to the sender. Recv-path → recvMu.
//
// AER-069: the cumulative ACK point is the highest CONTIGUOUSLY received seq,
// which is `ExpectedSeqNo() - 1` — NOT ExpectedSeqNo() itself. The old code
// returned the next-expected seq, i.e. one MORE than was actually received in
// order; a peer decoding it as the cumulative point (the field's meaning, per
// the ACKEngine's `BaseACK: expected-1`) would believe an extra frame was
// delivered and stop retransmitting a frame the receiver never got.
//
// When nothing has been received in order yet (expected==0), the point wraps
// to 0xFFFFFFFF, which is the same "no cumulative coverage" sentinel the
// ACKEngine flags with CACKNoCumulative (AER-060). This facade has no flag
// field, so callers must treat 0xFFFFFFFF as "no cumulative ACK yet".
func (e *Engine) GenerateSACKInfo() (cumulativeAck uint32, blocks []aether.SACKBlock) {
	e.recvMu.Lock()
	defer e.recvMu.Unlock()

	return e.RecvWin.ExpectedSeqNo() - 1, e.RecvWin.MissingRanges()
}

// SRTT returns the current smoothed RTT estimate.
func (e *Engine) SRTT() time.Duration {
	return e.RTT.SRTT()
}

// RTO returns the current retransmission timeout.
func (e *Engine) RTO() time.Duration {
	return e.RTT.RTO()
}

// Close marks the engine closed. Acquire both locks so no Send/Receive is in
// flight when it runs. It is idempotent and safe to call concurrently.
//
// AER-069: the old Close nil'd SendWin/RecvWin/RetransmitQ. The sub-components
// have no resources to release (no goroutines, no fds), so nil-ing bought
// nothing and turned any post-Close call — including a second Close, or a
// racing Tick/ProcessACK/Receive — into a nil-pointer panic. Flip a closed
// flag instead and leave the components intact; Closed() lets callers gate.
func (e *Engine) Close() {
	e.sendMu.Lock()
	defer e.sendMu.Unlock()
	e.recvMu.Lock()
	defer e.recvMu.Unlock()
	e.closed = true
}

// Closed reports whether Close has been called.
func (e *Engine) Closed() bool {
	e.sendMu.Lock()
	defer e.sendMu.Unlock()
	return e.closed
}
