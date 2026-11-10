/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/abuse"
	"github.com/ORBTR/aether/congestion"
	"github.com/ORBTR/aether/flow"
	"github.com/ORBTR/aether/reliability"
)

// streamSendBlockFloor is the minimum noiseStream.Send wall-clock duration
// that gets recorded into the session's streamSendBlockHist. Sub-floor
// samples are counted in streamSendFastTotal instead — a Send that
// completes in under 50µs almost certainly hit the flow.StreamWindow
// fast path (Consume's non-blocking TryAcquire) and the writeLoop wake
// path, neither of which the caller-block percentile should be dominated
// by. The same fast-path skip flow.StreamWindow.Consume applies to its
// grantStarveHist.
const streamSendBlockFloor = 50 * time.Microsecond

// fecSessionCacheBytes bounds what one session's FEC decoders hold together, the
// session's part of the working-set budget of reliability.FECBudget. A stream's
// decoder holds at most its budget's bytes, and a session may run its stream cap of
// them: past this bound a decoder evicts its own oldest and recovers less, which the
// sender's retransmit covers.
const fecSessionCacheBytes = 4 << 20

// noiseStream is a single Aether stream over Noise-UDP with full reliability.
type noiseStream struct {
	streamID uint64
	config   aether.StreamConfig
	session  *NoiseSession
	state    *aether.StreamStateMachine
	// recvQ holds the whole in-order messages between the readLoop
	// (handleData and deliverToControl, through
	// enqueueDelivery and enqueueControl) and Receive. recvDone is the
	// end Receive selects on, draining what recvQ still holds before it
	// returns io.EOF; closeRecvOnce closes it exactly once (recvOnce), from the
	// readLoop (endReceive, handleReset) and from application goroutines
	// (Reset). Both are made in createStream.
	recvQ    *recvQueue
	recvDone chan struct{}
	recvOnce sync.Once

	// reserved is the receive credit createStream reserved for this stream on
	// the session's ledger (session.admitted) before publishing it, and
	// releaseReservation gives back once, on whichever exit takes the stream
	// out of s.streams.
	reserved atomic.Int64

	// The stream's end has a send half and a receive half. Close sets
	// closeWanted, and finishSend queues the CLOSE frame once no Send is in
	// progress (sendsActive) and every DATA frame the stream sent has been
	// acknowledged: closeSent stops a second CLOSE, and a RESET either side sends
	// sets it too, and closeQueued says the CLOSE is in the send window. closeDone
	// is set once, by the ACK of that CLOSE or by a RESET. endReceive sets
	// peerClosed when the peer's CLOSE reaches its turn in the receive window. The
	// stream leaves s.streams once closeDone and peerClosed are set (leaveIfEnded),
	// because until then handleACK and the reliability tick, which find the stream
	// through s.streams, acknowledge and retransmit its frames, its CLOSE included,
	// and the peer's frames are delivered through it.
	sendsActive atomic.Int64
	closeWanted atomic.Bool
	closeSent   atomic.Bool
	closeQueued atomic.Bool
	closeDone   atomic.Bool
	peerClosed  atomic.Bool

	// left is set once, by whichever exit takes the stream out of the session
	// (leaveIfEnded, Reset, handleReset). A later Reset finds it set and writes
	// no RESET, which would reach whatever stream the peer now has on this ID.
	left atomic.Bool

	// refusedByPeer is set by handleReset when the peer's RESET carries
	// ResetRefused, so Send and Receive return aether.ErrStreamRefused.
	refusedByPeer atomic.Bool

	// overrun is set by enqueueDelivery when this side resets a sender past its
	// ceilings, and by handleReset when the peer's RESET carries ResetFlowCtrl,
	// so Send and Receive return aether.ErrStreamOverrun.
	overrun atomic.Bool

	// lastRTOBackoffAt is the last time reliabilityTick applied an RTO
	// backoff for this stream, which bounds the backoff to once per RTO
	// interval (RFC 6298 §5.5 — one doubling per timeout event) rather than
	// once per retransmitted frame. Written and read only from the single
	// reliabilityTick goroutine, so no lock is needed.
	lastRTOBackoffAt time.Time

	window *flow.StreamWindow

	// grantDebouncer coalesces stream-level WINDOW_UPDATE emissions driven
	// by application reads on this stream. When Receive takes a metered
	// message it records messageCredit of the message's length
	// (recordReceive), what Send charged; the debouncer calls
	// ReceiverConsume after GrantCoalesceWindow, or at once when the pending bytes reach
	// GrantImmediateFraction of the stream's initial credit. handleData's
	// receipt of a frame records nothing, so grants advertise what the
	// consumer took, a slow consumer backpressures the sender, and the
	// bytes waiting in recvQ stay charged to the sender, which is what
	// bounds recvQ.
	grantDebouncer *grantDebouncer

	// fec is the stream's FEC state, nil when the stream's level is FECNone or the
	// session has FEC disabled. No other stream shares it: sendSingleFrame encodes
	// this stream's frames in it, and handleData and handleFECRepair decode the
	// peer's for this stream's receive window.
	fec *reliability.StreamFEC

	// Per-stream reliability engine (Noise has NO native reliability)
	engine      *reliability.Engine
	ackEngine   *reliability.ACKEngine       // adaptive ACK generation
	sendWindow  *reliability.SendWindow      // alias: engine.SendWin
	recvWindow  *reliability.RecvWindow      // alias: engine.RecvWin
	retransmitQ *reliability.RetransmitQueue // alias: engine.RetransmitQ
	rtt         *reliability.RTTEstimator    // alias: engine.RTT
	replay      *reliability.ReplayWindow    // alias: engine.Replay
	connOnce    sync.Once                    // thread-safe Conn() init
	conn        net.Conn                     // cached net.Conn wrapper

	// Stall-detection progress markers, updated in handleACK and consulted
	// in reliabilityTick. Colocated with the stream so they die with it
	// (no session-level map to clean up) and atomic so handleACK can write
	// without contending on s.mu.
	//
	// lastBaseACKSeen: largest BaseACK value seen for this stream so far
	// (wraps with the uint32 SeqNo space — monotonic comparison uses the
	// prev<new check).
	//
	// lastProgressAtUnixNano: time.Now().UnixNano() at the instant
	// lastBaseACKSeen advanced. Zero means "no progress observed yet",
	// which the tick treats as "don't probe".
	lastBaseACKSeen        atomic.Uint32
	lastProgressAtUnixNano atomic.Int64

	// lastAckSilentLogUnixNano throttles the [ACK-SILENT] warning so
	// reliabilityTick logs at most once per minute per stream — at the
	// 10ms ticker resolution a wedged stream would otherwise flood the
	// log.
	lastAckSilentLogUnixNano atomic.Int64

	// lastStuckResetUnixNano throttles STREAM-STUCK-DETECT's tlp reset
	// to once per second per stream. Without the throttle, the 10ms
	// reliability ticker calls tlp.AnyAckReceived() on every iteration
	// where ConsecutiveProbes > 0, and TLP re-arms a fresh probe
	// between ticks — producing a ~100Hz tlpReset/log spam loop on a
	// stuck stream under heavy loss. One reset per second is still
	// aggressive enough to recover transient losses, while bounding the
	// log/CPU cost when the path is durably broken.
	lastStuckResetUnixNano atomic.Int64

	// fragBuf reassembles the fragments of this stream's messages. Touched by
	// the session's readLoop only (handleData, handleFECRepair), which hands
	// each completed message to recvQ.
	fragBuf *FragmentBuffer

	// generation is this stream object's number among the session's streams
	// (NoiseSession.streamGenerations), stamped on its fragments so the peer
	// tells them from fragments of an earlier stream that used the same ID.
	// Zero only for a stream built outside createStream, which then sends no
	// fragments.
	generation uint64

	// incarnation names this stream among those that have used its ID on the
	// session, as this side states it: the opener's generation, this stream's own
	// generation when this side opened it (OpenStream) and the generation the peer's
	// OPEN stated when the peer did (handleOpen), with WriterOpened set when this side
	// opened it. Its CLOSE (finishSend) and RESET (Reset) state it; handleClose and
	// handleReset end the stream only for a frame that names it (namedBy). Set in
	// createStream before the stream is published, read-only after.
	incarnation aether.StreamIncarnation

	// messageIDs numbers the messages Send splits into fragments; the next ID
	// is messageIDs.Add(1), so the first is 1 and none is 0.
	messageIDs atomic.Uint64

	// rack runs RFC 8985 time-based loss detection on this stream.
	// Updated by handleACK on every successful ACK (Ack call), consulted
	// each reliability tick to enumerate freshly-lost seqs to retransmit.
	// It is the loss-signal authority: reliabilityTick calls
	// OnLossWithPipe once per tick for the seqs DetectLost returns, so
	// cwnd is reduced once per actual loss and not once per retransmit
	// attempt (the RTO path re-sends without calling OnLoss).
	rack *congestion.RACK

	// tlp implements RFC 8985 §7 Tail Loss Probe. Armed by the adapter
	// when in-flight transitions from 0 → >0; fires when no ACK has
	// arrived for a full PTO. Sends one packet OUTSIDE cwnd to elicit
	// an ACK, breaking the deadlock where cwnd ≤ inFlight prevents any
	// further sends.
	tlp *congestion.TLP

	// beforeSchedulerExit is a test seam, nil outside tests: a RESET's exit (Reset,
	// endByPeerReset) calls it after the RESET's settlement and before the stream
	// leaves the scheduler, so a test can run there what a Send already past its
	// last state check does (sendStreamCharged).
	beforeSchedulerExit atomic.Pointer[func()]

	// chargeMu orders a Send's connection charge against the settlement of the
	// stream's credit (settleCharges). connCharged is what this stream's Sends have
	// charged to the session's connection window (commitConnCharge), less what a
	// Send gave back itself (returnCharge); connSettled is set once, by the
	// settlement, and from then on a Send that charges the connection window gives
	// that charge back itself. The settlement returns to the connection window what
	// connCharged says no grant has returned, not what the stream window holds: a
	// Send charges the stream window first (sendAdmitted), so the stream window can
	// hold a charge whose connection charge is still to come.
	chargeMu    sync.Mutex
	connCharged int64
	connSettled bool
}

// createStream creates a new stream with full reliability infrastructure via Engine.
// Admission runs atomically under s.mu with the map insert, so concurrent peer
// OPENs cannot pass it together: the MaxConcurrentStreams cap, then the
// stream's receive credit reserved on the session's ledger (s.admitted, whose
// parent is the peer's), all before the stream is published in s.streams and
// reaches an acceptor. A refused stream is returned as nil with
// aether.ErrStreamCapExhausted or aether.ErrStreamCreditRefused; when
// enforceRemoteCap is true (the peer opened it) the peer is also sent
// RESET(ResetRefused) and no state is kept, and locally-initiated OpenStream
// passes false and returns the error to its caller. An ID in use is refused with
// aether.ErrDuplicateStreamID and sends nothing. peerGeneration is the generation
// the peer's OPEN stated, the stream's incarnation for a stream the peer opened;
// OpenStream passes 0, and the stream's own generation names it.
func (s *NoiseSession) createStream(streamID uint64, cfg aether.StreamConfig, enforceRemoteCap bool, peerGeneration uint64) (*noiseStream, error) {
	// FEC is off by default and a caller opts in through cfg.FECLevel, which an
	// accepted stream takes from the peer's OPEN. Both callers have checked the
	// level (reliability.ValidFECLevel), so the only error left is the Reed-Solomon
	// tables for its fixed shard counts, which do not fail.
	var fec *reliability.StreamFEC
	if s.opts.FEC {
		fec, _ = reliability.NewStreamFEC(reliability.FECLevel(cfg.FECLevel), reliability.FECBudget{
			Groups:      s.opts.MaxFECGroups,
			Shared:      &s.fecCached,
			SharedBytes: fecSessionCacheBytes,
		})
	}
	// WindowSize 64: tracks Aether frame reordering (NOT UDP fragment reassembly).
	// Max in-flight per stream: gossip=2, RPC=3, keepalive=1, control=1.
	// 64 gives 32× headroom for gossip, 21× for RPC.
	eng := reliability.NewEngine(reliability.EngineConfig{
		StreamID:    streamID,
		Reliability: cfg.Reliability,
		WindowSize:  64,
		MaxAge:      cfg.MaxAge,
	})
	st := &noiseStream{
		streamID:    streamID,
		config:      cfg,
		session:     s,
		state:       aether.NewStreamStateMachine(),
		recvQ:       s.newQueue(),
		recvDone:    make(chan struct{}),
		window:      flow.NewStreamWindowWithCap(cfg.InitialCredit, cfg.MaxCredit),
		engine:      eng,
		fec:         fec,
		fragBuf:     newChargedFragmentBuffer(recvQueueEntryCost),
		generation:  s.streamGenerations.Add(1),
		sendWindow:  eng.SendWin,
		recvWindow:  eng.RecvWin,
		retransmitQ: eng.RetransmitQ,
		rtt:         eng.RTT,
		replay:      eng.Replay,
		rack:        congestion.NewRACK(eng.RTT.SRTT()),
		tlp:         congestion.NewTLP(eng.RTT.SRTT()),
	}
	st.incarnation = aether.StreamIncarnation{Generation: st.generation, WriterOpened: true}
	if enforceRemoteCap {
		st.incarnation = aether.StreamIncarnation{Generation: peerGeneration}
	}
	// Surface retransmit-queue evictions (the queue's onEvict hook) instead
	// of dropping them silently. An eviction (byte-cap pressure, deadline, or
	// max-retries exceeded) means a reliable frame lost its RTO safety net,
	// and without the count and the log the resulting stall or loss has no
	// diagnosable cause.
	st.retransmitQ.SetOnEvict(func(e *reliability.RetransmitEntry) {
		if e == nil || e.Frame == nil {
			return
		}
		atomic.AddUint64(&s.retransmitEvicted, 1)
		log.Printf("[RETX-EVICT] peer=%s stream=%d seq=%d — retransmit dropped, no RTO safety net",
			s.RemoteNodeID().Short(), streamID, e.Frame.SeqNo)
	})
	// Seed the TLP's max_ack_delay (RFC 9002 §6.2). Without a seed,
	// PTO uses the conservative 25ms default for the first RTT
	// regardless of the path's actual ACK cadence — firing spurious
	// TLPs on a sub-ms localhost path or under-firing on a multi-100ms
	// long-haul. UpdateMaxAckDelay's EWMA takes over once inbound
	// CompositeACKs start flowing.
	//
	// Source priority:
	//   1. PEER-ADVERTISED value carried in the Noise handshake
	//      NodeInfo payload (s.peerMaxAckDelay, captured at
	//      NewNoiseSession via the noiseConnAckDelay probe). This is
	//      the RFC 9002-compliant path: the handshake carries the value
	//      in both directions.
	//   2. RECEIVER-SIDE APPROXIMATION max(ACKPolicy.MaxDelay, SRTT/4)
	//      when (1) is zero (peer didn't advertise, e.g. an over-conn
	//      substrate using the minimal NodeInfo encoding that doesn't
	//      carry the field). Preserves correct behaviour against a peer
	//      whose NodeInfo lacks the field and over-conn substrates.
	initialAckDelay := s.peerMaxAckDelay
	if initialAckDelay <= 0 {
		policy := reliability.DefaultACKPolicy()
		initialAckDelay = policy.MaxDelay
		if srtt := eng.RTT.SRTT(); srtt > 0 {
			if quarter := srtt / 4; quarter > initialAckDelay {
				initialAckDelay = quarter
			}
		}
	}
	st.tlp.SetMaxAckDelay(initialAckDelay)
	// Wire the session's in-flight counter (wire bytes in flight) into this
	// stream's SendWindow so MarkWritten charges it and every removal,
	// including releaseInFlight when a RESET ends the stream, gives the
	// same count back, and the writeLoop's CanSend gate is a single
	// atomic.Load, not an O(streams) lock walk per send.
	// MUST run before any Send on this stream — earlier sends would
	// under-report by the size of their in-flight frames.
	eng.SendWin.SetSessionInFlightCounter(&s.inFlightBytes)
	// Share the session-level grant-starvation histogram with this
	// stream's flow window. All streams on a session record into the same
	// histogram so the percentile readout describes session-wide
	// credit-starvation tail behaviour rather than fragmenting per
	// stream (most streams produce too few samples to compute stable
	// percentiles on their own).
	st.window.SetGrantStarveHist(&s.grantStarveHist)
	// Share the session-level HOL-block histogram with this stream's
	// RecvWindow. Same rationale as grantStarveHist — per-stream sample
	// volume is too low for stable percentiles; the session-aggregate view
	// is what operators need to spot reordering. All streams on a session
	// record into one ring, so the p50/p99 reflects the worst-case HOL
	// across every active stream.
	st.recvWindow.SetHOLHist(&s.recvWindowHOLHist)
	// Per-stream grant debouncer. Immediate-flush floor at 50% of the
	// stream's initial credit so burst reads drain the pending total
	// without waiting the full coalesce window when the sender is close
	// to the stream-window edge.
	initialCredit := cfg.InitialCredit
	if initialCredit <= 0 {
		initialCredit = flow.DefaultStreamCredit
	}
	st.grantDebouncer = newGrantDebouncer(
		st.window,
		s.sendWindowUpdateAgnostic,
		streamID,
		int64(float64(initialCredit)*GrantImmediateFraction),
	)
	// Initialize ACK engine with adaptive policy — sends Composite ACKs
	// Pass RTT callback for first-after-idle threshold scaling
	st.ackEngine = reliability.NewACKEngine(eng.RecvWin, reliability.DefaultACKPolicy(), func(cack *aether.CompositeACK) {
		s.sendCompositeACK(streamID, cack)
	}, func() time.Duration {
		return eng.RTT.SRTT()
	})
	// Piggyback the stream window's cumulative WINDOW_UPDATE grant on
	// outgoing CompositeACKs via CACKHasWindowCredit, so a grant reaches the
	// sender's handleACK (ApplyUpdate) on an ACK already going out. The ACK
	// engine attaches each new cumulative value once; a CompositeACK lost on
	// the path takes that copy with it, and refreshWindowGrants' WINDOW_UPDATE
	// on the reliability tick re-delivers the total, which ApplyUpdate takes
	// as a duplicate when it has already arrived.
	st.ackEngine.SetWindowCreditFn(func() int64 {
		return st.window.CurrentGrant()
	})

	// Atomic admission + insert. Keeping these in one locked section
	// closes the TOCTOU gap where two concurrent peer OPENs could both
	// pass a separate admission check and then both insert, exceeding
	// the cap by one per racing goroutine.
	s.mu.Lock()
	// One stream per ID: the stream in place keeps its window and reservation.
	// The peer's handleOpen ignores the refusal, and OpenStream hands it to its
	// caller, who would otherwise be given another caller's stream and put a second
	// OPEN on the wire, which the peer ignores in turn. A stream that has just left
	// on both CLOSEs or by an acknowledged RESET holds its ID against a local open
	// for a short while (reopenQuietLocked), and one whose RESET waits for its
	// acknowledgment holds it until then (resetPendingLocked): the peer may still
	// hold that stream, and would take the new stream's frames for its own.
	if _, exists := s.streams[streamID]; exists || (!enforceRemoteCap && (s.reopenQuietLocked(streamID) || s.resetPendingLocked(streamID))) {
		s.mu.Unlock()
		st.discardUnpublished()
		return nil, aether.ErrDuplicateStreamID
	}
	// MaxConcurrentStreams cap applies to BOTH locally-initiated and
	// peer-initiated stream opens — otherwise a caller leaking streams
	// would not be gated by the configured cap. enforceRemoteCap=true
	// means peer-initiated → reply with RESET so the peer gives up;
	// enforceRemoteCap=false means locally-initiated → return nil and
	// let the caller surface the typed ErrStreamCapExhausted.
	{
		cap := s.opts.MaxConcurrentStreams
		if cap <= 0 {
			cap = aether.DefaultMaxConcurrentStreams
		}
		if len(s.streams) >= cap {
			s.mu.Unlock()
			s.reportAbuse(abuse.ReasonStreamRefused)
			s.refuseStream(st, enforceRemoteCap)
			return nil, aether.ErrStreamCapExhausted
		}
	}
	// The stream's receive credit is what this side lets the peer queue on it
	// before the consumer reads: the window's initial credit, which its grants
	// extend. Reserving it here, under s.mu with the insert, is what makes the
	// credit of every published stream fit the session and peer ceilings.
	credit := st.window.CurrentWindow()
	if err := s.admitted.reserve(credit); err != nil {
		s.mu.Unlock()
		if enforceRemoteCap {
			s.reportAbuse(abuse.ReasonStreamRefused)
		}
		s.refuseStream(st, enforceRemoteCap)
		return nil, err
	}
	st.reserved.Store(credit)
	s.streams[streamID] = st
	// A RESET for this ID from here on is this stream's, not the crossing of an
	// earlier one (handleReset's resetGrants).
	delete(s.resetGrants, streamID)
	s.mu.Unlock()

	// Register with stream GC for idle timeout tracking
	s.streamGC.Register(streamID)

	// Propagate cfg.LatencyClass to the scheduler. The caller's setting
	// MUST be honoured: the RPC caller that opens stream 1 sets
	// ClassINTERACTIVE and dropping it leaves RPC dispatch competing
	// with gossip at the lowest priority.
	//
	// ClassUnset (zero value) means the caller didn't specify a class —
	// fall back to DefaultLatencyClass(streamID) rather than treating
	// the omission as ClassREALTIME, which would funnel every
	// default-config stream past the scheduler's 10% bandwidth cap.
	class := cfg.LatencyClass
	if class == aether.ClassUnset {
		class = aether.DefaultLatencyClass(streamID)
	}
	s.sched.RegisterWithClass(streamID, cfg.Priority, cfg.Dependency, class)
	return st, nil
}

// refuseStream ends a stream createStream did not admit: it counts the refusal
// (StreamRefusedCount), stops what the stream started before admission and,
// for a stream the peer opened, answers it with RESET(ResetRefused), which the
// peer's handleReset turns into aether.ErrStreamRefused on that stream.
func (s *NoiseSession) refuseStream(st *noiseStream, toPeer bool) {
	atomic.AddUint64(&s.streamRefused, 1)
	st.discardUnpublished()
	if !toPeer {
		return
	}
	s.sendRefused(st.streamID, st.incarnation.Generation)
}

// sendRefused answers a peer's open of streamID with RESET(ResetRefused), which
// the peer's handleReset turns into aether.ErrStreamRefused on that stream. It names
// the stream by the generation the peer's OPEN stated, so the refusal ends that
// stream and no later one under the ID, and it is written again until acknowledged
// (writeReset): a lost refusal would leave the peer's stream holding its credit. No
// stream here has an RTT, so the wait starts at a fresh estimator's RTO.
// refuseStream sends it for a stream createStream did not admit, and handleOpen
// for an OPEN whose credit, FEC level or generation it refuses before any stream is
// built.
func (s *NoiseSession) sendRefused(streamID, generation uint64) {
	_ = s.writeReset(streamID, aether.ResetPayload{
		Reason:      aether.ResetRefused,
		Incarnation: aether.StreamIncarnation{Generation: generation},
	}, reliability.NewRTTEstimator().RTO())
}

// resetRTO is the wait before this stream's RESET is written again: the stream's
// RTO, or a fresh estimator's for a stream built outside createStream, which has no
// estimator of its own.
func (st *noiseStream) resetRTO() time.Duration {
	if st.rtt == nil {
		return reliability.NewRTTEstimator().RTO()
	}
	return st.rtt.RTO()
}

// namedBy reports whether inc, read from a frame of the peer's, names this stream:
// the same generation, and the peer's WriterOpened the opposite of this side's,
// since each side states whether it is the opener itself.
func (st *noiseStream) namedBy(inc aether.StreamIncarnation) bool {
	return inc.Generation == st.incarnation.Generation && inc.WriterOpened != st.incarnation.WriterOpened
}

// discardUnpublished stops the timers createStream starts before admission
// (the grant debouncer and the ACK engine, through teardown) for a stream that
// never entered s.streams, so a refused or duplicate open leaves nothing running.
func (st *noiseStream) discardUnpublished() {
	st.teardown()
}

// releaseReservation gives the session's ledger back the receive credit
// createStream reserved for the stream. Every exit that takes the stream out
// of s.streams calls it (handleReset, Reset, leaveSession);
// the swap makes a second call a no-op.
func (st *noiseStream) releaseReservation() {
	if n := st.reserved.Swap(0); n > 0 && st.session != nil && st.session.admitted != nil {
		st.session.admitted.release(n)
	}
}

// ────────────────────────────────────────────────────────────────────────────
// noiseStream — aether.Stream interface
// ────────────────────────────────────────────────────────────────────────────

func (st *noiseStream) StreamID() uint64            { return st.streamID }
func (st *noiseStream) Config() aether.StreamConfig { return st.config }
func (st *noiseStream) IsOpen() bool                { return st.state.IsOpen() }

func (st *noiseStream) Conn() net.Conn {
	st.connOnce.Do(func() { st.conn = NewStreamConn(st) })
	return st.conn
}

func (st *noiseStream) Send(ctx context.Context, data []byte) error {
	// A Send counts itself in sendsActive before it reads the stream's state,
	// and its exit asks finishSend whether a Close waits on it. Close changes the
	// state before finishSend reads sendsActive, so a Send that finishSend does
	// not count finds the state closed and adds no frame behind the CLOSE.
	st.sendsActive.Add(1)
	defer func() {
		st.sendsActive.Add(-1)
		_ = st.finishSend()
	}()
	if !st.state.CanSend() {
		return st.cannotSend()
	}
	// A closed session will write nothing, so a Send does not wait for credit first;
	// the credit waits end at the close (ConsumeUntil), and sendSingleFrame refuses
	// each frame on a closed session too, for a close that comes after them.
	select {
	case <-st.session.CloseSignal():
		return fmt.Errorf("stream %d: %w", st.streamID, aether.ErrSessionClosed)
	default:
	}
	return st.sendAdmitted(ctx, data)
}

// sendAdmitted is Send past its state and session checks: it charges the stream and
// connection credit and queues the message's frames (sendStreamCharged). A RESET may
// end the stream from here on (Reset, endByPeerReset), and every charge this makes
// comes back once: a connection charge recorded before the RESET's settlement
// (commitConnCharge) by that settlement (settleCharges), one made after it by this
// Send itself, and the stream charge by the settlement's ReleaseAllCharged or by this
// Send's own release, whichever finds it in the window.
func (st *noiseStream) sendAdmitted(ctx context.Context, data []byte) error {
	// Caller-block instrumentation. Measures wall-clock time the
	// application spent inside Send (window.Consume + connWindow.Consume +
	// sendSingleFrame for each fragment) from entry to return. Samples
	// below streamSendBlockFloor bypass the histogram Record and increment
	// streamSendFastTotal instead — the fast-path skip flow.StreamWindow.Consume
	// applies to grant-starvation, for the same reason: recording every
	// microsecond-fast send would dominate the distribution with
	// uncontended noise. CanSend gate is excluded — it's a single atomic
	// load before the wall-clock starts, so the "stream not open" error
	// path doesn't pollute the histogram either.
	sendStart := time.Now()
	defer func() {
		elapsed := time.Since(sendStart)
		if elapsed < streamSendBlockFloor {
			st.session.streamSendFastTotal.Add(1)
			return
		}
		st.session.streamSendBlockHist.Record(elapsed)
	}()

	// Flow control: consume stream + connection credit before sending, both
	// messageCredit of the plaintext length, the unit the receiver's queue
	// charges the message at and Receive records when the consumer takes it.
	// Each window blocks waiting for a grant (up to ConsumeTimeout) and then
	// fails with ErrCreditExhausted.
	n := messageCredit(int64(len(data)))
	//
	// Both reservations must be released if any subsequent step fails —
	// otherwise the credit that we acquired but never delivered to the
	// wire leaks permanently (the peer never sees the bytes, so no
	// WINDOW_UPDATE will ever return them). Without the release every
	// failed Send would shrink the window by its payload until Consume
	// times out.
	//
	// Record per-phase timing so streamSendBlockHist's total can
	// be attributed to per-stream credit vs conn credit vs the post-credit
	// path. Same below-floor skip as the aggregate to keep the fast-path
	// (uncontended) noise out of the percentile distribution.
	perStreamStart := time.Now()
	if err := st.window.ConsumeUntil(ctx, n, st.session.CloseSignal()); err != nil {
		return st.creditWaitError(err, "")
	}
	if d := time.Since(perStreamStart); d >= streamSendBlockFloor {
		st.session.perStreamWindowWaitHist.Record(d)
	}
	// A stream a RESET ended while this Send waited for credit (the settlement's
	// ReleaseAllCharged wakes the wait) does not charge the connection window: the
	// settlement has closed the stream's record of connection charges, so the charge
	// could only come straight back (commitConnCharge).
	if !st.state.CanSend() {
		st.window.ReleaseUnsent(n)
		return st.cannotSend()
	}
	return st.sendStreamCharged(ctx, data, n)
}

// sendStreamCharged is the rest of sendAdmitted once the stream's n bytes of credit
// are charged and its state still let it send: it charges the connection credit,
// records that charge on the stream (commitConnCharge) and queues the message's
// frames, giving back what it charged on any failure. A RESET that comes between that
// state check and the frames' queueing is settled by what the record says: a charge
// recorded before the settlement is the settlement's to return, and one the
// settlement has closed the record to is this Send's.
func (st *noiseStream) sendStreamCharged(ctx context.Context, data []byte, n int64) error {
	streamCredited := true
	defer func() {
		if streamCredited {
			st.window.ReleaseUnsent(n)
		}
	}()

	connWaitStart := time.Now()
	if err := st.session.connWindow.ConsumeUntil(ctx, n, st.session.CloseSignal()); err != nil {
		return st.creditWaitError(err, " conn")
	}
	if d := time.Since(connWaitStart); d >= streamSendBlockFloor {
		st.session.connWindowWaitHist.Record(d)
	}
	if !st.commitConnCharge(n) {
		// The stream's credit is settled: nothing will return this connection charge
		// but this Send, and the deferred release gives back the stream charge if the
		// settlement's ReleaseAllCharged did not find it in the window.
		st.session.connWindow.ReleaseUnsent(n)
		return st.cannotSend()
	}
	streamCredited = false
	charged := true
	defer func() {
		if charged {
			st.returnCharge(n)
		}
	}()

	// postCreditStart wraps the encrypt + writeloop + park path that
	// runs after credit is acquired. Recorded by both the fragment-loop
	// branch (large payload) and the single-frame branch (small payload)
	// at their respective return sites so the histogram excludes the
	// release-on-error fall-throughs above.
	postCreditStart := time.Now()
	recordPostCredit := func() {
		if d := time.Since(postCreditStart); d >= streamSendBlockFloor {
			st.session.postCreditSendHist.Record(d)
		}
	}

	// MTU-aware fragmentation: split large payloads into MSS-sized
	// fragments so each fragment is a single UDP packet (no IP fragmentation).
	// Lost fragments are individually retransmitted by the reliability engine.
	maxPayload := MSSToMaxPayload(st.session.pmtuProber.MSS())
	if st.fec != nil {
		// A repair is as long as the longest frame it covers plus its header and
		// table, and the path carries no frame past the MSS.
		maxPayload -= aether.FECRepairOverhead(st.fec.MaxCovered())
	}
	var fragments [][]byte
	if len(data) > maxPayload {
		var err error
		fragments, err = SplitMessage(st.session.fragmentBinding(st), st.messageIDs.Add(1), data, maxPayload)
		if err != nil {
			// A message past the fragment ceilings, or a session
			// that cannot fragment (no realm, no negotiated envelope). Fail
			// loudly instead of transmitting a silently-truncated message.
			// Returning here (before charged is cleared) lets the deferred
			// returnCharge give back the whole charge, since nothing reached
			// the wire.
			return fmt.Errorf("stream %d: %w", st.streamID, err)
		}
	}

	// A frame the scheduler refuses because the stream has left it (errLeftScheduler)
	// is settled with the stream (sendSingleFrame, releaseInFlight): this Send's charge
	// is in the record the settlement returns, made or to come, so returnCharge must
	// not run as well, or the connection window would get the bytes back twice.
	queued := func(err error) error {
		if errors.Is(err, errLeftScheduler) {
			charged = false
			return st.cannotSend()
		}
		return err
	}

	if fragments != nil {
		// Large payload — send as multiple fragments
		for _, frag := range fragments {
			if err := st.sendSingleFrame(ctx, frag, aether.FlagFRAGMENT); err != nil {
				return queued(err)
			}
		}
		// All fragments accepted — credit is now legitimately outstanding
		// and returns through the peer's grants as its consumer reads
		// (WINDOW_UPDATE, the CompositeACK piggyback).
		charged = false
		recordPostCredit()
		return nil
	}

	// Small payload — send as single frame (existing fast path)
	if err := st.sendSingleFrame(ctx, data, 0); err != nil {
		return queued(err)
	}
	charged = false
	recordPostCredit()
	return nil
}

// recordWrite records the frame's write on the stream's send window, called by
// emitFrameLocked under writeMu before conn.Write, and returns the byte count the
// congestion controller is shown for this write and whether it was the frame's
// first write. At a frame's first write the
// window charges the session counter with wire and starts the RTT, RACK and TLP
// clocks, the BBR sample is stamped (StampSample, because the writeLoop's OnSend is
// the one inflight increment), and the frame enters the retransmit queue, so the RTO
// runs from the write. A retransmit presents the count its first write recorded. A
// frame with no entry (acknowledged while queued) is shown as the bytes it is and is
// not a first write: no ACK will come for it.
//
// The GetEntry recheck closes an ACK landing between MarkWritten and EnqueueSized:
// handleACK's Remove runs after its ProcessCompositeACK, so if the entry is still
// there at the recheck that Remove comes later and finds the queue entry, and if it
// is gone this Remove takes it. Without it the queue would keep retransmitting a
// frame no ACK path would ever remove again.
func (st *noiseStream) recordWrite(frame *aether.Frame, wire int64) (int64, bool) {
	var sample *congestion.DeliveryRateSample
	if bbr, ok := st.session.congestion().(*congestion.BBRController); ok {
		stamped := bbr.StampSample()
		sample = &stamped
	}
	recorded, payload, first := st.sendWindow.MarkWritten(frame, wire, time.Now(), sample)
	if !first {
		if recorded > 0 {
			return recorded, false
		}
		return wire, false
	}
	st.retransmitQ.EnqueueSized(frame, payload)
	if st.sendWindow.GetEntry(frame.SeqNo) == nil {
		st.retransmitQ.Remove(frame.SeqNo)
	}
	return wire, true
}

// creditWaitError is what sendAdmitted answers for a credit wait that failed: the
// session's close when the wait ended at it (flow.ErrWaitEnded), aether.ErrSessionClosed
// as every other Send on a closed session answers, and the window's own error,
// backpressure or the caller's context, otherwise; which names the window in the
// message.
func (st *noiseStream) creditWaitError(err error, which string) error {
	if errors.Is(err, flow.ErrWaitEnded) {
		return fmt.Errorf("stream %d%s: %w: %w", st.streamID, which, aether.ErrSessionClosed, err)
	}
	return fmt.Errorf("stream %d%s: %w", st.streamID, which, err)
}

// errLeftScheduler is what sendSingleFrame returns when the scheduler no longer holds
// the stream; Send reads it to answer the stream's end (cannotSend) and to leave
// what sendSingleFrame settled alone.
var errLeftScheduler = errors.New("stream left the scheduler")

// sendSingleFrame sends one frame: a whole small message (extra 0) or one
// fragment envelope (extra aether.FlagFRAGMENT). It refuses, queueing nothing, on a
// closed session with aether.ErrSessionClosed: CloseWithError leaves the streams in
// the scheduler, and the write loop that would take the frame has stopped. When
// the scheduler refuses the frame or a repair, the stream has left it, so nothing
// more of the message can go: it hands the stream's charges to its settlement
// (releaseInFlight) and returns errLeftScheduler. Of the exits that take a stream
// out of the scheduler, Reset settles before it takes the stream out of s.streams
// and endByPeerReset just after handleReset or endSuperseded took it out, so the
// settlement has run or is about to, and it returns this Send's recorded connection
// charge (commitConnCharge); leaveSession has none, and a Send never meets it,
// because it needs this side's CLOSE acknowledged, which finishSend queues only once
// no Send is in progress (sendsActive), and every Send after it finds the state
// closed.
func (st *noiseStream) sendSingleFrame(ctx context.Context, data []byte, extra aether.FrameFlags) error {
	select {
	case <-st.session.CloseSignal():
		return fmt.Errorf("stream %d: %w", st.streamID, aether.ErrSessionClosed)
	default:
	}
	frame := &aether.Frame{
		SenderID:   st.session.LocalPeerID(),
		ReceiverID: st.session.RemotePeerID(),
		StreamID:   st.streamID,
		Type:       aether.TypeDATA,
		Flags:      aether.FlagANTIREPLAY | extra, // enable anti-replay on all Noise-UDP frames
		Length:     uint32(len(data)),
		Payload:    data,
	}

	// Assign SeqNo via send window (tracks for ACK/retransmit). Add sets
	// frame.SeqNo under the window's lock and records the plaintext count. The
	// frame's recovery state and in-flight charge begin at its first write
	// (recordWrite); once the scheduler has it the write loop may rewrite it, so
	// nothing here reads the frame's fields afterwards.
	st.sendWindow.Add(frame)

	// The stream's encoder names the frame by the sequence number Add gave it, read
	// here because the scheduler owns the frame once it has it. The repairs go
	// behind the frame that completes their group, so a receiver that loses nothing
	// has every covered frame when each repair arrives and holds no repair waiting.
	var repairs []*aether.Frame
	if st.fec != nil {
		repairs = st.fec.Encode(frame.SeqNo, data, extra.Has(aether.FlagFRAGMENT))
	}

	// Enqueue via scheduler for priority-ordered sending
	if !st.queueFrame(frame) {
		st.releaseInFlight()
		return errLeftScheduler
	}
	for _, repair := range repairs {
		repair.StreamID = st.streamID
		repair.SenderID = st.session.LocalPeerID()
		repair.ReceiverID = st.session.RemotePeerID()
		if !st.queueFrame(repair) {
			st.releaseInFlight()
			return errLeftScheduler
		}
	}
	return nil
}

// queueFrame puts one of this stream's frames in the scheduler and reports whether it
// did, which it does only while s.streams holds this stream under its ID: the check
// and the Enqueue are one step under s.mu, the lock every exit takes the stream out of
// s.streams under (Reset, handleReset, endSuperseded, leaveSession, the stream GC)
// before it unregisters the ID. The scheduler keys its queues by ID alone, so without
// the check a Send past its state check when the stream is reset, resuming once the
// peer has acknowledged the RESET and the ID's next stream has registered, would put
// this stream's frame, numbered in this stream's sequence, in the next stream's
// queue, and leave the connection credit it charged on windows nothing settles
// again. sendSingleFrame calls it for each frame and repair.
func (st *noiseStream) queueFrame(frame *aether.Frame) bool {
	s := st.session
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.streams[st.streamID]; !ok || cur != st {
		return false
	}
	return s.sched.Enqueue(st.streamID, frame)
}

// queueRetransmit puts a frame the reliability tick sends again (the RTO and RACK
// paths of reliabilityTick) in the scheduler as a retransmit (Scheduler.MarkRetransmit)
// and reports whether it did, which it does only while s.streams holds this stream
// under its ID, the check and the Enqueue one step under s.mu as in queueFrame. The
// tick works from a snapshot of s.streams taken before it gets here, and a stream a
// RESET ended since, its ID opened again, would otherwise put its frame, numbered in
// its own sequence, in the next stream's queue, which the peer reads as that stream's.
func (st *noiseStream) queueRetransmit(frame *aether.Frame) bool {
	s := st.session
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.streams[st.streamID]; !ok || cur != st {
		return false
	}
	s.sched.MarkRetransmit(st.streamID)
	return s.sched.Enqueue(st.streamID, frame)
}

// queueProbe puts a TLP probe of this stream's in the scheduler's probe slot for its
// ID (Scheduler.EnqueueProbe) and reports whether it did, under the check
// queueRetransmit makes, for the same reason: reliabilityTick's probe and the write
// loop's return of a probe the pacer deferred both come from a stream found before a
// RESET and a reopen of its ID can have run.
func (st *noiseStream) queueProbe(frame *aether.Frame) bool {
	s := st.session
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.streams[st.streamID]; !ok || cur != st {
		return false
	}
	s.sched.EnqueueProbe(st.streamID, frame)
	return true
}

// Receive returns the next whole message from recvQ. After closeRecvOnce has
// closed recvDone it still returns what recvQ holds, one message per call, and
// then io.EOF, or the typed end (typedEnd), so a message admitted before the
// CLOSE or RESET is not lost behind the end. Taking a metered message records it
// as consumed, which is what replenishes the sender's stream and connection
// credit: until then its bytes stay charged, and that charge is what bounds the
// queue. That holds after the stream has left the session on both CLOSEs too;
// only the connection grant still has anywhere to go then.
func (st *noiseStream) Receive(ctx context.Context) ([]byte, error) {
	take := func() ([]byte, bool) {
		data, credited, ok := st.recvQ.pop()
		if ok && credited {
			// recvQ holds whole messages only: the readLoop reassembles
			// fragments (reassemble) before delivery, so messageCredit of
			// this length is what the sender's Send charged for it.
			st.recordReceive(messageCredit(int64(len(data))))
		}
		return data, ok
	}
	for {
		if data, ok := take(); ok {
			return data, nil
		}
		select {
		case <-st.recvQ.wake:
		case <-st.recvDone:
			if data, ok := take(); ok {
				return data, nil
			}
			if err := st.typedEnd(); err != nil {
				return nil, err
			}
			return nil, io.EOF
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-st.session.CloseSignal():
			return nil, aether.ErrSessionClosed
		}
	}
}

// reassemble turns one in-order payload the receive window delivered into
// what the stream's consumer receives. An unmarked payload is a whole message
// and passes through. A marked one (its frame carried aether.FlagFRAGMENT) is a
// fragment: it goes to fragBuf, and reassemble returns the message once its
// last fragment arrives, and ok false until then or when the fragment is
// refused. Bytes reassembly drops (a refused or duplicate fragment, a
// discarded group) are granted back to the sender at once through both flow
// windows, since the application will never read them, and count as granted in
// what a RESET states (recvQueue.addGranted); a discarded group's
// count carries the message's recvQueueEntryCost (newChargedFragmentBuffer), so
// what Send charged for the message comes back whole. Called by the session's
// readLoop only.
func (st *noiseStream) reassemble(d reliability.RecvDelivery) (payload []byte, ok bool) {
	if !d.Marked {
		return d.Payload, true
	}
	s := st.session
	msg, released, err := st.fragBuf.Add(s.fragRecv, st.streamID, d.Payload)
	if released > 0 {
		st.recvQ.addGranted(released)
		releaseCredit(st.window, released, st.streamID, s.sendWindowUpdateAgnostic)
		if grant := s.connWindow.ReceiverConsume(released); grant > 0 {
			s.sendWindowUpdate(aether.StreamConnectionLevel, uint64(grant))
		}
	}
	if err != nil {
		dbgNoise.Printf("stream %d: fragment refused: %v", st.streamID, err)
		return nil, false
	}
	return msg, msg != nil
}

// settleExpired takes a frame the receive window has given up on (RecvWindow.SetMaxAge)
// and that was acknowledged while it waited: no retransmit will replace it and no
// Receive will record it, so a grant here is the only way its sender's credit comes
// back. A whole message returns what Send charged for it (messageCredit); a fragment
// returns its chunk, and its group's FragmentBuffer returns the rest when it discards
// the group. It counts as dropped, for the consumer summing DeliveryStats. Called by
// the session's readLoop only.
func (st *noiseStream) settleExpired(d reliability.RecvDelivery) {
	s := st.session
	n := messageCredit(int64(len(d.Payload)))
	if d.Marked {
		_, chunk, err := ParseFragment(d.Payload)
		if err != nil {
			return // a fragment that cannot be read charged nothing Add would have returned
		}
		n = int64(len(chunk))
	}
	s.deliveryStats.recordDropped(st.streamID, int(n))
	st.recvQ.addGranted(n)
	releaseCredit(st.window, n, st.streamID, s.sendWindowUpdateAgnostic)
	if grant := s.connWindow.ReceiverConsume(n); grant > 0 {
		s.sendWindowUpdate(aether.StreamConnectionLevel, uint64(grant))
	}
}

// recordReceive advances flow-control credit accounting for bytes the
// application has actually received on this stream. Both the per-stream
// debouncer AND the session-wide conn-level debouncer get the same byte
// count — stream grants reflect per-stream progress and conn grants
// reflect aggregate progress across all streams on this session.
//
// Debouncers coalesce multiple calls into one WINDOW_UPDATE per coalesce
// window, so rapid back-to-back Receive()s don't produce one wire frame
// per payload. See grant_debouncer.go for the coalescing policy.
func (st *noiseStream) recordReceive(n int64) {
	if n <= 0 {
		return
	}
	if st.grantDebouncer != nil {
		st.grantDebouncer.Record(n)
	}
	if st.session != nil && st.session.connGrantDebouncer != nil {
		st.session.connGrantDebouncer.Record(n)
	}
}

// Close ends the local send side: Send refuses from here on, and the CLOSE
// frame goes to the peer once every frame already sent has been acknowledged
// (finishSend), at once when none is outstanding. The receive side is not
// ended by Close: what the peer sends is admitted for Receive and its grants
// still flow until the peer's CLOSE reaches endReceive, which ends it
// (Receive returns what the queue holds, then io.EOF). The stream leaves the
// session once its CLOSE is acknowledged and the peer's has come (leaveIfEnded).
// It returns an error only for a session that has closed, and nil when the CLOSE
// is queued or waits on an ACK or a Send in progress.
func (st *noiseStream) Close() error {
	st.state.Transition(aether.EventSendFIN)
	st.closeWanted.Store(true)
	return st.finishSend()
}

// finishSend moves the stream's CLOSE along. Close, the exit of every Send and
// handleACK, after each ACK on the stream, call it, so whichever of them meets a
// condition acts on it, once.
//
// First it queues the CLOSE, once Close has asked for it (closeWanted), no Send is
// in progress (sendsActive) and the send window holds no frame. The CLOSE takes the
// stream's next sequence number from the send window, so it goes through the
// scheduler and is timed, retransmitted and acknowledged by the machinery DATA has
// (recordWrite, handleACK, reliabilityTick): a CLOSE lost on the path is written
// again, and the peer's receive side does not stay open until its stream GC.
//
// It waits for the ACK of every DATA frame though the peer would now read it in
// sequence (InsertEnd), because handleClose answers a CLOSE for a stream it no
// longer holds with a cumulative ACK up to that CLOSE. That answer clears every
// frame below it from this window, and it is true only of a stream whose frames
// were all acknowledged first: a stream whose OPEN was lost is unknown to the peer
// too, and its unacknowledged DATA would read as delivered.
//
// Then, once the CLOSE is in the window and the window is empty again, its ACK has
// come: closeDone is set and the stream leaves if the peer's CLOSE has come
// (leaveIfEnded). A stream never leaves on an unacknowledged CLOSE, since the peer
// that did not get it would hold the stream's receive side open and, once its
// stream GC resets it, stop granting for the messages it holds, stranding their
// connection credit here. When no ACK ever comes, the stream GC resets the stream,
// and the RESET takes the place of the CLOSE.
func (st *noiseStream) finishSend() error {
	if st.closeQueued.Load() {
		if st.sendWindow.InFlight() == 0 && st.closeDone.CompareAndSwap(false, true) {
			st.leaveIfEnded()
		}
		return nil
	}
	if !st.closeWanted.Load() || st.sendsActive.Load() != 0 {
		return nil
	}
	if st.sendWindow != nil && st.sendWindow.InFlight() != 0 {
		return nil
	}
	if !st.closeSent.CompareAndSwap(false, true) {
		return nil
	}
	s := st.session
	select {
	case <-s.CloseSignal():
		return fmt.Errorf("stream %d: %w", st.streamID, aether.ErrSessionClosed)
	default:
	}
	payload := aether.EncodeClosePayload(st.incarnation)
	frame := &aether.Frame{
		SenderID:   s.LocalPeerID(),
		ReceiverID: s.RemotePeerID(),
		StreamID:   st.streamID,
		Type:       aether.TypeCLOSE,
		Length:     uint32(len(payload)),
		Payload:    payload,
	}
	st.sendWindow.Add(frame)
	st.closeQueued.Store(true)
	if !s.sched.Enqueue(st.streamID, frame) {
		// The stream has left the scheduler: a RESET has ended both halves and taken
		// the CLOSE's place (Reset and endByPeerReset set closeDone), so there is
		// nothing to close and Close returns nil, as it does after a reset.
		return nil
	}
	return nil
}

// leaveIfEnded takes the stream out of the session once both halves of its end
// are done: this side's CLOSE acknowledged (closeDone, from finishSend) and the
// peer's CLOSE received (peerClosed, from endReceive). finishSend and endReceive
// both call it, so the second of them does the leaving. closeDone is also set by a
// RESET, whose exit has already set left, so only the two CLOSEs come through.
// teardown ends the grant debouncer and the queue's admission, and leaveSession
// gives back what the stream holds on the session. The queued messages stay readable
// and charged, to the peer's connection credit and to the session's budget, until
// they are read or the sweep finds them abandoned, and taking them then grants the
// peer its credit (recvQueue.leftSession). A retransmit of the peer's CLOSE from
// here on finds no stream, and handleClose answers it.
func (st *noiseStream) leaveIfEnded() {
	if !st.closeDone.Load() || !st.peerClosed.Load() {
		return
	}
	if !st.left.CompareAndSwap(false, true) {
		return
	}
	st.teardown()
	st.recvQ.leftSession()
	st.session.noteLeft(st.streamID, st.rtt.RTO())
	st.leaveSession()
}

// peerReopened takes a peer's OPEN for this stream's ID (handleOpen) as the news that
// the peer's stream under it has left, and reports whether this stream has gone too.
// That can only be true once both CLOSEs are out: the peer leaves on this side's CLOSE
// and the ACK of its own, so an OPEN from it says this side's CLOSE arrived, whose ACK
// must be lost or crossing. The window's entry for the CLOSE goes with the stream,
// giving the session's in-flight count back. Any earlier, the OPEN is a duplicate of
// the one that opened this stream, or one handleOpen weighs by its generation
// (supersededBy), and false leaves the stream as it is. Called by the session's
// readLoop only.
func (st *noiseStream) peerReopened() bool {
	if !st.closeQueued.Load() || !st.peerClosed.Load() {
		return false
	}
	if st.closeDone.CompareAndSwap(false, true) {
		st.sendWindow.ReleaseInFlight()
	}
	st.leaveIfEnded()
	return true
}

// enqueueDelivery hands one in-order message the sender charged credit for to
// the stream's consumer without blocking: the readLoop (handleData) calls it and
// must never wait on a stream's consumer. The message is admitted because its
// sender holds credit for it: the ceilings count messageCredit, the unit Send
// charges, against what that sender still has charged, so a sender honouring
// credit always fits, however far behind the consumers are, and handleData's
// ACK ahead of this call never acknowledges a message this drops. It returns
// false in two cases. The stream's queue has ended: an honest sender's CLOSE
// follows its last message in sequence, and past that a RESET has settled its
// credit (aether.ResetPayload). Or the sender is past a ceiling credit allows
// (receiveCeilings), which a peer ignoring credit reaches: that peer gets a
// flow-control RESET it reads as aether.ErrStreamOverrun and an abuse charge, and this
// stream's consumer reads what the queue holds and then the same error, so nothing
// acknowledged goes missing without its reader and its sender being told. The per-peer
// ceiling (flow.BoundsProfile.PeerMemoryCeiling) ends a stream the same way with no
// charge: connection credit is per session, so a sender with several sessions can meet
// it inside its credit.
func (st *noiseStream) enqueueDelivery(payload []byte) bool {
	s := st.session
	streamLimit, sessionLimit := st.receiveCeilings()
	s.makeQueueRoom(recvItemCost(payload), sessionLimit)
	switch st.recvQ.push(payload, streamLimit, sessionLimit) {
	case pushQueued:
		s.deliveryStats.recordDelivered(st.streamID)
		s.signalReceiveOverload()
		return true
	case pushEnded:
		return false
	case pushOverCredit:
		s.reportAbuse(abuse.ReasonFlowControlAbuse)
	}
	s.deliveryStats.recordDropped(st.streamID, len(payload))
	st.overrun.Store(true)
	_ = st.Reset(aether.ResetFlowCtrl)
	return false
}

// enqueueControl queues a control-plane frame for the stream's consumer
// (deliverToControl: WHOIS, RENDEZVOUS, NETWORK_CONFIG and application
// HANDSHAKE frames). They arrive as their own frame types and not as DATA, and
// Send charges credit only for what it sends as DATA, so no credit paces them
// and handleData's sequence numbers do not let a retransmit recover them; a peer
// that floods them meets a limit of two channels' worth of recvChCapacity, past
// which they are dropped and counted, and taking one later replenishes nothing.
func (st *noiseStream) enqueueControl(payload []byte) {
	s := st.session
	switch st.recvQ.pushUnmetered(payload, 2*recvChCapacity(st.streamID)) {
	case pushQueued:
		s.deliveryStats.recordDelivered(st.streamID)
	case pushOverCredit:
		s.deliveryStats.recordDropped(st.streamID, len(payload))
	}
}

// receiveCeilings returns the most this stream's queue may hold (metered
// credit) and the most the session's queues together may have charged to the
// peer's credit, both in messageCredit, before the peer is treated as ignoring
// credit. The stream's bound is the credit its sender holds, and this window is
// that credit: the opener's OpenStream builds it from its configuration and
// states it in OPEN, and the accepting handleOpen builds its own window from the
// stated credit, so both ends of a stream start at one credit, and the sender's
// grants come only from this side's consumption. The session's bound is the
// connection window's capacity, which is the peer's connection credit: both
// sides build it from one bounds profile (flow.CurrentBounds), and the session
// refuses a peer on another profile (aether.WireVersionBounds).
func (st *noiseStream) receiveCeilings() (streamLimit, sessionLimit int64) {
	_, maximum := st.session.connWindow.ReceiveCeilings()
	return st.window.CurrentWindow(), maximum
}

// teardown releases per-stream resources that must not outlive the
// stream itself: the grant debouncer's timer goroutine and pending flush,
// the ACK engine's delayed-ACK timer, the retransmit queue's entries (no frame
// of an ended stream is owed a retransmit, and reliabilityTick, working from its
// snapshot, would otherwise hand them on; a frame the write loop records after
// this is kept off a later stream by queueRetransmit), the FEC state's memory and
// the receive queue's admission (recvQ.end). Idempotent; safe to call
// from every termination path (leaveIfEnded, Reset, handleReset, the stream
// GC sweep through Reset) and from discardUnpublished, for a stream
// createStream built and never put in s.streams.
func (st *noiseStream) teardown() {
	if st.grantDebouncer != nil {
		st.grantDebouncer.Close()
	}
	if st.retransmitQ != nil {
		st.retransmitQ.Clear()
	}
	if st.ackEngine != nil {
		st.ackEngine.Stop()
	}
	if st.fec != nil {
		st.session.fecEvictedLeft.Add(st.fec.Release())
	}
	// End delivery: what the readLoop dispatches from now on is not queued
	// (enqueueDelivery returns false); what recvQ holds stays readable. The nil
	// guard covers a stream built outside createStream.
	if st.recvQ != nil {
		st.recvQ.end()
	}
}

// closeRecvOnce ends the stream's receive side exactly once: it closes
// recvDone, on which Receive returns what recvQ still holds and then io.EOF.
// Every termination path calls it (endReceive, handleReset, Reset, the
// stream GC through Reset), from the readLoop and from application
// goroutines, so recvOnce keeps the close idempotent.
func (st *noiseStream) closeRecvOnce() {
	st.recvOnce.Do(func() {
		close(st.recvDone)
	})
}

// Reset ends both halves of the stream with a RESET to the peer. A stream that
// has already left the session (left) has no peer stream to reset, and a frame
// would reach whatever stream now has the ID, so Reset writes nothing and returns
// nil; what it does for such a stream is grant its sender the credit of messages
// its consumer has now said it will not read (recvQueue.releaseCharge), which
// the sweep would otherwise hold for the idle timeout. They stay readable.
func (st *noiseStream) Reset(reason aether.ResetReason) error {
	if !st.left.CompareAndSwap(false, true) {
		st.session.grantConnCredit(st.recvQ.releaseCharge())
		return nil
	}
	st.state.Transition(aether.EventSendReset)
	// The RESET ends the send side: no CLOSE follows it (finishSend).
	st.closeSent.Store(true)
	st.closeDone.Store(true)
	p := st.settleLocalReset(reason)
	p.Incarnation = st.incarnation
	// Send the wire RESET first, then release the local state: teardown, the
	// s.streams entry (when it is this stream, not a later one on the same
	// ID), the credit reservation, the scheduler and stream GC registrations
	// (releaseStream) and the receive side (closeRecvOnce), the set
	// handleReset releases for a peer-initiated RESET. The stream leaves the
	// scheduler before the stream charges Sends made after the settlement are
	// released (leaveSchedulerThenSettle). The stream GC's sweep
	// and CloseWithError's acceptor drain call Reset for a stream still in
	// s.streams, and createStream counts every entry against
	// MaxConcurrentStreams, so a Reset that left the entry or the GC
	// registration behind would hold a slot and be reset again by the sweep.
	// The receive queue keeps its messages, readable and in the session's
	// budget, until they are read, makeQueueRoom needs the room or
	// sweepEndedQueues finds the queue abandoned (trackEnded). The RESET is
	// written again until the peer acknowledges it (writeReset), and the ID opens
	// locally only after that.
	err := st.session.writeReset(st.streamID, p, st.resetRTO())
	st.teardown()
	st.session.mu.Lock()
	if cur, ok := st.session.streams[st.streamID]; ok && cur == st {
		delete(st.session.streams, st.streamID)
	}
	st.session.mu.Unlock()
	st.leaveSchedulerThenSettle()
	st.releaseReservation()
	st.session.trackEnded(st.recvQ)
	st.closeRecvOnce()
	return err
}

// settleLocalReset stops what the RESET's counts describe and returns the
// statement, the writer's half of aether.ResetPayload: the queue's grants stop
// (peerEnded), the stream window's charge and what it still held are stated, and
// every byte this stream's Sends still have charged on the connection comes back
// here (settleCharges), since this side cannot tell what reached the peer. The peer
// corrects for the grants this crossed (handleReset, ConnWindow.Withhold). If the
// peer has reset the stream too, its RESET finds the count this leaves in
// resetGrants.
func (st *noiseStream) settleLocalReset(reason aether.ResetReason) aether.ResetPayload {
	p := aether.ResetPayload{Reason: reason}
	granted := st.recvQ.peerEnded()
	p.Consumed = uint64(granted)
	if st.window != nil {
		charged, released, held, _ := st.settleCharges()
		p.Charged, p.Released = uint64(charged), uint64(released)
		if st.session.connWindow != nil {
			st.session.connWindow.ReleaseUnsent(held)
		}
	}
	st.session.noteResetGrants(st.streamID, granted, st.incarnation)
	return p
}

// settlePeerReset is the reader's half: the peer's RESET has ended the stream.
// Of what this stream's Sends still have charged on the connection (settleCharges),
// it takes back what the peer's Consumed does not cover of all they charged there:
// the grants for Consumed are on their way or have come, and
// taking those bytes back as well would return them twice. And what this side
// granted past what the peer's grants had returned at its RESET (granted, from this
// side's peerEnded), the peer has taken back already, so it comes off this side's
// later grants. A statement that cannot be true, a release above the charge, is
// charged to the peer and withholds nothing. Neither count is read as credit this
// side has: a peer that overstates Consumed holds back only its own grants' worth of
// this side's sends, which it could do by not granting, and one that understates
// anything hands this side credit its own ceilings still hold it to.
func (st *noiseStream) settlePeerReset(p aether.ResetPayload, granted int64) {
	if st.window != nil && st.session.connWindow != nil {
		_, _, held, connCharged := st.settleCharges()
		st.session.connWindow.ReleaseUnsent(chargeNotCovered(connCharged, held, p.Consumed))
	}
	st.session.withholdGranted(granted, p)
}

// chargeNotCovered returns what a stream that charged charged, with outstanding
// bytes no grant has returned yet, takes back when grants up to consumed will
// still arrive: charged-consumed, within 0 and outstanding.
func chargeNotCovered(charged, outstanding int64, consumed uint64) int64 {
	if consumed >= uint64(charged) {
		return 0
	}
	if rest := charged - int64(consumed); rest < outstanding {
		return rest
	}
	return outstanding
}

// typedEnd is the error a stream's end owes its reader and sender when it is
// not an ordinary one: aether.ErrStreamRefused when the peer refused the stream
// (refusedByPeer), aether.ErrStreamOverrun when a RESET ended it for a sender
// past the receiver's ceilings (overrun) or this side threw unread messages away
// (recvQueue.discard). nil otherwise.
func (st *noiseStream) typedEnd() error {
	switch {
	case st.refusedByPeer.Load():
		return fmt.Errorf("stream %d: %w", st.streamID, aether.ErrStreamRefused)
	case st.overrun.Load(), st.recvQ != nil && st.recvQ.discardedMessages():
		return fmt.Errorf("stream %d: %w", st.streamID, aether.ErrStreamOverrun)
	}
	return nil
}

// cannotSend is Send's error for a stream whose state refuses sends: its
// typedEnd, or an untyped refusal for a stream that is simply closed.
func (st *noiseStream) cannotSend() error {
	if err := st.typedEnd(); err != nil {
		return err
	}
	return fmt.Errorf("stream %d: cannot send", st.streamID)
}

// leaveSession takes a stream that has ended on both CLOSEs out of s.streams if
// this stream object is the one there, then gives back what it holds on the
// session: its credit reservation, its scheduler and stream GC registrations,
// and, through trackEnded, its unread queue to the sweep. It returns no
// connection credit and nothing to the in-flight counter: its send window emptied
// on the ACK of its CLOSE, so every byte it charged has been acknowledged, which
// means the peer's receive window handed it to the peer's queue ahead of that CLOSE
// or its reassembly gave it back (reassemble), and the peer's grants return it as
// that queue is read or swept. The identity check keeps a call after another exit
// has removed it and a new stream has taken the ID from touching anything.
func (st *noiseStream) leaveSession() {
	s := st.session
	s.mu.Lock()
	cur, ok := s.streams[st.streamID]
	if !ok || cur != st {
		s.mu.Unlock()
		return
	}
	delete(s.streams, st.streamID)
	s.mu.Unlock()
	st.releaseReservation()
	s.releaseStream(st.streamID)
	s.trackEnded(st.recvQ)
}

// leaveSchedulerThenSettle is the end of a RESET's exit (Reset, endByPeerReset) once
// the stream is out of s.streams and its credit settled: it takes the stream out of the
// scheduler and the stream GC (releaseStream), then gives back what the stream still
// holds (releaseInFlight). In that order a Send already past its state check
// (sendAdmitted) either queued its frame before the scheduler let the stream go, and
// its frame is in the send window releaseInFlight empties, or meets the scheduler's
// refusal (sendSingleFrame); its connection charge is the settlement's when it was
// recorded first and the Send's own otherwise (commitConnCharge). The other order
// would let a Send's frame enter the send window after releaseInFlight and queue
// before releaseStream, whose drop of the frame no release would follow, keeping its
// in-flight count for the session's life.
func (st *noiseStream) leaveSchedulerThenSettle() {
	if hook := st.beforeSchedulerExit.Load(); hook != nil {
		(*hook)()
	}
	st.session.releaseStream(st.streamID)
	st.releaseInFlight()
}

// releaseInFlight settles what a stream ended by a RESET still holds once it is
// out of session.streams and the scheduler (leaveSchedulerThenSettle), and what a
// Send charged on a stream the scheduler refused (sendSingleFrame). It gives the
// session's in-flight byte counter back every frame this stream's SendWindow holds:
// handleACK looks the stream up there and returns when it is absent, so after the
// removal no ACK can take these entries out of the window, and a charge left in the
// counter would hold that much of the congestion window against every later send on
// the session (the write loop's CanSend gate and handleACK's OnAckWithPipe read the
// counter).
//
// The credit: once the stream's credit is settled, what the stream window holds was
// charged by Sends past the settlement, each of which returns its own connection
// charge (commitConnCharge), so only the stream window is emptied. Before the
// settlement it leaves the credit to it when the stream has left s.streams, since
// every exit that takes it out settles it (Reset before, endByPeerReset just after);
// a stream the scheduler let go while s.streams still holds it has no settlement to
// come, so it settles here, returning to the connection window what the stream's
// Sends charged there and no grant has returned. Nil guards cover a stream built
// outside createStream. Idempotent: both windows are empty of this stream after the
// first call that finds it settled.
func (st *noiseStream) releaseInFlight() {
	if st.sendWindow != nil {
		st.sendWindow.ReleaseInFlight()
	}
	if st.window == nil || st.session == nil || st.session.connWindow == nil {
		return
	}
	st.chargeMu.Lock()
	settled := st.connSettled
	st.chargeMu.Unlock()
	if settled {
		st.window.ReleaseAll()
		return
	}
	if holdsSelf(st) {
		_, _, held, _ := st.settleCharges()
		st.session.connWindow.ReleaseUnsent(held)
	}
}

// holdsSelf reports whether the session's s.streams holds st itself under its ID.
func holdsSelf(st *noiseStream) bool {
	s := st.session
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.streams[st.streamID]
	return ok && cur == st
}

// commitConnCharge records n bytes a Send has just charged to the connection window
// for this stream (sendStreamCharged) and reports true, or reports false once the
// stream's credit is settled (settleCharges), which counted only what was recorded
// before it: the Send then gives the charge back itself.
func (st *noiseStream) commitConnCharge(n int64) bool {
	st.chargeMu.Lock()
	defer st.chargeMu.Unlock()
	if st.connSettled {
		return false
	}
	st.connCharged += n
	return true
}

// returnCharge gives back n bytes a Send charged to both windows, recorded
// (commitConnCharge) and did not queue (sendStreamCharged's failures past its
// connection charge), unless the settlement has run: it counted them among
// connCharged and took the stream charge with ReleaseAllCharged, so a second release
// would hand the connection window bytes another stream still holds.
func (st *noiseStream) returnCharge(n int64) {
	st.chargeMu.Lock()
	defer st.chargeMu.Unlock()
	if st.connSettled {
		return
	}
	st.connCharged -= n
	st.window.ReleaseUnsent(n)
	st.session.connWindow.ReleaseUnsent(n)
}

// settleCharges ends the stream's credit, once: it releases what the stream window
// holds and reports the window's charge and that release (ReleaseAllCharged, one
// read, the RESET's statement in settleLocalReset), what this stream's Sends charged
// to the connection window (connCharged) and held, the part of that no grant has
// returned. Grants come back for what the stream window charged; charged minus
// released is what they returned, so held is connCharged less that, from 0 to
// connCharged. A stream charge whose Send has not charged the connection yet is in
// released and not in connCharged, and is not returned to the connection window: that
// Send finds the record closed (connSettled) and returns its own connection charge. A
// second call releases what the window holds again and reports held and connCharged 0.
// settleLocalReset, settlePeerReset and releaseInFlight call it; the caller returns
// held, or its part the peer's statement does not cover, to the connection window.
func (st *noiseStream) settleCharges() (charged, released, held, connCharged int64) {
	st.chargeMu.Lock()
	defer st.chargeMu.Unlock()
	released, charged = st.window.ReleaseAllCharged()
	if st.connSettled {
		return charged, released, 0, 0
	}
	st.connSettled = true
	connCharged = st.connCharged
	held = connCharged - (charged - released)
	if held < 0 {
		held = 0
	}
	return charged, released, held, connCharged
}

// autoTune is the session's tuning step for this stream (autoTuneWindows, from
// reliabilityTick): the window may shrink and grow back, never past the credit
// createStream reserved for the stream on the session's ledger (reserved). The
// window is this side's send credit, which only the peer's grants return, and
// this side's grant accounting and queue ceiling (receiveCeilings), which the
// reservation covers; growth past the reservation would be credit the peer
// never granted and the ledger never reserved. A stream that has left the
// session reads reserved 0 and does not grow.
func (st *noiseStream) autoTune(rtt time.Duration) aether.AutoTuneResult {
	return aether.AutoTuneWindowWithin(st.window, rtt, st.reserved.Load())
}

func (st *noiseStream) SetPriority(weight uint8, dependency uint64) {
	st.session.sched.SetWeight(st.streamID, weight)
}

// AvailableCredit exposes the current send-side flow-control credit for
// this stream. Used by upper layers (gossip) to self-throttle against
// a near-empty window.
func (st *noiseStream) AvailableCredit() int64 {
	return st.window.Available()
}

// Compile-time interface check
var _ aether.Stream = (*noiseStream)(nil)
