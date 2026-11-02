/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"context"
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

// noiseStream is a single Aether stream over Noise-UDP with full reliability.
type noiseStream struct {
	streamID uint64
	config   aether.StreamConfig
	session  *NoiseSession
	state    *aether.StreamStateMachine
	// recvQ holds the whole in-order messages between the readLoop
	// (handleData, handleImplicitOpen, handleFECRepair and deliverToControl,
	// through enqueueDelivery and enqueueControl) and Receive. recvDone is the
	// end Receive selects on, draining what recvQ still holds before it
	// returns io.EOF; closeRecvOnce closes it exactly once (recvOnce), from the
	// readLoop (handleClose, handleReset) and from application goroutines
	// (Reset). Both are made in createStream.
	recvQ    *recvQueue
	recvDone chan struct{}
	recvOnce sync.Once

	// lastRTOBackoffAt is the last time reliabilityTick applied an RTO
	// backoff for this stream, which bounds the backoff to once per RTO
	// interval (RFC 6298 §5.5 — one doubling per timeout event) rather than
	// once per retransmitted frame. Written and read only from the single
	// reliabilityTick goroutine, so no lock is needed.
	lastRTOBackoffAt time.Time

	window *flow.StreamWindow

	// grantDebouncer coalesces stream-level WINDOW_UPDATE emissions driven
	// by application reads on this stream. When Receive takes a metered
	// message it records the message's plaintext length (recordReceive), the
	// length Send charged; the debouncer calls ReceiverConsume after
	// GrantCoalesceWindow, or at once when the pending bytes reach
	// GrantImmediateFraction of the stream's initial credit. handleData's
	// receipt of a frame records nothing, so grants advertise what the
	// consumer took, a slow consumer backpressures the sender, and the
	// bytes waiting in recvQ stay charged to the sender, which is what
	// bounds recvQ.
	grantDebouncer *grantDebouncer

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
	// the session's readLoop only (handleData, handleImplicitOpen,
	// handleClose), which hands each completed message to recvQ.
	fragBuf *FragmentBuffer

	// generation is this stream object's number among the session's streams
	// (NoiseSession.streamGenerations), stamped on its fragments so the peer
	// tells them from fragments of an earlier stream that used the same ID.
	// Zero only for a stream built outside createStream, which then sends no
	// fragments.
	generation uint64

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
}

// createStream creates a new stream with full reliability infrastructure via Engine.
// When enforceRemoteCap is true, the admission check against MaxConcurrentStreams
// happens atomically under s.mu with the map insert — no TOCTOU race window
// where concurrent peer OPENs can exceed the cap. Returns nil and sends
// RESET(ResetRefused) when the cap is reached (peer-initiated paths only;
// locally-initiated OpenStream passes false).
func (s *NoiseSession) createStream(streamID uint64, cfg aether.StreamConfig, enforceRemoteCap bool) *noiseStream {
	// FEC group size selection. FEC is off by default: the FEC RECEIVE path
	// is not wired — the decoder is only ever fed repair shards (AddRepair),
	// never DATA (AddData), and DATA frames carry no group/index metadata —
	// so a group can never be reconstructed, and repair frames emitted by
	// default would spend 25-50% extra bandwidth with zero recovery benefit.
	// A caller opts in explicitly through cfg.FECLevel.
	// TODO: wire the receive path before any default emits parity.
	fecGroup := 0
	if cfg.FECLevel != 0 {
		// Caller explicitly opted in — map the level to a group size.
		switch reliability.FECLevel(cfg.FECLevel) {
		case reliability.FECNone:
			fecGroup = 0
		case reliability.FECBasicXOR:
			fecGroup = 4 // 25% overhead
		case reliability.FECInterleaved:
			fecGroup = 4 // 50% overhead (2 interleaved groups)
		}
	}
	// WindowSize 64: tracks Aether frame reordering (NOT UDP fragment reassembly).
	// Max in-flight per stream: gossip=2, RPC=3, keepalive=1, control=1.
	// 64 gives 32× headroom for gossip, 21× for RPC.
	eng := reliability.NewEngine(reliability.EngineConfig{
		StreamID:     streamID,
		Reliability:  cfg.Reliability,
		WindowSize:   64,
		MaxAge:       cfg.MaxAge,
		FECGroupSize: fecGroup,
	})
	st := &noiseStream{
		streamID:    streamID,
		config:      cfg,
		session:     s,
		state:       aether.NewStreamStateMachine(),
		recvQ:       newRecvQueue(&s.recvQueued),
		recvDone:    make(chan struct{}),
		window:      flow.NewStreamWindowWithCap(cfg.InitialCredit, cfg.MaxCredit),
		engine:      eng,
		fragBuf:     NewFragmentBuffer(),
		generation:  s.streamGenerations.Add(1),
		sendWindow:  eng.SendWin,
		recvWindow:  eng.RecvWin,
		retransmitQ: eng.RetransmitQ,
		rtt:         eng.RTT,
		replay:      eng.Replay,
		rack:        congestion.NewRACK(eng.RTT.SRTT()),
		tlp:         congestion.NewTLP(eng.RTT.SRTT()),
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
	// including releaseInFlight when the stream leaves s.streams, gives the
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
		s.sendCompositeACK(st, cack)
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
	if _, exists := s.streams[streamID]; exists {
		// Duplicate peer OPEN for an already-open stream — no new slot
		// needed; return the existing stream.
		existing := s.streams[streamID]
		s.mu.Unlock()
		return existing
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
			atomic.AddUint64(&s.streamRefused, 1)
			s.reportAbuse(abuse.ReasonStreamRefused)
			if enforceRemoteCap {
				// Peer-initiated: reply with RESET so the peer gives up;
				// no state created locally.
				payload := aether.EncodeReset(aether.ResetRefused)
				reset := &aether.Frame{
					SenderID:   s.LocalPeerID(),
					ReceiverID: s.RemotePeerID(),
					StreamID:   streamID,
					Type:       aether.TypeRESET,
					Length:     uint32(len(payload)),
					Payload:    payload,
				}
				s.writeFrame(reset)
			}
			return nil
		}
	}
	s.streams[streamID] = st
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
	return st
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
	if !st.state.CanSend() {
		return fmt.Errorf("stream %d: cannot send", st.streamID)
	}

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

	n := int64(len(data))

	// Flow control: consume stream + connection credit before sending, both in
	// the plaintext length n. Each window blocks waiting for a grant (up to
	// ConsumeTimeout) and then fails with ErrCreditExhausted.
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
	if err := st.window.Consume(ctx, n); err != nil {
		return fmt.Errorf("stream %d: %w", st.streamID, err)
	}
	if d := time.Since(perStreamStart); d >= streamSendBlockFloor {
		st.session.perStreamWindowWaitHist.Record(d)
	}
	// A stream that left while this Send waited for credit (releaseInFlight
	// wakes the wait) must not charge the connection window: nothing would ever
	// return bytes charged after that release.
	if !st.state.CanSend() {
		st.window.ReleaseUnsent(n)
		return fmt.Errorf("stream %d: cannot send", st.streamID)
	}
	streamCredited := true
	defer func() {
		if streamCredited {
			st.window.ReleaseUnsent(n)
		}
	}()

	connWaitStart := time.Now()
	if err := st.session.connWindow.Consume(ctx, n); err != nil {
		return fmt.Errorf("stream %d conn: %w", st.streamID, err)
	}
	if d := time.Since(connWaitStart); d >= streamSendBlockFloor {
		st.session.connWindowWaitHist.Record(d)
	}
	connCredited := true
	defer func() {
		if connCredited {
			st.session.connWindow.ReleaseUnsent(n)
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
	var fragments [][]byte
	if len(data) > maxPayload {
		var err error
		fragments, err = SplitMessage(st.session.fragmentBinding(st), st.messageIDs.Add(1), data, maxPayload)
		if err != nil {
			// A message past the fragment ceilings, or a session
			// that cannot fragment (no realm, no negotiated envelope). Fail
			// loudly instead of transmitting a silently-truncated message.
			// Returning here (before streamCredited/connCredited are cleared)
			// lets the deferred ReleaseUnsent guards return ALL consumed
			// credit, since nothing reached the wire.
			return fmt.Errorf("stream %d: %w", st.streamID, err)
		}
	}

	if fragments != nil {
		// Large payload — send as multiple fragments
		for _, frag := range fragments {
			if err := st.sendSingleFrame(ctx, frag, aether.FlagFRAGMENT); err != nil {
				return err
			}
		}
		// All fragments accepted — credit is now legitimately outstanding
		// and returns through the peer's grants as its consumer reads
		// (WINDOW_UPDATE, the CompositeACK piggyback).
		streamCredited = false
		connCredited = false
		recordPostCredit()
		return nil
	}

	// Small payload — send as single frame (existing fast path)
	if err := st.sendSingleFrame(ctx, data, 0); err != nil {
		return err
	}
	streamCredited = false
	connCredited = false
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

// sendSingleFrame sends one frame: a whole small message (extra 0) or one
// fragment envelope (extra aether.FlagFRAGMENT).
func (st *noiseStream) sendSingleFrame(ctx context.Context, data []byte, extra aether.FrameFlags) error {
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

	// FEC: add to encoder (may generate repair frames) — skip if disabled for this stream.
	// Stream's FECLevel selects which encoder to drive:
	//   FECInterleaved → interleaved XOR (2 burst losses)
	//   FECReedSolomon → RS(k,m) — recovers up to m losses per group
	//   FECBasicXOR / 0 → single-loss XOR (default)
	if st.session.opts.FEC && st.engine.FEC != nil {
		switch reliability.FECLevel(st.config.FECLevel) {
		case reliability.FECInterleaved:
			repairs := st.session.interleavedEncoder.Add(data)
			for _, repair := range repairs {
				repair.StreamID = st.streamID
				repair.SenderID = st.session.LocalPeerID()
				repair.ReceiverID = st.session.RemotePeerID()
				st.session.sched.Enqueue(st.streamID, repair)
			}
		case reliability.FECReedSolomon:
			if st.session.rsEncoder == nil {
				break
			}
			repairs := st.session.rsEncoder.Add(data)
			for _, repair := range repairs {
				repair.StreamID = st.streamID
				repair.SenderID = st.session.LocalPeerID()
				repair.ReceiverID = st.session.RemotePeerID()
				st.session.sched.Enqueue(st.streamID, repair)
			}
		default:
			if repair := st.session.fecEncoder.Add(data); repair != nil {
				repair.StreamID = st.streamID
				repair.SenderID = st.session.LocalPeerID()
				repair.ReceiverID = st.session.RemotePeerID()
				st.session.sched.Enqueue(st.streamID, repair)
			}
		}
	}

	// Enqueue via scheduler for priority-ordered sending
	st.session.sched.Enqueue(st.streamID, frame)
	return nil
}

// Receive returns the next whole message from recvQ. After closeRecvOnce has
// closed recvDone it still returns what recvQ holds, one message per call, and
// then io.EOF, so a message admitted before the CLOSE or RESET is not lost
// behind the end. Taking a metered message records it as consumed, which is
// what replenishes the sender's stream and connection credit: until then its
// bytes stay charged, and that charge is what bounds the queue.
func (st *noiseStream) Receive(ctx context.Context) ([]byte, error) {
	take := func() ([]byte, bool) {
		data, credited, ok := st.recvQ.pop()
		if ok && credited {
			// recvQ holds whole messages only: the readLoop reassembles
			// fragments (reassemble) before delivery, so this is the length
			// the sender charged for the message.
			st.recordReceive(int64(len(data)))
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
			return nil, io.EOF
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-st.session.CloseSignal():
			return nil, fmt.Errorf("session closed")
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
// windows, since the application will never read them. Called by the session's
// readLoop only.
func (st *noiseStream) reassemble(d reliability.RecvDelivery) (payload []byte, ok bool) {
	if !d.Marked {
		return d.Payload, true
	}
	s := st.session
	msg, released, err := st.fragBuf.Add(s.fragRecv, st.streamID, d.Payload)
	if released > 0 {
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

// Close ends the local send side. The receive side stays up while the peer may
// still send: its CLOSE reaches handleClose, which drains the receive window
// and ends the stream, and until then what arrives is admitted for Receive and
// its grants still flow. When the peer's side has already ended there is nothing
// more to admit, so the stream's resources go now and its unread messages leave
// the session's budget, since this caller is done with them.
func (st *noiseStream) Close() error {
	st.state.Transition(aether.EventSendFIN)
	if !st.state.IsOpen() {
		st.teardown()
		st.recvQ.detach(false)
	}
	frame := &aether.Frame{
		SenderID:   st.session.LocalPeerID(),
		ReceiverID: st.session.RemotePeerID(),
		StreamID:   st.streamID,
		Type:       aether.TypeCLOSE,
	}
	return st.session.writeFrame(frame)
}

// enqueueDelivery hands one in-order message the sender charged credit for to
// the stream's consumer without blocking: the readLoop (handleData,
// handleImplicitOpen, handleFECRepair through deliverToStream) calls it and
// must never wait on a stream's consumer. The message is admitted because its
// sender holds credit for it, so a sender honouring credit always fits, however
// far behind the consumer is, and handleData's ACK ahead of this call never
// acknowledges a message this drops. It returns false in two cases, and neither
// owes the sender a grant, since its connection credit returns from its own
// side when it learns the stream ended (releaseInFlight): the stream has ended
// here; or the sender is past every ceiling credit allows (receiveCeilings), which
// only a peer ignoring credit reaches. That peer gets a flow-control RESET and an
// abuse charge, and what it had queued is freed. The sender is never told to
// back off for bytes lost here, since none are.
func (st *noiseStream) enqueueDelivery(payload []byte) bool {
	s := st.session
	streamLimit, sessionLimit := st.receiveCeilings()
	switch st.recvQ.push(payload, streamLimit, sessionLimit) {
	case pushQueued:
		s.deliveryStats.recordDelivered(st.streamID)
		s.signalReceiveOverload()
		return true
	case pushEnded:
		return false
	}
	s.deliveryStats.recordDropped(st.streamID, len(payload))
	s.reportAbuse(abuse.ReasonFlowControlAbuse)
	st.recvQ.detach(true)
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

// receiveCeilings returns the most this stream's queue may hold (metered bytes)
// and the most the session's queues together may hold (queued cost) before
// the peer is treated as ignoring credit. The queue's real bound is the sender's
// credit, and OPEN does not carry the sender's initial credit
// (StreamConfig.InitialCredit stays local to each side, and handleOpen builds
// this window from the default), so this side's own window cannot be used as
// a limit: a sender that opened with more credit than this side's window would be
// refused for honouring its own. The connection window is the bound both sides
// share (NewConnWindow(0) on each), and every byte a sender queues here has been
// charged to it too, so its initial size holds any honest stream, and its capacity
// holds the session with room for departure skew (ConnWindow.ReceiveCeilings).
// TODO: when OPEN carries the opener's initial credit, narrow streamLimit to
// the credit this stream's sender actually holds.
func (st *noiseStream) receiveCeilings() (streamLimit, sessionLimit int64) {
	initial, maximum := st.session.connWindow.ReceiveCeilings()
	streamLimit = st.window.CurrentWindow()
	if streamLimit < initial {
		streamLimit = initial
	}
	return streamLimit, maximum
}

// teardown releases per-stream resources that must not outlive the
// stream itself: the grant debouncer's timer goroutine and pending flush,
// and the receive queue's admission (recvQ.end). Idempotent; safe to call
// from every termination path (Close, Reset, handleClose, handleReset,
// streamGC sweep).
func (st *noiseStream) teardown() {
	if st.grantDebouncer != nil {
		st.grantDebouncer.Close()
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
// Every termination path calls it (handleClose, handleReset, Reset, the
// stream GC through Reset), from the readLoop and from application
// goroutines, so recvOnce keeps the close idempotent.
func (st *noiseStream) closeRecvOnce() {
	st.recvOnce.Do(func() {
		close(st.recvDone)
	})
}

func (st *noiseStream) Reset(reason aether.ResetReason) error {
	st.state.Transition(aether.EventSendReset)
	payload := aether.EncodeReset(reason)
	frame := &aether.Frame{
		SenderID:   st.session.LocalPeerID(),
		ReceiverID: st.session.RemotePeerID(),
		StreamID:   st.streamID,
		Type:       aether.TypeRESET,
		Length:     uint32(len(payload)),
		Payload:    payload,
	}
	// Send the wire RESET first, then release the local state: teardown, the
	// s.streams entry, the scheduler and stream GC registrations
	// (releaseStream) and the receive side (closeRecvOnce), the set
	// handleReset releases for a peer-initiated RESET. The stream GC's sweep
	// and CloseWithError's acceptor drain call Reset for a stream still in
	// s.streams, and createStream counts every entry against
	// MaxConcurrentStreams, so a Reset that left the entry or the GC
	// registration behind would hold a slot and be reset again by the sweep.
	err := st.session.writeFrame(frame)
	st.teardown()
	st.recvQ.detach(false)
	st.session.mu.Lock()
	if _, ok := st.session.streams[st.streamID]; ok {
		delete(st.session.streams, st.streamID)
	}
	st.session.mu.Unlock()
	st.releaseInFlight()
	st.session.releaseStream(st.streamID)
	st.closeRecvOnce()
	return err
}

// releaseInFlight gives the session's in-flight byte counter back every
// frame this stream's SendWindow still holds. Called once the stream is out
// of session.streams (Reset here; handleClose and handleReset on the
// readLoop): handleACK looks the stream up there and returns when it is
// absent, so after the removal no ACK can take these entries out of the
// window, and a charge left in the counter would hold that much of the
// congestion window against every later send on the session (the write
// loop's CanSend gate and handleACK's OnAckWithPipe read the counter).
//
// It also gives the connection window every byte this stream still has
// charged, which is every byte no grant has returned: frames in the scheduler
// or on the path, frames the peer's receive window or reassembly holds, and
// messages in its queue. The peer's side cannot return them all, since it does
// not see what was lost on the path and a stream's end stops its Receive
// counting, and credit left charged would be stranded for the session's life.
// A grant already on its way for one of these bytes is the skew
// ConnWindow.ReceiveCeilings leaves room for; ApplyUpdate caps it at what is
// outstanding. Nil guards cover a stream built outside createStream. Idempotent:
// both windows are empty of this stream after the first call.
func (st *noiseStream) releaseInFlight() {
	if st.sendWindow != nil {
		st.sendWindow.ReleaseInFlight()
	}
	if st.window != nil && st.session != nil && st.session.connWindow != nil {
		st.session.connWindow.ReleaseUnsent(st.window.ReleaseAll())
	}
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
