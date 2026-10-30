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
	// recvCh holds the whole messages deliverLoop has handed to the
	// application (and the remainder handleClose hands over directly);
	// Receive reads it. It is never closed: its end is recvDone, which
	// closeRecvOnce closes exactly once (recvOnce) and Receive selects on,
	// draining what recvCh still holds before it returns io.EOF. A close of
	// recvCh would race deliverLoop's send into it, since closeRecvOnce runs
	// on the readLoop (handleClose, handleReset) and on application
	// goroutines (Reset) while deliverLoop runs on its own. recvDone is made
	// in createStream with recvCh; a stream built outside createStream has
	// neither recvDone nor deliverCh, and closeRecvOnce closes its recvCh
	// instead.
	recvCh   chan []byte
	recvDone chan struct{}
	recvOnce sync.Once

	// lastRTOBackoffAt is the last time reliabilityTick applied an RTO
	// backoff for this stream, which bounds the backoff to once per RTO
	// interval (RFC 6298 §5.5 — one doubling per timeout event) rather than
	// once per retransmitted frame. Written and read only from the single
	// reliabilityTick goroutine, so no lock is needed.
	lastRTOBackoffAt time.Time

	// deliverCh carries each in-order payload from the readLoop (handleData,
	// handleImplicitOpen and deliverToStream, through enqueueDelivery) to this
	// stream's deliverLoop, which performs the send into recvCh with its
	// bounded backpressure off the readLoop, so one slow consumer cannot stall
	// the readLoop that drains the noiseConn inbox for every stream. Buffered
	// at recvChCapacity(streamID), which with recvCh gives two buffers before
	// any drop; one producer and one consumer keep the order into recvCh. It
	// is never closed: its end is deliverDone, which teardown closes exactly
	// once (deliverOnce); enqueueDelivery and deliverLoop select on it. A
	// close of deliverCh would race enqueueDelivery's send, since teardown
	// runs on application goroutines (Close, Reset), the stream GC and
	// CloseWithError while the readLoop is still dispatching DATA for the
	// stream. Both are made in createStream, which starts deliverLoop.
	deliverCh   chan []byte
	deliverDone chan struct{}
	deliverOnce sync.Once // closes deliverDone exactly once

	window *flow.StreamWindow

	// grantDebouncer coalesces stream-level WINDOW_UPDATE emissions driven
	// by application reads on this stream. When Receive() successfully
	// returns a payload to the application, it records the byte count in
	// the debouncer; the debouncer fires ReceiverConsume on a 25 ms
	// coalesce window (or immediately for bursts above 50% of the
	// stream's initial credit). Emission is driven by application-read,
	// not frame-receipt inside DeliverToRecvChWithSignals, so grants
	// advertise real application progress and a slow consumer
	// backpressures the sender.
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
	// between ticks — producing a ~100Hz tlpReset/log spam loop on
	// genuinely-stuck streams (observed live on app-orbtr-io IAD
	// under heavy Fly 6PN packet loss). One reset per second is still
	// aggressive enough to recover transient losses, while bounding the
	// log/CPU cost when the path is durably broken.
	lastStuckResetUnixNano atomic.Int64

	// fragBuf reassembles the fragments of this stream's messages. Touched by
	// the session's readLoop only (handleData, handleImplicitOpen,
	// handleClose), which hands each completed message to deliverCh.
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
		recvCh:      make(chan []byte, recvChCapacity(streamID)),
		recvDone:    make(chan struct{}),
		deliverCh:   make(chan []byte, recvChCapacity(streamID)),
		deliverDone: make(chan struct{}),
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
	// Wire the session-level in-flight-bytes counter into this stream's
	// SendWindow so Add/Ack mutations update the session-wide atomic
	// as a side effect, and the writeLoop's CUBIC CanSend gate becomes
	// a single atomic.Load instead of an O(streams) lock walk per send.
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
	// outgoing CompositeACKs via CACKHasWindowCredit. Eliminates a
	// separate WINDOW_UPDATE frame when the receiver has granted new
	// credit, and — because ACKs have their own cumulative retransmit
	// path — makes the grant delivery fundamentally loss-tolerant.
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
	// MUST be honoured: Library opens stream 1 (BidiRPC) with
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
	// Start the per-stream delivery goroutine. This is the only
	// return path for a newly-created stream — the duplicate-open path
	// returns `existing` (already has a worker) and cap-refused paths return
	// nil, so no stream ever gets a second worker or is left without one.
	go st.deliverLoop()
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

	// Flow control: consume stream + connection credit before sending.
	// Stream window may block waiting for WINDOW_UPDATE (up to ConsumeTimeout);
	// the connection window is non-blocking and errors immediately if exhausted.
	//
	// Both reservations must be released if any subsequent step fails —
	// otherwise the credit that we acquired but never delivered to the
	// wire leaks permanently (the peer never sees the bytes, so no
	// WINDOW_UPDATE will ever return them). Without the release we
	// reproduce the production-observed drain of a 1 MB stream window
	// to ~40 KB after 13 failed exchanges.
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

	// MTU-aware fragmentation (Task 12): split large payloads into MSS-sized
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
		// and will be released by the peer's WINDOW_UPDATE / ACK paths.
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

	// Assign SeqNo via send window (tracks for ACK/retransmit)
	seqNo := st.sendWindow.Add(frame)
	frame.SeqNo = seqNo

	// BBRv2 per-packet sample stamping. When the active controller is
	// BBR, mint a per-packet DeliveryRateSample and store it on the
	// SendEntry so OnAckSampled can recover the delivery context when
	// the matching ACK arrives. CUBIC sessions skip this entirely (the
	// type assertion fails) and entry.BBRSample stays nil — the ACK
	// handler nil-checks before dereferencing.
	if bbr, ok := st.session.congestion().(*congestion.BBRController); ok {
		if entry := st.sendWindow.GetEntry(seqNo); entry != nil {
			// Stamp the sample WITHOUT incrementing inflight (StampSample): the
			// writeLoop's congestion().OnSend at actual transmission is the
			// single authoritative on-wire inflight increment, and an increment
			// here too would double-count every frame and wedge BBR in Drain.
			sample := bbr.StampSample()
			entry.BBRSample = &sample
		}
	}

	// Enqueue for retransmission tracking. This comes before the scheduler
	// hand-off below on purpose: Enqueue fixes the entry's PayloadBytes from
	// len(frame.Payload) now, while the frame is still this goroutine's; from
	// the hand-off on, writeFrame may swap frame.Payload and frame.Length
	// (compression, encryption) under writeMu on the write loop, and the
	// queue reads only its own count.
	st.retransmitQ.Enqueue(frame)

	// FEC: add to encoder (may generate repair frames) — skip if disabled for this stream.
	// Stream's FECLevel selects which encoder to drive:
	//   FECInterleaved → interleaved XOR (2 burst losses)
	//   FECReedSolomon → RS(k,m) — recovers up to m losses per group (#8)
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

// Receive returns the next whole message deliverLoop (or handleClose's
// remainder) handed to recvCh. After closeRecvOnce has closed recvDone it
// still returns what recvCh holds, one message per call, and then io.EOF;
// the drain comes first because a select with both recvCh and recvDone ready
// picks either, and a message delivered before the CLOSE or RESET must not
// be lost behind the end. A stream built without recvDone reports the same
// end through its closed recvCh.
func (st *noiseStream) Receive(ctx context.Context) ([]byte, error) {
	consumed := func(data []byte) ([]byte, error) {
		// recvCh holds whole messages only: the readLoop reassembles
		// fragments (reassemble) before delivery. Record credit for the
		// message now that the application has received it, which is the
		// length the sender charged for it. This advances both the
		// stream-level and conn-level flow-control windows from the
		// application's perspective (true consume-driven grants).
		st.recordReceive(int64(len(data)))
		return data, nil
	}
	for {
		select {
		case data, ok := <-st.recvCh:
			if !ok {
				return nil, io.EOF
			}
			return consumed(data)
		case <-st.recvDone:
			select {
			case data, ok := <-st.recvCh:
				if !ok {
					return nil, io.EOF
				}
				return consumed(data)
			default:
				return nil, io.EOF
			}
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

func (st *noiseStream) Close() error {
	st.state.Transition(aether.EventSendFIN)
	st.teardown()
	frame := &aether.Frame{
		SenderID:   st.session.LocalPeerID(),
		ReceiverID: st.session.RemotePeerID(),
		StreamID:   st.streamID,
		Type:       aether.TypeCLOSE,
	}
	return st.session.writeFrame(frame)
}

// deliverLoop is the per-stream delivery goroutine: it takes each in-order
// payload the readLoop put on deliverCh and performs the send into recvCh,
// with the bounded backpressure DeliverToRecvChWithSignals applies, off the
// readLoop, so a slow application consumer holds only this goroutine while
// the readLoop keeps draining the noiseConn inbox and the inbound ACKs of
// every other stream. It returns when teardown closes deliverDone, after
// handing over what deliverCh still holds, each payload within the same
// bound, so a message that arrived before a CLOSE reaches recvCh ahead of
// the end Receive reports. Nothing closes recvCh while this goroutine runs
// (closeRecvOnce closes recvDone), so the send never meets a closed channel.
func (st *noiseStream) deliverLoop() {
	s := st.session
	deliver := func(payload []byte) {
		ok := DeliverToRecvChWithSignals(st.recvCh, payload, st.window, st.streamID, s.sendWindowUpdateAgnostic, s.SendCongestion, &s.deliveryStats)
		if !ok {
			if grant := s.connWindow.ReceiverConsume(int64(len(payload))); grant > 0 {
				s.sendWindowUpdate(aether.StreamConnectionLevel, uint64(grant))
			}
		}
	}
	for {
		select {
		case payload := <-st.deliverCh:
			deliver(payload)
		case <-st.deliverDone:
			for {
				select {
				case payload := <-st.deliverCh:
					deliver(payload)
				default:
					return
				}
			}
		}
	}
}

// enqueueDelivery hands one in-order payload to deliverLoop without
// blocking: the readLoop (handleData, handleImplicitOpen, deliverToStream)
// calls it and must never wait on a stream's consumer. It returns false when
// it does not hand the payload over: deliverCh is full (deliverCh and recvCh
// both saturated, a sustained overload), in which case the payload is
// dropped with the accounting DeliverToRecvChWithSignals' drop path uses
// (backpressure and dropped stats, stream-window grant, CONGESTION signal) so
// the sender is throttled and never stalls on lost credit; or the stream has
// been torn down (deliverDone closed), in which case the payload is dropped
// without stream-level accounting, since the stream's window ends with the
// RESET or CLOSE teardown sent or received. The caller grants conn-level
// credit on false either way, as the conn window outlives the stream.
// deliverCh is never closed, so the send cannot meet a closed channel;
// selecting on deliverDone is what keeps a torn-down stream from filling its
// buffer and then signalling congestion for bytes no one will read.
func (st *noiseStream) enqueueDelivery(payload []byte) bool {
	select {
	case st.deliverCh <- payload:
		return true
	case <-st.deliverDone:
		return false
	default:
	}
	s := st.session
	s.deliveryStats.recordBackpressure(st.streamID)
	dropGrantCredit(st.window, payload, st.streamID, s.sendWindowUpdateAgnostic)
	s.deliveryStats.recordDropped(st.streamID, len(payload))
	// deliverCh full == sustained overload tier (matches deliver.go drop path).
	_ = s.SendCongestion(aether.CongestionPayload{Reason: aether.CongestionDownstream, Severity: 80, BackoffMs: 500})
	return false
}

// teardown releases per-stream resources that must not outlive the
// stream itself — currently the grant debouncer's timer goroutine +
// pending-flush. Idempotent; safe to call from every termination path
// (Close, Reset, handleClose, handleReset, streamGC sweep).
func (st *noiseStream) teardown() {
	if st.grantDebouncer != nil {
		st.grantDebouncer.Close()
	}
	// End delivery: closing deliverDone makes deliverLoop hand over what
	// deliverCh still holds and return, and makes enqueueDelivery drop what
	// the readLoop dispatches from now on. deliverCh is not closed because the
	// readLoop may be sending into it at this moment (enqueueDelivery). The
	// nil guard covers a stream built outside createStream, which has no
	// deliverCh and no deliverLoop.
	if st.deliverDone != nil {
		st.deliverOnce.Do(func() { close(st.deliverDone) })
	}
}

// closeRecvOnce ends the stream's receive side exactly once: it closes
// recvDone, on which Receive returns what recvCh still holds and then io.EOF.
// Every termination path calls it (handleClose, handleReset, Reset, the
// stream GC through Reset), from the readLoop and from application
// goroutines, so recvOnce keeps the close idempotent. recvCh itself is never
// closed here because deliverLoop may be sending into it on another
// goroutine; a stream built without recvDone (outside createStream, with no
// deliverLoop) has its recvCh closed instead, which Receive reads as the same
// end.
func (st *noiseStream) closeRecvOnce() {
	st.recvOnce.Do(func() {
		if st.recvDone != nil {
			close(st.recvDone)
			return
		}
		close(st.recvCh)
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
	st.session.mu.Lock()
	if _, ok := st.session.streams[st.streamID]; ok {
		delete(st.session.streams, st.streamID)
	}
	st.session.mu.Unlock()
	st.session.releaseStream(st.streamID)
	st.closeRecvOnce()
	return err
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
