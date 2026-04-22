//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package adapter

import (
	"context"
	"fmt"
	"io"
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

// noiseStream is a single Aether stream over Noise-UDP with full reliability.
type noiseStream struct {
	streamID uint64
	config   aether.StreamConfig
	session  *NoiseSession
	state    *aether.StreamStateMachine
	recvCh   chan []byte
	window   *flow.StreamWindow

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
	fragBuf     *FragmentBuffer              // reassembly buffer for fragmented payloads
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
}

// createStream creates a new stream with full reliability infrastructure via Engine.
// When enforceRemoteCap is true, the admission check against MaxConcurrentStreams
// happens atomically under s.mu with the map insert — no TOCTOU race window
// where concurrent peer OPENs can exceed the cap. Returns nil and sends
// RESET(ResetRefused) when the cap is reached (peer-initiated paths only;
// locally-initiated OpenStream passes false).
func (s *NoiseSession) createStream(streamID uint64, cfg aether.StreamConfig, enforceRemoteCap bool) *noiseStream {
	// FEC group size selection (priority order):
	// 1. Explicit cfg.FECLevel from StreamConfig (caller controls)
	// 2. Stream ID defaults: gossip/keepalive/control = disabled, others = group 4
	fecGroup := 4
	if cfg.FECLevel != 0 {
		// Caller specified FEC level — map to group size
		switch reliability.FECLevel(cfg.FECLevel) {
		case reliability.FECNone:
			fecGroup = 0
		case reliability.FECBasicXOR:
			fecGroup = 4 // 25% overhead
		case reliability.FECInterleaved:
			fecGroup = 4 // 50% overhead (2 interleaved groups)
		}
	} else {
		// Default: disable FEC on non-throughput streams (app-level recovery)
		switch streamID {
		case s.layout.Keepalive, s.layout.Control:
			fecGroup = 0
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
		window:      flow.NewStreamWindowWithCap(cfg.InitialCredit, cfg.MaxCredit),
		engine:      eng,
		fragBuf:     NewFragmentBuffer(),
		sendWindow:  eng.SendWin,
		recvWindow:  eng.RecvWin,
		retransmitQ: eng.RetransmitQ,
		rtt:         eng.RTT,
		replay:      eng.Replay,
	}
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
	if enforceRemoteCap {
		cap := s.opts.MaxConcurrentStreams
		if cap <= 0 {
			cap = aether.DefaultMaxConcurrentStreams
		}
		if len(s.streams) >= cap {
			s.mu.Unlock()
			atomic.AddUint64(&s.streamRefused, 1)
			s.reportAbuse(abuse.ReasonStreamRefused)
			// Reply with RESET so the peer gives up; no state created locally.
			payload := aether.EncodeReset(aether.ResetRefused)
			reset := &aether.Frame{
				SenderID:   s.localPeerID,
				ReceiverID: s.remotePeerID,
				StreamID:   streamID,
				Type:       aether.TypeRESET,
				Length:     uint32(len(payload)),
				Payload:    payload,
			}
			s.writeFrame(reset)
			return nil
		}
	}
	s.streams[streamID] = st
	s.mu.Unlock()

	// Register with stream GC for idle timeout tracking
	s.streamGC.Register(streamID)

	s.sched.Register(streamID, cfg.Priority, cfg.Dependency)
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

	// Flow control: consume stream + connection credit before sending.
	// Stream window may block waiting for WINDOW_UPDATE (up to ConsumeTimeout);
	// the connection window is non-blocking and errors immediately if exhausted.
	if err := st.window.Consume(ctx, int64(len(data))); err != nil {
		return fmt.Errorf("stream %d: %w", st.streamID, err)
	}
	if err := st.session.connWindow.Consume(ctx, int64(len(data))); err != nil {
		return fmt.Errorf("stream %d conn: %w", st.streamID, err)
	}

	// MTU-aware fragmentation (Task 12): split large payloads into MSS-sized
	// fragments so each fragment is a single UDP packet (no IP fragmentation).
	// Lost fragments are individually retransmitted by the reliability engine.
	maxPayload := MSSToMaxPayload(st.session.pmtuProber.MSS())
	fragments := SplitPayload(data, maxPayload)

	if fragments != nil {
		// Large payload — send as multiple fragments
		for _, frag := range fragments {
			if err := st.sendSingleFrame(ctx, frag); err != nil {
				return err
			}
		}
		return nil
	}

	// Small payload — send as single frame (existing fast path)
	return st.sendSingleFrame(ctx, data)
}

// sendSingleFrame sends one frame (original small payload or one fragment).
func (st *noiseStream) sendSingleFrame(ctx context.Context, data []byte) error {
	frame := &aether.Frame{
		SenderID:   st.session.localPeerID,
		ReceiverID: st.session.remotePeerID,
		StreamID:   st.streamID,
		Type:       aether.TypeDATA,
		Flags:      aether.FlagANTIREPLAY, // enable anti-replay on all Noise-UDP frames
		Length:     uint32(len(data)),
		Payload:    data,
	}

	// Assign SeqNo via send window (tracks for ACK/retransmit)
	seqNo := st.sendWindow.Add(frame)
	frame.SeqNo = seqNo

	// BBRv2 per-packet sample stamping. When the active controller is
	// BBR, ask it to mint a per-packet DeliveryRateSample and store it on
	// the SendEntry for OnAckSampled to recover later. CUBIC ignores the
	// hook (interface assertion fails silently).
	if bbr, ok := st.session.congestion().(*congestion.BBRController); ok {
		if entry := st.sendWindow.GetEntry(seqNo); entry != nil {
			entry.BBRSample = bbr.OnSend(int64(frame.Length))
		}
	}

	// Enqueue for retransmission tracking
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
				repair.SenderID = st.session.localPeerID
				repair.ReceiverID = st.session.remotePeerID
				st.session.sched.Enqueue(st.streamID, repair)
			}
		case reliability.FECReedSolomon:
			if st.session.rsEncoder == nil {
				break
			}
			repairs := st.session.rsEncoder.Add(data)
			for _, repair := range repairs {
				repair.StreamID = st.streamID
				repair.SenderID = st.session.localPeerID
				repair.ReceiverID = st.session.remotePeerID
				st.session.sched.Enqueue(st.streamID, repair)
			}
		default:
			if repair := st.session.fecEncoder.Add(data); repair != nil {
				repair.StreamID = st.streamID
				repair.SenderID = st.session.localPeerID
				repair.ReceiverID = st.session.remotePeerID
				st.session.sched.Enqueue(st.streamID, repair)
			}
		}
	}

	// Enqueue via scheduler for priority-ordered sending
	st.session.sched.Enqueue(st.streamID, frame)
	return nil
}

func (st *noiseStream) Receive(ctx context.Context) ([]byte, error) {
	for {
		select {
		case data, ok := <-st.recvCh:
			if !ok {
				return nil, io.EOF
			}
			// Fragment reassembly: if the payload starts with the fragment
			// magic, buffer it and return the assembled payload only when
			// all fragments have arrived.
			if IsFragment(data) {
				// Record credit for the raw fragment bytes even if the
				// assembled payload isn't ready yet — the sender consumed
				// window credit to transmit them and must get it back as
				// the receiver progresses, not only on final reassembly.
				// Otherwise a multi-fragment payload would stall the
				// sender for the full reassembly span.
				st.recordReceive(int64(len(data)))
				// The receive channel does not carry the originating frame's
				// SeqNo, so pass 0 — the per-stream FragmentBuffer will use
				// its own monotonic counter to keep group keys unique.
				// Stream-scoped FragmentBuffer state prevents cross-stream
				// collisions; per-stream sequencing relies on the
				// reliability layer delivering frames in order.
				assembled, err := st.fragBuf.Add(st.streamID, 0, data)
				if err != nil {
					continue // skip corrupted fragment
				}
				if assembled == nil {
					continue // more fragments needed — loop back to recvCh
				}
				return assembled, nil
			}
			// Non-fragmented payload — record credit for the bytes now
			// that the application has received them. This advances both
			// the stream-level and conn-level flow-control windows from
			// the application's perspective (true consume-driven grants).
			st.recordReceive(int64(len(data)))
			return data, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-st.session.closed:
			return nil, fmt.Errorf("session closed")
		}
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

func (st *noiseStream) Close() error {
	st.state.Transition(aether.EventSendFIN)
	st.teardown()
	frame := &aether.Frame{
		SenderID:   st.session.localPeerID,
		ReceiverID: st.session.remotePeerID,
		StreamID:   st.streamID,
		Type:       aether.TypeCLOSE,
	}
	return st.session.writeFrame(frame)
}

// teardown releases per-stream resources that must not outlive the
// stream itself — currently the grant debouncer's timer goroutine +
// pending-flush. Idempotent; safe to call from every termination path
// (Close, Reset, handleClose, handleReset, streamGC sweep).
func (st *noiseStream) teardown() {
	if st.grantDebouncer != nil {
		st.grantDebouncer.Close()
	}
}

func (st *noiseStream) Reset(reason aether.ResetReason) error {
	st.state.Transition(aether.EventSendReset)
	payload := aether.EncodeReset(reason)
	frame := &aether.Frame{
		SenderID:   st.session.localPeerID,
		ReceiverID: st.session.remotePeerID,
		StreamID:   st.streamID,
		Type:       aether.TypeRESET,
		Length:     uint32(len(payload)),
		Payload:    payload,
	}
	// Send the wire RESET first, then clean up local session state.
	// Previously only sched.Unregister was called, which left the
	// s.streams entry and the streamGC tracker alive — both are
	// now released here so local Reset is fully symmetric with
	// the peer-initiated handleReset path.
	err := st.session.writeFrame(frame)
	st.teardown()
	st.session.mu.Lock()
	if _, ok := st.session.streams[st.streamID]; ok {
		delete(st.session.streams, st.streamID)
	}
	st.session.mu.Unlock()
	st.session.releaseStream(st.streamID)
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
