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
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/abuse"
	"github.com/ORBTR/aether/congestion"
	"github.com/ORBTR/aether/flow"
	"github.com/ORBTR/aether/health"
	"github.com/ORBTR/aether/reliability"
	"github.com/ORBTR/aether/scheduler"
)

// DefaultTCPMaxConcurrentStreams is the stream cap for TCP/WS/gRPC
// sessions (lower than Noise-UDP because one TCP conn is a narrower
// pipe and the head-of-line blocking risk from too many streams is higher).
// See _SECURITY.md §3.12.
const DefaultTCPMaxConcurrentStreams = 256

// TCPSession implements Session over a TCP/TLS connection.
// Provides Aether multiplexing (all streams share one conn), flow control,
// and the priority scheduler. Reliability comes from TCP natively.
type TCPSession struct {
	mu   sync.Mutex
	conn net.Conn

	localNodeID  aether.NodeID
	remoteNodeID aether.NodeID
	localPeerID  aether.PeerID
	remotePeerID aether.PeerID

	proto         aether.Protocol // ProtoTCP (default) or set by wrappers (e.g. WebSocket, gRPC)
	connID        aether.ConnectionID
	layout        aether.StreamLayout
	opts          aether.SessionOptions
	classDefaults aether.TransportClassDefaults
	streams       map[uint64]*tcpStream
	acceptCh      chan *tcpStream
	writeMu       sync.Mutex
	healthMon     *health.Monitor
	sched         *scheduler.Scheduler
	connWindow    *flow.ConnWindow
	compressor    *aether.Compressor

	closed    chan struct{}
	closeOnce sync.Once
	closeErr  error

	// streamRefused counts peer-initiated OPEN requests rejected because
	// MaxConcurrentStreams was reached. See _SECURITY.md §3.12.
	streamRefused uint64

	// Protocol-agnostic capabilities (cross-adapter parity with Noise —
	// these aren't Noise-specific concerns, they're session-level).
	streamGC   *aether.StreamGC                // idle stream auto-RESET
	abuseScore *abuse.Score[aether.NodeID]     // per-peer misbehaviour scoring
	tickStop   chan struct{}                   // shuts down the housekeeping ticker

	// throttle holds the explicit-CONGESTION signal state received from the
	// peer. Zero value is "no throttle"; handleCongestion updates it when a
	// CONGESTION frame arrives. Send-path consumers can consult Throttle()
	// for RateFactor/ShouldStall before committing to large sends.
	throttle aether.CongestionThrottle
}

// tcpStream is a single Aether stream multiplexed over a TCP connection.
type tcpStream struct {
	streamID uint64
	config   aether.StreamConfig
	session  *TCPSession
	state    *aether.StreamStateMachine
	recvCh   chan []byte
	window   *flow.StreamWindow
	// grantDebouncer coalesces stream-level WINDOW_UPDATE emissions driven
	// by application reads. Lazily attached by attachGrantDebouncer after
	// struct construction because the session method references must reach
	// the initialized receiver. TCP's reliable bytestream absorbs
	// transport-level pacing, but stream credit still gates the app-level
	// read flow so we debounce here too for parity with the noise adapter.
	grantDebouncer *grantDebouncer
	observe        *reliability.ObserveEngine // ACK-observe metrics (no enforcement)
	localSeq       uint32                     // monotonic counter (TCP doesn't set SeqNo)
	closed         bool
	mu             sync.Mutex
	connOnce       sync.Once
	connView       net.Conn // cached net.Conn wrapper
}

// attachGrantDebouncer initializes st.grantDebouncer bound to st.window
// and st.session.sendWindowUpdateAgnostic. Called after the stream is
// fully constructed + registered so the session back-reference is live.
// Safe to call once per stream; no-op if already attached.
func (st *tcpStream) attachGrantDebouncer() {
	if st.grantDebouncer != nil || st.window == nil || st.session == nil {
		return
	}
	initialCredit := st.config.InitialCredit
	if initialCredit <= 0 {
		initialCredit = flow.DefaultStreamCredit
	}
	st.grantDebouncer = newGrantDebouncer(
		st.window,
		st.session.sendWindowUpdateAgnostic,
		st.streamID,
		int64(float64(initialCredit)*GrantImmediateFraction),
	)
}

// teardown releases per-stream resources that must not outlive the
// stream itself. Idempotent.
func (st *tcpStream) teardown() {
	if st.grantDebouncer != nil {
		st.grantDebouncer.Close()
	}
}

// NewTCPSession creates an Aether session over a TCP-family connection.
// `proto` must identify the underlying transport (ProtoTCP,
// ProtoWebSocket, ProtoGRPC) — WebSocket and gRPC share TCP's framing
// logic but need their own Protocol() identifier for capability
// reporting.
//
// Always takes SessionOptions. Numeric zero-values (MaxConcurrentStreams,
// MaxFECGroups, SessionIdleTimeout, CongestionAlgo) fall back to
// documented defaults via aether.NormalizeSessionOptions. Boolean fields
// are honoured as-supplied — start from aether.DefaultSessionOptions()
// if you want compression / header compression / scheduler etc. enabled
// and only want to override specific fields.
//
// Protocol-agnostic capability parity with NoiseSession — the
// following honour opts end-to-end on TCP/WS/gRPC, matching the Noise
// adapter's behaviour:
//
//   - `FrameLogging` / `Compression` / `HeaderComp` — per-frame gated
//   - `MaxConcurrentStreams` — RESET(Refused) + `reportAbuse` on excess
//   - `SessionIdleTimeout` — background tick closes idle sessions
//   - `AbuseScoreCapable` — per-peer misbehaviour scoring + circuit
//     breaker via `SetAbuseScoreRegistry`
//   - `StreamGC` — idle stream auto-RESET after timeout
//
// The ticker goroutine (`housekeepingTick`) handles idle eviction +
// stream GC — a single ticker covers both so we don't accumulate one
// goroutine per concern.
func NewTCPSession(conn net.Conn, localNodeID, remoteNodeID aether.NodeID, proto aether.Protocol, opts aether.SessionOptions) *TCPSession {
	opts = aether.NormalizeSessionOptions(opts)
	connID, _ := aether.GenerateConnectionID()
	tc := aether.TransportClassForProtocol(proto)
	s := &TCPSession{
		conn:          conn,
		localNodeID:   localNodeID,
		remoteNodeID:  remoteNodeID,
		localPeerID:   truncateID(localNodeID),
		remotePeerID:  truncateID(remoteNodeID),
		proto:         proto,
		connID:        connID,
		layout:        aether.DefaultStreamLayout(),
		opts:          opts,
		classDefaults: aether.DefaultsForClass(tc),
		streams:       make(map[uint64]*tcpStream),
		acceptCh:      make(chan *tcpStream, 16),
		healthMon:     health.NewMonitor(0.2),
		sched:         scheduler.NewScheduler(),
		connWindow:    flow.NewConnWindow(0),
		compressor:    aether.NewCompressor(),
		closed:        make(chan struct{}),
		tickStop:      make(chan struct{}),
	}
	// Per-peer abuse registry — per-session by default, overridable via
	// SetAbuseScoreRegistry for cross-session scoring.
	s.abuseScore = abuse.New[aether.NodeID](abuse.DefaultConfig())
	// Stream GC — identical policy to Noise; exempts well-known stream
	// IDs 0-3 (control / keepalive).
	s.streamGC = aether.NewStreamGC(aether.DefaultStreamIdleTimeout, func(streamID uint64) {
		dbgTCP.Printf("StreamGC: resetting idle stream %d", streamID)
		s.mu.Lock()
		if st, ok := s.streams[streamID]; ok {
			_ = st.Reset(aether.ResetTimeout)
			delete(s.streams, streamID)
		}
		s.mu.Unlock()
		s.sched.Unregister(streamID)
	})
	go s.streamGC.Start()
	go s.readLoop()
	go s.writeLoop()
	go s.housekeepingTick()
	return s
}

// readLoop reads Aether frames from the TCP connection and dispatches to streams.
// Handles both full and short (compressed) headers.
func (s *TCPSession) readLoop() {
	defer s.CloseWithError(fmt.Errorf("readLoop exited"))
	buf := make([]byte, 1)
	for {
		// Peek first byte to detect short vs full header
		if _, err := io.ReadFull(s.conn, buf); err != nil {
			dbgTCP.Printf("readLoop: EXIT firstByte err=%v remote=%s", err, truncNodeID(s.remoteNodeID))
			if err != io.EOF {
				s.closeErr = err
			}
			return
		}

		var frame *aether.Frame
		var err error
		if aether.IsShortHeader(buf[0]) {
			switch buf[0] {
			case aether.ShortDataIndicator:
				frame, err = s.compressor.DecodeDataShort(s.conn)
			case aether.ShortControlIndicator:
				frame, err = s.compressor.DecodeControlShort(s.conn)
			case aether.ShortACKIndicator:
				frame, err = s.compressor.DecodeACKShort(s.conn)
			case aether.ShortDataVarIndicator:
				frame, err = s.compressor.DecodeDataShortVar(s.conn)
			case aether.ShortEncryptedIndicator:
				frame, err = s.compressor.DecodeEncryptedDataShort(s.conn)
			case aether.ShortBatchIndicator:
				var frames []*aether.Frame
				frames, err = s.compressor.DecodeBatch(s.conn)
				if err == nil {
					for _, f := range frames {
						s.healthMon.RecordActivity()
						s.dispatchFrame(f)
					}
					continue
				}
			default:
				err = fmt.Errorf("aether: unknown short header indicator 0x%02x", buf[0])
			}
		} else {
			frame, err = aether.DecodeFrameWithFirstByte(s.conn, buf[0])
			if err == nil {
				s.compressor.RecordFullHeader(frame)
			}
		}
		if err != nil {
			dbgTCP.Printf("readLoop: EXIT decode err=%v remote=%s", err, truncNodeID(s.remoteNodeID))
			if err != io.EOF {
				s.closeErr = err
			}
			return
		}

		// Structural validation gate — short-header decoders skip
		// Frame.Validate(), so without this check a peer could slip
		// frames with unknown Type bytes or oversize Length straight
		// into the dispatch switch. Cross-adapter parity with the
		// Noise adapter's processIncomingFrame.
		if err := frame.Validate(); err != nil {
			dbgTCP.Printf("readLoop: frame validate failed: %v", err)
			s.reportAbuse(abuse.ReasonMalformedFrame)
			continue
		}

		s.healthMon.RecordActivity()
		dbgTCP.Printf("readLoop: RX type=%d stream=%d len=%d flags=0x%02x", frame.Type, frame.StreamID, frame.Length, frame.Flags)
		s.dispatchFrame(frame)
	}
}

// dispatchFrame routes an incoming frame to the appropriate stream.
func (s *TCPSession) dispatchFrame(frame *aether.Frame) {
	// Record stream activity for GC — any frame type counts as
	// activity on its stream (OPEN/DATA/CLOSE/RESET/WINDOW/etc.). This
	// keeps the idle-timeout reset even on control-only flows like
	// keepalive.
	if s.streamGC != nil && frame.StreamID != 0 {
		s.streamGC.RecordActivity(frame.StreamID)
	}
	switch frame.Type {
	case aether.TypeOPEN:
		s.handleOpen(frame)
	case aether.TypeDATA:
		s.deliverToStream(frame)
	case aether.TypeCLOSE:
		s.handleClose(frame)
	case aether.TypeRESET:
		s.handleReset(frame)
	case aether.TypeWINDOW:
		s.handleWindowUpdate(frame)
	case aether.TypePING:
		s.handlePing(frame)
	case aether.TypePONG:
		s.handlePong(frame)
	case aether.TypeGOAWAY:
		s.handleGoAway(frame)
	case aether.TypeACK:
		// TCP provides native reliability — ACK not used
	case aether.TypePRIORITY:
		s.handlePriority(frame)
	case aether.TypeCONGESTION:
		s.handleCongestion(frame)
	}
}

func (s *TCPSession) deliverToStream(frame *aether.Frame) {
	s.mu.Lock()
	st, ok := s.streams[frame.StreamID]
	s.mu.Unlock()
	if !ok {
		// Implicit open via SYN flag in DATA
		if frame.Flags.Has(aether.FlagSYN) {
			s.handleImplicitOpen(frame)
			return
		}
		dbgTCP.Printf("deliverToStream: no stream for ID=%d, dropping %d bytes", frame.StreamID, frame.Length)
		return // unknown stream, drop
	}
	delivered := DeliverToRecvChWithSignals(st.recvCh, frame.Payload, st.window, frame.StreamID, s.sendWindowUpdateAgnostic, s.SendCongestion)
	if delivered {
		// ACK-observe: track metrics (no wire ACK, no retransmit)
		if st.observe != nil {
			seqNo := frame.SeqNo
			if seqNo == 0 {
				st.localSeq++
				seqNo = st.localSeq
			}
			st.observe.RecordReceive(seqNo, len(frame.Payload), time.Now())
		}
		if frame.StreamID == 0 {
			dbgTCP.Printf("deliverToStream: delivered %d bytes to stream 0 (gossip)", len(frame.Payload))
		}
	} else {
		dbgTCP.Printf("deliverToStream: DROPPED frame for stream %d (%d bytes, recvCh full)", frame.StreamID, len(frame.Payload))
	}
}

// sendWindowUpdateAgnostic adapts sendWindowUpdate to the WindowUpdater signature.
func (s *TCPSession) sendWindowUpdateAgnostic(streamID uint64, credit uint64) {
	s.sendWindowUpdate(streamID, credit)
}

// sendWindowUpdate sends a WINDOW_UPDATE frame granting additional credit to the sender.
func (s *TCPSession) sendWindowUpdate(streamID uint64, credit uint64) {
	dbgTCP.Printf("WINDOW_UPDATE send stream=%d credit=%d", streamID, credit)
	payload := aether.EncodeWindowUpdate(credit)
	frame := &aether.Frame{
		SenderID:   s.localPeerID,
		ReceiverID: s.remotePeerID,
		StreamID:   streamID,
		Type:       aether.TypeWINDOW,
		Length:     uint32(len(payload)),
		Payload:    payload,
	}
	if err := s.writeFrame(frame); err != nil {
		dbgTCP.Printf("WINDOW_UPDATE send FAILED stream=%d credit=%d err=%v", streamID, credit, err)
	}
}

// registerStream performs an atomic check-and-insert for a freshly-constructed
// tcpStream. When enforceRemoteCap is true and MaxConcurrentStreams would be
// exceeded, sends RESET(ResetRefused) and returns nil — the caller drops the
// frame. The check and the map write happen under a single s.mu.Lock so
// concurrent peer OPENs cannot race past the cap.
// See _SECURITY.md §3.12 / S5.
func (s *TCPSession) registerStream(st *tcpStream, enforceRemoteCap bool) *tcpStream {
	s.mu.Lock()
	if existing, ok := s.streams[st.streamID]; ok {
		s.mu.Unlock()
		return existing // duplicate peer OPEN for open stream — return existing
	}
	if enforceRemoteCap {
		cap := s.opts.MaxConcurrentStreams
		if cap <= 0 {
			cap = DefaultTCPMaxConcurrentStreams
		}
		if len(s.streams) >= cap {
			s.mu.Unlock()
			atomic.AddUint64(&s.streamRefused, 1)
			s.reportAbuse(abuse.ReasonStreamRefused)
			payload := aether.EncodeReset(aether.ResetRefused)
			reset := &aether.Frame{
				SenderID:   s.localPeerID,
				ReceiverID: s.remotePeerID,
				StreamID:   st.streamID,
				Type:       aether.TypeRESET,
				Length:     uint32(len(payload)),
				Payload:    payload,
			}
			s.writeFrame(reset)
			return nil
		}
	}
	s.streams[st.streamID] = st
	s.mu.Unlock()
	// Register with stream GC for idle-timeout tracking — only after
	// the cap check + map insert succeed.
	if s.streamGC != nil {
		s.streamGC.Register(st.streamID)
	}
	return st
}

// StreamRefusedCount returns the number of peer-initiated stream opens
// rejected because MaxConcurrentStreams was reached.
func (s *TCPSession) StreamRefusedCount() uint64 {
	return atomic.LoadUint64(&s.streamRefused)
}

func (s *TCPSession) handleOpen(frame *aether.Frame) {
	dbgTCP.Printf("handleOpen: stream=%d", frame.StreamID)
	payload := aether.DecodeOpenPayload(frame.Payload)
	candidate := &tcpStream{
		streamID: frame.StreamID,
		config: aether.StreamConfig{
			StreamID:    frame.StreamID,
			Reliability: payload.Reliability,
			Priority:    payload.Priority,
			Dependency:  payload.Dependency,
		},
		session: s,
		state:   aether.NewStreamStateMachine(),
		recvCh:  make(chan []byte, recvChCapacity(frame.StreamID)),
		window:  flow.NewStreamWindowWithCap(0, 0),
		observe: reliability.NewObserveEngine(),
	}
	st := s.registerStream(candidate, true /* enforceRemoteCap */)
	if st == nil {
		dbgTCP.Printf("handleOpen: refused stream=%d (cap reached)", frame.StreamID)
		return
	}
	// registerStream returns the pre-existing stream on duplicate OPEN;
	// only advance state + notify acceptor when we actually inserted.
	if st != candidate {
		return
	}
	st.attachGrantDebouncer()
	st.state.Transition(aether.EventRecvOpen)

	s.sched.Register(frame.StreamID, payload.Priority, payload.Dependency)

	select {
	case s.acceptCh <- st:
	default:
	}
}

func (s *TCPSession) handleImplicitOpen(frame *aether.Frame) {
	// Decode the OPEN payload from the SYN-flagged DATA frame for proper stream config.
	// Falls back to defaults if the payload is missing or malformed.
	var cfg aether.StreamConfig
	if len(frame.Payload) > 0 {
		payload := aether.DecodeOpenPayload(frame.Payload)
		cfg = aether.StreamConfig{
			StreamID:    frame.StreamID,
			Reliability: payload.Reliability,
			Priority:    payload.Priority,
			Dependency:  payload.Dependency,
		}
	} else {
		cfg = aether.DefaultStreamConfig(frame.StreamID)
	}

	candidate := &tcpStream{
		streamID: frame.StreamID,
		config:   cfg,
		session:  s,
		state:    aether.NewStreamStateMachine(),
		recvCh:   make(chan []byte, recvChCapacity(frame.StreamID)),
		window:   flow.NewStreamWindowWithCap(cfg.InitialCredit, cfg.MaxCredit),
		observe:  reliability.NewObserveEngine(),
	}
	st := s.registerStream(candidate, true /* enforceRemoteCap */)
	if st == nil {
		dbgTCP.Printf("handleImplicitOpen: refused stream=%d (cap reached)", frame.StreamID)
		return
	}
	if st != candidate {
		return
	}
	st.attachGrantDebouncer()
	st.state.Transition(aether.EventRecvData)

	s.sched.Register(frame.StreamID, cfg.Priority, cfg.Dependency)

	select {
	case s.acceptCh <- st:
	default:
	}
}

func (s *TCPSession) handleClose(frame *aether.Frame) {
	s.mu.Lock()
	st, ok := s.streams[frame.StreamID]
	s.mu.Unlock()
	if ok {
		st.state.Transition(aether.EventRecvFIN)
		if !st.state.IsOpen() {
			st.teardown()
			close(st.recvCh)
		}
	}
	s.compressor.RemoveStream(frame.StreamID)
}

func (s *TCPSession) handleReset(frame *aether.Frame) {
	s.mu.Lock()
	st, ok := s.streams[frame.StreamID]
	if ok {
		delete(s.streams, frame.StreamID)
	}
	s.mu.Unlock()
	s.compressor.RemoveStream(frame.StreamID)
	if ok {
		st.state.Transition(aether.EventRecvReset)
		st.teardown()
		close(st.recvCh)
		s.sched.Unregister(frame.StreamID)
	}
}

func (s *TCPSession) handleWindowUpdate(frame *aether.Frame) {
	credit := aether.DecodeWindowUpdate(frame.Payload)
	if frame.StreamID == aether.StreamConnectionLevel {
		dbgTCP.Printf("WINDOW_UPDATE recv stream=conn credit=%d", credit)
		s.connWindow.ApplyUpdate(int64(credit))
	} else {
		s.mu.Lock()
		st, ok := s.streams[frame.StreamID]
		s.mu.Unlock()
		if ok {
			dbgTCP.Printf("WINDOW_UPDATE recv stream=%d credit=%d", frame.StreamID, credit)
			st.window.ApplyUpdate(int64(credit))
		} else {
			dbgTCP.Printf("WINDOW_UPDATE recv for unknown stream=%d credit=%d (DROPPED)", frame.StreamID, credit)
		}
	}
}

func (s *TCPSession) handlePing(frame *aether.Frame) {
	// Respond with PONG
	pong := &aether.Frame{
		SenderID:   s.localPeerID,
		ReceiverID: s.remotePeerID,
		StreamID:   s.layout.Keepalive,
		Type:       aether.TypePONG,
		SeqNo:      frame.SeqNo, // echo the ping's SeqNo for RTT calculation
	}
	s.writeFrame(pong)
}

func (s *TCPSession) handlePong(frame *aether.Frame) {
	s.healthMon.RecordActivity()
	// SeqNo echoes the PING's SeqNo (low 32 bits of UnixNano at send time)
	sentAt := time.Unix(0, int64(frame.SeqNo))
	s.healthMon.RecordPongRecv(frame.SeqNo, sentAt)
}

func (s *TCPSession) handleGoAway(frame *aether.Frame) {
	reason, message := aether.DecodeGoAway(frame.Payload)
	log.Printf("[AETHER-TCP] GOAWAY from %s: reason=%d msg=%s", truncNodeID(s.remoteNodeID), reason, message)
	s.CloseWithError(fmt.Errorf("peer sent GOAWAY (reason=%d): %s", reason, message))
}

func (s *TCPSession) handlePriority(frame *aether.Frame) {
	p := aether.DecodePriority(frame.Payload)
	s.sched.SetWeight(frame.StreamID, p.Weight)
}

// handleCongestion processes an explicit CONGESTION frame — the peer
// asking us to slow down. The session stores the hint in its throttle;
// send-path consumers can check before committing large payloads.
func (s *TCPSession) handleCongestion(frame *aether.Frame) {
	p := aether.DecodeCongestion(frame.Payload)
	s.throttle.Apply(p)
	dbgTCP.Printf("CONGESTION recv severity=%d reason=%d backoff=%dms",
		p.Severity, p.Reason, p.BackoffMs)
}

// SendCongestion emits a CONGESTION frame to the peer. Used when this
// side detects local pressure (memory high, recvCh backlog, etc.) and
// wants the remote to back off before packets pile up.
func (s *TCPSession) SendCongestion(p aether.CongestionPayload) error {
	payload := aether.EncodeCongestion(p)
	frame := &aether.Frame{
		SenderID:   s.localPeerID,
		ReceiverID: s.remotePeerID,
		StreamID:   aether.StreamConnectionLevel,
		Type:       aether.TypeCONGESTION,
		Length:     uint32(len(payload)),
		Payload:    payload,
	}
	return s.writeFrame(frame)
}

// Throttle exposes the session's congestion-throttle state. Callers
// (e.g. gossip scheduler) can consult RateFactor/ShouldStall before
// dispatching large sends.
func (s *TCPSession) Throttle() *aether.CongestionThrottle {
	return &s.throttle
}

// writeLoop reads from the scheduler and writes frames to the TCP connection.
// When multiple frames are queued, they're batched into a single write (0x85).
// A short ticker (2ms) provides batching window — gives the scheduler a
// chance to accumulate frames for coalescing — but the loop also consumes
// the wake channel so it serves bursty traffic with minimal latency.
func (s *TCPSession) writeLoop() {
	ticker := time.NewTicker(2 * time.Millisecond)
	defer ticker.Stop()
	wake := s.sched.WakeCh()
	for {
		select {
		case <-s.closed:
			return
		case <-ticker.C:
		case <-wake:
		}

		frame := s.sched.Dequeue()
		if frame == nil {
			continue
		}

		// Check for batch opportunity — coalesce up to 16 queued frames
		if s.opts.HeaderComp && s.sched.Len() > 0 {
			batch := []*aether.Frame{frame}
			for s.sched.Len() > 0 && len(batch) < 16 {
				next := s.sched.Dequeue()
				if next == nil {
					break
				}
				batch = append(batch, next)
			}
			if len(batch) > 1 {
				s.writeMu.Lock()
				if _, err := s.compressor.EncodeBatch(s.conn, batch); err != nil {
					dbgTCP.Printf("writeLoop: batch err=%v count=%d", err, len(batch))
				}
				s.writeMu.Unlock()
				continue
			}
			// Only 1 frame — fall through to single write
			frame = batch[0]
		}

		if s.opts.FrameLogging || frame.StreamID == 0 {
			dbgTCP.Printf("writeLoop: TX stream=%d type=%d seq=%d len=%d",
				frame.StreamID, frame.Type, frame.SeqNo, frame.Length)
		}
		if err := s.writeFrame(frame); err != nil {
			dbgTCP.Printf("writeLoop: writeFrame err=%v stream=%d", err, frame.StreamID)
		}
	}
}

// writeFrame serializes and writes a single frame to the TCP connection.
// Uses v2 short header compression when enabled by kill switch.
func (s *TCPSession) writeFrame(frame *aether.Frame) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if s.opts.HeaderComp {
		// Control frames: PING/PONG/CLOSE/RESET → 4 bytes
		if s.compressor.ShouldCompressControl(frame) {
			_, err := s.compressor.EncodeControlShort(s.conn, frame)
			return err
		}
		// ACK frames → 11 bytes (lite) or 3+N (full)
		if s.compressor.ShouldCompressACK(frame) {
			_, err := s.compressor.EncodeACKShort(s.conn, frame)
			return err
		}
		// DATA frames → 6-9 bytes
		if s.compressor.ShouldCompressData(frame) {
			if frame.Length <= 127 {
				_, err := s.compressor.EncodeDataShortVar(s.conn, frame)
				return err
			}
			_, err := s.compressor.EncodeDataShort(s.conn, frame)
			return err
		}
	}

	// Full 50-byte header (fallback)
	_, err := aether.EncodeFrame(s.conn, frame)
	if err == nil {
		s.compressor.RecordFullHeader(frame)
	}
	return err
}

// ────────────────────────────────────────────────────────────────────────────
// Session interface implementation
// ────────────────────────────────────────────────────────────────────────────

func (s *TCPSession) OpenStream(ctx context.Context, cfg aether.StreamConfig) (aether.Stream, error) {
	select {
	case <-s.closed:
		return nil, fmt.Errorf("session closed")
	default:
	}

	st := &tcpStream{
		streamID: cfg.StreamID,
		config:   cfg,
		session:  s,
		state:    aether.NewStreamStateMachine(),
		recvCh:   make(chan []byte, recvChCapacity(cfg.StreamID)),
		window:   flow.NewStreamWindowWithCap(cfg.InitialCredit, cfg.MaxCredit),
		observe:  reliability.NewObserveEngine(),
	}
	st.state.Transition(aether.EventSendOpen)

	// Locally-initiated open: no remote cap enforcement.
	if s.registerStream(st, false) == nil {
		return nil, fmt.Errorf("stream %d: registerStream returned nil", cfg.StreamID)
	}
	st.attachGrantDebouncer()

	s.sched.Register(cfg.StreamID, cfg.Priority, cfg.Dependency)

	// Implicit OPEN via SYN flag — saves 50 bytes by combining OPEN with first DATA frame.
	// The OPEN payload (reliability, priority, dependency) rides as the DATA frame's payload.
	// The remote's handleImplicitOpen decodes it to configure the stream properly.
	openPayload := aether.EncodeOpenPayload(aether.OpenPayload{
		Reliability: cfg.Reliability,
		Priority:    cfg.Priority,
		Dependency:  cfg.Dependency,
	})
	frame := &aether.Frame{
		SenderID:   s.localPeerID,
		ReceiverID: s.remotePeerID,
		StreamID:   cfg.StreamID,
		Type:       aether.TypeDATA,
		Flags:      aether.FlagSYN,
		Length:     uint32(len(openPayload)),
		Payload:    openPayload,
	}
	if err := s.writeFrame(frame); err != nil {
		return nil, fmt.Errorf("send SYN+DATA: %w", err)
	}

	return st, nil
}

func (s *TCPSession) AcceptStream(ctx context.Context) (aether.Stream, error) {
	dbgTCP.Printf("AcceptStream: waiting... (acceptCh len=%d)", len(s.acceptCh))
	select {
	case st := <-s.acceptCh:
		dbgTCP.Printf("AcceptStream: got stream=%d", st.streamID)
		return st, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.closed:
		return nil, fmt.Errorf("session closed")
	}
}

func (s *TCPSession) LocalNodeID() aether.NodeID  { return s.localNodeID }
func (s *TCPSession) RemoteNodeID() aether.NodeID { return s.remoteNodeID }
func (s *TCPSession) LocalPeerID() aether.PeerID  { return s.localPeerID }
func (s *TCPSession) RemotePeerID() aether.PeerID { return s.remotePeerID }

func (s *TCPSession) Capabilities() aether.Capabilities {
	return aether.CapabilitiesForProtocol(s.proto)
}

func (s *TCPSession) Ping(ctx context.Context) (time.Duration, error) {
	start := time.Now()
	frame := &aether.Frame{
		SenderID:   s.localPeerID,
		ReceiverID: s.remotePeerID,
		StreamID:   s.layout.Keepalive,
		Type:       aether.TypePING,
		SeqNo:      uint32(start.UnixNano() & 0xFFFFFFFF),
	}
	if err := s.writeFrame(frame); err != nil {
		return 0, err
	}
	// Note: actual RTT measurement requires waiting for PONG.
	// For now, return the health monitor's average RTT.
	_, avg := s.healthMon.RTT()
	return avg, nil
}

func (s *TCPSession) GoAway(ctx context.Context, reason aether.GoAwayReason, message string) error {
	payload := aether.EncodeGoAway(reason, message)
	frame := &aether.Frame{
		SenderID:   s.localPeerID,
		ReceiverID: s.remotePeerID,
		StreamID:   s.layout.Control,
		Type:       aether.TypeGOAWAY,
		Length:     uint32(len(payload)),
		Payload:    payload,
	}
	return s.writeFrame(frame)
}

func (s *TCPSession) Close() error {
	return s.CloseWithError(nil)
}

func (s *TCPSession) CloseWithError(err error) error {
	s.closeOnce.Do(func() {
		if err != nil {
			s.closeErr = err
		}
		close(s.closed)
		if s.tickStop != nil {
			// Non-blocking close: housekeepingTick watches both this
			// and s.closed so either signal stops it.
			select {
			case <-s.tickStop:
			default:
				close(s.tickStop)
			}
		}
		if s.streamGC != nil {
			s.streamGC.Stop()
		}
		s.conn.Close()
	})
	return nil
}

// CloseErr returns the error the session was closed with, or nil if it
// was closed cleanly (or is still open). Satisfies the optional
// aether.CloseErrorReporter interface so the HSTLES connection manager
// can trigger grade-based transport fallback when it sees
// aether.ErrSessionStuck (or another fatal close reason).
func (s *TCPSession) CloseErr() error {
	return s.closeErr
}

// housekeepingTick runs the protocol-agnostic periodic maintenance
// that NoiseSession's reliabilityTick does (minus the Noise-specific
// reliability work). Three concerns per tick:
//
//  1. **Idle session eviction** — session with no inbound activity for
//     `opts.SessionIdleTimeout` is closed so goroutines + memory are
//     reclaimed. Matches the Noise adapter's policy exactly.
//  2. **Flow-control auto-tune** — feeds the session's observed RTT
//     into each stream's window and applies a bounded window resize
//     based on `SuggestedWindow()`. Gated by AETHER_AUTOTUNE env var
//     (set to "off" to disable) so we can kill it in production if it
//     misbehaves.
//  3. **Keepalive nudge** — TCP relies on native keepalive which the
//     OS usually has tuned to hours; we don't reimplement it here,
//     but RecordActivity gets called on every incoming frame so the
//     idle check above stays accurate under real traffic.
//
// Runs on a 10s cadence — idle eviction is not latency-sensitive, and
// a 10s tick means we pay under ~1 µs/sec in aggregate. Exits on
// session close.
func (s *TCPSession) housekeepingTick() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.closed:
			return
		case <-s.tickStop:
			return
		case <-ticker.C:
			idle := s.opts.SessionIdleTimeout
			if idle <= 0 {
				idle = aether.DefaultSessionIdleTimeout
			}
			if time.Since(s.healthMon.LastActivity()) > idle {
				dbgTCP.Printf("session idle timeout (%s) — closing", idle)
				s.CloseWithError(fmt.Errorf("session idle timeout (%s)", idle))
				return
			}
			s.autoTuneWindows()
		}
	}
}

// autoTuneWindows feeds session RTT into each stream's window and applies
// a bounded resize based on SuggestedWindow. Called from housekeepingTick.
// Disabled when AETHER_AUTOTUNE=off. Safe to call concurrently with sends
// because GrowWindow/ShrinkWindow use the semaphore's own locks.
func (s *TCPSession) autoTuneWindows() {
	if aether.AutoTuneDisabled() {
		return
	}
	_, avgRTT := s.healthMon.RTT()
	if avgRTT <= 0 {
		return
	}
	s.mu.Lock()
	streams := make([]*tcpStream, 0, len(s.streams))
	for _, st := range s.streams {
		streams = append(streams, st)
	}
	s.mu.Unlock()
	for _, st := range streams {
		st.window.SetRTT(avgRTT)
		current := st.window.CurrentWindow()
		suggested := st.window.SuggestedWindow()
		if suggested == current {
			continue
		}
		// Bound each adjustment to ±25 % of current to avoid oscillation.
		delta := suggested - current
		maxStep := current / 4
		if delta > maxStep {
			delta = maxStep
		} else if delta < -maxStep {
			delta = -maxStep
		}
		if delta > 0 {
			if grown := st.window.GrowWindow(delta); grown > 0 {
				dbgTCP.Printf("autoTune stream=%d grow=%d current=%d rtt=%s",
					st.streamID, grown, current+grown, avgRTT)
			}
		} else if delta < 0 {
			if shrunk := st.window.ShrinkWindow(-delta); shrunk > 0 {
				dbgTCP.Printf("autoTune stream=%d shrink=%d current=%d rtt=%s",
					st.streamID, shrunk, current-shrunk, avgRTT)
			}
		}
		st.window.ResetPeak()
	}
}

// reportAbuse records a peer misbehaviour event. Mirrors the Noise
// adapter's path: the registry's decay model means transient events
// are forgiven while sustained misbehaviour trips the circuit breaker,
// at which point we GoAway + Close. Safe to call at high frequency.
func (s *TCPSession) reportAbuse(r abuse.Reason) {
	if s.abuseScore == nil {
		return
	}
	if _, exceeded := s.abuseScore.Record(s.remoteNodeID, r); exceeded {
		dbgTCP.Printf("peer %s blacklisted (abuse score exceeded): reason=%s", s.remoteNodeID.Short(), r)
		_ = s.GoAway(context.Background(), aether.GoAwayError, "abuse threshold")
		s.CloseWithError(fmt.Errorf("peer %s exceeded abuse threshold (reason: %s)", s.remoteNodeID.Short(), r))
	}
}

// PeerAbuseScore returns the remote peer's current decayed score (0
// when no events recorded or when the registry is nil).
func (s *TCPSession) PeerAbuseScore() float64 {
	if s.abuseScore == nil {
		return 0
	}
	return s.abuseScore.Current(s.remoteNodeID)
}

// SetAbuseScoreRegistry swaps the per-session registry for a shared
// one — for cross-session operator dashboards. Signature takes
// `interface{}` to satisfy `aether.AbuseScoreCapable` without an
// import cycle; returns false when the registry type doesn't match.
func (s *TCPSession) SetAbuseScoreRegistry(r interface{}) bool {
	registry, ok := r.(*abuse.Score[aether.NodeID])
	if !ok {
		return false
	}
	s.abuseScore = registry
	return true
}

// LastActivity satisfies aether.IdleEvictable — when the session's
// healthMon last observed inbound data.
func (s *TCPSession) LastActivity() time.Time {
	return s.healthMon.LastActivity()
}

// IdleTimeout satisfies aether.IdleEvictable — configured eviction
// threshold (opts override, else package default).
func (s *TCPSession) IdleTimeout() time.Duration {
	if s.opts.SessionIdleTimeout > 0 {
		return s.opts.SessionIdleTimeout
	}
	return aether.DefaultSessionIdleTimeout
}

func (s *TCPSession) IsClosed() bool {
	select {
	case <-s.closed:
		return true
	default:
		return false
	}
}

func (s *TCPSession) ConnectionID() aether.ConnectionID { return s.connID }
func (s *TCPSession) Health() *health.Monitor           { return s.healthMon }
func (s *TCPSession) SessionKey() []byte                { return nil } // TLS provides encryption
func (s *TCPSession) CongestionWindow() int64           { return 0 }   // TCP handles congestion
func (s *TCPSession) Protocol() aether.Protocol         { return s.proto }
func (s *TCPSession) Metrics() aether.SessionMetrics {
	_, avg := s.healthMon.RTT()
	s.mu.Lock()
	streamCount := len(s.streams)
	observeData := make(map[uint64]aether.StreamObserveData, len(s.streams))
	for id, st := range s.streams {
		if st.observe != nil {
			m := st.observe.Metrics()
			observeData[id] = aether.StreamObserveData{
				PacketsReceived:      m.PacketsReceived,
				BytesReceived:        m.BytesReceived,
				HighestSeqNo:         m.HighestSeqNo,
				GapCount:             m.GapCount,
				ReorderCount:         m.ReorderCount,
				MaxReorderDistance:   m.MaxReorderDistance,
				LossEstimatePermille: m.LossEstimatePermille,
				JitterUs:             m.JitterUs,
			}
		}
	}
	s.mu.Unlock()
	return aether.SessionMetrics{
		RTT:           avg,
		ActiveStreams: streamCount,
		StreamObserve: observeData,
		// TCP/WS/gRPC have no reliability engine, so only StreamRefused
		// applies. Other security counters live on the Noise path.
		StreamRefused: s.StreamRefusedCount(),
	}
}

// ────────────────────────────────────────────────────────────────────────────
// tcpStream — aether.Stream implementation
// ────────────────────────────────────────────────────────────────────────────

func (st *tcpStream) StreamID() uint64            { return st.streamID }
func (st *tcpStream) Config() aether.StreamConfig { return st.config }
func (st *tcpStream) IsOpen() bool                { return st.state.IsOpen() }

func (st *tcpStream) Conn() net.Conn {
	st.connOnce.Do(func() { st.connView = NewStreamConn(st) })
	return st.connView
}

func (st *tcpStream) Send(ctx context.Context, data []byte) error {
	if !st.state.CanSend() {
		if st.streamID == 0 {
			dbgTCP.Printf("Send: stream 0 cannot send (state=%s)", st.state.State())
		}
		return fmt.Errorf("stream %d: cannot send (state=%s)", st.streamID, st.state.State())
	}

	// Flow control: TCP provides native backpressure, so we don't enforce
	// Aether-level credit limits on TCP/WS adapters. The Consume call is tracked
	// for metrics but errors are ignored. Only Noise-UDP (unreliable transport)
	// needs application-level flow control enforcement.
	_ = st.window.Consume(ctx, int64(len(data)))

	// MaxFrameSize enforcement (Task 15): split large payloads into
	// MaxFrameSize-sized chunks so they interleave with other streams
	// via the scheduler, avoiding head-of-line blocking.
	maxFrame := st.session.classDefaults.MaxFrameSize
	if maxFrame <= 0 {
		maxFrame = 65536 // ClassSTREAM default
	}

	totalLen := len(data)
	for len(data) > 0 {
		chunk := data
		if len(chunk) > maxFrame {
			chunk = data[:maxFrame]
		}
		data = data[len(chunk):]

		frame := &aether.Frame{
			SenderID:   st.session.localPeerID,
			ReceiverID: st.session.remotePeerID,
			StreamID:   st.streamID,
			Type:       aether.TypeDATA,
			Length:     uint32(len(chunk)),
			Payload:    chunk,
		}
		st.session.sched.Enqueue(st.streamID, frame)
	}

	if st.streamID == 0 {
		dbgTCP.Printf("Send: enqueued %d bytes for stream 0 (gossip), schedLen=%d", totalLen, st.session.sched.QueueLen(0))
	}
	return nil
}

func (st *tcpStream) Receive(ctx context.Context) ([]byte, error) {
	select {
	case data, ok := <-st.recvCh:
		if !ok {
			return nil, io.EOF
		}
		// Consume-driven grant: record the app-consumed bytes in the
		// stream-level debouncer so WINDOW_UPDATE emission advances with
		// application progress, not frame-receipt.
		if st.grantDebouncer != nil {
			st.grantDebouncer.Record(int64(len(data)))
		}
		return data, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-st.session.closed:
		return nil, fmt.Errorf("session closed")
	}
}

func (st *tcpStream) Close() error {
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

func (st *tcpStream) Reset(reason aether.ResetReason) error {
	st.state.Transition(aether.EventSendReset)
	st.teardown()
	payload := aether.EncodeReset(reason)
	frame := &aether.Frame{
		SenderID:   st.session.localPeerID,
		ReceiverID: st.session.remotePeerID,
		StreamID:   st.streamID,
		Type:       aether.TypeRESET,
		Length:     uint32(len(payload)),
		Payload:    payload,
	}
	st.session.sched.Unregister(st.streamID)
	return st.session.writeFrame(frame)
}

func (st *tcpStream) SetPriority(weight uint8, dependency uint64) {
	st.session.sched.SetWeight(st.streamID, weight)
}

// AvailableCredit exposes the current send-side flow-control credit for
// this stream. Used by upper layers (gossip) to self-throttle against
// a near-empty window. TCP-family streams still track a window even though
// Send ignores timeouts — the value is accurate for scheduling decisions.
func (st *tcpStream) AvailableCredit() int64 {
	return st.window.Available()
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────

func truncNodeID(nodeID aether.NodeID) string {
	s := string(nodeID)
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func truncateID(nodeID aether.NodeID) aether.PeerID {
	var pid aether.PeerID
	copy(pid[:], []byte(string(nodeID)))
	return pid
}

// Ensure interfaces are satisfied at compile time.
var _ aether.Session = (*TCPSession)(nil)
var _ aether.AbuseScoreCapable = (*TCPSession)(nil)
var _ aether.IdleEvictable = (*TCPSession)(nil)
var _ aether.Stream = (*tcpStream)(nil)

// Suppress unused import warnings for packages used in struct fields.
var _ = (*congestion.Controller)(nil)
