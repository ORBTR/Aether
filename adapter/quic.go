//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package adapter

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/health"
	"github.com/quic-go/quic-go"
)

// QUICSession implements Session over a QUIC connection.
// QUIC provides native streams, reliability, flow control, congestion control,
// and encryption. The adapter is the SIMPLEST — it maps Aether stream operations
// directly to QUIC bidirectional stream operations with zero protocol overhead.
//
// Aether provides: stream lifecycle (OPEN/CLOSE/RESET semantics only).
// QUIC provides: EVERYTHING ELSE (reliability, flow control, congestion, mux, encryption).
type QUICSession struct {
	conn         quic.Connection
	connID       aether.ConnectionID
	localNodeID  aether.NodeID
	remoteNodeID aether.NodeID
	localPeerID  aether.PeerID
	remotePeerID aether.PeerID
	streams      map[uint64]*quicStream
	acceptCh     chan *quicStream
	// acceptor handles per-StreamID accept dispatch — pinned waiters,
	// per-ID backlog, and the FIFO fallback to acceptCh. Shared
	// transport-agnostic implementation in the root aether package, so
	// the Noise, TCP, and QUIC adapters all delegate here rather than
	// each carrying their own copy. acceptLoop calls acceptor.Notify;
	// AcceptStreamByID delegates to acceptor.AcceptByID.
	acceptor  *aether.StreamAcceptor
	healthMon *health.Monitor
	closed    chan struct{}
	closeOnce sync.Once
	mu        sync.Mutex
}

// quicStream wraps a native QUIC bidirectional stream as an Aether Stream.
type quicStream struct {
	streamID   uint64
	quicStream quic.Stream
	config     aether.StreamConfig
	state      *aether.StreamStateMachine
	session    *QUICSession
	connOnce   sync.Once
	connView   net.Conn
}

// NewQuicSession creates an Aether session over a QUIC connection.
func NewQuicSession(conn quic.Connection, localNodeID, remoteNodeID aether.NodeID) *QUICSession {
	connID, _ := aether.GenerateConnectionID()
	s := &QUICSession{
		conn:         conn,
		connID:       connID,
		localNodeID:  localNodeID,
		remoteNodeID: remoteNodeID,
		localPeerID:  truncateID(localNodeID),
		remotePeerID: truncateID(remoteNodeID),
		streams:      make(map[uint64]*quicStream),
		acceptCh:     make(chan *quicStream, 16),
		healthMon:    health.NewMonitor(0.2),
		closed:       make(chan struct{}),
	}
	// Per-StreamID accept dispatch — shared implementation in the root
	// aether package. Fallback blocks on FIFO acceptCh OR session close,
	// preserving the pre-refactor QUIC behaviour where a packed
	// acceptCh stalls the accept loop until a consumer drains.
	s.acceptor = aether.NewStreamAcceptor(
		s.pushToAcceptCh,
		s.closed,
		aether.ErrSessionClosed,
	)
	go s.acceptLoop()
	return s
}

// pushToAcceptCh forwards a stream to the FIFO acceptCh. Wired as the
// StreamAcceptor fallback in NewQuicSession. Blocks until acceptCh
// accepts or the session closes — matches pre-refactor QUIC semantics
// (which used a select on acceptCh + closed). Returning early on
// session close means the accept loop will see a subsequent Notify
// short-circuit because the acceptor is closed.
func (s *QUICSession) pushToAcceptCh(st aether.Stream) {
	qs, ok := st.(*quicStream)
	if !ok {
		return
	}
	select {
	case s.acceptCh <- qs:
	case <-s.closed:
	}
}

// acceptLoop accepts incoming QUIC streams and wraps them as Aether streams.
func (s *QUICSession) acceptLoop() {
	for {
		qs, err := s.conn.AcceptStream(context.Background())
		if err != nil {
			return // connection closed
		}

		// Read stream header: [StreamID:8][OpenPayload:10]
		var hdr [8 + aether.OpenPayloadSize]byte
		if _, err := io.ReadFull(qs, hdr[:]); err != nil {
			qs.CancelRead(0)
			continue
		}

		streamID := binary.BigEndian.Uint64(hdr[0:8])
		openPayload := aether.DecodeOpenPayload(hdr[8:])

		st := &quicStream{
			streamID:   streamID,
			quicStream: qs,
			config: aether.StreamConfig{
				StreamID:    streamID,
				Reliability: openPayload.Reliability,
				Priority:    openPayload.Priority,
				Dependency:  openPayload.Dependency,
			},
			state:   aether.NewStreamStateMachine(),
			session: s,
		}
		st.state.Transition(aether.EventRecvOpen)

		s.mu.Lock()
		s.streams[streamID] = st
		s.mu.Unlock()

		// Hand to the shared per-StreamID dispatcher. Notify always
		// makes progress (waiter / backlog / fallback). If the
		// session has closed mid-dispatch the acceptor's isClosed
		// guard rejects the notify and the loop continues; we exit
		// on the next conn.AcceptStream error instead.
		s.acceptor.Notify(st)
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Session interface
// ────────────────────────────────────────────────────────────────────────────

func (s *QUICSession) OpenStream(ctx context.Context, cfg aether.StreamConfig) (aether.Stream, error) {
	select {
	case <-s.closed:
		return nil, fmt.Errorf("session closed")
	default:
	}

	qs, err := s.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("quic open stream: %w", err)
	}

	// Write stream header: [StreamID:8][OpenPayload:10]
	var hdr [8 + aether.OpenPayloadSize]byte
	binary.BigEndian.PutUint64(hdr[0:8], cfg.StreamID)
	copy(hdr[8:], aether.EncodeOpenPayload(aether.OpenPayload{
		Reliability: cfg.Reliability,
		Priority:    cfg.Priority,
		Dependency:  cfg.Dependency,
	}))
	if _, err := qs.Write(hdr[:]); err != nil {
		return nil, fmt.Errorf("write stream header: %w", err)
	}

	st := &quicStream{
		streamID:   cfg.StreamID,
		quicStream: qs,
		config:     cfg,
		state:      aether.NewStreamStateMachine(),
		session:    s,
	}
	st.state.Transition(aether.EventSendOpen)

	s.mu.Lock()
	s.streams[cfg.StreamID] = st
	s.mu.Unlock()

	return st, nil
}

func (s *QUICSession) AcceptStream(ctx context.Context) (aether.Stream, error) {
	select {
	case st := <-s.acceptCh:
		return st, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.closed:
		return nil, fmt.Errorf("session closed")
	}
}

// AcceptStreamByID delegates to the shared aether.StreamAcceptor. See
// the Session interface comment + stream_acceptor.go for the
// architectural rationale — the per-StreamID dispatch lives in the
// root aether package so all three transport adapters share one
// implementation.
func (s *QUICSession) AcceptStreamByID(ctx context.Context, streamID uint64) (aether.Stream, error) {
	return s.acceptor.AcceptByID(ctx, streamID)
}

func (s *QUICSession) LocalNodeID() aether.NodeID  { return s.localNodeID }
func (s *QUICSession) RemoteNodeID() aether.NodeID { return s.remoteNodeID }
func (s *QUICSession) LocalPeerID() aether.PeerID  { return s.localPeerID }
func (s *QUICSession) RemotePeerID() aether.PeerID { return s.remotePeerID }

func (s *QUICSession) Capabilities() aether.Capabilities {
	return aether.CapabilitiesForProtocol(aether.ProtoQUIC)
}

// Ping reports session liveness for keepalive. QUIC has its own
// transport-layer keepalive so we don't write an aether-level PING
// frame, but we DO need to surface session death to callers — pre-v0.0.22
// returned the cached RTT regardless of whether the underlying QUIC
// connection had been torn down, leaving zombie sessions registered
// in the connection manager indefinitely. Now we check IsClosed plus
// the underlying QUIC connection's context, which fires on transport
// close, idle timeout, or peer-initiated CONNECTION_CLOSE.
func (s *QUICSession) Ping(ctx context.Context) (time.Duration, error) {
	if s.IsClosed() {
		return 0, aether.ErrSessionClosed
	}
	if err := s.conn.Context().Err(); err != nil {
		return 0, aether.ErrSessionClosed
	}
	_, avg := s.healthMon.RTT()
	return avg, nil
}

func (s *QUICSession) GoAway(ctx context.Context, reason aether.GoAwayReason, message string) error {
	// QUIC uses connection close with error code
	return s.conn.CloseWithError(quic.ApplicationErrorCode(reason), message)
}

func (s *QUICSession) Close() error {
	s.closeOnce.Do(func() {
		close(s.closed)
		// Release ByID waiters and drain the backlog; blocked
		// AcceptStreamByID callers return ErrSessionClosed. Drained
		// backlog streams are not Reset here because QUIC stream
		// cancel is handled by quic-go on conn close — calling
		// CancelRead/Write twice is harmless but redundant.
		if s.acceptor != nil {
			_ = s.acceptor.Close()
		}
		s.conn.CloseWithError(0, "session closed")
	})
	return nil
}

func (s *QUICSession) IsClosed() bool {
	select {
	case <-s.closed:
		return true
	default:
		return false
	}
}

func (s *QUICSession) ConnectionID() aether.ConnectionID { return s.connID }
func (s *QUICSession) Health() *health.Monitor           { return s.healthMon }
func (s *QUICSession) SessionKey() []byte                { return nil } // QUIC handles encryption
func (s *QUICSession) CongestionWindow() int64           { return 0 }   // QUIC handles congestion
func (s *QUICSession) Protocol() aether.Protocol         { return aether.ProtoQUIC }
func (s *QUICSession) Metrics() aether.SessionMetrics {
	_, avg := s.healthMon.RTT()
	s.mu.Lock()
	streamCount := len(s.streams)
	s.mu.Unlock()
	return aether.SessionMetrics{RTT: avg, ActiveStreams: streamCount}
}

// ────────────────────────────────────────────────────────────────────────────
// quicStream — aether.Stream interface
// ────────────────────────────────────────────────────────────────────────────

func (st *quicStream) StreamID() uint64            { return st.streamID }
func (st *quicStream) Config() aether.StreamConfig { return st.config }
func (st *quicStream) IsOpen() bool                { return st.state.IsOpen() }

func (st *quicStream) Conn() net.Conn {
	st.connOnce.Do(func() { st.connView = NewStreamConn(st) })
	return st.connView
}

func (st *quicStream) Send(ctx context.Context, data []byte) error {
	if !st.state.CanSend() {
		return fmt.Errorf("stream %d: cannot send", st.streamID)
	}
	// Write directly to QUIC stream — QUIC handles framing, reliability, flow control
	// Prefix with 4-byte length for message boundaries
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	if _, err := st.quicStream.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := st.quicStream.Write(data)
	return err
}

func (st *quicStream) Receive(ctx context.Context) ([]byte, error) {
	// Read 4-byte length prefix
	var lenBuf [4]byte
	if _, err := io.ReadFull(st.quicStream, lenBuf[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length > aether.MaxPayloadSize {
		return nil, fmt.Errorf("message too large: %d", length)
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(st.quicStream, data); err != nil {
		return nil, err
	}
	st.session.healthMon.RecordActivity()
	return data, nil
}

func (st *quicStream) Close() error {
	st.state.Transition(aether.EventSendFIN)
	return st.quicStream.Close()
}

func (st *quicStream) Reset(reason aether.ResetReason) error {
	st.state.Transition(aether.EventSendReset)
	st.quicStream.CancelRead(quic.StreamErrorCode(reason))
	st.quicStream.CancelWrite(quic.StreamErrorCode(reason))
	return nil
}

func (st *quicStream) SetPriority(weight uint8, dependency uint64) {
	// QUIC doesn't expose per-stream priority in quic-go
	// Priority is tracked in config for informational purposes
	st.config.Priority = weight
	st.config.Dependency = dependency
}

// Compile-time interface checks
var _ aether.Session = (*QUICSession)(nil)
var _ aether.Stream = (*quicStream)(nil)
