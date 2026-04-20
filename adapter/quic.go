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
	healthMon    *health.Monitor
	closed       chan struct{}
	closeOnce    sync.Once
	mu           sync.Mutex
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
	go s.acceptLoop()
	return s
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

		select {
		case s.acceptCh <- st:
		case <-s.closed:
			return
		}
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

func (s *QUICSession) LocalNodeID() aether.NodeID  { return s.localNodeID }
func (s *QUICSession) RemoteNodeID() aether.NodeID { return s.remoteNodeID }
func (s *QUICSession) LocalPeerID() aether.PeerID  { return s.localPeerID }
func (s *QUICSession) RemotePeerID() aether.PeerID { return s.remotePeerID }

func (s *QUICSession) Capabilities() aether.Capabilities {
	return aether.CapabilitiesForProtocol(aether.ProtoQUIC)
}

func (s *QUICSession) Ping(ctx context.Context) (time.Duration, error) {
	// QUIC doesn't expose ping directly — use health monitor
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
