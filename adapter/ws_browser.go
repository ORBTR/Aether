//go:build js && wasm

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package adapter

import (
	"context"
	"fmt"
	"net"
	"sync"
	"syscall/js"

	aether "github.com/ORBTR/aether"
	"github.com/ORBTR/aether/flow"
	"github.com/ORBTR/aether/scheduler"
)

// BrowserWSSession implements aether.Session over a browser-native WebSocket.
// Uses syscall/js to call the browser's WebSocket API directly.
// This is the ONLY transport available in WASM — all other adapters are
// excluded by build tags.
type BrowserWSSession struct {
	ws           js.Value
	localNodeID  aether.NodeID
	remoteNodeID aether.NodeID
	localPeerID  aether.PeerID
	remotePeerID aether.PeerID
	layout       aether.StreamLayout
	opts         aether.SessionOptions

	connID  aether.ConnectionID
	streams map[uint64]*browserStream
	mu      sync.Mutex
	sched   *scheduler.Scheduler
	closed  chan struct{}

	// throttle holds the explicit-CONGESTION signal state from the peer.
	// Zero value is "no throttle"; handleCongestion updates it on incoming
	// CONGESTION frames. Send-path consumers can consult Throttle() for
	// RateFactor / ShouldStall before committing large sends — parity
	// with NoiseSession / TCPSession.
	throttle aether.CongestionThrottle
}

// browserStream wraps a logical stream over the browser WebSocket.
type browserStream struct {
	streamID uint64
	config   aether.StreamConfig
	session  *BrowserWSSession
	recvCh   chan []byte
	window   *flow.StreamWindow
	state    *aether.StreamStateMachine
	connOnce sync.Once
	connView net.Conn
}

// DialBrowserWS creates a session by connecting to a WebSocket URL.
// This is called from the WASM JS bridge (wasm/main.go).
func DialBrowserWS(ctx context.Context, url string, localNodeID aether.NodeID) (*BrowserWSSession, error) {
	ws := js.Global().Get("WebSocket").New(url)
	ws.Set("binaryType", "arraybuffer")

	connID, _ := aether.GenerateConnectionID()
	s := &BrowserWSSession{
		ws:          ws,
		localNodeID: localNodeID,
		localPeerID: aether.PeerID{},
		layout:      aether.DefaultStreamLayout(),
		opts:        aether.DefaultSessionOptions(),
		connID:      connID,
		streams:     make(map[uint64]*browserStream),
		sched:       scheduler.NewScheduler(),
		closed:      make(chan struct{}),
	}

	// Wait for WebSocket to open
	openCh := make(chan struct{})
	var openOnce sync.Once
	ws.Call("addEventListener", "open", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		openOnce.Do(func() { close(openCh) })
		return nil
	}))

	// Handle incoming messages
	ws.Call("addEventListener", "message", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		event := args[0]
		data := event.Get("data")
		// Convert ArrayBuffer to Go []byte
		buf := js.Global().Get("Uint8Array").New(data)
		payload := make([]byte, buf.Length())
		js.CopyBytesToGo(payload, buf)
		s.handleIncoming(payload)
		return nil
	}))

	// Handle close
	ws.Call("addEventListener", "close", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		close(s.closed)
		return nil
	}))

	// Wait for open or context cancel
	select {
	case <-openCh:
		return s, nil
	case <-ctx.Done():
		ws.Call("close")
		return nil, ctx.Err()
	}
}

func (s *BrowserWSSession) handleIncoming(payload []byte) {
	if len(payload) < aether.HeaderSize {
		return // too short to be a valid frame
	}

	// Decode frame header
	frame, err := aether.DecodeFrameFromBytes(payload)
	if err != nil {
		return // corrupted frame
	}

	s.mu.Lock()
	st, ok := s.streams[frame.StreamID]
	s.mu.Unlock()

	if !ok {
		// Unknown stream — might be a remotely-opened stream
		// For browser sessions, we don't support AcceptStream (server-side only)
		return
	}

	switch frame.Type {
	case aether.TypeDATA:
		// Use the agnostic DeliverToRecvChWithSignals helper so we get
		// the same three-trigger grant emission, adaptive backpressure,
		// and receiver-driven CONGESTION feedback as the TCP / Noise
		// adapters. The SendCongestion callback emits a CONGESTION
		// frame back to the sender when this side has to drop due to
		// a saturated recvCh — parity with the other adapters.
		DeliverToRecvChWithSignals(st.recvCh, frame.Payload, st.window, st.streamID,
			s.sendWindowUpdateAgnostic, s.SendCongestion)
	case aether.TypeWINDOW:
		credit := aether.DecodeWindowUpdate(frame.Payload)
		st.window.ApplyUpdate(int64(credit))
	case aether.TypeCONGESTION:
		// Peer signalled explicit backpressure — apply to the session-wide
		// throttle so the send path paces appropriately. Matches the
		// handleCongestion path in NoiseSession / TCPSession.
		s.handleCongestion(frame)
	case aether.TypeCLOSE:
		close(st.recvCh)
	case aether.TypeRESET:
		close(st.recvCh)
	}
}

// handleCongestion processes an explicit CONGESTION frame. Mirrors the
// NoiseSession / TCPSession equivalents — shared payload decoding, shared
// throttle type, so the browser path paces the same way under peer load.
func (s *BrowserWSSession) handleCongestion(frame *aether.Frame) {
	p := aether.DecodeCongestion(frame.Payload)
	s.throttle.Apply(p)
}

// SendCongestion emits a CONGESTION frame to the peer. Called by
// DeliverToRecvChWithSignals when the receive side has to drop due to
// backpressure; the sender's CongestionThrottle picks up the signal and
// paces accordingly. Agnostic with NoiseSession.SendCongestion /
// TCPSession.SendCongestion so the DeliverToRecvChWithSignals callback
// shape plugs in unchanged.
func (s *BrowserWSSession) SendCongestion(p aether.CongestionPayload) error {
	payload := aether.EncodeCongestion(p)
	frame := &aether.Frame{
		SenderID:   s.localPeerID,
		ReceiverID: s.remotePeerID,
		StreamID:   aether.StreamConnectionLevel,
		Type:       aether.TypeCONGESTION,
		Length:     uint32(len(payload)),
		Payload:    payload,
	}
	encoded := aether.EncodeFrameToBytes(frame)
	buf := js.Global().Get("Uint8Array").New(len(encoded))
	js.CopyBytesToJS(buf, encoded)
	s.ws.Call("send", buf.Get("buffer"))
	return nil
}

// Throttle exposes the session's congestion-throttle state. Callers
// (e.g. gossip scheduler) can consult RateFactor / ShouldStall before
// dispatching large sends. Parity with NoiseSession.Throttle / TCPSession.Throttle.
func (s *BrowserWSSession) Throttle() *aether.CongestionThrottle {
	return &s.throttle
}

// sendWindowUpdate emits a WINDOW_UPDATE frame to the peer granting additional
// credit on the given stream. Mirrors TCPSession.sendWindowUpdate.
func (s *BrowserWSSession) sendWindowUpdate(streamID uint64, credit uint64) {
	payload := aether.EncodeWindowUpdate(credit)
	frame := &aether.Frame{
		SenderID:   s.localPeerID,
		ReceiverID: s.remotePeerID,
		StreamID:   streamID,
		Type:       aether.TypeWINDOW,
		Length:     uint32(len(payload)),
		Payload:    payload,
	}
	encoded := aether.EncodeFrameToBytes(frame)
	buf := js.Global().Get("Uint8Array").New(len(encoded))
	js.CopyBytesToJS(buf, encoded)
	s.ws.Call("send", buf.Get("buffer"))
}

// sendWindowUpdateAgnostic adapts sendWindowUpdate to the WindowUpdater
// signature expected by DeliverToRecvCh.
func (s *BrowserWSSession) sendWindowUpdateAgnostic(streamID uint64, credit uint64) {
	s.sendWindowUpdate(streamID, credit)
}

// OpenStream creates a new multiplexed stream.
func (s *BrowserWSSession) OpenStream(ctx context.Context, cfg aether.StreamConfig) (aether.Stream, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	st := &browserStream{
		streamID: cfg.StreamID,
		config:   cfg,
		session:  s,
		recvCh:   make(chan []byte, recvChCapacity(cfg.StreamID)),
		window:   flow.NewStreamWindow(cfg.InitialCredit),
		state:    aether.NewStreamStateMachine(),
	}
	s.streams[cfg.StreamID] = st
	return st, nil
}

func (s *BrowserWSSession) AcceptStream(ctx context.Context) (aether.Stream, error) {
	// Browser sessions don't accept streams — only the server side does.
	// Block until context cancelled.
	<-ctx.Done()
	return nil, ctx.Err()
}

func (s *BrowserWSSession) Close() error {
	s.ws.Call("close")
	return nil
}

func (s *BrowserWSSession) IsClosed() bool {
	select {
	case <-s.closed:
		return true
	default:
		return false
	}
}

func (s *BrowserWSSession) LocalNodeID() aether.NodeID   { return s.localNodeID }
func (s *BrowserWSSession) RemoteNodeID() aether.NodeID  { return s.remoteNodeID }
func (s *BrowserWSSession) LocalPeerID() aether.PeerID   { return s.localPeerID }
func (s *BrowserWSSession) RemotePeerID() aether.PeerID  { return s.remotePeerID }
func (s *BrowserWSSession) ConnectionID() aether.ConnectionID { return s.connID }
func (s *BrowserWSSession) Conn() net.Conn               { return nil }
func (s *BrowserWSSession) Protocol() aether.Protocol     { return aether.ProtoWebSocket }

// browserStream implements aether.Stream
func (st *browserStream) StreamID() uint64               { return st.streamID }
func (st *browserStream) Config() aether.StreamConfig    { return st.config }
func (st *browserStream) IsOpen() bool                   { return st.state.IsOpen() }

func (st *browserStream) Send(ctx context.Context, data []byte) error {
	// Flow control
	if err := st.window.Consume(ctx, int64(len(data))); err != nil {
		return fmt.Errorf("stream %d: %w", st.streamID, err)
	}

	// Encode as Aether frame
	frame := &aether.Frame{
		SenderID:   st.session.localPeerID,
		ReceiverID: st.session.remotePeerID,
		StreamID:   st.streamID,
		Type:       aether.TypeDATA,
		Length:     uint32(len(data)),
		Payload:    data,
	}

	encoded := aether.EncodeFrameToBytes(frame)
	buf := js.Global().Get("Uint8Array").New(len(encoded))
	js.CopyBytesToJS(buf, encoded)
	st.session.ws.Call("send", buf.Get("buffer"))
	return nil
}

func (st *browserStream) Receive(ctx context.Context) ([]byte, error) {
	select {
	case data, ok := <-st.recvCh:
		if !ok {
			return nil, fmt.Errorf("stream closed")
		}
		return data, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-st.session.closed:
		return nil, fmt.Errorf("session closed")
	}
}

func (st *browserStream) Close() error {
	st.state.Transition(aether.EventSendFIN)
	return nil
}

func (st *browserStream) Reset(reason aether.ResetReason) error {
	st.state.Transition(aether.EventSendReset)
	return nil
}

func (st *browserStream) SetPriority(weight uint8, dependency uint64) {}

// AvailableCredit exposes the current send-side flow-control credit for
// this stream. Parity with the other adapters so upper layers can make
// agnostic scheduling decisions.
func (st *browserStream) AvailableCredit() int64 {
	return st.window.Available()
}

func (st *browserStream) Conn() net.Conn {
	st.connOnce.Do(func() { st.connView = NewStreamConn(st) })
	return st.connView
}
