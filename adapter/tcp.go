//go:build !js

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
	"github.com/ORBTR/aether/flow"
	"github.com/ORBTR/aether/health"
	"github.com/ORBTR/aether/reliability"
	"github.com/ORBTR/aether/scheduler"
	"golang.org/x/sync/semaphore"
)

// DefaultTCPMaxConcurrentStreams is the stream cap for TCP/WS/gRPC
// sessions (lower than Noise-UDP because one TCP conn is a narrower
// pipe and the head-of-line blocking risk from too many streams is higher).
// registerStream refuses opens past it with RESET(ResetRefused).
const DefaultTCPMaxConcurrentStreams = 256

// The per-StreamID backlog tuning constants (aether.MaxByIDBacklogPerStream,
// aether.ByIDBacklogGrace) live in the root package beside StreamAcceptor
// (stream_acceptor.go), which the Noise, TCP and QUIC adapters share, so one
// limit governs every adapter's accept backlog and none redeclares it here.

// TCPSession implements Session over a byte-stream connection (TCP, TLS,
// WebSocket, gRPC, a QUIC stream): the Lite profile. It provides Aether
// multiplexing (all streams share one conn), the stream lifecycle and the
// priority scheduler. Reliability, flow control and congestion control belong
// to the transport, so a session keeps no stream or connection credit, writes
// no WINDOW_UPDATE or CONGESTION frame and acts on none it reads
// (dispatchFrame). What bounds a peer's unread messages is the stream's delivery
// queue, whose overflow ends that stream with a typed reset (enqueueDelivery).
type TCPSession struct {
	// BaseSession owns the identity + lifecycle + accessor surface
	// (LocalNodeID/RemoteNodeID/LocalPeerID/RemotePeerID/ConnectionID/
	// Capabilities/Protocol/Health/IsClosed/LastActivity/IdleTimeout)
	// shared with the Noise + QUIC adapters. Embedded as a pointer so
	// the close-signal channel + sync.Once are safe across the read /
	// write / housekeeping goroutines.
	*aether.BaseSession

	mu   sync.Mutex
	conn net.Conn

	layout        aether.StreamLayout
	opts          aether.SessionOptions
	classDefaults aether.TransportClassDefaults
	streams       map[uint64]*tcpStream

	// acceptor owns per-StreamID accept dispatch — pinned waiters,
	// per-ID backlog, and the FIFO that AcceptStream drains. Shared
	// transport-agnostic implementation in the root aether package, so
	// the Noise, TCP, and QUIC adapters do not each carry their own
	// channel + push-mode shim. handleOpen calls acceptor.Notify;
	// AcceptStream and AcceptStreamByID delegate to it.
	acceptor *aether.StreamAcceptor

	writeMu sync.Mutex
	sched   *scheduler.Scheduler
	// out is the session's one path to the conn for frames and the preface: every
	// writer holds writeMu and writes through it (sessionWriter).
	out *sessionWriter
	// queuedFrames maps a DATA frame between Send and the conn to the room it took
	// on its stream's sendRoom, which frameWritten gives back once it is written and
	// releaseStream when the scheduler drops it. The map finds the stream the frame
	// was charged to, since a later stream may hold the ID by then.
	queuedFrames sync.Map // *aether.Frame -> queuedFrame
	// txCompressor and rxCompressor are separate compressor states for TX
	// (encode: writeFrame, writeLoop's EncodeBatch) and RX (decode: readLoop's
	// ReadNextFrame), so cross-direction traffic never pollutes
	// SessionCompState identity (lastSender/lastReceiver) or a stream's
	// lastSeqNo/frameCount: one shared instance would flip the reconstructed
	// identity with the direction of the most recent full header and
	// cross-increment the frameCount%64 resync cadence, where dedicated state
	// per direction tracks identically on both peers. Both write and read
	// full frames only until readPreface applies the chosen set, so a frame
	// written before the peer's preface is read is a full frame.
	txCompressor *aether.Compressor
	rxCompressor *aether.Compressor

	// streamRefused counts peer-initiated OPEN requests rejected because
	// MaxConcurrentStreams was reached (registerStream).
	streamRefused uint64

	// streamGenerations numbers the streams this session opens; OpenStream states
	// each one's number in its SYN, and its CLOSE and RESET name it by that number
	// (tcpStream.incarnation).
	streamGenerations atomic.Uint64

	// recvMemory is what this session's delivery queues hold, against the bounds
	// profile's session and per-peer ceilings (tcpStream.enqueueDelivery), and the
	// queues of ended streams, which housekeepingTick's sweep and makeQueueRoom
	// discard. A session built under a remote node ID its transport proved
	// (NewTCPSession) shares that peer's entry in peerMemoryLedgers; one built
	// under an ID the remote only stated (NewSessionForStatedPeer) holds a
	// per-peer ceiling of its own, so its queues never take another node's room.
	recvMemory

	// Protocol-agnostic capabilities (cross-adapter parity with Noise —
	// these aren't Noise-specific concerns, they're session-level).
	streamGC     *aether.StreamGC     // idle stream auto-RESET
	abuseTracker *aether.AbuseTracker // per-peer misbehaviour scoring + threshold-breaker
	tickStop     chan struct{}        // shuts down the housekeeping ticker

	// Per-session delivery counters, session-aggregate across streams, the
	// same type NoiseSession.deliveryStats is. enqueueDelivery counts each
	// message it queues as delivered, and overrun counts the message that
	// does not fit the queue, the one the stream's reset refuses, both as
	// backpressure and as dropped with its bytes. Surfaced through
	// DeliveryStats() for the consumer that sums a session's stats.
	deliveryStats DeliveryStats

	// wireOffer is the wire version offer this session's preface sends:
	// aether's entries plus opts.WireVersions (aether.LocalWireVersions).
	// wireOfferErr is that merge's refusal, which closes the session before
	// any preface is written. Both are set in newTCPSession before any
	// goroutine starts and never change.
	wireOffer    aether.WireVersions
	wireOfferErr error

	// wireExchange is the preface exchange: OpenStream waits on it, and readLoop
	// decodes no frame before it. prefaceWritten closes once this side's preface
	// write has returned, so a refusing readLoop can let its preface reach the peer
	// before the conn closes and the peer reaches the same refusal.
	wireExchange
	prefaceWritten chan struct{}
	prefaceTimeout time.Duration

	// fragRecv is what a fragment this session receives must match. A
	// TCPSession's identity is established by its caller before construction
	// and binds it to no network key, so it has no realm: fragRecv refuses
	// every fragment (FragmentNoRealm), and Send never splits a message.
	// readPreface sets it from the chosen set before readLoop decodes a
	// frame; only readLoop reads it.
	fragRecv *FragmentReceiver
}

// queuedFrame is what a frame on its way to the conn holds on its stream's sendRoom.
type queuedFrame struct {
	st   *tcpStream
	cost int64
}

// tcpStream is a single Aether stream multiplexed over a TCP connection.
type tcpStream struct {
	streamID uint64
	config   aether.StreamConfig
	session  *TCPSession
	state    *aether.StreamStateMachine
	// recvQ is the stream's delivery queue: the readLoop (deliverToStream,
	// through enqueueDelivery) puts each whole in-order message on it without
	// waiting, and Receive takes them. Its bound is the bounds profile's stream
	// credit, in the bytes recvQueue counts (messageCredit), and not a count of
	// messages, beside the session's and the peer's ceilings over every queue
	// (recvMemory). A message that does not fit ends the stream through overrun,
	// because the readLoop also answers PING and serves the control plane and
	// every other stream, so it cannot wait on this consumer, and the peer's
	// sender holds no aether credit that would stop it first. A queue is never
	// closed: its end is recvDone, which closeRecvOnce closes exactly once
	// (recvOnce) and Receive selects on, taking what recvQ still holds before
	// it returns the stream's end. handleOpen and OpenStream build both.
	recvQ    *recvQueue
	recvDone chan struct{}
	// endErr is the reason the stream ended, when it is not an ordinary end:
	// aether.ErrStreamOverrun after either side's delivery queue overran
	// (overrun here, the peer's RESET(ResetFlowCtrl) in handleReset), or
	// aether.ErrStreamRefused after the peer's RESET(ResetRefused). Receive
	// returns it, once recvQ is drained, where it would return io.EOF, and
	// Send returns it for a stream that can no longer send. setEnd keeps the
	// first reason; nil means io.EOF.
	endErr atomic.Pointer[error]
	// fragBuf takes a peer's fragments (DATA frames flagged
	// aether.FlagFRAGMENT) and refuses each against the session's fragRecv,
	// which has no realm. Touched only by the readLoop (deliverToStream).
	fragBuf  *FragmentBuffer
	observe  *reliability.ObserveEngine // ACK-observe metrics (no enforcement)
	localSeq uint32                     // monotonic counter (TCP doesn't set SeqNo)
	// sendRoom bounds the bytes this stream has between Send and the conn, in
	// messageCredit, at the bounds profile's stream credit. The transport's
	// backpressure reaches Send through it: a conn that stops taking bytes stops the
	// writeLoop, the scheduler fills, and the next Send waits (awaitSendRoom).
	// sendEnded closes (endSend) once the stream can send no more, releasing Sends
	// waiting for room that will not come.
	sendRoom    *semaphore.Weighted
	sendEnded   chan struct{}
	sendEndOnce sync.Once
	// mu makes Send's state check and its Enqueue one step against Close's
	// transition and Enqueue, so no DATA is queued behind the stream's CLOSE:
	// the peer's receive side ends at that CLOSE (handleClose) and would refuse
	// DATA behind it after Send had returned nil.
	mu       sync.Mutex
	connOnce sync.Once
	connView net.Conn // cached net.Conn wrapper
	recvOnce sync.Once
	// closeFrame is the CLOSE that Close queued, and closeWritten says the
	// writeLoop has written it (frameWritten); s.mu guards both. The stream stays
	// in the session until closeWritten and the peer's CLOSE have both come
	// (leaveIfEndedLocked), because the scheduler drops what a stream still has
	// queued when it unregisters, which would lose this side's DATA and its CLOSE
	// to a peer's CLOSE that arrives first.
	closeFrame   *aether.Frame
	closeWritten bool

	// incarnation names this stream among those that have used its ID on the
	// session, as this side states it: the opener's generation, from this session's
	// streamGenerations when this side opened it (OpenStream) and from the peer's
	// SYN when the peer did (handleOpen), with WriterOpened set when this side
	// opened it. Its CLOSE and RESET state it, and handleClose and handleReset end
	// the stream only for a frame that names it (namedBy): the peer writes its CLOSE
	// or RESET of a stream before it reads this side's RESET of it, so on the
	// ordered byte stream such a frame can follow this side's reopening of the ID,
	// and would otherwise end the new stream. Set before the stream is registered,
	// read-only after.
	incarnation aether.StreamIncarnation
}

// namedBy reports whether inc, read from a frame of the peer's, names this stream:
// the same generation, and the peer's WriterOpened the opposite of this side's.
func (st *tcpStream) namedBy(inc aether.StreamIncarnation) bool {
	return inc.Generation == st.incarnation.Generation && inc.WriterOpened != st.incarnation.WriterOpened
}

// closeRecvOnce ends the stream's receive side exactly once: it ends recvQ, so
// enqueueDelivery queues nothing more, and closes recvDone, on which Receive
// returns what recvQ still holds and then the stream's end (endError). Every
// termination path calls it (handleClose, handleReset, overrun, Reset, the
// OpenStream rollback, the stream GC through Reset), from the readLoop and from
// application goroutines, so recvOnce keeps the close idempotent.
func (st *tcpStream) closeRecvOnce() {
	st.recvOnce.Do(func() {
		st.recvQ.end()
		close(st.recvDone)
	})
}

// setEnd records why the stream ended when that is not an ordinary end
// (endErr). The first reason is kept, so a RESET the peer sends after this
// side's overrun does not replace this side's own reason.
func (st *tcpStream) setEnd(err error) {
	st.endErr.CompareAndSwap(nil, &err)
}

// endError is what Receive returns once the receive side has ended and recvQ
// is drained, and what Send returns for a stream that can no longer send: the
// recorded reason (endErr) with the stream's ID, or ordinary when none was
// recorded.
func (st *tcpStream) endError(ordinary error) error {
	if p := st.endErr.Load(); p != nil {
		return fmt.Errorf("stream %d: %w", st.streamID, *p)
	}
	return ordinary
}

// endSend releases every Send waiting on sendRoom for a stream that can send no
// more. Idempotent; handleReset, sendReset and leaveIfEndedLocked call it.
func (st *tcpStream) endSend() {
	st.sendEndOnce.Do(func() { close(st.sendEnded) })
}

// awaitSendRoom takes n bytes of the stream's room between Send and the conn,
// waiting while the scheduler holds as much as the bounds profile's stream credit
// allows. The wait runs under the caller's context, so a cancelled caller or a
// passed StreamConn deadline stops it, and for at most flow.ConsumeTimeout, Noise's
// wait for credit. Both of those end in flow.ErrCreditExhausted, the backpressure a
// caller reads on every profile; nothing has been queued. A session that closes or a
// stream that ends meanwhile returns what Send returns for that end, once the wait
// has seen it.
func (st *tcpStream) awaitSendRoom(ctx context.Context, n int64) error {
	if st.sendRoom.TryAcquire(n) {
		return nil
	}
	s := st.session
	wait, cancel := context.WithTimeout(ctx, flow.ConsumeTimeout)
	defer cancel()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-st.sendEnded:
			cancel()
		case <-s.CloseSignal():
			cancel()
		case <-stop:
		}
	}()
	err := st.sendRoom.Acquire(wait, n)
	switch {
	case err == nil:
		return nil
	case s.IsClosed():
		return s.closedError()
	case !st.state.CanSend():
		return st.endError(fmt.Errorf("stream %d: cannot send (state=%s)", st.streamID, st.state.State()))
	case ctx.Err() != nil:
		return fmt.Errorf("stream %d: %w: %w", st.streamID, flow.ErrCreditExhausted, ctx.Err())
	}
	return fmt.Errorf("stream %d: %w: the conn took nothing of %d queued bytes for %s",
		st.streamID, flow.ErrCreditExhausted, flow.CurrentBounds().StreamCredit, flow.ConsumeTimeout)
}

// enqueueDelivery puts one whole in-order message on the stream's delivery
// queue (recvQ) without waiting: the readLoop (deliverToStream) calls it, and
// the readLoop also answers PING and serves the control plane and every other
// stream, so it never waits on one stream's consumer. It returns true when the
// message is queued for Receive. It returns false in two cases. The receive
// side has already ended (the peer's CLOSE or RESET, this side's Reset or
// overrun), so the message is one the peer sent after its own end or after this
// side's RESET, which tells the peer the stream is gone. Or the message would
// take the queue past the bounds profile's stream credit, the session's queues past
// its session ceiling or the peer's past its per-peer ceiling, all in messageCredit
// (makeQueueRoom first discards a queue a RESET ended to make that room): the stream
// ends through overrun, which refuses this message and every later one with a RESET
// the sender reads as aether.ErrStreamOverrun, while the consumer still reads every
// message queued ahead of it. A stream that goes on loses no message: the sender holds
// no aether credit that would stop it short of the queue, so the refusal is how the
// queue's bound reaches the sender.
func (st *tcpStream) enqueueDelivery(payload []byte) bool {
	s := st.session
	bounds := flow.CurrentBounds()
	s.makeQueueRoom(recvItemCost(payload), bounds.SessionMemoryCeiling)
	switch st.recvQ.push(payload, bounds.StreamCredit, bounds.SessionMemoryCeiling) {
	case pushQueued:
		st.session.deliveryStats.recordDelivered(st.streamID)
		return true
	case pushEnded:
		return false
	}
	st.overrun(len(payload))
	return false
}

// overrun ends a stream whose delivery queue cannot take the next message the
// readLoop has for it (enqueueDelivery). It counts that message as having met
// a full queue and as dropped (DeliveryStats, which the consumer summing a
// session's stats reads), records aether.ErrStreamOverrun as the stream's end,
// ends the receive side, so Receive returns every message recvQ holds and then
// aether.ErrStreamOverrun, then writes the peer RESET(ResetFlowCtrl), which the
// peer's handleReset reads as aether.ErrStreamOverrun, and takes the stream out
// of the session (sendReset). The receive side ends first so the consumer's end
// does not wait on that write. It runs on the readLoop, whose RESET write is the
// same kind of write as its PONG and its refusal RESET (registerStream).
// No abuse is charged: an honest sender reaches it by sending faster than the
// consumer reads.
func (st *tcpStream) overrun(n int) {
	s := st.session
	s.deliveryStats.recordBackpressure(st.streamID)
	s.deliveryStats.recordDropped(st.streamID, n)
	st.setEnd(aether.ErrStreamOverrun)
	dbgTCP.Printf("enqueueDelivery: stream %d delivery queue full (%d bytes unread, next %d), resetting with ResetFlowCtrl",
		st.streamID, st.recvQ.queuedBytes(), n)
	st.closeRecvOnce()
	_ = st.sendReset(aether.ResetFlowCtrl)
}

// sendReset moves the stream to reset, writes RESET(reason) to the peer and
// takes the stream out of the session: s.streams, the scheduler and the stream
// GC (releaseStream), and both directional compressors' per-stream state, an
// unbounded map (codec_short.go Compressor.streams). Reset, the funnel for every
// local teardown (a direct Reset, the stream GC's idle reap, the acceptor's
// close), and overrun call it; it returns the RESET write's error. A stream that
// has already left the session writes nothing and touches nothing: the peer has
// finished with it, and a later stream may hold the ID, on both ends, which a
// RESET under that ID would end, and whose scheduler slot and map entry a
// release would take away.
func (st *tcpStream) sendReset(reason aether.ResetReason) error {
	s := st.session
	s.mu.Lock()
	cur, ok := s.streams[st.streamID]
	inSession := ok && cur == st
	s.mu.Unlock()
	if !inSession {
		return nil
	}
	st.state.Transition(aether.EventSendReset)
	st.endSend()
	payload := aether.EncodeResetPayload(aether.ResetPayload{Reason: reason, Incarnation: st.incarnation})
	err := s.writeFrame(&aether.Frame{
		SenderID:   s.LocalPeerID(),
		ReceiverID: s.RemotePeerID(),
		StreamID:   st.streamID,
		Type:       aether.TypeRESET,
		Length:     uint32(len(payload)),
		Payload:    payload,
	})
	s.mu.Lock()
	if cur, ok := s.streams[st.streamID]; ok && cur == st {
		delete(s.streams, st.streamID)
		s.releaseStream(st.streamID)
	}
	s.mu.Unlock()
	st.recvQ.peerEnded()
	s.trackEnded(st.recvQ)
	s.txCompressor.RemoveStream(st.streamID)
	s.rxCompressor.RemoveStream(st.streamID)
	return err
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
//
// remoteNodeID keys the per-peer memory ledger (peerMemoryLedgers), so it must
// be the identity conn's transport proved; a session whose remote ID is a label
// the remote stated is built through NewSessionForStatedPeer, which gives it a
// ledger of its own.
func NewTCPSession(conn net.Conn, localNodeID, remoteNodeID aether.NodeID, proto aether.Protocol, opts aether.SessionOptions) *TCPSession {
	return newTCPSession(conn, localNodeID, remoteNodeID, proto, opts, true)
}

// newTCPSession is NewTCPSession with the choice of per-peer memory ledger:
// sharedPeer joins the remote node ID's entry in peerMemoryLedgers, which every
// session to that node built under a proved ID shares, Noise sessions included;
// false gives the session a ledger of its own at the same ceiling
// (recvMemory.joinPeerMemory), for NewSessionForStatedPeer, whose caller holds
// only the ID the remote stated, so sharing it would let one peer fill another's
// room and send that node's streams a typed reset.
func newTCPSession(conn net.Conn, localNodeID, remoteNodeID aether.NodeID, proto aether.Protocol, opts aether.SessionOptions, sharedPeer bool) *TCPSession {
	opts = aether.NormalizeSessionOptions(opts)
	tc := aether.TransportClassForProtocol(proto)
	base := aether.NewBaseSession(localNodeID, remoteNodeID, proto)
	base.SetHealthMonitor(health.NewMonitor(0.2))
	base.SetIdleTimeouts(opts.SessionIdleTimeout, aether.DefaultSessionIdleTimeout)
	s := &TCPSession{
		BaseSession:   base,
		conn:          conn,
		layout:        aether.DefaultStreamLayout(),
		opts:          opts,
		classDefaults: aether.DefaultsForClass(tc),
		streams:       make(map[uint64]*tcpStream),
		sched:         scheduler.NewScheduler(),
		out:           newSessionWriter(conn, base.CloseSignal()),
		txCompressor:  aether.NewCompressor(), // encode-side state
		rxCompressor:  aether.NewCompressor(), // decode-side state
		tickStop:      make(chan struct{}),

		wireExchange:   newWireExchange(),
		prefaceWritten: make(chan struct{}),
		prefaceTimeout: wireVersionsPrefaceTimeout,
	}
	s.joinPeerMemory(remoteNodeID, sharedPeer)
	s.wireOffer, s.wireOfferErr = aether.LocalWireVersions(opts.WireVersions)
	// Per-peer abuse tracker — per-session registry by default,
	// overridable via SetAbuseScoreRegistry for cross-session scoring.
	// The tracker wraps the registry plus the threshold-breaker
	// GoAway + close hooks so reportAbuse stays a one-liner.
	s.abuseTracker = aether.NewAbuseTracker(
		abuse.New[aether.NodeID](abuse.DefaultConfig()),
		remoteNodeID,
		func(reason aether.GoAwayReason, msg string) error {
			return s.GoAway(context.Background(), reason, msg)
		},
		s.CloseWithError,
		dbgTCP.Printf,
	)
	// Per-StreamID accept dispatch + AcceptStream FIFO — shared
	// implementation in the root aether package. NonBlockingDrop: when the
	// FIFO is full the OPEN-frame handler drops the stream rather than hold
	// the readLoop, which runs handleOpen.
	s.acceptor = aether.NewStreamAcceptor(aether.StreamAcceptorConfig{
		Mode:      aether.NonBlockingDrop,
		Closed:    base.CloseSignal(),
		ErrClosed: aether.ErrSessionClosed,
	})
	// Stream GC — identical policy to Noise; exempts well-known stream
	// IDs 0-3 (control / keepalive).
	s.streamGC = aether.NewStreamGC(aether.DefaultStreamIdleTimeout, func(streamID uint64) {
		dbgTCP.Printf("StreamGC: resetting idle stream %d", streamID)
		s.mu.Lock()
		st, ok := s.streams[streamID]
		s.mu.Unlock()
		if !ok {
			return
		}
		// st.Reset deletes from s.streams, ends the receive side, releaseStream.
		_ = st.Reset(aether.ResetTimeout)
	})
	go s.streamGC.Start()

	// Clear any deadline the transport left armed on the conn during its
	// dial/handshake phase. Two known leak sources, both landing here:
	//   - WebSocket dial: gobwas/ws applies the dial context's deadline
	//     to the socket for the handshake and never clears it (the hijack
	//     dial in websocket/transport.go clears its own), so the socket
	//     carries the dialler's context deadline into the session.
	//   - WebSocket/TLS accept: a hijacked HTTP connection keeps whatever
	//     Read/Idle timeout the serving http.Server armed on it.
	// A TCPSession is long-lived and owns its liveness via the keepalive
	// stream + housekeepingTick idle eviction — readLoop blocks
	// indefinitely by design. A leftover deadline fires mid-session and
	// kills it at the dialler's context deadline (gobwas/ws leaves it armed
	// on the socket). Cleared once here, at the
	// single chokepoint every stream transport (WebSocket, TLS) funnels
	// through, so no transport can leak a deadline into a live session.
	_ = conn.SetDeadline(time.Time{})

	// The preface is the first thing written. Every frame write holds
	// writeMu, so taking it here and releasing it in writePreface, once the
	// preface write returns, orders the preface ahead of any frame whichever
	// goroutine writes first.
	s.writeMu.Lock()
	s.wireTimer.Store(time.AfterFunc(s.prefaceTimeout, func() {
		if s.finishWireVersions(aether.NegotiatedWireVersions{}, errWireVersionsPrefaceTimeout) {
			s.CloseWithError(errWireVersionsPrefaceTimeout)
		}
	}))
	go s.writePreface()
	go s.readLoop()
	go s.writeLoop()
	go s.housekeepingTick()
	return s
}

// writePreface writes this session's wire version preface, then releases
// the writeMu newTCPSession took. A malformed local offer writes nothing.
// A failed write ends the exchange, if it is still open, and closes the
// session. writeMu is released before any close so the close path's own
// frame writes cannot wait on it.
func (s *TCPSession) writePreface() {
	err := s.wireOfferErr
	if err == nil {
		err = aether.WriteWireVersionsPreface(s.out, s.wireOffer)
		if err != nil {
			err = fmt.Errorf("wire versions preface write: %w", err)
		}
	}
	s.writeMu.Unlock()
	close(s.prefaceWritten)
	if err != nil {
		s.finishWireVersions(aether.NegotiatedWireVersions{}, err)
		s.CloseWithError(err)
	}
}

// readPreface reads the peer's preface (bounded by
// aether.ReadWireVersionsPreface and wireVersionsPrefaceTimeout) and makes
// the choice from the two offers. It runs at the head of readLoop, so on a
// refusal no frame has been decoded and no stream exists.
func (s *TCPSession) readPreface() error {
	if s.wireOfferErr != nil {
		return s.wireOfferErr
	}
	peer, err := aether.ReadWireVersionsPreface(s.conn)
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return fmt.Errorf("wire versions preface: %w", err)
	}
	chosen, err := aether.ChooseWireVersions(s.wireOffer, peer)
	if err != nil {
		return err
	}
	// The grammar is set before readLoop decodes the peer's first frame,
	// which follows its preface on the conn, and before this side's writers
	// can choose a short form.
	s.rxCompressor.UseWireVersions(chosen)
	s.txCompressor.UseWireVersions(chosen)
	fragmentVersion, _ := chosen.Version(aether.WireVersionFragment)
	s.fragRecv = NewFragmentReceiver(fragmentVersion, 0, false, s.RemotePeerID())
	if !s.finishWireVersions(chosen, nil) {
		// The deadline or a close ended the exchange first.
		if r := s.wireResult.Load(); r != nil && r.err != nil {
			return r.err
		}
		return aether.ErrSessionClosed
	}
	return nil
}

// awaitWireVersions blocks until the preface exchange has ended (wireExchange).
// OpenStream calls it before creating any stream state.
func (s *TCPSession) awaitWireVersions(ctx context.Context) error {
	return s.awaitWire(ctx, s.CloseSignal())
}

// WireVersions returns the set the preface exchange chose (wireExchange.chosenWire).
func (s *TCPSession) WireVersions() aether.NegotiatedWireVersions {
	return s.chosenWire(s.CloseSignal())
}

// readLoop reads Aether frames from the TCP connection and dispatches to streams.
// Delegates the per-byte decode + short/full/batch dispatch to
// aether.ReadNextFrame so the Noise and TCP adapters share one decode
// implementation. Adapter-specific responsibilities stay here:
// structural validation gate + abuse-on-malformed + per-frame logging.
func (s *TCPSession) readLoop() {
	// exitErr carries the real ReadNextFrame failure (or nil on clean
	// EOF) into the deferred CloseWithError, so [SESSION-CLOSE]
	// reason= surfaces the actual transport/decode error instead of a
	// generic "readLoop exited" placeholder that masked the cause. It is the
	// close reason only if this close is the first: a session that has already
	// closed for a reason (failWrite) keeps it, and the conn's close is what ended
	// this read.
	var exitErr error
	defer func() { s.CloseWithError(exitErr) }()
	if err := s.readPreface(); err != nil {
		dbgTCP.Printf("readLoop: preface refused err=%v remote=%s", err, s.RemoteNodeID().Short())
		s.finishWireVersions(aether.NegotiatedWireVersions{}, err)
		// Let this side's own preface reach the peer before the conn closes,
		// so the peer reads both offers and reaches the same refusal rather
		// than a bare end of stream.
		select {
		case <-s.prefaceWritten:
		case <-s.CloseSignal():
		case <-time.After(s.prefaceTimeout):
		}
		exitErr = err
		return
	}
	for {
		frame, _, batch, err := aether.ReadNextFrame(s.conn, s.rxCompressor) // decode-side state
		if err != nil {
			dbgTCP.Printf("readLoop: EXIT err=%v remote=%s", err, s.RemoteNodeID().Short())
			if err != io.EOF {
				exitErr = err
			}
			return
		}
		if batch != nil {
			for _, f := range batch {
				// Batched sub-frames are decoded by the short-header
				// decoders (codec_short.go), which skip
				// Frame.Validate() — the same gap the single-frame path
				// guards below. Without a per-sub-frame gate a peer could
				// smuggle unknown Type bytes, oversize Length, or
				// payload/length mismatches into dispatchFrame inside a
				// 0x85 batch AND evade the ReasonMalformedFrame abuse
				// signal. Cross-adapter parity with the Noise adapter's
				// processIncomingFrame batch loop.
				if err := f.Validate(); err != nil {
					dbgTCP.Printf("readLoop: batch sub-frame validate failed: %v", err)
					s.reportAbuse(abuse.ReasonMalformedFrame)
					continue
				}
				s.Health().RecordActivity()
				s.dispatchFrame(f)
			}
			continue
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

		s.Health().RecordActivity()
		dbgTCP.Printf("readLoop: RX type=%d stream=%d len=%d flags=0x%02x", frame.Type, frame.StreamID, frame.Length, frame.Flags)
		s.dispatchFrame(frame)
	}
}

// dispatchFrame routes an incoming frame to the appropriate stream.
func (s *TCPSession) dispatchFrame(frame *aether.Frame) {
	// Record stream activity for GC — any frame type counts as
	// activity on its stream (OPEN/DATA/CLOSE/RESET/etc.). This
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
	case aether.TypePING:
		s.handlePing(frame)
	case aether.TypePONG:
		s.handlePong(frame)
	case aether.TypeGOAWAY:
		s.handleGoAway(frame)
	case aether.TypeACK, aether.TypeWINDOW, aether.TypeCONGESTION:
		// The transport owns reliability, flow control and congestion on this
		// profile, so nothing here reads what these frames carry.
	case aether.TypePRIORITY:
		s.handlePriority(frame)
	}
}

func (s *TCPSession) deliverToStream(frame *aether.Frame) {
	s.mu.Lock()
	st, ok := s.streams[frame.StreamID]
	// A SYN under the ID of a stream both sides have closed is the peer's next
	// stream: it reopens the ID only after reading this side's CLOSE, and the
	// writeLoop that wrote that CLOSE may not have run frameWritten yet, so the
	// finished stream goes now and the SYN opens the new one. The compressors'
	// state for the ID carries over, since this frame has just refreshed it.
	if ok && frame.Flags.Has(aether.FlagSYN) && st.state.State() == aether.StreamClosed {
		delete(s.streams, frame.StreamID)
		s.releaseStream(frame.StreamID)
		ok = false
	}
	s.mu.Unlock()
	// A SYN frame opens its stream and carries no message (aether.FlagSYN): its
	// payload is the OPEN payload, which handleOpen reads, and a live stream stays
	// as it is, so those bytes never reach its consumer as a message.
	if frame.Flags.Has(aether.FlagSYN) {
		s.handleOpen(frame)
		return
	}
	if !ok {
		dbgTCP.Printf("deliverToStream: no stream for ID=%d, dropping %d bytes", frame.StreamID, frame.Length)
		return // unknown stream, drop
	}
	// A fragment is never delivered as message bytes: the session has no
	// realm, so the buffer refuses it.
	if frame.IsFragment() {
		if st.fragBuf == nil {
			st.fragBuf = NewFragmentBuffer() // a stream built outside the open paths
		}
		_, _, err := st.fragBuf.Add(s.fragRecv, st.streamID, frame.Payload)
		dbgTCP.Printf("deliverToStream: stream %d fragment refused: %v", frame.StreamID, err)
		return
	}
	// Queue the payload for the stream's consumer without waiting
	// (enqueueDelivery), so a slow consumer on this stream never holds the
	// readLoop, which keeps serving gossip, keepalive, control and every other
	// stream; a full queue ends this stream with a typed reset instead. A
	// stream whose receive side ended between the lookup above and this call
	// (a Reset on another goroutine) refuses the payload.
	accepted := st.enqueueDelivery(frame.Payload)
	if accepted {
		// ACK-observe: track metrics (no wire ACK, no retransmit). Runs only
		// on the readLoop, so localSeq stays single-threaded.
		if st.observe != nil {
			seqNo := frame.SeqNo
			if seqNo == 0 {
				st.localSeq++
				seqNo = st.localSeq
			}
			st.observe.RecordReceive(seqNo, len(frame.Payload), time.Now())
		}
		if frame.StreamID == 0 {
			dbgTCP.Printf("deliverToStream: enqueued %d bytes for stream 0 (gossip)", len(frame.Payload))
		}
	} else {
		dbgTCP.Printf("deliverToStream: refused frame for stream %d (%d bytes, receive side ended or delivery queue full)", frame.StreamID, len(frame.Payload))
	}
}

// registerStream performs an atomic check-and-insert for a freshly-constructed
// tcpStream. When enforceRemoteCap is true and MaxConcurrentStreams would be
// exceeded, sends RESET(ResetRefused) and returns nil — the caller drops the
// frame. The check and the map write happen under a single s.mu.Lock so
// concurrent peer OPENs cannot race past the cap. Each refusal counts in
// streamRefused and charges abuse.ReasonStreamRefused.
func (s *TCPSession) registerStream(st *tcpStream, enforceRemoteCap bool) *tcpStream {
	s.mu.Lock()
	if existing, ok := s.streams[st.streamID]; ok {
		s.mu.Unlock()
		return existing // duplicate peer OPEN for open stream — return existing
	}
	// MaxConcurrentStreams cap applies to BOTH locally-initiated and
	// peer-initiated stream opens. enforceRemoteCap=true means
	// peer-initiated → on refusal, send a RESET so the peer gives up;
	// enforceRemoteCap=false means locally-initiated → return nil and
	// let the caller surface ErrStreamCapExhausted.
	{
		cap := s.opts.MaxConcurrentStreams
		if cap <= 0 {
			cap = DefaultTCPMaxConcurrentStreams
		}
		if len(s.streams) >= cap {
			s.mu.Unlock()
			atomic.AddUint64(&s.streamRefused, 1)
			s.reportAbuse(abuse.ReasonStreamRefused)
			if enforceRemoteCap {
				s.sendRefused(st.streamID, st.incarnation.Generation)
			}
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

// sendRefused answers a stream the peer opened and this side will not admit, with
// RESET(ResetRefused), which the peer's handleReset reads as aether.ErrStreamRefused.
// It names the stream by the generation the peer's SYN stated, so it ends that
// stream and no later one under the ID.
func (s *TCPSession) sendRefused(streamID, generation uint64) {
	payload := aether.EncodeResetPayload(aether.ResetPayload{
		Reason:      aether.ResetRefused,
		Incarnation: aether.StreamIncarnation{Generation: generation},
	})
	s.writeFrame(&aether.Frame{
		SenderID:   s.LocalPeerID(),
		ReceiverID: s.RemotePeerID(),
		StreamID:   streamID,
		Type:       aether.TypeRESET,
		Length:     uint32(len(payload)),
		Payload:    payload,
	})
}

// unregisterStream undoes registerStream — removes the stream from the
// session map and the GC tracker. Paired rollback for OpenStream's
// commit/rollback flow when a post-registration step (writeFrame, etc.)
// fails. Idempotent; safe to call even if the stream was never inserted.
func (s *TCPSession) unregisterStream(streamID uint64) {
	s.mu.Lock()
	delete(s.streams, streamID)
	s.mu.Unlock()
	s.releaseStream(streamID)
}

// StreamRefusedCount returns the number of peer-initiated stream opens
// rejected because MaxConcurrentStreams was reached.
func (s *TCPSession) StreamRefusedCount() uint64 {
	return atomic.LoadUint64(&s.streamRefused)
}

// handleOpen admits a stream the peer opened, by an OPEN frame or a DATA frame
// flagged aether.FlagSYN (deliverToStream), which is how OpenStream writes it. A
// payload that is not an OPEN payload, or one stating a generation of zero or above
// aether.MaxStreamGeneration, which names no stream, is refused with
// RESET(ResetRefused) and an abuse charge and keeps no state: the peer has written
// bytes this side cannot read as what the frame says they are. A duplicate leaves
// the stream in place as it is.
func (s *TCPSession) handleOpen(frame *aether.Frame) {
	dbgTCP.Printf("handleOpen: stream=%d", frame.StreamID)
	s.mu.Lock()
	_, live := s.streams[frame.StreamID]
	s.mu.Unlock()
	if live {
		return
	}
	// The payload's InitialCredit is not read: on a byte-stream session the
	// transport owns flow control, and the stream keeps no aether credit.
	payload := aether.DecodeOpenPayload(frame.Payload)
	if len(frame.Payload) != aether.OpenPayloadSize || !aether.ValidStreamGeneration(payload.Generation) {
		atomic.AddUint64(&s.streamRefused, 1)
		s.reportAbuse(abuse.ReasonStreamRefused)
		s.sendRefused(frame.StreamID, payload.Generation)
		return
	}
	candidate := &tcpStream{
		streamID: frame.StreamID,
		config: aether.StreamConfig{
			StreamID:    frame.StreamID,
			Reliability: payload.Reliability,
			Priority:    payload.Priority,
			Dependency:  payload.Dependency,
		},
		session:   s,
		state:     aether.NewStreamStateMachine(),
		recvQ:     s.newQueue(),
		recvDone:  make(chan struct{}),
		fragBuf:   NewFragmentBuffer(),
		observe:   reliability.NewObserveEngine(),
		sendRoom:  semaphore.NewWeighted(flow.CurrentBounds().StreamCredit),
		sendEnded: make(chan struct{}),
	}
	candidate.incarnation = aether.StreamIncarnation{Generation: payload.Generation}
	st := s.registerStream(candidate, true /* enforceRemoteCap */)
	if st == nil {
		dbgTCP.Printf("handleOpen: refused stream=%d (cap reached)", frame.StreamID)
		return
	}
	// registerStream returns the pre-existing stream when a local OpenStream of the
	// ID took it after the check above; only advance state + notify acceptor when
	// we actually inserted, so the same stream is never delivered twice to a waiter
	// / acceptCh.
	if st != candidate {
		return
	}
	st.state.Transition(aether.EventRecvOpen)

	s.sched.Register(frame.StreamID, payload.Priority, payload.Dependency)

	s.notifyStreamAccepted(st)
}

// notifyStreamAccepted hands a freshly-accepted stream to the shared
// StreamAcceptor. The acceptor picks between a pinned ByID waiter, a
// per-ID backlog slot, or the internal FIFO that AcceptStream drains.
// Called by handleOpen, the path that produces a remotely-initiated stream.
func (s *TCPSession) notifyStreamAccepted(st *tcpStream) {
	s.acceptor.Notify(st)
}

// handleClose ends the stream's receive side at the peer's CLOSE: the messages
// queued before it stay in recvQ, and Receive returns them and then io.EOF
// without waiting for a local Close; enqueueDelivery refuses whatever comes
// after it. This side can still Send until its own Close. The stream leaves the
// session here only if this side's CLOSE is already written; otherwise
// frameWritten takes it out after writing that CLOSE. The compressors' state for
// the stream stays until the leave, since this side may still be sending on it.
// A CLOSE naming another stream than the one under the ID (tcpStream.incarnation)
// ends nothing and leaves the compressors' state alone: it is the CLOSE of a stream
// this side has reset, written before the peer read that RESET.
func (s *TCPSession) handleClose(frame *aether.Frame) {
	s.mu.Lock()
	st, ok := s.streams[frame.StreamID]
	if !ok {
		s.mu.Unlock()
		s.txCompressor.RemoveStream(frame.StreamID) // both directional compressors hold per-stream state
		s.rxCompressor.RemoveStream(frame.StreamID)
		return
	}
	if !st.namedBy(aether.DecodeClosePayload(frame.Payload)) {
		s.mu.Unlock()
		return
	}
	st.state.Transition(aether.EventRecvFIN)
	left := s.leaveIfEndedLocked(st)
	s.mu.Unlock()

	st.closeRecvOnce()
	if left {
		s.txCompressor.RemoveStream(frame.StreamID)
		s.rxCompressor.RemoveStream(frame.StreamID)
	}
}

// frameWritten is what the writeLoop does after a frame has gone to the conn: a
// DATA frame gives its room back to its stream's Send (releaseSendRoom), and a
// stream's CLOSE, the last frame the stream has in the scheduler because Close
// and Send are ordered by st.mu, lets the stream leave once the peer's CLOSE has
// also come. closeFrame identifies the frame, so a CLOSE of a stream that was
// reset while the writeLoop held it does nothing to a later stream under the ID.
func (s *TCPSession) frameWritten(frame *aether.Frame) {
	s.releaseSendRoom(frame)
	if frame.Type != aether.TypeCLOSE {
		return
	}
	s.mu.Lock()
	st, ok := s.streams[frame.StreamID]
	if !ok || st.closeFrame != frame {
		s.mu.Unlock()
		return
	}
	st.closeWritten = true
	left := s.leaveIfEndedLocked(st)
	s.mu.Unlock()
	if left {
		s.txCompressor.RemoveStream(frame.StreamID)
		s.rxCompressor.RemoveStream(frame.StreamID)
	}
}

// leaveIfEndedLocked takes st out of s.streams, the scheduler and the stream GC
// when both sides have closed it and this side's CLOSE is written, and reports
// whether it did. handleClose and frameWritten call it with s.mu held, whichever
// comes last, and hold it across the release so that an OpenStream of the same ID
// registers after it and keeps its scheduler slot. A consumer still holding the
// stream goes on reading what recvQ holds.
func (s *TCPSession) leaveIfEndedLocked(st *tcpStream) bool {
	if !st.closeWritten || st.state.State() != aether.StreamClosed {
		return false
	}
	delete(s.streams, st.streamID)
	s.releaseStream(st.streamID)
	st.endSend()
	st.recvQ.leftSession()
	s.trackEnded(st.recvQ)
	return true
}

// handleReset ends the stream the peer's RESET names (tcpStream.incarnation). A
// RESET naming another stream than the one under the ID, written by the peer before
// it read this side's own RESET of that stream, ends nothing and leaves the
// compressors' state alone. A RESET flagged aether.FlagACK is a Full-profile
// session's acknowledgment, which no TCP-family peer writes, since the transport
// delivers every RESET once in order; it is not a RESET and changes nothing.
func (s *TCPSession) handleReset(frame *aether.Frame) {
	if frame.Flags.Has(aether.FlagACK) {
		return
	}
	payload := aether.DecodeResetPayload(frame.Payload)
	s.mu.Lock()
	st, ok := s.streams[frame.StreamID]
	if ok && !st.namedBy(payload.Incarnation) {
		s.mu.Unlock()
		return
	}
	if ok {
		// The peer's reason and the stream's state come first, ahead of the release:
		// the scheduler's dropped frames give their room back to a Send waiting for
		// it, which then reads CanSend and endErr (Receive after the messages recvQ
		// holds, and Send, name it). A refusal (the peer's registerStream cap) is
		// aether.ErrStreamRefused, the peer's full delivery queue (overrun)
		// aether.ErrStreamOverrun. Every other reason ends the stream as io.EOF.
		switch payload.Reason {
		case aether.ResetRefused:
			st.setEnd(aether.ErrStreamRefused)
		case aether.ResetFlowCtrl:
			st.setEnd(aether.ErrStreamOverrun)
		}
		st.state.Transition(aether.EventRecvReset)
		st.endSend()
		delete(s.streams, frame.StreamID)
		s.releaseStream(frame.StreamID)
	}
	s.mu.Unlock()
	s.txCompressor.RemoveStream(frame.StreamID) // both directional compressors hold per-stream state
	s.rxCompressor.RemoveStream(frame.StreamID)
	if ok {
		st.closeRecvOnce()
		st.recvQ.peerEnded()
		s.trackEnded(st.recvQ)
	}
}

// releaseStream idempotently unregisters streamID from the scheduler
// and stream GC. Parity with NoiseSession.releaseStream — gives every
// teardown path one helper to call instead of duplicating the pair. Callers
// may hold s.mu: neither takes it, and StreamGC runs its reset outside its lock.
// Frames the scheduler drops here give their room back, which lets a Send waiting
// on it find the stream has ended.
func (s *TCPSession) releaseStream(streamID uint64) {
	dropped, _ := s.sched.Unregister(streamID)
	for _, frame := range dropped {
		s.releaseSendRoom(frame)
	}
	if s.streamGC != nil {
		s.streamGC.Unregister(streamID)
	}
}

// releaseSendRoom gives back the room a frame took on its stream's sendRoom, once.
// A frame Send did not charge (a CLOSE) has none.
func (s *TCPSession) releaseSendRoom(frame *aether.Frame) {
	if v, ok := s.queuedFrames.LoadAndDelete(frame); ok {
		q := v.(queuedFrame)
		q.st.sendRoom.Release(q.cost)
	}
}

// closedError is what Send and Receive return for a closed session: the typed reason
// when the session could not write (aether.ErrSessionWriteFailed), since a message
// Send accepted may be among what was lost, and aether.ErrSessionClosed otherwise.
func (s *TCPSession) closedError() error {
	if err := s.CloseErr(); errors.Is(err, aether.ErrSessionWriteFailed) {
		return err
	}
	return aether.ErrSessionClosed
}

// controlHandler returns a ControlFrameHandler bound to this session's
// scheduler, health monitor and frame writer, for PING, PONG and PRIORITY. It
// has no window to serve: this session's dispatchFrame never calls
// HandleWindowUpdate, the one method that reads ConnWindow.
// WakeScheduler is false because the TCP writeLoop runs on a 2 ms
// ticker rather than blocking on Consume, so no writer waits for a wake.
func (s *TCPSession) controlHandler() *aether.ControlFrameHandler {
	return &aether.ControlFrameHandler{
		HealthMon:         s.Health(),
		Sched:             s.sched,
		Writer:            s.writeFrame,
		Sender:            s.LocalPeerID(),
		Receiver:          s.RemotePeerID(),
		KeepaliveStreamID: s.layout.Keepalive,
		WakeScheduler:     false,
	}
}

func (s *TCPSession) handlePing(frame *aether.Frame) {
	s.controlHandler().HandlePing(frame)
}

func (s *TCPSession) handlePong(frame *aether.Frame) {
	s.controlHandler().HandlePong(frame)
}

func (s *TCPSession) handleGoAway(frame *aether.Frame) {
	aether.HandleGoAwayFrame(s.CloseWithError, s.RemoteNodeID().Short(), "TCP", frame)
}

func (s *TCPSession) handlePriority(frame *aether.Frame) {
	s.controlHandler().HandlePriority(frame)
}

// DeliveryStats exposes the session's receive-path delivery counters to
// the consumer that sums a session's stats; cross-adapter parity with
// NoiseSession.DeliveryStats. The
// returned pointer is stable for the session's lifetime — callers can
// sample Delivered / Dropped / Backpressure / BytesDropped via Load()
// at monitoring cadence without holding any session lock.
func (s *TCPSession) DeliveryStats() *DeliveryStats {
	return &s.deliveryStats
}

// writeLoop reads from the scheduler and writes frames to the TCP connection.
// When multiple frames are queued, they're batched into a single write (0x85).
// A short ticker (2ms) provides batching window — gives the scheduler a
// chance to accumulate frames for coalescing — but the loop also consumes
// the wake channel so it serves bursty traffic with minimal latency.
//
// A write that fails ends the session (failWrite): sessionWriter has already
// retried a temporary error, and the transport carries frames in one sequence with
// no retransmit, so the frame is lost and the conn's framing may be cut mid-frame.
func (s *TCPSession) writeLoop() {
	ticker := time.NewTicker(2 * time.Millisecond)
	defer ticker.Stop()
	wake := s.sched.WakeCh()
	for {
		select {
		case <-s.CloseSignal():
			return
		case <-ticker.C:
		case <-wake:
		}

		frame, _ := s.sched.Dequeue()
		// isProbe is irrelevant for the TCP transport — TCP has its own
		// kernel-level flow control and aether's cwnd is not enforced
		// here. The signature is the scheduler's, kept consistent so a
		// single call site doesn't have to special-case Dequeue per
		// transport.
		if frame == nil {
			continue
		}

		// Check for batch opportunity — coalesce up to 16 queued frames.
		// Skip batching when the head frame is stream-0 (gossip): gossip
		// frames are already ~64KB max-size chunks, so batching gains
		// nothing in compression but extends the writeMu hold and HoL-
		// blocks stream-1 (RPC). Releasing writeMu after every gossip
		// frame lets stream-1 interleave instead of waiting for a 16-
		// frame snapshot burst to drain. Skipping stream-0 batching
		// gives per-frame fairness on the one shared writeMu; a
		// writeLoop per class would give the same without the per-frame
		// release.
		// A batch is itself a short form (0x85), so only a session whose
		// grammar has the short forms coalesces.
		if s.opts.HeaderComp && s.txCompressor.ShortForms() && frame.StreamID != 0 && s.sched.Len() > 0 {
			batch := []*aether.Frame{frame}
			for s.sched.Len() > 0 && len(batch) < 16 {
				next, _ := s.sched.Dequeue()
				if next == nil {
					break
				}
				batch = append(batch, next)
			}
			if len(batch) > 1 {
				s.writeMu.Lock()
				_, err := s.txCompressor.EncodeBatch(s.out, batch) // encode-side state
				s.writeMu.Unlock()
				if err != nil {
					dbgTCP.Printf("writeLoop: batch err=%v count=%d", err, len(batch))
					s.failWrite(err)
					return
				}
				for _, written := range batch {
					s.frameWritten(written)
				}
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
			s.failWrite(err)
			return
		}
		s.frameWritten(frame)
	}
}

// writeFrame serializes and writes a single frame to the TCP connection.
// With opts.HeaderComp it takes a short form when the TX Compressor admits
// one, which it does only on a session whose chosen set has frame.short.
func (s *TCPSession) writeFrame(frame *aether.Frame) error {
	err := s.encodeFrame(frame)
	if err != nil && s.out.failed() {
		s.failWrite(err)
	}
	return err
}

// encodeFrame is writeFrame's encoding under writeMu. writeFrame's failure path runs
// outside it, because the close path's own frame writes take writeMu.
func (s *TCPSession) encodeFrame(frame *aether.Frame) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if s.opts.HeaderComp {
		// All encoding goes through the TX-side compressor state (txCompressor).
		// Control frames: PING/PONG/CLOSE/RESET → 4 bytes
		if s.txCompressor.ShouldCompressControl(frame) {
			_, err := s.txCompressor.EncodeControlShort(s.out, frame)
			return err
		}
		// ACK frames → 11 bytes (lite) or 3+N (full)
		if s.txCompressor.ShouldCompressACK(frame) {
			_, err := s.txCompressor.EncodeACKShort(s.out, frame)
			return err
		}
		// DATA frames → 6-9 bytes
		if s.txCompressor.ShouldCompressData(frame) {
			if frame.Length <= 127 {
				_, err := s.txCompressor.EncodeDataShortVar(s.out, frame)
				return err
			}
			_, err := s.txCompressor.EncodeDataShort(s.out, frame)
			return err
		}
	}

	// Full frame: discriminator and 50-byte header.
	_, err := aether.EncodeFrame(s.out, frame)
	if err == nil {
		s.txCompressor.RecordFullHeader(frame) // encode-side state
	}
	return err
}

// failWrite ends the session on a write that failed (aether.ErrSessionWriteFailed). A
// frame the encoder refused before any byte reached the conn ends it too: the frame
// was accepted and it is lost. CloseWithError writes through writeFrame in turn, which
// its own once-only gate leaves harmless.
func (s *TCPSession) failWrite(err error) {
	s.CloseWithError(fmt.Errorf("%w: %w", aether.ErrSessionWriteFailed, err))
}

// ────────────────────────────────────────────────────────────────────────────
// Session interface implementation
// ────────────────────────────────────────────────────────────────────────────

func (s *TCPSession) OpenStream(ctx context.Context, cfg aether.StreamConfig) (aether.Stream, error) {
	select {
	case <-s.CloseSignal():
		if err := s.wireRefusal(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("session closed")
	default:
	}
	// No stream exists before the wire versions are chosen: a refused peer
	// returns the refusal here and the session holds nothing to tear down.
	if err := s.awaitWireVersions(ctx); err != nil {
		return nil, err
	}

	st := &tcpStream{
		streamID:  cfg.StreamID,
		config:    cfg,
		session:   s,
		state:     aether.NewStreamStateMachine(),
		recvQ:     s.newQueue(),
		recvDone:  make(chan struct{}),
		fragBuf:   NewFragmentBuffer(),
		observe:   reliability.NewObserveEngine(),
		sendRoom:  semaphore.NewWeighted(flow.CurrentBounds().StreamCredit),
		sendEnded: make(chan struct{}),
		incarnation: aether.StreamIncarnation{
			Generation:   s.streamGenerations.Add(1),
			WriterOpened: true,
		},
	}
	st.state.Transition(aether.EventSendOpen)

	// Locally-initiated open. registerStream(false) enforces the
	// MaxConcurrentStreams cap but skips the peer-side RESET. Surface
	// the typed sentinel ErrStreamCapExhausted so pool/dispatch
	// callers can detect cap-hit via errors.Is and back off rather
	// than closing the session.
	// registerStream has a tri-state return — nil on cap-hit, the
	// PRE-EXISTING stream when cfg.StreamID is still live in s.streams
	// (duplicate), or st on a fresh insert. A duplicate must not proceed
	// with the detached, never-mapped st: the rollback defer below would
	// delete the live map entry, RegisterWithClass would overwrite its
	// scheduler slot, and inbound DATA would route to the original stream
	// while the returned st's recvQ never fills. Compare identity and
	// error out — matching handleOpen's `st != candidate` guard — BEFORE
	// the rollback defer is armed so no cleanup touches the pre-existing
	// stream.
	registered := s.registerStream(st, false)
	if registered == nil {
		cap := s.opts.MaxConcurrentStreams
		if cap <= 0 {
			cap = DefaultTCPMaxConcurrentStreams
		}
		return nil, fmt.Errorf("OpenStream cap=%d: %w", cap, aether.ErrStreamCapExhausted)
	}
	if registered != st {
		// Duplicate still-live StreamID (e.g. a pool recycling an ID
		// before the prior stream closed). The pre-existing stream is
		// untouched; never return a detached, dead stream.
		return nil, fmt.Errorf("OpenStream stream=%d: %w", cfg.StreamID, aether.ErrDuplicateStreamID)
	}

	// committed flips to true after every post-registration step succeeds.
	// Until then, the deferred rollback unwinds every side-effect that
	// registerStream + scheduler.Register + writeFrame installed. A (nil, err) return that left the map entry and the GC and
	// scheduler registrations in place would
	// leave a stream no caller holds in s.streams until the stream GC's idle
	// sweep resets it, counted against MaxConcurrentStreams by registerStream
	// the whole while.
	committed := false
	defer func() {
		if committed {
			return
		}
		s.unregisterStream(cfg.StreamID)
		st.closeRecvOnce()
	}()

	// Propagate cfg.LatencyClass — parity with the noise adapter so a
	// caller's explicit class isn't silently dropped to ClassBULK.
	// ClassUnset (zero value) → DefaultLatencyClass(streamID).
	classOpen := cfg.LatencyClass
	if classOpen == aether.ClassUnset {
		classOpen = aether.DefaultLatencyClass(cfg.StreamID)
	}
	s.sched.RegisterWithClass(cfg.StreamID, cfg.Priority, cfg.Dependency, classOpen)

	// The stream opens with a DATA frame flagged aether.FlagSYN, whose payload is
	// the OPEN payload (reliability, priority, dependency, generation); the peer's
	// handleOpen decodes it to configure the stream and name it. Its InitialCredit is
	// zero, the value that states no aether stream credit: on a byte-stream session
	// the transport owns flow control, and handleOpen does not read the field.
	openPayload := aether.EncodeOpenPayload(aether.OpenPayload{
		Reliability: cfg.Reliability,
		Priority:    cfg.Priority,
		Dependency:  cfg.Dependency,
		Generation:  st.incarnation.Generation,
	})
	frame := &aether.Frame{
		SenderID:   s.LocalPeerID(),
		ReceiverID: s.RemotePeerID(),
		StreamID:   cfg.StreamID,
		Type:       aether.TypeDATA,
		Flags:      aether.FlagSYN,
		Length:     uint32(len(openPayload)),
		Payload:    openPayload,
	}
	if err := s.writeFrame(frame); err != nil {
		return nil, fmt.Errorf("send SYN+DATA: %w", err)
	}

	committed = true
	return st, nil
}

// AcceptStream delegates to the shared aether.StreamAcceptor, which owns
// the FIFO channel and the per-StreamID dispatch for every adapter. See
// stream_acceptor.go for the underlying drain order (waiter → backlog
// → FIFO).
func (s *TCPSession) AcceptStream(ctx context.Context) (aether.Stream, error) {
	dbgTCP.Printf("AcceptStream: waiting...")
	st, err := s.acceptor.Accept(ctx)
	if err == nil {
		if ts, ok := st.(*tcpStream); ok {
			dbgTCP.Printf("AcceptStream: got stream=%d", ts.streamID)
		}
	} else if werr := s.wireRefusal(); werr != nil {
		return nil, werr
	}
	return st, err
}

// AcceptStreamByID delegates to the shared aether.StreamAcceptor. See
// the Session interface comment + stream_acceptor.go for the
// architectural rationale — the per-StreamID dispatch lives in the
// root aether package so the Noise, TCP, and QUIC adapters share one
// implementation rather than each maintaining its own copy.
func (s *TCPSession) AcceptStreamByID(ctx context.Context, streamID uint64) (aether.Stream, error) {
	st, err := s.acceptor.AcceptByID(ctx, streamID)
	if err != nil {
		if werr := s.wireRefusal(); werr != nil {
			return nil, werr
		}
	}
	return st, err
}

// Identity / Capabilities / Protocol accessors are promoted from the
// embedded *BaseSession. Ping is below.

// Ping sends a PING frame and waits for inbound activity (PONG or any
// other frame) before reporting RTT. Delegates to
// aether.WaitForActivityPing for the polling loop — see that helper
// for the zombie-session detection rationale.
func (s *TCPSession) Ping(ctx context.Context) (time.Duration, error) {
	return aether.WaitForActivityPing(ctx, s.Health(), s.CloseSignal(), func(seqNo uint32) error {
		return s.writeFrame(&aether.Frame{
			SenderID:   s.LocalPeerID(),
			ReceiverID: s.RemotePeerID(),
			StreamID:   s.layout.Keepalive,
			Type:       aether.TypePING,
			SeqNo:      seqNo,
		})
	})
}

func (s *TCPSession) GoAway(ctx context.Context, reason aether.GoAwayReason, message string) error {
	return aether.SendGoAway(s.writeFrame, s.LocalPeerID(), s.RemotePeerID(), s.layout.Control, reason, message)
}

func (s *TCPSession) Close() error {
	return s.CloseWithError(nil)
}

func (s *TCPSession) CloseWithError(err error) error {
	if !s.SignalClose() {
		return nil
	}
	if err != nil {
		s.SetCloseErr(err)
	}
	// A close before the preface exchange ended ends it, releasing every
	// waiter and stopping the deadline timer.
	s.finishWireVersions(aether.NegotiatedWireVersions{}, aether.ErrSessionClosed)
	s.leavePeerMemory(s.RemoteNodeID())
	// Capture the caller chain so the FIRST closer in a close
	// cascade is identifiable. Frame 0 is this closure, 1 is
	// CloseWithError; frames 2-5 are the actual callers — readLoop
	// defer, stall detector, idle watchdog, the ORBTR dedup/multipath
	// layer, or transport accept-full.
	callerChain := aether.CaptureCallerChain(2, 4)
	// Log EVERY close, including a clean nil Close: the dedup/multipath
	// layer above closes a losing session with a nil error, and a log of
	// error closes alone would show only the readLoop-exit close that
	// follows on the peer, not the close that started the churn. The
	// callers= chain names whoever triggered the close.
	reason := "clean(nil)"
	if err != nil {
		reason = err.Error()
	}
	log.Printf("[SESSION-CLOSE] %s peer=%s reason=%q callers=%s",
		s.Protocol(), s.RemoteNodeID().Short(), reason, callerChain)
	if s.tickStop != nil {
		// Non-blocking close: housekeepingTick watches both this
		// and the BaseSession close-signal so either signal stops it.
		select {
		case <-s.tickStop:
		default:
			close(s.tickStop)
		}
	}
	if s.streamGC != nil {
		s.streamGC.Stop()
	}
	// Release any AcceptStreamByID waiters and unparked backlog
	// streams so blocked callers return ErrSessionClosed instead of
	// deadlocking. Backlog streams are reset because their config /
	// recvQ is otherwise orphaned — nobody else will ever pick
	// them up after close. The acceptor surfaces drained backlog
	// streams; the adapter calls Reset because the transport-
	// specific teardown lives here.
	if s.acceptor != nil {
		for _, st := range s.acceptor.Close() {
			_ = st.Reset(aether.ResetCancel)
		}
	}
	s.conn.Close()
	return nil
}

// housekeepingTick runs the protocol-agnostic periodic maintenance
// that NoiseSession's reliabilityTick does (minus the Noise-specific
// reliability work). Two concerns per tick:
//
//  1. **Idle session eviction** — session with no inbound activity for
//     `opts.SessionIdleTimeout` is closed so goroutines + memory are
//     reclaimed. Matches the Noise adapter's policy exactly.
//  2. **Keepalive nudge** — TCP relies on native keepalive which the
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
		case <-s.CloseSignal():
			return
		case <-s.tickStop:
			return
		case <-ticker.C:
			idle := s.opts.SessionIdleTimeout
			if idle <= 0 {
				idle = aether.DefaultSessionIdleTimeout
			}
			if time.Since(s.Health().LastActivity()) > idle {
				dbgTCP.Printf("session idle timeout (%s) — closing", idle)
				s.CloseWithError(fmt.Errorf("session idle timeout (%s)", idle))
				return
			}
			s.sweepEnded(time.Now(), nil)
		}
	}
}

// reportAbuse records a peer misbehaviour event. Delegates to the
// shared AbuseTracker, which handles the registry Record +
// threshold-breaker GoAway + close. Safe to call at high frequency —
// the decay model means transient events are forgiven.
func (s *TCPSession) reportAbuse(r abuse.Reason) {
	s.abuseTracker.Report(r)
}

// PeerAbuseScore returns the remote peer's current decayed score (0
// when no events recorded or when the tracker has no registry).
func (s *TCPSession) PeerAbuseScore() float64 {
	score, _ := s.abuseTracker.PeerScore()
	return score
}

// SetAbuseScoreRegistry swaps the per-session registry for a shared
// one — for cross-session operator dashboards. Signature takes
// `interface{}` to satisfy `aether.AbuseScoreCapable` without an
// import cycle; returns false when the registry type doesn't match.
func (s *TCPSession) SetAbuseScoreRegistry(r interface{}) bool {
	return s.abuseTracker.SetRegistry(r)
}

// LastActivity / IdleTimeout / IsClosed / ConnectionID / Health /
// Protocol / Capabilities all come from the embedded *BaseSession.

func (s *TCPSession) SessionKey() []byte      { return nil } // TLS provides encryption
func (s *TCPSession) CongestionWindow() int64 { return 0 }   // TCP handles congestion
func (s *TCPSession) Metrics() aether.SessionMetrics {
	_, avg := s.Health().RTT()
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
	totalLen := len(data)

	// A message keeps its boundary, arriving as one Receive(). The
	// fragment envelope that would split one larger than the class
	// MaxFrameSize into interleavable frames needs the session's realm, and a
	// TCPSession has none (fragRecv), so every message travels as one DATA
	// frame. The byte stream carries a frame of any length up to
	// aether.MaxPayloadSize, which the peer's ReadNextFrame also enforces, and
	// the peer's delivery queue (enqueueDelivery) takes one of at most the
	// bounds profile's stream credit, its entry cost included, so a larger
	// message fails here, typed and with the stream still open, where the peer's
	// queue would end the stream. A message above MaxFrameSize holds the write
	// loop for its whole length.
	// TODO: when a byte-stream session's identity binds a mesh realm, split a
	// message above MaxFrameSize with SplitMessage as NoiseSession does, so
	// other streams interleave with it.
	if totalLen > aether.MaxPayloadSize {
		return fmt.Errorf("stream %d: %w: %d bytes, one frame carries at most %d",
			st.streamID, ErrPayloadTooLarge, totalLen, aether.MaxPayloadSize)
	}
	if credit := flow.CurrentBounds().StreamCredit; messageCredit(int64(totalLen)) > credit {
		return fmt.Errorf("stream %d: %w: %d bytes and the %d B entry cost, the peer's delivery queue holds at most %d",
			st.streamID, ErrPayloadTooLarge, totalLen, recvQueueEntryCost, credit)
	}

	// The room is taken before st.mu, since a wait holding it would stop Close.
	cost := messageCredit(int64(totalLen))
	if err := st.awaitSendRoom(ctx, cost); err != nil {
		return err
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if !st.state.CanSend() {
		st.sendRoom.Release(cost)
		if st.streamID == 0 {
			dbgTCP.Printf("Send: stream 0 cannot send (state=%s)", st.state.State())
		}
		return st.endError(fmt.Errorf("stream %d: cannot send (state=%s)", st.streamID, st.state.State()))
	}
	// The writeLoop has stopped on a closed session, so a frame queued now would
	// never be written.
	select {
	case <-st.session.CloseSignal():
		st.sendRoom.Release(cost)
		return st.session.closedError()
	default:
	}
	frame := &aether.Frame{
		SenderID:   st.session.LocalPeerID(),
		ReceiverID: st.session.RemotePeerID(),
		StreamID:   st.streamID,
		Type:       aether.TypeDATA,
		Length:     uint32(totalLen),
		Payload:    data,
	}
	st.session.queuedFrames.Store(frame, queuedFrame{st: st, cost: cost})
	if !st.session.sched.Enqueue(st.streamID, frame) {
		// A RESET has taken the stream out of the scheduler ahead of its state.
		st.session.releaseSendRoom(frame)
		return st.endError(fmt.Errorf("stream %d: cannot send (reset)", st.streamID))
	}

	if st.streamID == 0 {
		dbgTCP.Printf("Send: enqueued %d bytes for stream 0 (gossip), schedLen=%d", totalLen, st.session.sched.QueueLen(0))
	}
	return nil
}

// Receive returns the next whole message the readLoop queued on recvQ
// (enqueueDelivery). What recvQ holds comes first, one message per call, whatever
// has ended: after closeRecvOnce has closed recvDone it returns the stream's end
// once recvQ is empty, io.EOF or the typed reason endErr records
// (aether.ErrStreamOverrun, aether.ErrStreamRefused; aether.ErrStreamOverrun too for
// a consumer returning to messages recvMemory discarded), and after the session
// closed it returns that close once recvQ is empty, so a message delivered before
// either end is not lost behind it.
func (st *tcpStream) Receive(ctx context.Context) ([]byte, error) {
	for {
		if data, _, ok := st.recvQ.pop(); ok {
			return data, nil
		}
		select {
		case <-st.recvQ.wake:
		case <-st.recvDone:
			if data, _, ok := st.recvQ.pop(); ok {
				return data, nil
			}
			if st.recvQ.discardedMessages() {
				st.setEnd(aether.ErrStreamOverrun)
			}
			return nil, st.endError(io.EOF)
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-st.session.CloseSignal():
			if data, _, ok := st.recvQ.pop(); ok {
				return data, nil
			}
			if err := st.session.closedError(); !errors.Is(err, aether.ErrSessionClosed) {
				return nil, err
			}
			return nil, fmt.Errorf("session closed")
		}
	}
}

// Close ends this side's sending: it queues CLOSE behind every DATA this stream
// has queued, in the scheduler, whose per-stream order the one writeLoop writes
// to the conn, so the peer's Receive sees all of it and then the end. It returns
// without waiting for the write, and the stream leaves the session once CLOSE is
// written and the peer's CLOSE has come (frameWritten, handleClose). A message
// the peer sends after this still reaches Receive. A repeated Close, or a Close
// after a reset, has nothing to say to the peer and returns nil. On a closed
// session it returns aether.ErrSessionClosed: nothing will write the CLOSE.
func (st *tcpStream) Close() error {
	s := st.session
	st.mu.Lock()
	defer st.mu.Unlock()
	if err := st.state.Transition(aether.EventSendFIN); err != nil {
		return nil
	}
	select {
	case <-s.CloseSignal():
		return s.closedError()
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
	s.mu.Lock()
	st.closeFrame = frame
	s.mu.Unlock()
	s.sched.Enqueue(st.streamID, frame)
	return nil
}

// Reset abandons the stream from this side: it writes RESET(reason) and takes the
// stream out of the session (sendReset, which also frees the compressors'
// per-stream state the stream would otherwise hold for the session's life), then
// ends the receive side, after which Receive returns what recvQ holds and then
// the stream's end (io.EOF unless endErr records a typed reason). A direct Reset,
// the stream GC's idle reap and CloseWithError's reset of unaccepted streams all
// come here.
func (st *tcpStream) Reset(reason aether.ResetReason) error {
	err := st.sendReset(reason)
	st.closeRecvOnce()
	return err
}

func (st *tcpStream) SetPriority(weight uint8, dependency uint64) {
	st.session.sched.SetWeight(st.streamID, weight)
}

// Ensure interfaces are satisfied at compile time.
var _ aether.Session = (*TCPSession)(nil)
var _ aether.AbuseScoreCapable = (*TCPSession)(nil)
var _ aether.IdleEvictable = (*TCPSession)(nil)
var _ aether.WireVersionsReporter = (*TCPSession)(nil)
var _ aether.Stream = (*tcpStream)(nil)
