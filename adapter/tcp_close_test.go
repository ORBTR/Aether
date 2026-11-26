//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package adapter

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/flow"
)

// liteRawPeer is the far end of a TCPSession's conn, driven by hand: the preface
// is exchanged with an offer of no short forms, so every frame the session writes
// is a full frame, which next reads with a deadline.
type liteRawPeer struct {
	t       *testing.T
	sess    *TCPSession
	conn    net.Conn
	decoder *aether.Compressor
}

func newLiteRawPeer(t *testing.T) *liteRawPeer {
	t.Helper()
	sess, conn := rawPeer(t, aether.DefaultSessionOptions())
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	offer, err := aether.ReadWireVersionsPreface(conn)
	if err != nil {
		t.Fatalf("read preface: %v", err)
	}
	if err := aether.WriteWireVersionsPreface(conn, frameOnlyOffer()); err != nil {
		t.Fatalf("write preface: %v", err)
	}
	chosen, err := aether.ChooseWireVersions(frameOnlyOffer(), offer)
	if err != nil {
		t.Fatalf("choose: %v", err)
	}
	return &liteRawPeer{t: t, sess: sess, conn: conn, decoder: wireDecoder(chosen)}
}

func (p *liteRawPeer) next() *aether.Frame {
	p.t.Helper()
	frame, _, _, err := aether.ReadNextFrame(p.conn, p.decoder)
	if err != nil {
		p.t.Fatalf("read frame: %v", err)
	}
	return frame
}

// open opens stream id from the session side and reads its SYN off the conn.
func (p *liteRawPeer) open(ctx context.Context, id uint64) *tcpStream {
	p.t.Helper()
	type opened struct {
		st  aether.Stream
		err error
	}
	done := make(chan opened, 1)
	go func() {
		st, err := p.sess.OpenStream(ctx, aether.StreamConfig{StreamID: id, Reliability: aether.ReliableOrdered, Priority: 128})
		done <- opened{st, err}
	}()
	if syn := p.next(); syn.StreamID != id || !syn.Flags.Has(aether.FlagSYN) {
		p.t.Fatalf("first frame on stream %d is %+v, want its SYN", id, syn)
	}
	r := <-done
	if r.err != nil {
		p.t.Fatalf("open %d: %v", id, r.err)
	}
	return r.st.(*tcpStream)
}

func synFrame(id uint64) *aether.Frame {
	return &aether.Frame{StreamID: id, Type: aether.TypeDATA, Flags: aether.FlagSYN,
		Payload: aether.EncodeOpenPayload(aether.OpenPayload{Reliability: aether.ReliableOrdered, Generation: rawGeneration(id)})}
}

func inSession(s *TCPSession, id uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.streams[id]
	return ok
}

// TestTCPStream_AReplyThenCloseArrivesWhole: a caller sends a request and
// half-closes, and the server replies and closes at once, 15 RPCs over three
// sizes. Every reply reaches the caller's Receive, followed by io.EOF: the
// server's CLOSE stays behind its DATA in the scheduler, with or without time
// between the two.
func TestTCPStream_AReplyThenCloseArrivesWhole(t *testing.T) {
	for _, delay := range []time.Duration{0, 50 * time.Millisecond} {
		t.Run(delay.String(), func(t *testing.T) {
			client, server := tcpPairWithOptions(t, aether.DefaultSessionOptions())
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			sizes := []int{512, 64 * 1024, 512 * 1024}
			for k := 0; k < 15; k++ {
				cs, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: uint64(30 + 2*k), Reliability: aether.ReliableOrdered, Priority: 128})
				if err != nil {
					t.Fatalf("RPC %d open: %v", k, err)
				}
				if err := cs.Send(ctx, []byte("req")); err != nil {
					t.Fatalf("RPC %d request: %v", k, err)
				}
				if err := cs.Close(); err != nil {
					t.Fatalf("RPC %d close: %v", k, err)
				}
				ss, err := server.AcceptStream(ctx)
				if err != nil {
					t.Fatalf("RPC %d accept: %v", k, err)
				}
				if _, err := ss.Receive(ctx); err != nil {
					t.Fatalf("RPC %d server receive: %v", k, err)
				}
				size := sizes[k%3]
				if err := ss.Send(ctx, burstMessage(k, size)); err != nil {
					t.Fatalf("RPC %d reply: %v", k, err)
				}
				time.Sleep(delay)
				if err := ss.Close(); err != nil {
					t.Fatalf("RPC %d server close: %v", k, err)
				}
				rctx, rcancel := context.WithTimeout(ctx, 20*time.Second)
				got, err := cs.Receive(rctx)
				if err != nil || len(got) != size || int(binary.BigEndian.Uint32(got)) != k {
					rcancel()
					t.Fatalf("RPC %d: %d of %d bytes: %v", k, len(got), size, err)
				}
				if _, err := cs.Receive(rctx); !errors.Is(err, io.EOF) {
					rcancel()
					t.Fatalf("RPC %d after the reply: %v, want io.EOF", k, err)
				}
				rcancel()
			}
		})
	}
}

// TestTCPStream_ThePeersCloseEndsTheReceiveSide: the peer's CLOSE gives Receive
// what it holds and then io.EOF with no local Close, this side can still reply,
// and DATA behind the CLOSE is refused, not delivered.
func TestTCPStream_ThePeersCloseEndsTheReceiveSide(t *testing.T) {
	p := newLiteRawPeer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	writeFrames(t, p.conn,
		synFrame(40),
		&aether.Frame{StreamID: 40, Type: aether.TypeDATA, Payload: []byte("one")},
		rawClose(40),
		&aether.Frame{StreamID: 40, Type: aether.TypeDATA, Payload: []byte("behind")})
	st, err := p.sess.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if got, err := st.Receive(ctx); err != nil || string(got) != "one" {
		t.Fatalf("receive: %q, %v", got, err)
	}
	if _, err := st.Receive(ctx); !errors.Is(err, io.EOF) {
		t.Fatalf("after the peer's CLOSE: %v, want io.EOF", err)
	}
	if err := st.Send(ctx, []byte("reply")); err != nil {
		t.Fatalf("a reply after the peer's CLOSE: %v", err)
	}
	if f := p.next(); f.Type != aether.TypeDATA || string(f.Payload) != "reply" {
		t.Fatalf("the reply on the wire: %+v", f)
	}
	// The readLoop serves frames in order, so its PONG follows its handling of
	// the DATA behind the CLOSE.
	writeFrames(t, p.conn, &aether.Frame{StreamID: 2, Type: aether.TypePING})
	if f := p.next(); f.Type != aether.TypePONG {
		t.Fatalf("frame on the wire: type %v, want PONG", f.Type)
	}
	if got := p.sess.DeliveryStats().Delivered.Load(); got != 1 {
		t.Errorf("Delivered = %d, want 1: the DATA behind the CLOSE is not a message", got)
	}
}

// TestTCPStream_ALocalCloseAfterThePeersLeavesAtOnce: once the peer has closed,
// a local Close leaves the session as soon as its CLOSE is written, on both ends,
// and not at the stream GC's idle sweep.
func TestTCPStream_ALocalCloseAfterThePeersLeavesAtOnce(t *testing.T) {
	client, server := tcpPairWithOptions(t, aether.DefaultSessionOptions())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cs, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: 44, Reliability: aether.ReliableOrdered, Priority: 128})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := cs.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	ss, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if _, err := ss.Receive(ctx); !errors.Is(err, io.EOF) {
		t.Fatalf("server receive: %v, want io.EOF", err)
	}
	if !inSession(server, 44) {
		t.Fatalf("the half-closed stream left before this side closed: it could not reply")
	}
	if err := ss.Close(); err != nil {
		t.Fatalf("server close: %v", err)
	}
	waitFor(t, "both ends left", func() bool { return !inSession(server, 44) && !inSession(client, 44) })
	if n := server.sched.StreamCount(); n != 0 {
		t.Errorf("the server's scheduler still holds %d streams", n)
	}
	if n := client.sched.StreamCount(); n != 0 {
		t.Errorf("the client's scheduler still holds %d streams", n)
	}
}

// TestTCPStream_ThePeersCloseDoesNotOvertakeQueuedFrames: this side has DATA and
// its CLOSE queued, unwritten because the conn is not being read, when the peer's
// CLOSE arrives. The stream stays in the session, since unregistering it would
// drop those frames; they reach the wire in order, and only then does it leave.
func TestTCPStream_ThePeersCloseDoesNotOvertakeQueuedFrames(t *testing.T) {
	p := newLiteRawPeer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	st := p.open(ctx, 46)
	for i := 0; i < 3; i++ {
		if err := st.Send(ctx, burstMessage(i, 256)); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	writeFrames(t, p.conn, closeTo(st))
	if _, err := st.Receive(ctx); !errors.Is(err, io.EOF) {
		t.Fatalf("after the peer's CLOSE: %v, want io.EOF", err)
	}
	if !inSession(p.sess, 46) {
		t.Fatalf("the stream left with its CLOSE unwritten")
	}
	for i := 0; i < 3; i++ {
		f := p.next()
		if f.Type != aether.TypeDATA || int(binary.BigEndian.Uint32(f.Payload)) != i {
			t.Fatalf("frame %d on the wire: type %v", i, f.Type)
		}
	}
	if f := p.next(); f.Type != aether.TypeCLOSE {
		t.Fatalf("last frame on the wire: type %v, want CLOSE", f.Type)
	}
	waitFor(t, "the stream left once its CLOSE was written", func() bool { return !inSession(p.sess, 46) })
}

// TestTCPStream_ASynOnAClosedStreamOpensTheNextStream: the peer reopens an ID only
// after reading this side's CLOSE, which can reach it before the writeLoop that
// wrote the CLOSE records it. A SYN under the ID of a stream both sides closed is
// the next stream, not a message on the finished one.
func TestTCPStream_ASynOnAClosedStreamOpensTheNextStream(t *testing.T) {
	p := newLiteRawPeer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	first := p.open(ctx, 48)
	if err := first.Send(ctx, []byte("unwritten")); err != nil {
		t.Fatalf("send: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	writeFrames(t, p.conn,
		closeTo(first),
		synFrame(48),
		&aether.Frame{StreamID: 48, Type: aether.TypeDATA, Payload: []byte("next")})
	next, err := p.sess.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept the next stream: %v", err)
	}
	if next == aether.Stream(first) {
		t.Fatalf("the SYN did not open a new stream")
	}
	if got, err := next.Receive(ctx); err != nil || string(got) != "next" {
		t.Fatalf("the next stream's message: %q, %v", got, err)
	}
}

// TestTCPStream_AResetOfALeftStreamLeavesTheNextStreamUnderItsID: a stream that
// left on both CLOSEs writes nothing on Reset and takes nothing from a later
// stream under its ID: that stream goes on in both directions.
func TestTCPStream_AResetOfALeftStreamLeavesTheNextStreamUnderItsID(t *testing.T) {
	client, server := tcpPairWithOptions(t, aether.DefaultSessionOptions())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	const id = 52
	cfg := aether.StreamConfig{StreamID: id, Reliability: aether.ReliableOrdered, Priority: 128}
	old, err := client.OpenStream(ctx, cfg)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := old.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	oldServer, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if err := oldServer.Close(); err != nil {
		t.Fatalf("server close: %v", err)
	}
	waitFor(t, "both ends left", func() bool { return !inSession(client, id) && !inSession(server, id) })

	next, err := client.OpenStream(ctx, cfg)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if err := next.Send(ctx, []byte("ping")); err != nil {
		t.Fatalf("send: %v", err)
	}
	nextServer, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept the next: %v", err)
	}
	if err := old.Reset(aether.ResetCancel); err != nil {
		t.Fatalf("reset of the left stream: %v", err)
	}
	if err := oldServer.Reset(aether.ResetCancel); err != nil {
		t.Fatalf("server reset of the left stream: %v", err)
	}
	if got, err := nextServer.Receive(ctx); err != nil || string(got) != "ping" {
		t.Fatalf("the next stream's message: %q, %v", got, err)
	}
	if err := nextServer.Send(ctx, []byte("pong")); err != nil {
		t.Fatalf("reply: %v", err)
	}
	if got, err := next.Receive(ctx); err != nil || string(got) != "pong" {
		t.Fatalf("the next stream's reply: %q, %v", got, err)
	}
}

// TestTCPSession_ReopeningAnIDRoundTrips: a pool recycling one stream ID across
// many RPCs: each open that succeeds is a fresh stream on both ends, and every
// reply arrives.
func TestTCPSession_ReopeningAnIDRoundTrips(t *testing.T) {
	client, server := tcpPairWithOptions(t, aether.DefaultSessionOptions())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cfg := aether.StreamConfig{StreamID: 54, Reliability: aether.ReliableOrdered, Priority: 128}
	for k := 0; k < 40; k++ {
		var cs aether.Stream
		var err error
		for {
			cs, err = client.OpenStream(ctx, cfg)
			if !errors.Is(err, aether.ErrDuplicateStreamID) {
				break
			}
			time.Sleep(time.Millisecond)
		}
		if err != nil {
			t.Fatalf("RPC %d open: %v", k, err)
		}
		if err := cs.Send(ctx, burstMessage(k, 128)); err != nil {
			t.Fatalf("RPC %d send: %v", k, err)
		}
		if err := cs.Close(); err != nil {
			t.Fatalf("RPC %d close: %v", k, err)
		}
		ss, err := server.AcceptStream(ctx)
		if err != nil {
			t.Fatalf("RPC %d accept: %v", k, err)
		}
		got, err := ss.Receive(ctx)
		if err != nil || int(binary.BigEndian.Uint32(got)) != k {
			t.Fatalf("RPC %d server receive: %v", k, err)
		}
		if err := ss.Send(ctx, got); err != nil {
			t.Fatalf("RPC %d reply: %v", k, err)
		}
		if err := ss.Close(); err != nil {
			t.Fatalf("RPC %d server close: %v", k, err)
		}
		got, err = cs.Receive(ctx)
		if err != nil || int(binary.BigEndian.Uint32(got)) != k {
			t.Fatalf("RPC %d reply receive: %v", k, err)
		}
		if _, err := cs.Receive(ctx); !errors.Is(err, io.EOF) {
			t.Fatalf("RPC %d end: %v, want io.EOF", k, err)
		}
	}
}

// TestTCPSession_RunsNoAetherCredit: a Lite session writes no WINDOW_UPDATE or
// CONGESTION however much its consumer reads, acts on neither frame when it reads
// one, and exposes no credit (StreamConn answers -1, which means no flow control
// to a consumer outside this repository that throttles itself on it) and no
// throttle.
func TestTCPSession_RunsNoAetherCredit(t *testing.T) {
	p := newLiteRawPeer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	const size = 100 * 1024
	frames := []*aether.Frame{
		synFrame(56),
		aether.BuildWindowUpdateFrame(aether.PeerID{}, aether.PeerID{}, 56, 1<<20),
		aether.BuildWindowUpdateFrame(aether.PeerID{}, aether.PeerID{}, aether.StreamConnectionLevel, 1<<20),
		aether.BuildCongestionFrame(aether.PeerID{}, aether.PeerID{}, aether.CongestionPayload{Reason: aether.CongestionQueueFull, Severity: 100, BackoffMs: 60000}),
	}
	for i := 0; i < 8; i++ { // past every grant trigger of a 1 MiB window
		frames = append(frames, &aether.Frame{StreamID: 56, Type: aether.TypeDATA, Payload: burstMessage(i, size)})
	}
	writeFrames(t, p.conn, frames...)
	st, err := p.sess.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	for i := 0; i < 8; i++ {
		got, err := st.Receive(ctx)
		if err != nil || int(binary.BigEndian.Uint32(got)) != i {
			t.Fatalf("message %d: %v", i, err)
		}
	}
	if err := st.Send(ctx, []byte("reply")); err != nil {
		t.Fatalf("send under a stall-severity CONGESTION: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	for {
		f := p.next()
		if f.Type == aether.TypeWINDOW || f.Type == aether.TypeCONGESTION {
			t.Fatalf("the session wrote a %v frame", f.Type)
		}
		if f.Type == aether.TypeCLOSE {
			break
		}
	}
	if p.sess.IsClosed() {
		t.Fatalf("a WINDOW_UPDATE or CONGESTION frame closed the session")
	}

	type credited interface{ AvailableCredit() int64 }
	if _, ok := aether.Stream(st).(credited); ok {
		t.Errorf("a byte-stream session's stream exposes AvailableCredit")
	}
	if got := st.Conn().(*StreamConn).AvailableCredit(); got != -1 {
		t.Errorf("StreamConn.AvailableCredit = %d, want -1", got)
	}
	type throttled interface {
		Throttle() *aether.CongestionThrottle
	}
	wsClient, wsServer := net.Pipe()
	defer func() {
		if err := wsClient.Close(); err != nil {
			t.Errorf("wsClient.Close: %v", err)
		}
	}()
	defer func() {
		if err := wsServer.Close(); err != nil {
			t.Errorf("wsServer.Close: %v", err)
		}
	}()
	ws := NewWebSocketSession(wsClient, "vl1_lite_a", "vl1_lite_b", aether.DefaultSessionOptions())
	defer func() {
		if err := ws.Close(); err != nil {
			t.Errorf("ws.Close: %v", err)
		}
	}()
	for name, sess := range map[string]any{"tcp": p.sess, "websocket": ws} {
		if _, ok := sess.(throttled); ok {
			t.Errorf("%s session exposes Throttle", name)
		}
	}
}

// TestTCPStream_TheQueueIsBoundedInBytesNotMessages: far more small messages than
// any message count would hold stay queued while they fit the stream credit, and
// the first that does not fit ends the stream with the typed reset after the
// consumer reads all of them.
func TestTCPStream_TheQueueIsBoundedInBytesNotMessages(t *testing.T) {
	p := newLiteRawPeer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	credit := flow.CurrentBounds().StreamCredit
	const size = 1024
	fits := int(credit / messageCredit(size))
	frames := []*aether.Frame{synFrame(58)}
	for i := 0; i < fits+1; i++ {
		frames = append(frames, &aether.Frame{StreamID: 58, Type: aether.TypeDATA, Payload: burstMessage(i, size)})
	}
	writeFrames(t, p.conn, frames...)
	st, err := p.sess.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	reset := p.next()
	if reset.Type != aether.TypeRESET || aether.DecodeReset(reset.Payload) != aether.ResetFlowCtrl {
		t.Fatalf("frame on the wire: %+v, want RESET(ResetFlowCtrl)", reset)
	}
	if got := st.(*tcpStream).recvQ.len(); got != fits {
		t.Fatalf("the queue holds %d messages, want the %d the credit fits", got, fits)
	}
	for i := 0; i < fits; i++ {
		got, err := st.Receive(ctx)
		if err != nil || int(binary.BigEndian.Uint32(got)) != i {
			t.Fatalf("message %d: %v", i, err)
		}
	}
	if _, err := st.Receive(ctx); !errors.Is(err, aether.ErrStreamOverrun) {
		t.Fatalf("after the queue: %v, want aether.ErrStreamOverrun", err)
	}
}

// TestTCPStream_AMessageOverTheStreamCreditIsRefusedAtSend: the largest message the
// peer's queue can hold passes; one byte more is refused, typed, before it reaches
// the wire and with the stream still open; and the same message from a peer that
// sends it anyway meets the typed reset.
func TestTCPStream_AMessageOverTheStreamCreditIsRefusedAtSend(t *testing.T) {
	client, server := tcpPairWithOptions(t, aether.DefaultSessionOptions())
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	largest := int(flow.CurrentBounds().StreamCredit - recvQueueEntryCost)
	cs, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: 60, Reliability: aether.ReliableOrdered, Priority: 128})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := cs.Send(ctx, make([]byte, largest+1)); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("a message over the credit: %v, want ErrPayloadTooLarge", err)
	}
	if err := cs.Send(ctx, make([]byte, largest)); err != nil {
		t.Fatalf("the largest message: %v", err)
	}
	ss, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if got, err := ss.Receive(ctx); err != nil || len(got) != largest {
		t.Fatalf("received %d bytes, %v; want %d", len(got), err, largest)
	}

	p := newLiteRawPeer(t)
	writeFrames(t, p.conn, synFrame(62), &aether.Frame{StreamID: 62, Type: aether.TypeDATA, Payload: bytes.Repeat([]byte{7}, largest+1)})
	st, err := p.sess.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept from the raw peer: %v", err)
	}
	if _, err := st.Receive(ctx); !errors.Is(err, aether.ErrStreamOverrun) {
		t.Fatalf("an oversize frame from a peer: %v, want aether.ErrStreamOverrun", err)
	}
}

// TestTCPStream_SessionCloseDoesNotLoseWhatIsQueued: a message delivered before
// the session closed is still read before the session's end, and Send and Close on
// a closed session are typed: nothing would write their frames.
func TestTCPStream_SessionCloseDoesNotLoseWhatIsQueued(t *testing.T) {
	p := newLiteRawPeer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	writeFrames(t, p.conn, synFrame(64), &aether.Frame{StreamID: 64, Type: aether.TypeDATA, Payload: []byte("queued")})
	st, err := p.sess.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	waitFor(t, "the message queued", func() bool { return st.(*tcpStream).recvQ.len() == 1 })
	_ = p.sess.Close()
	if err := st.Send(ctx, []byte("x")); !errors.Is(err, aether.ErrSessionClosed) {
		t.Errorf("Send on a closed session: %v, want aether.ErrSessionClosed", err)
	}
	if err := st.Close(); !errors.Is(err, aether.ErrSessionClosed) {
		t.Errorf("Close on a closed session: %v, want aether.ErrSessionClosed", err)
	}
	if got, err := st.Receive(ctx); err != nil || string(got) != "queued" {
		t.Fatalf("Receive after the session closed: %q, %v; want the queued message", got, err)
	}
	if _, err := st.Receive(ctx); err == nil {
		t.Fatalf("Receive past the queue on a closed session returned no error")
	}
}

// TestTCPStream_NoSendLandsBehindItsClose: Send racing Close on another goroutine.
// Every Send that returned nil arrives, before the end: a message queued behind
// the CLOSE would have been refused by the peer's ended receive side after Send
// had reported success.
func TestTCPStream_NoSendLandsBehindItsClose(t *testing.T) {
	client, server := tcpPairWithOptions(t, aether.DefaultSessionOptions())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for round := 0; round < 60; round++ {
		id := uint64(200 + round)
		cs, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: id, Reliability: aether.ReliableOrdered, Priority: 128})
		if err != nil {
			t.Fatalf("round %d open: %v", round, err)
		}
		sent := make(chan int, 1)
		go func() {
			n := 0
			for cs.Send(ctx, burstMessage(n, 64)) == nil {
				n++
				if n == 1000 {
					break
				}
			}
			sent <- n
		}()
		time.Sleep(time.Duration(round%8) * 100 * time.Microsecond)
		if err := cs.Close(); err != nil {
			t.Fatalf("round %d close: %v", round, err)
		}
		n := <-sent
		ss, err := server.AcceptStream(ctx)
		if err != nil {
			t.Fatalf("round %d accept: %v", round, err)
		}
		got := 0
		for {
			m, err := ss.Receive(ctx)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatalf("round %d receive: %v", round, err)
			}
			if int(binary.BigEndian.Uint32(m)) != got {
				t.Fatalf("round %d: message %d numbered %d", round, got, binary.BigEndian.Uint32(m))
			}
			got++
		}
		if got != n {
			t.Fatalf("round %d: %d Sends returned nil, %d messages arrived", round, n, got)
		}
		_ = ss.Close()
	}
}

// TestTCPStream_ASYNPayloadIsNeverAMessage: a SYN frame whose payload is not an OPEN
// payload is refused with RESET(ResetRefused) and keeps no state, and a SYN frame on a
// live stream delivers nothing to its consumer.
func TestTCPStream_ASYNPayloadIsNeverAMessage(t *testing.T) {
	p := newLiteRawPeer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	writeFrames(t, p.conn, &aether.Frame{StreamID: 50, Type: aether.TypeDATA, Flags: aether.FlagSYN, Payload: []byte("hello")})
	if f := p.next(); f.Type != aether.TypeRESET || f.StreamID != 50 || aether.DecodeReset(f.Payload) != aether.ResetRefused {
		t.Fatalf("frame on the wire: %+v, want RESET(ResetRefused)", f)
	}
	if inSession(p.sess, 50) {
		t.Fatal("a SYN frame carrying message bytes kept a stream")
	}

	writeFrames(t, p.conn,
		synFrame(52),
		synFrame(52),
		&aether.Frame{StreamID: 52, Type: aether.TypeDATA, Flags: aether.FlagSYN, Payload: []byte("hello")},
		&aether.Frame{StreamID: 52, Type: aether.TypeDATA, Payload: []byte("one")})
	st, err := p.sess.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if got, err := st.Receive(ctx); err != nil || string(got) != "one" {
		t.Fatalf("first message: %q, %v; want the DATA frame, no SYN payload", got, err)
	}
	if got := p.sess.DeliveryStats().Delivered.Load(); got != 1 {
		t.Fatalf("Delivered = %d, want 1", got)
	}
}

// TestTCPStream_DataBehindAResetIsRefused: the peer's RESET ends the stream, whose
// consumer reads what it holds and then the end, the session answers it with its
// acknowledgment, and DATA behind the RESET is not a message.
func TestTCPStream_DataBehindAResetIsRefused(t *testing.T) {
	p := newLiteRawPeer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	writeFrames(t, p.conn,
		synFrame(54),
		&aether.Frame{StreamID: 54, Type: aether.TypeDATA, Payload: []byte("one")},
		rawReset(54, aether.ResetCancel),
		&aether.Frame{StreamID: 54, Type: aether.TypeDATA, Payload: []byte("behind")},
		&aether.Frame{StreamID: 2, Type: aether.TypePING})
	if seen := p.readUntilPong(); len(seen) != 1 || seen[0].StreamID != 54 || !seen[0].Flags.Has(aether.FlagACK) {
		t.Fatalf("frames ahead of the PONG: %d %+v, want the RESET's acknowledgment alone", len(seen), seen)
	}
	st, err := p.sess.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if got, err := st.Receive(ctx); err != nil || string(got) != "one" {
		t.Fatalf("receive: %q, %v", got, err)
	}
	if _, err := st.Receive(ctx); !errors.Is(err, io.EOF) {
		t.Fatalf("after the RESET: %v, want io.EOF", err)
	}
	if got := p.sess.DeliveryStats().Delivered.Load(); got != 1 {
		t.Errorf("Delivered = %d, want 1: the DATA behind the RESET is not a message", got)
	}
}
