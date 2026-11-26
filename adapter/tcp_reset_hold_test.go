//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package adapter

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// readUntilPong reads the session's frames off a liteRawPeer's conn until the PONG
// that answers the PING written after frames the test wants handled: the readLoop
// serves frames in order, so the PONG follows its handling of everything before the
// PING. It returns the frames read ahead of the PONG.
func (p *liteRawPeer) readUntilPong() []*aether.Frame {
	p.t.Helper()
	var seen []*aether.Frame
	for {
		f := p.next()
		if f.Type == aether.TypePONG {
			return seen
		}
		seen = append(seen, f)
	}
}

// ackOf is the acknowledgment a peer writes for a RESET naming inc: the same stream,
// the same reason, no counts.
func ackOf(id uint64, reason aether.ResetReason, inc aether.StreamIncarnation) *aether.Frame {
	return &aether.Frame{StreamID: id, Type: aether.TypeRESET, Flags: aether.FlagACK,
		Payload: aether.EncodeResetPayload(aether.ResetPayload{Reason: reason, Incarnation: inc})}
}

func pingFrame() *aether.Frame { return &aether.Frame{StreamID: 2, Type: aether.TypePING} }

// wantOpenRefused fails unless a local OpenStream of cfg on s returns
// aether.ErrDuplicateStreamID. An open that goes through blocks writing its SYN to a
// liteRawPeer nobody reads, so the call runs aside and a call still running after
// two seconds fails the test, whose cleanup closes the session under it.
func wantOpenRefused(t *testing.T, ctx context.Context, s *TCPSession, cfg aether.StreamConfig, what string) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		_, err := s.OpenStream(ctx, cfg)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, aether.ErrDuplicateStreamID) {
			t.Fatalf("OpenStream %s: %v, want ErrDuplicateStreamID", what, err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("OpenStream %s went through and is writing its SYN, want ErrDuplicateStreamID", what)
	}
}

// TestTCPSession_ALocalResetHoldsTheIDUntilThePeerAcknowledgesIt: after a local
// Reset the ID refuses a local OpenStream with aether.ErrDuplicateStreamID while the
// peer has not acknowledged the RESET, and an acknowledgment naming another stream
// under the ID changes nothing. The peer's DATA written before it read the RESET
// reaches no stream. The acknowledgment naming the reset stream opens the ID at
// once, and the new stream reads only what the peer sends it.
func TestTCPSession_ALocalResetHoldsTheIDUntilThePeerAcknowledgesIt(t *testing.T) {
	p := newLiteRawPeer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	const id = 60
	cfg := aether.StreamConfig{StreamID: id, Reliability: aether.ReliableOrdered, Priority: 128}
	st := p.open(ctx, id)
	resetDone := make(chan error, 1)
	go func() { resetDone <- st.Reset(aether.ResetCancel) }()
	reset := p.next()
	if reset.Type != aether.TypeRESET || reset.Flags.Has(aether.FlagACK) || reset.StreamID != id {
		t.Fatalf("frame after Reset: %+v, want the RESET of %d", reset, id)
	}
	if got := aether.DecodeResetPayload(reset.Payload).Incarnation; got != st.incarnation {
		t.Fatalf("the RESET names %+v, want %+v", got, st.incarnation)
	}
	if err := <-resetDone; err != nil {
		t.Fatalf("reset: %v", err)
	}
	wantOpenRefused(t, ctx, p.sess, cfg, "while the RESET waits")

	// The peer's old DATA, then an acknowledgment of another stream under the ID.
	other := aether.StreamIncarnation{Generation: st.incarnation.Generation + 1, WriterOpened: true}
	writeFrames(t, p.conn,
		&aether.Frame{StreamID: id, Type: aether.TypeDATA, Payload: []byte("old")},
		ackOf(id, aether.ResetCancel, other),
		pingFrame())
	if seen := p.readUntilPong(); len(seen) != 0 {
		t.Fatalf("the session wrote %d frames for the peer's old DATA and a namesake acknowledgment: %+v", len(seen), seen[0])
	}
	wantOpenRefused(t, ctx, p.sess, cfg, "after an acknowledgment naming another stream")

	writeFrames(t, p.conn, ackOf(id, aether.ResetCancel, st.incarnation), pingFrame())
	p.readUntilPong()
	next := p.open(ctx, id)
	writeFrames(t, p.conn, &aether.Frame{StreamID: id, Type: aether.TypeDATA, Payload: []byte("new")})
	if r := <-receiveAsync(ctx, next, 5*time.Second); r.err != nil || string(r.data) != "new" {
		t.Fatalf("the reopened stream read %q, %v; want new", r.data, r.err)
	}
	if got := p.sess.DeliveryStats().Delivered.Load(); got != 1 {
		t.Errorf("Delivered = %d, want 1: the peer's old DATA reached a stream", got)
	}
}

// TestTCPSession_EveryResetIsAcknowledgedBehindTheStreamsFrames: a RESET from the
// peer is answered by a RESET flagged FlagACK naming the stream as the RESET did,
// with its reason and no counts, and no frame of the stream it ends follows that
// acknowledgment on the wire, though the stream had DATA queued. A RESET naming a
// stream the session does not hold, and one naming another stream than the one under
// its ID, are acknowledged too, and the live stream stays.
func TestTCPSession_EveryResetIsAcknowledgedBehindTheStreamsFrames(t *testing.T) {
	p := newLiteRawPeer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	const id = 70
	writeFrames(t, p.conn, synFrame(id))
	st, err := p.sess.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	inc := aether.StreamIncarnation{Generation: rawGeneration(id), WriterOpened: true}
	const queued = 8
	for i := 0; i < queued; i++ {
		if err := st.Send(ctx, []byte(fmt.Sprintf("s-%d", i))); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	writeFrames(t, p.conn, rawReset(id, aether.ResetTimeout), pingFrame())
	seen := p.readUntilPong()
	acked := -1
	for i, f := range seen {
		switch {
		case f.Type == aether.TypeRESET && f.Flags.Has(aether.FlagACK):
			got := aether.DecodeResetPayload(f.Payload)
			want := aether.ResetPayload{Reason: aether.ResetTimeout, Incarnation: inc}
			if f.StreamID != id || got != want {
				t.Fatalf("acknowledgment %+v on %d, want %+v on %d", got, f.StreamID, want, id)
			}
			acked = i
		case f.StreamID == id && acked >= 0:
			t.Fatalf("frame %+v of the reset stream follows its acknowledgment", f)
		}
	}
	if acked < 0 {
		t.Fatalf("no acknowledgment of the RESET among %d frames", len(seen))
	}
	if inSession(p.sess, id) {
		t.Fatal("the reset stream is still in the session")
	}

	// A RESET of a stream the session does not hold.
	writeFrames(t, p.conn, rawReset(71, aether.ResetCancel), pingFrame())
	if seen := p.readUntilPong(); len(seen) != 1 || !seen[0].Flags.Has(aether.FlagACK) || seen[0].StreamID != 71 {
		t.Fatalf("frames for a RESET of an unknown stream: %d %+v, want its acknowledgment", len(seen), seen)
	}

	// A RESET naming another stream than the live one under its ID.
	writeFrames(t, p.conn, synFrame(72))
	live, err := p.sess.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept 72: %v", err)
	}
	stale := &aether.Frame{StreamID: 72, Type: aether.TypeRESET, Payload: aether.EncodeResetPayload(aether.ResetPayload{
		Reason: aether.ResetCancel, Incarnation: aether.StreamIncarnation{Generation: rawGeneration(72) + 3, WriterOpened: true}})}
	writeFrames(t, p.conn, stale, pingFrame())
	if seen := p.readUntilPong(); len(seen) != 1 || !seen[0].Flags.Has(aether.FlagACK) || seen[0].StreamID != 72 {
		t.Fatalf("frames for a RESET naming another stream: %d %+v, want its acknowledgment", len(seen), seen)
	}
	if !inSession(p.sess, 72) || !live.IsOpen() {
		t.Fatal("a RESET naming another stream ended the live one")
	}
}

// TestTCPSession_ARefusedOpenHoldsTheIDUntilTheRefusalIsAcknowledged: a SYN this
// side refuses (a generation naming no stream) is answered with RESET(ResetRefused)
// naming the stream the peer opened, and the ID refuses a local OpenStream until the
// peer acknowledges that refusal, since the peer's DATA behind its SYN may still be
// on the way.
func TestTCPSession_ARefusedOpenHoldsTheIDUntilTheRefusalIsAcknowledged(t *testing.T) {
	p := newLiteRawPeer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	const id = 82
	bad := &aether.Frame{StreamID: id, Type: aether.TypeDATA, Flags: aether.FlagSYN,
		Payload: aether.EncodeOpenPayload(aether.OpenPayload{Reliability: aether.ReliableOrdered})}
	writeFrames(t, p.conn, bad, pingFrame())
	seen := p.readUntilPong()
	if len(seen) != 1 || seen[0].Type != aether.TypeRESET || seen[0].Flags.Has(aether.FlagACK) {
		t.Fatalf("frames for a refused SYN: %d %+v, want one RESET", len(seen), seen)
	}
	refusal := aether.DecodeResetPayload(seen[0].Payload)
	if refusal.Reason != aether.ResetRefused {
		t.Fatalf("refusal reason %v, want ResetRefused", refusal.Reason)
	}
	cfg := aether.StreamConfig{StreamID: id, Reliability: aether.ReliableOrdered, Priority: 128}
	wantOpenRefused(t, ctx, p.sess, cfg, "of a refused ID before the acknowledgment")
	writeFrames(t, p.conn, ackOf(id, aether.ResetRefused, refusal.Incarnation), pingFrame())
	p.readUntilPong()
	p.open(ctx, id)
}

// TestTCPSession_TheResetHoldIsBoundedByTheStreamCap: past the stream cap of RESETs
// waiting for an acknowledgment, a further RESET holds nothing, so a peer that
// acknowledges none cannot grow the map; a RESET under an ID already waiting replaces
// its entry.
func TestTCPSession_TheResetHoldIsBoundedByTheStreamCap(t *testing.T) {
	s := &TCPSession{opts: aether.SessionOptions{MaxConcurrentStreams: 2}}
	inc := func(g uint64) aether.StreamIncarnation {
		return aether.StreamIncarnation{Generation: g, WriterOpened: true}
	}
	s.holdForResetLocked(10, inc(1))
	s.holdForResetLocked(11, inc(2))
	s.holdForResetLocked(12, inc(3))
	if _, held := s.pendingResets[12]; held || len(s.pendingResets) != 2 {
		t.Fatalf("pending %v: a RESET past the cap was held", s.pendingResets)
	}
	s.holdForResetLocked(10, inc(4))
	if s.pendingResets[10] != inc(4) || len(s.pendingResets) != 2 {
		t.Fatalf("pending %v: a RESET under a waiting ID did not replace its entry", s.pendingResets)
	}
}

// TestTCPStream_AResetStreamQueuesNothingUnderTheIDsNextStream: a stream the session
// no longer holds under its ID queues no frame, whatever its own state says, so a
// Send that passed its state check before a RESET cannot put DATA into the scheduler
// slot of the next stream under the ID.
func TestTCPStream_AResetStreamQueuesNothingUnderTheIDsNextStream(t *testing.T) {
	p := newLiteRawPeer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	const id = 90
	old := p.open(ctx, id)
	resetDone := make(chan error, 1)
	go func() { resetDone <- old.Reset(aether.ResetCancel) }()
	if f := p.next(); f.Type != aether.TypeRESET {
		t.Fatalf("frame after Reset: %+v", f)
	}
	if err := <-resetDone; err != nil {
		t.Fatalf("Reset: %v", err)
	}
	writeFrames(t, p.conn, ackOf(id, aether.ResetCancel, old.incarnation), pingFrame())
	p.readUntilPong()
	p.open(ctx, id)
	before := p.sess.sched.QueueLen(id)
	if old.queueFrame(&aether.Frame{StreamID: id, Type: aether.TypeDATA, Payload: []byte("late")}) {
		t.Fatal("a reset stream queued a frame under its ID's next stream")
	}
	if got := p.sess.sched.QueueLen(id); got != before {
		t.Fatalf("the next stream's queue went from %d to %d", before, got)
	}
}

// TestTCPSession_AResetThenAReopenOnceAllowedReadsNoOldMessage: the client resets
// a stream while the server is still sending on it and reopens the ID as soon as the
// session allows. No message the server sent on the old stream reaches the new one:
// the reopen waits for the server's acknowledgment of the RESET, which follows every
// frame of the old stream on the byte stream.
func TestTCPSession_AResetThenAReopenOnceAllowedReadsNoOldMessage(t *testing.T) {
	const rounds = 10
	for round := 0; round < rounds; round++ {
		client, server := tcpPairWithOptions(t, aether.DefaultSessionOptions())
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		cfg := aether.StreamConfig{StreamID: 31, Reliability: aether.ReliableOrdered, Priority: 128}
		cs, err := client.OpenStream(ctx, cfg)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if err := cs.Send(ctx, []byte("req")); err != nil {
			t.Fatalf("req: %v", err)
		}
		ss, err := server.AcceptStream(ctx)
		if err != nil {
			t.Fatalf("accept: %v", err)
		}
		if _, err := ss.Receive(ctx); err != nil {
			t.Fatalf("server receive: %v", err)
		}
		var sent atomic.Int64
		stop := make(chan struct{})
		go func() {
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				sctx, sc := context.WithTimeout(ctx, 500*time.Millisecond)
				err := ss.Send(sctx, []byte(fmt.Sprintf("old-%d", i)))
				sc()
				if err != nil {
					return
				}
				sent.Add(1)
			}
		}()
		for sent.Load() < 20 {
			time.Sleep(time.Millisecond)
		}
		if err := cs.Reset(aether.ResetCancel); err != nil {
			t.Fatalf("reset: %v", err)
		}
		var ns aether.Stream
		for start := time.Now(); ; time.Sleep(time.Millisecond) {
			ns, err = client.OpenStream(ctx, cfg)
			if err == nil || !errors.Is(err, aether.ErrDuplicateStreamID) || time.Since(start) > 10*time.Second {
				break
			}
		}
		if err != nil {
			t.Fatalf("round %d: the ID never reopened: %v", round, err)
		}
		_ = ns.Send(ctx, []byte("new-req"))
		var old []string
		for {
			r := <-receiveAsync(ctx, ns, 300*time.Millisecond)
			if r.err != nil {
				break
			}
			old = append(old, string(r.data))
		}
		close(stop)
		cancel()
		if len(old) > 0 {
			t.Errorf("round %d: %d messages the server sent on the old stream reached the new one, first %q", round, len(old), strings.Join(old[:min(3, len(old))], " "))
		}
	}
}
