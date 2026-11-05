//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"bytes"
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	aether "github.com/ORBTR/aether"
)

// The write loop's writeFrame rewrites a queued frame's Payload, Length and
// Flags under writeMu at the write boundary. Neither readLoop path below takes
// writeMu, so under -race any read they make of those fields on a frame still
// queued is reported. The tests hold the write loop inside conn.Write with the
// frame queued behind it, then release it and run the readLoop path at once, so
// the commit and the read overlap and no lock the test takes orders them.

// holdConn parks every Write while hold holds a channel, until it closes.
type holdConn struct {
	net.Conn
	hold atomic.Pointer[chan struct{}]
}

func (h *holdConn) Write(b []byte) (int, error) {
	if g := h.hold.Load(); g != nil {
		<-*g
	}
	return h.Conn.Write(b)
}

func noisePairWithHoldClient(t *testing.T) (client, server *NoiseSession, hold *holdConn) {
	t.Helper()
	chosen := aetherChosen(t)
	c, s := loopbackPair(t)
	hold = &holdConn{Conn: c}
	client = NewNoiseSession(realmConn{Conn: hold, chosen: chosen}, "vl1_hold_client", "vl1_hold_server", aether.DefaultSessionOptions())
	server = NewNoiseSession(realmConn{Conn: s, chosen: chosen}, "vl1_hold_server", "vl1_hold_client", aether.DefaultSessionOptions())
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	return client, server, hold
}

// raceRounds is how many overlaps each test forces; one reported overlap fails
// the test under -race, so a round that happens to order the two does no harm.
const raceRounds = 80

// overlapDelay spins for a round's share of 400 µs. The write loop's next lock of
// a mutex the readLoop path also takes orders whichever came first, so the rounds
// step the path across the moment the write loop commits and writes the frame.
func overlapDelay(round int) {
	for end := time.Now().Add(time.Duration(round%8) * 50 * time.Microsecond); time.Now().Before(end); {
	}
}

// queueBehindHeldWrite sends a first frame that parks the write loop in
// conn.Write and a second, compressible one that stays queued behind it, and
// returns the second frame's send-window entry with the channel that frees the
// write loop. g is never reassigned once the conn holds its address: the parked
// Write reads it through that pointer.
func queueBehindHeldWrite(t *testing.T, ctx context.Context, cs aether.Stream, st *noiseStream, hold *holdConn) (uint32, chan struct{}) {
	t.Helper()
	g := make(chan struct{})
	hold.hold.Store(&g)
	msg := bytes.Repeat([]byte{'a'}, 512)
	// A PMTU probe parked in the same Write holds the prober's lock that Send's
	// MSS read waits on, so the sends have a bound and a parked probe gets freed.
	sent := make(chan error, 1)
	go func() {
		err := cs.Send(ctx, msg)
		if err == nil {
			err = cs.Send(ctx, msg)
		}
		sent <- err
	}()
	select {
	case err := <-sent:
		if err != nil {
			t.Fatalf("send: %v", err)
		}
	case <-time.After(2 * time.Second):
		hold.hold.Store(nil)
		close(g)
		if err := <-sent; err != nil {
			t.Fatalf("send: %v", err)
		}
		return st.sendWindow.Next() - 1, make(chan struct{})
	}
	return st.sendWindow.Next() - 1, g
}

// TestNoiseSession_AnACKForAQueuedFrameReadsNothingTheWriteLoopCommits: a peer's
// ACK may cover a frame that has not reached the wire. handleACK takes its byte
// counts from the entry and never from the entry's live Frame.
func TestNoiseSession_AnACKForAQueuedFrameReadsNothingTheWriteLoopCommits(t *testing.T) {
	client, server, hold := noisePairWithHoldClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cs, ss := openAccept(t, ctx, client, server, 110)
	st := asNoiseStream(t, cs)
	go func() {
		for ctx.Err() == nil {
			if _, err := ss.Receive(ctx); err != nil {
				return
			}
		}
	}()
	for i := 0; i < raceRounds; i++ {
		seq, g := queueBehindHeldWrite(t, ctx, cs, st, hold)
		ack := &aether.Frame{
			Type:     aether.TypeACK,
			StreamID: st.streamID,
			Flags:    aether.FlagCOMPOSITE_ACK,
			Payload:  aether.EncodeCompositeACK(&aether.CompositeACK{BaseACK: seq}),
		}
		ack.Length = uint32(len(ack.Payload))
		hold.hold.Store(nil)
		close(g)
		overlapDelay(i)
		client.handleACK(ack)
	}
}

// TestNoiseSession_APeerResetReadsNothingTheWriteLoopCommits: the frame the write
// loop is committing can have a second reference in the scheduler, which the stream's
// leave collects (the test queues one as a probe). The readLoop's handleReset releases
// the stream with no lock the write loop holds and reads no field of either.
func TestNoiseSession_APeerResetReadsNothingTheWriteLoopCommits(t *testing.T) {
	client, server, hold := noisePairWithHoldClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	for i := 0; i < raceRounds; i++ {
		cs, ss := openAccept(t, ctx, client, server, uint64(200+i))
		st := asNoiseStream(t, cs)
		seq, g := queueBehindHeldWrite(t, ctx, cs, st, hold)
		e := st.sendWindow.GetEntry(seq)
		if e == nil {
			t.Fatalf("round %d: no entry for seq %d", i, seq)
		}
		client.sched.EnqueueProbe(st.streamID, e.Frame)
		reset := peerReset(st, aether.ResetCancel)
		hold.hold.Store(nil)
		close(g)
		overlapDelay(i)
		client.handleReset(reset)
		_ = ss
	}
}
