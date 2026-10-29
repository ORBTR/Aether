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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// gatedConn is a net.Conn whose Write, once armed, parks until release is
// closed. writeFrame has already compressed and encrypted the frame under
// writeMu when it reaches conn.Write, so a parked Write holds the write loop
// between the commit of a queued frame and its hand-off to the wire, where
// an RTO firing on reliabilityTick dequeues that same frame. blocked is
// closed by the first parked Write so the test knows the commit has run.
type gatedConn struct {
	net.Conn
	armed   atomic.Bool
	once    sync.Once
	blocked chan struct{}
	release chan struct{}
}

func newGatedConn(c net.Conn) *gatedConn {
	return &gatedConn{Conn: c, blocked: make(chan struct{}), release: make(chan struct{})}
}

func (g *gatedConn) Write(b []byte) (int, error) {
	if g.armed.Load() {
		g.once.Do(func() { close(g.blocked) })
		<-g.release
	}
	return g.Conn.Write(b)
}

// compressibleMessage is a payload the write boundary shortens: longer than
// the 64 bytes under which writeFrame skips compression, and one repeated
// byte, which deflate reduces to a few bytes, so the committed frame's
// Payload is far shorter than the payload bytes the sender enqueued.
func compressibleMessage() []byte { return bytes.Repeat([]byte{'a'}, 512) }

// noisePairWithGatedClient is noisePairWithRealms with the client's conn
// wrapped so the test can park the client's write loop inside conn.Write.
func noisePairWithGatedClient(t *testing.T) (client, server *NoiseSession, gate *gatedConn) {
	t.Helper()
	chosen := aetherChosen(t)
	c, s := loopbackPair(t)
	gate = newGatedConn(c)
	client = NewNoiseSession(realmConn{Conn: gate, chosen: chosen}, "vl1_gate_client", "vl1_gate_server", aether.DefaultSessionOptions())
	server = NewNoiseSession(realmConn{Conn: s, chosen: chosen}, "vl1_gate_server", "vl1_gate_client", aether.DefaultSessionOptions())
	t.Cleanup(func() {
		// Open the gate before closing: Close writes under writeMu, which a
		// parked Write still holds.
		select {
		case <-gate.release:
		default:
			close(gate.release)
		}
		_ = client.Close()
		_ = server.Close()
	})
	return client, server, gate
}

// TestNoiseSession_RTODequeueDoesNotReadTheFrameTheWriteLoopCommits parks the
// client's write loop inside conn.Write after it has committed a queued DATA
// frame (writeFrame's compression swap of frame.Payload under writeMu), then
// waits for the frame's RTO to fire on reliabilityTick, whose Dequeue of the
// retransmit queue runs under the queue's own lock only. The queue must take
// nothing from the frame after Enqueue, so the RTO path never reads the
// Payload the write loop is committing; a read there is a data race the race
// detector reports against writeFrame's write.
func TestNoiseSession_RTODequeueDoesNotReadTheFrameTheWriteLoopCommits(t *testing.T) {
	client, server, gate := noisePairWithGatedClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cs, _ := openAccept(t, ctx, client, server, 100)
	st, ok := cs.(*noiseStream)
	if !ok {
		t.Fatalf("stream of type %T, want *noiseStream", cs)
	}

	// The first message's entry leaves the queue with its ACK; from then on
	// the queue holds only the frame this test parks.
	deadline := time.Now().Add(5 * time.Second)
	for st.retransmitQ.Len() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("premise wrong: %d entries still queued 5 s after the first message was received", st.retransmitQ.Len())
		}
		time.Sleep(5 * time.Millisecond)
	}

	rtoAtEnqueue := st.rtt.RTO()
	gate.armed.Store(true)
	if err := cs.Send(ctx, compressibleMessage()); err != nil {
		t.Fatalf("send: %v", err)
	}

	// The parked Write keeps the ACK from ever arriving, so the frame's RTO
	// fires at the estimator's floor. The RTO path has run once the queue's
	// entry is due again later than the RTO it was enqueued with:
	// advanceEntryLocked doubles the entry's RTO and re-enqueues it (the TLP
	// probe, which also fires while the write is parked, touches the send
	// window and the scheduler, never this queue). The test does not wait on
	// gate.blocked before this: receiving it would order the write loop's
	// commit before this goroutine, and this goroutine's lock of the queue
	// before reliabilityTick's, so the race would be hidden by the test's
	// own synchronisation; the parked write is checked afterwards instead.
	deadline = time.Now().Add(5 * time.Second)
	for st.retransmitQ.NextDueIn() <= rtoAtEnqueue+50*time.Millisecond {
		if time.Now().After(deadline) {
			t.Fatalf("premise wrong: the parked frame's RTO (%v at enqueue) did not fire within 5 s", rtoAtEnqueue)
		}
		time.Sleep(5 * time.Millisecond)
	}
	select {
	case <-gate.blocked:
	default:
		t.Fatal("premise wrong: the RTO fired before the write loop committed the frame and reached conn.Write")
	}
	close(gate.release)
}

// TestNoiseSession_RetransmitQueueByteCountReturnsToZeroAfterTheWriteLoopCommits
// sends a compressible message, lets the write loop commit the frame and the
// peer's ACK remove it, and requires the retransmit queue's payload byte
// count to return to 0: the count an entry adds at Enqueue is the count it
// subtracts when it leaves, not the length of the committed Payload.
func TestNoiseSession_RetransmitQueueByteCountReturnsToZeroAfterTheWriteLoopCommits(t *testing.T) {
	client, server := noisePairWithRealms(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cs, ss := openAccept(t, ctx, client, server, 101)
	st, ok := cs.(*noiseStream)
	if !ok {
		t.Fatalf("stream of type %T, want *noiseStream", cs)
	}

	msg := compressibleMessage()
	if err := cs.Send(ctx, msg); err != nil {
		t.Fatalf("send: %v", err)
	}
	got, err := ss.Receive(ctx)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("receive: %d bytes, %v; want the %d sent", len(got), err, len(msg))
	}
	deadline := time.Now().Add(5 * time.Second)
	for st.retransmitQ.Len() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("premise wrong: %d entries still queued 5 s after the peer received the message", st.retransmitQ.Len())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := st.retransmitQ.BufferedBytes(); got != 0 {
		t.Fatalf("retransmit queue holds %d payload bytes with no entry queued, want 0", got)
	}
}
