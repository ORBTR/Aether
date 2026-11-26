//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package adapter

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/congestion"
)

// ceRecorder is the session's congestion controller with every OnCE call
// recorded and passed on.
type ceRecorder struct {
	congestion.Controller
	mu sync.Mutex
	ce []int64
}

func (r *ceRecorder) OnCE(bytesMarked int64) {
	r.mu.Lock()
	r.ce = append(r.ce, bytesMarked)
	r.mu.Unlock()
	r.Controller.OnCE(bytesMarked)
}

func (r *ceRecorder) calls() []int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]int64(nil), r.ce...)
}

// TestNoiseSession_CEClaimIsBoundedInWireBytes: with the CE interval counter
// drained and an ACK that acknowledges nothing, handleACK bounds the peer's
// CEBytes claim by the wire bytes still in flight, the unit of the claim, of
// bytesSentSinceLastCE and of OnCE. The frame in flight is a compressible
// message, whose wire form is far shorter than the plaintext its stream's
// credit charged, and the claim lies between the two, so a bound read from
// credit would pass it unclamped.
func TestNoiseSession_CEClaimIsBoundedInWireBytes(t *testing.T) {
	client, server, gate := noisePairWithGatedClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cs, _ := openAccept(t, ctx, client, server, 108)
	st := asNoiseStream(t, cs)
	waitStepAcked(t, st)
	waitProbeSweepsDone(t, client, server)

	rec := &ceRecorder{Controller: client.congestion()}
	var ctrl congestion.Controller = rec
	client.cong.Store(&ctrl)

	// The frame's first write charges its wire bytes in flight before the
	// Write the gate parks, so no ACK for it can arrive.
	gate.armed.Store(true)
	msg := compressibleMessage()
	if err := cs.Send(ctx, msg); err != nil {
		t.Fatalf("send: %v", err)
	}
	waitFor(t, "the frame's first write", func() bool { return client.totalInFlightBytes() > 0 })
	wire := client.totalInFlightBytes()
	plain := st.window.Outstanding()
	if wire >= plain {
		t.Fatalf("premise wrong: %d wire bytes in flight for %d plaintext bytes of credit", wire, plain)
	}
	claim := (wire + plain) / 2

	client.bytesSentSinceLastCE.Store(0)
	payload := aether.EncodeCompositeACK(&aether.CompositeACK{
		BaseACK: 0,
		Flags:   aether.CACKHasECN,
		CEBytes: uint32(claim),
	})
	client.handleACK(&aether.Frame{
		SenderID:   client.RemotePeerID(),
		ReceiverID: client.LocalPeerID(),
		StreamID:   st.streamID,
		Type:       aether.TypeACK,
		Flags:      aether.FlagCOMPOSITE_ACK,
		Length:     uint32(len(payload)),
		Payload:    payload,
	})

	got := rec.calls()
	if len(got) != 1 || got[0] != wire {
		t.Fatalf("OnCE calls %v for a claim of %d with %d wire bytes in flight (%d plaintext); want one call of %d",
			got, claim, wire, plain, wire)
	}
}

// TestNoiseSession_ACEClaimNoSentByteBacksDrivesNothing: with nothing in flight,
// the CE interval counter drained and a duplicate ACK that acknowledges
// nothing, every bound on the peer's CEBytes claim reads 0. handleACK neither
// tells the controller of the claim nor charges the peer, however large the
// claim.
func TestNoiseSession_ACEClaimNoSentByteBacksDrivesNothing(t *testing.T) {
	key := uint32(0x5eed5eed)
	client, server := noisePairWithRealms(t, &key, &key)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cs, _ := openAccept(t, ctx, client, server, 109)
	st := asNoiseStream(t, cs)
	waitStepAcked(t, st)
	waitProbeSweepsDone(t, client, server)
	waitSendWindowEmpty(t, st, "the opening message acknowledged")
	waitInFlightBytesZero(t, client, "nothing in flight")

	rec := &ceRecorder{Controller: client.congestion()}
	var ctrl congestion.Controller = rec
	client.cong.Store(&ctrl)
	cwnd := rec.CWND()
	score := client.PeerAbuseScore()

	client.bytesSentSinceLastCE.Store(0)
	payload := aether.EncodeCompositeACK(&aether.CompositeACK{
		BaseACK: st.sendWindow.Next() - 1,
		Flags:   aether.CACKHasECN,
		CEBytes: 1 << 30,
	})
	client.handleACK(&aether.Frame{
		SenderID:   client.RemotePeerID(),
		ReceiverID: client.LocalPeerID(),
		StreamID:   st.streamID,
		Type:       aether.TypeACK,
		Flags:      aether.FlagCOMPOSITE_ACK,
		Length:     uint32(len(payload)),
		Payload:    payload,
	})

	if got := rec.calls(); len(got) != 0 {
		t.Fatalf("OnCE calls %v for a claim no sent byte backs", got)
	}
	if got := rec.CWND(); got != cwnd {
		t.Fatalf("the controller's window moved from %d to %d", cwnd, got)
	}
	if got := client.PeerAbuseScore(); got != score {
		t.Fatalf("the peer's abuse score moved from %v to %v", score, got)
	}
}
