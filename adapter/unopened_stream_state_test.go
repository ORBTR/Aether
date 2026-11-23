/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"context"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// sendToUnopenedStreams writes a DATA frame to each of ids, none of them an open
// stream, then opens one real stream and carries a message on it, so every
// frame before it has been read and handled when the message arrives.
func sendToUnopenedStreams(t *testing.T, write func(*aether.Frame) error, from, to aether.PeerID,
	open func(context.Context, aether.StreamConfig) (aether.Stream, error), accept func(context.Context) (aether.Stream, error), ids []uint64) {
	t.Helper()
	for _, id := range ids {
		payload := []byte("x")
		if err := write(&aether.Frame{SenderID: from, ReceiverID: to, StreamID: id, Type: aether.TypeDATA, Length: uint32(len(payload)), Payload: payload}); err != nil {
			t.Fatalf("DATA to stream %d: %v", id, err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cs, err := open(ctx, aether.StreamConfig{StreamID: 4001, Reliability: aether.ReliableOrdered, Priority: 128})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := cs.Send(ctx, []byte("after")); err != nil {
		t.Fatalf("send: %v", err)
	}
	ss, err := accept(ctx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if got, err := ss.Receive(ctx); err != nil || string(got) != "after" {
		t.Fatalf("receive = %q, %v", got, err)
	}
}

func unopenedIDs() []uint64 {
	ids := make([]uint64, 0, 64)
	for id := uint64(2001); id < 2001+2*64; id += 2 {
		ids = append(ids, id)
	}
	return ids
}

// A frame for a stream ID that never opens leaves no receive-compressor state
// behind on a Noise session, so a peer cycling stream IDs cannot grow it.
func TestNoiseSession_AFrameForAStreamThatNeverOpensLeavesNoState(t *testing.T) {
	client, server := noisePairWithServerOptions(t, aether.DefaultSessionOptions())
	ids := unopenedIDs()
	sendToUnopenedStreams(t, client.writeFrame, client.LocalPeerID(), client.RemotePeerID(), client.OpenStream, server.AcceptStream, ids)
	for _, id := range ids {
		if server.rxCompressor.HasStream(id) {
			t.Fatalf("the server still holds receive state for stream %d, which never opened", id)
		}
	}
	if !server.rxCompressor.HasStream(4001) {
		t.Fatal("the open stream's receive state was released")
	}
}

// The same on a TCP session.
func TestTCPSession_AFrameForAStreamThatNeverOpensLeavesNoState(t *testing.T) {
	client, server := tcpPairWithOptions(t, aether.DefaultSessionOptions())
	ids := unopenedIDs()
	sendToUnopenedStreams(t, client.writeFrame, client.LocalPeerID(), client.RemotePeerID(), client.OpenStream, server.AcceptStream, ids)
	for _, id := range ids {
		if server.rxCompressor.HasStream(id) {
			t.Fatalf("the server still holds receive state for stream %d, which never opened", id)
		}
	}
}
