//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// aep0507NewPair builds a paired client/server TCPSession over net.Pipe with
// header compression enabled (DefaultSessionOptions), so the tx/rx compressor
// encode + decode paths are actually exercised. Uniquely named to avoid
// cross-agent symbol collisions in package adapter.
func aep0507NewPair(t *testing.T) (client, server *TCPSession, cleanup func()) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	client = NewTCPSession(clientConn, "vl1_aep0507_client_node_abcdef", "vl1_aep0507_server_node_ghijkl", aether.ProtoTCP, aether.DefaultSessionOptions())
	server = NewTCPSession(serverConn, "vl1_aep0507_server_node_ghijkl", "vl1_aep0507_client_node_abcdef", aether.ProtoTCP, aether.DefaultSessionOptions())
	cleanup = func() {
		client.Close()
		server.Close()
		clientConn.Close()
		serverConn.Close()
	}
	return client, server, cleanup
}

// TestAEP05_TxRxCompressorsAreSeparate proves the AE-P-05 fix: TCPSession
// holds two DISTINCT compressor instances — txCompressor for encode
// (writeFrame / writeLoop) and rxCompressor for decode (readLoop) — so
// cross-direction traffic can no longer pollute one shared SessionCompState
// identity or a stream's per-stream SeqNo/frameCount. Before the fix there
// was a single shared `compressor` field; this test would not even compile,
// and the distinct-instance + independent-per-stream-state assertions below
// would be impossible.
func TestAEP05_TxRxCompressorsAreSeparate(t *testing.T) {
	client, _, cleanup := aep0507NewPair(t)
	defer cleanup()

	if client.txCompressor == nil || client.rxCompressor == nil {
		t.Fatalf("AE-P-05: tx/rx compressors must both be constructed; tx=%v rx=%v",
			client.txCompressor, client.rxCompressor)
	}
	// The whole point of the split: encode-side and decode-side state live in
	// two different Compressor instances.
	if client.txCompressor == client.rxCompressor {
		t.Fatalf("AE-P-05: txCompressor and rxCompressor must be distinct instances, got the same pointer")
	}

	// Independent per-stream maps: the same StreamID resolves to a different
	// StreamCompState in each direction, so a decode never mutates the
	// encoder's lastSeqNo/frameCount and vice versa.
	const sid = 7
	txState := client.txCompressor.GetOrCreateStream(sid)
	rxState := client.rxCompressor.GetOrCreateStream(sid)
	if txState == rxState {
		t.Fatalf("AE-P-05: per-stream compressor state must be independent per direction, got shared pointer for stream %d", sid)
	}
}

// TestAEP05_BidirectionalRoundTripAfterSplit is the regression guard that the
// tx/rx split did not break the wire: with header compression on, data still
// round-trips in BOTH directions, exercising client.txCompressor (encode) +
// server.rxCompressor (decode) and the reverse.
func TestAEP05_BidirectionalRoundTripAfterSplit(t *testing.T) {
	client, server, cleanup := aep0507NewPair(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	clientStream, err := client.OpenStream(ctx, aether.StreamConfig{
		StreamID: 11, Reliability: aether.ReliableOrdered, Priority: 128,
	})
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	serverStream, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept stream: %v", err)
	}

	// client -> server (client txCompressor encodes, server rxCompressor decodes)
	if err := clientStream.Send(ctx, []byte("aep05-c2s")); err != nil {
		t.Fatalf("client send: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	got, err := serverStream.Receive(ctx)
	if err != nil {
		t.Fatalf("server receive: %v", err)
	}
	if string(got) != "aep05-c2s" {
		t.Fatalf("server got %q, want %q", got, "aep05-c2s")
	}

	// server -> client (server txCompressor encodes, client rxCompressor decodes)
	if err := serverStream.Send(ctx, []byte("aep05-s2c")); err != nil {
		t.Fatalf("server send: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	got, err = clientStream.Receive(ctx)
	if err != nil {
		t.Fatalf("client receive: %v", err)
	}
	if string(got) != "aep05-s2c" {
		t.Fatalf("client got %q, want %q", got, "aep05-s2c")
	}
}

// TestAEP07_ResetFreesCompressorState proves the AE-P-07 fix: local
// tcpStream.Reset() — the single funnel for every LOCAL teardown (direct
// Reset, streamGC idle-reap, and the cancel path) — now frees the per-stream
// compressor entry from BOTH directional compressors. The compressor keeps
// per-stream state in an unbounded sync.Map that previously only the
// peer-driven handleClose/handleReset paths pruned, so a locally-reset stream
// whose peer never echoed CLOSE/RESET leaked its entry for the session
// lifetime. Pointer identity (fresh entry != freed entry) is the observable
// signal that the old entry was removed.
func TestAEP07_ResetFreesCompressorState(t *testing.T) {
	client, server, cleanup := aep0507NewPair(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	const sid = 42
	clientStream, err := client.OpenStream(ctx, aether.StreamConfig{
		StreamID: sid, Reliability: aether.ReliableOrdered, Priority: 128,
	})
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	if _, err := server.AcceptStream(ctx); err != nil {
		t.Fatalf("accept stream: %v", err)
	}

	// Seed / capture the per-stream compressor entry in BOTH directions.
	txBefore := client.txCompressor.GetOrCreateStream(sid)
	rxBefore := client.rxCompressor.GetOrCreateStream(sid)

	st, ok := clientStream.(*tcpStream)
	if !ok {
		t.Fatalf("expected *tcpStream, got %T", clientStream)
	}
	if err := st.Reset(aether.ResetTimeout); err != nil {
		t.Fatalf("reset: %v", err)
	}

	// After Reset the old entries must be gone: GetOrCreateStream allocates a
	// fresh StreamCompState, so its pointer differs from the pre-Reset one.
	// (txBefore/rxBefore stay reachable via these locals, so the runtime can't
	// recycle their addresses into the new allocations.)
	txAfter := client.txCompressor.GetOrCreateStream(sid)
	rxAfter := client.rxCompressor.GetOrCreateStream(sid)
	if txAfter == txBefore {
		t.Errorf("AE-P-07: txCompressor entry for stream %d not freed by Reset (leak)", sid)
	}
	if rxAfter == rxBefore {
		t.Errorf("AE-P-07: rxCompressor entry for stream %d not freed by Reset (leak)", sid)
	}

	// Also confirm the stream was fully torn down (parity guard).
	client.mu.Lock()
	_, stillMapped := client.streams[sid]
	client.mu.Unlock()
	if stillMapped {
		t.Errorf("AE-P-07: stream %d should be removed from s.streams after Reset", sid)
	}
	_ = server
}
