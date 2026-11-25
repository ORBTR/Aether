//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ORBTR/aether"
	"github.com/quic-go/quic-go"
)

// TestQUICSession_ExchangesTheWireVersionPreface: two QUICSessions choose one set
// through the preface, each reports it, and a stream opens over the grammar it chose.
func TestQUICSession_ExchangesTheWireVersionPreface(t *testing.T) {
	client, server := quicLoopback(t)
	defer func() {
		if err := client.Close(); err != nil {
			t.Errorf("client.Close: %v", err)
		}
	}()
	defer func() {
		if err := server.Close(); err != nil {
			t.Errorf("server.Close: %v", err)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: 10, Reliability: aether.ReliableOrdered})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for name, sess := range map[string]aether.Session{"client": client, "server": server} {
		chosen, ok := aether.SessionWireVersions(sess)
		if !ok {
			t.Fatalf("%s does not report a set", name)
		}
		if v, ok := chosen.Version(aether.WireVersionFrame); !ok || v != aether.WireVersionFrameCurrent {
			t.Fatalf("%s chose frame version %d, %v", name, v, ok)
		}
	}
	if err := st.Send(ctx, []byte("after the preface")); err != nil {
		t.Fatalf("send: %v", err)
	}
	accepted, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if got, err := accepted.Receive(ctx); err != nil || string(got) != "after the preface" {
		t.Fatalf("receive: %q, %v", got, err)
	}
}

// TestQUICSession_RefusesAPeerWithNoCommonVersion: a required entry with no version
// both sides list refuses the session on both ends before any stream exists, whichever
// end's close reaches the other first, and OpenStream and AcceptStream name the
// refusal. The session records the refusal as its close reason just after it ends the
// exchange, which is what releases OpenStream (refuseWire, then closeRefused), so the
// reason is read once it has been recorded.
func TestQUICSession_RefusesAPeerWithNoCommonVersion(t *testing.T) {
	cc, sc := quicLoopbackConns(t)
	entry := func(v uint16) aether.WireVersion {
		return aether.WireVersion{Name: "app.codec", Versions: []uint16{v}, Required: true}
	}
	client := NewQuicSession(cc, aether.NodeID("quic-client"), aether.NodeID("quic-server"), entry(1))
	server := NewQuicSession(sc, aether.NodeID("quic-server"), aether.NodeID("quic-client"), entry(2))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if st, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: 10}); st != nil || !errors.Is(err, aether.ErrWireVersionMismatch) {
		t.Fatalf("client OpenStream = %v, %v; want the mismatch", st, err)
	}
	if st, err := server.AcceptStream(ctx); st != nil || !errors.Is(err, aether.ErrWireVersionMismatch) {
		t.Fatalf("server AcceptStream = %v, %v; want the mismatch", st, err)
	}
	if got := client.Metrics().ActiveStreams; got != 0 {
		t.Fatalf("client holds %d streams", got)
	}
	waitFor(t, "the client's close reason", func() bool { return client.CloseErr() != nil })
	if !errors.Is(client.CloseErr(), aether.ErrWireVersionMismatch) {
		t.Fatalf("client close reason %v", client.CloseErr())
	}
	if got := client.WireVersions(); len(got.Entries()) != 0 {
		t.Fatalf("a refused session reports %v", got)
	}
}

// TestQUICSession_ARefusedSessionReadsNoStreamHeader: a session whose exchange refused
// its peer accepts no stream, even on a connection that goes on offering them.
func TestQUICSession_ARefusedSessionReadsNoStreamHeader(t *testing.T) {
	conn := &aep06Conn{queue: []quic.Stream{newAEP06Stream(10)}, done: make(chan struct{}),
		peerOffer: aether.WireVersions{{Name: aether.WireVersionFrame, Versions: []uint16{aether.WireVersionFrameCurrent - 1}, Required: true}}}
	sess := NewQuicSession(conn, aether.NodeID("aep06-local"), aether.NodeID("aep06-remote"))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := sess.OpenStream(ctx, aether.StreamConfig{StreamID: 11}); !errors.Is(err, aether.ErrWireVersionMismatch) {
		t.Fatalf("OpenStream: %v, want the mismatch", err)
	}
	time.Sleep(100 * time.Millisecond)
	conn.mu.Lock()
	taken := conn.idx
	conn.mu.Unlock()
	if taken != 0 {
		t.Fatalf("a refused session took %d streams off the connection", taken)
	}
}

// TestQUICSession_APeerSilentOnThePrefaceIsRefusedAtTheDeadline: a peer that opens no
// preface stream has the session closed at the deadline with the typed reason.
func TestQUICSession_APeerSilentOnThePrefaceIsRefusedAtTheDeadline(t *testing.T) {
	prev := wireVersionsPrefaceTimeout
	wireVersionsPrefaceTimeout = 200 * time.Millisecond
	defer func() { wireVersionsPrefaceTimeout = prev }()
	cc, _ := quicLoopbackConns(t)
	client := NewQuicSession(cc, aether.NodeID("quic-client"), aether.NodeID("quic-server"))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: 10}); !errors.Is(err, errWireVersionsPrefaceTimeout) {
		t.Fatalf("OpenStream: %v, want the preface deadline", err)
	}
}

// TestQUICSession_ALocalOpenOfALiveIDIsRefusedBeforeTheWire: OpenStream of an ID a
// stream holds is the typed refusal, the peer sees one stream, and the first stream's
// late Close after a later stream took the ID leaves that later stream's entry alone.
func TestQUICSession_ALocalOpenOfALiveIDIsRefusedBeforeTheWire(t *testing.T) {
	client, server := quicLoopback(t)
	defer func() {
		if err := client.Close(); err != nil {
			t.Errorf("client.Close: %v", err)
		}
	}()
	defer func() {
		if err := server.Close(); err != nil {
			t.Errorf("server.Close: %v", err)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cfg := aether.StreamConfig{StreamID: 10, Reliability: aether.ReliableOrdered}
	first, err := client.OpenStream(ctx, cfg)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if st, err := client.OpenStream(ctx, cfg); st != nil || !errors.Is(err, aether.ErrDuplicateStreamID) {
		t.Fatalf("second OpenStream = %v, %v; want ErrDuplicateStreamID", st, err)
	}
	if _, err := server.AcceptStream(ctx); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	second, err := client.OpenStream(ctx, cfg)
	if err != nil {
		t.Fatalf("open after the close: %v", err)
	}
	first.(*quicStream).dropStream()
	if got := client.Metrics().ActiveStreams; got != 1 {
		t.Fatalf("after the first stream's late drop: %d streams, want the second", got)
	}
	_ = second.Reset(aether.ResetCancel)
}
