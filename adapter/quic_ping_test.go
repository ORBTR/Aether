//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
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

// quicPrefaceOnly is a QUIC peer that writes the wire-versions preface and nothing
// else: the session on cc sees the exchange end, and no PONG ever comes back.
func quicPrefaceOnly(t *testing.T, sc quic.Connection) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	offer, err := aether.LocalWireVersions(nil)
	if err != nil {
		t.Fatalf("offer: %v", err)
	}
	st, err := sc.OpenUniStreamSync(ctx)
	if err != nil {
		t.Fatalf("open preface stream: %v", err)
	}
	if err := aether.WriteWireVersionsPreface(st, offer); err != nil {
		t.Fatalf("write preface: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close preface stream: %v", err)
	}
}

// TestQUICSession_PingIsARoundTripTheEstimatorLearnsFrom: a Ping from either side is
// answered by the peer's PONG on its probe stream, and each answer is a sample in the
// session's RTT estimator, the measurement aether.KeepalivePlanFor derives its plan from.
func TestQUICSession_PingIsARoundTripTheEstimatorLearnsFrom(t *testing.T) {
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
	for name, s := range map[string]*QUICSession{"client": client, "server": server} {
		for i := uint64(1); i <= 3; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			rtt, err := s.Ping(ctx)
			cancel()
			if err != nil {
				t.Fatalf("%s ping %d: %v", name, i, err)
			}
			if rtt <= 0 {
				t.Fatalf("%s ping %d: rtt %v, want a measured round trip", name, i, rtt)
			}
			if got := s.Health().SampleCount(); got != i {
				t.Fatalf("%s ping %d: %d estimator samples, want %d", name, i, got, i)
			}
		}
		if s.Health().SRTT() <= 0 {
			t.Fatalf("%s: SRTT %v after answered pings", name, s.Health().SRTT())
		}
	}
}

// TestQUICSession_PingOfASilentPeerFails: a peer that holds the connection open and
// answers nothing is a failed probe at the ctx deadline, with no sample taken: the QUIC
// connection being up says nothing of the peer's session.
func TestQUICSession_PingOfASilentPeerFails(t *testing.T) {
	cc, sc := quicLoopbackConns(t)
	s := NewQuicSession(cc, aether.NodeID("quic-client"), aether.NodeID("quic-server"))
	defer func() {
		if err := s.Close(); err != nil {
			t.Errorf("s.Close: %v", err)
		}
	}()
	quicPrefaceOnly(t, sc)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := s.awaitWire(ctx, s.CloseSignal()); err != nil {
		t.Fatalf("premise wrong: the exchange did not end: %v", err)
	}
	pingCtx, pingCancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer pingCancel()
	rtt, err := s.Ping(pingCtx)
	if err == nil {
		t.Fatalf("a silent peer's Ping answered nil with rtt %v", rtt)
	}
	if got := s.Health().SampleCount(); got != 0 {
		t.Fatalf("a silent peer gave %d estimator samples", got)
	}
}

// TestQUICSession_PingOfADeadConnectionIsSessionClosed: a connection QUIC has torn down
// answers ErrSessionClosed at once, though nothing has closed the session above it.
func TestQUICSession_PingOfADeadConnectionIsSessionClosed(t *testing.T) {
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
	if _, err := client.Ping(ctx); err != nil {
		t.Fatalf("premise wrong: the first ping: %v", err)
	}
	if err := client.conn.CloseWithError(0, "gone"); err != nil {
		t.Fatalf("close the connection: %v", err)
	}
	if _, err := client.Ping(ctx); !errors.Is(err, aether.ErrSessionClosed) {
		t.Fatalf("ping of a dead connection: %v, want ErrSessionClosed", err)
	}
}

// TestQUICSession_AnotherFrameEndsTheProbeStream: a frame other than PING or PONG on a
// peer's probe stream ends serveProbes on it, so a PING written after that frame gets
// no answer.
func TestQUICSession_AnotherFrameEndsTheProbeStream(t *testing.T) {
	cc, sc := quicLoopbackConns(t)
	s := NewQuicSession(cc, aether.NodeID("quic-client"), aether.NodeID("quic-server"))
	defer func() {
		if err := s.Close(); err != nil {
			t.Errorf("s.Close: %v", err)
		}
	}()
	quicPrefaceOnly(t, sc)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	probe, err := sc.OpenUniStreamSync(ctx)
	if err != nil {
		t.Fatalf("open the probe stream: %v", err)
	}
	if _, err := aether.EncodeFrame(probe, &aether.Frame{Type: aether.TypeDATA, SeqNo: 1}); err != nil {
		t.Fatalf("write the frame: %v", err)
	}
	if _, err := aether.EncodeFrame(probe, &aether.Frame{Type: aether.TypePING, SeqNo: 2}); err != nil {
		t.Fatalf("write the PING: %v", err)
	}
	answerCtx, answerCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer answerCancel()
	// The session's own preface comes first; an answer would be the stream after it.
	if _, err := sc.AcceptUniStream(answerCtx); err != nil {
		t.Fatalf("premise wrong: no preface from the session: %v", err)
	}
	if _, err := sc.AcceptUniStream(answerCtx); err == nil {
		t.Fatal("a PING behind a frame of another type was answered")
	}
}
