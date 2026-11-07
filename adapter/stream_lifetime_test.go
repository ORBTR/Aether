//go:build !js

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

// lifetimeIdle is the stream idle timeout the session-lifetime tests run both ends at.
const lifetimeIdle = 150 * time.Millisecond

// lifetimeOptions are session options naming 700 a session-lifetime stream, with a
// stream idle timeout short enough for a test to idle past several times.
func lifetimeOptions() aether.SessionOptions {
	opts := aether.DefaultSessionOptions()
	opts.StreamIdleTimeout = lifetimeIdle
	opts.SessionLifetimeStreams = []uint64{700}
	return opts
}

// TestTCPSession_ASessionLifetimeChannelOutlivesItsIdleness: two TCP-family sessions
// that both name 700 a session-lifetime stream keep it open, and carrying frames both
// ways, after it idles past several stream idle timeouts, while a per-call stream
// opened beside it is reset by the same GC. The sessions run over a loopback socket:
// both GCs reset the per-call stream in one sweep, and each readLoop writes the other's
// RESET acknowledgement, which an unbuffered net.Pipe holds until the other readLoop,
// itself writing, reads it.
func TestTCPSession_ASessionLifetimeChannelOutlivesItsIdleness(t *testing.T) {
	c, s := loopbackPair(t)
	client := NewTCPSession(c, "lifetime_client", "lifetime_server", aether.ProtoTCP, lifetimeOptions())
	server := NewTCPSession(s, "lifetime_server", "lifetime_client", aether.ProtoTCP, lifetimeOptions())
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	holdsTheLifetimeChannel(t, client, server)
}

// TestNoiseSession_ASessionLifetimeChannelOutlivesItsIdleness is the same hold on two
// NoiseSessions, whose GC the Noise adapter builds from the same options.
func TestNoiseSession_ASessionLifetimeChannelOutlivesItsIdleness(t *testing.T) {
	chosen := aetherChosen(t)
	c, s := loopbackPair(t)
	client := NewNoiseSession(realmConn{Conn: c, chosen: chosen}, "lifetime_client", "lifetime_server", lifetimeOptions())
	server := NewNoiseSession(realmConn{Conn: s, chosen: chosen}, "lifetime_server", "lifetime_client", lifetimeOptions())
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	holdsTheLifetimeChannel(t, client, server)
}

// holdsTheLifetimeChannel opens 700 and the per-call stream 15 from client, idles both
// for six stream idle timeouts, and holds 700 to carrying a frame each way and 15 to
// having been reset.
func holdsTheLifetimeChannel(t *testing.T, client, server aether.Session) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	open := func(id uint64) (aether.Stream, aether.Stream) {
		t.Helper()
		local, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: id, Reliability: aether.ReliableOrdered, Priority: 100})
		if err != nil {
			t.Fatalf("open stream %d: %v", id, err)
		}
		if err := local.Send(ctx, []byte("open")); err != nil {
			t.Fatalf("first send on %d: %v", id, err)
		}
		remote, err := server.AcceptStreamByID(ctx, id)
		if err != nil {
			t.Fatalf("accept stream %d: %v", id, err)
		}
		if _, err := remote.Receive(ctx); err != nil {
			t.Fatalf("first receive on %d: %v", id, err)
		}
		return local, remote
	}
	channelLocal, channelRemote := open(700)
	perCallLocal, _ := open(15)

	time.Sleep(6 * lifetimeIdle)

	if err := perCallLocal.Send(ctx, []byte("late")); err == nil {
		t.Error("a per-call stream idle for 6 stream idle timeouts still sends: the GC reclaimed nothing")
	}
	if err := channelLocal.Send(ctx, []byte("after idle")); err != nil {
		t.Fatalf("the session-lifetime channel was reset after idling: send: %v", err)
	}
	if got, err := channelRemote.Receive(ctx); err != nil || string(got) != "after idle" {
		t.Fatalf("the session-lifetime channel was reset after idling: receive = (%q, %v)", got, err)
	}
	if err := channelRemote.Send(ctx, []byte("back")); err != nil {
		t.Fatalf("the session-lifetime channel was reset after idling: send back: %v", err)
	}
	if got, err := channelLocal.Receive(ctx); err != nil || string(got) != "back" {
		t.Fatalf("the session-lifetime channel was reset after idling: receive back = (%q, %v)", got, err)
	}
	if client.IsClosed() || server.IsClosed() {
		t.Error("a session closed while its channel idled")
	}
}
