//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package adapter

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/pmtu"
)

// lengthDroppingConn is a net.Conn whose Write, once dropping is set, writes
// nothing and records the length it was given, so the peer never acks the
// frame and the sender keeps writing it again.
type lengthDroppingConn struct {
	net.Conn
	dropping atomic.Bool
	mu       sync.Mutex
	lengths  []int
}

func (d *lengthDroppingConn) Write(b []byte) (int, error) {
	if d.dropping.Load() {
		d.mu.Lock()
		d.lengths = append(d.lengths, len(b))
		d.mu.Unlock()
		return len(b), nil
	}
	return d.Conn.Write(b)
}

// writesOfFirstLength returns the length of the first dropped write and how
// many dropped writes had that length.
func (d *lengthDroppingConn) writesOfFirstLength() (length, n int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.lengths) == 0 {
		return 0, 0
	}
	length = d.lengths[0]
	for _, l := range d.lengths {
		if l == length {
			n++
		}
	}
	return length, n
}

// TestNoiseSession_BytesSentCountsPayloadOnEveryWrite: a compressible message
// whose writes never reach the peer is written again by the TLP probe and the
// RTO, each time in the compressed form its first write committed, and every
// write adds the message's payload length to bytesSent, the payload bytes
// Metrics reports as BytesSent, not the frame's shorter wire length.
func TestNoiseSession_BytesSentCountsPayloadOnEveryWrite(t *testing.T) {
	chosen := aetherChosen(t)
	c, s := loopbackPair(t)
	drop := &lengthDroppingConn{Conn: c}
	client := NewNoiseSession(realmConn{Conn: drop, chosen: chosen}, "vl1_count_client", "vl1_count_server", aether.DefaultSessionOptions())
	server := NewNoiseSession(realmConn{Conn: s, chosen: chosen}, "vl1_count_server", "vl1_count_client", aether.DefaultSessionOptions())
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cs, _ := openAccept(t, ctx, client, server, 109)
	st := asNoiseStream(t, cs)
	waitStepAcked(t, st)
	waitProbeSweepsDone(t, client, server)

	msg := compressibleMessage()
	before := client.bytesSent.Load()
	drop.dropping.Store(true)
	if err := cs.Send(ctx, msg); err != nil {
		t.Fatalf("send: %v", err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, n := drop.writesOfFirstLength(); n >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("premise wrong: the frame was not written a second time within 30 s")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// countFrameSent runs before writeQueuedFrame, so every write already
	// recorded here has been counted when bytesSent is read after it.
	wire, n := drop.writesOfFirstLength()
	counted := client.bytesSent.Load() - before
	if wire >= len(msg) {
		t.Fatalf("premise wrong: the frame's wire length %d is not shorter than its %d-byte payload", wire, len(msg))
	}
	if counted < uint64(n*len(msg)) {
		t.Fatalf("bytesSent rose by %d over %d writes of a %d-byte payload (%d bytes each on the wire), want at least %d",
			counted, n, len(msg), wire, n*len(msg))
	}
}

// TestNoiseSession_PathProbeGoesAtItsPaddedSize: a PMTU probe reaches conn.Write
// exactly as long as the largest frame the MSS it tests would carry, on a session
// that compresses frames. This session has no frame key, so that is the size less
// the seal's tag, the size a keyed session's seal then fills. The padding is zeros,
// so a deflated probe would be a few bytes long and would test no path size, and a
// longer probe would have the sweep stop below what the path carries.
func TestNoiseSession_PathProbeGoesAtItsPaddedSize(t *testing.T) {
	chosen := aetherChosen(t)
	c, s := loopbackPair(t)
	drop := &lengthDroppingConn{Conn: c}
	opts := aether.DefaultSessionOptions()
	if !opts.Compression {
		t.Fatal("premise wrong: the default session options do not compress")
	}
	client := NewNoiseSession(realmConn{Conn: drop, chosen: chosen}, "vl1_probe_client", "vl1_probe_server", opts)
	server := NewNoiseSession(realmConn{Conn: s, chosen: chosen}, "vl1_probe_server", "vl1_probe_client", aether.DefaultSessionOptions())
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	waitProbeSweepsDone(t, client, server)

	drop.dropping.Store(true)
	client.pmtuProber.StartProbe()
	// The sweep's first probe tests pmtu.SafeFloorMSS.
	want := aether.FullFrameHeaderWireSize + MSSToMaxPayload(pmtu.SafeFloorMSS)
	if want != pmtu.SafeFloorMSS-frameAEADTagSize {
		t.Fatalf("premise wrong: a full frame at the floor is %d bytes before its seal", want)
	}
	drop.mu.Lock()
	longest := 0
	for _, l := range drop.lengths {
		if l > longest {
			longest = l
		}
	}
	drop.mu.Unlock()
	if longest != want {
		t.Fatalf("longest write after the probe started: %d bytes, want the probe's %d", longest, want)
	}
}
