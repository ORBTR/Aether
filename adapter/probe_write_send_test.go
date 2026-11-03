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

	"github.com/ORBTR/aether/pmtu"
)

// waitProbeSweepsDone waits until neither session is probing and each has
// moved its MSS above pmtu.SafeFloorMSS. NewNoiseSession starts a sweep on each
// side, and the sweep writes a PATH_PROBE frame per step and the peer an echo,
// both through writeFrame on the client's conn as well as the server's. A gate
// armed during a sweep can park one of those writes, which holds writeMu, so
// a test that parks a chosen write waits for both sweeps first. Over the
// loopback connection every probe is answered, so a finished sweep has moved
// MSS past the floor, which is also the value MSS reads before the sweep
// starts; the next sweep begins at ShouldReprobe, pmtu.ProbeInterval later.
func waitProbeSweepsDone(t *testing.T, sessions ...*NoiseSession) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for _, s := range sessions {
		for s.pmtuProber.IsProbing() || s.MSS() <= pmtu.SafeFloorMSS {
			if time.Now().After(deadline) {
				t.Fatalf("premise wrong: %s's PMTU sweep did not finish within 30 s (MSS %d, probing %v)",
					s.LocalPeerID(), s.MSS(), s.pmtuProber.IsProbing())
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
}

// TestNoiseStream_SendReturnsAtItsContextWhileAProbeWriteIsParked: a PMTU probe
// the client starts parks in conn.Write, or behind the parked write on writeMu,
// and a Send whose context then ends returns by that end. Send reads the
// prober's MSS for every message, so the read may not wait on the probe's write;
// the prober's state reads the reliability tick makes may not either.
func TestNoiseStream_SendReturnsAtItsContextWhileAProbeWriteIsParked(t *testing.T) {
	client, server, gate := noisePairWithGatedClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cs, _ := openAccept(t, ctx, client, server, 107)
	waitProbeSweepsDone(t, client, server)

	gate.armed.Store(true)
	go client.pmtuProber.StartProbe()
	select {
	case <-gate.blocked:
	case <-time.After(10 * time.Second):
		t.Fatal("premise wrong: no client write reached the gate within 10 s of the probe's start")
	}

	// The sweep is started once IsProbing reads true; StartProbe sets that
	// before it calls the probe's write, which the parked Write keeps from
	// finishing. Each read runs beside the test so a read that waits on the
	// write fails here rather than hanging the run.
	deadline := time.Now().Add(10 * time.Second)
	for started := false; !started; {
		probing := make(chan bool, 1)
		go func() { probing <- client.pmtuProber.IsProbing() }()
		select {
		case started = <-probing:
		case <-time.After(5 * time.Second):
			t.Fatal("IsProbing did not return within 5 s while the probe's write was parked")
		}
		if !started {
			if time.Now().After(deadline) {
				t.Fatal("premise wrong: the probe the test started never read as probing")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}

	sendCtx, sendCancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- cs.Send(sendCtx, []byte("sent while a probe write is parked")) }()
	time.Sleep(200 * time.Millisecond)
	sendCancel()
	select {
	case err := <-done:
		// The scheduler takes the frame without waiting on the write loop, so
		// Send may have returned nil before its context ended.
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("send: %v, want nil or the context's end", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Send did not return within 5 s of its context's end while a probe write was parked")
	}
}
