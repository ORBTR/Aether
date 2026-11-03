/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package pmtu

import (
	"testing"
	"time"
)

// parkedSender is a sendProbe whose call parks until release is closed: the
// shape NoiseSession's probe callback takes when its writeFrame waits on
// writeMu or on a conn.Write the transport has not yet taken. entered receives
// each probe ID as its call begins.
type parkedSender struct {
	entered chan uint32
	release chan struct{}
}

func (s *parkedSender) send(probeID uint32, _ uint16) error {
	s.entered <- probeID
	<-s.release
	return nil
}

// returnsWithin runs f on its own goroutine and fails the test if f has not
// returned within d.
func returnsWithin(t *testing.T, what string, d time.Duration, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		f()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not return within %v while a probe write was parked", what, d)
	}
}

// TestProber_ReadsDoNotWaitOnAParkedProbeWrite: with the probe StartProbe sent
// parked in its write, MSS and the state reads the reliability tick makes
// return, and the response to that probe advances the sweep and sends the next
// probe while the first write is still parked. noiseStream.Send reads MSS for
// every message, so a read that waited on a write would hold every Send on the
// session past its context.
func TestProber_ReadsDoNotWaitOnAParkedProbeWrite(t *testing.T) {
	s := &parkedSender{entered: make(chan uint32, 8), release: make(chan struct{})}
	defer close(s.release)
	p := NewProber(s.send)

	go p.StartProbe()
	var first uint32
	select {
	case first = <-s.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("premise wrong: StartProbe did not call sendProbe within 5 s")
	}

	returnsWithin(t, "MSS", 5*time.Second, func() { _ = p.MSS() })
	returnsWithin(t, "IsProbing", 5*time.Second, func() { _ = p.IsProbing() })
	returnsWithin(t, "ProbeTimedOut", 5*time.Second, func() { _ = p.ProbeTimedOut() })
	returnsWithin(t, "ShouldReprobe", 5*time.Second, func() { _ = p.ShouldReprobe() })

	go p.OnProbeResponse(first)
	select {
	case next := <-s.entered:
		if next != first+1 {
			t.Fatalf("second probe ID %d, want %d", next, first+1)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the response to a probe whose write is parked did not send the next probe within 5 s")
	}
	var mss int
	returnsWithin(t, "MSS after the first response", 5*time.Second, func() { mss = p.MSS() })
	returnsWithin(t, "IsProbing after the first response", 5*time.Second, func() { _ = p.IsProbing() })
	returnsWithin(t, "ProbeTimedOut after the first response", 5*time.Second, func() { _ = p.ProbeTimedOut() })
	if mss != SafeFloorMSS {
		t.Fatalf("MSS after the first probe's response: got %d, want %d", mss, SafeFloorMSS)
	}
}
