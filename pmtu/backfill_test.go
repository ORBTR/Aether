/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package pmtu

import (
	"errors"
	"testing"
	"time"
)

// recordingSender captures every probe emitted by the Prober so tests can
// assert the exact (probeID, paddingSize) sequence. Returned errors let us
// exercise the send-failure path.
type recordingSender struct {
	probeIDs []uint32
	paddings []uint16
	err      error // returned by every call when non-nil
}

func (r *recordingSender) send(probeID uint32, paddingSize uint16) error {
	r.probeIDs = append(r.probeIDs, probeID)
	r.paddings = append(r.paddings, paddingSize)
	return r.err
}

func (r *recordingSender) count() int { return len(r.probeIDs) }

func TestNewProber_InitialState(t *testing.T) {
	rec := &recordingSender{}
	p := NewProber(rec.send)

	if got := p.MSS(); got != DefaultMSS {
		t.Errorf("initial MSS: got %d, want %d", got, DefaultMSS)
	}
	if p.IsProbing() {
		t.Error("fresh prober should not be probing")
	}
	if p.ShouldReprobe() {
		t.Error("fresh prober (Idle) should not want to re-probe")
	}
	if p.ProbeTimedOut() {
		t.Error("fresh prober should not report a timed-out probe")
	}
	if rec.count() != 0 {
		t.Errorf("no probe should be sent before StartProbe, got %d", rec.count())
	}
}

func TestStartProbe_SendsFirstProbe(t *testing.T) {
	rec := &recordingSender{}
	p := NewProber(rec.send)

	p.StartProbe()

	if !p.IsProbing() {
		t.Error("StartProbe should move prober into the probing state")
	}
	if rec.count() != 1 {
		t.Fatalf("StartProbe should send exactly one probe, got %d", rec.count())
	}
	// probeID starts at 0 and is pre-incremented, so the first probe is #1.
	if rec.probeIDs[0] != 1 {
		t.Errorf("first probeID: got %d, want 1", rec.probeIDs[0])
	}
	// First size is probeSizes[0] == 1400; padding = size - 50 header.
	if rec.paddings[0] != 1400-50 {
		t.Errorf("first padding: got %d, want %d", rec.paddings[0], 1400-50)
	}
	// MSS is unchanged until a response confirms a size.
	if p.MSS() != DefaultMSS {
		t.Errorf("MSS before any response: got %d, want %d", p.MSS(), DefaultMSS)
	}
}

func TestStartProbe_IdempotentWhileActive(t *testing.T) {
	rec := &recordingSender{}
	p := NewProber(rec.send)

	p.StartProbe()
	p.StartProbe() // already active — must be a no-op

	if rec.count() != 1 {
		t.Errorf("second StartProbe while active must not send a probe, got %d probes", rec.count())
	}
}

// TestFullDiscoveryWalk drives an entire successful probe sequence and asserts
// the MSS climbs through every probe size and the exact probe frames emitted.
func TestFullDiscoveryWalk(t *testing.T) {
	rec := &recordingSender{}
	p := NewProber(rec.send)

	wantSizes := []int{1400, 1500, 2000, 4000, 8000}

	p.StartProbe()

	// After each successful response the MSS should equal the size just probed,
	// and (until the last) the next probe should have been emitted.
	for i := range wantSizes {
		// The probeID we must echo is i+1 (pre-incremented per probe).
		p.OnProbeResponse(uint32(i + 1))

		if got := p.MSS(); got != wantSizes[i] {
			t.Errorf("after response %d: MSS got %d, want %d", i+1, got, wantSizes[i])
		}
	}

	// All sizes probed → discovery complete.
	if p.IsProbing() {
		t.Error("prober should be complete after the last successful response")
	}
	if p.state != ProbeComplete {
		t.Errorf("final state: got %v, want ProbeComplete", p.state)
	}
	if got := p.MSS(); got != 8000 {
		t.Errorf("final MSS: got %d, want 8000", got)
	}

	// Exactly len(wantSizes) probes should have been emitted, with monotonic IDs
	// and padding == size-50.
	if rec.count() != len(wantSizes) {
		t.Fatalf("probe count: got %d, want %d", rec.count(), len(wantSizes))
	}
	for i, size := range wantSizes {
		if rec.probeIDs[i] != uint32(i+1) {
			t.Errorf("probe %d ID: got %d, want %d", i, rec.probeIDs[i], i+1)
		}
		if int(rec.paddings[i]) != size-50 {
			t.Errorf("probe %d padding: got %d, want %d", i, rec.paddings[i], size-50)
		}
	}
}

func TestOnProbeResponse_StaleProbeIDIgnored(t *testing.T) {
	rec := &recordingSender{}
	p := NewProber(rec.send)

	p.StartProbe()      // sends probe #1
	p.OnProbeResponse(1) // → MSS 1400, sends probe #2
	p.OnProbeResponse(2) // → MSS 1500, sends probe #3 (current probeID now 3)

	beforeMSS := p.MSS()
	beforeCount := rec.count()

	// Echo an old, no-longer-current probeID: must be ignored entirely.
	p.OnProbeResponse(2)

	if p.MSS() != beforeMSS {
		t.Errorf("stale response changed MSS: got %d, want %d", p.MSS(), beforeMSS)
	}
	if rec.count() != beforeCount {
		t.Errorf("stale response sent a probe: count %d, want %d", rec.count(), beforeCount)
	}
	if !p.IsProbing() {
		t.Error("stale response should not end probing")
	}
}

func TestOnProbeResponse_IgnoredWhenIdle(t *testing.T) {
	rec := &recordingSender{}
	p := NewProber(rec.send)

	// Never started — a response must be a no-op.
	p.OnProbeResponse(1)

	if p.MSS() != DefaultMSS {
		t.Errorf("idle response changed MSS: got %d, want %d", p.MSS(), DefaultMSS)
	}
	if p.IsProbing() {
		t.Error("idle response must not start probing")
	}
	if rec.count() != 0 {
		t.Errorf("idle response must not send probes, got %d", rec.count())
	}
}

// TestOnProbeTimeout_KeepsLastSuccessful confirms a timeout freezes the MSS at
// the last confirmed size and completes discovery without emitting more probes.
func TestOnProbeTimeout_KeepsLastSuccessful(t *testing.T) {
	rec := &recordingSender{}
	p := NewProber(rec.send)

	p.StartProbe()       // probe #1 (size 1400)
	p.OnProbeResponse(1) // MSS 1400, probe #2 (size 1500)
	p.OnProbeResponse(2) // MSS 1500, probe #3 (size 2000)

	countBefore := rec.count()

	// Probe #3 (size 2000) gets no response.
	p.OnProbeTimeout()

	if p.IsProbing() {
		t.Error("timeout should complete probing")
	}
	if p.state != ProbeComplete {
		t.Errorf("state after timeout: got %v, want ProbeComplete", p.state)
	}
	if got := p.MSS(); got != 1500 {
		t.Errorf("MSS after timeout: got %d, want 1500 (last confirmed)", got)
	}
	if rec.count() != countBefore {
		t.Errorf("timeout must not send another probe: count %d, want %d", rec.count(), countBefore)
	}
}

func TestOnProbeTimeout_NoOpWhenNotActive(t *testing.T) {
	rec := &recordingSender{}
	p := NewProber(rec.send)

	// Idle: must return early and must NOT index probeSizes[probeIndex].
	p.OnProbeTimeout()
	if p.state != ProbeIdle {
		t.Errorf("timeout while idle changed state to %v", p.state)
	}

	// Complete: also a no-op.
	p.StartProbe()
	for i := 1; i <= 5; i++ {
		p.OnProbeResponse(uint32(i))
	}
	if p.state != ProbeComplete {
		t.Fatalf("setup: expected ProbeComplete, got %v", p.state)
	}
	mssBefore := p.MSS()
	p.OnProbeTimeout()
	if p.MSS() != mssBefore {
		t.Errorf("timeout while complete changed MSS: got %d, want %d", p.MSS(), mssBefore)
	}
}

// TestRestartAfterComplete verifies StartProbe restarts a full cycle from the
// smallest size once discovery has completed (PMTU can shrink over time).
func TestRestartAfterComplete(t *testing.T) {
	rec := &recordingSender{}
	p := NewProber(rec.send)

	p.StartProbe()
	for i := 1; i <= 5; i++ {
		p.OnProbeResponse(uint32(i))
	}
	if p.MSS() != 8000 || p.state != ProbeComplete {
		t.Fatalf("setup: got MSS=%d state=%v, want 8000/Complete", p.MSS(), p.state)
	}
	countAfterFirst := rec.count() // 5

	// Restart. probeID keeps climbing (was 5 → 6); index resets to the smallest.
	p.StartProbe()
	if !p.IsProbing() {
		t.Error("StartProbe after Complete should re-enter probing")
	}
	if rec.count() != countAfterFirst+1 {
		t.Fatalf("restart should emit one probe, got %d", rec.count()-countAfterFirst)
	}
	if rec.probeIDs[len(rec.probeIDs)-1] != 6 {
		t.Errorf("restart probeID: got %d, want 6", rec.probeIDs[len(rec.probeIDs)-1])
	}
	if int(rec.paddings[len(rec.paddings)-1]) != 1400-50 {
		t.Errorf("restart padding: got %d, want %d (smallest size again)",
			rec.paddings[len(rec.paddings)-1], 1400-50)
	}
	// Responding to the restarted first probe drops MSS back to the smallest.
	p.OnProbeResponse(6)
	if p.MSS() != 1400 {
		t.Errorf("MSS after restart's first response: got %d, want 1400", p.MSS())
	}
}

func TestSendProbe_ErrorDoesNotDerailStateMachine(t *testing.T) {
	rec := &recordingSender{err: errors.New("boom")}
	p := NewProber(rec.send)

	// StartProbe's send fails, but the prober must stay Active and have recorded
	// probeSent (so it can later time out) rather than panicking.
	p.StartProbe()

	if !p.IsProbing() {
		t.Error("send error must not stop the prober from being active")
	}
	if rec.count() != 1 {
		t.Errorf("send should still have been attempted once, got %d", rec.count())
	}
	if p.MSS() != DefaultMSS {
		t.Errorf("MSS should be untouched after a send error: got %d", p.MSS())
	}
}

func TestNilSendCallback_DoesNotPanic(t *testing.T) {
	p := NewProber(nil)

	// sendNextProbe guards on sendProbe != nil, so this must be safe.
	p.StartProbe()
	if !p.IsProbing() {
		t.Error("nil-callback prober should still enter probing state")
	}
	// A response still advances the state machine without a sender.
	p.OnProbeResponse(1)
	if p.MSS() != 1400 {
		t.Errorf("MSS after first response with nil sender: got %d, want 1400", p.MSS())
	}
}

// TestProbeTimedOut_Deterministic drives ProbeTimedOut by stamping probeSent
// directly (same-package test) so no wall-clock sleep is needed.
func TestProbeTimedOut_Deterministic(t *testing.T) {
	rec := &recordingSender{}
	p := NewProber(rec.send)

	// Idle: probeSent is zero → not timed out.
	if p.ProbeTimedOut() {
		t.Error("idle prober should never report a timed-out probe")
	}

	p.StartProbe()
	// Just-sent probe: elapsed ~0 < ProbeTimeout → false.
	if p.ProbeTimedOut() {
		t.Error("just-started probe should not be timed out yet")
	}

	// Backdate the send well past ProbeTimeout → true.
	p.mu.Lock()
	p.probeSent = time.Now().Add(-2 * ProbeTimeout)
	p.mu.Unlock()
	if !p.ProbeTimedOut() {
		t.Error("probe older than ProbeTimeout should report timed out")
	}

	// Once no longer Active, ProbeTimedOut must be false regardless of probeSent.
	p.OnProbeTimeout()
	if p.ProbeTimedOut() {
		t.Error("completed prober must not report an in-flight timeout")
	}
}

// TestShouldReprobe_Deterministic drives ShouldReprobe by stamping lastProbe
// directly rather than waiting out ProbeInterval.
func TestShouldReprobe_Deterministic(t *testing.T) {
	rec := &recordingSender{}
	p := NewProber(rec.send)

	// Active state never wants a re-probe.
	p.StartProbe()
	if p.ShouldReprobe() {
		t.Error("active prober should not want to re-probe")
	}

	// Complete the cycle → lastProbe = now, still within ProbeInterval.
	for i := 1; i <= 5; i++ {
		p.OnProbeResponse(uint32(i))
	}
	if p.state != ProbeComplete {
		t.Fatalf("setup: expected ProbeComplete, got %v", p.state)
	}
	if p.ShouldReprobe() {
		t.Error("freshly completed prober should not re-probe yet")
	}

	// Backdate lastProbe beyond ProbeInterval → should re-probe.
	p.mu.Lock()
	p.lastProbe = time.Now().Add(-2 * ProbeInterval)
	p.mu.Unlock()
	if !p.ShouldReprobe() {
		t.Error("prober idle longer than ProbeInterval should want to re-probe")
	}
}

func TestProbeStateConstants(t *testing.T) {
	// Guard the iota ordering the state machine relies on.
	tests := []struct {
		name  string
		state ProbeState
		want  int
	}{
		{"idle", ProbeIdle, 0},
		{"active", ProbeActive, 1},
		{"complete", ProbeComplete, 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if int(tc.state) != tc.want {
				t.Errorf("%s: got %d, want %d", tc.name, int(tc.state), tc.want)
			}
		})
	}
}
