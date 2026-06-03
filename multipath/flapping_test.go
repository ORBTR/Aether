package multipath

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// TestRecordTLPReset_DemoteAndRecover walks the full PathFlapping
// state-machine end-to-end:
//
//  1. Two paths to the same peer (noise-UDP primary, WS standby).
//  2. Record flappingResetThreshold tlpReset hits on the noise-UDP
//     path inside the flappingWindowDur window.
//  3. Assert noise-UDP transitions to PathFlapping.
//  4. Assert promotebestStandby (via PrimarySession after the
//     demote-driven failover RecordTLPReset performs) picks the WS
//     path so dispatch traffic moves off the flaky transport.
//  5. Advance the injected clock past flappingDemoteDur with no
//     further hits and trigger the opportunistic-resurrection path
//     via PickPath. Assert the noise-UDP path reverts to
//     PathStandby and is again primary after a manual
//     promotebestStandby (Quality 100 > 30 → wins re-election).
func TestRecordTLPReset_DemoteAndRecover(t *testing.T) {
	m := NewManager()

	// Injectable clock. virtualNow is read by Manager.now() through
	// nowFunc; tests advance it deterministically with advance().
	var virtualNow atomic.Pointer[time.Time]
	start := time.Now()
	virtualNow.Store(&start)
	m.nowFunc = func() time.Time { return *virtualNow.Load() }
	advance := func(d time.Duration) {
		t := virtualNow.Load().Add(d)
		virtualNow.Store(&t)
	}

	udpSess := newFakeSession(aether.ProtoNoise, 5*time.Millisecond, time.Millisecond)
	wsSess := newFakeSession(aether.ProtoWebSocket, 5*time.Millisecond, time.Millisecond)

	// Add UDP first so it becomes primary (Quality 100 > nothing →
	// promoted to PathActive on insert). Then WS (Quality 30 →
	// stays PathStandby).
	m.AddPath(udpSess, aether.ProtoNoise, 100)
	m.AddPath(wsSess, aether.ProtoWebSocket, 30)

	// Sanity check pre-conditions.
	if primary, ok := m.PrimarySession(); !ok || primary != udpSess {
		t.Fatalf("UDP path should be primary before any tlpResets")
	}

	// Record threshold-1 hits — should NOT demote yet. Each hit
	// advances virtual time by 1s so all three land inside the
	// 5-minute window.
	for i := 0; i < flappingResetThreshold-1; i++ {
		if demoted := m.RecordTLPReset(udpSess); demoted {
			t.Fatalf("hit #%d should not have demoted (below threshold)", i+1)
		}
		advance(1 * time.Second)
	}
	m.mu.Lock()
	udpPath := m.paths[0]
	if udpPath.State != PathActive {
		t.Errorf("UDP path should still be PathActive before threshold; got %s", udpPath.State)
	}
	m.mu.Unlock()

	// Threshold-crossing hit — should demote AND hand primary to WS.
	if demoted := m.RecordTLPReset(udpSess); !demoted {
		t.Fatalf("threshold-crossing hit should have demoted UDP path to PathFlapping")
	}

	m.mu.Lock()
	if udpPath.State != PathFlapping {
		t.Errorf("UDP path should be PathFlapping after threshold; got %s", udpPath.State)
	}
	m.mu.Unlock()

	primary, ok := m.PrimarySession()
	if !ok {
		t.Fatal("PrimarySession should return a session after demote")
	}
	if primary != wsSess {
		t.Errorf("primary should have moved to WS path after UDP demote; got proto=%v", primary.Protocol())
	}

	// Sanity-check the demote-window enforcement: PickPath (which
	// runs the opportunistic flapping resurrection) before the
	// window elapses should still see UDP demoted. PickPath with
	// weightedLB disabled returns PrimarySession, so we check the
	// internal state directly here — confirm
	// resurrectExpiredFlappingPathsLocked has not yet promoted.
	advance(flappingDemoteDur / 2) // half-way through demote
	m.mu.Lock()
	m.resurrectExpiredFlappingPathsLocked()
	if udpPath.State != PathFlapping {
		t.Errorf("UDP path should still be PathFlapping at t=demoteDur/2; got %s", udpPath.State)
	}
	m.mu.Unlock()

	// Advance clock past the demote window. 70s > 60s
	// flappingDemoteDur, less the demoteDur/2 already advanced.
	// We want total > flappingDemoteDur since the LAST tlpReset.
	advance(70*time.Second - flappingDemoteDur/2)

	// Trigger the opportunistic resurrection. PathFlappingCount
	// runs resurrectExpiredFlappingPathsLocked then returns the
	// post-recovery count.
	if got := m.PathFlappingCount(); got != 0 {
		t.Errorf("after demote window elapsed expected PathFlappingCount=0; got %d", got)
	}

	m.mu.Lock()
	if udpPath.State != PathStandby {
		t.Errorf("UDP path should have reverted to PathStandby; got %s", udpPath.State)
	}
	if !udpPath.flappingUntil.IsZero() {
		t.Errorf("flappingUntil should be cleared after recovery")
	}
	m.mu.Unlock()

	// Re-run promotion. Quality 100 > 30 → UDP wins re-election.
	m.mu.Lock()
	m.promotebestStandby()
	m.mu.Unlock()
	if primary, ok := m.PrimarySession(); !ok || primary != udpSess {
		t.Fatalf("UDP path should be re-elected primary after recovery; got proto=%v", func() any {
			if primary == nil {
				return "nil"
			}
			return primary.Protocol()
		}())
	}
}

// TestRecordTLPReset_SustainedBurstExtendsDemote verifies that hits
// arriving DURING the demote window push the recovery deadline
// forward (so a slow drip of resets at 50 s intervals doesn't let
// the path recover between hits). Without this behaviour a flaky
// path would re-flap immediately after every recovery.
func TestRecordTLPReset_SustainedBurstExtendsDemote(t *testing.T) {
	m := NewManager()
	var virtualNow atomic.Pointer[time.Time]
	start := time.Now()
	virtualNow.Store(&start)
	m.nowFunc = func() time.Time { return *virtualNow.Load() }
	advance := func(d time.Duration) {
		t := virtualNow.Load().Add(d)
		virtualNow.Store(&t)
	}

	udpSess := newFakeSession(aether.ProtoNoise, 5*time.Millisecond, time.Millisecond)
	wsSess := newFakeSession(aether.ProtoWebSocket, 5*time.Millisecond, time.Millisecond)
	m.AddPath(udpSess, aether.ProtoNoise, 100)
	m.AddPath(wsSess, aether.ProtoWebSocket, 30)

	// Trigger initial demote.
	for i := 0; i < flappingResetThreshold; i++ {
		m.RecordTLPReset(udpSess)
		advance(1 * time.Second)
	}
	m.mu.Lock()
	udpPath := m.paths[0]
	initialUntil := udpPath.flappingUntil
	m.mu.Unlock()
	if udpPath.State != PathFlapping {
		t.Fatalf("expected PathFlapping after initial burst; got %s", udpPath.State)
	}

	// 50s later — still inside demote window. Another tlpReset
	// should extend the deadline by another flappingDemoteDur.
	advance(50 * time.Second)
	m.RecordTLPReset(udpSess)

	m.mu.Lock()
	extendedUntil := udpPath.flappingUntil
	m.mu.Unlock()

	if !extendedUntil.After(initialUntil) {
		t.Errorf("flappingUntil should advance on hits during demote (initial=%v extended=%v)",
			initialUntil, extendedUntil)
	}

	// Verify state is still Flapping after the original deadline
	// would have elapsed — without the extension, recovery would
	// have run by now.
	advance(flappingDemoteDur / 2) // total 80s since first hit, but only 30s since the extending hit
	if got := m.PathFlappingCount(); got != 1 {
		t.Errorf("expected path to still be flapping post-extension; PathFlappingCount=%d", got)
	}
}

// TestRecordTLPReset_OutOfWindowDoesNotDemote verifies the sliding
// window semantics: hits older than flappingWindowDur don't count
// toward the threshold, so a path emitting one false-positive every
// 6 minutes will never be demoted.
func TestRecordTLPReset_OutOfWindowDoesNotDemote(t *testing.T) {
	m := NewManager()
	var virtualNow atomic.Pointer[time.Time]
	start := time.Now()
	virtualNow.Store(&start)
	m.nowFunc = func() time.Time { return *virtualNow.Load() }
	advance := func(d time.Duration) {
		t := virtualNow.Load().Add(d)
		virtualNow.Store(&t)
	}

	udpSess := newFakeSession(aether.ProtoNoise, 5*time.Millisecond, time.Millisecond)
	m.AddPath(udpSess, aether.ProtoNoise, 100)

	// Three hits, each separated by 6 minutes — well past the
	// 5-minute sliding window. The ring will contain three
	// timestamps but only the most recent counts as "in-window".
	for i := 0; i < flappingResetThreshold; i++ {
		if demoted := m.RecordTLPReset(udpSess); demoted {
			t.Fatalf("hit #%d separated by 6min should not demote", i+1)
		}
		advance(6 * time.Minute)
	}

	m.mu.Lock()
	if m.paths[0].State == PathFlapping {
		t.Errorf("path should NOT be flapping with all hits outside window")
	}
	m.mu.Unlock()
}

// TestRecordTLPReset_UnknownSessionIsNoOp guards against panic when
// the caller passes a session that's not registered with this
// manager (e.g. the multipath manager was just torn down and the
// connection-manager forwarded one last tlpReset event).
func TestRecordTLPReset_UnknownSessionIsNoOp(t *testing.T) {
	m := NewManager()
	udpSess := newFakeSession(aether.ProtoNoise, 5*time.Millisecond, time.Millisecond)
	m.AddPath(udpSess, aether.ProtoNoise, 100)

	stranger := newFakeSession(aether.ProtoNoise, 5*time.Millisecond, time.Millisecond)
	if demoted := m.RecordTLPReset(stranger); demoted {
		t.Errorf("RecordTLPReset on unknown session should return false")
	}
	if got := m.PathFlappingCount(); got != 0 {
		t.Errorf("PathFlappingCount should be 0 after unknown-session call; got %d", got)
	}
}
