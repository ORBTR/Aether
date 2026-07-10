package multipath

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/health"
	"github.com/ORBTR/aether/quality"
)

// fakeSession is a minimal aether.Session implementation for tests. We
// only need Health, Metrics, Protocol, IsClosed, and identity.
type fakeSession struct {
	mu       sync.Mutex
	closed   atomic.Bool
	proto    aether.Protocol
	remoteID aether.NodeID
	hm       *health.Monitor
	metrics  aether.SessionMetrics
}

func newFakeSession(proto aether.Protocol, srtt, rttvar time.Duration) *fakeSession {
	hm := health.NewMonitor(0)
	if srtt > 0 {
		// Seed the health monitor with a synthetic ping so SRTT() returns
		// a non-zero value. The estimator updates to the sample.
		hm.RecordPongRecv(0, time.Now().Add(-srtt))
	}
	return &fakeSession{
		proto:    proto,
		remoteID: aether.NodeID("fake-remote"),
		hm:       hm,
	}
}

func (f *fakeSession) OpenStream(context.Context, aether.StreamConfig) (aether.Stream, error) {
	return nil, errors.New("not implemented")
}
func (f *fakeSession) AcceptStream(context.Context) (aether.Stream, error) {
	return nil, errors.New("not implemented")
}
func (f *fakeSession) AcceptStreamByID(context.Context, uint64) (aether.Stream, error) {
	return nil, errors.New("not implemented")
}
func (f *fakeSession) LocalNodeID() aether.NodeID                  { return aether.NodeID("local") }
func (f *fakeSession) RemoteNodeID() aether.NodeID                 { return f.remoteID }
func (f *fakeSession) LocalPeerID() aether.PeerID                  { return aether.PeerID{} }
func (f *fakeSession) RemotePeerID() aether.PeerID                 { return aether.PeerID{} }
func (f *fakeSession) Capabilities() aether.Capabilities           { return 0 }
func (f *fakeSession) Ping(context.Context) (time.Duration, error) { return 0, nil }
func (f *fakeSession) GoAway(context.Context, aether.GoAwayReason, string) error {
	return nil
}
func (f *fakeSession) Close() error               { f.closed.Store(true); return nil }
func (f *fakeSession) IsClosed() bool             { return f.closed.Load() }
func (f *fakeSession) Health() *health.Monitor    { return f.hm }
func (f *fakeSession) SessionKey() []byte         { return nil }
func (f *fakeSession) ConnectionID() aether.ConnectionID {
	return aether.ConnectionID{}
}
func (f *fakeSession) CongestionWindow() int64    { return 0 }
func (f *fakeSession) Protocol() aether.Protocol  { return f.proto }
func (f *fakeSession) Metrics() aether.SessionMetrics {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.metrics
}

func (f *fakeSession) setMetrics(m aether.SessionMetrics) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.metrics = m
}

func TestPickByQuality_FallsBackToLegacyWhenNoConfig(t *testing.T) {
	m := NewManager()
	s := newFakeSession(aether.ProtoNoise, 5*time.Millisecond, time.Millisecond)
	m.AddPath(s, aether.ProtoNoise, 100)

	got, ok := m.PickByQuality(quality.OpDefault)
	if !ok {
		t.Fatal("PickByQuality should fall back to PrimarySession when no quality config")
	}
	if got != s {
		t.Errorf("PickByQuality returned wrong session in legacy fallback")
	}
}

func TestPickByQuality_PrefersHigherScoreSession(t *testing.T) {
	tracker := quality.NewTracker()
	m := NewManager()
	// Two sessions to the same peer over different transports. The
	// noise-udp one is healthy; the WS one has consecutive failures
	// recorded so its score is dragged down.
	udpSess := newFakeSession(aether.ProtoNoise, 5*time.Millisecond, time.Millisecond)
	wsSess := newFakeSession(aether.ProtoWebSocket, 5*time.Millisecond, time.Millisecond)

	if err := m.EnsureK(context.Background(), QualityConfig{
		Tracker:     tracker,
		LocalRegion: "syd",
		PeerID:      "peer1",
		Weights:     quality.DefaultWeights,
	}, 0); err != nil {
		t.Fatalf("EnsureK: %v", err)
	}

	m.AddPathQA(udpSess, aether.ProtoNoise, "syd") // same-region
	m.AddPathQA(wsSess, aether.ProtoWebSocket, "syd")

	// Inject failure history on the WS path.
	tracker.RecordClose(quality.Key("peer1", aether.ProtoWebSocket.String()), false)
	tracker.RecordClose(quality.Key("peer1", aether.ProtoWebSocket.String()), false)
	tracker.RecordClose(quality.Key("peer1", aether.ProtoWebSocket.String()), false)

	// Set both to old enough to clear age grace.
	for _, p := range m.paths {
		p.LastSuccess = time.Now().Add(-2 * time.Minute)
	}

	got, ok := m.PickByQuality(quality.OpDefault)
	if !ok {
		t.Fatal("PickByQuality should return a session")
	}
	if got != udpSess {
		t.Errorf("expected UDP session (no failures), got WS session (3 failures)")
	}
}

func TestPickByQuality_RegionAffinityForOpDefault(t *testing.T) {
	tracker := quality.NewTracker()
	m := NewManager()

	// Two equally-healthy paths to peer in syd: one same-region (we
	// are syd), one cross-region (relay through iad). Same-region
	// should win on default op-class.
	sameRegionSess := newFakeSession(aether.ProtoWebSocket, 5*time.Millisecond, time.Millisecond)
	crossRegionSess := newFakeSession(aether.ProtoWebSocket, 250*time.Millisecond, 20*time.Millisecond)

	if err := m.EnsureK(context.Background(), QualityConfig{
		Tracker:     tracker,
		LocalRegion: "syd",
		PeerID:      "peer1",
		Weights:     quality.DefaultWeights,
	}, 0); err != nil {
		t.Fatalf("EnsureK: %v", err)
	}

	m.AddPathQA(sameRegionSess, aether.ProtoWebSocket, "syd")
	m.AddPathQA(crossRegionSess, aether.ProtoWebSocket, "iad")

	for _, p := range m.paths {
		p.LastSuccess = time.Now().Add(-2 * time.Minute)
	}

	got, ok := m.PickByQuality(quality.OpDefault)
	if !ok {
		t.Fatal("PickByQuality should return a session")
	}
	if got != sameRegionSess {
		t.Errorf("expected same-region session, got cross-region")
	}
}

func TestEnsureK_DialsUntilTargetReached(t *testing.T) {
	tracker := quality.NewTracker()
	m := NewManager()

	dialed := atomic.Int32{}
	cfg := QualityConfig{
		Tracker:     tracker,
		LocalRegion: "syd",
		PeerID:      "peer1",
		Weights:     quality.DefaultWeights,
		DialFunc: func(ctx context.Context) (aether.Session, aether.Protocol, string, error) {
			n := dialed.Add(1)
			if n > 3 {
				// Stop dialing once we've added enough — return nil
				// session, no error to indicate "no candidate".
				return nil, 0, "", nil
			}
			return newFakeSession(aether.ProtoNoise, 5*time.Millisecond, time.Millisecond),
				aether.ProtoNoise, "syd", nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := m.EnsureK(ctx, cfg, 3); err != nil {
		t.Fatalf("EnsureK: %v", err)
	}
	defer m.Stop()

	// Wait for the loop to converge to target.
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if m.aliveCount() >= 3 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if m.aliveCount() < 3 {
		t.Errorf("EnsureK should have dialed to 3 paths; got %d", m.aliveCount())
	}
}

func TestEnsureK_BacksOffOnConsecutiveFailures(t *testing.T) {
	tracker := quality.NewTracker()
	m := NewManager()

	dialErrors := atomic.Int32{}
	cfg := QualityConfig{
		Tracker:     tracker,
		LocalRegion: "syd",
		PeerID:      "peer1",
		Weights:     quality.DefaultWeights,
		DialFunc: func(ctx context.Context) (aether.Session, aether.Protocol, string, error) {
			dialErrors.Add(1)
			return nil, 0, "", errors.New("dial refused")
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	if err := m.EnsureK(ctx, cfg, 1); err != nil {
		t.Fatalf("EnsureK: %v", err)
	}
	defer m.Stop()

	// Let it run for ~10s. With base backoff 5s and exponential growth,
	// we should see roughly 2-3 dial attempts in 10s, NOT a tight loop
	// pounding the dial fn many times per second.
	time.Sleep(10 * time.Second)
	got := dialErrors.Load()
	if got > 5 {
		t.Errorf("backoff broken: got %d dial attempts in 10s, expected ≤5", got)
	}
	if got < 1 {
		t.Errorf("dial loop never fired: got %d attempts", got)
	}
}

func TestStop_TerminatesEnsureGoroutine(t *testing.T) {
	tracker := quality.NewTracker()
	m := NewManager()

	dialed := atomic.Int32{}
	cfg := QualityConfig{
		Tracker:     tracker,
		LocalRegion: "syd",
		PeerID:      "peer1",
		Weights:     quality.DefaultWeights,
		DialFunc: func(ctx context.Context) (aether.Session, aether.Protocol, string, error) {
			dialed.Add(1)
			return nil, 0, "", errors.New("dial refused")
		},
	}
	if err := m.EnsureK(context.Background(), cfg, 1); err != nil {
		t.Fatalf("EnsureK: %v", err)
	}
	time.Sleep(5500 * time.Millisecond)
	beforeStop := dialed.Load()
	m.Stop()
	time.Sleep(8 * time.Second)
	afterStop := dialed.Load()
	if afterStop > beforeStop+1 {
		// Allow up to one in-flight dial to finish after Stop;
		// anything beyond that means the goroutine didn't exit.
		t.Errorf("Stop didn't terminate goroutine: %d before, %d after", beforeStop, afterStop)
	}
}

// TestPickByQuality_SkipsFlappingAndDeadPaths is the AE-M-10 regression.
// PickByQuality must not hand back a session on a PathDead or PathFlapping
// path (both keep a live session — a flapping path's Ping still succeeds,
// a dead path within deadResurrectCooldown too), which would silently
// defeat the flapping demote and primary-failure failover. It must also
// resurrect flapping paths whose demote window has elapsed so a recovered
// path is selectable again.
func TestPickByQuality_SkipsFlappingAndDeadPaths(t *testing.T) {
	tracker := quality.NewTracker()
	m := NewManager()

	// Higher-grade Noise path (grade A) vs a WS path (grade C) dragged
	// lower with recorded failures — absent any demotion the Noise path
	// is the unambiguous winner, so if a later assertion returns the WS
	// session it can only be because the guard shunned the Noise path.
	noiseSess := newFakeSession(aether.ProtoNoise, 5*time.Millisecond, time.Millisecond)
	wsSess := newFakeSession(aether.ProtoWebSocket, 5*time.Millisecond, time.Millisecond)

	if err := m.EnsureK(context.Background(), QualityConfig{
		Tracker:     tracker,
		LocalRegion: "syd",
		PeerID:      "peer1",
		Weights:     quality.DefaultWeights,
	}, 0); err != nil {
		t.Fatalf("EnsureK: %v", err)
	}

	m.AddPathQA(noiseSess, aether.ProtoNoise, "syd") // same-region, grade A
	m.AddPathQA(wsSess, aether.ProtoWebSocket, "syd") // same-region, grade C

	tracker.RecordClose(quality.Key("peer1", aether.ProtoWebSocket.String()), false)
	tracker.RecordClose(quality.Key("peer1", aether.ProtoWebSocket.String()), false)
	tracker.RecordClose(quality.Key("peer1", aether.ProtoWebSocket.String()), false)

	// Age both past the AgeGrace ramp so their scores are clearly
	// non-zero and the grade/health ordering is deterministic.
	old := time.Now().Add(-2 * time.Minute)
	for _, p := range m.paths {
		p.LastSuccess = old
		p.CreatedAt = old
	}

	pathByProto := func(proto aether.Protocol) *Path {
		t.Helper()
		for _, p := range m.paths {
			if p.Protocol == proto {
				return p
			}
		}
		t.Fatalf("no path for protocol %s", proto)
		return nil
	}
	noisePath := pathByProto(aether.ProtoNoise)

	// Baseline: with no path demoted, the higher-grade Noise path wins.
	if got, ok := m.PickByQuality(quality.OpDefault); !ok || got != noiseSess {
		t.Fatalf("baseline: want Noise session ok=true, got=%v ok=%v", got, ok)
	}

	// Case A — flapping path (session still alive) must be shunned; the
	// healthy WS path is selected instead of the higher-scoring flapper.
	noisePath.State = PathFlapping
	noisePath.flappingUntil = time.Now().Add(time.Minute)
	if got, ok := m.PickByQuality(quality.OpDefault); !ok || got != wsSess {
		t.Errorf("Case A (flapping): want WS session ok=true, got=%v ok=%v", got, ok)
	}

	// Case B — dead path within deadResurrectCooldown (session still
	// alive) must be shunned.
	noisePath.State = PathDead
	noisePath.flappingUntil = time.Time{}
	noisePath.LastFailure = time.Now()
	if got, ok := m.PickByQuality(quality.OpDefault); !ok || got != wsSess {
		t.Errorf("Case B (dead-in-cooldown): want WS session ok=true, got=%v ok=%v", got, ok)
	}

	// Case C — flapping demote window already elapsed: the added
	// resurrectExpiredFlappingPathsLocked call restores the path to
	// PathStandby so the highest-score Noise path is selectable again.
	noisePath.State = PathFlapping
	noisePath.LastFailure = time.Time{}
	noisePath.flappingUntil = time.Now().Add(-time.Second)
	if got, ok := m.PickByQuality(quality.OpDefault); !ok || got != noiseSess {
		t.Errorf("Case C (recovered flapper): want Noise session ok=true, got=%v ok=%v", got, ok)
	}
	if noisePath.State != PathStandby {
		t.Errorf("Case C: elapsed flapper should be resurrected to Standby, got %s", noisePath.State)
	}

	// Case D — every path demoted with a future window: no candidate
	// survives the guard, so PickByQuality reports no session rather than
	// handing back a shunned path.
	for _, p := range m.paths {
		p.State = PathFlapping
		p.flappingUntil = time.Now().Add(time.Minute)
	}
	if got, ok := m.PickByQuality(quality.OpDefault); ok {
		t.Errorf("Case D (all demoted): want ok=false, got=%v ok=%v", got, ok)
	}
}
