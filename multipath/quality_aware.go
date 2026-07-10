package multipath

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/quality"
)

// QualityConfig governs how the manager uses quality scores. Optional —
// callers that don't set this fall back to the legacy integer-Quality
// path (computePathWeight + setPrimary by integer comparison) for back-
// compat with code not yet migrated to the score-driven plane.
type QualityConfig struct {
	// Tracker holds longer-window state shared across paths in this
	// manager. One Tracker per ConnectionManager (the Library passes
	// the same instance to every per-peer Manager) so failure history
	// is visible across reconnects.
	Tracker *quality.Tracker

	// LocalRegion is the region tag of the current node ("syd", "iad",
	// etc). Combined with each path's RemoteRegion to classify
	// RouteClass for score normalization.
	LocalRegion string

	// PeerID is the remote node's stable identifier; used as part of
	// the Tracker key so failure history is per-(peer,transport).
	PeerID string

	// Weights for the score's geometric mean. Defaults to
	// quality.DefaultWeights when zero.
	Weights quality.Weights

	// DialFunc is called by the EnsureK reconnect loop when the
	// manager has fewer than the target K paths. Caller is responsible
	// for picking which transport to dial; the manager just signals
	// "dial something" by invoking this callback. Returning a nil
	// session + nil error means "no candidate available right now",
	// which the manager treats as backoff.
	//
	// The manager calls AddPathQA on whatever the dial function
	// returns — callers should NOT also AddPath on success.
	DialFunc func(ctx context.Context) (session aether.Session, proto aether.Protocol, remoteRegion string, err error)
}

// PathMeta holds per-path metadata that's needed for score computation
// but isn't part of the legacy Path struct (which is wire-stable for
// debug snapshots). Stored side-by-side with paths in a parallel map.
type PathMeta struct {
	RemoteRegion string
	Class        quality.RouteClass
	TrackerKey   string
	LastScore    quality.Score
	LastScoreAt  time.Time

	// LastTrackerUpdate throttles the side-effect that PickByQuality
	// (via computeScoreLocked) used to do on every dispatch call:
	// UpdateRTT + UpdateThroughput on the Tracker. At dispatch rates
	// of hundreds per second, that collapsed the baselineRTT EMA to
	// instantaneous SRTT in ~60 calls (α=0.05 × 60 samples) instead
	// of the intended ~60 seconds — killing the RTT-spike signal the
	// quality.Inputs.BaselineRTT field is supposed to provide.
	// L4 #3 fix: only refresh the tracker EMAs once per
	// trackerUpdateMinInterval per path.
	LastTrackerUpdate time.Time
}

// trackerUpdateMinInterval is the minimum gap between Tracker EMA
// updates per path. Picked so the EMA converges over its intended
// time horizon regardless of dispatch frequency.
const trackerUpdateMinInterval = 1 * time.Second

// addQualityState extends Manager with quality-aware bookkeeping.
// Held in a separate struct so legacy callers don't need to know about
// it. Lookup is by Path pointer identity.
type qualityState struct {
	mu      sync.Mutex
	cfg     QualityConfig
	meta    map[*Path]*PathMeta
	stop    chan struct{} // closed by Stop()
	target  int           // K — current EnsureK target
	stopped bool

	// probeOnce gates RunProbeLoop start so EnsureK can launch it
	// idempotently on first call. The probe loop pings non-primary
	// paths every probeInterval so dead/standby paths can resurrect
	// based on real liveness signal — without this, dead-path recovery
	// only happens opportunistically when something calls PickPath /
	// PickByQuality (audit critical finding #1).
	probeOnce sync.Once
}

// EnsureK starts (or updates) a goroutine that maintains at least k
// paths to this peer by calling cfg.DialFunc when len(paths) < k.
// Idempotent: calling EnsureK multiple times with different k values
// updates the target. Pass k=0 to disable (the goroutine exits).
//
// The dial loop runs at adaptive cadence: tight when below target,
// relaxed once at-target. A single dial in flight at a time so a
// peer with permanent dial failures doesn't hammer; backoff on
// consecutive failures uses an exponential curve floored at 5 s and
// capped at 60 s.
//
// Replaces the old `Scaler.scaleUp(target=N)` mechanism — the scaler
// used to decide "I want N connections to this peer" outside the
// multipath manager and dial through the connection manager. This
// folds the decision INTO the manager that already knows how many
// paths there are, eliminating the cross-loop coordination.
func (m *Manager) EnsureK(ctx context.Context, cfg QualityConfig, k int) error {
	m.mu.Lock()
	if m.qstate == nil {
		m.qstate = &qualityState{
			cfg:    cfg,
			meta:   make(map[*Path]*PathMeta),
			stop:   make(chan struct{}),
			target: k,
		}
		q := m.qstate
		m.mu.Unlock()
		go q.runEnsure(ctx, m)
		// Critical fix: start the probe loop ONCE per manager. Without
		// this RunProbeLoop is dead code (it was defined but never
		// invoked, so dead-path resurrection only happened on
		// opportunistic PickPath / PickByQuality calls). Now every
		// manager that runs EnsureK gets active liveness probes.
		q.probeOnce.Do(func() {
			go m.RunProbeLoop(ctx)
		})
		return nil
	}
	m.qstate.mu.Lock()
	if m.qstate.stopped {
		m.qstate.mu.Unlock()
		m.mu.Unlock()
		return errors.New("manager already stopped")
	}
	m.qstate.cfg = cfg
	m.qstate.target = k
	q := m.qstate
	m.qstate.mu.Unlock()
	m.mu.Unlock()
	// Late-arriving EnsureK call (e.g., manager existed from a prior
	// AddPathQA without EnsureK) — also start the probe loop once.
	q.probeOnce.Do(func() {
		go m.RunProbeLoop(ctx)
	})
	return nil
}

// Stop terminates the EnsureK goroutine for this manager. Safe to call
// when EnsureK was never started.
func (m *Manager) Stop() {
	m.mu.Lock()
	q := m.qstate
	m.mu.Unlock()
	if q == nil {
		return
	}
	q.mu.Lock()
	if q.stopped {
		q.mu.Unlock()
		return
	}
	q.stopped = true
	close(q.stop)
	q.mu.Unlock()
}

// gradeQualityForProto maps an aether.Protocol to the legacy integer
// `Quality` used by setPrimary / promotebestStandby / computePathWeight.
// Higher = better. Mirrors the Grade A/B/C hierarchy in
// the consuming mesh grade layer so the legacy WDRR scheduler picks the
// SAME path the grade-aware scaler would.
//
// Cascade A.2 fix (L4 #1): AddPathQA previously passed Quality=0 for
// every path, leaving setPrimary/promotebestStandby blind to grade —
// whichever path was registered first became permanent primary even
// when a higher-grade path arrived later. With this mapping, a noise
// path arriving after a WS path actually displaces it.
func gradeQualityForProto(proto aether.Protocol) int {
	switch proto {
	case aether.ProtoNoise:
		return 100 // Grade A
	case aether.ProtoQUIC, aether.ProtoGRPC:
		return 60 // Grade B
	case aether.ProtoWebSocket, aether.ProtoTCP:
		return 30 // Grade C
	default:
		return 10 // Unknown / fallback — never zero, so it can still
		// be promoted over a path with truly no signal.
	}
}

// AddPathQA registers a path with quality-aware metadata. Equivalent
// to AddPath but also records the remote region so the path can be
// classified by RouteClass for score normalisation. Callers that
// don't pass a region or quality config can keep using AddPath; the
// two coexist so the legacy WDRR scheduler keeps working alongside.
//
// Audit M11: AddPath is invoked through the lock-already-held
// addPathLocked variant so the qstate.meta entry is attached to the
// path returned in the SAME critical section — closes the race where
// a concurrent AddPath could insert between AddPathQA's
// AddPath-unlock and AddPathQA-relock and leave meta pointing at the
// wrong Path pointer.
func (m *Manager) AddPathQA(session aether.Session, proto aether.Protocol, remoteRegion string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	path := m.addPathLocked(session, proto, gradeQualityForProto(proto))
	if path == nil {
		return
	}

	if m.qstate == nil {
		// Quality state not initialised — caller hasn't called
		// EnsureK yet. Allocate so subsequent AddPathQA calls find
		// the same map; EnsureK will populate cfg later.
		m.qstate = &qualityState{
			meta: make(map[*Path]*PathMeta),
			stop: make(chan struct{}),
		}
	}

	cfg := m.qstate.cfg
	class := quality.ClassifyRegions(cfg.LocalRegion, remoteRegion)
	key := quality.Key(cfg.PeerID, proto.String())

	m.qstate.mu.Lock()
	m.qstate.meta[path] = &PathMeta{
		RemoteRegion: remoteRegion,
		Class:        class,
		TrackerKey:   key,
	}
	m.qstate.mu.Unlock()
}

// PickByQuality returns the highest-DispatchRank alive session for the
// given op class. Falls back to PrimarySession if no quality-aware paths
// exist yet (legacy callers).
//
// This is the score-driven replacement for PrimarySession + PickPath.
// Unlike those, it doesn't need an explicit "primary" — selection is
// deterministic from the current scores.
func (m *Manager) PickByQuality(op quality.DispatchOp) (aether.Session, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Opportunistic dead-path resurrection — see Manager.PickPath for
	// the same call. Even without RunProbeLoop running, a path whose
	// cooldown elapsed is back in the candidate pool here.
	m.resurrectExpiredDeadPathsLocked()
	m.resurrectExpiredFlappingPathsLocked()
	if m.qstate == nil || m.qstate.cfg.Tracker == nil {
		// No quality config; fall back to legacy primary selection.
		if len(m.paths) == 0 || m.primary >= len(m.paths) {
			return nil, false
		}
		return m.paths[m.primary].Session, true
	}

	var bestSession aether.Session
	bestRank := -1.0
	for _, p := range m.paths {
		if p.Session == nil || p.Session.IsClosed() {
			continue
		}
		// AE-M-10: exclude PathDead / PathFlapping from quality-aware
		// selection, mirroring PickPath and promotebestStandby
		// (manager.go). A flapping path's session is still alive (its
		// Ping succeeds — the RecordTLPReset premise) and a dead path
		// within deadResurrectCooldown also has a live session, so both
		// pass the nil/IsClosed guard above and would win on DispatchRank,
		// silently defeating the flapping demote and primary-failure
		// failover. The resurrection calls above return any path whose
		// cooldown/demote window has elapsed to PathStandby, so this only
		// shuns paths still inside their window — capability preserved.
		if p.State == PathDead || p.State == PathFlapping {
			continue
		}
		score := m.computeScoreLocked(p)
		rank := quality.DispatchRank(score, op)
		if rank > bestRank {
			bestRank = rank
			bestSession = p.Session
		}
	}
	if bestSession == nil {
		return nil, false
	}
	return bestSession, true
}

// PeerStatsReporter is the optional capability multipath probes for on
// each session — when present, it returns the most recent STATS frame
// the peer reported. Used by computeScoreLocked to fold the peer's
// observed loss / reorder / RTT into the scoring inputs so an
// asymmetric path (downstream healthy on our side, upstream lossy on
// the peer's side) doesn't score as healthy on local signals alone.
//
// Sessions that don't ship STATS frames (TCP, QUIC, in-process fakes)
// simply don't implement this interface; the type assertion below
// fails silently and the scorer falls back to local-metrics-only — the
// behaviour multipath had pre-STATS-wiring, so no regression for those
// transports.
type PeerStatsReporter interface {
	LastPeerStats() aether.SessionMetrics
}

// computeScoreLocked computes the current quality score for a path.
// Caller must hold m.mu. Reads metrics from the session's health
// monitor and tracker — does NOT do I/O so safe under the lock.
func (m *Manager) computeScoreLocked(p *Path) quality.Score {
	if m.qstate == nil {
		return quality.Score{}
	}
	cfg := m.qstate.cfg
	if cfg.Tracker == nil {
		return quality.Score{}
	}

	m.qstate.mu.Lock()
	meta := m.qstate.meta[p]
	m.qstate.mu.Unlock()
	if meta == nil {
		return quality.Score{}
	}

	w := cfg.Weights
	if w == (quality.Weights{}) {
		w = quality.DefaultWeights
	}

	health := p.Session.Health()
	metrics := p.Session.Metrics()

	// Sum reorder counts across streams (per-stream observe data).
	var reorders int64
	for _, sd := range metrics.StreamObserve {
		reorders += sd.ReorderCount
	}

	// Asymmetric-aware folding: probe the session for the peer's last
	// STATS frame, then take the worse of {local, peer} for the loss /
	// reorder / drop signals. Rationale: a path that's healthy in the
	// direction we observe (downstream) but lossy in the direction we
	// send (upstream) is invisible to local metrics alone — the peer's
	// drop / reorder counts ARE the upstream loss signal. Taking the
	// max-of-pair gives the scorer the worst-case view; a path that
	// looks fine from both ends scores as well as before.
	//
	// FramesRecv: sum-of-pair (our frames-recv + peer's frames-recv =
	// total frames the pair has exchanged) is the right denominator
	// for normalising reorder rate — using only local FramesRecv
	// under-weights peer-reported reorders against our own count.
	//
	// PeerStatsReporter is an optional capability: TCP / QUIC / fake
	// sessions don't ship STATS frames and don't implement it, so the
	// type assertion fails silently and the scorer behaves exactly as
	// before for those transports.
	if rep, ok := p.Session.(PeerStatsReporter); ok {
		peer := rep.LastPeerStats()
		if peerLossPpm := uint32(peer.LossPercent * 10000); peerLossPpm > uint32(metrics.LossPercent*10000) {
			metrics.LossPercent = peer.LossPercent
		}
		if peer.DroppedFrames > metrics.DroppedFrames {
			metrics.DroppedFrames = peer.DroppedFrames
		}
		if peer.FramesRecv > 0 {
			// Fold the peer's total reorder roll-up (synthesised under
			// StreamObserve[0] by DecodeStats) into our reorder sum.
			for _, sd := range peer.StreamObserve {
				reorders += sd.ReorderCount
			}
		}
		// Throughput (BytesRecv): sum-of-pair so a path used only in
		// one direction still surfaces as carrying traffic. The
		// Tracker.UpdateThroughput call below feeds the EMA used for
		// BytesPerSec — using local-only would zero-out a path that
		// the peer is sending to us heavily while we're idle.
		metrics.BytesRecv += peer.BytesRecv
	}

	// Translate session metrics into Inputs for the quality package.
	// Most fields read directly; baseline RTT and throughput come from
	// the Tracker's longer-window EMAs.
	//
	// L4 #3 throttle: only push fresh samples into the Tracker EMAs
	// once per trackerUpdateMinInterval. PickByQuality fires on every
	// dispatch decision; without throttling, hundreds of calls per
	// second collapsed the baseline RTT EMA to instantaneous SRTT.
	now := time.Now()
	if now.Sub(meta.LastTrackerUpdate) >= trackerUpdateMinInterval {
		cfg.Tracker.UpdateRTT(meta.TrackerKey, health.SRTT())
		cfg.Tracker.UpdateThroughput(meta.TrackerKey, metrics.BytesRecv)
		meta.LastTrackerUpdate = now
	}

	in := quality.Inputs{
		Class:               meta.Class,
		SRTT:                health.SRTT(),
		RTTVar:              health.RTTVar(),
		BaselineRTT:         cfg.Tracker.BaselineRTT(meta.TrackerKey),
		LossPermille:        int(metrics.LossPercent * 10),
		FramesRecv:          int64(metrics.FramesRecv),
		Reorders:            reorders,
		BytesPerSec:         cfg.Tracker.BytesPerSec(meta.TrackerKey),
		ConsecutiveFailures: cfg.Tracker.ConsecutiveFailures(meta.TrackerKey),
		Reliability:         cfg.Tracker.Reliability(meta.TrackerKey),
		Stability:           cfg.Tracker.Stability(meta.TrackerKey),
		Age:                 sessionAge(p),
	}

	score := quality.Compute(in, w)
	cfg.Tracker.RecordScore(meta.TrackerKey, score.Aggregate)

	// Cache for diagnostic surface (Manager.PathScores).
	m.qstate.mu.Lock()
	if pm := m.qstate.meta[p]; pm != nil {
		pm.LastScore = score
		pm.LastScoreAt = time.Now()
	}
	m.qstate.mu.Unlock()

	return score
}

// PathScores returns a snapshot of the most recent quality score per
// path, keyed by transport protocol. Used by diagnostics endpoints and
// observability that needs to surface why dispatch picked the path it
// did.
func (m *Manager) PathScores() map[aether.Protocol]quality.Score {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.qstate == nil {
		return nil
	}
	out := make(map[aether.Protocol]quality.Score)
	m.qstate.mu.Lock()
	for _, p := range m.paths {
		if pm, ok := m.qstate.meta[p]; ok {
			out[p.Protocol] = pm.LastScore
		}
	}
	m.qstate.mu.Unlock()
	return out
}

// runEnsure is the EnsureK reconnect loop. Maintains len(alive paths) >=
// target by calling DialFunc when below target. Backs off
// exponentially on consecutive dial failures so a peer with permanent
// reachability problems doesn't drain the dialer's connection budget.
func (q *qualityState) runEnsure(ctx context.Context, m *Manager) {
	consecutiveFails := 0
	const baseBackoff = 5 * time.Second
	const maxBackoff = 60 * time.Second

	timer := time.NewTimer(baseBackoff)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-q.stop:
			return
		case <-timer.C:
		}

		q.mu.Lock()
		dialFn := q.cfg.DialFunc
		target := q.target
		stopped := q.stopped
		q.mu.Unlock()
		if stopped {
			return
		}

		if dialFn == nil || target <= 0 {
			timer.Reset(baseBackoff)
			continue
		}

		alive := m.aliveCount()
		if alive >= target {
			// Above target — relaxed cadence.
			timer.Reset(30 * time.Second)
			continue
		}

		// Below target — dial once and reset cadence based on outcome.
		dialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		session, proto, remoteRegion, err := dialFn(dialCtx)
		cancel()
		if err != nil {
			consecutiveFails++
			// Cap the shift before applying. baseBackoff (5s) << 5 already
			// equals 160s — well past maxBackoff (60s). Without this cap,
			// consecutiveFails ~33+ overflows the int64 left-shift and
			// flips backoff negative (observed in fleet logs as
			// `backoff=-1759548h`). The `> maxBackoff` clamp below
			// doesn't catch negative values, so timer.Reset(<0) fires
			// immediately and a permanently-unreachable peer drives a
			// dial-storm at full speed.
			shift := consecutiveFails - 1
			if shift > 5 {
				shift = 5
			}
			backoff := baseBackoff << uint(shift)
			if backoff > maxBackoff || backoff <= 0 {
				backoff = maxBackoff
			}
			log.Printf("[multipath] EnsureK dial failed (peer=%s, attempt=%d, backoff=%v): %v",
				truncPeer(q.cfg.PeerID), consecutiveFails, backoff, err)
			timer.Reset(backoff)
			continue
		}
		if session == nil {
			// No candidate right now — relaxed cadence, no failure
			// counter increment (this isn't a dial failure).
			timer.Reset(15 * time.Second)
			continue
		}
		consecutiveFails = 0
		m.AddPathQA(session, proto, remoteRegion)
		log.Printf("[multipath] EnsureK dialed peer=%s proto=%s remoteRegion=%s alive=%d/%d",
			truncPeer(q.cfg.PeerID), proto, remoteRegion, m.aliveCount(), target)
		// Below or at target — quick re-check.
		timer.Reset(2 * time.Second)
	}
}

// aliveCount returns the number of paths whose session reports IsClosed
// = false. Cheap; OK to call from the dial loop.
func (m *Manager) aliveCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, p := range m.paths {
		if p.Session != nil && !p.Session.IsClosed() {
			n++
		}
	}
	return n
}

// sessionAge returns time since the path was first added to this
// manager (Path.CreatedAt). Stable across the path's lifetime — does
// NOT reset on probe success — so the quality scorer's AgeGrace gate
// ramps from 0→1 monotonically over the path's lifetime instead of
// re-entering the grace window every probe ACK.
//
// Caveat: reading LastSuccess as a creation-time proxy is wrong because
// OnProbeSuccess rewrites LastSuccess every probe, and on a fast probe
// cadence the path stays permanently inside AgeGrace=0 (multiplicatively
// zeroing the Aggregate score). Use CreatedAt for sessionAge, not
// LastSuccess.
//
// LastSuccess fallback covers paths constructed before the CreatedAt
// field existed (zero-value CreatedAt) so a rolling upgrade doesn't
// briefly score every legacy path at AgeGrace=0.
func sessionAge(p *Path) time.Duration {
	if !p.CreatedAt.IsZero() {
		return time.Since(p.CreatedAt)
	}
	if p.LastSuccess.IsZero() {
		return 0
	}
	return time.Since(p.LastSuccess)
}

// truncPeer truncates a peer ID for log readability without losing the
// distinguishing prefix.
func truncPeer(id string) string {
	if len(id) > 14 {
		return id[:14] + "..."
	}
	return id
}

// String returns a human-readable description of the manager's current
// state — used by diagnostics endpoints and SESSION-CLOSE post-mortem
// logs.
func (m *Manager) String() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.qstate == nil {
		return fmt.Sprintf("multipath{paths=%d, primary=%d}", len(m.paths), m.primary)
	}
	q := m.qstate
	q.mu.Lock()
	target := q.target
	q.mu.Unlock()
	return fmt.Sprintf("multipath{paths=%d, target=%d, alive=%d}",
		len(m.paths), target, m.aliveCountLocked())
}

// aliveCountLocked is aliveCount without acquiring m.mu — caller must
// already hold it.
func (m *Manager) aliveCountLocked() int {
	n := 0
	for _, p := range m.paths {
		if p.Session != nil && !p.Session.IsClosed() {
			n++
		}
	}
	return n
}
