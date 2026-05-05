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
}

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
		m.mu.Unlock()
		go m.qstate.runEnsure(ctx, m)
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
	m.qstate.mu.Unlock()
	m.mu.Unlock()
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

// AddPathQA registers a path with quality-aware metadata. Equivalent to
// AddPath but also records the remote region so the path can be
// classified for score normalization. Use this from callers that have
// migrated to the quality-driven control plane; legacy callers can
// continue to use AddPath.
func (m *Manager) AddPathQA(session aether.Session, proto aether.Protocol, remoteRegion string) {
	m.AddPath(session, proto, 0) // legacy quality int unused on this path

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.qstate == nil {
		// Quality state not initialised — caller hasn't called
		// EnsureK yet. Allocate so subsequent AddPathQA calls find
		// the same map; EnsureK will populate cfg later.
		m.qstate = &qualityState{
			meta: make(map[*Path]*PathMeta),
			stop: make(chan struct{}),
		}
	}

	// Find the path we just added (it's the last one).
	if len(m.paths) == 0 {
		return
	}
	path := m.paths[len(m.paths)-1]

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

	// Translate session metrics into Inputs for the quality package.
	// Most fields read directly; baseline RTT and throughput come from
	// the Tracker's longer-window EMAs.
	cfg.Tracker.UpdateRTT(meta.TrackerKey, health.SRTT())
	cfg.Tracker.UpdateThroughput(meta.TrackerKey, metrics.BytesRecv)

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

// PathScores returns a snapshot of the most recent score per path. Used
// by diagnostics endpoints and for the Stage 1 logging that compares
// current decisions against quality-driven decisions.
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
			backoff := baseBackoff << uint(consecutiveFails-1)
			if backoff > maxBackoff {
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

// sessionAge returns time since the path's session was first observed
// by this manager (LastSuccess at AddPath time stands in for creation
// because aether.Session doesn't expose CreatedAt directly).
func sessionAge(p *Path) time.Duration {
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
