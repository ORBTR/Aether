/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */

// Package abuse implements per-peer behavioural scoring with a circuit
// breaker for cross-subsystem misbehaviour. See _SECURITY.md §3.6 and
// §3.9. The goal is a single dial operators can read ("this peer is
// misbehaving, drop it") instead of relying on each subsystem to enforce
// its own per-feature cap.
//
// Scores accrue on observed bad behaviour and decay exponentially while
// the peer is quiet. When a peer exceeds its threshold, callers should
// `GOAWAY(GoAwayError)` the session and refuse new sessions from that peer
// for the configured cool-off window.
package abuse

import (
	"math"
	"sync"
	"time"
)

// Reason identifies the subsystem that contributed to a score increment.
type Reason int

const (
	ReasonDecryptFail     Reason = iota // noise/session.go decrypt error
	ReasonMalformedFrame                // frame decode / validate failure
	ReasonACKValidation                 // S1 — Composite ACK rejected
	ReasonStreamRefused                 // S5 — peer hit MaxConcurrentStreams
	ReasonWHOISFlood                    // application: WHOIS spam
	ReasonReplayDetected                // anti-replay window rejection
	ReasonProtocolViolation             // any unexpected sequence/state
	ReasonFlowControlAbuse              // peer hoarding credit without delivering (sustained grantsEmitted vs consumed imbalance)
)

func (r Reason) String() string {
	switch r {
	case ReasonDecryptFail:
		return "decrypt-fail"
	case ReasonMalformedFrame:
		return "malformed-frame"
	case ReasonACKValidation:
		return "ack-validation"
	case ReasonStreamRefused:
		return "stream-refused"
	case ReasonWHOISFlood:
		return "whois-flood"
	case ReasonReplayDetected:
		return "replay-detected"
	case ReasonProtocolViolation:
		return "protocol-violation"
	case ReasonFlowControlAbuse:
		return "flow-control-abuse"
	default:
		return "unknown"
	}
}

// DefaultWeight returns the score increment for a reason. Heavier weights
// for behaviours that imply attack rather than misconfiguration.
func DefaultWeight(r Reason) float64 {
	switch r {
	case ReasonDecryptFail:
		return 5
	case ReasonMalformedFrame:
		return 5
	case ReasonACKValidation:
		return 25 // crafted ACK is a CPU-exhaustion attempt
	case ReasonStreamRefused:
		return 2
	case ReasonWHOISFlood:
		return 3
	case ReasonReplayDetected:
		return 8
	case ReasonProtocolViolation:
		return 10
	case ReasonFlowControlAbuse:
		// Sustained-imbalance signal — not a single-event attack.
		// Weight matches ReplayDetected: notable but not by itself
		// near the threshold; 4 sustained windows in a row would.
		return 8
	default:
		return 1
	}
}

const (
	// DefaultThreshold is the score at which a peer is marked abusive.
	DefaultThreshold = 100

	// DefaultHalfLife is the score's exponential half-life: a peer that
	// stops misbehaving sees its score halve every HalfLife. Five minutes
	// matches typical NAT rebind timing.
	DefaultHalfLife = 5 * time.Minute

	// DefaultBlacklistTTL is how long an abusive peer stays blacklisted.
	DefaultBlacklistTTL = 5 * time.Minute
)

// Config tunes the scoring behaviour. Use DefaultConfig() unless you have
// strong reasons to deviate.
type Config struct {
	Threshold     float64
	HalfLife      time.Duration
	BlacklistTTL  time.Duration
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		Threshold:    DefaultThreshold,
		HalfLife:     DefaultHalfLife,
		BlacklistTTL: DefaultBlacklistTTL,
	}
}

// PeerScore tracks one peer's running misbehaviour score.
type PeerScore struct {
	score        float64
	lastUpdate   time.Time
	lastReason   Reason
	blacklisted  bool
	blacklistEnd time.Time
	hits         uint64 // total events recorded against this peer
}

// Score is a thread-safe registry of per-peer scores.
// Generic over PeerKey so callers can use NodeID, PeerID, IP, etc.
type Score[K comparable] struct {
	mu     sync.Mutex
	cfg    Config
	peers  map[K]*PeerScore
}

// New creates a Score registry with the given config.
func New[K comparable](cfg Config) *Score[K] {
	if cfg.Threshold <= 0 {
		cfg.Threshold = DefaultThreshold
	}
	if cfg.HalfLife <= 0 {
		cfg.HalfLife = DefaultHalfLife
	}
	if cfg.BlacklistTTL <= 0 {
		cfg.BlacklistTTL = DefaultBlacklistTTL
	}
	return &Score[K]{cfg: cfg, peers: make(map[K]*PeerScore)}
}

// Record adds a weighted score increment for the given reason. Returns
// the peer's current score and whether the peer just crossed the abuse
// threshold (callers act on the threshold-crossing edge: GOAWAY + add to
// blacklist).
func (s *Score[K]) Record(peer K, r Reason) (current float64, justExceeded bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	p, ok := s.peers[peer]
	if !ok {
		p = &PeerScore{lastUpdate: now}
		s.peers[peer] = p
	}
	s.decayLocked(p, now)

	p.score += DefaultWeight(r)
	p.lastReason = r
	p.lastUpdate = now
	p.hits++

	// AE-P-09: re-arm the breaker on current state, not just the rising
	// edge. The old guard blacklisted only on a below->over transition
	// (!wasOver && nowOver) using a pre-decay wasOver snapshot. A peer
	// whose score stayed >= threshold across a cool-off kept wasOver==true
	// forever, so once IsBlacklisted auto-cleared the flag at TTL expiry
	// (without resetting the score) the breaker never re-fired and the
	// accept gate re-admitted a still-abusive peer permanently. Clear an
	// expired cool-off here first (so re-arming does not depend on
	// IsBlacklisted having been polled), then re-blacklist whenever the
	// post-decay score is over threshold and the peer is not already
	// serving a cool-off. This fires at most one GoAway per BlacklistTTL
	// for a sustained abuser and never resets the accumulated score, so no
	// misbehaviour evidence is lost (capability preserved).
	if p.blacklisted && now.After(p.blacklistEnd) {
		p.blacklisted = false
	}
	nowOver := p.score >= s.cfg.Threshold
	if nowOver && !p.blacklisted {
		p.blacklisted = true
		p.blacklistEnd = now.Add(s.cfg.BlacklistTTL)
		justExceeded = true
	}
	return p.score, justExceeded
}

// Current returns the peer's current score after applying decay.
func (s *Score[K]) Current(peer K) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.peers[peer]
	if !ok {
		return 0
	}
	s.decayLocked(p, time.Now())
	return p.score
}

// IsBlacklisted reports whether the peer is currently in the cool-off
// window. Auto-clears once the TTL expires.
//
// AE-M-04 caveat: this predicate is what the responder-side accept gate
// (adapter.AcceptSessionOverConn) consults to refuse a peer for its
// BlacklistTTL cool-off, rather than letting the peer reset its score to
// 0 by reconnecting. That protection only holds when callers share ONE
// node-scoped registry across sessions; a fresh per-session registry
// carries no prior blacklist. Auto-clear here only ungates the accept
// path once the TTL lapses; it deliberately does NOT reset the score
// (a still-misbehaving peer keeps its accumulated evidence). AE-P-09:
// re-arming no longer depends on a HalfLife≈BlacklistTTL decay
// coincidence — Record re-arms the breaker on the peer's current
// post-decay state regardless of peak, so a peer that stays >= threshold
// across the cool-off is re-blacklisted on its next event instead of
// staying latched open.
func (s *Score[K]) IsBlacklisted(peer K) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.peers[peer]
	if !ok {
		return false
	}
	if p.blacklisted && time.Now().After(p.blacklistEnd) {
		p.blacklisted = false
		// Score keeps decaying; we don't reset to 0 because the peer
		// may still be misbehaving — they just earned a fresh chance.
	}
	return p.blacklisted
}

// Forgive clears the blacklist flag and resets the score to 0. Operator
// use only — should not be called from automatic policy.
func (s *Score[K]) Forgive(peer K) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.peers[peer]; ok {
		p.score = 0
		p.blacklisted = false
	}
}

// Prune drops entries with negligible score that haven't been updated
// recently. Call periodically (e.g. every minute) to bound memory.
func (s *Score[K]) Prune(maxIdle time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, p := range s.peers {
		// AER-052: capture the idle duration BEFORE decayLocked resets
		// p.lastUpdate to now — otherwise now.Sub(p.lastUpdate) was always 0
		// and nothing was ever pruned, so a shared registry grew without bound.
		idle := now.Sub(p.lastUpdate)
		s.decayLocked(p, now)
		if !p.blacklisted && p.score < 1 && idle > maxIdle {
			delete(s.peers, k)
		}
	}
}

// decayLocked applies exponential decay since the last update.
// Caller must hold s.mu.
func (s *Score[K]) decayLocked(p *PeerScore, now time.Time) {
	elapsed := now.Sub(p.lastUpdate)
	if elapsed <= 0 || s.cfg.HalfLife <= 0 {
		return
	}
	// score *= 0.5 ^ (elapsed / halfLife)
	// Equivalent to multiplying by exp2(-elapsed/halfLife). Cheap-ish
	// approximation: convert to multiplier via float math.
	periods := float64(elapsed) / float64(s.cfg.HalfLife)
	// Clamp to avoid pow blowing up on long idle gaps.
	if periods > 30 {
		p.score = 0
	} else {
		p.score *= pow2neg(periods)
	}
	p.lastUpdate = now
}

// pow2neg returns 2^-n for n ≥ 0.
//
// AER-092: use the exact math.Exp2 rather than a linear interpolation of the
// fractional part. The convex 2^-frac was over-estimated by `1 - 0.5*frac`
// (~6% high at frac=0.5), so misbehaviour scores decayed measurably slower
// than the configured half-life.
func pow2neg(n float64) float64 {
	if n <= 0 {
		return 1
	}
	return math.Exp2(-n)
}
