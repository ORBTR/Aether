/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package aether

import (
	"sync"
	"time"

)

// PathScore tracks the quality of a network path to a peer.
// Used by NAT traversal (RENDEZVOUS) and connection selection.
type PathScore struct {
	PeerID              PeerID
	Protocol            Protocol
	Address             string
	RTT                 time.Duration
	LossPercent         float64
	SuccessRate         float64   // successful connections / total attempts
	Attempts            int
	Successes           int
	ConsecutiveFailures int       // current consecutive failure run (reset on success)
	LastSuccess         time.Time
	LastFailure         time.Time
	DeadUntil           time.Time // cooldown — don't attempt until this time
}

// IsAlive returns true if the path is not in dead cooldown.
func (p *PathScore) IsAlive() bool {
	return time.Now().After(p.DeadUntil)
}

// IsDead returns true if the path is in dead cooldown.
func (p *PathScore) IsDead() bool {
	return !p.IsAlive()
}

const (
	// PathDeadCooldown is how long to wait before retrying a dead path.
	PathDeadCooldown = 30 * time.Minute

	// PathConsecutiveFailuresBeforeDead is the number of consecutive failures
	// before marking a path as dead.
	PathConsecutiveFailuresBeforeDead = 3
)

// PathScorer tracks path quality for all peers and protocols.
type PathScorer struct {
	mu    sync.RWMutex
	paths map[pathKey]*PathScore
}

type pathKey struct {
	peerID   PeerID
	protocol Protocol
	address  string
}

// NewPathScorer creates a path quality tracker.
func NewPathScorer() *PathScorer {
	return &PathScorer{
		paths: make(map[pathKey]*PathScore),
	}
}

// RecordSuccess records a successful connection/exchange on a path.
func (s *PathScorer) RecordSuccess(peerID PeerID, proto Protocol, addr string, rtt time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	k := pathKey{peerID, proto, addr}
	p, ok := s.paths[k]
	if !ok {
		p = &PathScore{PeerID: peerID, Protocol: proto, Address: addr}
		s.paths[k] = p
	}
	p.Attempts++
	p.Successes++
	p.ConsecutiveFailures = 0 // reset consecutive failure counter
	p.RTT = rtt
	p.SuccessRate = float64(p.Successes) / float64(p.Attempts)
	p.LastSuccess = time.Now()
	p.DeadUntil = time.Time{} // clear dead state on success
}

// RecordFailure records a failed connection/exchange on a path.
func (s *PathScorer) RecordFailure(peerID PeerID, proto Protocol, addr string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	k := pathKey{peerID, proto, addr}
	p, ok := s.paths[k]
	if !ok {
		p = &PathScore{PeerID: peerID, Protocol: proto, Address: addr}
		s.paths[k] = p
	}
	p.Attempts++
	p.ConsecutiveFailures++
	p.SuccessRate = float64(p.Successes) / float64(p.Attempts)
	p.LastFailure = time.Now()

	// Check for consecutive failures → mark dead (regardless of overall success rate)
	if p.ConsecutiveFailures >= PathConsecutiveFailuresBeforeDead {
		p.DeadUntil = time.Now().Add(PathDeadCooldown)
	}
}

// Score returns the PathScore for a specific peer/protocol/address triple.
// Returns nil if no history exists for this path.
func (s *PathScorer) Score(peerID PeerID, proto Protocol, addr string) *PathScore {
	s.mu.RLock()
	defer s.mu.RUnlock()

	k := pathKey{peerID, proto, addr}
	return s.paths[k]
}

// BestPath returns the best scored path for a peer (highest success rate, lowest RTT).
// Returns nil if no alive paths exist.
func (s *PathScorer) BestPath(peerID PeerID) *PathScore {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var best *PathScore
	for _, p := range s.paths {
		if p.PeerID != peerID || p.IsDead() {
			continue
		}
		if best == nil || p.SuccessRate > best.SuccessRate ||
			(p.SuccessRate == best.SuccessRate && p.RTT < best.RTT) {
			best = p
		}
	}
	return best
}

// AllPaths returns all scored paths for a peer (including dead).
func (s *PathScorer) AllPaths(peerID PeerID) []*PathScore {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var paths []*PathScore
	for _, p := range s.paths {
		if p.PeerID == peerID {
			paths = append(paths, p)
		}
	}
	return paths
}

// Prune removes paths that haven't been used in the given duration.
func (s *PathScorer) Prune(maxAge time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	for k, p := range s.paths {
		lastUsed := p.LastSuccess
		if p.LastFailure.After(lastUsed) {
			lastUsed = p.LastFailure
		}
		if lastUsed.Before(cutoff) {
			delete(s.paths, k)
		}
	}
}
