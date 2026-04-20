/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package aether

import (
	"math"
	"net"
	"sort"
	"time"
)

// PathScope indicates the reachability scope for an address.
type PathScope string

const (
	PathScopePublic  PathScope = "public"
	PathScopeLAN     PathScope = "lan"
	PathScopeRFC1918 PathScope = "rfc1918"
)

// Path describes a candidate transport route towards a node.
type Path struct {
	NodeID   NodeID
	ScopeID ScopeID
	Address  *net.UDPAddr
	Scope    PathScope
	Latency  time.Duration
	Score    float64
}

// ReachInfo provides reachability information for a peer.
// Consumers populate this from their record types (e.g., application-specific reach records).
type ReachInfo struct {
	NodeID       string
	ScopeID     string
	Addresses    []ReachAddress
	Region       string
	Availability float64
	LoadFactor   float64
	Latency      time.Duration
}

// ReachAddress is a peer address with scope annotation.
type ReachAddress struct {
	Addr  string
	Scope string
}

func (a ReachAddress) String() string { return a.Addr }

// LatencyDuration returns the measured latency.
func (r ReachInfo) LatencyDuration() time.Duration { return r.Latency }

// PathScorer ranks reachability records when selecting which paths to attempt.
type PathRanker interface {
	Score(reach ReachInfo) float64
}

// PathSelector produces ranked path candidates.
type PathSelector struct {
	scorer PathRanker
}

// NewPathSelector constructs a selector with the provided scorer or a default.
func NewPathSelector(scorer PathRanker) *PathSelector {
	if scorer == nil {
		scorer = DefaultPathScorer{}
	}
	return &PathSelector{scorer: scorer}
}

// Candidates returns a ranked slice of paths for the supplied reach records.
func (s *PathSelector) Candidates(records []ReachInfo, limit int) []Path {
	if limit <= 0 {
		limit = math.MaxInt
	}
	paths := make([]Path, 0, len(records))
	for _, reach := range records {
		score := s.scorer.Score(reach)
		for _, addr := range reach.Addresses {
			udp, err := net.ResolveUDPAddr("udp", addr.String())
			if err != nil {
				continue
			}
			paths = append(paths, Path{
				NodeID:   NodeID(reach.NodeID),
				ScopeID: ScopeID(reach.ScopeID),
				Address:  udp,
				Scope:    PathScope(addr.Scope),
				Latency:  reach.LatencyDuration(),
				Score:    score,
			})
		}
	}
	sort.Slice(paths, func(i, j int) bool {
		if math.Abs(paths[i].Score-paths[j].Score) < 1e-6 {
			return paths[i].Latency < paths[j].Latency
		}
		return paths[i].Score > paths[j].Score
	})
	if len(paths) > limit {
		paths = paths[:limit]
	}
	return paths
}

// DefaultPathScorer weights latency, region, and observer signals from reach records.
type DefaultPathScorer struct {
	LocalRegion string
}

// NewDefaultPathScorer creates a new scorer with the given local region.
func NewDefaultPathScorer(region string) DefaultPathScorer {
	return DefaultPathScorer{LocalRegion: region}
}

// Score implements PathScorer.
func (s DefaultPathScorer) Score(reach ReachInfo) float64 {
	latency := reach.LatencyDuration()
	if latency <= 0 {
		latency = 50 * time.Millisecond
	}
	latencyScore := 1 / latency.Seconds()
	availability := reach.Availability
	if availability < 0 {
		availability = 0
	}

	// Region Bonus: Prefer nodes in the same region
	regionBonus := 1.0
	if s.LocalRegion != "" && reach.Region == s.LocalRegion {
		regionBonus = 1.5 // 50% score boost for same region
	}

	// LoadFactor: 0.0 (good) -> 1.0 (bad)
	// Penalize high load by reducing the score.
	loadPenalty := 1.0 - (reach.LoadFactor * 0.8) // Heavy penalty for load
	if loadPenalty < 0.1 {
		loadPenalty = 0.1
	}

	return (latencyScore*0.7 + availability*0.3) * loadPenalty * regionBonus
}
