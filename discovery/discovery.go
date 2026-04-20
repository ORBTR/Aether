/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package discovery

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
)

// PeerAddress represents a discovered peer endpoint.
type PeerAddress struct {
	Host   string // hostname or IP
	Port   uint16 // port number
	NodeID string // optional — may be empty for DNS SRV / static seeds
	Source string // "dns", "mdns", "seed", "persisted"
}

// String returns a host:port representation.
func (p PeerAddress) String() string {
	return fmt.Sprintf("%s:%d", p.Host, p.Port)
}

// Discoverer is the interface for peer discovery layers.
// Each layer provides a different mechanism for finding mesh peers.
type Discoverer interface {
	// Discover returns a list of peer addresses found by this discovery layer.
	Discover(ctx context.Context) ([]PeerAddress, error)
}

// DiscoveredPeer is the unified type returned by the discovery chain.
// It aggregates information from one or more PeerAddress results into
// a richer peer record suitable for the PeerConnectionManager.
type DiscoveredPeer struct {
	NodeID    string
	Addresses []string
	Region    string
	Source    string // "persisted", "mdns", "dns-srv", "static", "pex"
}

// PeerStore is the interface for persisted peer list.
type PeerStore interface {
	LoadDiscovered() ([]DiscoveredPeer, error)
	SaveDiscovered(peers []DiscoveredPeer) error
}

// MultiDiscoverer chains multiple discoverers in priority order.
// Results are merged with deduplication: persisted -> mDNS -> DNS SRV -> seeds.
type MultiDiscoverer struct {
	discoverers []namedDiscoverer
}

// namedDiscoverer pairs a Discoverer with a human-readable label for logging.
type namedDiscoverer struct {
	name       string
	discoverer Discoverer
}

// NewMultiDiscoverer creates a chained discoverer from the given layers.
// Layers are tried in the order provided; results are merged with deduplication.
func NewMultiDiscoverer(layers ...DiscovererOption) *MultiDiscoverer {
	md := &MultiDiscoverer{}
	for _, opt := range layers {
		opt(md)
	}
	return md
}

// DiscovererOption configures a layer in the MultiDiscoverer.
type DiscovererOption func(*MultiDiscoverer)

// WithLayer adds a named discovery layer.
func WithLayer(name string, d Discoverer) DiscovererOption {
	return func(md *MultiDiscoverer) {
		md.discoverers = append(md.discoverers, namedDiscoverer{name: name, discoverer: d})
	}
}

// Discover runs through all discovery layers in order and returns merged,
// deduplicated results. Each layer's errors are logged but do not prevent
// subsequent layers from running.
func (md *MultiDiscoverer) Discover(ctx context.Context) ([]PeerAddress, error) {
	seen := make(map[string]bool) // "host:port" -> already included
	var results []PeerAddress

	for _, nd := range md.discoverers {
		peers, err := nd.discoverer.Discover(ctx)
		if err != nil {
			log.Printf("[DISCOVERY] %s layer failed: %v", nd.name, err)
			continue
		}

		added := 0
		for _, p := range peers {
			key := p.String()
			if p.NodeID != "" {
				key = p.NodeID // prefer NodeID dedup when available
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			results = append(results, p)
			added++
		}

		if added > 0 {
			dbgDiscovery.Printf("%s: discovered %d new peers", nd.name, added)
		}
	}

	dbgDiscovery.Printf("Total discovered: %d peers from %d layers",
		len(results), len(md.discoverers))
	return results, nil
}

// SeedDiscoverer wraps a static list of bootstrap hosts as a Discoverer.
type SeedDiscoverer struct {
	Seeds []string // host:port strings
}

// Discover returns the static seed list as PeerAddress entries.
func (s *SeedDiscoverer) Discover(_ context.Context) ([]PeerAddress, error) {
	var peers []PeerAddress
	for _, seed := range s.Seeds {
		host, port := splitHostPort(seed)
		peers = append(peers, PeerAddress{
			Host:   host,
			Port:   port,
			Source: "seed",
		})
	}
	return peers, nil
}

// splitHostPort extracts host and port from "host:port" string.
// Uses net.SplitHostPort which correctly handles IPv6 addresses like [::1]:8443.
// If no port is present or parsing fails, defaults to 8443.
func splitHostPort(addr string) (string, uint16) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		// No port or unparseable — return as-is with default port
		return addr, 8443
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return host, 8443
	}
	return host, uint16(port)
}
