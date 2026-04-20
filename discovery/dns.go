//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package discovery

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// DNSSRVDiscoverer discovers mesh peers via DNS SRV records.
// Queries _mesh._tcp.<domain> for seed node addresses and ports.
// Results are cached for the configured TTL duration.
type DNSSRVDiscoverer struct {
	domain   string        // e.g., "hstles.com"
	resolver *net.Resolver // nil = use default
	cacheTTL time.Duration // how long to cache results (default: 5m)

	mu       sync.RWMutex
	cache    []PeerAddress
	cacheExp time.Time
}

// DNSSRVOption configures a DNSSRVDiscoverer.
type DNSSRVOption func(*DNSSRVDiscoverer)

// WithResolver overrides the DNS resolver (useful for testing).
func WithResolver(r *net.Resolver) DNSSRVOption {
	return func(d *DNSSRVDiscoverer) { d.resolver = r }
}

// WithCacheTTL sets the cache duration for SRV lookup results.
func WithCacheTTL(ttl time.Duration) DNSSRVOption {
	return func(d *DNSSRVDiscoverer) { d.cacheTTL = ttl }
}

// NewDNSSRVDiscoverer creates a resolver for the given domain.
// It queries _mesh._tcp.<domain> SRV records and optional TXT metadata.
func NewDNSSRVDiscoverer(domain string, opts ...DNSSRVOption) *DNSSRVDiscoverer {
	d := &DNSSRVDiscoverer{
		domain:   domain,
		cacheTTL: 5 * time.Minute,
	}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

// Discover looks up SRV records and returns discovered peers sorted by priority.
// Results are cached for the TTL duration to avoid excessive DNS queries.
func (d *DNSSRVDiscoverer) Discover(ctx context.Context) ([]PeerAddress, error) {
	// Return cached results if still valid
	d.mu.RLock()
	if d.cache != nil && time.Now().Before(d.cacheExp) {
		cached := make([]PeerAddress, len(d.cache))
		copy(cached, d.cache)
		d.mu.RUnlock()
		return cached, nil
	}
	d.mu.RUnlock()

	svcName := fmt.Sprintf("_mesh._tcp.%s", d.domain)
	resolver := d.resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	// Lookup SRV records: _mesh._tcp.<domain>
	_, addrs, err := resolver.LookupSRV(ctx, "mesh", "tcp", d.domain)
	if err != nil {
		return nil, fmt.Errorf("dns srv lookup %s: %w", svcName, err)
	}

	// Lookup TXT records for optional metadata (region hints, mesh-version, etc.)
	txtRecords, _ := resolver.LookupTXT(ctx, svcName)
	metadata := parseTXTMetadata(txtRecords)

	type srvEntry struct {
		peer     PeerAddress
		priority uint16
		weight   uint16
	}

	var entries []srvEntry
	for _, addr := range addrs {
		host := strings.TrimSuffix(addr.Target, ".")
		entries = append(entries, srvEntry{
			peer: PeerAddress{
				Host:   host,
				Port:   addr.Port,
				Source: "dns",
			},
			priority: addr.Priority,
			weight:   addr.Weight,
		})
	}

	// Sort by priority (lower = higher priority), then weight (higher = preferred)
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].priority != entries[j].priority {
			return entries[i].priority < entries[j].priority
		}
		return entries[i].weight > entries[j].weight
	})

	peers := make([]PeerAddress, len(entries))
	for i, e := range entries {
		peers[i] = e.peer
	}

	// Update cache
	d.mu.Lock()
	d.cache = peers
	d.cacheExp = time.Now().Add(d.cacheTTL)
	d.mu.Unlock()

	_ = metadata // metadata available for future use (region hints, version)
	dbgDNS.Printf("Discovered %d peers via %s", len(peers), svcName)
	return peers, nil
}

// parseTXTMetadata parses key=value pairs from TXT records.
// Expected format: "mesh-version=1" "region=syd"
func parseTXTMetadata(records []string) map[string]string {
	meta := make(map[string]string)
	for _, rec := range records {
		if idx := strings.IndexByte(rec, '='); idx > 0 {
			meta[rec[:idx]] = rec[idx+1:]
		}
	}
	return meta
}
