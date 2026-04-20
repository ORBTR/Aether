/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package aether

import (
	"fmt"
	"sort"
	"sync"
)

// Registry manages available transport protocols.
type Registry struct {
	mu         sync.RWMutex
	transports map[Protocol]Transport
}

var (
	// DefaultRegistry is the global transport registry.
	DefaultRegistry = NewRegistry()
)

// NewRegistry creates a new transport registry.
func NewRegistry() *Registry {
	return &Registry{
		transports: make(map[Protocol]Transport),
	}
}

// Register adds a transport implementation for a protocol.
func (r *Registry) Register(protocol Protocol, t Transport) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.transports[protocol] = t
}

// Get returns the transport for a protocol.
func (r *Registry) Get(protocol Protocol) (Transport, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.transports[protocol]
	return t, ok
}

// List returns all registered protocols sorted by grade (best first).
// Lower Protocol value = higher grade (NoiseUDP < QUIC < WS < TLS < gRPC).
func (r *Registry) List() []Protocol {
	r.mu.RLock()
	defer r.mu.RUnlock()
	protocols := make([]Protocol, 0, len(r.transports))
	for p := range r.transports {
		protocols = append(protocols, p)
	}
	sort.Slice(protocols, func(i, j int) bool {
		return protocols[i] < protocols[j]
	})
	return protocols
}

// RegisterTransport registers a transport with the default registry.
func RegisterTransport(protocol Protocol, t Transport) {
	DefaultRegistry.Register(protocol, t)
}

// GetTransport returns a transport from the default registry.
func GetTransport(protocol Protocol) (Transport, error) {
	t, ok := DefaultRegistry.Get(protocol)
	if !ok {
		return nil, fmt.Errorf("transport not found for protocol: %s", protocol)
	}
	return t, nil
}
