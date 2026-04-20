/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package aether

import (
	"sync"
	"time"
)

// ConnectionMap provides a unified, thread-safe container for session lookups.
type ConnectionMap struct {
	mu       sync.RWMutex
	byNodeID map[NodeID]Connection
	byAddr   map[string]Connection            // address string → session
	byScope map[string]map[NodeID]Connection // scopeID → nodeID → session
}

// NewConnectionMap creates an empty session map.
func NewConnectionMap() *ConnectionMap {
	return &ConnectionMap{
		byNodeID: make(map[NodeID]Connection),
		byAddr:   make(map[string]Connection),
		byScope: make(map[string]map[NodeID]Connection),
	}
}

// Get returns a session by NodeID, or nil if not found.
func (m *ConnectionMap) Get(id NodeID) Connection {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.byNodeID[id]
}

// GetByAddr returns a session by address string, or nil if not found.
func (m *ConnectionMap) GetByAddr(addr string) Connection {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.byAddr[addr]
}

// Put registers a session in all indexes.
func (m *ConnectionMap) Put(id NodeID, addr string, scope string, sess Connection) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byNodeID[id] = sess
	if addr != "" {
		m.byAddr[addr] = sess
	}
	if scope != "" {
		if m.byScope[scope] == nil {
			m.byScope[scope] = make(map[NodeID]Connection)
		}
		m.byScope[scope][id] = sess
	}
}

// Remove unregisters a session from all indexes.
func (m *ConnectionMap) Remove(id NodeID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sess := m.byNodeID[id]
	delete(m.byNodeID, id)

	// Remove from byAddr (find by value)
	for addr, s := range m.byAddr {
		if s == sess {
			delete(m.byAddr, addr)
			break
		}
	}

	// Remove from byScope
	for tid, nodeMap := range m.byScope {
		delete(nodeMap, id)
		if len(nodeMap) == 0 {
			delete(m.byScope, tid)
		}
	}
}

// ForEachTenant iterates sessions for a specific scope.
func (m *ConnectionMap) ForEachTenant(scope string, fn func(NodeID, Connection)) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for id, sess := range m.byScope[scope] {
		fn(id, sess)
	}
}

// Count returns the total number of sessions.
func (m *ConnectionMap) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.byNodeID)
}

// All returns a snapshot of all sessions.
func (m *ConnectionMap) All() map[NodeID]Connection {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[NodeID]Connection, len(m.byNodeID))
	for id, sess := range m.byNodeID {
		out[id] = sess
	}
	return out
}

// RemoveByAddr unregisters a session by its address string.
// Returns the NodeID of the removed session, or "" if not found.
func (m *ConnectionMap) RemoveByAddr(addr string) NodeID {
	m.mu.Lock()
	defer m.mu.Unlock()
	sess, ok := m.byAddr[addr]
	if !ok {
		return ""
	}
	delete(m.byAddr, addr)

	// Find the NodeID for this session
	var nodeID NodeID
	for id, s := range m.byNodeID {
		if s == sess {
			nodeID = id
			delete(m.byNodeID, id)
			break
		}
	}

	// Remove from byScope
	if nodeID != "" {
		for tid, nodeMap := range m.byScope {
			delete(nodeMap, nodeID)
			if len(nodeMap) == 0 {
				delete(m.byScope, tid)
			}
		}
	}
	return nodeID
}

// TenantCount returns the number of sessions for a specific scope.
func (m *ConnectionMap) TenantCount(scope string) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.byScope[scope])
}

// HasTenant returns true if the scope has any sessions registered.
func (m *ConnectionMap) HasTenant(scope string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.byScope[scope]
	return ok
}

// TenantCountAll returns the total number of tenants with sessions.
func (m *ConnectionMap) TenantCountAll() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.byScope)
}

// Prune removes sessions that are idle beyond maxAge.
// Sessions must implement HealthReporter to be pruned; others are skipped.
// Returns count of pruned sessions.
func (m *ConnectionMap) Prune(maxAge time.Duration) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	var pruned int
	for id, sess := range m.byNodeID {
		if hr, ok := sess.(HealthReporter); ok {
			if !hr.IsAlive(maxAge) {
				_ = sess.Close()
				delete(m.byNodeID, id)
				for addr, s := range m.byAddr {
					if s == sess {
						delete(m.byAddr, addr)
						break
					}
				}
				for tid, nodeMap := range m.byScope {
					delete(nodeMap, id)
					if len(nodeMap) == 0 {
						delete(m.byScope, tid)
					}
				}
				pruned++
			}
		}
	}
	return pruned
}
