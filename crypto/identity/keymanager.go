/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 *
 * NetworkKeyManager manages the set of PSK (network) keys used in Noise
 * handshake prologues. Extracted from NoiseTransport for reusability and
 * clean key rotation without lock contention on the transport struct.
 */
package crypto

import (
	"errors"
	"hash/crc32"
	"sync"
)

// NetworkKeyManager manages network keys (PSKs) for VL1 transport handshakes.
// The first key is the active key (used for outbound). Additional keys are
// accepted for inbound (supporting dual-key overlap during rotation).
// Thread-safe.
type NetworkKeyManager struct {
	mu     sync.RWMutex
	keys   [][]byte          // first = active, rest = old/rotation overlap
	keyMap map[uint32][]byte // CRC32 fingerprint → key bytes (for fast lookup)
}

// NewNetworkKeyManager creates a key manager from string keys.
// At least one key is required.
func NewNetworkKeyManager(keys []string) (*NetworkKeyManager, error) {
	if len(keys) == 0 {
		return nil, errors.New("crypto: at least one network key is required")
	}
	km := &NetworkKeyManager{
		keyMap: make(map[uint32][]byte, len(keys)),
	}
	for _, keyStr := range keys {
		key := []byte(keyStr)
		km.keys = append(km.keys, key)
		km.keyMap[CRC32Hash(key)] = key
	}
	return km, nil
}

// ActiveKey returns the current active key (first in the list).
func (km *NetworkKeyManager) ActiveKey() []byte {
	km.mu.RLock()
	defer km.mu.RUnlock()
	if len(km.keys) == 0 {
		return nil
	}
	return km.keys[0]
}

// AllKeys returns a copy of all keys.
func (km *NetworkKeyManager) AllKeys() [][]byte {
	km.mu.RLock()
	defer km.mu.RUnlock()
	out := make([][]byte, len(km.keys))
	for i, k := range km.keys {
		out[i] = append([]byte(nil), k...)
	}
	return out
}

// LookupByFingerprint returns the key matching the CRC32 fingerprint.
func (km *NetworkKeyManager) LookupByFingerprint(fp uint32) ([]byte, bool) {
	km.mu.RLock()
	defer km.mu.RUnlock()
	k, ok := km.keyMap[fp]
	return k, ok
}

// Rotate replaces all keys atomically. The first key becomes the new active key.
// Old keys that appear in the new set are preserved for overlap.
func (km *NetworkKeyManager) Rotate(newKeys [][]byte) error {
	if len(newKeys) == 0 {
		return errors.New("crypto: at least one key is required")
	}
	newMap := make(map[uint32][]byte, len(newKeys))
	copied := make([][]byte, len(newKeys))
	for i, k := range newKeys {
		copied[i] = append([]byte(nil), k...)
		newMap[CRC32Hash(copied[i])] = copied[i]
	}
	km.mu.Lock()
	km.keys = copied
	km.keyMap = newMap
	km.mu.Unlock()
	return nil
}

// CRC32Hash computes the CRC32-IEEE fingerprint of a key.
// Used for fast key identification in handshake packets.
func CRC32Hash(key []byte) uint32 {
	return crc32.ChecksumIEEE(key)
}
