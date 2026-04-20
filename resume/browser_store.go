//go:build js && wasm

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package resume

import (
	"encoding/base64"
	"fmt"
	"syscall/js"
)

// BrowserStore persists session resume tokens in browser localStorage.
// Replaces FileStore for WASM environments where filesystem is unavailable.
type BrowserStore struct {
	prefix string // key prefix (e.g., "aether-resume-")
}

// NewBrowserStore creates a localStorage-backed token store.
func NewBrowserStore(prefix string) *BrowserStore {
	if prefix == "" {
		prefix = "aether-resume-"
	}
	return &BrowserStore{prefix: prefix}
}

// Store saves a resume token for a peer.
func (s *BrowserStore) Store(peerID string, token []byte) error {
	key := s.prefix + peerID
	value := base64.StdEncoding.EncodeToString(token)
	js.Global().Get("localStorage").Call("setItem", key, value)
	return nil
}

// Load retrieves a resume token for a peer.
func (s *BrowserStore) Load(peerID string) ([]byte, error) {
	key := s.prefix + peerID
	result := js.Global().Get("localStorage").Call("getItem", key)
	if result.IsNull() || result.IsUndefined() {
		return nil, fmt.Errorf("no resume token for %s", peerID)
	}
	return base64.StdEncoding.DecodeString(result.String())
}

// Delete removes a resume token.
func (s *BrowserStore) Delete(peerID string) {
	key := s.prefix + peerID
	js.Global().Get("localStorage").Call("removeItem", key)
}

// Clear removes all resume tokens.
func (s *BrowserStore) Clear() {
	storage := js.Global().Get("localStorage")
	length := storage.Get("length").Int()
	var keysToRemove []string
	for i := 0; i < length; i++ {
		key := storage.Call("key", i).String()
		if len(key) > len(s.prefix) && key[:len(s.prefix)] == s.prefix {
			keysToRemove = append(keysToRemove, key)
		}
	}
	for _, key := range keysToRemove {
		storage.Call("removeItem", key)
	}
}
