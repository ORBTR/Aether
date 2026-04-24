//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package resume

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// FileStore persists resume tokens to disk so they survive restarts.
// Each peer's token is stored as a separate JSON file in a directory.
// This is the production store — MemoryStore is for testing only.
type FileStore struct {
	mu  sync.RWMutex
	dir string
}

// fileEntry is the on-disk JSON format for a resume token. The
// PeerID is recorded alongside the ticket data so List can recover
// the canonical peer identity even when the filename has been
// sanitised (sanitizePeerID is lossy — multiple distinct peer IDs
// can collide onto the same filename).
type fileEntry struct {
	PeerID     string `json:"peer_id,omitempty"`
	TokenData  []byte `json:"token"`
	SessionKey []byte `json:"key"`
}

// NewFileStore creates a file-based token store in the given directory.
// Creates the directory if it doesn't exist.
func NewFileStore(dir string) (*FileStore, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("resume: create store dir: %w", err)
	}
	return &FileStore{dir: dir}, nil
}

func (s *FileStore) Save(peerID string, token *Token, sessionKey []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := fileEntry{
		PeerID:     peerID,
		TokenData:  token.Encode(),
		SessionKey: sessionKey,
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("resume: marshal token: %w", err)
	}

	path := filepath.Join(s.dir, sanitizePeerID(peerID)+".json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("resume: write token file: %w", err)
	}
	return nil
}

func (s *FileStore) Load(peerID string) (*Token, []byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	path := filepath.Join(s.dir, sanitizePeerID(peerID)+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("resume: read token file: %w", err)
	}

	var entry fileEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, nil, fmt.Errorf("resume: unmarshal token: %w", err)
	}

	token, err := DecodeToken(entry.TokenData)
	if err != nil {
		return nil, nil, err
	}

	return token, entry.SessionKey, nil
}

func (s *FileStore) Delete(peerID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.dir, sanitizePeerID(peerID)+".json")
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil // already deleted
	}
	return err
}

// List walks the store directory and returns the peer IDs embedded
// in each valid entry file. Files that fail to parse are skipped so
// a single corrupted entry doesn't block boot-time reconnection.
func (s *FileStore) List() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	dirents, err := os.ReadDir(s.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("resume: list store dir: %w", err)
	}
	out := make([]string, 0, len(dirents))
	for _, d := range dirents {
		if d.IsDir() || filepath.Ext(d.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.dir, d.Name()))
		if err != nil {
			continue
		}
		var entry fileEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			continue
		}
		if entry.PeerID != "" {
			out = append(out, entry.PeerID)
		}
	}
	return out, nil
}

// sanitizePeerID replaces characters unsafe for filenames.
func sanitizePeerID(peerID string) string {
	safe := make([]byte, 0, len(peerID))
	for _, c := range []byte(peerID) {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			safe = append(safe, c)
		} else {
			safe = append(safe, '_')
		}
	}
	return string(safe)
}

// Compile-time interface check
var _ Store = (*FileStore)(nil)
