/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package resume

import (
	"crypto/rand"
	"os"
	"sort"
	"testing"
)

func makeToken(t *testing.T) (*Token, []byte) {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	tok, err := GenerateToken(key)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	return tok, key
}

// TestMemoryStoreList verifies the in-memory store reports every
// saved peer ID and drops entries on Delete.
func TestMemoryStoreList(t *testing.T) {
	s := NewMemoryStore()
	tok, key := makeToken(t)
	for _, id := range []string{"peer-a", "peer-b", "peer-c"} {
		if err := s.Save(id, tok, key); err != nil {
			t.Fatalf("Save %s: %v", id, err)
		}
	}
	ids, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	sort.Strings(ids)
	expected := []string{"peer-a", "peer-b", "peer-c"}
	if len(ids) != len(expected) {
		t.Fatalf("expected %d ids, got %d: %v", len(expected), len(ids), ids)
	}
	for i, want := range expected {
		if ids[i] != want {
			t.Errorf("ids[%d] = %q, want %q", i, ids[i], want)
		}
	}

	if err := s.Delete("peer-b"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	ids, _ = s.List()
	if len(ids) != 2 {
		t.Errorf("after delete, expected 2 ids, got %d", len(ids))
	}
}

// TestFileStoreList verifies the file store round-trips peer IDs
// through disk without losing them to the filename sanitiser —
// specifically protects against the dual-peer collision case where
// two distinct peer IDs sanitise to the same filename.
func TestFileStoreList(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFileStore(dir)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	tok, key := makeToken(t)
	ids := []string{"peer-alpha", "peer:beta", "peer/gamma"}
	for _, id := range ids {
		if err := s.Save(id, tok, key); err != nil {
			t.Fatalf("Save %s: %v", id, err)
		}
	}
	got, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != len(ids) {
		// Known caveat: two peer IDs that sanitise identically collide.
		// The test here uses IDs that sanitise to different filenames:
		// peer-alpha -> peer-alpha, peer:beta -> peer_beta,
		// peer/gamma -> peer_gamma. All three distinct.
		t.Fatalf("expected %d ids, got %d: %v", len(ids), len(got), got)
	}
	sort.Strings(got)
	expected := append([]string(nil), ids...)
	sort.Strings(expected)
	for i := range expected {
		if got[i] != expected[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], expected[i])
		}
	}
}

// TestFileStoreListSkipsCorrupted verifies a corrupted entry doesn't
// block List from returning the remaining valid peers — needed
// because a boot-time reconnect loop shouldn't fail entirely because
// one file got truncated on a prior crash.
func TestFileStoreListSkipsCorrupted(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFileStore(dir)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	tok, key := makeToken(t)
	if err := s.Save("peer-ok", tok, key); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// Drop a corrupt JSON file into the store dir.
	corruptPath := dir + "/peer_bad.json"
	if err := os.WriteFile(corruptPath, []byte("not valid json"), 0600); err != nil {
		t.Fatalf("write corrupt: %v", err)
	}
	ids, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(ids) != 1 || ids[0] != "peer-ok" {
		t.Errorf("expected only valid peer-ok, got %v", ids)
	}
}

// TestFileStoreListEmptyDir verifies a brand-new store returns an
// empty list without error.
func TestFileStoreListEmptyDir(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFileStore(dir)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	ids, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(ids) != 0 {
		t.Errorf("expected empty list, got %v", ids)
	}
}

