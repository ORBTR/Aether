//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// TestAEL01_DuplicateStreamIDReturnsError guards AE-L-01: OpenStream must
// reject a StreamID that is already live in the session's stream table with
// the typed sentinel aether.ErrDuplicateStreamID and a nil stream, and must
// leave the pre-existing stream entry untouched.
//
// Before the fix, registerStream's tri-state return (nil on cap-hit, the
// PRE-EXISTING stream on a duplicate, or the fresh st) was tested only with
// `== nil`, so a duplicate fell through: OpenStream armed the rollback defer,
// let RegisterWithClass clobber the live scheduler slot, sent a second
// SYN+DATA, and returned a detached, never-mapped stream whose recvCh hangs
// forever. Assertion A fails pre-fix (non-nil dead stream, nil error) and
// passes after; Assertion B guards the scheduler-overwrite / rollback-delete
// collateral damage against the live stream.
func TestAEL01_DuplicateStreamIDReturnsError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	client := NewTCPSession(clientConn, "vl1_client", "vl1_server", aether.ProtoTCP, aether.DefaultSessionOptions())
	server := NewTCPSession(serverConn, "vl1_server", "vl1_client", aether.ProtoTCP, aether.DefaultSessionOptions())
	defer client.Close()
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	first, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: 100, Reliability: aether.ReliableOrdered, Priority: 128})
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	ael01Orig, _ := first.(*tcpStream)
	if ael01Orig == nil {
		t.Fatalf("first open: returned stream is not *tcpStream (%T)", first)
	}

	// Reuse the still-live StreamID 100.
	dup, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: 100, Reliability: aether.ReliableOrdered, Priority: 128})

	// Assertion A — typed error, nil stream.
	if err == nil {
		t.Fatal("duplicate OpenStream returned nil error, want ErrDuplicateStreamID")
	}
	if !errors.Is(err, aether.ErrDuplicateStreamID) {
		t.Errorf("err = %v; want errors.Is(err, ErrDuplicateStreamID)", err)
	}
	if dup != nil {
		t.Errorf("duplicate OpenStream returned non-nil stream %v, want nil", dup)
	}

	// Assertion B — pre-existing stream left intact (not overwritten/deleted).
	client.mu.Lock()
	ael01Mapped := client.streams[100]
	client.mu.Unlock()
	if ael01Mapped != ael01Orig {
		t.Errorf("s.streams[100] = %p, want original %p (duplicate open corrupted the live entry)", ael01Mapped, ael01Orig)
	}
}
