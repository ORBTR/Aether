/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 */
package websocket

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gobwas/ws"
)

// readWithTimeout runs WSConn.Read in a goroutine and fails the test if it
// does not return within d. AE-H-11 regression harness: an unguarded oversized
// frame would either OOM or panic 'makeslice: len out of range' rather than
// return; a prompt return proves the size guard fired before the allocation.
func readWithTimeout(t *testing.T, wc *WSConn, buf []byte, d time.Duration) (int, error) {
	t.Helper()
	type res struct {
		n   int
		err error
	}
	ch := make(chan res, 1)
	go func() {
		n, err := wc.Read(buf)
		ch <- res{n, err}
	}()
	select {
	case r := <-ch:
		return r.n, r.err
	case <-time.After(d):
		t.Fatal("WSConn.Read did not return promptly — possible hang/OOM on oversized frame")
		return 0, nil
	}
}

// TestWSConnReadRejectsOversizedFrame is the AE-H-11 regression test: a peer
// that advertises a frame far larger than the mesh frame ceiling
// (hijackMaxFrameSize, 16 MB) must be rejected with a "frame too large" error
// instead of allocating make([]byte, header.Length). It also asserts that
// legitimately-sized frames still round-trip (capability preserved) and that a
// frame of exactly the cap is NOT rejected by the `>` guard.
func TestWSConnReadRejectsOversizedFrame(t *testing.T) {
	// (a) Oversized frame: header advertises 1<<40 bytes, no payload sent.
	// The size guard must reject it before any allocation.
	t.Run("oversized_rejected", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()
		wc := NewWSConn(serverConn, true, "peer", 0)

		go func() {
			_ = ws.WriteHeader(clientConn, ws.Header{
				Fin:    true,
				OpCode: ws.OpBinary,
				Length: 1 << 40, // ~1 TB — must be rejected, never allocated
				Masked: true,
				Mask:   ws.NewMask(),
			})
		}()

		buf := make([]byte, 4096)
		n, err := readWithTimeout(t, wc, buf, 5*time.Second)
		if n != 0 {
			t.Fatalf("expected n==0 on rejected frame, got %d", n)
		}
		if err == nil || !strings.Contains(err.Error(), "frame too large") {
			t.Fatalf("expected a 'frame too large' error, got %v", err)
		}
	})

	// (b) Capability preserved: a valid small masked binary frame must still
	// be delivered intact — the cap must not break normal framing.
	t.Run("valid_small_frame_delivered", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()
		wc := NewWSConn(serverConn, true, "peer", 0)

		payload := []byte("hello")
		mask := ws.NewMask()
		go func() {
			_ = ws.WriteHeader(clientConn, ws.Header{
				Fin:    true,
				OpCode: ws.OpBinary,
				Length: int64(len(payload)),
				Masked: true,
				Mask:   mask,
			})
			masked := make([]byte, len(payload))
			copy(masked, payload)
			ws.Cipher(masked, mask, 0)
			_, _ = clientConn.Write(masked)
		}()

		buf := make([]byte, 4096)
		n, err := readWithTimeout(t, wc, buf, 5*time.Second)
		if err != nil {
			t.Fatalf("unexpected error on valid frame: %v", err)
		}
		if got := string(buf[:n]); got != "hello" {
			t.Fatalf("expected payload %q, got %q", "hello", got)
		}
	})

	// (c) Boundary: a frame of exactly hijackMaxFrameSize must PASS the guard
	// (the check is `>`, not `>=`). We send only the header then close the
	// pipe, so Read proceeds past the guard and fails at io.ReadFull with a
	// read error — proving the guard did not reject the boundary value.
	t.Run("boundary_at_cap_not_rejected", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		defer serverConn.Close()
		wc := NewWSConn(serverConn, true, "peer", 0)

		go func() {
			_ = ws.WriteHeader(clientConn, ws.Header{
				Fin:    true,
				OpCode: ws.OpBinary,
				Length: hijackMaxFrameSize, // exactly at the cap
				Masked: true,
				Mask:   ws.NewMask(),
			})
			// No payload — close so the server's io.ReadFull ends with a read
			// error rather than the size guard.
			clientConn.Close()
		}()

		buf := make([]byte, 4096)
		n, err := readWithTimeout(t, wc, buf, 5*time.Second)
		if n != 0 {
			t.Fatalf("expected n==0, got %d", n)
		}
		if err == nil {
			t.Fatalf("expected a read error after the header, got nil")
		}
		if strings.Contains(err.Error(), "frame too large") {
			t.Fatalf("boundary frame (== cap) must pass the `>` guard, but was size-rejected: %v", err)
		}
	})
}
