//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/health"
	"github.com/quic-go/quic-go"
)

// AE-H-01 regression coverage. QUICSession.streams was written on every
// accepted/opened stream but never deleted, so a long-lived connection
// doing OpenStream+Close (or Receive-to-EOF) per RPC leaked one pinned
// *quicStream — and the quic.Stream handle it retained — for every stream
// ever created, and Metrics().ActiveStreams over-reported forever. These
// tests drive quicStream's three termination paths (Close, Reset, Receive)
// with a fake quic.Stream and assert the session map is evicted, so a
// regression to the pre-fix (no delete) code fails them.

// fakeAEH01Stream is a minimal quic.Stream stub. It carries no real QUIC
// transport: Read is served from an optional in-memory buffer (nil => an
// immediate io.EOF), and Close/Cancel are no-ops. That is enough to drive
// quicStream.Close/Reset/Receive without standing up a loopback QUIC pair,
// keeping the eviction assertions fully deterministic.
type fakeAEH01Stream struct {
	readBuf *bytes.Reader
}

func (f *fakeAEH01Stream) Read(p []byte) (int, error) {
	if f.readBuf != nil {
		return f.readBuf.Read(p)
	}
	return 0, io.EOF
}
func (f *fakeAEH01Stream) Write(p []byte) (int, error)      { return len(p), nil }
func (f *fakeAEH01Stream) Close() error                     { return nil }
func (f *fakeAEH01Stream) CancelRead(quic.StreamErrorCode)  {}
func (f *fakeAEH01Stream) CancelWrite(quic.StreamErrorCode) {}
func (f *fakeAEH01Stream) Context() context.Context         { return context.Background() }
func (f *fakeAEH01Stream) StreamID() quic.StreamID          { return 0 }
func (f *fakeAEH01Stream) SetReadDeadline(time.Time) error  { return nil }
func (f *fakeAEH01Stream) SetWriteDeadline(time.Time) error { return nil }
func (f *fakeAEH01Stream) SetDeadline(time.Time) error      { return nil }

var _ quic.Stream = (*fakeAEH01Stream)(nil)

// newAEH01Session builds a QUICSession with just enough wiring for the
// eviction paths (streams map + mutex + health monitor for Metrics). It
// deliberately does NOT call NewQuicSession — that would start acceptLoop
// against a real conn — so conn/acceptor stay nil, which none of the
// exercised paths (dropStream, Metrics, quicStream.Close/Reset/Receive)
// touch.
func newAEH01Session(t *testing.T) *QUICSession {
	t.Helper()
	base := aether.NewBaseSession(aether.NodeID("local-node"), aether.NodeID("remote-node"), aether.ProtoQUIC)
	base.SetHealthMonitor(health.NewMonitor(0.2))
	return &QUICSession{
		BaseSession: base,
		streams:     make(map[uint64]*quicStream),
	}
}

// registerAEH01Stream mirrors how OpenStream/acceptLoop populate the map:
// a fresh state machine transitioned to OPEN, then inserted under mu.
func registerAEH01Stream(sess *QUICSession, id uint64, qs quic.Stream) *quicStream {
	st := &quicStream{
		streamID:   id,
		quicStream: qs,
		config:     aether.StreamConfig{StreamID: id},
		state:      aether.NewStreamStateMachine(),
		session:    sess,
	}
	st.state.Transition(aether.EventSendOpen)
	sess.mu.Lock()
	sess.streams[id] = st
	sess.mu.Unlock()
	return st
}

func mapLen(sess *QUICSession) int {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	return len(sess.streams)
}

// TestQUICSession_StreamMapEvictedOnClose is the headline AE-H-01 case:
// open N streams, Close each, and assert the map and the ActiveStreams
// metric both drain to zero. Pre-fix this fails with len == N.
func TestQUICSession_StreamMapEvictedOnClose(t *testing.T) {
	sess := newAEH01Session(t)

	const n = 50
	streams := make([]*quicStream, n)
	for i := 0; i < n; i++ {
		streams[i] = registerAEH01Stream(sess, uint64(i), &fakeAEH01Stream{})
	}

	if got := mapLen(sess); got != n {
		t.Fatalf("setup: streams map len = %d, want %d", got, n)
	}
	if got := sess.Metrics().ActiveStreams; got != n {
		t.Fatalf("setup: ActiveStreams = %d, want %d", got, n)
	}

	for i, st := range streams {
		if err := st.Close(); err != nil {
			t.Fatalf("stream %d Close: %v", i, err)
		}
	}

	if got := mapLen(sess); got != 0 {
		t.Fatalf("streams map after Close: len = %d, want 0 (AE-H-01 leak regressed)", got)
	}
	if got := sess.Metrics().ActiveStreams; got != 0 {
		t.Fatalf("ActiveStreams after Close = %d, want 0", got)
	}
}

// TestQUICSession_StreamMapEvictedOnReset covers the Reset() termination
// path — a stream torn down via RESET must also leave the map.
func TestQUICSession_StreamMapEvictedOnReset(t *testing.T) {
	sess := newAEH01Session(t)
	st := registerAEH01Stream(sess, 7, &fakeAEH01Stream{})

	if err := st.Reset(aether.ResetReason(0)); err != nil {
		t.Fatalf("Reset: %v", err)
	}

	if got := mapLen(sess); got != 0 {
		t.Fatalf("streams map after Reset: len = %d, want 0", got)
	}
}

// TestQUICSession_StreamMapEvictedOnReceive covers the second AE-H-01 site:
// a read-to-EOF-then-abandon consumer (a common QUIC server pattern where
// the accepted stream is never explicitly Closed) must not leak. Both
// terminal Receive error paths — length-prefix read error and a framing
// desync (length > MaxPayloadSize) — evict.
func TestQUICSession_StreamMapEvictedOnReceive(t *testing.T) {
	t.Run("EOF on length prefix", func(t *testing.T) {
		sess := newAEH01Session(t)
		st := registerAEH01Stream(sess, 9, &fakeAEH01Stream{}) // Read => io.EOF

		if _, err := st.Receive(context.Background()); err == nil {
			t.Fatal("Receive: expected error on EOF, got nil")
		}
		if got := mapLen(sess); got != 0 {
			t.Fatalf("streams map after Receive EOF: len = %d, want 0", got)
		}
	})

	t.Run("oversized length", func(t *testing.T) {
		sess := newAEH01Session(t)
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(aether.MaxPayloadSize)+1)
		st := registerAEH01Stream(sess, 11, &fakeAEH01Stream{readBuf: bytes.NewReader(lenBuf[:])})

		if _, err := st.Receive(context.Background()); err == nil {
			t.Fatal("Receive: expected error on oversized length, got nil")
		}
		if got := mapLen(sess); got != 0 {
			t.Fatalf("streams map after oversized Receive: len = %d, want 0", got)
		}
	})
}
