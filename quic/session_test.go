//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package quic

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/ORBTR/aether"
	"github.com/quic-go/quic-go"
)

// fakeUniStream is a minimal quic.ReceiveStream whose Read is backed by an
// in-memory buffer. It embeds the quic.ReceiveStream interface so the unused
// methods (StreamID, CancelRead, SetReadDeadline) are satisfied at compile time
// without being exercised — QuicSession.Receive only ever calls Read.
type fakeUniStream struct {
	quic.ReceiveStream
	r *bytes.Reader
}

func (f *fakeUniStream) Read(p []byte) (int, error) { return f.r.Read(p) }

// fakeQuicConn is a minimal quic.Connection that hands out a single peer-opened
// unidirectional stream. It embeds the quic.Connection interface so the rest of
// the (large) method set is satisfied at compile time; only AcceptUniStream is
// overridden because that is the sole method QuicSession.Receive calls.
type fakeQuicConn struct {
	quic.Connection
	stream   quic.ReceiveStream
	accepted bool
}

func (f *fakeQuicConn) AcceptUniStream(ctx context.Context) (quic.ReceiveStream, error) {
	if f.accepted {
		return nil, io.EOF
	}
	f.accepted = true
	return f.stream, nil
}

// newFakeSession builds a QuicSession whose next accepted uni-stream yields the
// given raw bytes, so Receive can be exercised without a live QUIC handshake.
func newFakeSession(payload []byte) *QuicSession {
	conn := &fakeQuicConn{stream: &fakeUniStream{r: bytes.NewReader(payload)}}
	return NewQuicSession(aether.NodeID("local"), aether.NodeID("remote"), conn)
}

// TestQuicSessionReceiveRejectsOversizedPayload verifies the AE-M-15 guard:
// QuicSession.Receive caps a peer-controlled uni-stream at aether.MaxPayloadSize
// so a malicious peer cannot stream unbounded data and OOM the process, while
// legitimate messages up to exactly MaxPayloadSize still pass unchanged.
func TestQuicSessionReceiveRejectsOversizedPayload(t *testing.T) {
	t.Run("over_cap", func(t *testing.T) {
		// One byte past the cap must be rejected, not buffered/returned.
		sess := newFakeSession(make([]byte, aether.MaxPayloadSize+1))

		payload, err := sess.Receive(context.Background())
		if err == nil {
			t.Fatalf("expected error for oversized payload, got nil (payload len=%d)", len(payload))
		}
		if !strings.Contains(err.Error(), "too large") {
			t.Fatalf("expected a 'too large' error, got: %v", err)
		}
		if payload != nil {
			t.Fatalf("expected nil payload on rejection, got len=%d", len(payload))
		}
	})

	t.Run("under_cap", func(t *testing.T) {
		// Capability preserved: a full max-size message still round-trips.
		sess := newFakeSession(make([]byte, aether.MaxPayloadSize))

		payload, err := sess.Receive(context.Background())
		if err != nil {
			t.Fatalf("expected no error for max-size payload, got: %v", err)
		}
		if len(payload) != aether.MaxPayloadSize {
			t.Fatalf("expected payload len %d, got %d", aether.MaxPayloadSize, len(payload))
		}
	})

	t.Run("small_payload", func(t *testing.T) {
		// A normal small message passes through untouched.
		want := []byte("hello aether")
		sess := newFakeSession(want)

		payload, err := sess.Receive(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Equal(payload, want) {
			t.Fatalf("payload mismatch: got %q want %q", payload, want)
		}
	})
}
