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
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ORBTR/aether"
	"github.com/quic-go/quic-go"
)

// AE-P-06 regression coverage. QUICSession.acceptLoop inserted every
// accepted stream with `s.streams[streamID] = st` and no duplicate check,
// so a second live QUIC stream presenting an already-registered aether
// StreamID silently overwrote the map entry — corrupting
// Metrics().ActiveStreams and, via dropStream (AE-H-01), letting either
// stream's close evict the survivor's slot. The fix refuses the duplicate
// transport stream (CancelRead+CancelWrite) and keeps the first mapping.
//
// These tests drive the REAL acceptLoop through a fake quic.Connection that
// hands out fake streams presenting chosen header StreamIDs, then asserts on
// the resulting streams map / metrics / refusal. Symbol names are AE-P-06
// unique to avoid collisions with other agents' tests in package adapter.

// aep06Stream is a fake quic.Stream that serves a fixed 18-byte aether stream
// header ([StreamID:8][OpenPayload:10]) on Read and records whether acceptLoop
// refused it via CancelRead/CancelWrite. Write/Close are no-ops.
type aep06Stream struct {
	readBuf     *bytes.Reader
	cancelRead  atomic.Bool
	cancelWrite atomic.Bool
}

func newAEP06Stream(streamID uint64) *aep06Stream {
	h := make([]byte, 8+aether.OpenPayloadSize)
	binary.BigEndian.PutUint64(h[0:8], streamID)
	copy(h[8:], aether.EncodeOpenPayload(aether.OpenPayload{}))
	return &aep06Stream{readBuf: bytes.NewReader(h)}
}

func (f *aep06Stream) Read(p []byte) (int, error)  { return f.readBuf.Read(p) }
func (f *aep06Stream) Write(p []byte) (int, error) { return len(p), nil }
func (f *aep06Stream) Close() error                { return nil }
func (f *aep06Stream) CancelRead(quic.StreamErrorCode) {
	f.cancelRead.Store(true)
}
func (f *aep06Stream) CancelWrite(quic.StreamErrorCode) {
	f.cancelWrite.Store(true)
}
func (f *aep06Stream) Context() context.Context         { return context.Background() }
func (f *aep06Stream) StreamID() quic.StreamID          { return 0 }
func (f *aep06Stream) SetReadDeadline(time.Time) error  { return nil }
func (f *aep06Stream) SetWriteDeadline(time.Time) error { return nil }
func (f *aep06Stream) SetDeadline(time.Time) error      { return nil }

var _ quic.Stream = (*aep06Stream)(nil)

// aep06Conn is a fake quic.Connection whose AcceptStream drains a fixed queue
// of fake streams and then closes `done` and returns io.EOF (terminating
// acceptLoop). Because acceptLoop is a single sequential goroutine, by the
// time the terminating AcceptStream fires, every prior stream's map insert /
// refusal is fully complete — so `<-done` is a clean synchronization point.
type aep06Conn struct {
	mu       sync.Mutex
	queue    []quic.Stream
	idx      int
	done     chan struct{}
	doneOnce sync.Once
}

func (c *aep06Conn) AcceptStream(context.Context) (quic.Stream, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.idx < len(c.queue) {
		s := c.queue[c.idx]
		c.idx++
		return s, nil
	}
	c.doneOnce.Do(func() { close(c.done) })
	return nil, io.EOF
}

func (c *aep06Conn) AcceptUniStream(context.Context) (quic.ReceiveStream, error) { return nil, io.EOF }
func (c *aep06Conn) OpenStream() (quic.Stream, error)                            { return nil, io.EOF }
func (c *aep06Conn) OpenStreamSync(context.Context) (quic.Stream, error)         { return nil, io.EOF }
func (c *aep06Conn) OpenUniStream() (quic.SendStream, error)                     { return nil, io.EOF }
func (c *aep06Conn) OpenUniStreamSync(context.Context) (quic.SendStream, error)  { return nil, io.EOF }
func (c *aep06Conn) LocalAddr() net.Addr                                         { return nil }
func (c *aep06Conn) RemoteAddr() net.Addr                                        { return nil }
func (c *aep06Conn) CloseWithError(quic.ApplicationErrorCode, string) error      { return nil }
func (c *aep06Conn) Context() context.Context                                    { return context.Background() }
func (c *aep06Conn) ConnectionState() quic.ConnectionState                       { return quic.ConnectionState{} }
func (c *aep06Conn) SendDatagram([]byte) error                                   { return nil }
func (c *aep06Conn) ReceiveDatagram(context.Context) ([]byte, error)             { return nil, io.EOF }

var _ quic.Connection = (*aep06Conn)(nil)

// runAEP06AcceptLoop stands up a real QUICSession over a fake conn seeded with
// one fake stream per id (in order), waits for acceptLoop to drain the queue,
// and returns the session plus the fake streams for assertion.
func runAEP06AcceptLoop(t *testing.T, ids ...uint64) (*QUICSession, []*aep06Stream) {
	t.Helper()
	streams := make([]*aep06Stream, len(ids))
	q := make([]quic.Stream, len(ids))
	for i, id := range ids {
		s := newAEP06Stream(id)
		streams[i] = s
		q[i] = s
	}
	conn := &aep06Conn{queue: q, done: make(chan struct{})}
	sess := NewQuicSession(conn, aether.NodeID("aep06-local"), aether.NodeID("aep06-remote"))
	select {
	case <-conn.done:
	case <-time.After(2 * time.Second):
		t.Fatal("AE-P-06: acceptLoop did not drain the fake stream queue")
	}
	return sess, streams
}

func aep06MapLen(sess *QUICSession) int {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	return len(sess.streams)
}

// TestAEP06_DuplicateStreamIDRefused is the headline case: two accepted QUIC
// streams present the SAME aether StreamID. The guard must register only the
// first, refuse the second (CancelRead+CancelWrite), keep ActiveStreams == 1,
// and deliver exactly one stream to the accept surface. Pre-fix the map insert
// overwrote and the count/dispatch bookkeeping went wrong.
func TestAEP06_DuplicateStreamIDRefused(t *testing.T) {
	const dupID = uint64(0x4242)
	sess, streams := runAEP06AcceptLoop(t, dupID, dupID)
	defer sess.Close()

	if got := aep06MapLen(sess); got != 1 {
		t.Fatalf("streams map len = %d, want 1 (duplicate StreamID must not overwrite/add a 2nd entry)", got)
	}
	if got := sess.Metrics().ActiveStreams; got != 1 {
		t.Fatalf("ActiveStreams = %d, want 1 (duplicate corrupted the count)", got)
	}

	// First stream accepted (never refused); second (duplicate) refused.
	if streams[0].cancelRead.Load() || streams[0].cancelWrite.Load() {
		t.Fatal("first stream was refused; want accepted (AE-P-06 must keep the first mapping)")
	}
	if !streams[1].cancelRead.Load() || !streams[1].cancelWrite.Load() {
		t.Fatal("duplicate stream was not refused via CancelRead+CancelWrite (AE-P-06 guard missing)")
	}

	// Exactly one stream reaches the accept surface, and it carries the ID.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	st, err := sess.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("AcceptStream: %v", err)
	}
	if st.StreamID() != dupID {
		t.Fatalf("accepted StreamID = %d, want %d", st.StreamID(), dupID)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel2()
	if extra, err := sess.AcceptStream(ctx2); err == nil {
		t.Fatalf("AcceptStream returned a 2nd stream (id %d); want exactly one", extra.StreamID())
	}
}

// TestAEP06_DistinctStreamIDsBothAccepted is the regression control: two
// DISTINCT StreamIDs must both register and neither be refused — the guard
// only rejects true duplicates.
func TestAEP06_DistinctStreamIDsBothAccepted(t *testing.T) {
	sess, streams := runAEP06AcceptLoop(t, 0x01, 0x02)
	defer sess.Close()

	if got := aep06MapLen(sess); got != 2 {
		t.Fatalf("streams map len = %d, want 2 (distinct IDs must both register)", got)
	}
	if got := sess.Metrics().ActiveStreams; got != 2 {
		t.Fatalf("ActiveStreams = %d, want 2", got)
	}
	for i, s := range streams {
		if s.cancelRead.Load() || s.cancelWrite.Load() {
			t.Fatalf("distinct stream %d was refused; want accepted", i)
		}
	}
}
