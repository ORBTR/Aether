//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/ORBTR/aether"
	"github.com/quic-go/quic-go"
)

// streamHangBound is how long these tests wait for something the code
// under test must do: a frame crossing a loopback QUIC connection, a
// released call returning. A passing run never waits for it. It only
// turns a hang into a failure, so it sits far above what a loaded machine
// running the race detector needs.
const streamHangBound = 30 * time.Second

// awaitClosed fails the test unless ch closes within streamHangBound.
func awaitClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(streamHangBound):
		t.Fatalf("%s did not happen within %v", what, streamHangBound)
	}
}

// quicLoopbackDials is how many times quicLoopback tries for a connected
// pair. A loopback dial now and then gets no reply at all and fails at
// quic-go's 5s handshake idle timeout, while the dials that succeed take a
// few milliseconds whatever the load. The handshake is not what these
// tests measure, and each try has its own listener and client socket, so
// four tries turn that into a 20s setup failure only if all four meet it.
const quicLoopbackDials = 4

// quicLoopback returns a client and a server QUICSession over one real
// loopback QUIC connection. The server grants each stream 16 KiB of
// receive window, so a client Write larger than that blocks until the
// server reads.
func quicLoopback(t *testing.T) (client, server *QUICSession) {
	t.Helper()
	cc, sc := quicLoopbackConns(t)
	client = NewQuicSession(cc, aether.NodeID("quic-client"), aether.NodeID("quic-server"))
	server = NewQuicSession(sc, aether.NodeID("quic-server"), aether.NodeID("quic-client"))
	return client, server
}

// quicLoopbackConns returns both ends of one real loopback QUIC connection, for a
// test that builds its own QUICSession on either end.
func quicLoopbackConns(t *testing.T) (cc, sc quic.Connection) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	tlsConf := &tls.Config{
		Certificates:       []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:         []string{"aether-deadline-test"},
		InsecureSkipVerify: true,
	}
	for try := 1; ; try++ {
		if cc, sc, err = quicLoopbackPair(t, tlsConf); err == nil {
			break
		}
		if try == quicLoopbackDials {
			t.Fatalf("no loopback QUIC connection in %d tries; the last: %v", try, err)
		}
		t.Logf("loopback QUIC try %d: %v", try, err)
	}
	t.Cleanup(func() {
		_ = cc.CloseWithError(0, "")
		_ = sc.CloseWithError(0, "")
	})
	return cc, sc
}

// quicLoopbackPair listens on a fresh loopback port, dials it once and
// returns both ends of the connection. The listener closes with the test
// when the pair is returned, and at once when the dial or accept fails.
func quicLoopbackPair(t *testing.T, tlsConf *tls.Config) (dialed, accepted quic.Connection, err error) {
	t.Helper()
	ln, err := quic.ListenAddr("127.0.0.1:0", tlsConf, &quic.Config{
		InitialStreamReceiveWindow:     16 << 10,
		MaxStreamReceiveWindow:         16 << 10,
		InitialConnectionReceiveWindow: 64 << 10,
		MaxConnectionReceiveWindow:     64 << 10,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), streamHangBound)
	defer cancel()
	type acceptResult struct {
		conn quic.Connection
		err  error
	}
	acceptCh := make(chan acceptResult, 1)
	go func() {
		c, err := ln.Accept(ctx)
		acceptCh <- acceptResult{c, err}
	}()
	dialed, err = quic.DialAddr(ctx, ln.Addr().String(), tlsConf, nil)
	if err != nil {
		_ = ln.Close()
		return nil, nil, fmt.Errorf("dial: %w", err)
	}
	a := <-acceptCh
	if a.err != nil {
		_ = dialed.CloseWithError(0, "")
		_ = ln.Close()
		return nil, nil, fmt.Errorf("accept: %w", a.err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return dialed, a.conn, nil
}

// fakeTimeout is the error a fake quic.Stream returns for a deadline that
// has passed; quicStream tells a deadline from any other failure by
// net.Error's Timeout, as it does with quic-go's own error.
type fakeTimeout struct{}

func (fakeTimeout) Error() string   { return "fake stream: deadline exceeded" }
func (fakeTimeout) Timeout() bool   { return true }
func (fakeTimeout) Temporary() bool { return true }

// A Send that timed out before any byte of its frame was accepted leaves
// the stream usable and clears the QUIC write deadline it moved: the frame
// sent before it arrives whole, the next Send goes through, and its frame
// is the next one the peer reads, so no byte of the timed-out frame was
// written.
//
// The stream is put in the one state where a frame's 4-byte length cannot
// be accepted. quic-go keeps up to 1452 bytes of a stream's writes that
// flow control holds back, and returns from Write once the rest has gone.
// The first frame is sized to end 1450 bytes past the peer's 16 KiB
// stream window, so its Send returns with those 1450 bytes held and the
// next length would make 1454. The peer reads nothing until the second
// Send has returned, so the window cannot open under it: the second Send
// can only end by its context, and the test has no race to lose.
func TestQuicStream_SendTimedOutWithNothingWrittenLeavesStreamUsable(t *testing.T) {
	const (
		window = 16 << 10                   // quicLoopback's stream receive window
		opened = 8 + aether.OpenPayloadSize // the header OpenStream wrote
		held   = 1450                       // of quic-go's 1452-byte write buffer
	)
	client, server := quicLoopback(t)
	ctx, cancel := context.WithTimeout(context.Background(), streamHangBound)
	defer cancel()
	st, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: 1})
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}

	first := bytes.Repeat([]byte{0xA5}, window+held-opened-4)
	if err := st.Send(ctx, first); err != nil {
		t.Fatalf("Send of the frame that fills the window: %v", err)
	}
	short, cancelShort := context.WithTimeout(ctx, 100*time.Millisecond)
	err = st.Send(short, []byte("timed out"))
	cancelShort()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Send behind a full window and a full write buffer = %v, want context.DeadlineExceeded", err)
	}

	peer, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("AcceptStream: %v", err)
	}
	if got, err := peer.Receive(ctx); err != nil || !bytes.Equal(got, first) {
		t.Fatalf("peer Receive of the first frame = (%d bytes, %v), want its %d bytes", len(got), err, len(first))
	}
	if err := st.Send(ctx, []byte("after")); err != nil {
		t.Fatalf("Send after one that timed out with nothing written: %v", err)
	}
	if got, err := peer.Receive(ctx); err != nil || string(got) != "after" {
		t.Fatalf("peer Receive after the timed-out Send = (%q, %v), want after", got, err)
	}
}

// heldMoveStream is a quic.Stream whose Write waits for letWrite and whose
// first SetWriteDeadline to a non-zero time waits for letMove, so a test
// can hold quicStream.boundWrite's move of the deadline in flight while
// the Write it bounds returns. Like quic-go's stream, a Write that starts
// with a write deadline in the past fails with a timeout.
type heldMoveStream struct {
	fakeAEH01Stream
	writing, letWrite chan struct{}
	moving, letMove   chan struct{}
	writingOnce       sync.Once
	movingOnce        sync.Once
	mu                sync.Mutex
	deadline          time.Time
}

func newHeldMoveStream() *heldMoveStream {
	return &heldMoveStream{
		writing: make(chan struct{}), letWrite: make(chan struct{}),
		moving: make(chan struct{}), letMove: make(chan struct{}),
	}
}

func (s *heldMoveStream) Write(p []byte) (int, error) {
	s.writingOnce.Do(func() { close(s.writing) })
	<-s.letWrite
	if dl := s.writeDeadline(); !dl.IsZero() && !time.Now().Before(dl) {
		return 0, fakeTimeout{}
	}
	return len(p), nil
}

func (s *heldMoveStream) SetWriteDeadline(t time.Time) error {
	if !t.IsZero() {
		s.movingOnce.Do(func() { close(s.moving) })
		<-s.letMove
	}
	s.mu.Lock()
	s.deadline = t
	s.mu.Unlock()
	return nil
}

func (s *heldMoveStream) writeDeadline() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deadline
}

// A later Send never meets a write deadline left in the past. The move of
// the deadline to now runs on its own goroutine once the Send's context
// ends, and the Write it bounds can return on its own while that move is
// still in flight. The Send must wait for the move before it clears the
// deadline: cleared first, the move would land afterwards and fail every
// later Send.
//
// The test holds the move in flight, lets the Write return, and requires
// that the Send has not returned 100ms later. A correct Send cannot return
// while the move is held, so that wait never fails one; the 100ms only
// gives a Send that does not wait the time to show it.
func TestQuicStream_SendClearsWriteDeadlineAfterItsMove(t *testing.T) {
	fake := newHeldMoveStream()
	st := registerAEH01Stream(newAEH01Session(t), 1, fake)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sent := make(chan error, 1)
	go func() { sent <- st.Send(ctx, []byte("first")) }()

	awaitClosed(t, fake.writing, "the Send's Write")
	cancel()
	awaitClosed(t, fake.moving, "the move of the write deadline")
	close(fake.letWrite)
	select {
	case err := <-sent:
		t.Fatalf("Send returned (%v) while the move of its write deadline was in flight", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(fake.letMove)
	select {
	case err := <-sent:
		if err != nil {
			t.Fatalf("Send whose Writes completed: %v", err)
		}
	case <-time.After(streamHangBound):
		t.Fatalf("Send did not return within %v of its move", streamHangBound)
	}

	if dl := fake.writeDeadline(); !dl.IsZero() {
		t.Fatalf("write deadline after the Send = %v, want none", dl)
	}
	if err := st.Send(context.Background(), []byte("second")); err != nil {
		t.Fatalf("later Send: %v", err)
	}
}
