//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// frameOnlyOffer is a peer offer of the bounds profile, the frame grammar, the
// fragment envelope and the reliability profile without the short-form table, so
// a session that negotiates with it chooses no frame.short.
func frameOnlyOffer() aether.WireVersions {
	return aether.WireVersions{
		{Name: aether.WireVersionBounds, Versions: []uint16{2}, Required: true},
		{Name: aether.WireVersionFragment, Versions: []uint16{aether.WireVersionFragmentCurrent}, Required: true},
		{Name: aether.WireVersionFrame, Versions: []uint16{aether.WireVersionFrameCurrent}, Required: true},
		{Name: aether.WireVersionReliability, Versions: []uint16{2}, Required: true},
	}
}

// wireDecoder returns the reader-side Compressor for a peer that chose
// chosen, the decoder a raw test peer reads a session's frames with.
func wireDecoder(chosen aether.NegotiatedWireVersions) *aether.Compressor {
	c := aether.NewCompressor()
	c.UseWireVersions(chosen)
	return c
}

// frameTally collects the discriminators of every frame a raw peer read, a
// batch's children counted with the batch.
type frameTally struct {
	mu     sync.Mutex
	inds   []byte
	frames int
	err    error
}

func (ft *frameTally) read(conn net.Conn, rx *aether.Compressor, until time.Time) {
	_ = conn.SetReadDeadline(until)
	for {
		f, ind, batch, err := aether.ReadNextFrame(conn, rx)
		ft.mu.Lock()
		if err != nil {
			var ne net.Error
			if !(errors.As(err, &ne) && ne.Timeout()) {
				ft.err = err
			}
			ft.mu.Unlock()
			return
		}
		ft.inds = append(ft.inds, ind)
		if batch != nil {
			ft.frames += len(batch)
		} else if f != nil {
			ft.frames++
		}
		ft.mu.Unlock()
	}
}

func (ft *frameTally) shortSeen() bool {
	for _, b := range ft.inds {
		if b != aether.FullFrameDiscriminator {
			return true
		}
	}
	return false
}

// tcpRawPeerWithOffer runs a TCPSession against a raw peer that answers the
// session's preface with offer, then has the session open a stream and send
// messages. It returns what the raw peer read and the set the session chose.
func tcpRawPeerWithOffer(t *testing.T, offer aether.WireVersions) (*frameTally, aether.NegotiatedWireVersions) {
	t.Helper()
	sess, peer := rawPeer(t, aether.DefaultSessionOptions())
	_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	local, err := aether.ReadWireVersionsPreface(peer)
	if err != nil {
		t.Fatalf("read the session's preface: %v", err)
	}
	if err := aether.WriteWireVersionsPreface(peer, offer); err != nil {
		t.Fatalf("write the raw peer's preface: %v", err)
	}
	chosen, err := aether.ChooseWireVersions(offer, local)
	if err != nil {
		t.Fatalf("raw peer choice: %v", err)
	}
	tally := &frameTally{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		tally.read(peer, wireDecoder(chosen), time.Now().Add(1500*time.Millisecond))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	st, err := sess.OpenStream(ctx, aether.DefaultStreamConfig(10))
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	for i := 0; i < 80; i++ {
		if err := st.Send(ctx, []byte("grammar")); err != nil {
			t.Fatalf("Send %d: %v", i, err)
		}
	}
	<-done
	if got := sess.WireVersions(); !got.Equal(chosen) {
		t.Fatalf("session chose %v, raw peer %v", got, chosen)
	}
	return tally, chosen
}

// TestTCPSession_FrameShortNotChosenWritesFullFramesOnly: a TCPSession whose
// peer offers no frame.short writes every frame behind the full-frame
// discriminator, batches included, and the raw peer's full-only reader
// refuses nothing; the same traffic to a peer that offers frame.short carries
// short forms.
func TestTCPSession_FrameShortNotChosenWritesFullFramesOnly(t *testing.T) {
	tally, chosen := tcpRawPeerWithOffer(t, frameOnlyOffer())
	if _, ok := chosen.Version(aether.WireVersionFrameShort); ok {
		t.Fatalf("set %v chose frame.short", chosen)
	}
	if tally.err != nil {
		t.Fatalf("a full-only reader refused the session's bytes: %v", tally.err)
	}
	if tally.frames < 81 {
		t.Fatalf("raw peer read %d frames, want at least 81", tally.frames)
	}
	if tally.shortSeen() {
		t.Fatalf("a session with no frame.short wrote discriminators % x", tally.inds)
	}

	tally, _ = tcpRawPeerWithOffer(t, aether.AetherWireVersions())
	if tally.err != nil {
		t.Fatalf("control: reader refused the session's bytes: %v", tally.err)
	}
	if !tally.shortSeen() {
		t.Fatalf("control: a session that chose frame.short wrote %d frames, all full", tally.frames)
	}
}

// wireVersionsConn is a net.Conn reporting a chosen wire version set, as the
// Noise handshake's conn does, so a NoiseSession over a pipe takes its grammar
// from it.
type wireVersionsConn struct {
	net.Conn
	chosen aether.NegotiatedWireVersions
}

func (c wireVersionsConn) WireVersions() aether.NegotiatedWireVersions { return c.chosen }

func noiseRawPeerWithChosen(t *testing.T, chosen aether.NegotiatedWireVersions) *frameTally {
	t.Helper()
	c, peer := net.Pipe()
	sess := NewNoiseSession(wireVersionsConn{Conn: c, chosen: chosen}, "vl1_grammar_local", "vl1_grammar_raw", aether.DefaultSessionOptions())
	t.Cleanup(func() { _ = sess.Close(); _ = peer.Close() })
	if got := sess.WireVersions(); !got.Equal(chosen) {
		t.Fatalf("session reports %v, conn %v", got, chosen)
	}
	tally := &frameTally{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		tally.read(peer, wireDecoder(chosen), time.Now().Add(1500*time.Millisecond))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	go func() {
		st, err := sess.OpenStream(ctx, aether.DefaultStreamConfig(10))
		if err != nil {
			return
		}
		for i := 0; i < 16; i++ {
			if st.Send(ctx, []byte("grammar")) != nil {
				return
			}
		}
	}()
	<-done
	return tally
}

// TestNoiseSession_FrameShortNotChosenWritesFullFramesOnly: a NoiseSession
// whose handshake chose no frame.short writes every frame behind the
// full-frame discriminator; one whose handshake chose it carries short forms.
func TestNoiseSession_FrameShortNotChosenWritesFullFramesOnly(t *testing.T) {
	fullOnly, err := aether.ChooseWireVersions(aether.AetherWireVersions(), frameOnlyOffer())
	if err != nil {
		t.Fatalf("choose: %v", err)
	}
	tally := noiseRawPeerWithChosen(t, fullOnly)
	if tally.err != nil {
		t.Fatalf("a full-only reader refused the session's bytes: %v", tally.err)
	}
	if tally.frames < 5 {
		t.Fatalf("raw peer read %d frames, want at least 5", tally.frames)
	}
	if tally.shortSeen() {
		t.Fatalf("a session with no frame.short wrote discriminators % x", tally.inds)
	}

	both, err := aether.ChooseWireVersions(aether.AetherWireVersions(), aether.AetherWireVersions())
	if err != nil {
		t.Fatalf("choose: %v", err)
	}
	tally = noiseRawPeerWithChosen(t, both)
	if tally.err != nil {
		t.Fatalf("control: reader refused the session's bytes: %v", tally.err)
	}
	if !tally.shortSeen() {
		t.Fatalf("control: a session that chose frame.short wrote %d frames, all full", tally.frames)
	}
}

// TestTCPSession_RefusesUnnegotiatedShortForm: a short form from a peer that
// did not offer frame.short closes the session with a
// *aether.FrameDiscriminatorError, and no stream exists.
func TestTCPSession_RefusesUnnegotiatedShortForm(t *testing.T) {
	sess, peer := rawPeer(t, aether.DefaultSessionOptions())
	_ = peer.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := aether.ReadWireVersionsPreface(peer); err != nil {
		t.Fatalf("read the session's preface: %v", err)
	}
	if err := aether.WriteWireVersionsPreface(peer, frameOnlyOffer()); err != nil {
		t.Fatalf("write preface: %v", err)
	}
	// A control short form (0x83 PING on stream 2), which a session that
	// chose no frame.short has no reading for.
	// The session reads the one discriminator byte, refuses and closes the
	// pipe, so the rest of this write may fail; the refusal is what is tested.
	_, _ = peer.Write([]byte{0x83, 0x06, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01})
	waitClosed(t, sess)
	err := waitCloseErr(sess)
	var de *aether.FrameDiscriminatorError
	if !errors.As(err, &de) || de.Discriminator != 0x83 || de.ShortForms {
		t.Fatalf("close reason %v, want a *FrameDiscriminatorError for 0x83", err)
	}
}

// TestTCPSession_ReadsChosenShortForms: a TCPSession that chose frame.short
// with its peer reads the peer's short forms, here a short DATA frame after
// the full frame that opened its stream.
func TestTCPSession_ReadsChosenShortForms(t *testing.T) {
	sess, peer := rawPeer(t, aether.DefaultSessionOptions())
	_ = peer.SetDeadline(time.Now().Add(3 * time.Second))
	local, err := aether.ReadWireVersionsPreface(peer)
	if err != nil {
		t.Fatalf("read the session's preface: %v", err)
	}
	offer := aether.AetherWireVersions()
	if err := aether.WriteWireVersionsPreface(peer, offer); err != nil {
		t.Fatalf("write preface: %v", err)
	}
	chosen, err := aether.ChooseWireVersions(offer, local)
	if err != nil {
		t.Fatalf("choose: %v", err)
	}
	go func() { _, _ = io.Copy(io.Discard, peer) }()

	tx := wireDecoder(chosen)
	openPayload := aether.EncodeOpenPayload(aether.OpenPayload{Reliability: aether.ReliableOrdered})
	open := &aether.Frame{StreamID: 10, Type: aether.TypeDATA, Flags: aether.FlagSYN, Length: uint32(len(openPayload)), Payload: openPayload}
	var wire bytes.Buffer
	if _, err := aether.EncodeFrame(&wire, open); err != nil {
		t.Fatalf("encode open: %v", err)
	}
	tx.RecordFullHeader(open)
	data := &aether.Frame{StreamID: 10, Type: aether.TypeDATA, SeqNo: 1, Length: 5, Payload: []byte("short")}
	if _, err := tx.EncodeDataShort(&wire, data); err != nil {
		t.Fatalf("encode short DATA: %v", err)
	}
	go func() { _, _ = peer.Write(wire.Bytes()) }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	st, err := sess.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("AcceptStream: %v (close reason %v)", err, aether.SessionCloseErr(sess))
	}
	got, err := st.Receive(ctx)
	if err != nil || string(got) != "short" {
		t.Fatalf("Receive = %q, %v (close reason %v)", got, err, aether.SessionCloseErr(sess))
	}
}
