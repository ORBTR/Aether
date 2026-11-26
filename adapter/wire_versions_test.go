//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package adapter

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/noise"
	fnoise "github.com/flynn/noise"
)

func newOverConnKeypair(t *testing.T) (priv, pub []byte) {
	t.Helper()
	kp, err := fnoise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	return kp.Private, kp.Public
}

// byteStreamProtocols are the protocols NewSessionForProtocol builds a
// TCPSession for: TCP, WebSocket, gRPC and the QUIC stream factory path.
var byteStreamProtocols = []aether.Protocol{aether.ProtoTCP, aether.ProtoWebSocket, aether.ProtoGRPC, aether.ProtoQUIC}

func optsWith(app aether.WireVersions) aether.SessionOptions {
	o := aether.DefaultSessionOptions()
	o.WireVersions = app
	return o
}

func byteStreamPair(t *testing.T, proto aether.Protocol, clientApp, serverApp aether.WireVersions) (client, server aether.Session) {
	t.Helper()
	c, s := net.Pipe()
	var err error
	client, err = NewSessionForProtocol(c, proto, "vl1_wv_client", "vl1_wv_server", optsWith(clientApp))
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	server, err = NewSessionForProtocol(s, proto, "vl1_wv_server", "vl1_wv_client", optsWith(serverApp))
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	return client, server
}

// TestTCPSession_IncompatibleWireVersionsRefuseBeforeStream: on every
// byte-stream protocol, a required application entry with no common version
// closes both sessions with ErrWireVersionMismatch, OpenStream and
// AcceptStream return it, and no stream exists on either side.
func TestTCPSession_IncompatibleWireVersionsRefuseBeforeStream(t *testing.T) {
	for _, proto := range byteStreamProtocols {
		t.Run(proto.String(), func(t *testing.T) {
			client, server := byteStreamPair(t, proto,
				aether.WireVersions{{Name: "gossip.codec", Versions: []uint16{1}, Required: true}},
				aether.WireVersions{{Name: "gossip.codec", Versions: []uint16{2}, Required: true}})
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			accepted := make(chan error, 1)
			go func() {
				st, err := server.AcceptStream(ctx)
				if st != nil {
					err = errors.New("server accepted a stream")
				}
				accepted <- err
			}()
			st, err := client.OpenStream(ctx, aether.DefaultStreamConfig(10))
			if st != nil {
				t.Fatalf("OpenStream returned a stream")
			}
			if !errors.Is(err, aether.ErrWireVersionMismatch) {
				t.Fatalf("OpenStream err = %v, want ErrWireVersionMismatch", err)
			}
			if err := <-accepted; !errors.Is(err, aether.ErrWireVersionMismatch) {
				t.Fatalf("AcceptStream err = %v, want ErrWireVersionMismatch", err)
			}
			for name, s := range map[string]aether.Session{"client": client, "server": server} {
				waitClosed(t, s)
				if err := waitCloseErr(s); !errors.Is(err, aether.ErrWireVersionMismatch) {
					t.Fatalf("%s close reason %v, want ErrWireVersionMismatch", name, err)
				}
				if n := s.Metrics().ActiveStreams; n != 0 {
					t.Fatalf("%s holds %d streams after a refusal", name, n)
				}
				if got, ok := aether.SessionWireVersions(s); !ok || len(got.Entries()) != 0 {
					t.Fatalf("%s reports set %v (%v) after a refusal", name, got, ok)
				}
			}
		})
	}
}

// waitCloseErr returns the session's close reason, waiting briefly for it:
// CloseWithError marks the session closed before it records the reason.
func waitCloseErr(s aether.Session) error {
	deadline := time.Now().Add(2 * time.Second)
	for {
		if err := aether.SessionCloseErr(s); err != nil || time.Now().After(deadline) {
			return err
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func waitClosed(t *testing.T, s aether.Session) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !s.IsClosed() {
		if time.Now().After(deadline) {
			t.Fatalf("session still open")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestTCPSession_CompatibleWireVersionsSameSetBothEnds: on every byte-stream
// protocol both ends report the same chosen set, and a stream carries data.
func TestTCPSession_CompatibleWireVersionsSameSetBothEnds(t *testing.T) {
	for _, proto := range byteStreamProtocols {
		t.Run(proto.String(), func(t *testing.T) {
			client, server := byteStreamPair(t, proto,
				aether.WireVersions{{Name: "gossip.codec", Versions: []uint16{1, 2}, Required: true}},
				aether.WireVersions{{Name: "gossip.codec", Versions: []uint16{2, 3}, Required: true}})
			a, okA := aether.SessionWireVersions(client)
			b, okB := aether.SessionWireVersions(server)
			if !okA || !okB || !a.Equal(b) {
				t.Fatalf("client %v (%v) server %v (%v)", a, okA, b, okB)
			}
			for name, want := range map[string]uint16{"frame": aether.WireVersionFrameCurrent, "frame.short": 1, "gossip.codec": 2} {
				if v, ok := a.Version(name); !ok || v != want {
					t.Fatalf("%s = %d, %v; want %d", name, v, ok, want)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			st, err := client.OpenStream(ctx, aether.DefaultStreamConfig(10))
			if err != nil {
				t.Fatalf("OpenStream: %v", err)
			}
			if err := st.Send(ctx, []byte("after the preface")); err != nil {
				t.Fatalf("Send: %v", err)
			}
			in, err := server.AcceptStreamByID(ctx, 10)
			if err != nil {
				t.Fatalf("AcceptStreamByID: %v", err)
			}
			for {
				got, err := in.Receive(ctx)
				if err != nil {
					t.Fatalf("Receive: %v", err)
				}
				if len(got) == 0 || got[0] == 0 { // the SYN frame's open payload
					continue
				}
				if string(got) != "after the preface" {
					t.Fatalf("received %q", got)
				}
				break
			}
		})
	}
}

// rawPeer is the far end of a TCPSession's conn, driven by hand.
func rawPeer(t *testing.T, opts aether.SessionOptions) (*TCPSession, net.Conn) {
	t.Helper()
	c, s := net.Pipe()
	sess := NewTCPSession(c, "vl1_wv_local", "vl1_wv_raw", aether.ProtoTCP, opts)
	t.Cleanup(func() { _ = sess.Close(); _ = s.Close() })
	return sess, s
}

// TestTCPSession_WritesPrefaceBeforeAnyFrame: the first bytes on the wire are
// the preface carrying this session's offer, even when a stream is opened at
// once and the peer has not answered.
func TestTCPSession_WritesPrefaceBeforeAnyFrame(t *testing.T) {
	sess, peer := rawPeer(t, aether.DefaultSessionOptions())
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, _ = sess.OpenStream(ctx, aether.DefaultStreamConfig(10))
	}()
	_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	got, err := aether.ReadWireVersionsPreface(peer)
	if err != nil {
		t.Fatalf("first bytes are not a preface: %v", err)
	}
	local, _ := aether.LocalWireVersions(nil)
	want, _ := local.Encode()
	if enc, _ := got.Encode(); !bytes.Equal(enc, want) {
		t.Fatalf("preface offers %+v, want %+v", got, local)
	}
}

// TestTCPSession_RefusesPeerWithoutPreface: a peer whose first bytes are a
// frame rather than a preface closes the session with
// ErrWireVersionsMalformed, and the frame opens no stream.
func TestTCPSession_RefusesPeerWithoutPreface(t *testing.T) {
	sess, peer := rawPeer(t, aether.DefaultSessionOptions())
	go func() { _, _ = io.Copy(io.Discard, peer) }()
	frame := aether.EncodeFrameToBytes(&aether.Frame{
		StreamID: 10,
		Type:     aether.TypeDATA,
		Flags:    aether.FlagSYN,
		Length:   uint32(len("hello")),
		Payload:  []byte("hello"),
	})
	go func() { _, _ = peer.Write(frame) }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	st, err := sess.AcceptStream(ctx)
	if st != nil {
		t.Fatalf("a frame sent without a preface opened a stream")
	}
	if !errors.Is(err, aether.ErrWireVersionsMalformed) {
		t.Fatalf("AcceptStream err = %v, want ErrWireVersionsMalformed", err)
	}
	waitClosed(t, sess)
	if err := waitCloseErr(sess); !errors.Is(err, aether.ErrWireVersionsMalformed) {
		t.Fatalf("close reason %v", err)
	}
}

// TestTCPSession_PrefaceDeadline: a peer that never sends its preface has the
// session closed at the preface deadline, and OpenStream returns that reason.
func TestTCPSession_PrefaceDeadline(t *testing.T) {
	prev := wireVersionsPrefaceTimeout
	wireVersionsPrefaceTimeout = 200 * time.Millisecond
	defer func() { wireVersionsPrefaceTimeout = prev }()
	sess, peer := rawPeer(t, aether.DefaultSessionOptions())
	go func() { _, _ = io.Copy(io.Discard, peer) }()
	start := time.Now()
	st, err := sess.OpenStream(context.Background(), aether.DefaultStreamConfig(10))
	if st != nil {
		t.Fatalf("OpenStream returned a stream with no preface from the peer")
	}
	if !errors.Is(err, errWireVersionsPrefaceTimeout) {
		t.Fatalf("OpenStream err = %v, want the preface deadline", err)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("refusal took %v", took)
	}
	waitClosed(t, sess)
}

// TestTCPSession_RefusesMalformedLocalEntries: an application entry naming
// one of aether's entries closes the session before any preface is written.
func TestTCPSession_RefusesMalformedLocalEntries(t *testing.T) {
	sess, peer := rawPeer(t, optsWith(aether.WireVersions{{Name: "frame", Versions: []uint16{7}, Required: true}}))
	_ = peer.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, _ := peer.Read(make([]byte, 16)); n != 0 {
		t.Fatalf("%d bytes written for a malformed local offer", n)
	}
	waitClosed(t, sess)
	if err := waitCloseErr(sess); !errors.Is(err, aether.ErrWireVersionsMalformed) {
		t.Fatalf("close reason %v", err)
	}
}

// TestNoiseSession_ReportsHandshakeWireVersions: a NoiseSession reports the
// set its Noise handshake chose, the same on both ends; an incompatible pair
// returns ErrWireVersionMismatch from the dial and builds no session.
func TestNoiseSession_ReportsHandshakeWireVersions(t *testing.T) {
	run := func(dialApp, acceptApp aether.WireVersions) (*NoiseSession, *NoiseSession, error) {
		aPriv, aPub := newOverConnKeypair(t)
		bPriv, bPub := newOverConnKeypair(t)
		c, s := net.Pipe()
		t.Cleanup(func() { _ = c.Close(); _ = s.Close() })
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		type res struct {
			s   *NoiseSession
			err error
		}
		ch := make(chan res, 1)
		go func() {
			sess, err := AcceptSessionOverConn(ctx, noise.AcceptConnConfig{
				LocalNodeID: "vl1_wv_b", StaticPriv: bPriv, StaticPub: bPub,
				HandshakeTimeout: 2 * time.Second, WireVersions: acceptApp,
			}, s, aether.DefaultSessionOptions())
			ch <- res{sess, err}
		}()
		dialed, err := DialSessionOverConn(ctx, noise.DialConnConfig{
			LocalNodeID: "vl1_wv_a", StaticPriv: aPriv, StaticPub: aPub,
			HandshakeTimeout: 2 * time.Second, WireVersions: dialApp,
		}, c, aether.DefaultSessionOptions())
		if err != nil {
			_ = c.Close()
		}
		r := <-ch
		if dialed != nil {
			t.Cleanup(func() { _ = dialed.Close() })
		}
		if r.s != nil {
			t.Cleanup(func() { _ = r.s.Close() })
		}
		if err == nil {
			err = r.err
		}
		return dialed, r.s, err
	}

	a, b, err := run(
		aether.WireVersions{{Name: "gossip.codec", Versions: []uint16{1, 2}, Required: true}},
		aether.WireVersions{{Name: "gossip.codec", Versions: []uint16{2}, Required: true}})
	if err != nil {
		t.Fatalf("compatible pair: %v", err)
	}
	ga, okA := aether.SessionWireVersions(a)
	gb, okB := aether.SessionWireVersions(b)
	if !okA || !okB || !ga.Equal(gb) {
		t.Fatalf("dialer %v (%v) accepter %v (%v)", ga, okA, gb, okB)
	}
	if v, ok := ga.Version("gossip.codec"); !ok || v != 2 {
		t.Fatalf("gossip.codec = %d, %v", v, ok)
	}

	a, b, err = run(
		aether.WireVersions{{Name: "gossip.codec", Versions: []uint16{1}, Required: true}},
		aether.WireVersions{{Name: "gossip.codec", Versions: []uint16{2}, Required: true}})
	if !errors.Is(err, aether.ErrWireVersionMismatch) {
		t.Fatalf("incompatible pair err = %v, want ErrWireVersionMismatch", err)
	}
	if a != nil || b != nil {
		t.Fatalf("incompatible pair built a session (dialer=%v accepter=%v)", a != nil, b != nil)
	}
}
