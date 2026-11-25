//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"net"
	"testing"
	"time"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/flow"
)

// liteRawPeerOver is newLiteRawPeer for a session build makes over its end of a
// net.Pipe, so a test chooses the constructor and the remote node ID.
func liteRawPeerOver(t *testing.T, build func(net.Conn) *TCPSession) *liteRawPeer {
	t.Helper()
	c, s := net.Pipe()
	sess := build(c)
	t.Cleanup(func() { _ = sess.Close(); _ = s.Close() })
	_ = s.SetDeadline(time.Now().Add(60 * time.Second))
	offer, err := aether.ReadWireVersionsPreface(s)
	if err != nil {
		t.Fatalf("read preface: %v", err)
	}
	if err := aether.WriteWireVersionsPreface(s, frameOnlyOffer()); err != nil {
		t.Fatalf("write preface: %v", err)
	}
	chosen, err := aether.ChooseWireVersions(frameOnlyOffer(), offer)
	if err != nil {
		t.Fatalf("choose: %v", err)
	}
	return &liteRawPeer{t: t, sess: sess, conn: s, decoder: wireDecoder(chosen)}
}

// fillUntilPong writes frames and a PING, and returns every RESET the session
// writes before the PONG that answers it.
func fillUntilPong(p *liteRawPeer, frames []*aether.Frame) []*aether.Frame {
	p.t.Helper()
	writeFrames(p.t, p.conn, append(frames, &aether.Frame{StreamID: 2, Type: aether.TypePING})...)
	var resets []*aether.Frame
	for {
		f := p.next()
		if f.Type == aether.TypePONG {
			return resets
		}
		if f.Type == aether.TypeRESET {
			resets = append(resets, f)
		}
	}
}

// peerMemoryEntry is peerMemoryLedgers' ledger for id and the count of sessions
// sharing it, nil and 0 when no session to id shares one.
func peerMemoryEntry(id aether.NodeID) (*creditLedger, int) {
	peerMemoryLedgers.mu.Lock()
	defer peerMemoryLedgers.mu.Unlock()
	if e := peerMemoryLedgers.m[id]; e != nil {
		return e.ledger, e.sessions
	}
	return nil, 0
}

// TestTCPSession_SessionsUnderAProvedIDShareThePeersRoom: two sessions NewTCPSession
// builds for one remote node ID hold one per-peer memory ledger, the registry's entry
// for that ID, so the profile's per-peer ceiling bounds them together.
func TestTCPSession_SessionsUnderAProvedIDShareThePeersRoom(t *testing.T) {
	const peer aether.NodeID = "vl1_stated_shared_proved"
	build := func(c net.Conn) *TCPSession {
		return NewTCPSession(c, "vl1_stated_local", peer, aether.ProtoTCP, aether.DefaultSessionOptions())
	}
	a := liteRawPeerOver(t, build)
	b := liteRawPeerOver(t, build)
	drainAtEnd(t, a)
	drainAtEnd(t, b)
	entry, sessions := peerMemoryEntry(peer)
	if entry == nil || sessions != 2 {
		t.Fatalf("the per-peer memory entry for a proved ID counts %d sessions, want 2", sessions)
	}
	if a.sess.peerShare.parent != entry || b.sess.peerShare.parent != entry {
		t.Fatal("two sessions under one proved ID hold different per-peer ledgers")
	}
	if got, want := entry.ceiling, flow.CurrentBounds().PeerMemoryCeiling; got != want {
		t.Fatalf("the per-peer ledger's ceiling is %d, want the profile's %d", got, want)
	}
}

// TestTCPSession_AStatedIDCannotFillTheNamedNodesRoom: a session built under a node
// ID its remote only stated (NewSessionForStatedPeer) queues up to its own session
// ceiling without taking anything from the room of the node it names. The proved
// session to that node then queues as much again with no reset, which together is
// past the per-peer ceiling, so the two counted against one ledger would have reset
// the proved session's stream.
func TestTCPSession_AStatedIDCannotFillTheNamedNodesRoom(t *testing.T) {
	const victim aether.NodeID = "vl1_stated_victim"
	const size, perStream, streams = 64 * 1024, 15, 15
	bounds := flow.CurrentBounds()
	fill := streams * perStream * messageCredit(size)
	if fill > bounds.SessionMemoryCeiling || 2*fill <= bounds.PeerMemoryCeiling {
		t.Fatalf("premise: a fill of %d must fit the session ceiling %d and two must pass the peer ceiling %d",
			fill, bounds.SessionMemoryCeiling, bounds.PeerMemoryCeiling)
	}

	proved := liteRawPeerOver(t, func(c net.Conn) *TCPSession {
		return NewTCPSession(c, "vl1_stated_local", victim, aether.ProtoTCP, aether.DefaultSessionOptions())
	})
	drainAtEnd(t, proved)
	stated := liteRawPeerOver(t, func(c net.Conn) *TCPSession {
		s, err := NewSessionForStatedPeer(c, aether.ProtoWebSocket, "vl1_stated_local", victim, aether.DefaultSessionOptions())
		if err != nil {
			t.Fatalf("stated session: %v", err)
		}
		return s.(*WebSocketSession).TCPSession
	})
	drainAtEnd(t, stated)
	if got := stated.sess.RemoteNodeID(); got != victim {
		t.Fatalf("the stated session reports %q, want the stated ID %q", got, victim)
	}
	entry, sessions := peerMemoryEntry(victim)
	if entry == nil || proved.sess.peerShare.parent != entry {
		t.Fatal("the proved session holds no share of its peer's entry")
	}
	if stated.sess.peerShare.parent == entry || sessions != 1 {
		t.Fatalf("the stated session joined the named node's per-peer entry (%d sessions on it)", sessions)
	}

	var frames []*aether.Frame
	for k := 0; k < streams; k++ {
		frames = append(frames, liteFill(uint64(600+k), perStream, size)...)
	}
	if resets := fillUntilPong(stated, frames); len(resets) != 0 {
		t.Fatalf("the stated session reset %+v inside its own ceiling", resets)
	}
	if got := stated.sess.recvQueued.Load(); got != fill {
		t.Fatalf("the stated session queues %d, want %d", got, fill)
	}
	if got := entry.held(); got != 0 {
		t.Fatalf("the named node's room holds %d of the stated session's queues", got)
	}

	if resets := fillUntilPong(proved, frames); len(resets) != 0 {
		t.Fatalf("the named node's own session was reset %+v after a stated session filled its queues", resets)
	}
	if got := entry.held(); got != fill {
		t.Fatalf("the named node's room holds %d, want its own session's %d", got, fill)
	}
}

// TestNewSessionForStatedPeer_EveryAdapterKeepsItsPeerLedgersToItself: for every
// protocol the factory builds, a session under a stated ID joins neither per-peer
// registry, while NewSessionForProtocol's session under the same ID joins both that
// its adapter keeps (the memory ledger on every adapter, the credit ledger on Noise).
func TestNewSessionForStatedPeer_EveryAdapterKeepsItsPeerLedgersToItself(t *testing.T) {
	type ledgers struct{ memory, credit *creditLedger }
	of := func(s aether.Session) ledgers {
		switch x := s.(type) {
		case *NoiseSession:
			return ledgers{x.peerShare.parent, x.admitted.parent}
		case *WebSocketSession:
			return ledgers{memory: x.peerShare.parent}
		case *GrpcSession:
			return ledgers{memory: x.peerShare.parent}
		case *TCPSession:
			return ledgers{memory: x.peerShare.parent}
		}
		t.Fatalf("session type %T", s)
		return ledgers{}
	}
	chosen := aetherChosen(t)
	for _, proto := range []aether.Protocol{aether.ProtoNoise, aether.ProtoWebSocket, aether.ProtoQUIC, aether.ProtoGRPC, aether.ProtoTCP} {
		t.Run(proto.String(), func(t *testing.T) {
			peer := aether.NodeID("vl1_stated_factory_" + proto.String())
			build := func(f func(net.Conn, aether.Protocol, aether.NodeID, aether.NodeID, aether.SessionOptions) (aether.Session, error)) aether.Session {
				c, s := net.Pipe()
				conn := c
				if proto == aether.ProtoNoise {
					conn = realmConn{Conn: c, chosen: chosen}
				}
				sess, err := f(conn, proto, "vl1_stated_local", peer, aether.DefaultSessionOptions())
				if err != nil {
					t.Fatalf("build: %v", err)
				}
				t.Cleanup(func() { _ = sess.Close(); _ = s.Close() })
				return sess
			}
			proved := of(build(NewSessionForProtocol))
			stated := of(build(NewSessionForStatedPeer))
			if entry, _ := peerMemoryEntry(peer); proved.memory == nil || proved.memory != entry {
				t.Fatal("NewSessionForProtocol's session holds no share of the peer's memory entry")
			}
			if stated.memory == nil || stated.memory == proved.memory {
				t.Fatal("the stated session shares the named node's memory ledger")
			}
			if stated.memory.ceiling != flow.CurrentBounds().PeerMemoryCeiling {
				t.Fatalf("the stated session's own memory ceiling is %d, want the profile's %d",
					stated.memory.ceiling, flow.CurrentBounds().PeerMemoryCeiling)
			}
			if proto != aether.ProtoNoise {
				return
			}
			sessionPeerLedgers.mu.Lock()
			entry := sessionPeerLedgers.m[peer]
			sessionPeerLedgers.mu.Unlock()
			if entry == nil || proved.credit != entry.ledger {
				t.Fatal("NewSessionForProtocol's Noise session holds no share of the peer's credit entry")
			}
			if stated.credit == nil || stated.credit == proved.credit {
				t.Fatal("the stated Noise session shares the named node's credit ledger")
			}
		})
	}
}
