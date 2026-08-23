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
)

// Coverage for the lost-OPEN rescue on noise-UDP.
//
// THE DEFECT THESE PIN: OpenStream installs a stream locally and then writes ONE
// `TypeOPEN` frame with no SeqNo and no send-window entry. There is no OPEN
// retransmit, ack, or timeout anywhere in the codebase. On noise-UDP a single
// lost datagram therefore left the receiver without the stream forever — and
// every later DATA frame hit handleData's `return // unknown stream`, dropped
// WITHOUT an ACK, so the sender's bytes never retired: unbounded progressAge,
// TLP probing a stream the peer would never create.
//
// The receiver already carried the rescue (handleImplicitOpen) but it is
// reachable ONLY from FlagSYN, and nothing on the noise path ever set that flag —
// so on this transport the rescue was dead code while being live on TCP.
//
// ⚠ THE NEGATIVE CONTROL IN TestUnknownStream_NoSYNIsDroppedSilently IS THE
// DEFECT ITSELF, EXECUTABLE. It is expected to keep passing: it documents that a
// non-SYN frame for an unknown stream is still dropped. If it ever fails, the
// unknown-stream branch changed and the rationale above needs re-measuring.

// discardConn is a net.Conn whose writes always succeed and whose reads block
// until close. A real session's writeLoop/ACK path must not fail or block for
// these tests, and net.Pipe would block writes with no reader.
type discardConn struct {
	closed chan struct{}
}

func newDiscardConn() *discardConn { return &discardConn{closed: make(chan struct{})} }

func (c *discardConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}
func (c *discardConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *discardConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}
func (c *discardConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (c *discardConn) RemoteAddr() net.Addr               { return &net.UDPAddr{} }
func (c *discardConn) SetDeadline(time.Time) error        { return nil }
func (c *discardConn) SetReadDeadline(time.Time) error    { return nil }
func (c *discardConn) SetWriteDeadline(time.Time) error   { return nil }

// 📌 STATUS: THE SENDER-SIDE HALF IS **NOT IN THE TREE**. A change setting FlagSYN
// on outbound noise DATA frames was written, tested, mutation-proven, and then
// REVERTED — because the rescue it triggers routes through the acceptor's 100 ms
// per-ID backlog, and on a wedge older than the responder's 30 s AcceptStreamByID
// deadline no waiter is left to claim the rescued stream. It would then flush to
// the FIFO, be picked up by loom's dynamic-RPC handler (which filters no StreamID),
// fail to unmarshal, and be discarded frame after frame — converting a LOUD,
// detectable wedge into SILENT data loss on exactly the population the fix targets.
//
// So the sender flag must not ship alone. It needs a companion that guarantees the
// rescued stream reaches the right consumer (a responder re-arm, and/or a StreamID
// filter on that dynamic handler). Both companions are loom-side.
//
// The two tests below characterise the RECEIVER, which is unchanged and already
// deployed. They are what make the sender-side fix meaningful when it does land,
// and they hold today regardless.

// TestUnknownStream_SYNCreatesTheStream proves the rescue path a sender-side
// FlagSYN would reach is actually wired and does create the stream.
//
// This is what would make such a sender change worth anything — without it,
// setting the flag would be a no-op against a receiver that ignored it.
func TestUnknownStream_SYNCreatesTheStream(t *testing.T) {
	conn := newDiscardConn()
	defer conn.Close()

	s := NewNoiseSession(
		conn,
		aether.NodeID("vl1_local_syn_rescue_probe_aaaa"),
		aether.NodeID("vl1_remote_syn_rescue_probe_bbb"),
		aether.DefaultSessionOptions(),
	)
	defer s.Close()

	const probeStream = 100

	s.mu.Lock()
	_, existsBefore := s.streams[probeStream]
	s.mu.Unlock()
	if existsBefore {
		t.Fatal("precondition failed: stream 100 already exists on a fresh session")
	}

	s.handleData(&aether.Frame{
		StreamID: probeStream,
		Type:     aether.TypeDATA,
		Flags:    aether.FlagANTIREPLAY | aether.FlagSYN,
		SeqNo:    1,
		Length:   4,
		Payload:  []byte("ping"),
	})

	s.mu.Lock()
	_, existsAfter := s.streams[probeStream]
	s.mu.Unlock()
	if !existsAfter {
		t.Error("a SYN-bearing DATA frame for an unknown stream did NOT create it. " +
			"handleImplicitOpen is the rescue path the sender-side FlagSYN exists to " +
			"reach; if it is no longer wired, the sender change is inert and the " +
			"lost-OPEN wedge is back")
	}
}

// TestUnknownStream_NoSYNIsDroppedSilently is the NEGATIVE CONTROL, and it is the
// wedge mechanism itself expressed as a test.
//
// Without it the test above proves only "streams can be created", not that the
// FLAG is what decides it. The pair together is the whole finding: identical
// frame, one bit different, opposite outcomes.
func TestUnknownStream_NoSYNIsDroppedSilently(t *testing.T) {
	conn := newDiscardConn()
	defer conn.Close()

	s := NewNoiseSession(
		conn,
		aether.NodeID("vl1_local_syn_control_probe_ccc"),
		aether.NodeID("vl1_remote_syn_control_probe_dd"),
		aether.DefaultSessionOptions(),
	)
	defer s.Close()

	const probeStream = 100

	// Byte-for-byte the frame from the test above, minus FlagSYN.
	s.handleData(&aether.Frame{
		StreamID: probeStream,
		Type:     aether.TypeDATA,
		Flags:    aether.FlagANTIREPLAY,
		SeqNo:    1,
		Length:   4,
		Payload:  []byte("ping"),
	})

	s.mu.Lock()
	_, exists := s.streams[probeStream]
	s.mu.Unlock()
	if exists {
		t.Error("a DATA frame WITHOUT FlagSYN created an unknown stream. That is a " +
			"fine change — but it means the unknown-stream drop no longer exists, so " +
			"the sender-side FlagSYN is redundant and this file's rationale is stale")
	}
}
