/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// A stream reached by DATA and no OPEN. OpenStream writes one TypeOPEN frame with
// no sequence number and no send-window entry, and nothing retransmits it, so a lost
// OPEN leaves the receiver with no stream: handleData drops the stream's DATA without
// an ACK until the sender's stream GC resets the stream. Only a frame flagged
// aether.FlagSYN would create the stream from then on, and the two tests below
// characterise that receiver.
//
// TODO: a Noise sender that writes the OPEN payload again in a frame flagged
// aether.FlagSYN once its DATA goes unacknowledged. That stream reaches the acceptor's
// per-ID backlog, and past a responder's AcceptStreamByID deadline it goes on to the
// FIFO, so the application's dynamic-stream handler, which filters no stream ID, would
// read and discard its messages as unparseable; the sender needs a responder that
// re-arms its wait, or a stream ID filter on that handler, both outside this repository.

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
func (c *discardConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *discardConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (c *discardConn) SetDeadline(time.Time) error      { return nil }
func (c *discardConn) SetReadDeadline(time.Time) error  { return nil }
func (c *discardConn) SetWriteDeadline(time.Time) error { return nil }

// TestUnknownStream_SYNCreatesTheStream: a frame flagged aether.FlagSYN for an unknown
// stream admits the stream from the OPEN payload it carries, at the credit it states,
// and delivers nothing, since the payload is no message.
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

	const credit = 256 << 10
	open := aether.EncodeOpenPayload(aether.OpenPayload{Reliability: aether.ReliableOrdered, InitialCredit: credit, Generation: 1})
	s.handleData(&aether.Frame{
		StreamID: probeStream,
		Type:     aether.TypeDATA,
		Flags:    aether.FlagANTIREPLAY | aether.FlagSYN,
		Length:   uint32(len(open)),
		Payload:  open,
	})

	s.mu.Lock()
	st, existsAfter := s.streams[probeStream]
	s.mu.Unlock()
	if !existsAfter {
		t.Fatal("a SYN frame carrying an OPEN payload did not create its stream")
	}
	if got := st.window.CurrentWindow(); got != credit {
		t.Errorf("window = %d, want the %d the OPEN payload states", got, credit)
	}
	if n := st.recvQ.len(); n != 0 {
		t.Errorf("%d messages queued, want none: the OPEN payload is no message", n)
	}
}

// TestNoiseSession_ASYNPayloadIsNeverAMessage: a frame flagged aether.FlagSYN whose
// payload is not an OPEN payload is refused and keeps no state, and on a live stream
// such a frame changes nothing and delivers nothing.
func TestNoiseSession_ASYNPayloadIsNeverAMessage(t *testing.T) {
	s := NewNoiseSession(newDiscardConn(), aether.NodeID("vl1_local_syn_meaning_aaaaaaaaaa"),
		aether.NodeID("vl1_remote_syn_meaning_bbbbbbbbb"), aether.DefaultSessionOptions())
	defer s.Close()

	syn := func(id uint64, payload []byte) *aether.Frame {
		return &aether.Frame{StreamID: id, Type: aether.TypeDATA, Flags: aether.FlagSYN, Length: uint32(len(payload)), Payload: payload}
	}
	s.handleData(syn(100, []byte("ping")))
	s.mu.Lock()
	_, exists := s.streams[100]
	s.mu.Unlock()
	if exists {
		t.Fatal("a SYN frame carrying message bytes created a stream")
	}
	if got := atomic.LoadUint64(&s.streamRefused); got != 1 {
		t.Errorf("streamRefused = %d, want 1", got)
	}

	open := aether.EncodeOpenPayload(aether.OpenPayload{Reliability: aether.ReliableOrdered, InitialCredit: 256 << 10, Generation: 1})
	s.handleData(syn(101, open))
	s.mu.Lock()
	st := s.streams[101]
	s.mu.Unlock()
	if st == nil {
		t.Fatal("no stream from the OPEN payload")
	}
	s.handleData(syn(101, []byte("ping")))
	s.handleData(syn(101, open))
	s.mu.Lock()
	same := s.streams[101] == st
	s.mu.Unlock()
	if !same || st.recvQ.len() != 0 {
		t.Fatalf("a SYN frame on the live stream: same stream %v, %d messages queued", same, st.recvQ.len())
	}
	if st.closeDone.Load() {
		t.Error("a SYN frame on a stream with no CLOSE out settled the stream's CLOSE")
	}
	if got := atomic.LoadUint64(&s.streamRefused); got != 1 {
		t.Errorf("streamRefused = %d, want 1: a SYN frame on a live stream refuses nothing", got)
	}
}

// TestUnknownStream_NoSYNIsDroppedSilently: the flag is what decides it. A DATA frame
// for an unknown stream that lacks aether.FlagSYN creates nothing, which is what leaves
// a stream whose OPEN was lost without a receiver.
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

	// A frame of DATA, as a stream whose OPEN was lost would send.
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
		t.Error("a DATA frame without FlagSYN created an unknown stream")
	}
}
