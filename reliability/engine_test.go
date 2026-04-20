/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package reliability

import (
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

func newTestEngine() *Engine {
	return NewEngine(EngineConfig{
		StreamID:    1,
		Reliability: aether.ReliableOrdered,
		WindowSize:  64,
	})
}

func TestEngine_SendAssignsSeqNo(t *testing.T) {
	eng := newTestEngine()
	frame := &aether.Frame{StreamID: 1, Type: aether.TypeDATA, Payload: []byte("hello")}

	seq := eng.Send(frame)
	if seq != 0 {
		t.Errorf("first SeqNo: got %d, want 0", seq)
	}
	if frame.SeqNo != 0 {
		t.Errorf("frame.SeqNo: got %d, want 0", frame.SeqNo)
	}

	frame2 := &aether.Frame{StreamID: 1, Type: aether.TypeDATA, Payload: []byte("world")}
	seq2 := eng.Send(frame2)
	if seq2 != 1 {
		t.Errorf("second SeqNo: got %d, want 1", seq2)
	}
}

func TestEngine_ReceiveInOrder(t *testing.T) {
	eng := newTestEngine()

	delivered := eng.Receive(0, []byte("first"), false)
	if len(delivered) != 1 || string(delivered[0]) != "first" {
		t.Fatalf("expected 1 delivery, got %d", len(delivered))
	}

	delivered = eng.Receive(1, []byte("second"), false)
	if len(delivered) != 1 || string(delivered[0]) != "second" {
		t.Fatalf("expected 1 delivery, got %d", len(delivered))
	}
}

func TestEngine_ReceiveOutOfOrder(t *testing.T) {
	eng := newTestEngine()

	// Receive SeqNo 1 first (out of order)
	delivered := eng.Receive(1, []byte("second"), false)
	if len(delivered) != 0 {
		t.Fatalf("out-of-order should not deliver: got %d", len(delivered))
	}

	// Now receive SeqNo 0 — should deliver both
	delivered = eng.Receive(0, []byte("first"), false)
	if len(delivered) != 2 {
		t.Fatalf("expected 2 deliveries (flush), got %d", len(delivered))
	}
	if string(delivered[0]) != "first" {
		t.Errorf("first delivery: got %q, want 'first'", delivered[0])
	}
	if string(delivered[1]) != "second" {
		t.Errorf("second delivery: got %q, want 'second'", delivered[1])
	}
}

func TestEngine_ProcessACK(t *testing.T) {
	eng := newTestEngine()

	frame := &aether.Frame{StreamID: 1, Type: aether.TypeDATA, Payload: []byte("test"), Length: 4}
	eng.Send(frame)

	// Small delay to get a measurable RTT
	time.Sleep(5 * time.Millisecond)

	rtt, ackedBytes := eng.ProcessACK(0, nil)
	if rtt <= 0 {
		t.Error("expected positive RTT sample")
	}
	if ackedBytes <= 0 {
		t.Error("expected positive acked bytes")
	}
}

func TestEngine_GenerateSACKInfo(t *testing.T) {
	eng := newTestEngine()

	// Receive 0, skip 1, receive 2
	eng.Receive(0, []byte("a"), false)
	eng.Receive(2, []byte("c"), false)

	expected, blocks := eng.GenerateSACKInfo()
	if expected != 1 {
		t.Errorf("expected SeqNo: got %d, want 1", expected)
	}
	if len(blocks) != 1 {
		t.Fatalf("expected 1 SACK block, got %d", len(blocks))
	}
	if blocks[0].Start != 2 || blocks[0].End != 2 {
		t.Errorf("SACK block: got [%d,%d], want [2,2]", blocks[0].Start, blocks[0].End)
	}
}

func TestEngine_AntiReplay(t *testing.T) {
	eng := newTestEngine()

	// First receive should work
	delivered := eng.Receive(5, []byte("data"), true)
	if len(delivered) == 0 {
		t.Log("out-of-order, buffered (expected)")
	}

	// Replay should be rejected
	delivered = eng.Receive(5, []byte("data"), true)
	if len(delivered) != 0 {
		t.Fatal("replayed frame should be rejected")
	}
}

func TestEngine_SRTT(t *testing.T) {
	eng := newTestEngine()
	// Before any samples, SRTT should be 0
	if eng.SRTT() != 0 {
		t.Errorf("initial SRTT: got %v, want 0", eng.SRTT())
	}
}
