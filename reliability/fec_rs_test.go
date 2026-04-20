/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package reliability

import (
	"bytes"
	"testing"

	"github.com/ORBTR/aether"
)

func TestRSEncoderRoundTrip(t *testing.T) {
	enc, err := NewRSEncoder(8, 2)
	if err != nil {
		t.Fatalf("NewRSEncoder: %v", err)
	}
	dec, err := NewRSDecoder(8, 2)
	if err != nil {
		t.Fatalf("NewRSDecoder: %v", err)
	}

	// Generate 8 data shards of varying length so the encoder pads.
	originals := [][]byte{
		[]byte("alpha"),
		[]byte("bravo"),
		[]byte("charlie-1"),
		[]byte("delta-payload-larger"),
		[]byte("echo"),
		[]byte("foxtrot-abc"),
		[]byte("golf-x"),
		[]byte("hotel-y-z"),
	}

	var repairs []*aether.Frame
	for _, p := range originals {
		out := enc.Add(p)
		if out != nil {
			repairs = out
		}
	}
	if len(repairs) != 2 {
		t.Fatalf("expected 2 parity frames, got %d", len(repairs))
	}

	// Receiver gets shards 0,1,3,5,6,7 (6 of 8 data) plus both parity.
	deliveredIdx := []int{0, 1, 3, 5, 6, 7}
	var recovered [][]byte
	for _, i := range deliveredIdx {
		recovered = dec.AddData(0, uint8(i), 10, originals[i])
	}
	// Now feed the parity frames — recovery should complete on the second.
	for _, r := range repairs {
		hdr := aether.DecodeFECHeader(r.Payload[:aether.FECHeaderSize])
		out := dec.AddRepair(hdr, r.Payload[aether.FECHeaderSize:])
		if out != nil {
			recovered = out
		}
	}

	if recovered == nil {
		t.Fatal("recovery did not complete")
	}
	if len(recovered) != 8 {
		t.Fatalf("recovered %d shards, want 8", len(recovered))
	}
	// Shards are padded to maxLen, so check the original prefix matches.
	for i, orig := range originals {
		if !bytes.HasPrefix(recovered[i], orig) {
			t.Errorf("shard %d: got %q, want prefix %q", i, recovered[i], orig)
		}
	}
}

func TestRSDecoderInsufficientShards(t *testing.T) {
	dec, err := NewRSDecoder(4, 2)
	if err != nil {
		t.Fatalf("NewRSDecoder: %v", err)
	}
	// Receive only 2 of 4 data shards + 1 parity → still 1 short of k=4.
	dec.AddData(0, 0, 6, []byte("aaaa"))
	dec.AddData(0, 1, 6, []byte("bbbb"))
	out := dec.AddRepair(aether.FECHeader{GroupID: 0, Index: 4, Total: 6}, []byte{0, 4, 'p', 'p', 'p', 'p'})
	if out != nil {
		t.Errorf("recovered with insufficient shards: %v", out)
	}
}
