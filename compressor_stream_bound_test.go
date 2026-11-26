/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package aether

import (
	"bytes"
	"testing"
)

// fullDataFrame is a full DATA frame on streamID with a one-byte payload.
func fullDataFrame(streamID uint64) []byte {
	f := goldenFullFrame
	f.StreamID = streamID
	f.Flags = 0
	f.Payload = []byte{1}
	f.Length = 1
	return EncodeFrameToBytes(&f)
}

// A peer writes full frames under any stream IDs it likes, and the decoder
// records each one's state before the frame is checked. It records no more
// stream entries than its bound, still decodes every frame, and records a new
// stream again once an entry is removed.
func TestADecoderRecordsNoMoreStreamsThanItsBound(t *testing.T) {
	c := NewCompressor()
	c.BoundStreams(3)
	for id := uint64(1); id <= 10; id++ {
		f, _, _, err := ReadNextFrame(bytes.NewReader(fullDataFrame(id)), c)
		if err != nil || f == nil || f.StreamID != id {
			t.Fatalf("stream %d: frame %v, err %v; want the frame decoded", id, f, err)
		}
	}
	if got := c.StreamEntries(); got != 3 {
		t.Fatalf("StreamEntries = %d after 10 stream IDs, want the bound 3", got)
	}
	if c.HasStream(10) {
		t.Fatal("a stream past the bound was recorded")
	}
	c.RemoveStream(1)
	c.RemoveStream(1)
	if got := c.StreamEntries(); got != 2 {
		t.Fatalf("StreamEntries = %d after one removal, want 2", got)
	}
	if _, _, _, err := ReadNextFrame(bytes.NewReader(fullDataFrame(11)), c); err != nil {
		t.Fatal(err)
	}
	if !c.HasStream(11) || c.StreamEntries() != 3 {
		t.Fatalf("a stream under the bound was not recorded: entries %d", c.StreamEntries())
	}

	// With no bound set, the default holds.
	d := NewCompressor()
	for id := uint64(1); id <= DefaultCompressorStreamBound+5; id++ {
		if _, _, _, err := ReadNextFrame(bytes.NewReader(fullDataFrame(id)), d); err != nil {
			t.Fatal(err)
		}
	}
	if got := d.StreamEntries(); got != DefaultCompressorStreamBound {
		t.Fatalf("StreamEntries = %d with no bound set, want DefaultCompressorStreamBound %d", got, DefaultCompressorStreamBound)
	}
}
