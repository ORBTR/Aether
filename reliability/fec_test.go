/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package reliability

import (
	"bytes"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// fecDecode reads a repair frame's header and bytes the way handleFECRepair does.
func fecDecode(t *testing.T, repair *aether.Frame) (aether.FECHeader, []byte) {
	t.Helper()
	if repair.Type != aether.TypeFEC_REPAIR {
		t.Fatalf("frame type %v, want FEC_REPAIR", repair.Type)
	}
	h, data, err := aether.DecodeFECHeader(repair.Payload)
	if err != nil {
		t.Fatalf("decode repair: %v", err)
	}
	return h, data
}

func xorDecoder(t *testing.T, level FECLevel) *RepairDecoder {
	t.Helper()
	d, err := newRepairDecoder(level, FECBudget{})
	if err != nil {
		t.Fatalf("decoder: %v", err)
	}
	return d
}

// seqPayload is a payload distinct per sequence number, of a length that varies
// with it, so padding and order mistakes show.
func seqPayload(seq uint32) []byte {
	return bytes.Repeat([]byte{byte(seq + 1)}, 40+int(seq%7)*11)
}

func TestFECEncoder_GroupComplete(t *testing.T) {
	enc := NewFECEncoder(4)
	for seq := uint32(10); seq < 13; seq++ {
		if repair := enc.Add(seq, seqPayload(seq), false); repair != nil {
			t.Fatalf("repair before the group is complete at %d", seq)
		}
	}
	repair := enc.Add(13, seqPayload(13), true)
	if repair == nil {
		t.Fatal("no repair at the group's last frame")
	}
	h, data := fecDecode(t, repair)
	if h.GroupID != 0 || h.Index != 4 || h.Total != 5 || h.Level != uint8(FECBasicXOR) {
		t.Fatalf("header %+v", h)
	}
	for i, c := range h.Covered {
		want := uint32(10 + i)
		if c.SeqNo != want || int(c.Length) != len(seqPayload(want)) || c.Fragment != (want == 13) {
			t.Fatalf("covered[%d] = %+v", i, c)
		}
	}
	if len(data) != len(seqPayload(13)) && len(data) != len(seqPayload(12)) && len(data) != len(seqPayload(11)) && len(data) != len(seqPayload(10)) {
		t.Fatalf("repair bytes %d", len(data))
	}
}

func TestFECEncoder_FlushCoversThePartialGroup(t *testing.T) {
	enc := NewFECEncoder(4)
	if enc.Flush() != nil {
		t.Fatal("flush of an empty group gave a repair")
	}
	enc.Add(5, []byte("abc"), false)
	enc.Add(6, []byte("defgh"), false)
	h, data := fecDecode(t, enc.Flush())
	if len(h.Covered) != 2 || h.Index != 2 || h.Total != 3 || len(data) != 5 {
		t.Fatalf("header %+v, %d bytes", h, len(data))
	}
	if enc.Flush() != nil {
		t.Fatal("second flush gave a repair")
	}
}

func TestFECEncoder_GroupIDsAdvance(t *testing.T) {
	enc := NewFECEncoder(2)
	for g := uint32(0); g < 3; g++ {
		enc.Add(g*2, []byte("a"), false)
		h, _ := fecDecode(t, enc.Add(g*2+1, []byte("b"), false))
		if h.GroupID != g {
			t.Fatalf("group %d carries ID %d", g, h.GroupID)
		}
	}
}

// A frame too long for a table entry joins no group: its retransmit recovers it.
func TestFECEncoder_AFrameTheTableCannotStateJoinsNoGroup(t *testing.T) {
	enc := NewFECEncoder(2)
	if repair := enc.Add(0, make([]byte, 65536), false); repair != nil {
		t.Fatal("repair for an oversize frame")
	}
	enc.Add(1, []byte("a"), false)
	h, _ := fecDecode(t, enc.Add(2, []byte("b"), false))
	if h.Covered[0].SeqNo != 1 || h.Covered[1].SeqNo != 2 {
		t.Fatalf("covered %+v", h.Covered)
	}
}

func TestFECRoundTrip_NoLossRecoversNothing(t *testing.T) {
	enc, dec := NewFECEncoder(4), xorDecoder(t, FECBasicXOR)
	var repair *aether.Frame
	for seq := uint32(0); seq < 4; seq++ {
		repair = enc.Add(seq, seqPayload(seq), false)
		if got := dec.AddData(seq, seqPayload(seq)); got != nil {
			t.Fatalf("recovered %+v with nothing lost", got)
		}
	}
	h, data := fecDecode(t, repair)
	if got, err := dec.AddRepair(h, data); err != nil || got != nil {
		t.Fatalf("repair with nothing lost: %+v, %v", got, err)
	}
	if dec.EvictedCount() != 0 {
		t.Fatalf("a group decided with nothing lost counted evicted: %d", dec.EvictedCount())
	}
}

// Every position in the group is recovered, with the payload's own length (the
// padding stripped by the table's entry) and its fragment flag.
func TestFECRoundTrip_SingleLossAnyPosition(t *testing.T) {
	for lost := uint32(0); lost < 4; lost++ {
		enc, dec := NewFECEncoder(4), xorDecoder(t, FECBasicXOR)
		var repair *aether.Frame
		for seq := uint32(0); seq < 4; seq++ {
			repair = enc.Add(seq, seqPayload(seq), seq%2 == 0)
			if seq != lost {
				dec.AddData(seq, seqPayload(seq))
			}
		}
		h, data := fecDecode(t, repair)
		got, err := dec.AddRepair(h, data)
		if err != nil || len(got) != 1 {
			t.Fatalf("lost %d: %+v, %v", lost, got, err)
		}
		if got[0].SeqNo != lost || !bytes.Equal(got[0].Payload, seqPayload(lost)) || got[0].Fragment != (lost%2 == 0) {
			t.Fatalf("lost %d: recovered seq %d, %d bytes, fragment %v", lost, got[0].SeqNo, len(got[0].Payload), got[0].Fragment)
		}
	}
}

// The repair arrives ahead of the frames: the DATA frame that leaves one absent
// recovers it.
func TestFECRoundTrip_RepairAheadOfItsFrames(t *testing.T) {
	enc, dec := NewFECEncoder(4), xorDecoder(t, FECBasicXOR)
	var repair *aether.Frame
	for seq := uint32(0); seq < 4; seq++ {
		repair = enc.Add(seq, seqPayload(seq), false)
	}
	h, data := fecDecode(t, repair)
	if got, err := dec.AddRepair(h, data); err != nil || got != nil {
		t.Fatalf("repair with all frames absent: %+v, %v", got, err)
	}
	dec.AddData(0, seqPayload(0))
	dec.AddData(1, seqPayload(1))
	got := dec.AddData(3, seqPayload(3))
	if len(got) != 1 || got[0].SeqNo != 2 || !bytes.Equal(got[0].Payload, seqPayload(2)) {
		t.Fatalf("recovered %+v", got)
	}
}

func TestFECRoundTrip_TwoLostIsNotRecoveredByXOR(t *testing.T) {
	enc, dec := NewFECEncoder(4), xorDecoder(t, FECBasicXOR)
	var repair *aether.Frame
	for seq := uint32(0); seq < 4; seq++ {
		repair = enc.Add(seq, seqPayload(seq), false)
		if seq > 1 {
			dec.AddData(seq, seqPayload(seq))
		}
	}
	h, data := fecDecode(t, repair)
	if got, err := dec.AddRepair(h, data); err != nil || got != nil {
		t.Fatalf("two lost: %+v, %v", got, err)
	}
}

// A repair names its stream's own sequence numbers, so a repair over a group of one
// is the frame itself, and goes through the receive window like one.
func TestFECRoundTrip_AGroupOfOne(t *testing.T) {
	enc, dec := NewFECEncoder(4), xorDecoder(t, FECBasicXOR)
	enc.Add(9, []byte("alone"), false)
	h, data := fecDecode(t, enc.Flush())
	got, err := dec.AddRepair(h, data)
	if err != nil || len(got) != 1 || got[0].SeqNo != 9 || string(got[0].Payload) != "alone" {
		t.Fatalf("%+v, %v", got, err)
	}
}

func TestRepairDecoder_AnExactDuplicateRepairIsHarmless(t *testing.T) {
	dec := xorDecoder(t, FECBasicXOR)
	h := aether.FECHeader{GroupID: 1, Index: 2, Total: 3, Level: uint8(FECBasicXOR), Covered: []aether.FECCovered{{SeqNo: 0, Length: 1}, {SeqNo: 1, Length: 1}}}
	for i := 0; i < 2; i++ {
		if got, err := dec.AddRepair(h, []byte{7}); err != nil || got != nil {
			t.Fatalf("copy %d: %+v, %v", i, got, err)
		}
	}
	if dec.EvictedCount() != 0 {
		t.Fatalf("evicted %d", dec.EvictedCount())
	}
}

// Conflicting metadata or bytes discard the group, and the frames it would have
// rebuilt are not rebuilt from either version.
func TestRepairDecoder_AConflictDiscardsTheGroup(t *testing.T) {
	base := aether.FECHeader{GroupID: 1, Index: 2, Total: 3, Level: uint8(FECBasicXOR), Covered: []aether.FECCovered{{SeqNo: 0, Length: 1}, {SeqNo: 1, Length: 1}}}
	cases := map[string]func() (aether.FECHeader, []byte){
		"other bytes": func() (aether.FECHeader, []byte) { return base, []byte{8} },
		"other frames": func() (aether.FECHeader, []byte) {
			h := base
			h.Covered = []aether.FECCovered{{SeqNo: 0, Length: 1}, {SeqNo: 2, Length: 1}}
			return h, []byte{7}
		},
	}
	for name, second := range cases {
		t.Run(name, func(t *testing.T) {
			dec := xorDecoder(t, FECBasicXOR)
			if _, err := dec.AddRepair(base, []byte{7}); err != nil {
				t.Fatal(err)
			}
			h, data := second()
			if _, err := dec.AddRepair(h, data); !errors.Is(err, aether.ErrFECRepairMalformed) {
				t.Fatalf("conflict: %v", err)
			}
			if got := dec.AddData(0, []byte{1}); got != nil {
				t.Fatalf("recovered %+v from a discarded group", got)
			}
			if dec.EvictedCount() != 1 {
				t.Fatalf("evicted %d", dec.EvictedCount())
			}
		})
	}
}

func TestRepairDecoder_RefusesARepairThatDoesNotFit(t *testing.T) {
	two := []aether.FECCovered{{SeqNo: 0, Length: 3}, {SeqNo: 1, Length: 2}}
	cases := map[string]struct {
		h    aether.FECHeader
		data []byte
	}{
		"another level": {aether.FECHeader{Index: 2, Total: 3, Level: uint8(FECInterleaved), Covered: two}, []byte{1, 2, 3}},
		"short bytes":   {aether.FECHeader{Index: 2, Total: 3, Level: uint8(FECBasicXOR), Covered: two}, []byte{1, 2}},
		"long bytes":    {aether.FECHeader{Index: 2, Total: 3, Level: uint8(FECBasicXOR), Covered: two}, []byte{1, 2, 3, 4}},
		"index":         {aether.FECHeader{Index: 1, Total: 3, Level: uint8(FECBasicXOR), Covered: two}, []byte{1, 2, 3}},
		"total":         {aether.FECHeader{Index: 2, Total: 4, Level: uint8(FECBasicXOR), Covered: two}, []byte{1, 2, 3}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			dec := xorDecoder(t, FECBasicXOR)
			if _, err := dec.AddRepair(c.h, c.data); !errors.Is(err, aether.ErrFECRepairMalformed) {
				t.Fatalf("got %v", err)
			}
			if len(dec.groups) != 0 || dec.bytes != 0 {
				t.Fatalf("a refused repair left %d groups, %d bytes", len(dec.groups), dec.bytes)
			}
		})
	}
}

// A frame that arrived at another length than the table states, and bytes past the
// stated length of a rebuilt frame that are not the sender's zero padding, are not
// the group the repair names: nothing conflicting is delivered.
func TestRepairDecoder_AGroupThatDoesNotAddUpRecoversNothing(t *testing.T) {
	t.Run("arrived length", func(t *testing.T) {
		dec := xorDecoder(t, FECBasicXOR)
		dec.AddData(0, []byte{1, 2})
		h := aether.FECHeader{Index: 2, Total: 3, Level: uint8(FECBasicXOR), Covered: []aether.FECCovered{{SeqNo: 0, Length: 3}, {SeqNo: 1, Length: 3}}}
		got, err := dec.AddRepair(h, []byte{1, 2, 3})
		if !errors.Is(err, aether.ErrFECRepairMalformed) || got != nil {
			t.Fatalf("%+v, %v", got, err)
		}
	})
	t.Run("padding", func(t *testing.T) {
		dec := xorDecoder(t, FECBasicXOR)
		dec.AddData(0, []byte{1, 2, 3})
		h := aether.FECHeader{Index: 2, Total: 3, Level: uint8(FECBasicXOR), Covered: []aether.FECCovered{{SeqNo: 0, Length: 3}, {SeqNo: 1, Length: 1}}}
		// frame 1 is one byte long, so its rebuilt bytes 1 and 2 must be zero.
		got, err := dec.AddRepair(h, []byte{1 ^ 9, 2 ^ 9, 3})
		if !errors.Is(err, aether.ErrFECRepairMalformed) || got != nil {
			t.Fatalf("%+v, %v", got, err)
		}
	})
}

func TestRepairDecoder_ABudgetHoldsItsFramesBytesAndGroups(t *testing.T) {
	t.Run("frames", func(t *testing.T) {
		dec, _ := newRepairDecoder(FECBasicXOR, FECBudget{Frames: 3})
		for seq := uint32(0); seq < 10; seq++ {
			dec.AddData(seq, []byte{1})
		}
		if len(dec.frames) != 3 || dec.bytes != 3 {
			t.Fatalf("%d frames, %d bytes", len(dec.frames), dec.bytes)
		}
		if _, ok := dec.frames[9]; !ok {
			t.Fatal("the newest frame was evicted")
		}
	})
	t.Run("bytes", func(t *testing.T) {
		dec, _ := newRepairDecoder(FECBasicXOR, FECBudget{Bytes: 100})
		for seq := uint32(0); seq < 10; seq++ {
			dec.AddData(seq, make([]byte, 30))
		}
		if dec.bytes > 100 {
			t.Fatalf("%d bytes held", dec.bytes)
		}
		dec.AddData(99, make([]byte, 101))
		if _, ok := dec.frames[99]; ok {
			t.Fatal("a frame past the whole budget was held")
		}
	})
	t.Run("groups", func(t *testing.T) {
		dec, _ := newRepairDecoder(FECBasicXOR, FECBudget{Groups: 4})
		for id := uint32(0); id < 20; id++ {
			h := aether.FECHeader{GroupID: id, Index: 2, Total: 3, Level: uint8(FECBasicXOR), Covered: []aether.FECCovered{{SeqNo: id * 2, Length: 1}, {SeqNo: id*2 + 1, Length: 1}}}
			if _, err := dec.AddRepair(h, []byte{1}); err != nil {
				t.Fatal(err)
			}
		}
		if len(dec.groups) != 4 || dec.EvictedCount() != 16 {
			t.Fatalf("%d groups, %d evicted", len(dec.groups), dec.EvictedCount())
		}
	})
	t.Run("shared with the session", func(t *testing.T) {
		var shared atomic.Int64
		a, _ := newRepairDecoder(FECBasicXOR, FECBudget{Shared: &shared, SharedBytes: 100})
		b, _ := newRepairDecoder(FECBasicXOR, FECBudget{Shared: &shared, SharedBytes: 100})
		for seq := uint32(0); seq < 8; seq++ {
			a.AddData(seq, make([]byte, 30))
			b.AddData(seq, make([]byte, 30))
		}
		if v := shared.Load(); v > 100 || v != a.bytes+b.bytes {
			t.Fatalf("shared %d, decoders %d and %d", v, a.bytes, b.bytes)
		}
		a.Release()
		b.Release()
		if v := shared.Load(); v != 0 {
			t.Fatalf("shared %d after both released", v)
		}
	})
}

func TestRepairDecoder_PruneOlderThanDropsGroupsAndFrames(t *testing.T) {
	dec := xorDecoder(t, FECBasicXOR)
	dec.AddData(0, []byte{1})
	h := aether.FECHeader{GroupID: 1, Index: 2, Total: 3, Level: uint8(FECBasicXOR), Covered: []aether.FECCovered{{SeqNo: 5, Length: 1}, {SeqNo: 6, Length: 1}}}
	if _, err := dec.AddRepair(h, []byte{1}); err != nil {
		t.Fatal(err)
	}
	dec.PruneOlderThan(time.Hour)
	if len(dec.frames) != 1 || len(dec.groups) != 1 {
		t.Fatalf("pruned young state: %d frames, %d groups", len(dec.frames), len(dec.groups))
	}
	dec.frames[0].at = time.Now().Add(-2 * time.Minute)
	dec.groups[1].firstSeen = time.Now().Add(-2 * time.Minute)
	dec.PruneOlderThan(time.Minute)
	if len(dec.frames) != 0 || len(dec.groups) != 0 || dec.bytes != 0 {
		t.Fatalf("after prune: %d frames, %d groups, %d bytes", len(dec.frames), len(dec.groups), dec.bytes)
	}
	if dec.EvictedCount() != 1 {
		t.Fatalf("evicted %d", dec.EvictedCount())
	}
}

func TestRepairDecoder_ReleaseStopsItAndHandsOverItsCount(t *testing.T) {
	dec, _ := newRepairDecoder(FECBasicXOR, FECBudget{Groups: 1})
	for id := uint32(0); id < 3; id++ {
		h := aether.FECHeader{GroupID: id, Index: 2, Total: 3, Level: uint8(FECBasicXOR), Covered: []aether.FECCovered{{SeqNo: id * 2, Length: 1}, {SeqNo: id*2 + 1, Length: 1}}}
		_, _ = dec.AddRepair(h, []byte{1})
	}
	if n := dec.Release(); n != 2 {
		t.Fatalf("Release returned %d", n)
	}
	if n := dec.Release(); n != 0 {
		t.Fatalf("a second Release returned %d", n)
	}
	dec.AddData(1, []byte{1})
	if dec.bytes != 0 {
		t.Fatalf("a released decoder held %d bytes", dec.bytes)
	}
}

func TestInterleavedFEC_EachSubGroupCoversEveryOtherFrame(t *testing.T) {
	enc := NewInterleavedFECEncoder(4)
	var repairs []*aether.Frame
	for seq := uint32(0); seq < 8; seq++ {
		repairs = append(repairs, enc.Add(seq, seqPayload(seq), false)...)
	}
	if len(repairs) != 2 {
		t.Fatalf("%d repairs for 8 frames", len(repairs))
	}
	seen := map[uint32]bool{}
	for _, r := range repairs {
		h, _ := fecDecode(t, r)
		if h.Level != uint8(FECInterleaved) {
			t.Fatalf("level %d", h.Level)
		}
		if seen[h.GroupID] {
			t.Fatalf("group ID %d used twice", h.GroupID)
		}
		seen[h.GroupID] = true
		for i := 1; i < len(h.Covered); i++ {
			if h.Covered[i].SeqNo != h.Covered[i-1].SeqNo+2 {
				t.Fatalf("covered %+v", h.Covered)
			}
		}
	}
}

func TestInterleavedFEC_FlushCoversBothPartialGroups(t *testing.T) {
	enc := NewInterleavedFECEncoder(4)
	enc.Add(0, []byte("a"), false)
	enc.Add(1, []byte("b"), false)
	enc.Add(2, []byte("c"), false)
	repairs := enc.Flush()
	if len(repairs) != 2 {
		t.Fatalf("%d repairs", len(repairs))
	}
	if enc.Flush() != nil {
		t.Fatal("second flush gave repairs")
	}
}

func TestInterleavedFEC_MinimumGroupSize(t *testing.T) {
	enc := NewInterleavedFECEncoder(0)
	enc.Add(0, []byte("a"), false)
	enc.Add(1, []byte("b"), false)
	if got := enc.Add(2, []byte("c"), false); len(got) != 1 {
		t.Fatalf("%d repairs for sub-group A's second frame", len(got))
	}
}

// Every burst of two consecutive frames falls one in each sub-group, and both come
// back. Three consecutive put two in one sub-group: that one does not, the other
// does.
func TestInterleavedFEC_BurstLoss(t *testing.T) {
	for first := uint32(0); first < 7; first++ {
		enc, dec := NewInterleavedFECEncoder(4), xorDecoder(t, FECInterleaved)
		var repairs []*aether.Frame
		for seq := uint32(0); seq < 8; seq++ {
			repairs = append(repairs, enc.Add(seq, seqPayload(seq), false)...)
			if seq != first && seq != first+1 {
				dec.AddData(seq, seqPayload(seq))
			}
		}
		got := map[uint32][]byte{}
		for _, r := range repairs {
			h, data := fecDecode(t, r)
			rec, err := dec.AddRepair(h, data)
			if err != nil {
				t.Fatal(err)
			}
			for _, x := range rec {
				got[x.SeqNo] = x.Payload
			}
		}
		for _, seq := range []uint32{first, first + 1} {
			if !bytes.Equal(got[seq], seqPayload(seq)) {
				t.Fatalf("burst at %d: frame %d came back as %d bytes", first, seq, len(got[seq]))
			}
		}
	}
	enc, dec := NewInterleavedFECEncoder(4), xorDecoder(t, FECInterleaved)
	var repairs []*aether.Frame
	for seq := uint32(0); seq < 8; seq++ {
		repairs = append(repairs, enc.Add(seq, seqPayload(seq), false)...)
		if seq < 2 || seq > 4 {
			dec.AddData(seq, seqPayload(seq))
		}
	}
	var got []uint32
	for _, r := range repairs {
		h, data := fecDecode(t, r)
		rec, err := dec.AddRepair(h, data)
		if err != nil {
			t.Fatal(err)
		}
		for _, x := range rec {
			got = append(got, x.SeqNo)
		}
	}
	if len(got) != 1 || got[0] != 3 {
		t.Fatalf("three lost: recovered %v, want frame 3, the one alone in its sub-group", got)
	}
}

func rsRound(t *testing.T, lost map[uint32]bool, parityToDeliver int) (map[uint32]FECRecovered, error) {
	t.Helper()
	enc, err := NewRSEncoder(DefaultRSDataShards, DefaultRSParityShards)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := newRepairDecoder(FECReedSolomon, FECBudget{})
	if err != nil {
		t.Fatal(err)
	}
	var repairs []*aether.Frame
	for seq := uint32(20); seq < 28; seq++ {
		repairs = append(repairs, enc.Add(seq, seqPayload(seq), seq == 21)...)
		if !lost[seq] {
			dec.AddData(seq, seqPayload(seq))
		}
	}
	if len(repairs) != DefaultRSParityShards {
		t.Fatalf("%d parity frames", len(repairs))
	}
	got := map[uint32]FECRecovered{}
	for _, r := range repairs[:parityToDeliver] {
		h, data := fecDecode(t, r)
		rec, err := dec.AddRepair(h, data)
		if err != nil {
			return got, err
		}
		for _, x := range rec {
			got[x.SeqNo] = x
		}
	}
	return got, nil
}

func TestRSFEC_RecoversUpToTheParityCount(t *testing.T) {
	for _, lost := range []map[uint32]bool{{20: true}, {21: true, 27: true}, {24: true, 25: true}} {
		name := fmt.Sprint(lost)
		got, err := rsRound(t, lost, DefaultRSParityShards)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(got) != len(lost) {
			t.Fatalf("%s: recovered %d frames", name, len(got))
		}
		for seq := range lost {
			if !bytes.Equal(got[seq].Payload, seqPayload(seq)) || got[seq].Fragment != (seq == 21) {
				t.Fatalf("%s: frame %d: %d bytes, fragment %v", name, seq, len(got[seq].Payload), got[seq].Fragment)
			}
		}
	}
}

func TestRSFEC_NotEnoughShardsRecoversNothing(t *testing.T) {
	got, err := rsRound(t, map[uint32]bool{20: true, 21: true, 22: true}, DefaultRSParityShards)
	if err != nil || len(got) != 0 {
		t.Fatalf("three lost: %+v, %v", got, err)
	}
	got, err = rsRound(t, map[uint32]bool{20: true, 21: true}, 1)
	if err != nil || len(got) != 0 {
		t.Fatalf("one parity for two lost: %+v, %v", got, err)
	}
}

// A malformed parity frame is refused before a group exists for it: its index, its
// total and its count all have to be the code's.
func TestRSFEC_RefusesAMalformedParityFrame(t *testing.T) {
	covered := make([]aether.FECCovered, DefaultRSDataShards)
	for i := range covered {
		covered[i] = aether.FECCovered{SeqNo: uint32(i), Length: 1}
	}
	k, m := uint8(DefaultRSDataShards), uint8(DefaultRSParityShards)
	cases := map[string]aether.FECHeader{
		"index in the data": {Index: 0, Total: k + m, Level: uint8(FECReedSolomon), Covered: covered},
		"index past total":  {Index: k + m, Total: k + m, Level: uint8(FECReedSolomon), Covered: covered},
		"total":             {Index: k, Total: k + m + 1, Level: uint8(FECReedSolomon), Covered: covered},
		"count":             {Index: k, Total: k + m, Level: uint8(FECReedSolomon), Covered: covered[:3]},
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			dec, _ := newRepairDecoder(FECReedSolomon, FECBudget{})
			if _, err := dec.AddRepair(h, []byte{1}); !errors.Is(err, aether.ErrFECRepairMalformed) {
				t.Fatalf("got %v", err)
			}
			if len(dec.groups) != 0 {
				t.Fatal("a refused frame made a group")
			}
		})
	}
}

// A stream's FEC state is its own, and a level outside the registry refuses.
func TestStreamFEC_LevelsAndRegistry(t *testing.T) {
	if f, err := NewStreamFEC(FECNone, FECBudget{}); f != nil || err != nil {
		t.Fatalf("FECNone: %v, %v", f, err)
	}
	if _, err := NewStreamFEC(FECLevel(4), FECBudget{}); !errors.Is(err, aether.ErrFECLevelUnsupported) {
		t.Fatalf("level 4: %v", err)
	}
	if ValidFECLevel(4) || !ValidFECLevel(0) || !ValidFECLevel(3) {
		t.Fatal("registry")
	}
	for _, c := range []struct {
		level   FECLevel
		frames  int
		repairs int
		covered int
	}{{FECBasicXOR, 4, 1, 4}, {FECInterleaved, 8, 2, 4}, {FECReedSolomon, 8, 2, 8}} {
		f, err := NewStreamFEC(c.level, FECBudget{})
		if err != nil {
			t.Fatal(err)
		}
		if f.Level() != c.level || f.MaxCovered() != c.covered {
			t.Fatalf("level %d: %d, covered %d", c.level, f.Level(), f.MaxCovered())
		}
		var repairs int
		for seq := 0; seq < c.frames; seq++ {
			repairs += len(f.Encode(uint32(seq), []byte("payload"), false))
		}
		if repairs != c.repairs {
			t.Fatalf("level %d: %d repairs from %d frames", c.level, repairs, c.frames)
		}
	}
	a, _ := NewStreamFEC(FECBasicXOR, FECBudget{})
	b, _ := NewStreamFEC(FECBasicXOR, FECBudget{})
	for seq := uint32(0); seq < 3; seq++ {
		if a.Encode(seq, []byte("a"), false) != nil {
			t.Fatal("a repair before stream a's group completed")
		}
	}
	if b.Encode(0, []byte("b"), false) != nil {
		t.Fatal("stream b's first frame completed stream a's group")
	}
}
