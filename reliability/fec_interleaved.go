/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package reliability

import (
	"sync"
	"time"

	"github.com/ORBTR/aether"
)

// FECLevel defines the forward error correction level.
type FECLevel uint8

const (
	FECNone        FECLevel = 0 // No FEC
	FECBasicXOR    FECLevel = 1 // XOR, group=4, recovers 1 loss (25% overhead)
	FECInterleaved FECLevel = 2 // Interleaved XOR: 2 offset groups, recovers burst of 2 (50% overhead)
	FECReedSolomon FECLevel = 3 // Reed-Solomon RS(k,m): recovers up to m losses per group (Concern #8)
)

// InterleavedFECEncoder generates interleaved XOR-based FEC repair packets.
// Two XOR groups are interleaved by offset:
//   - Group A: frames [0, 2, 4, 6] → repair A
//   - Group B: frames [1, 3, 5, 7] → repair B
//
// Losing 2 consecutive frames (e.g., 3, 4) puts each in a different group,
// making both recoverable. This handles burst loss of up to 2 consecutive packets.
type InterleavedFECEncoder struct {
	mu       sync.Mutex
	groupA   *FECEncoder // even-indexed frames
	groupB   *FECEncoder // odd-indexed frames
	index    int         // tracks frame position (0-based)
}

// NewInterleavedFECEncoder creates an interleaved FEC encoder.
// groupSize is per sub-group (total group = 2 * groupSize).
func NewInterleavedFECEncoder(groupSize int) *InterleavedFECEncoder {
	if groupSize < 2 {
		groupSize = 2
	}
	return &InterleavedFECEncoder{
		groupA: NewFECEncoder(groupSize),
		groupB: NewFECEncoder(groupSize),
	}
}

// Add records a data payload and returns FEC repair frames when sub-groups complete.
// May return 0, 1, or 2 repair frames.
//
// Repair frames embed a sub-group tag in the GroupID's low bit so the decoder
// can route them: even GroupID → sub-group A, odd GroupID → sub-group B.
// Without this tag, both sub-encoders start at groupID 0 and collisions make
// routing impossible.
func (e *InterleavedFECEncoder) Add(payload []byte) []*aether.Frame {
	e.mu.Lock()
	defer e.mu.Unlock()

	var repairs []*aether.Frame

	if e.index%2 == 0 {
		// Even index → group A (even GroupID tag)
		if repair := e.groupA.Add(payload); repair != nil {
			repairs = append(repairs, tagRepair(repair, 0))
		}
	} else {
		// Odd index → group B (odd GroupID tag)
		if repair := e.groupB.Add(payload); repair != nil {
			repairs = append(repairs, tagRepair(repair, 1))
		}
	}

	e.index++
	return repairs
}

// Flush forces generation of repair frames for any partial sub-groups.
func (e *InterleavedFECEncoder) Flush() []*aether.Frame {
	e.mu.Lock()
	defer e.mu.Unlock()

	var repairs []*aether.Frame
	if repair := e.groupA.Flush(); repair != nil {
		repairs = append(repairs, tagRepair(repair, 0))
	}
	if repair := e.groupB.Flush(); repair != nil {
		repairs = append(repairs, tagRepair(repair, 1))
	}
	return repairs
}

// tagRepair rewrites the FEC repair frame's GroupID so its low bit identifies
// the interleave sub-group (0 = A, 1 = B). The original groupID is shifted up,
// preserving per-sub-group uniqueness.
func tagRepair(repair *aether.Frame, subGroup uint32) *aether.Frame {
	if repair == nil || len(repair.Payload) < aether.FECHeaderSize {
		return repair
	}
	hdr := aether.DecodeFECHeader(repair.Payload[:aether.FECHeaderSize])
	hdr.GroupID = (hdr.GroupID << 1) | (subGroup & 0x1)
	tagged := aether.EncodeFECHeader(hdr)
	copy(repair.Payload[:aether.FECHeaderSize], tagged)
	return repair
}

// InterleavedFECDecoder recovers data from interleaved FEC repair packets.
// Uses two independent FECDecoder instances — one per interleave group.
// Since even-indexed frames go to group A and odd to group B, a burst loss of
// 2 consecutive frames puts each in a different group, making both recoverable.
type InterleavedFECDecoder struct {
	mu     sync.Mutex
	groupA *FECDecoder
	groupB *FECDecoder
}

// NewInterleavedFECDecoder creates an interleaved FEC decoder.
func NewInterleavedFECDecoder() *InterleavedFECDecoder {
	return &InterleavedFECDecoder{
		groupA: NewFECDecoder(),
		groupB: NewFECDecoder(),
	}
}

// AddData records a received data frame for potential FEC recovery.
// `index` is the global frame position (even → sub-group A, odd → sub-group B).
// `groupID` is the sub-encoder's group counter (the un-tagged value, matching
// the original encoder side); the decoder shifts it into tagged space to keep
// alignment with repair frames.
func (d *InterleavedFECDecoder) AddData(index int, groupID uint32, seqInGroup uint8, groupSize uint8, payload []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if index%2 == 0 {
		taggedID := (groupID << 1) | 0
		d.groupA.AddData(taggedID, seqInGroup, groupSize, payload)
	} else {
		taggedID := (groupID << 1) | 1
		d.groupB.AddData(taggedID, seqInGroup, groupSize, payload)
	}
}

// AddRepair processes a FEC repair frame and attempts recovery.
// The repair's tagged GroupID low bit identifies the sub-group.
// Returns recovered data if exactly one frame was missing, nil otherwise.
func (d *InterleavedFECDecoder) AddRepair(header aether.FECHeader, repairData []byte) []byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	if header.GroupID&0x1 == 0 {
		return d.groupA.AddRepair(header, repairData)
	}
	return d.groupB.AddRepair(header, repairData)
}

// Prune removes old groups from both sub-decoders.
func (d *InterleavedFECDecoder) Prune(maxGroups int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.groupA.Prune(maxGroups)
	d.groupB.Prune(maxGroups)
}

// PruneOlderThan drops groups first seen more than maxAge ago from both
// sub-decoders. See FECDecoder.PruneOlderThan for the S2 rationale.
func (d *InterleavedFECDecoder) PruneOlderThan(maxAge time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.groupA.PruneOlderThan(maxAge)
	d.groupB.PruneOlderThan(maxAge)
}

// EvictedCount returns total groups evicted by either sub-decoder.
func (d *InterleavedFECDecoder) EvictedCount() uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.groupA.EvictedCount() + d.groupB.EvictedCount()
}
