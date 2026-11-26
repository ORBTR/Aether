/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package reliability

import (
	"encoding/binary"
	"sync"

	"github.com/ORBTR/aether"
)

// FECLevel defines the forward error correction level.
type FECLevel uint8

const (
	FECNone        FECLevel = 0 // No FEC
	FECBasicXOR    FECLevel = 1 // XOR, group=4, recovers 1 loss (25% overhead)
	FECInterleaved FECLevel = 2 // Interleaved XOR: 2 offset groups, recovers burst of 2 (50% overhead)
	FECReedSolomon FECLevel = 3 // Reed-Solomon RS(k,m): recovers up to m losses per group
)

// InterleavedFECEncoder generates interleaved XOR-based FEC repair packets.
// Two XOR groups are interleaved by offset:
//   - Group A: frames [0, 2, 4, 6] → repair A
//   - Group B: frames [1, 3, 5, 7] → repair B
//
// Losing 2 consecutive frames (e.g., 3, 4) puts each in a different group,
// making both recoverable. This handles burst loss of up to 2 consecutive packets.
type InterleavedFECEncoder struct {
	mu     sync.Mutex
	groupA *FECEncoder // even-indexed frames
	groupB *FECEncoder // odd-indexed frames
	index  int         // tracks frame position (0-based)
}

// NewInterleavedFECEncoder creates an interleaved FEC encoder.
// groupSize is per sub-group (total group = 2 * groupSize).
func NewInterleavedFECEncoder(groupSize int) *InterleavedFECEncoder {
	if groupSize < 2 {
		groupSize = 2
	}
	a, b := NewFECEncoder(groupSize), NewFECEncoder(groupSize)
	a.level, b.level = FECInterleaved, FECInterleaved
	return &InterleavedFECEncoder{groupA: a, groupB: b}
}

// Add records one data frame and returns FEC repair frames when sub-groups
// complete. May return 0, 1, or 2 repair frames.
//
// Repair frames embed a sub-group tag in the GroupID's low bit: both
// sub-encoders count their groups from 0, and a RepairDecoder keys a stream's
// groups by GroupID, so without the tag a repair of one sub-group would be taken
// for a conflicting repair of the other.
func (e *InterleavedFECEncoder) Add(seq uint32, payload []byte, fragment bool) []*aether.Frame {
	e.mu.Lock()
	defer e.mu.Unlock()

	var repairs []*aether.Frame

	if e.index%2 == 0 {
		// Even index → group A (even GroupID tag)
		if repair := e.groupA.Add(seq, payload, fragment); repair != nil {
			repairs = append(repairs, tagRepair(repair, 0))
		}
	} else {
		// Odd index → group B (odd GroupID tag)
		if repair := e.groupB.Add(seq, payload, fragment); repair != nil {
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

// tagRepair rewrites the FEC repair frame's GroupID, the header's first four
// bytes, so its low bit identifies the interleave sub-group (0 = A, 1 = B). The
// original groupID is shifted up, preserving per-sub-group uniqueness.
func tagRepair(repair *aether.Frame, subGroup uint32) *aether.Frame {
	if repair == nil || len(repair.Payload) < aether.FECHeaderSize {
		return repair
	}
	id := binary.BigEndian.Uint32(repair.Payload[:4])
	binary.BigEndian.PutUint32(repair.Payload[:4], (id<<1)|(subGroup&0x1))
	return repair
}
