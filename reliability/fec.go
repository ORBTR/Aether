/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package reliability

import (
	"math"
	"sync"

	"github.com/ORBTR/aether"
)

// DefaultFECGroupSize is the number of data frames per FEC group.
// With N=4, one repair packet is generated per 4 data packets (25% overhead).
const DefaultFECGroupSize = 4

// FECEncoder generates XOR-based forward error correction repair packets for one
// stream's frames (StreamFEC). For every N data frames, it produces one
// FEC_REPAIR frame containing the XOR of all N payloads and the sequence number,
// length and fragment flag of each. If any single frame in the group is lost, a
// RepairDecoder recovers it from the repair frame + the remaining N-1 frames.
type FECEncoder struct {
	mu        sync.Mutex
	groupSize int                 // N data frames per FEC group
	level     FECLevel            // the code the repair's header names
	groupID   uint32              // current group identifier
	covered   []aether.FECCovered // the frames of the current group
	buffer    [][]byte            // payloads in the current group
	maxLen    int                 // max payload length in current group (for XOR padding)
}

// NewFECEncoder creates an encoder with the specified group size, 2 to
// aether.MaxFECCovered; any other size takes DefaultFECGroupSize. A group size
// of 4 gives 25% overhead.
func NewFECEncoder(groupSize int) *FECEncoder {
	if groupSize < 2 || groupSize > aether.MaxFECCovered {
		groupSize = DefaultFECGroupSize
	}
	return &FECEncoder{
		groupSize: groupSize,
		level:     FECBasicXOR,
		buffer:    make([][]byte, 0, groupSize),
	}
}

// Add records one data frame by its sequence number, payload and fragment flag,
// and returns an FEC_REPAIR frame when the group is complete, nil if more data
// frames are needed. A payload longer than a table entry can state joins no
// group: a repair could not name it, and its retransmit still recovers it. The
// returned Frame has Type=TypeFEC_REPAIR with the header, table and XOR bytes.
func (e *FECEncoder) Add(seq uint32, payload []byte, fragment bool) *aether.Frame {
	e.mu.Lock()
	defer e.mu.Unlock()

	if len(payload) > math.MaxUint16 {
		return nil
	}
	// Copy payload to avoid aliasing
	cp := make([]byte, len(payload))
	copy(cp, payload)
	e.buffer = append(e.buffer, cp)
	e.covered = append(e.covered, aether.FECCovered{SeqNo: seq, Length: uint16(len(cp)), Fragment: fragment})

	if len(cp) > e.maxLen {
		e.maxLen = len(cp)
	}

	if len(e.buffer) < e.groupSize {
		return nil // group not complete
	}
	return e.finishGroupLocked()
}

// Flush forces generation of a repair frame for the current partial group.
// Returns nil if the buffer is empty.
func (e *FECEncoder) Flush() *aether.Frame {
	e.mu.Lock()
	defer e.mu.Unlock()

	if len(e.buffer) == 0 {
		return nil
	}
	return e.finishGroupLocked()
}

// finishGroupLocked XORs the buffered payloads, each zero-padded to maxLen, into
// the repair frame for the group and starts the next group.
func (e *FECEncoder) finishGroupLocked() *aether.Frame {
	xor := make([]byte, e.maxLen)
	for _, payload := range e.buffer {
		for i, b := range payload {
			xor[i] ^= b
		}
	}

	covered := make([]aether.FECCovered, len(e.covered))
	copy(covered, e.covered)
	header := aether.EncodeFECHeader(aether.FECHeader{
		GroupID: e.groupID,
		Index:   uint8(len(e.buffer)), // repair is at index N (after data 0..N-1)
		Total:   uint8(len(e.buffer) + 1),
		Level:   uint8(e.level),
		Covered: covered,
	})
	repairPayload := append(header, xor...)

	e.groupID++
	e.buffer = e.buffer[:0]
	e.covered = e.covered[:0]
	e.maxLen = 0
	return &aether.Frame{
		Type:    aether.TypeFEC_REPAIR,
		Length:  uint32(len(repairPayload)),
		Payload: repairPayload,
	}
}
