/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */

// Reed-Solomon FEC.
//
// RS(k, n) encodes k data shards into n total shards (n-k parity shards).
// Any k of n shards can reconstruct the originals — meaning up to (n-k)
// losses per group are recoverable. Compare with the basic XOR encoder
// (recovers 1 loss per group) and interleaved XOR (recovers 2 burst losses).
//
// Default config: RS(8, 2) → 8 data + 2 parity = 25% overhead, recovers
// any 2 losses per group. Same overhead as basic XOR but more capable.
package reliability

import (
	"math"
	"sync"

	"github.com/klauspost/reedsolomon"

	"github.com/ORBTR/aether"
)

// DefaultRSDataShards is the default k for Reed-Solomon FEC.
const DefaultRSDataShards = 8

// DefaultRSParityShards is the default m for Reed-Solomon FEC.
const DefaultRSParityShards = 2

// RSEncoder generates Reed-Solomon parity shards for one stream's frames
// (StreamFEC). Add buffers k data frames; once the buffer is full, the encoder
// produces m parity shards wrapped as TypeFEC_REPAIR frames, each naming the k
// frames in its table.
type RSEncoder struct {
	mu      sync.Mutex
	enc     reedsolomon.Encoder
	k       int
	m       int
	groupID uint32
	covered []aether.FECCovered // the frames of the current group
	buffer  [][]byte            // accumulates k data frames
	maxLen  int                 // max payload length seen in this group (for padding)
}

// NewRSEncoder creates an encoder with k data shards and m parity shards.
// k must be ≥ 1, m ≥ 1, and the underlying RS implementation requires
// k+m ≤ 256. Zero or negative counts take the defaults.
func NewRSEncoder(dataShards, parityShards int) (*RSEncoder, error) {
	if dataShards <= 0 {
		dataShards = DefaultRSDataShards
	}
	if parityShards <= 0 {
		parityShards = DefaultRSParityShards
	}
	enc, err := reedsolomon.New(dataShards, parityShards)
	if err != nil {
		return nil, err
	}
	return &RSEncoder{
		enc:    enc,
		k:      dataShards,
		m:      parityShards,
		buffer: make([][]byte, 0, dataShards),
	}, nil
}

// Add buffers one data frame by its sequence number, payload and fragment flag.
// It returns the m parity FEC_REPAIR frames once k frames are accumulated, nil
// otherwise. A payload longer than a table entry can state joins no group: a
// repair could not name it, and its retransmit still recovers it.
func (e *RSEncoder) Add(seq uint32, payload []byte, fragment bool) []*aether.Frame {
	e.mu.Lock()
	defer e.mu.Unlock()

	if len(payload) > math.MaxUint16 {
		return nil
	}
	cp := make([]byte, len(payload))
	copy(cp, payload)
	e.buffer = append(e.buffer, cp)
	e.covered = append(e.covered, aether.FECCovered{SeqNo: seq, Length: uint16(len(cp)), Fragment: fragment})
	if len(payload) > e.maxLen {
		e.maxLen = len(payload)
	}
	if len(e.buffer) < e.k {
		return nil
	}

	// Pad all data shards to maxLen so RS can operate on equal-sized shards.
	shards := make([][]byte, e.k+e.m)
	for i := 0; i < e.k; i++ {
		shard := make([]byte, e.maxLen)
		copy(shard, e.buffer[i])
		shards[i] = shard
	}
	for i := e.k; i < e.k+e.m; i++ {
		shards[i] = make([]byte, e.maxLen)
	}
	covered := make([]aether.FECCovered, len(e.covered))
	copy(covered, e.covered)
	maxLen := e.maxLen
	e.buffer = e.buffer[:0]
	e.covered = e.covered[:0]
	e.maxLen = 0
	if maxLen == 0 {
		// Every frame is empty, so there is nothing a parity shard could carry
		// and nothing a loss would lose but the frame, whose retransmit recovers it.
		return nil
	}
	if err := e.enc.Encode(shards); err != nil {
		// Should not happen with valid k/m. Drop the group rather than
		// emit malformed parity.
		return nil
	}

	groupID := e.groupID
	e.groupID++
	repairs := make([]*aether.Frame, 0, e.m)
	for i := 0; i < e.m; i++ {
		header := aether.EncodeFECHeader(aether.FECHeader{
			GroupID: groupID,
			Index:   uint8(e.k + i), // parity indices come after data indices
			Total:   uint8(e.k + e.m),
			Level:   uint8(FECReedSolomon),
			Covered: covered,
		})
		payload := append(header, shards[e.k+i]...)
		repairs = append(repairs, &aether.Frame{
			Type:    aether.TypeFEC_REPAIR,
			Length:  uint32(len(payload)),
			Payload: payload,
		})
	}
	return repairs
}
