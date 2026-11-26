/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package reliability

import (
	"fmt"
	"time"

	"github.com/ORBTR/aether"
)

// ValidFECLevel reports whether level is in the registry a stream may run. An
// OPEN stating any other is refused (adapter.NoiseSession's handleOpen), and
// OpenStream refuses it from a caller, so an unknown level is never read as no FEC.
func ValidFECLevel(level uint8) bool {
	switch FECLevel(level) {
	case FECNone, FECBasicXOR, FECInterleaved, FECReedSolomon:
		return true
	}
	return false
}

// StreamFEC is one stream's FEC state: the encoder of its level and the decoder
// of what its peer sends at that level. A stream owns its own, so no group,
// counter or failure state of one stream reaches another, and a repair's table
// names sequence numbers in that stream's space. adapter.NoiseSession's createStream
// builds it for a stream whose level is not FECNone on a session with FEC enabled.
type StreamFEC struct {
	level       FECLevel
	xor         *FECEncoder
	interleaved *InterleavedFECEncoder
	rs          *RSEncoder
	dec         *RepairDecoder
}

// NewStreamFEC builds the state of a stream at level, with the decoder under
// budget. It returns nil for FECNone, and aether.ErrFECLevelUnsupported for a
// level outside the registry.
func NewStreamFEC(level FECLevel, budget FECBudget) (*StreamFEC, error) {
	if !ValidFECLevel(uint8(level)) {
		return nil, fmt.Errorf("%w: %d", aether.ErrFECLevelUnsupported, level)
	}
	if level == FECNone {
		return nil, nil
	}
	dec, err := newRepairDecoder(level, budget)
	if err != nil {
		return nil, err
	}
	f := &StreamFEC{level: level, dec: dec}
	switch level {
	case FECInterleaved:
		f.interleaved = NewInterleavedFECEncoder(DefaultFECGroupSize)
	case FECReedSolomon:
		if f.rs, err = NewRSEncoder(DefaultRSDataShards, DefaultRSParityShards); err != nil {
			return nil, err
		}
	default:
		f.xor = NewFECEncoder(DefaultFECGroupSize)
	}
	return f, nil
}

// Level returns the stream's level. OpenStream states it in OPEN.
func (f *StreamFEC) Level() FECLevel { return f.level }

// MaxCovered is the most frames one of this stream's repairs covers, what
// noiseStream.Send's room for the repair's table (aether.FECRepairOverhead) is
// computed from.
func (f *StreamFEC) MaxCovered() int {
	if f.level == FECReedSolomon {
		return DefaultRSDataShards
	}
	return DefaultFECGroupSize
}

// Encode takes one DATA frame the stream is sending, by the sequence number its
// send window gave it, and returns the repair frames it completes.
func (f *StreamFEC) Encode(seq uint32, payload []byte, fragment bool) []*aether.Frame {
	switch f.level {
	case FECInterleaved:
		return f.interleaved.Add(seq, payload, fragment)
	case FECReedSolomon:
		return f.rs.Add(seq, payload, fragment)
	}
	if repair := f.xor.Add(seq, payload, fragment); repair != nil {
		return []*aether.Frame{repair}
	}
	return nil
}

// AddData records a received DATA frame (RepairDecoder.AddData).
func (f *StreamFEC) AddData(seq uint32, payload []byte) []FECRecovered {
	return f.dec.AddData(seq, payload)
}

// AddRepair takes a received repair (RepairDecoder.AddRepair).
func (f *StreamFEC) AddRepair(h aether.FECHeader, repair []byte) ([]FECRecovered, error) {
	return f.dec.AddRepair(h, repair)
}

// PruneOlderThan bounds what the decoder holds by age (RepairDecoder.PruneOlderThan).
func (f *StreamFEC) PruneOlderThan(maxAge time.Duration) { f.dec.PruneOlderThan(maxAge) }

// EvictedCount returns the decoder's undecided groups dropped (RepairDecoder.EvictedCount).
func (f *StreamFEC) EvictedCount() uint64 { return f.dec.EvictedCount() }

// Release gives back what the decoder holds and returns its evicted count
// (RepairDecoder.Release). A stream's teardown calls it.
func (f *StreamFEC) Release() uint64 { return f.dec.Release() }
