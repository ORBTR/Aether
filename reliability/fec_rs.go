/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

// Reed-Solomon FEC (Concern #8 — _implementation_plan.md).
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
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/reedsolomon"

	"github.com/ORBTR/aether"
)

// DefaultRSDataShards is the default k for Reed-Solomon FEC.
const DefaultRSDataShards = 8

// DefaultRSParityShards is the default m for Reed-Solomon FEC.
const DefaultRSParityShards = 2

// RSEncoder generates Reed-Solomon parity shards. AddData buffers k data
// frames; once the buffer is full, the encoder produces m parity shards
// wrapped as TypeFEC_REPAIR frames carrying an extended FEC header.
type RSEncoder struct {
	mu      sync.Mutex
	enc     reedsolomon.Encoder
	k       int
	m       int
	groupID uint32
	buffer  [][]byte // accumulates k data frames
	maxLen  int      // max payload length seen in this group (for padding)
}

// NewRSEncoder creates an encoder with k data shards and m parity shards.
// k must be ≥ 1, m ≥ 1, and the underlying RS implementation requires
// k+m ≤ 256.
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

// Add buffers a data frame. Returns the m parity FEC_REPAIR frames once
// k frames are accumulated; nil otherwise.
func (e *RSEncoder) Add(payload []byte) []*aether.Frame {
	e.mu.Lock()
	defer e.mu.Unlock()

	cp := make([]byte, len(payload))
	copy(cp, payload)
	e.buffer = append(e.buffer, cp)
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
	if err := e.enc.Encode(shards); err != nil {
		// Should not happen with valid k/m. Drop the group rather than
		// emit malformed parity.
		e.buffer = e.buffer[:0]
		e.maxLen = 0
		return nil
	}

	groupID := e.groupID
	e.groupID++
	repairs := make([]*aether.Frame, 0, e.m)
	for i := 0; i < e.m; i++ {
		hdr := aether.EncodeFECHeader(aether.FECHeader{
			GroupID: groupID,
			Index:   uint8(e.k + i), // parity indices come after data indices
			Total:   uint8(e.k + e.m),
		})
		// Payload layout: [FEC header (6B)][shardLen:2 BE][parity shard]
		payload := make([]byte, len(hdr)+2+e.maxLen)
		copy(payload, hdr)
		payload[len(hdr)] = byte(e.maxLen >> 8)
		payload[len(hdr)+1] = byte(e.maxLen)
		copy(payload[len(hdr)+2:], shards[e.k+i])
		repairs = append(repairs, &aether.Frame{
			Type:    aether.TypeFEC_REPAIR,
			Length:  uint32(len(payload)),
			Payload: payload,
		})
	}
	e.buffer = e.buffer[:0]
	e.maxLen = 0
	return repairs
}

// RSDecoder reconstructs missing data shards from received data + parity.
type RSDecoder struct {
	mu      sync.Mutex
	enc     reedsolomon.Encoder
	k, m    int
	groups  map[uint32]*rsGroup
	evicted uint64 // atomic
}

type rsGroup struct {
	shards    [][]byte // [k+m]; nil entries are missing
	received  int
	shardLen  int
	firstSeen time.Time // for PruneOlderThan (age-based eviction)
}

// NewRSDecoder creates a decoder mirroring the encoder's k/m configuration.
func NewRSDecoder(dataShards, parityShards int) (*RSDecoder, error) {
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
	return &RSDecoder{
		enc:    enc,
		k:      dataShards,
		m:      parityShards,
		groups: make(map[uint32]*rsGroup),
	}, nil
}

// AddData records a received data shard. Stores the payload as-is; the
// authoritative shardLen is learned from the parity frame and used to
// pad data shards just before Reconstruct.
func (d *RSDecoder) AddData(groupID uint32, index uint8, total uint8, payload []byte) [][]byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	g := d.getOrCreateGroup(groupID, int(total), 0)
	if int(index) >= len(g.shards) {
		return nil
	}
	if g.shards[index] == nil {
		g.received++
	}
	cp := make([]byte, len(payload))
	copy(cp, payload)
	g.shards[index] = cp
	return d.tryRecover(groupID, g)
}

// AddRepair records a received parity shard. Payload layout:
//   [shardLen:2 BE][parity shard bytes]
// (the FEC header has already been stripped by the caller).
func (d *RSDecoder) AddRepair(header aether.FECHeader, payload []byte) [][]byte {
	if len(payload) < 2 {
		return nil
	}
	shardLen := int(payload[0])<<8 | int(payload[1])
	if shardLen <= 0 || shardLen > len(payload)-2 {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	g := d.getOrCreateGroup(header.GroupID, int(header.Total), shardLen)
	if int(header.Index) >= len(g.shards) {
		return nil
	}
	if g.shards[header.Index] == nil {
		g.received++
	}
	cp := make([]byte, shardLen)
	copy(cp, payload[2:2+shardLen])
	g.shards[header.Index] = cp
	return d.tryRecover(header.GroupID, g)
}

// Prune evicts oldest groups when the in-flight count exceeds maxGroups.
func (d *RSDecoder) Prune(maxGroups int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.groups) <= maxGroups {
		return
	}
	ids := make([]uint32, 0, len(d.groups))
	for id := range d.groups {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	toRemove := len(d.groups) - maxGroups
	for i := 0; i < toRemove && i < len(ids); i++ {
		delete(d.groups, ids[i])
		atomic.AddUint64(&d.evicted, 1)
	}
}

// PruneOlderThan drops groups first seen more than maxAge ago. Complements
// count-based Prune (slow trickle of unique GroupIDs can stay under the
// count cap but accumulate memory over time). Plan S2 specifies 2×SRTT.
func (d *RSDecoder) PruneOlderThan(maxAge time.Duration) {
	if maxAge <= 0 {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	for id, g := range d.groups {
		if !g.firstSeen.IsZero() && g.firstSeen.Before(cutoff) {
			delete(d.groups, id)
			atomic.AddUint64(&d.evicted, 1)
		}
	}
}

// EvictedCount returns total groups evicted (by either Prune or PruneOlderThan).
func (d *RSDecoder) EvictedCount() uint64 {
	return atomic.LoadUint64(&d.evicted)
}

func (d *RSDecoder) getOrCreateGroup(groupID uint32, total, shardLen int) *rsGroup {
	g, ok := d.groups[groupID]
	if !ok {
		g = &rsGroup{
			shards:    make([][]byte, total),
			shardLen:  shardLen,
			firstSeen: time.Now(),
		}
		d.groups[groupID] = g
		return g
	}
	// Late update: shardLen is set by the first parity frame; data
	// frames arriving before that pass shardLen=0. Adopt the larger
	// non-zero value.
	if shardLen > g.shardLen {
		g.shardLen = shardLen
	}
	return g
}

// tryRecover attempts reconstruction. Returns the k recovered data shards
// when the group has enough info; nil otherwise. Successful recovery
// removes the group. Data shards are padded to shardLen — the wire format
// stores variable-length data on the regular DATA path, so the decoder
// pads at reconstruct time using the parity frame's authoritative length.
func (d *RSDecoder) tryRecover(groupID uint32, g *rsGroup) [][]byte {
	if g.received < d.k {
		return nil
	}
	// Reconstruct requires a known shardLen — that comes from a parity
	// frame. If we have k data shards but no parity yet, no recovery is
	// needed — but we still don't know the original lengths from the
	// sender (data shards may have padding that the upper layer would
	// have to strip). For the missing-shard case, parity is mandatory.
	if g.shardLen == 0 {
		// Find the longest received data shard as a proxy and proceed —
		// any nil entries can't be reconstructed without parity anyway.
		// If everything is present, just return the data shards as-is.
		allPresent := true
		for i := 0; i < d.k; i++ {
			if g.shards[i] == nil {
				allPresent = false
				break
			}
		}
		if !allPresent {
			return nil // need parity
		}
		out := make([][]byte, d.k)
		for i := 0; i < d.k; i++ {
			out[i] = g.shards[i]
		}
		delete(d.groups, groupID)
		return out
	}

	// Pad data shards to shardLen before Reconstruct.
	for i := 0; i < d.k; i++ {
		if g.shards[i] == nil {
			continue
		}
		if len(g.shards[i]) < g.shardLen {
			padded := make([]byte, g.shardLen)
			copy(padded, g.shards[i])
			g.shards[i] = padded
		} else if len(g.shards[i]) > g.shardLen {
			g.shards[i] = g.shards[i][:g.shardLen]
		}
	}
	if err := d.enc.Reconstruct(g.shards); err != nil {
		return nil
	}
	out := make([][]byte, d.k)
	for i := 0; i < d.k; i++ {
		out[i] = g.shards[i]
	}
	delete(d.groups, groupID)
	return out
}
