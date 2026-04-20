/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package reliability

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ORBTR/aether"
)

// DefaultFECGroupSize is the number of data frames per FEC group.
// With N=4, one repair packet is generated per 4 data packets (25% overhead).
const DefaultFECGroupSize = 4

// FECEncoder generates XOR-based forward error correction repair packets.
// For every N data frames, it produces one FEC_REPAIR frame containing the
// XOR of all N payloads. If any single frame in the group is lost, it can
// be recovered from the repair frame + the remaining N-1 frames.
type FECEncoder struct {
	mu        sync.Mutex
	groupSize int      // N data frames per FEC group
	groupID   uint32   // current group identifier
	buffer    [][]byte // payloads in the current group
	maxLen    int      // max payload length in current group (for XOR padding)
}

// NewFECEncoder creates an encoder with the specified group size.
// groupSize must be >= 2. A group size of 4 gives 25% overhead.
func NewFECEncoder(groupSize int) *FECEncoder {
	if groupSize < 2 {
		groupSize = DefaultFECGroupSize
	}
	return &FECEncoder{
		groupSize: groupSize,
		buffer:    make([][]byte, 0, groupSize),
	}
}

// Add records a data payload and returns an FEC_REPAIR frame when the group is complete.
// Returns nil if more data frames are needed to complete the group.
// The returned Frame has Type=TypeFEC_REPAIR with the XOR repair payload.
func (e *FECEncoder) Add(payload []byte) *aether.Frame {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Copy payload to avoid aliasing
	cp := make([]byte, len(payload))
	copy(cp, payload)
	e.buffer = append(e.buffer, cp)

	if len(cp) > e.maxLen {
		e.maxLen = len(cp)
	}

	if len(e.buffer) < e.groupSize {
		return nil // group not complete
	}

	// Group complete — generate repair frame
	repair := e.generateRepair()
	e.groupID++
	e.buffer = e.buffer[:0]
	e.maxLen = 0
	return repair
}

// Flush forces generation of a repair frame for the current partial group.
// Returns nil if the buffer is empty.
func (e *FECEncoder) Flush() *aether.Frame {
	e.mu.Lock()
	defer e.mu.Unlock()

	if len(e.buffer) == 0 {
		return nil
	}

	repair := e.generateRepair()
	e.groupID++
	e.buffer = e.buffer[:0]
	e.maxLen = 0
	return repair
}

// generateRepair XORs all buffered payloads to produce the repair data.
// Shorter payloads are zero-padded to maxLen before XOR.
func (e *FECEncoder) generateRepair() *aether.Frame {
	xor := make([]byte, e.maxLen)
	for _, payload := range e.buffer {
		for i, b := range payload {
			xor[i] ^= b
		}
	}

	fecHeader := aether.EncodeFECHeader(aether.FECHeader{
		GroupID: e.groupID,
		Index:   uint8(len(e.buffer)), // repair is at index N (after data 0..N-1)
		Total:   uint8(len(e.buffer) + 1),
	})

	repairPayload := append(fecHeader, xor...)

	return &aether.Frame{
		Type:    aether.TypeFEC_REPAIR,
		Length:  uint32(len(repairPayload)),
		Payload: repairPayload,
	}
}

// FECDecoder recovers lost frames using XOR-based FEC repair packets.
// When a repair packet arrives and exactly one data frame from its group is
// missing, the missing frame is recovered by XORing the repair with all
// received frames.
type FECDecoder struct {
	mu      sync.Mutex
	groups  map[uint32]*fecGroup
	evicted uint64 // atomic: total groups evicted by Prune / PruneOlderThan
}

type fecGroup struct {
	total     int               // total frames in group (data + repair)
	received  map[uint8][]byte  // index → payload
	repair    []byte            // XOR repair payload (nil until received)
	firstSeen time.Time         // when the first frame of this group arrived (for age-based eviction — S2)
}

// NewFECDecoder creates a decoder.
func NewFECDecoder() *FECDecoder {
	return &FECDecoder{
		groups: make(map[uint32]*fecGroup),
	}
}

// AddData records a received data frame in its FEC group.
// index is the frame's position (0-based) within the group.
// Returns a recovered payload if the addition completes recovery, nil otherwise.
func (d *FECDecoder) AddData(groupID uint32, index uint8, total uint8, payload []byte) []byte {
	d.mu.Lock()
	defer d.mu.Unlock()

	g := d.getOrCreateGroup(groupID, int(total))
	cp := make([]byte, len(payload))
	copy(cp, payload)
	g.received[index] = cp

	return d.tryRecover(groupID, g)
}

// AddRepair records a received FEC_REPAIR frame.
// Returns a recovered payload if the repair completes recovery, nil otherwise.
func (d *FECDecoder) AddRepair(header aether.FECHeader, repairPayload []byte) []byte {
	d.mu.Lock()
	defer d.mu.Unlock()

	g := d.getOrCreateGroup(header.GroupID, int(header.Total))
	cp := make([]byte, len(repairPayload))
	copy(cp, repairPayload)
	g.repair = cp

	return d.tryRecover(header.GroupID, g)
}

// Prune removes completed or stale groups to prevent unbounded memory growth.
// Call periodically (e.g., every 10 seconds).
// Evicts the lowest groupIDs first (deterministic, oldest-first).
func (d *FECDecoder) Prune(maxGroups int) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(d.groups) <= maxGroups {
		return
	}

	// Collect and sort group IDs for deterministic eviction (lowest = oldest)
	ids := make([]uint32, 0, len(d.groups))
	for id := range d.groups {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	// Evict from the front (oldest) until within budget
	toRemove := len(d.groups) - maxGroups
	for i := 0; i < toRemove && i < len(ids); i++ {
		delete(d.groups, ids[i])
		atomic.AddUint64(&d.evicted, 1)
	}
}

// PruneOlderThan removes groups first seen more than maxAge ago. Complements
// count-based Prune for S2: a slow trickle of FEC_REPAIR frames with unique
// GroupIDs can stay under the count cap but still accumulate memory over
// time. Plan S2 specifies 2×SRTT as the right age bound.
func (d *FECDecoder) PruneOlderThan(maxAge time.Duration) {
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

// EvictedCount returns the total number of groups pruned (count-based or
// age-based) over the decoder's lifetime. Observability hook for S2.
func (d *FECDecoder) EvictedCount() uint64 {
	return atomic.LoadUint64(&d.evicted)
}

func (d *FECDecoder) getOrCreateGroup(groupID uint32, total int) *fecGroup {
	g, ok := d.groups[groupID]
	if !ok {
		g = &fecGroup{
			total:     total,
			received:  make(map[uint8][]byte),
			firstSeen: time.Now(),
		}
		d.groups[groupID] = g
	}
	return g
}

// tryRecover attempts to recover a missing frame using XOR.
// Returns the recovered payload if exactly one data frame is missing and
// the repair frame is available. Otherwise returns nil.
func (d *FECDecoder) tryRecover(groupID uint32, g *fecGroup) []byte {
	if g.repair == nil {
		return nil // no repair frame yet
	}

	dataCount := g.total - 1 // total includes repair
	if len(g.received) >= dataCount {
		// All data frames received — no recovery needed
		delete(d.groups, groupID)
		return nil
	}

	if len(g.received) < dataCount-1 {
		return nil // more than one frame missing — can't recover with XOR
	}

	// Exactly one frame missing — recover it
	var missingIndex uint8
	for i := uint8(0); i < uint8(dataCount); i++ {
		if _, ok := g.received[i]; !ok {
			missingIndex = i
			break
		}
	}

	// XOR the repair with all received data frames
	recovered := make([]byte, len(g.repair))
	copy(recovered, g.repair)
	for _, payload := range g.received {
		for i := 0; i < len(payload) && i < len(recovered); i++ {
			recovered[i] ^= payload[i]
		}
	}

	// Store recovered frame and clean up
	g.received[missingIndex] = recovered
	delete(d.groups, groupID)

	return recovered
}
