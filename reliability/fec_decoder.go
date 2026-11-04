/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package reliability

import (
	"bytes"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/reedsolomon"

	"github.com/ORBTR/aether"
)

// FECRecovered is one DATA frame a RepairDecoder rebuilt. adapter.NoiseSession's
// handleFECRepair and handleData put it through the path a frame from the wire
// takes (admitSequenced): the replay window and the receive window it passes make
// it one delivery, in order, whichever of it and a retransmit of the frame comes
// first.
type FECRecovered struct {
	SeqNo    uint32
	Payload  []byte
	Fragment bool
}

// FECBudget bounds what one stream's RepairDecoder holds: the payloads repairs
// are decoded against and the repairs waiting for more of them. Frames is an entry
// bound and Bytes a byte bound for the stream, Groups the repairs' groups, and
// Shared, when set, counts this decoder's bytes with every other on the session
// against SharedBytes. A frame or repair that does not fit costs only the recovery
// it could have helped: the sender retransmits every frame not acknowledged.
type FECBudget struct {
	Frames      int
	Bytes       int64
	Groups      int
	Shared      *atomic.Int64
	SharedBytes int64
}

// DefaultFECBudget is a stream's budget when its caller states none. 64 frames is
// the reorder depth of the adapter's receive window, several groups of every level
// (XOR 4, interleaved 8, Reed-Solomon 8).
var DefaultFECBudget = FECBudget{Frames: 64, Bytes: 256 * 1024, Groups: 16}

// cachedFrame is one payload a RepairDecoder holds, with its arrival time for
// PruneOlderThan.
type cachedFrame struct {
	seq     uint32
	payload []byte
	at      time.Time
}

// repairGroup is one group's repairs, waiting for enough of its covered frames.
// parity holds them by their index in the group: one for XOR, up to the parity
// count for Reed-Solomon.
type repairGroup struct {
	covered   []aether.FECCovered
	parity    map[uint8][]byte
	shardLen  int
	firstSeen time.Time
}

// RepairDecoder recovers one stream's lost DATA frames from FEC_REPAIR frames that
// name them (StreamFEC). It holds recent payloads by sequence number, so a repair
// finds what it is decoded against whichever arrived first, and a group is decided
// by which of the frames its table names are absent: one absent frame per repair
// of XOR, up to the parity count of Reed-Solomon. Conflicting metadata or bytes
// discard the group and return aether.ErrFECRepairMalformed; nothing conflicting
// is ever delivered. Its state belongs to one stream: the session's readLoop feeds
// it, its reliabilityTick prunes it, and its stream's teardown releases it.
type RepairDecoder struct {
	mu      sync.Mutex
	level   FECLevel
	rs      reedsolomon.Encoder
	k, m    int
	budget  FECBudget
	frames  map[uint32]*cachedFrame
	order   []*cachedFrame
	bytes   int64
	groups  map[uint32]*repairGroup
	evicted uint64
	closed  bool
}

// newRepairDecoder builds the decoder for level. Its budget's zero fields take
// DefaultFECBudget's values.
func newRepairDecoder(level FECLevel, budget FECBudget) (*RepairDecoder, error) {
	if budget.Frames <= 0 {
		budget.Frames = DefaultFECBudget.Frames
	}
	if budget.Bytes <= 0 {
		budget.Bytes = DefaultFECBudget.Bytes
	}
	if budget.Groups <= 0 {
		budget.Groups = DefaultFECBudget.Groups
	}
	d := &RepairDecoder{
		level:  level,
		budget: budget,
		frames: make(map[uint32]*cachedFrame),
		groups: make(map[uint32]*repairGroup),
	}
	if level == FECReedSolomon {
		rs, err := reedsolomon.New(DefaultRSDataShards, DefaultRSParityShards)
		if err != nil {
			return nil, err
		}
		d.rs, d.k, d.m = rs, DefaultRSDataShards, DefaultRSParityShards
	}
	return d, nil
}

// AddData records a received DATA frame's payload and returns the frames it lets
// a held repair rebuild.
func (d *RepairDecoder) AddData(seq uint32, payload []byte) []FECRecovered {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.cacheLocked(seq, payload, true)
	if len(d.groups) == 0 {
		return nil
	}
	return d.recoverAfterLocked(seq)
}

// AddRepair takes one FEC_REPAIR frame's decoded header and repair bytes and
// returns the frames it lets the decoder rebuild. A repair that does not fit this
// stream's level, whose bytes are not as long as the longest frame its table names,
// or that conflicts with a repair already held for its group returns
// aether.ErrFECRepairMalformed, and the group is discarded on a conflict. An exact
// duplicate is harmless.
func (d *RepairDecoder) AddRepair(h aether.FECHeader, repair []byte) ([]FECRecovered, error) {
	if err := d.checkHeader(h, repair); err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, nil
	}
	g, ok := d.groups[h.GroupID]
	if ok {
		if !sameCovered(g.covered, h.Covered) {
			d.evictGroupLocked(h.GroupID, g)
			return nil, fmt.Errorf("%w: group %d names other frames", aether.ErrFECRepairMalformed, h.GroupID)
		}
		if held, dup := g.parity[h.Index]; dup {
			if !bytes.Equal(held, repair) {
				d.evictGroupLocked(h.GroupID, g)
				return nil, fmt.Errorf("%w: group %d repair %d differs", aether.ErrFECRepairMalformed, h.GroupID, h.Index)
			}
			return nil, nil
		}
	}
	if d.allPresentLocked(h.Covered) {
		if ok {
			d.removeGroupLocked(h.GroupID, g)
		}
		return nil, nil
	}
	if !d.makeRepairRoomLocked(int64(len(repair)), ok) {
		return nil, nil
	}
	if !ok {
		g = &repairGroup{
			covered:   append([]aether.FECCovered(nil), h.Covered...),
			parity:    make(map[uint8][]byte),
			shardLen:  len(repair),
			firstSeen: time.Now(),
		}
		d.groups[h.GroupID] = g
	}
	g.parity[h.Index] = append([]byte(nil), repair...)
	d.addBytesLocked(int64(len(repair)))
	out, err := d.tryGroupLocked(h.GroupID, g)
	for _, r := range out {
		out = append(out, d.recoverAfterLocked(r.SeqNo)...)
	}
	return out, err
}

// checkHeader refuses a repair that cannot belong to this stream's code.
func (d *RepairDecoder) checkHeader(h aether.FECHeader, repair []byte) error {
	if FECLevel(h.Level) != d.level {
		return fmt.Errorf("%w: level %d on a stream of level %d", aether.ErrFECRepairMalformed, h.Level, d.level)
	}
	longest := 0
	for _, c := range h.Covered {
		if int(c.Length) > longest {
			longest = int(c.Length)
		}
	}
	if len(repair) != longest {
		return fmt.Errorf("%w: %d repair bytes for a longest frame of %d", aether.ErrFECRepairMalformed, len(repair), longest)
	}
	count := len(h.Covered)
	if d.level == FECReedSolomon {
		if count != d.k || int(h.Total) != d.k+d.m || int(h.Index) < d.k || int(h.Index) >= d.k+d.m {
			return fmt.Errorf("%w: index %d of %d over %d frames", aether.ErrFECRepairMalformed, h.Index, h.Total, count)
		}
		return nil
	}
	if count == 0 || int(h.Index) != count || int(h.Total) != count+1 {
		return fmt.Errorf("%w: index %d of %d over %d frames", aether.ErrFECRepairMalformed, h.Index, h.Total, count)
	}
	return nil
}

// recoverAfterLocked tries every group that names seq, then every group that names
// a frame this recovers, and returns all they rebuild. A group that conflicts is
// dropped and counted there; the DATA frame that exposed it stands on its own.
func (d *RepairDecoder) recoverAfterLocked(seq uint32) []FECRecovered {
	var out []FECRecovered
	work := []uint32{seq}
	for len(work) > 0 {
		next := work[0]
		work = work[1:]
		for id, g := range d.groups {
			if !coversSeq(g.covered, next) {
				continue
			}
			got, _ := d.tryGroupLocked(id, g)
			out = append(out, got...)
			for _, r := range got {
				work = append(work, r.SeqNo)
			}
		}
	}
	return out
}

// tryGroupLocked rebuilds the group's absent frames when its repairs are enough,
// holds it otherwise, and drops it once decided. Each rebuilt payload joins the
// cache, so another group naming it can use it.
func (d *RepairDecoder) tryGroupLocked(id uint32, g *repairGroup) ([]FECRecovered, error) {
	var missing []int
	for i, c := range g.covered {
		held, ok := d.frames[c.SeqNo]
		if !ok {
			missing = append(missing, i)
			continue
		}
		if len(held.payload) != int(c.Length) {
			d.evictGroupLocked(id, g)
			return nil, fmt.Errorf("%w: group %d states %d bytes for frame %d, %d arrived",
				aether.ErrFECRepairMalformed, id, c.Length, c.SeqNo, len(held.payload))
		}
	}
	if len(missing) == 0 {
		d.removeGroupLocked(id, g)
		return nil, nil
	}
	if len(missing) > len(g.parity) {
		return nil, nil
	}
	var rebuilt [][]byte
	if d.level == FECReedSolomon {
		rebuilt = d.reconstructLocked(g, missing)
	} else {
		rebuilt = [][]byte{d.xorLocked(g)}
	}
	if rebuilt == nil {
		d.evictGroupLocked(id, g)
		return nil, fmt.Errorf("%w: group %d does not reconstruct", aether.ErrFECRepairMalformed, id)
	}
	out := make([]FECRecovered, 0, len(missing))
	for n, i := range missing {
		c := g.covered[i]
		// The sender pads a short frame with zeros up to the group's longest, so
		// anything else past the stated length is a repair that is not the XOR or
		// parity of the frames it names.
		if !allZero(rebuilt[n][c.Length:]) {
			d.evictGroupLocked(id, g)
			return nil, fmt.Errorf("%w: group %d frame %d padding", aether.ErrFECRepairMalformed, id, c.SeqNo)
		}
		out = append(out, FECRecovered{SeqNo: c.SeqNo, Payload: rebuilt[n][:c.Length:c.Length], Fragment: c.Fragment})
	}
	d.removeGroupLocked(id, g)
	for _, r := range out {
		d.cacheLocked(r.SeqNo, r.Payload, false)
	}
	return out, nil
}

// xorLocked rebuilds the one frame the group lacks from its repair and the frames
// it holds, each zero-padded to the repair's length.
func (d *RepairDecoder) xorLocked(g *repairGroup) []byte {
	var out []byte
	for _, p := range g.parity {
		out = append([]byte(nil), p...)
	}
	for _, c := range g.covered {
		if held, ok := d.frames[c.SeqNo]; ok {
			for i, b := range held.payload {
				out[i] ^= b
			}
		}
	}
	return out
}

// reconstructLocked rebuilds the frames at the given table positions by
// Reed-Solomon, returning one slice per position, or nil when the shards do not
// reconstruct.
func (d *RepairDecoder) reconstructLocked(g *repairGroup, missing []int) [][]byte {
	shards := make([][]byte, d.k+d.m)
	for i, c := range g.covered {
		if held, ok := d.frames[c.SeqNo]; ok {
			shard := make([]byte, g.shardLen)
			copy(shard, held.payload)
			shards[i] = shard
		}
	}
	for idx, p := range g.parity {
		shards[idx] = append([]byte(nil), p...)
	}
	if err := d.rs.ReconstructData(shards); err != nil {
		return nil
	}
	out := make([][]byte, len(missing))
	for n, i := range missing {
		out[n] = shards[i]
	}
	return out
}

// PruneOlderThan drops what the decoder has held longer than maxAge: repairs'
// groups, which count as evicted (Metrics' FECGroupsEvicted), and cached payloads.
// A slow trickle stays under the count and byte bounds and would otherwise hold
// its memory for the stream's life. The noise adapter's reliabilityTick passes
// twice the session's largest stream SRTT (floor 2 s): after two RTTs the sender's
// retransmit has covered any frame a group could still repair.
func (d *RepairDecoder) PruneOlderThan(maxAge time.Duration) {
	if maxAge <= 0 {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	for id, g := range d.groups {
		if g.firstSeen.Before(cutoff) {
			d.evictGroupLocked(id, g)
		}
	}
	for len(d.order) > 0 && d.order[0].at.Before(cutoff) {
		d.evictFrameLocked()
	}
}

// EvictedCount returns the groups dropped undecided: evicted for room, pruned for
// age or discarded on a conflict. adapter.NoiseSession's Metrics sums it into
// SessionMetrics.FECGroupsEvicted.
func (d *RepairDecoder) EvictedCount() uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.evicted
}

// Release gives back everything the decoder holds and stops it, so a frame a
// stream's teardown races is not cached against the session's budget for good. It
// returns the count EvictedCount held, for the session's total, and leaves that at
// zero, which also makes a second call return zero.
func (d *RepairDecoder) Release() uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	d.addBytesLocked(-d.bytes)
	d.frames, d.order, d.groups = make(map[uint32]*cachedFrame), nil, make(map[uint32]*repairGroup)
	evicted := d.evicted
	d.evicted = 0
	return evicted
}

// cacheLocked holds a payload by sequence number within the budget, evicting the
// oldest payloads for room. A frame already held stays as it arrived. copyIt is
// false for a payload this decoder rebuilt, which it owns.
func (d *RepairDecoder) cacheLocked(seq uint32, payload []byte, copyIt bool) {
	if _, held := d.frames[seq]; held {
		return
	}
	n := int64(len(payload))
	for len(d.order) > 0 && (len(d.order) >= d.budget.Frames || d.bytes+n > d.budget.Bytes || !d.sharedFits(n)) {
		d.evictFrameLocked()
	}
	if n > d.budget.Bytes || !d.sharedFits(n) {
		return
	}
	if copyIt {
		payload = append([]byte(nil), payload...)
	}
	f := &cachedFrame{seq: seq, payload: payload, at: time.Now()}
	d.frames[seq] = f
	d.order = append(d.order, f)
	d.addBytesLocked(n)
}

func (d *RepairDecoder) sharedFits(n int64) bool {
	return d.budget.Shared == nil || d.budget.Shared.Load()+n <= d.budget.SharedBytes
}

func (d *RepairDecoder) evictFrameLocked() {
	f := d.order[0]
	d.order[0] = nil
	d.order = d.order[1:]
	delete(d.frames, f.seq)
	d.addBytesLocked(-int64(len(f.payload)))
}

func (d *RepairDecoder) addBytesLocked(n int64) {
	d.bytes += n
	if d.budget.Shared != nil {
		d.budget.Shared.Add(n)
	}
}

// makeRepairRoomLocked makes room for a repair of n bytes: past the group bound a
// new group evicts the oldest, and past the byte bounds a new group evicts the
// oldest groups and then, as a repair joining a held group does at once, the oldest
// payloads. It reports whether the repair fits.
func (d *RepairDecoder) makeRepairRoomLocked(n int64, joining bool) bool {
	fits := func() bool { return d.bytes+n <= d.budget.Bytes && d.sharedFits(n) }
	for !joining && len(d.groups) > 0 && (len(d.groups) >= d.budget.Groups || !fits()) {
		id, g := d.oldestGroupLocked()
		d.evictGroupLocked(id, g)
	}
	for len(d.order) > 0 && !fits() {
		d.evictFrameLocked()
	}
	return fits()
}

func (d *RepairDecoder) oldestGroupLocked() (uint32, *repairGroup) {
	var (
		oldestID uint32
		oldest   *repairGroup
	)
	for id, g := range d.groups {
		if oldest == nil || g.firstSeen.Before(oldest.firstSeen) {
			oldestID, oldest = id, g
		}
	}
	return oldestID, oldest
}

// removeGroupLocked takes a decided group and its repairs' bytes off the decoder.
func (d *RepairDecoder) removeGroupLocked(id uint32, g *repairGroup) {
	delete(d.groups, id)
	for _, p := range g.parity {
		d.addBytesLocked(-int64(len(p)))
	}
}

// evictGroupLocked drops a group undecided and counts it (EvictedCount).
func (d *RepairDecoder) evictGroupLocked(id uint32, g *repairGroup) {
	d.removeGroupLocked(id, g)
	d.evicted++
}

func (d *RepairDecoder) allPresentLocked(covered []aether.FECCovered) bool {
	for _, c := range covered {
		if _, ok := d.frames[c.SeqNo]; !ok {
			return false
		}
	}
	return true
}

func sameCovered(a, b []aether.FECCovered) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func coversSeq(covered []aether.FECCovered, seq uint32) bool {
	for _, c := range covered {
		if c.SeqNo == seq {
			return true
		}
	}
	return false
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}
