/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package adapter

import (
	"fmt"
	"sync"
	"time"
)

// Fragment header format (4 bytes):
//   [0x46 0x52]      — magic "FR" (distinguishes from non-fragmented payloads)
//   [index:1]        — fragment position (0-255, supports up to 255 fragments = ~306KB)
//   [total:1]        — total fragment count
//
// The fragmentID is implicit — it's the Aether SeqNo of the first fragment.
// All fragments in a group share contiguous SeqNos, so the receiver can
// group them by (firstSeqNo = seqNo - index).

const (
	fragMagic0     byte = 0x46 // 'F'
	fragMagic1     byte = 0x52 // 'R'
	fragHeaderSize      = 4    // magic(2) + index(1) + total(1)
	fragTimeout         = 10 * time.Second

	// MaxGroupsPerStream caps the number of concurrent fragment groups
	// being reassembled on a single stream. Without this, a peer sending
	// index=0 fragments with never-completing totals would grow the
	// per-stream groups map without bound. Realistic workloads never
	// interleave more than 1-2 fragmented messages on a stream at
	// once; 4 leaves headroom for reasonable reordering scenarios
	// without amplifying per-stream buffer memory.
	MaxGroupsPerStream = 4

	// MaxStreamsInFragBuffer caps how many streams can appear in the
	// fragment buffer at once. Secondary defence against a flood of
	// single-fragment open-and-abandon groups spread across fresh
	// stream IDs.
	MaxStreamsInFragBuffer = 1024

	// DefaultFragBufferMaxBytes caps the total bytes held across all
	// in-progress fragment groups in one FragmentBuffer. Prevents a
	// peer from pinning arbitrary memory by opening many near-complete
	// groups and never sending the final fragment. 512 KB covers any
	// realistic single-message reassembly (max ~306 KB at 1200-byte
	// MSS) with headroom for a couple of overlapping groups.
	DefaultFragBufferMaxBytes int64 = 512 * 1024

	// DefaultFragGroupMaxAge caps how long an incomplete group may
	// linger before being garbage-collected by the next Add call. The
	// per-buffer `timeout` field still overrides this when set, but in
	// the default configuration groups older than this are dropped
	// eagerly to reclaim their bytes.
	DefaultFragGroupMaxAge = 30 * time.Second
)

// SplitPayload splits a large payload into MSS-sized fragments.
// Each fragment carries a 4-byte header: [magic:2][index:1][total:1].
// Returns nil if the payload fits in a single frame (no fragmentation needed).
func SplitPayload(data []byte, maxPayload int) [][]byte {
	if maxPayload <= fragHeaderSize {
		maxPayload = 1200 // safe default
	}
	chunkSize := maxPayload - fragHeaderSize
	if len(data) <= maxPayload {
		return nil // no fragmentation needed
	}

	total := (len(data) + chunkSize - 1) / chunkSize
	if total > 255 {
		total = 255 // cap at 255 fragments (~306KB at 1200 byte chunks)
		data = data[:255*chunkSize]
	}

	fragments := make([][]byte, total)
	for i := 0; i < total; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk := data[start:end]

		frag := make([]byte, fragHeaderSize+len(chunk))
		frag[0] = fragMagic0
		frag[1] = fragMagic1
		frag[2] = byte(i)     // index
		frag[3] = byte(total) // total
		copy(frag[fragHeaderSize:], chunk)
		fragments[i] = frag
	}
	return fragments
}

// IsFragment returns true if the payload starts with the fragment magic.
func IsFragment(data []byte) bool {
	return len(data) >= fragHeaderSize && data[0] == fragMagic0 && data[1] == fragMagic1
}

// ParseFragmentHeader extracts index and total from a fragment payload.
func ParseFragmentHeader(data []byte) (index, total uint8, payload []byte, err error) {
	if len(data) < fragHeaderSize {
		return 0, 0, nil, fmt.Errorf("fragment too short (%d bytes)", len(data))
	}
	if data[0] != fragMagic0 || data[1] != fragMagic1 {
		return 0, 0, nil, fmt.Errorf("fragment magic mismatch")
	}
	return data[2], data[3], data[fragHeaderSize:], nil
}

// FragmentBuffer reassembles fragmented payloads, scoped per-stream so
// concurrent messages on different streams (or interleaved retransmits on
// the same stream) cannot corrupt each other's groups.
//
// Group key = SeqNo of the first fragment (index=0). The reliability layer
// guarantees in-order delivery within a stream, so when an index=0 fragment
// arrives we know its SeqNo identifies a brand-new message; subsequent
// fragments (index > 0) join whichever group is currently being assembled
// on that stream.
//
// Memory bounds: the buffer enforces three independent caps that together
// bound worst-case memory. MaxStreamsInFragBuffer caps the top-level map,
// MaxGroupsPerStream caps the per-stream group map, and
// maxBufferedBytes caps the cumulative bytes held across all groups.
// A group older than groupMaxAge is garbage-collected on the next Add
// call regardless of whether any more fragments arrive for it.
type FragmentBuffer struct {
	mu               sync.Mutex
	streams          map[uint64]*streamFragmentState
	timeout          time.Duration
	maxBufferedBytes int64
	groupMaxAge      time.Duration
	bufferedBytes    int64
}

type streamFragmentState struct {
	groups       map[uint32]*fragmentGroup // SeqNo of first fragment → group
	current      uint32                    // SeqNo of the group being assembled
	hasCurr      bool                      // false until first index=0 arrives
	syntheticSeq uint32                    // monotonic counter used when caller passes seqNo=0
}

type fragmentGroup struct {
	fragments [][]byte
	total     int
	received  int
	created   time.Time
	bytes     int64 // sum of len(fragment) across populated slots
}

// NewFragmentBuffer creates a reassembly buffer with default byte and
// age caps (DefaultFragBufferMaxBytes, DefaultFragGroupMaxAge).
func NewFragmentBuffer() *FragmentBuffer {
	return &FragmentBuffer{
		streams:          make(map[uint64]*streamFragmentState),
		timeout:          fragTimeout,
		maxBufferedBytes: DefaultFragBufferMaxBytes,
		groupMaxAge:      DefaultFragGroupMaxAge,
	}
}

// SetMaxBufferedBytes overrides the cumulative byte cap across all
// in-progress groups. Pass 0 to disable the byte cap (discouraged; the
// frame-count caps alone do not bound payload bytes).
func (fb *FragmentBuffer) SetMaxBufferedBytes(max int64) {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	if max < 0 {
		max = 0
	}
	fb.maxBufferedBytes = max
}

// SetGroupMaxAge overrides the per-group staleness cap. Groups older
// than this are garbage-collected lazily on the next Add. Pass 0 to
// disable age-based pruning (falls back to `timeout` only).
func (fb *FragmentBuffer) SetGroupMaxAge(d time.Duration) {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	if d < 0 {
		d = 0
	}
	fb.groupMaxAge = d
}

// Add processes a fragment and returns the reassembled payload when all
// fragments in the group have arrived. Returns nil if more fragments needed.
//
// streamID + seqNo together identify the fragment uniquely. The first
// fragment of a message (index=0) seeds a new group keyed by its SeqNo;
// subsequent fragments join the current group on the same stream.
func (fb *FragmentBuffer) Add(streamID uint64, seqNo uint32, data []byte) ([]byte, error) {
	index, total, payload, err := ParseFragmentHeader(data)
	if err != nil {
		return nil, err
	}

	fb.mu.Lock()
	defer fb.mu.Unlock()

	ss, ok := fb.streams[streamID]
	if !ok {
		if len(fb.streams) >= MaxStreamsInFragBuffer {
			return nil, fmt.Errorf("fragment buffer: stream cap %d reached", MaxStreamsInFragBuffer)
		}
		ss = &streamFragmentState{groups: make(map[uint32]*fragmentGroup)}
		fb.streams[streamID] = ss
	}

	// Prune expired groups across all streams (cheap; most streams have
	// 0-1 groups). A group is expired when either the legacy `timeout`
	// elapses or the newer `groupMaxAge` cap elapses — whichever is
	// shorter. Reclaiming bytes here is how the buffer recovers when a
	// peer opens lots of near-complete groups and never finishes.
	now := time.Now()
	ageCap := fb.timeout
	if fb.groupMaxAge > 0 && (ageCap == 0 || fb.groupMaxAge < ageCap) {
		ageCap = fb.groupMaxAge
	}
	for sid, st := range fb.streams {
		for k, g := range st.groups {
			if ageCap > 0 && now.Sub(g.created) > ageCap {
				fb.bufferedBytes -= g.bytes
				delete(st.groups, k)
			}
		}
		if len(st.groups) == 0 && sid != streamID {
			// Drop empty per-stream state for inactive streams.
			delete(fb.streams, sid)
		}
	}
	if fb.bufferedBytes < 0 {
		fb.bufferedBytes = 0
	}

	// Per-stream cap check — refuse new-group admission rather than grow
	// unbounded. Existing groups (index > 0 joining their current group)
	// still proceed since they don't add a new map entry.
	if index == 0 && len(ss.groups) >= MaxGroupsPerStream {
		return nil, fmt.Errorf("fragment buffer: stream %d groups cap %d reached", streamID, MaxGroupsPerStream)
	}

	// Byte cap check — reject fragments that would push cumulative
	// buffered bytes past the configured limit. Frames already part of
	// the current group still pay this cost, so a small cap combined
	// with many-fragment messages could starve legitimate senders;
	// operators who hit this should tune maxBufferedBytes upward rather
	// than lowering fragment sizes.
	if fb.maxBufferedBytes > 0 && fb.bufferedBytes+int64(len(payload)) > fb.maxBufferedBytes {
		return nil, fmt.Errorf("fragment buffer: byte cap %d reached (buffered=%d, incoming=%d)",
			fb.maxBufferedBytes, fb.bufferedBytes, len(payload))
	}

	// index=0 → new group. Caller can either supply the originating frame's
	// real SeqNo (preferred — uniquely identifies the message) or pass 0
	// to use a per-stream synthetic counter. Either way, groupKey is unique
	// within the stream.
	var groupKey uint32
	if index == 0 {
		key := seqNo
		if key == 0 {
			ss.syntheticSeq++
			key = ss.syntheticSeq
		}
		ss.current = key
		ss.hasCurr = true
		groupKey = key
	} else {
		if !ss.hasCurr {
			// Out-of-order non-zero fragment with no preceding index=0 — drop.
			return nil, fmt.Errorf("fragment index %d on stream %d with no active group", index, streamID)
		}
		groupKey = ss.current
	}

	group, ok := ss.groups[groupKey]
	if !ok {
		group = &fragmentGroup{
			fragments: make([][]byte, total),
			total:     int(total),
			created:   now,
		}
		ss.groups[groupKey] = group
	}

	if int(index) >= group.total {
		return nil, fmt.Errorf("fragment index %d >= total %d", index, group.total)
	}

	// Track per-group and buffer-wide byte usage. Replacing an existing
	// slot (duplicate fragment) nets to zero; installing a new slot
	// increases both counters by len(payload).
	prevLen := 0
	if group.fragments[index] != nil {
		prevLen = len(group.fragments[index])
	} else {
		group.received++
	}
	group.fragments[index] = payload
	delta := int64(len(payload) - prevLen)
	group.bytes += delta
	fb.bufferedBytes += delta

	if group.received < group.total {
		return nil, nil // more fragments needed
	}

	// All fragments received — reassemble
	totalLen := 0
	for _, f := range group.fragments {
		totalLen += len(f)
	}
	assembled := make([]byte, 0, totalLen)
	for _, f := range group.fragments {
		assembled = append(assembled, f...)
	}
	fb.bufferedBytes -= group.bytes
	if fb.bufferedBytes < 0 {
		fb.bufferedBytes = 0
	}
	delete(ss.groups, groupKey)
	if groupKey == ss.current {
		ss.hasCurr = false
	}

	return assembled, nil
}

// Pending returns the number of incomplete fragment groups across all streams.
func (fb *FragmentBuffer) Pending() int {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	n := 0
	for _, ss := range fb.streams {
		n += len(ss.groups)
	}
	return n
}

// MSSToMaxPayload computes the maximum application payload per fragment
// given the MSS and the Aether + encryption overhead.
func MSSToMaxPayload(mss int) int {
	overhead := 50 + 16 // Aether header + Noise AEAD tag
	maxPayload := mss - overhead
	if maxPayload < 100 {
		maxPayload = 100
	}
	return maxPayload
}

// EncodeFragmentID packs two uint16 values for logging.
func EncodeFragmentID(index, total uint8) uint16 {
	return uint16(index)<<8 | uint16(total)
}

// DecodeFragmentID unpacks.
func DecodeFragmentID(id uint16) (index, total uint8) {
	return uint8(id >> 8), uint8(id & 0xFF)
}
