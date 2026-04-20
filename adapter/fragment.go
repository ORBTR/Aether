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
	// per-stream groups map without bound.
	MaxGroupsPerStream = 16

	// MaxStreamsInFragBuffer caps how many streams can appear in the
	// fragment buffer at once. Secondary defence against a flood of
	// single-fragment open-and-abandon groups spread across fresh
	// stream IDs.
	MaxStreamsInFragBuffer = 1024
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
// the same stream) cannot corrupt each other's groups. Concern #18.
//
// Group key = SeqNo of the first fragment (index=0). The reliability layer
// guarantees in-order delivery within a stream, so when an index=0 fragment
// arrives we know its SeqNo identifies a brand-new message; subsequent
// fragments (index > 0) join whichever group is currently being assembled
// on that stream.
type FragmentBuffer struct {
	mu      sync.Mutex
	streams map[uint64]*streamFragmentState
	timeout time.Duration
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
}

// NewFragmentBuffer creates a reassembly buffer.
func NewFragmentBuffer() *FragmentBuffer {
	return &FragmentBuffer{
		streams: make(map[uint64]*streamFragmentState),
		timeout: fragTimeout,
	}
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

	// Prune expired groups across all streams (cheap; most streams have 0–1 groups).
	now := time.Now()
	for sid, st := range fb.streams {
		for k, g := range st.groups {
			if now.Sub(g.created) > fb.timeout {
				delete(st.groups, k)
			}
		}
		if len(st.groups) == 0 && sid != streamID {
			// Drop empty per-stream state for inactive streams.
			delete(fb.streams, sid)
		}
	}

	// Per-stream cap check — refuse new-group admission rather than grow
	// unbounded. Existing groups (index > 0 joining their current group)
	// still proceed since they don't add a new map entry.
	if index == 0 && len(ss.groups) >= MaxGroupsPerStream {
		return nil, fmt.Errorf("fragment buffer: stream %d groups cap %d reached", streamID, MaxGroupsPerStream)
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

	if group.fragments[index] == nil {
		group.received++
	}
	group.fragments[index] = payload

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
