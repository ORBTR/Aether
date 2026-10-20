/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ORBTR/aether"
)

// A message larger than one frame's payload travels as fragments: DATA frames
// marked aether.FlagFRAGMENT, each payload one FragmentEnvelope followed by a
// slice of the message. The frame flag, not the payload, says which DATA
// payloads are fragments, so a whole message that begins with any bytes at all
// is delivered as it is. The envelope's version is the session's chosen
// aether.WireVersionFragment entry.
//
// Envelope layout (FragmentEnvelopeSize bytes, big-endian):
//
//	[1  version]          aether.WireVersionFragmentCurrent
//	[4  realm]            network key id of the sending session
//	[8  peer]             the sender's PeerID
//	[8  incarnation]      the sending session's ConnectionID
//	[8  stream ID]
//	[8  stream generation]
//	[8  message ID]
//	[2  index]
//	[2  total]
//	[4  original length]  the whole message's length
//
// The receiver (FragmentBuffer.Add) checks every field against its own session
// and stream before it allocates, and joins only fragments whose session,
// stream generation and message ID all agree.

const (
	// FragmentEnvelopeSize is the encoded size of a FragmentEnvelope.
	FragmentEnvelopeSize = 1 + 4 + 8 + 8 + 8 + 8 + 8 + 2 + 2 + 4

	fragTimeout = 10 * time.Second

	// MaxFragments is the ceiling on fragments per message the sender splits
	// into and the receiver admits. It also bounds the per-group slot slice
	// FragmentBuffer.Add allocates from a fragment's total, so a peer's total
	// field cannot size an allocation past it.
	MaxFragments = 255

	// MaxGroupsPerStream caps the number of concurrent fragment groups
	// being reassembled on a single stream. Without this, a peer sending
	// first fragments with never-completing totals would grow the
	// per-stream groups map without bound. Concurrent Sends on one stream
	// interleave at most a few messages; 4 leaves headroom for that
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
	// groups and never sending the final fragment.
	DefaultFragBufferMaxBytes int64 = 512 * 1024

	// MaxFragmentedMessageSize is the largest message a session splits into
	// fragments and the largest original length a receiver admits. It equals
	// DefaultFragBufferMaxBytes because a message larger than the buffer that
	// reassembles it could never complete.
	MaxFragmentedMessageSize = int(DefaultFragBufferMaxBytes)

	// DefaultFragGroupMaxAge caps how long an incomplete group may
	// linger before being garbage-collected by the next Add call. The
	// per-buffer `timeout` field still overrides this when set, but in
	// the default configuration groups older than this are dropped
	// eagerly to reclaim their bytes.
	DefaultFragGroupMaxAge = 30 * time.Second

	// fragmentIDWindow is how many message IDs below the highest one a stream
	// has seen remain admissible for a new group. Interleaved sends on one
	// stream open their groups in near message-ID order, so a window this wide
	// admits every legitimate one while refusing an ID that opened a group
	// already, completed or discarded.
	fragmentIDWindow = 64
)

// ErrPayloadTooLarge is returned by SplitMessage (and surfaced by a stream's
// Send) when a payload cannot be represented within MaxFragments fragments at
// the current frame payload size, or is larger than MaxFragmentedMessageSize.
// Callers must chunk at the application layer or fail loudly — the alternative
// (silent tail truncation) corrupts the message with no error on either end.
var ErrPayloadTooLarge = errors.New("aether: payload exceeds maximum fragment count")

// ErrFragmentRefused is the sentinel every fragment refusal matches through
// errors.Is: the sender's SplitMessage and the receiver's FragmentBuffer.Add
// both return a *FragmentError naming the reason.
var ErrFragmentRefused = errors.New("aether: fragment refused")

// FragmentRefusal names why a fragment was not sent or not joined.
type FragmentRefusal string

const (
	// FragmentNotNegotiated: the session chose no fragment envelope version
	// this build writes and reads.
	FragmentNotNegotiated FragmentRefusal = "fragment envelope not negotiated"
	// FragmentNoRealm: the session is bound to no network key, so a fragment
	// would carry no realm.
	FragmentNoRealm FragmentRefusal = "session has no realm"
	FragmentVersion FragmentRefusal = "unsupported envelope version"
	// FragmentTruncated: fewer bytes than one envelope.
	FragmentTruncated   FragmentRefusal = "truncated envelope"
	FragmentRealm       FragmentRefusal = "realm does not match the session"
	FragmentPeer        FragmentRefusal = "peer does not match the session"
	FragmentStream      FragmentRefusal = "stream ID does not match the stream"
	FragmentIncarnation FragmentRefusal = "session incarnation does not match"
	FragmentGeneration  FragmentRefusal = "stream generation is zero or older than the stream's"
	// FragmentMessageID: zero, or an ID that already opened a group on this
	// stream generation.
	FragmentMessageID FragmentRefusal = "message ID zero or reused"
	FragmentTotal     FragmentRefusal = "total zero or impossible"
	FragmentIndex     FragmentRefusal = "index not below total"
	FragmentLength    FragmentRefusal = "length zero or past a ceiling"
	// FragmentConflict: a fragment disagreeing with the live group of its
	// message ID (metadata, or different bytes at an index already held);
	// the group is discarded.
	FragmentConflict FragmentRefusal = "conflicts with the message's live group"
	// FragmentCapacity: a stream, group or byte bound of the buffer.
	FragmentCapacity FragmentRefusal = "reassembly bound reached"
)

// FragmentError is a refused fragment: the reason and a detail naming the
// values compared.
type FragmentError struct {
	Reason FragmentRefusal
	Detail string
}

func (e *FragmentError) Error() string {
	if e.Detail == "" {
		return fmt.Sprintf("%v: %s", ErrFragmentRefused, e.Reason)
	}
	return fmt.Sprintf("%v: %s (%s)", ErrFragmentRefused, e.Reason, e.Detail)
}

// Is lets errors.Is(err, ErrFragmentRefused) match a *FragmentError.
func (e *FragmentError) Is(target error) bool { return target == ErrFragmentRefused }

func refuse(reason FragmentRefusal, format string, args ...interface{}) error {
	return &FragmentError{Reason: reason, Detail: fmt.Sprintf(format, args...)}
}

// FragmentEnvelope is the header of one fragment (layout above).
type FragmentEnvelope struct {
	Version uint8
	// Realm is the mesh realm the sending session's identity binds it to:
	// the network key id, the CRC32 fingerprint (crypto/identity CRC32Hash) of
	// the network key its Noise prologue bound, which noiseConn reports
	// through NetworkKeyID. A session bound to no network key has no realm
	// and neither sends nor admits fragments.
	Realm          uint32
	Peer           aether.PeerID
	Incarnation    aether.ConnectionID
	StreamID       uint64
	Generation     uint64
	MessageID      uint64
	Index          uint16
	Total          uint16
	OriginalLength uint32
}

// Append writes e's encoding onto dst.
func (e FragmentEnvelope) Append(dst []byte) []byte {
	dst = append(dst, e.Version)
	dst = binary.BigEndian.AppendUint32(dst, e.Realm)
	dst = append(dst, e.Peer[:]...)
	dst = append(dst, e.Incarnation[:]...)
	dst = binary.BigEndian.AppendUint64(dst, e.StreamID)
	dst = binary.BigEndian.AppendUint64(dst, e.Generation)
	dst = binary.BigEndian.AppendUint64(dst, e.MessageID)
	dst = binary.BigEndian.AppendUint16(dst, e.Index)
	dst = binary.BigEndian.AppendUint16(dst, e.Total)
	dst = binary.BigEndian.AppendUint32(dst, e.OriginalLength)
	return dst
}

// ParseFragment splits a fragment payload into its envelope and its slice of
// the message. It refuses a version other than aether.WireVersionFragmentCurrent
// after reading only the version byte, and a payload shorter than one envelope.
// It checks no field against a session; FragmentBuffer.Add does.
func ParseFragment(b []byte) (FragmentEnvelope, []byte, error) {
	if len(b) == 0 {
		return FragmentEnvelope{}, nil, refuse(FragmentTruncated, "empty payload")
	}
	if uint16(b[0]) != aether.WireVersionFragmentCurrent {
		return FragmentEnvelope{}, nil, refuse(FragmentVersion, "version %d, this build reads %d", b[0], aether.WireVersionFragmentCurrent)
	}
	if len(b) < FragmentEnvelopeSize {
		return FragmentEnvelope{}, nil, refuse(FragmentTruncated, "%d bytes, envelope is %d", len(b), FragmentEnvelopeSize)
	}
	var e FragmentEnvelope
	e.Version = b[0]
	e.Realm = binary.BigEndian.Uint32(b[1:5])
	copy(e.Peer[:], b[5:13])
	copy(e.Incarnation[:], b[13:21])
	e.StreamID = binary.BigEndian.Uint64(b[21:29])
	e.Generation = binary.BigEndian.Uint64(b[29:37])
	e.MessageID = binary.BigEndian.Uint64(b[37:45])
	e.Index = binary.BigEndian.Uint16(b[45:47])
	e.Total = binary.BigEndian.Uint16(b[47:49])
	e.OriginalLength = binary.BigEndian.Uint32(b[49:53])
	return e, b[FragmentEnvelopeSize:], nil
}

// FragmentBinding is what one sending stream stamps on its fragments.
// NoiseSession and TCPSession build it from the session (chosen fragment
// version, network key, own PeerID, ConnectionID) and the stream (ID,
// generation).
type FragmentBinding struct {
	// Version is the session's chosen aether.WireVersionFragment version, 0
	// when it chose none.
	Version     uint16
	Realm       uint32
	RealmBound  bool
	Peer        aether.PeerID
	Incarnation aether.ConnectionID
	StreamID    uint64
	Generation  uint64
}

// SplitMessage returns the fragment payloads that carry data in frames of at
// most maxPayload bytes, each to be sent as a DATA frame flagged
// aether.FlagFRAGMENT, or (nil, nil) when data fits one frame and travels whole
// in an unflagged frame. messageID is the stream's next message ID, non-zero.
// It refuses a binding without a negotiated envelope or a realm, a zero message
// ID or generation (typed *FragmentError), and a message past MaxFragments
// fragments or MaxFragmentedMessageSize bytes (ErrPayloadTooLarge), before it
// allocates any fragment.
func SplitMessage(b FragmentBinding, messageID uint64, data []byte, maxPayload int) ([][]byte, error) {
	if len(data) <= maxPayload {
		return nil, nil
	}
	if b.Version != aether.WireVersionFragmentCurrent {
		return nil, refuse(FragmentNotNegotiated, "session chose fragment version %d, this build writes %d", b.Version, aether.WireVersionFragmentCurrent)
	}
	if !b.RealmBound {
		return nil, refuse(FragmentNoRealm, "a %d-byte message needs fragments", len(data))
	}
	if messageID == 0 {
		return nil, refuse(FragmentMessageID, "message ID 0")
	}
	if b.Generation == 0 {
		return nil, refuse(FragmentGeneration, "stream generation 0")
	}
	if maxPayload <= FragmentEnvelopeSize {
		return nil, fmt.Errorf("%w: frame payload %d leaves no room past the %d-byte envelope",
			ErrPayloadTooLarge, maxPayload, FragmentEnvelopeSize)
	}
	if len(data) > MaxFragmentedMessageSize {
		return nil, fmt.Errorf("%w: %d bytes, the fragmented-message ceiling is %d",
			ErrPayloadTooLarge, len(data), MaxFragmentedMessageSize)
	}
	chunkSize := maxPayload - FragmentEnvelopeSize
	total := (len(data) + chunkSize - 1) / chunkSize
	if total > MaxFragments {
		return nil, fmt.Errorf("%w: %d bytes needs %d fragments at %d-byte chunks (max %d)",
			ErrPayloadTooLarge, len(data), total, chunkSize, MaxFragments)
	}
	env := FragmentEnvelope{
		Version:        uint8(b.Version),
		Realm:          b.Realm,
		Peer:           b.Peer,
		Incarnation:    b.Incarnation,
		StreamID:       b.StreamID,
		Generation:     b.Generation,
		MessageID:      messageID,
		Total:          uint16(total),
		OriginalLength: uint32(len(data)),
	}
	fragments := make([][]byte, total)
	for i := 0; i < total; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(data) {
			end = len(data)
		}
		env.Index = uint16(i)
		frag := make([]byte, 0, FragmentEnvelopeSize+end-start)
		frag = env.Append(frag)
		fragments[i] = append(frag, data[start:end]...)
	}
	return fragments, nil
}

// FragmentReceiver is what every fragment one session receives must match:
// the session's chosen envelope version, its realm, the remote PeerID, and one
// sending incarnation, which the first admitted fragment pins (the peer's
// ConnectionID is not exchanged before data flows). NoiseSession and
// TCPSession hold one per session and pass it to each stream's FragmentBuffer.
type FragmentReceiver struct {
	version    uint16
	realm      uint32
	realmBound bool
	peer       aether.PeerID

	mu          sync.Mutex
	incarnation aether.ConnectionID
	pinned      bool
}

// NewFragmentReceiver returns the receiver side of a session: version is the
// chosen aether.WireVersionFragment version (0 when none was chosen), realm
// and realmBound the session's network key, peer the remote PeerID.
func NewFragmentReceiver(version uint16, realm uint32, realmBound bool, peer aether.PeerID) *FragmentReceiver {
	return &FragmentReceiver{version: version, realm: realm, realmBound: realmBound, peer: peer}
}

// checkSession refuses an envelope that does not belong to r's session. The
// incarnation is checked by pinIncarnation once every other field passed, so a
// malformed fragment pins nothing.
func (r *FragmentReceiver) checkSession(e FragmentEnvelope) error {
	if r == nil || r.version != aether.WireVersionFragmentCurrent {
		v := uint16(0)
		if r != nil {
			v = r.version
		}
		return refuse(FragmentNotNegotiated, "session chose fragment version %d", v)
	}
	if !r.realmBound {
		return refuse(FragmentNoRealm, "fragment names realm %08x", e.Realm)
	}
	if e.Realm != r.realm {
		return refuse(FragmentRealm, "fragment %08x, session %08x", e.Realm, r.realm)
	}
	if e.Peer != r.peer {
		return refuse(FragmentPeer, "fragment %x, session peer %x", e.Peer[:], r.peer[:])
	}
	return nil
}

func (r *FragmentReceiver) pinIncarnation(inc aether.ConnectionID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.pinned {
		r.incarnation, r.pinned = inc, true
		return nil
	}
	if inc != r.incarnation {
		return refuse(FragmentIncarnation, "fragment %x, session pinned %x", inc[:], r.incarnation[:])
	}
	return nil
}

// FragmentBuffer reassembles fragmented messages, scoped per stream, and
// within a stream per stream generation and message ID, so fragments of
// different messages, sessions or stream generations never join.
//
// Memory bounds: MaxStreamsInFragBuffer caps the per-stream map,
// MaxGroupsPerStream the per-stream group map, MaxFragments each group's slot
// slice, and maxBufferedBytes the bytes held across all groups. A group older
// than groupMaxAge is garbage-collected on the next Add call regardless of
// whether any more fragments arrive for it.
type FragmentBuffer struct {
	mu               sync.Mutex
	streams          map[uint64]*streamFragmentState
	timeout          time.Duration
	maxBufferedBytes int64
	groupMaxAge      time.Duration
	bufferedBytes    int64
}

// streamFragmentState is one stream's reassembly state: the sending stream
// generation it follows, its live groups by message ID, and the window of
// message IDs that already opened a group (top and the opened bitmap, bit i
// for top-i).
type streamFragmentState struct {
	generation uint64
	groups     map[uint64]*fragmentGroup
	top        uint64
	opened     uint64
}

type fragmentGroup struct {
	fragments      [][]byte
	total          int
	originalLength uint32
	received       int
	created        time.Time
	bytes          int64 // sum of len(fragment) across populated slots
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

// Add takes one fragment payload (a DATA frame flagged aether.FlagFRAGMENT)
// arriving on streamID of r's session. It returns the whole message once every
// fragment of its group has arrived, and nil while more are needed.
//
// released is the number of message bytes this call took out of reassembly
// without delivering them: the refused or duplicate fragment's slice and every
// group it discarded. The sender charged its flow-control windows for those
// bytes as part of their message, so the session grants them back at once;
// the bytes of a delivered message are granted when the application reads it.
//
// Every check runs before any allocation: the envelope against r's session and
// streamID, the version, total, index, original length and message ID against
// their bounds, then the stream generation and the buffer's caps.
func (fb *FragmentBuffer) Add(r *FragmentReceiver, streamID uint64, data []byte) (assembled []byte, released int64, err error) {
	env, chunk, err := ParseFragment(data)
	if err != nil {
		if n := len(data) - FragmentEnvelopeSize; n > 0 {
			released = int64(n)
		}
		return nil, released, err
	}
	released = int64(len(chunk))
	if err := r.checkSession(env); err != nil {
		return nil, released, err
	}
	if env.StreamID != streamID {
		return nil, released, refuse(FragmentStream, "fragment %d, stream %d", env.StreamID, streamID)
	}
	if err := fb.checkBounds(env, chunk); err != nil {
		return nil, released, err
	}
	if err := r.pinIncarnation(env.Incarnation); err != nil {
		return nil, released, err
	}

	fb.mu.Lock()
	defer fb.mu.Unlock()

	ss, ok := fb.streams[streamID]
	if !ok {
		if len(fb.streams) >= MaxStreamsInFragBuffer {
			return nil, released, refuse(FragmentCapacity, "stream cap %d", MaxStreamsInFragBuffer)
		}
		ss = &streamFragmentState{groups: make(map[uint64]*fragmentGroup)}
		fb.streams[streamID] = ss
	}

	// The sending stream's generation only rises: a fragment of an older
	// generation is a leftover of a stream that ended, and a newer one means
	// that stream ended, so its unfinished groups and ID window go.
	switch {
	case env.Generation < ss.generation:
		return nil, released, refuse(FragmentGeneration, "fragment %d, stream follows %d", env.Generation, ss.generation)
	case env.Generation > ss.generation:
		for id, g := range ss.groups {
			released += fb.discardLocked(ss, id, g)
		}
		ss.generation, ss.top, ss.opened = env.Generation, 0, 0
	}

	released += fb.pruneLocked(time.Now())

	group, live := ss.groups[env.MessageID]
	if live {
		if group.total != int(env.Total) || group.originalLength != env.OriginalLength {
			released += fb.discardLocked(ss, env.MessageID, group)
			return nil, released, refuse(FragmentConflict, "message %d: total %d length %d, group has total %d length %d",
				env.MessageID, env.Total, env.OriginalLength, group.total, group.originalLength)
		}
		if held := group.fragments[env.Index]; held != nil {
			if bytes.Equal(held, chunk) {
				return nil, released, nil // exact duplicate: harmless
			}
			released += fb.discardLocked(ss, env.MessageID, group)
			return nil, released, refuse(FragmentConflict, "message %d index %d: different bytes", env.MessageID, env.Index)
		}
	} else {
		if len(ss.groups) >= MaxGroupsPerStream {
			return nil, released, refuse(FragmentCapacity, "stream %d groups cap %d", streamID, MaxGroupsPerStream)
		}
		if !ss.openID(env.MessageID) {
			return nil, released, refuse(FragmentMessageID, "message %d already opened a group on generation %d", env.MessageID, env.Generation)
		}
		group = &fragmentGroup{
			fragments:      make([][]byte, env.Total),
			total:          int(env.Total),
			originalLength: env.OriginalLength,
			created:        time.Now(),
		}
		ss.groups[env.MessageID] = group
	}

	n := int64(len(chunk))
	if group.bytes+n > int64(group.originalLength) {
		released += fb.discardLocked(ss, env.MessageID, group)
		return nil, released, refuse(FragmentConflict, "message %d: fragments exceed original length %d", env.MessageID, group.originalLength)
	}
	if fb.maxBufferedBytes > 0 && fb.bufferedBytes+n > fb.maxBufferedBytes {
		// The group cannot complete without this fragment, which no reliable
		// stream sends again, so it goes with it.
		released += fb.discardLocked(ss, env.MessageID, group)
		return nil, released, refuse(FragmentCapacity, "byte cap %d (buffered %d, incoming %d)", fb.maxBufferedBytes, fb.bufferedBytes, n)
	}
	group.fragments[env.Index] = chunk
	group.received++
	group.bytes += n
	fb.bufferedBytes += n
	released -= n

	if group.received < group.total {
		return nil, released, nil
	}
	if group.bytes != int64(group.originalLength) {
		released += fb.discardLocked(ss, env.MessageID, group)
		return nil, released, refuse(FragmentConflict, "message %d: %d bytes arrived, original length %d", env.MessageID, group.bytes, group.originalLength)
	}
	assembled = make([]byte, 0, group.originalLength)
	for _, f := range group.fragments {
		assembled = append(assembled, f...)
	}
	fb.bufferedBytes -= group.bytes
	delete(ss.groups, env.MessageID)
	return assembled, released, nil
}

// checkBounds refuses an envelope whose counts or lengths no message this
// buffer could reassemble has, before any state is touched.
func (fb *FragmentBuffer) checkBounds(e FragmentEnvelope, chunk []byte) error {
	if e.Generation == 0 {
		return refuse(FragmentGeneration, "generation 0")
	}
	if e.MessageID == 0 {
		return refuse(FragmentMessageID, "message ID 0")
	}
	if e.Total == 0 || e.Total > MaxFragments {
		return refuse(FragmentTotal, "total %d, admitted 1-%d", e.Total, MaxFragments)
	}
	if e.Index >= e.Total {
		return refuse(FragmentIndex, "index %d, total %d", e.Index, e.Total)
	}
	fb.mu.Lock()
	byteCap := fb.maxBufferedBytes
	fb.mu.Unlock()
	if e.OriginalLength == 0 || e.OriginalLength > uint32(MaxFragmentedMessageSize) ||
		(byteCap > 0 && int64(e.OriginalLength) > byteCap) {
		return refuse(FragmentLength, "original length %d, ceiling %d, buffer cap %d", e.OriginalLength, MaxFragmentedMessageSize, byteCap)
	}
	if uint32(e.Total) > e.OriginalLength {
		return refuse(FragmentTotal, "total %d exceeds original length %d", e.Total, e.OriginalLength)
	}
	if len(chunk) == 0 || uint32(len(chunk)) > e.OriginalLength {
		return refuse(FragmentLength, "fragment carries %d bytes of a %d-byte message", len(chunk), e.OriginalLength)
	}
	return nil
}

// openID admits id as a new group's message ID: above the highest seen, or
// within fragmentIDWindow below it and not yet opened. It records id as opened.
func (ss *streamFragmentState) openID(id uint64) bool {
	if id > ss.top {
		shift := id - ss.top
		if shift >= fragmentIDWindow {
			ss.opened = 1
		} else {
			ss.opened = ss.opened<<shift | 1
		}
		ss.top = id
		return true
	}
	d := ss.top - id
	if d >= fragmentIDWindow {
		return false
	}
	bit := uint64(1) << d
	if ss.opened&bit != 0 {
		return false
	}
	ss.opened |= bit
	return true
}

// discardLocked removes a group and returns its buffered bytes. Its message ID
// stays opened, so a later fragment of it is refused rather than starting a
// group that can never complete.
func (fb *FragmentBuffer) discardLocked(ss *streamFragmentState, id uint64, g *fragmentGroup) int64 {
	delete(ss.groups, id)
	fb.bufferedBytes -= g.bytes
	if fb.bufferedBytes < 0 {
		fb.bufferedBytes = 0
	}
	return g.bytes
}

// pruneLocked drops every group older than the shorter of timeout and
// groupMaxAge, across all streams, and returns the bytes it dropped.
func (fb *FragmentBuffer) pruneLocked(now time.Time) int64 {
	ageCap := fb.timeout
	if fb.groupMaxAge > 0 && (ageCap == 0 || fb.groupMaxAge < ageCap) {
		ageCap = fb.groupMaxAge
	}
	if ageCap <= 0 {
		return 0
	}
	var dropped int64
	for _, st := range fb.streams {
		for id, g := range st.groups {
			if now.Sub(g.created) > ageCap {
				dropped += fb.discardLocked(st, id, g)
			}
		}
	}
	return dropped
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

// BufferedBytes returns the message bytes held across incomplete groups.
func (fb *FragmentBuffer) BufferedBytes() int64 {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	return fb.bufferedBytes
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
