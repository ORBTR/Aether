/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package aether

import (
	"errors"
	"fmt"
)

// HeaderSize is the fixed size of every Aether frame header in bytes.
const HeaderSize = 50

// MaxPayloadSize is the maximum allowed payload size (16 MB).
const MaxPayloadSize = 16 << 20 // 16,777,216 bytes

// ErrPayloadTooLarge is the refusal of a frame whose header declares a payload
// longer than MaxPayloadSize. Every decoder returns it before it allocates or
// reads the payload and before it records any stream state for the frame, so a
// header is the only thing a peer can make a receiver read for such a frame;
// Validate returns it for a frame built in memory. errors.Is matches it.
var ErrPayloadTooLarge = errors.New("aether: payload too large")

// ────────────────────────────────────────────────────────────────────────────
// Frame Types
// ────────────────────────────────────────────────────────────────────────────

// FrameType identifies the purpose of an Aether frame.
type FrameType byte

const (
	TypeDATA           FrameType = 0x01 // Application data
	TypeOPEN           FrameType = 0x02 // Open a new stream
	TypeCLOSE          FrameType = 0x03 // Graceful stream close (FIN)
	TypeRESET          FrameType = 0x04 // Abort stream immediately
	TypeWINDOW         FrameType = 0x05 // Flow control credit grant
	TypePING           FrameType = 0x06 // Keepalive / RTT measurement
	TypePONG           FrameType = 0x07 // Keepalive response
	TypeACK            FrameType = 0x08 // Composite ACK (bitmap + optional extensions)
	TypePRIORITY       FrameType = 0x0A // Stream priority change
	TypeGOAWAY         FrameType = 0x0B // Graceful connection shutdown
	TypeFEC_REPAIR     FrameType = 0x0C // Forward error correction repair
	TypeWHOIS          FrameType = 0x0D // Fast identity resolution (PeerID → NodeID + pubkey)
	TypeRENDEZVOUS     FrameType = 0x0E // NAT traversal hints (observed addresses for hole-punching)
	TypeNETWORK_CONFIG FrameType = 0x0F // Inline signed config/policy push
	TypeHANDSHAKE      FrameType = 0x10 // In-band session renegotiation (key rotation, capability update)
	TypeSTATS          FrameType = 0x11 // Periodic session stats report (RTT, loss, cwnd, etc.)
	TypeTRACE          FrameType = 0x12 // Distributed RPC trace through mesh hops
	TypePATH_PROBE     FrameType = 0x13 // Active path measurement + PMTU discovery
	TypeCONGESTION     FrameType = 0x14 // Explicit congestion signal — sender slowdown hint
)

// String returns a human-readable name for the frame type.
func (t FrameType) String() string {
	switch t {
	case TypeDATA:
		return "DATA"
	case TypeOPEN:
		return "OPEN"
	case TypeCLOSE:
		return "CLOSE"
	case TypeRESET:
		return "RESET"
	case TypeWINDOW:
		return "WINDOW"
	case TypePING:
		return "PING"
	case TypePONG:
		return "PONG"
	case TypeACK:
		return "ACK"
	case TypePRIORITY:
		return "PRIORITY"
	case TypeGOAWAY:
		return "GOAWAY"
	case TypeFEC_REPAIR:
		return "FEC_REPAIR"
	case TypeWHOIS:
		return "WHOIS"
	case TypeRENDEZVOUS:
		return "RENDEZVOUS"
	case TypeNETWORK_CONFIG:
		return "NETWORK_CONFIG"
	case TypeHANDSHAKE:
		return "HANDSHAKE"
	case TypeSTATS:
		return "STATS"
	case TypeTRACE:
		return "TRACE"
	case TypePATH_PROBE:
		return "PATH_PROBE"
	case TypeCONGESTION:
		return "CONGESTION"
	default:
		return fmt.Sprintf("UNKNOWN(0x%02X)", byte(t))
	}
}

// IsValid returns true if the frame type is a defined wire type.
//
// This enumerates the defined types rather than range-checking
// [TypeDATA..TypeCONGESTION]. A range check would admit the reserved hole
// at 0x09 (between TypeACK=0x08 and TypePRIORITY=0x0A): a Type=0x09 frame
// would pass Validate (IsValid true, no minPayloadSizes entry) and then be
// silently dropped at dispatch instead of scored via
// reportAbuse(ReasonMalformedFrame). Enumerating defined types makes 0x09
// — and any future in-range gap — fail Validate and route to the
// malformed-frame abuse path, exactly like out-of-range types >0x14.
func (t FrameType) IsValid() bool {
	switch t {
	case TypeDATA, TypeOPEN, TypeCLOSE, TypeRESET, TypeWINDOW, TypePING,
		TypePONG, TypeACK, TypePRIORITY, TypeGOAWAY, TypeFEC_REPAIR,
		TypeWHOIS, TypeRENDEZVOUS, TypeNETWORK_CONFIG, TypeHANDSHAKE,
		TypeSTATS, TypeTRACE, TypePATH_PROBE, TypeCONGESTION:
		return true
	default:
		return false
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Frame Flags
// ────────────────────────────────────────────────────────────────────────────

// FrameFlags is a bitfield of frame-level options.
type FrameFlags byte

const (
	FlagFIN        FrameFlags = 0x01 // Last frame in stream
	FlagSYN        FrameFlags = 0x02 // This DATA frame opens its stream: its payload is the stream's OpenPayload, never a message, on every profile
	FlagACK        FrameFlags = 0x04 // This frame answers one of its type: a PATH_PROBE response, a RESET's acknowledgment (ResetPayload)
	FlagPRIORITY   FrameFlags = 0x08 // Priority field present in payload
	FlagENCRYPTED  FrameFlags = 0x10 // Payload is AEAD encrypted
	FlagCOMPRESSED FrameFlags = 0x20 // Payload is DEFLATE compressed
	FlagANTIREPLAY FrameFlags = 0x40 // SeqNo doubles as anti-replay counter (sliding window)

	// FlagFRAGMENT marks a TypeDATA frame whose payload is one fragment
	// envelope (adapter.FragmentEnvelope) rather than a whole message, so the
	// receiver tells the two apart from the frame and never from payload bytes.
	// The bit is FlagCOMPOSITE_ACK's on TypeACK frames; the two never meet
	// because each is read only on its own frame type (Frame.IsFragment). Only
	// the full header carries it, so ShouldCompressData keeps such a frame full.
	FlagFRAGMENT FrameFlags = 0x80
)

// Has returns true if the flag is set.
func (f FrameFlags) Has(flag FrameFlags) bool {
	return f&flag != 0
}

// Set returns flags with the given flag set.
func (f FrameFlags) Set(flag FrameFlags) FrameFlags {
	return f | flag
}

// Clear returns flags with the given flag cleared.
func (f FrameFlags) Clear(flag FrameFlags) FrameFlags {
	return f &^ flag
}

// String returns a human-readable representation of all set flags.
func (f FrameFlags) String() string {
	var parts []string
	if f.Has(FlagFIN) {
		parts = append(parts, "FIN")
	}
	if f.Has(FlagSYN) {
		parts = append(parts, "SYN")
	}
	if f.Has(FlagACK) {
		parts = append(parts, "ACK")
	}
	if f.Has(FlagPRIORITY) {
		parts = append(parts, "PRIORITY")
	}
	if f.Has(FlagENCRYPTED) {
		parts = append(parts, "ENCRYPTED")
	}
	if f.Has(FlagCOMPRESSED) {
		parts = append(parts, "COMPRESSED")
	}
	if f.Has(FlagANTIREPLAY) {
		parts = append(parts, "ANTIREPLAY")
	}
	if f.Has(FlagCOMPOSITE_ACK) {
		// The bit is FlagCOMPOSITE_ACK on an ACK and FlagFRAGMENT on DATA; the
		// flags alone do not say which.
		parts = append(parts, "COMPOSITE_ACK|FRAGMENT")
	}
	if len(parts) == 0 {
		return "0"
	}
	return fmt.Sprintf("%v", parts)
}

// ────────────────────────────────────────────────────────────────────────────
// Identity
// ────────────────────────────────────────────────────────────────────────────

// PeerID is an 8-byte truncated fingerprint of a NodeID.
// Used in frame headers for compact sender/receiver identification.
// A zero PeerID means broadcast (used for gossip frames).
type PeerID [8]byte

// Broadcast is the zero PeerID indicating a broadcast frame.
var Broadcast PeerID

// IsZero returns true if the PeerID is the broadcast address.
func (p PeerID) IsZero() bool {
	return p == Broadcast
}

// String returns a hex representation of the PeerID.
func (p PeerID) String() string {
	return fmt.Sprintf("%x", p[:])
}

// ────────────────────────────────────────────────────────────────────────────
// Nonce
// ────────────────────────────────────────────────────────────────────────────

// NonceSize is the size of the AEAD nonce in bytes.
const NonceSize = 12

// Nonce is a 12-byte value for AEAD encryption.
// Zero when the ENCRYPTED flag is not set.
type Nonce [NonceSize]byte

// IsZero returns true if the nonce is all zeros.
func (n Nonce) IsZero() bool {
	for _, b := range n {
		if b != 0 {
			return false
		}
	}
	return true
}

// ────────────────────────────────────────────────────────────────────────────
// StreamConnectionLevel is a sentinel StreamID used in WINDOW_UPDATE frames
// to indicate connection-level (not stream-level) flow control.
// This is the ONLY stream ID defined by the protocol. All application-level
// stream assignments are consumer-defined.
const StreamConnectionLevel uint64 = 0xFFFFFFFFFFFFFFFF

// StreamLayout configures which stream IDs serve protocol-level functions.
// Consumers set this when creating sessions to define their stream assignment.
// Zero values mean "not used" — the adapter skips that function.
type StreamLayout struct {
	Keepalive uint64 // stream for ping/pong liveness (0 = disabled)
	Control   uint64 // stream for control frames (GOAWAY, migration, etc.)
	// RPC marks a stream as latency-sensitive request/response so the
	// reliability engine emits ACKs immediately (no delayed-ACK timer)
	// and the writer can take low-latency fast paths. Zero = consumer
	// did not opt in; the adapter treats the stream as bulk data.
	RPC uint64
	// Application streams (gossip, etc.) are consumer-defined and not
	// part of the session layout.
}

// DefaultStreamLayout returns the default stream layout.
// New consumers should define their own.
func DefaultStreamLayout() StreamLayout {
	return StreamLayout{
		Keepalive: 2,
		Control:   3,
	}
}

// MaxStreamID is the maximum assignable stream ID before exhaustion.
// When a session exceeds this, it should send GOAWAY and create a new session.
const MaxStreamID uint64 = 1<<62 - 1

// ────────────────────────────────────────────────────────────────────────────
// Reliability Modes
// ────────────────────────────────────────────────────────────────────────────

// Reliability defines the delivery guarantee for a stream.
type Reliability uint8

const (
	// ReliableOrdered delivers all data in order. TCP-like semantics.
	// Use for: RPC dispatch, control channel.
	ReliableOrdered Reliability = iota

	// ReliableUnordered delivers all data but order is not guaranteed.
	// Reduces head-of-line blocking. Use for: bulk transfer, file sync.
	ReliableUnordered

	// UnreliableOrdered drops stale data but preserves ordering of delivered frames.
	// Use for: real-time telemetry, streaming metrics.
	UnreliableOrdered

	// UnreliableSequenced delivers only the latest frame, dropping older ones.
	// Use for: status updates, game state, heartbeats.
	UnreliableSequenced

	// BestEffort retries briefly (MaxRetries or MaxAge) then drops.
	// Use for: gossip deltas (convergent — next sync recovers).
	BestEffort
)

// String returns a human-readable name for the reliability mode.
func (r Reliability) String() string {
	switch r {
	case ReliableOrdered:
		return "reliable-ordered"
	case ReliableUnordered:
		return "reliable-unordered"
	case UnreliableOrdered:
		return "unreliable-ordered"
	case UnreliableSequenced:
		return "unreliable-sequenced"
	case BestEffort:
		return "best-effort"
	default:
		return fmt.Sprintf("unknown(%d)", r)
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Frame
// ────────────────────────────────────────────────────────────────────────────

// Frame is the canonical Aether wire format.
// Every transport carries these frames — the transport is just a pipe.
type Frame struct {
	SenderID   PeerID     // 8 bytes: truncated fingerprint of sender NodeID
	ReceiverID PeerID     // 8 bytes: truncated fingerprint of receiver (zero=broadcast)
	StreamID   uint64     // 8 bytes: application-defined stream identifier
	Type       FrameType  // 1 byte: frame type
	Flags      FrameFlags // 1 byte: bitfield
	SeqNo      uint32     // 4 bytes: per-stream sender sequence number
	AckNo      uint32     // 4 bytes: piggyback acknowledgment
	Length     uint32     // 4 bytes: payload length
	Nonce      Nonce      // 12 bytes: AEAD nonce (zero when ENCRYPTED flag unset)
	Payload    []byte     // variable: Length bytes
}

// Validate checks the frame for structural correctness.
// Returns nil if valid, or an error describing the issue.
//
// Type-specific minimum-size checks: each control type has a known wire
// size declared above (OpenPayloadSize, ResetPayloadSize, etc.). A frame
// arriving with a shorter payload would otherwise be read by its decoder
// as a zero value (DecodeOpenPayload, DecodeReset, DecodeWindowUpdate,
// DecodeCongestion and DecodeStats each return one on short input) and
// handled as a real control frame. Validation here rejects it before the
// type-handler is invoked (minPayloadSizes), which is what lets the noise
// adapter's processIncomingFrame charge abuse.ReasonMalformedFrame for it.
func (f *Frame) Validate() error {
	if !f.Type.IsValid() {
		return fmt.Errorf("aether: invalid frame type 0x%02X", byte(f.Type))
	}
	if f.Length > MaxPayloadSize {
		return fmt.Errorf("%w (%d bytes, max %d)", ErrPayloadTooLarge, f.Length, MaxPayloadSize)
	}
	if uint32(len(f.Payload)) != f.Length {
		return fmt.Errorf("aether: payload length mismatch (header=%d, actual=%d)", f.Length, len(f.Payload))
	}
	if f.Flags.Has(FlagENCRYPTED) && f.Nonce.IsZero() {
		return fmt.Errorf("aether: ENCRYPTED flag set but nonce is zero")
	}
	// The per-type minimum describes the UNCOMPRESSED wire size, so it must
	// not be applied to a payload that is still deflated: writeFrame compresses
	// any payload over 64 bytes, and a 74-byte STATS frame (StatsPayloadSize)
	// compresses to ~40 bytes, which is legitimately below its own minimum, so
	// a check here would reject every compressed STATS frame as malformed.
	//
	// The check is DEFERRED, NOT DROPPED. The receive path re-runs Validate()
	// immediately after decompression, where FlagCOMPRESSED has been cleared and
	// Length is the true size — so a genuinely undersized frame is still rejected
	// and still scored as abuse. That deliberate anti-abuse intent (see the
	// minPayloadSizes comment below) is preserved, not weakened.
	//
	// ⚠ ANY caller that decompresses a payload MUST re-validate afterwards, or
	// the minimum goes unenforced for compressed frames. processIncomingFrame
	// (adapter/noise_dispatch.go) is the one caller that decompresses, and it
	// re-runs Validate after decompressPayload.
	if minSize, ok := minPayloadSizes[f.Type]; ok && f.Length < minSize &&
		!f.Flags.Has(FlagCOMPRESSED) {
		return fmt.Errorf("aether: %s payload too small (%d bytes, min %d)", f.Type, f.Length, minSize)
	}
	return nil
}

// minPayloadSizes is the per-type minimum wire size for control frames.
// Sourced from the per-type Size constants declared in this file. DATA
// frames have no minimum (zero-length DATA is a valid keepalive on some
// streams). Validate refuses a shorter uncompressed payload before any type
// handler runs, which is what lets the noise adapter's processIncomingFrame
// charge abuse.ReasonMalformedFrame for it instead of a handler acting on a
// zero value. The decoders (DecodeOpenPayload, DecodeReset,
// DecodeWindowUpdate, DecodeCongestion, DecodeStats) still check short input
// and return a zero value themselves: a second guard that holds for any
// caller, whether or not it ran Validate on the frame first.
var minPayloadSizes = map[FrameType]uint32{
	TypeOPEN:       OpenPayloadSize,
	TypeCLOSE:      ClosePayloadSize,
	TypeRESET:      ResetPayloadSize,
	TypeWINDOW:     WindowUpdateSize,
	TypeCONGESTION: CongestionPayloadSize,
	TypeFEC_REPAIR: FECHeaderSize,
	// STATS is fixed-size — gate undersized payloads at Validate so the
	// abuse path fires instead of the handler silently dropping. Pairs
	// with the StatsPayloadSize guard in noise_dispatch.handleStats
	// (defence-in-depth — handler-level guard stays because Validate is
	// skipped on a few short-header decode paths).
	TypeSTATS: StatsPayloadSize,
}

// IsControl returns true if this is a control frame (not DATA).
func (f *Frame) IsControl() bool {
	return f.Type != TypeDATA
}

// IsFragment reports whether f is a DATA frame carrying one fragment envelope:
// TypeDATA with FlagFRAGMENT. The session read paths (adapter NoiseSession and
// TCPSession) route such a payload to reassembly and every other DATA payload
// to the stream as a whole message.
func (f *Frame) IsFragment() bool {
	return f.Type == TypeDATA && f.Flags.Has(FlagFRAGMENT)
}

// ────────────────────────────────────────────────────────────────────────────
// SACK Block (payload of TypeACK frames)
// ────────────────────────────────────────────────────────────────────────────

// SACKBlock represents a range of received sequence numbers in a selective ACK.
// [Start, End] inclusive — "I have received SeqNos Start through End."
type SACKBlock struct {
	Start uint32 // first received SeqNo in this block
	End   uint32 // last received SeqNo in this block
}

// SACKBlockSize is the wire size of a single SACK block (8 bytes).
const SACKBlockSize = 8

// MaxSACKBlocks is the maximum number of SACK blocks per ACK frame.
const MaxSACKBlocks = 4

// ────────────────────────────────────────────────────────────────────────────
// Composite ACK with bitmap and extensions.
// ────────────────────────────────────────────────────────────────────────────

// CompositeACKFlags are extension flags in the Composite ACK payload.
type CompositeACKFlags byte

const (
	CACKHasExtRanges    CompositeACKFlags = 0x01 // Extended SACK ranges follow (max 8)
	CACKHasDropped      CompositeACKFlags = 0x02 // Dropped ranges follow (max 4, sorted, non-overlapping, merged)
	CACKHasLossDensity  CompositeACKFlags = 0x04 // 2-byte advisory loss rate follows
	CACKHasECN          CompositeACKFlags = 0x08 // ECN extension: 4-byte CE-marked-byte counter
	CACKInvertedBitmap  CompositeACKFlags = 0x10 // Reserved, set and read by no code: bit=1 would mean MISSING. Burst loss is recovered by interleaved FEC (FECInterleaved: two offset XOR groups in the FEC layer); the bit stays reserved for an ACK-layer loss-signalling mode.
	CACKHasGaps         CompositeACKFlags = 0x20 // Receive window has gaps. ACK-lite (BitmapLen=0) ONLY valid when HasGaps=0
	CACKHasWindowCredit CompositeACKFlags = 0x40 // Window-credit extension: 8-byte cumulative stream-level WINDOW_UPDATE grant piggybacked on the ACK. Eliminates a separate WINDOW_UPDATE frame when the receiver has granted new credit for this stream. Sender applies via StreamWindow.ApplyUpdate with the same cumulative semantics as a standalone WINDOW_UPDATE.
	CACKNoCumulative    CompositeACKFlags = 0x80 // No cumulative acknowledgment: the receiver has delivered nothing in-order yet (expected==0), so BaseACK carries the wrapped sentinel expected-1 (0xFFFFFFFF) purely to keep the SACK bitmap aligned (BaseACK+1+i wraps to seq i). The sender MUST skip the cumulative-ack loop and its jump check and process only the SACK bitmap. Without the flag, expected-1 reads as a ~4-billion forward jump, and SendWindow.ProcessCompositeACK discards the whole ACK and charges the honest receiver with ACK-validation abuse.
)

// FlagCOMPOSITE_ACK is set on TypeACK frames that use the Composite ACK format.
// Distinguishes Composite ACK from simple ACK.
const FlagCOMPOSITE_ACK FrameFlags = 0x80

// CompositeACK is the decoded payload of a TypeACK frame (v2 format).
// Wire format:
//
//	ACK-LITE (8 bytes): [BaseACK:4][AckDelay:2][BitmapLen:1=0][Flags:1=0]
//	ACK-FULL (12+ bytes): [BaseACK:4][AckDelay:2][BitmapLen:1][Bitmap:N][Flags:1][extensions...]
type CompositeACK struct {
	BaseACK  uint32            // highest contiguous SeqNo received
	AckDelay uint16            // delay in 8µs units (max ~524ms)
	Bitmap   []byte            // received bitmap (0/4/8/16/32 bytes). Bit i=1 means BaseACK+1+i received.
	Flags    CompositeACKFlags // extension flags

	// Optional extensions (present only if flagged)
	ExtRanges     []SACKBlock // extended SACK ranges beyond bitmap window (max 8)
	DroppedRanges []SACKBlock // ranges receiver has dropped (max 4)
	LossRate      uint16      // loss% × 100 over a sliding wall-clock window (default 5s, see reliability.DefaultLossWindow) of received-packet samples; 0-10000. Receiver gates emission on ACKEngine.HasWarmedUp() so an undersampled early window never reaches the wire. Advisory only.
	CEBytes       uint32      // ECN: cumulative bytes of CE-marked packets observed since last ACK
	WindowCredit  uint64      // Cumulative stream-level WINDOW_UPDATE grant piggybacked on this ACK. Same semantics as the WINDOW_UPDATE frame payload: cumulative, not delta; sender's ApplyUpdate drops stale/duplicate values via the grantsReceived cursor.
}

// Valid bitmap lengths in bytes.
const (
	BitmapLen0   = 0  // ACK-lite: no bitmap (pure cumulative)
	BitmapLen32  = 4  // 32-bit window
	BitmapLen64  = 8  // 64-bit window
	BitmapLen128 = 16 // 128-bit window
	BitmapLen256 = 32 // 256-bit window
)

// CompositeACKMinSize is the minimum payload: BaseACK(4) + AckDelay(2) + BitmapLen(1) + Flags(1) = 8 bytes.
const CompositeACKMinSize = 8

// MaxExtRanges is the maximum extended SACK ranges per ACK.
const MaxExtRanges = 8

// MaxDroppedRanges is the maximum dropped ranges per ACK.
const MaxDroppedRanges = 4

// AckDelayGranularity is the granularity of the AckDelay field in microseconds.
const AckDelayGranularity = 8

// ────────────────────────────────────────────────────────────────────────────
// WINDOW_UPDATE payload
// ────────────────────────────────────────────────────────────────────────────

// WindowUpdateSize is the wire size of a WINDOW_UPDATE payload (8 bytes).
//
// The payload carries a CUMULATIVE total of credit granted since the stream
// started (not a per-WINDOW_UPDATE delta). Cumulative semantics make the
// grant channel idempotent across loss / duplication / reordering on
// unreliable transports — the sender's ApplyUpdate compares the incoming
// cumulative value against the highest-seen-so-far and applies only the
// positive delta. A single lost WINDOW_UPDATE packet is implicitly recovered
// by the next one, which carries a still-larger cumulative value.
//
// The field is uint64 rather than uint32 because cumulative totals can grow
// past 4 GB over long-lived sessions (the previous 4-byte wire format would
// wrap, making post-wrap grants appear stale to the sender and deadlocking
// the stream after ~40 hours of heavy gossip traffic).
const WindowUpdateSize = 8

// ────────────────────────────────────────────────────────────────────────────
// CONGESTION payload
// ────────────────────────────────────────────────────────────────────────────

// CongestionPayloadSize is the wire size of a CONGESTION payload (5 bytes).
//
//	[1 byte reason][1 byte severity 0-100][2 bytes backoff_ms][1 byte reserved]
const CongestionPayloadSize = 5

// CongestionReason identifies why the receiver is signalling congestion.
type CongestionReason byte

const (
	CongestionUnspecified CongestionReason = 0
	CongestionQueueFull   CongestionReason = 1 // Receiver's delivery queue is backlogged
	CongestionMemoryHigh  CongestionReason = 2 // Receiver near memory pressure
	CongestionCPUHigh     CongestionReason = 3 // Receiver can't keep up CPU-wise
	CongestionRateLimit   CongestionReason = 4 // Receiver policy rate-limit
	CongestionDownstream  CongestionReason = 5 // Receiver can't drain to its downstream
)

// CongestionPayload is an explicit backpressure hint from receiver to sender.
// Senders that honour it reduce their send rate by `Severity/100` for
// `BackoffMs` milliseconds before resuming normal cadence. Severity 100 means
// "stop entirely for BackoffMs". Severity 0 is an explicit "all clear".
type CongestionPayload struct {
	Reason    CongestionReason
	Severity  uint8  // 0 (clear) to 100 (full stop)
	BackoffMs uint16 // how long the sender should respect this hint
}

// ────────────────────────────────────────────────────────────────────────────
// PRIORITY payload
// ────────────────────────────────────────────────────────────────────────────

// PriorityPayloadSize is the wire size of a PRIORITY payload (9 bytes).
const PriorityPayloadSize = 9

// PriorityPayload is the decoded payload of a PRIORITY frame.
type PriorityPayload struct {
	Weight     uint8  // 1-255, relative weight for WFQ scheduling
	Dependency uint64 // parent stream ID (0 = root)
}

// ────────────────────────────────────────────────────────────────────────────
// FEC_REPAIR payload header
// ────────────────────────────────────────────────────────────────────────────

// FECHeaderSize is the wire size of the fixed part of an FEC_REPAIR payload:
// [4 group ID][1 index][1 total][1 level][1 covered count]. The table of the
// frames the repair covers follows it (FECCoveredSize each), then the repair
// bytes. Validate refuses an uncompressed FEC_REPAIR frame shorter than this.
const FECHeaderSize = 8

// FECCoveredSize is the wire size of one FEC_REPAIR table entry:
// [4 sequence number][2 payload length][1 flags, bit 0 fragment].
const FECCoveredSize = 7

// MaxFECCovered is the most frames one repair may cover. DecodeFECHeader refuses
// a larger count before it allocates the table.
const MaxFECCovered = 32

// FECCovered names one DATA frame a repair covers: its sequence number, the
// payload length that strips the zero padding off a recovered payload, and
// whether the frame carried aether.FlagFRAGMENT, which reassembly needs and a
// repair is otherwise the only source of for a frame that never arrived.
type FECCovered struct {
	SeqNo    uint32
	Length   uint16
	Fragment bool
}

// FECHeader is the decoded header of an FEC_REPAIR frame. Covered is what lets
// adapter.NoiseSession's handleFECRepair place a recovered payload in its
// stream's receive window, where it is delivered once and in order whichever of
// the repair and a retransmit arrives first.
type FECHeader struct {
	GroupID uint32       // FEC group identifier, unique per sender stream
	Index   uint8        // this repair's position in the group: the covered frames take 0..len(Covered)-1
	Total   uint8        // total frames in the group, repairs included
	Level   uint8        // the group's code, a reliability.FECLevel value
	Covered []FECCovered // the DATA frames the repair covers, in group order
}

// FECRepairOverhead is what an FEC_REPAIR payload holds beyond its repair bytes
// when it covers covered frames. A repair's bytes are as long as the longest
// frame it covers, so noiseStream.Send takes this off the largest frame payload
// of a stream with FEC, which keeps the repair inside the MSS its frames fit.
func FECRepairOverhead(covered int) int {
	return FECHeaderSize + covered*FECCoveredSize
}

// ────────────────────────────────────────────────────────────────────────────
// GOAWAY payload
// ────────────────────────────────────────────────────────────────────────────

// GoAwayReason codes for the GOAWAY frame.
type GoAwayReason uint32

const (
	GoAwayNormal    GoAwayReason = 0 // Graceful shutdown
	GoAwayError     GoAwayReason = 1 // Unrecoverable error
	GoAwayMigration GoAwayReason = 2 // Migrating to a better transport
	GoAwayOverload  GoAwayReason = 3 // Backpressure / load shedding
)

// GoAwayPayloadMinSize is the minimum wire size of a GOAWAY payload.
const GoAwayPayloadMinSize = 4 // reason code only

// ────────────────────────────────────────────────────────────────────────────
// OPEN payload
// ────────────────────────────────────────────────────────────────────────────

// OpenPayloadSize is the wire size of an OPEN frame payload in frame grammar
// WireVersionFrameCurrent. Validate refuses an uncompressed OPEN frame shorter
// than this (minPayloadSizes) before either session's handleOpen runs.
const OpenPayloadSize = 39

// MaxOpenCredit is the largest initial credit an OPEN payload can state: the
// field is four bytes. adapter.NoiseSession's OpenStream refuses a stream
// whose initial credit is above it with ErrStreamCreditRefused, before the
// stream exists.
const MaxOpenCredit int64 = 1<<32 - 1

// OpenPayload is the decoded payload of an OPEN frame. The TCP-family
// session also writes it as the payload of its SYN DATA frame, and the QUIC
// stream adapter writes it in each QUIC stream's header.
//
// InitialCredit is the credit, in the bytes adapter.NoiseSession's Send
// charges, the opener reserved for this stream: what it lets the peer queue on
// the stream before its consumer reads, and what the peer's own window for
// the stream starts at. The accepting NoiseSession builds the stream's window
// and its credit reservation from it, and refuses with RESET(ResetRefused),
// keeping no state, an OPEN whose credit is below flow.MinGuaranteedWindow or
// above its own stream ceiling. Zero has one meaning: the opener runs no
// aether stream credit, which the TCP-family session and the QUIC stream
// adapter state because their transport owns flow control; they do not read
// the field, and a NoiseSession refuses an OPEN stating zero.
//
// FECLevel is the reliability.FECLevel both ends of the stream run: each side
// encodes repairs for what it sends at this level, and the accepting
// NoiseSession keeps the recent payloads a repair is decoded against only when
// the OPEN states one. Zero is no FEC. A level outside the registry is refused
// with RESET(ResetRefused) and no state. The TCP-family session and the QUIC
// stream adapter state zero: FEC belongs to their transport.
//
// Generation is the opener's number for this stream, from 1 to
// MaxStreamGeneration, rising with every stream the opener's session creates: the
// stream's incarnation is this generation together with which side opened it
// (StreamIncarnation), and every CLOSE and RESET of the stream states it. The
// NoiseSession and TCP-family session refuse with RESET(ResetRefused) and no
// state an OPEN stating zero or a number above MaxStreamGeneration. The QUIC
// stream adapter states zero and does not read it: each of its streams is a QUIC
// stream of its own, which QUIC never hands out twice.
//
// PriorGeneration and PriorConsumed are the opener's statement of its earlier stream
// under the ID, one it opened and a RESET ended: that stream's generation, and what
// the opener's consumer returned of the receiver's sends on it through connection
// grants (ResetPayload.Consumed, as its RESET of that stream stated it). A
// NoiseSession that still holds that stream, the opener's RESET of it never having
// arrived, ends it at this OPEN (it is superseded) and settles its connection charge
// on PriorConsumed exactly as that RESET would have, and acknowledges that RESET.
// Zero PriorGeneration states no earlier stream: an ID's first stream, a stream that
// ended on both CLOSEs, or a statement the opener no longer keeps (its note lifetime).
// The TCP-family session and the QUIC stream adapter state zero and do not read them.
type OpenPayload struct {
	Reliability     Reliability // 1 byte: delivery guarantee
	Priority        uint8       // 1 byte: initial weight (1-255)
	Dependency      uint64      // 8 bytes: parent stream ID
	InitialCredit   uint32      // 4 bytes: the opener's initial stream credit
	FECLevel        uint8       // 1 byte: the stream's FEC level
	Generation      uint64      // 8 bytes: the opener's generation of the stream
	PriorGeneration uint64      // 8 bytes: the opener's earlier stream under the ID, 0 for none
	PriorConsumed   uint64      // 8 bytes: what the opener's consumer returned on that stream
}

// ────────────────────────────────────────────────────────────────────────────
// Stream incarnation
// ────────────────────────────────────────────────────────────────────────────

// MaxStreamGeneration is the largest stream generation a frame states: the
// eight bytes of an incarnation keep their top bit for WriterOpened.
const MaxStreamGeneration uint64 = 1<<63 - 1

// StreamIncarnationSize is the wire size of a StreamIncarnation: eight bytes,
// big-endian, the top bit WriterOpened and the rest Generation.
const StreamIncarnationSize = 8

// ClosePayloadSize is the wire size of a CLOSE frame payload: the stream's
// incarnation. Validate refuses an uncompressed CLOSE frame shorter than this
// (minPayloadSizes), so a CLOSE stating no incarnation ends nothing.
const ClosePayloadSize = StreamIncarnationSize

// StreamIncarnation names one stream among those that have used its stream ID
// on a session: the generation its opener's OPEN stated (OpenPayload.Generation),
// and whether the side writing the frame is that opener. Two sides number their
// streams each from their own count, so the generation alone can name a stream
// of each side; the opener bit tells them apart.
//
// CLOSE carries one as its payload and RESET in its payload (ResetPayload). A
// session's handleClose and handleReset end a stream only when the frame's
// incarnation is the stream's own, the receiver reading WriterOpened as "the peer
// opened it": a CLOSE or RESET of an earlier stream under the ID, a copy delayed
// on the path or written before its writer read this side's reopening, finds the
// stream it names gone and ends nothing of the stream that now has the ID.
type StreamIncarnation struct {
	Generation   uint64
	WriterOpened bool
}

// ────────────────────────────────────────────────────────────────────────────
// RESET payload
// ────────────────────────────────────────────────────────────────────────────

// ResetPayloadSize is the wire size of a RESET frame payload:
// [4 reason][8 charged][8 released][8 consumed][8 incarnation], all big-endian.
const ResetPayloadSize = 36

// ResetPayload is the decoded payload of a RESET frame. On adapter.NoiseSession
// (the Full profile) its Consumed settles the stream's connection credit exactly
// once, in the credit Send charges, whichever grants were on the path at the time:
//
//   - Charged is all the writer's sends on the stream charged to its stream window.
//   - Released is the part of Charged the writer's stream window still held at this
//     RESET, what no stream grant had returned by then.
//   - Consumed is the credit of the peer's messages on this stream the writer's
//     consumer has returned through connection grants, which stop at this RESET.
//
// Each side settles the connection charge of its own sends on the stream on the
// peer's statement of Consumed and on nothing else: the peer's RESET of the stream,
// or the peer's acknowledgment of this side's RESET, whichever comes first, or, for a
// stream the peer's later OPEN supersedes, that OPEN's statement
// (OpenPayload.PriorConsumed). It gives
// back what its sends charged less Consumed, since the grants for Consumed still
// arrive and nothing returns the rest, and it withholds none of its own grants.
// Charged and Released are stated for the stream window's own accounting and no
// reader settles on them. A refusal, which holds no stream, and a TCP-family or QUIC
// session, whose transport owns flow control, state zero counts (and those sessions
// do not read them).
//
// Incarnation is the stream the RESET ends (StreamIncarnation); a refusal states
// the generation of the OPEN it refuses, opened by the peer. A RESET flagged
// FlagACK is a NoiseSession's acknowledgment of a RESET it read, whatever that
// RESET found: it states the acknowledged RESET's incarnation exactly as that
// RESET stated it, the same reason, Charged and Released zero, and as Consumed
// what the acknowledging side's consumer had returned of the RESET writer's sends
// on the stream (zero for a stream it never held), and its reader settles on that
// Consumed and answers nothing. A NoiseSession writes each RESET of a stream again
// until its own acknowledgment comes (adapter.NoiseSession's pending RESETs, one per
// stream it names), because a RESET
// lost on a datagram path would leave the peer's stream live under an ID this
// side may open again. A TCP-family session writes its acknowledgment once with
// zero counts and no second copy of a RESET, its transport delivering every frame
// once in order.
type ResetPayload struct {
	Reason      ResetReason
	Charged     uint64
	Released    uint64
	Consumed    uint64
	Incarnation StreamIncarnation
}

// ResetReason codes for RESET frames.
type ResetReason uint32

const (
	ResetCancel   ResetReason = 0 // Application cancelled the stream
	ResetRefused  ResetReason = 1 // Stream refused by peer
	ResetInternal ResetReason = 2 // Internal error
	ResetFlowCtrl ResetReason = 3 // Flow control violation
	ResetTimeout  ResetReason = 4 // Stream idle timeout
)

// ────────────────────────────────────────────────────────────────────────────
// Latency Classes
// ────────────────────────────────────────────────────────────────────────────

// LatencyClass defines the scheduling priority class for a stream.
// Strict priority between classes: REALTIME > INTERACTIVE > BULK.
// WFQ by weight within each class.
//
// Numeric reservation: 0 is reserved as ClassUnset so callers who leave
// StreamConfig.LatencyClass at its zero value can be distinguished from
// callers who explicitly chose REALTIME. Adapter call sites translate
// ClassUnset → DefaultLatencyClass(streamID). If REALTIME were 0, every
// config-omits-class stream would silently route into REALTIME and the
// scheduler's 10%-bandwidth cap would demote them past every other
// class on the same session — stalling delivery.
//
// LatencyClass is NOT carried on the wire (OpenPayload encodes only
// Reliability + Priority + Dependency). Each peer schedules its own
// outbound frames per its local config, so renumbering is wire-safe.
type LatencyClass uint8

const (
	// ClassUnset is the zero value reserved for "caller didn't specify".
	// Callers must NEVER set this explicitly; adapter sites substitute
	// DefaultLatencyClass(streamID).
	ClassUnset LatencyClass = 0

	// ClassREALTIME is strict-priority, never queued behind BULK.
	// Bandwidth-capped at 10% of link to prevent abuse.
	// Use for: PING/PONG, WHOIS, RENDEZVOUS, input events, emergency policy.
	ClassREALTIME LatencyClass = 1

	// ClassINTERACTIVE is medium priority, served after REALTIME, before BULK.
	// Use for: RPC dispatch, screen key frames, tunnels, normal policy.
	ClassINTERACTIVE LatencyClass = 2

	// ClassBULK is lowest priority, gets remaining bandwidth.
	// WFQ by weight within this class.
	// Use for: gossip, telemetry, file transfer, screen deltas.
	ClassBULK LatencyClass = 3
)

// String returns a human-readable class name.
func (c LatencyClass) String() string {
	switch c {
	case ClassUnset:
		return "UNSET"
	case ClassREALTIME:
		return "REALTIME"
	case ClassINTERACTIVE:
		return "INTERACTIVE"
	case ClassBULK:
		return "BULK"
	default:
		return fmt.Sprintf("class(%d)", c)
	}
}

// DefaultLatencyClass returns ClassBULK. Consumers set the actual class
// in their StreamConfig when opening streams. The protocol does not
// assign default classes to stream IDs — that's an application decision.
func DefaultLatencyClass(streamID uint64) LatencyClass {
	return ClassBULK
}

// ────────────────────────────────────────────────────────────────────────────
// WHOIS payload (TypeWHOIS)
// ────────────────────────────────────────────────────────────────────────────

// WhoisMinSize is the minimum WHOIS payload size (request).
const WhoisMinSize = 9 // PeerID(8) + ResponseFlag(1)

// WhoisPayload is the decoded payload of a WHOIS frame.
type WhoisPayload struct {
	TargetPeerID PeerID   // 8 bytes: the PeerID to resolve
	IsResponse   bool     // 1 byte: false=request, true=response
	NodeID       string   // variable: full NodeID string (response only)
	PubKey       [32]byte // 32 bytes: Ed25519 public key (response only)
}

// ────────────────────────────────────────────────────────────────────────────
// RENDEZVOUS payload (TypeRENDEZVOUS)
// ────────────────────────────────────────────────────────────────────────────

// RendezvousPayloadSize is the fixed RENDEZVOUS payload size.
const RendezvousPayloadSize = 27 // PeerID(8) + IP(16) + Port(2) + NATType(1)

// NATType describes the NAT behavior observed for a peer.
type NATType uint8

const (
	NATUnknown        NATType = 0
	NATOpen           NATType = 1
	NATFullCone       NATType = 2
	NATRestricted     NATType = 3
	NATPortRestricted NATType = 4
	NATSymmetric      NATType = 5
	NATBlocked        NATType = 6
)

// String returns a human-readable NAT type name.
func (n NATType) String() string {
	switch n {
	case NATUnknown:
		return "unknown"
	case NATOpen:
		return "open"
	case NATFullCone:
		return "full-cone"
	case NATRestricted:
		return "restricted"
	case NATPortRestricted:
		return "port-restricted"
	case NATSymmetric:
		return "symmetric"
	case NATBlocked:
		return "blocked"
	default:
		return fmt.Sprintf("nat(%d)", n)
	}
}

// RendezvousPayload is the decoded payload of a RENDEZVOUS frame.
type RendezvousPayload struct {
	TargetPeerID PeerID   // 8 bytes: peer to connect to
	ObservedIP   [16]byte // 16 bytes: IPv6-mapped observed address (IPv4 uses ::ffff:x.x.x.x)
	ObservedPort uint16   // 2 bytes: observed UDP port
	NATType      NATType  // 1 byte: NAT behavior
}

// ────────────────────────────────────────────────────────────────────────────
// NETWORK_CONFIG payload (TypeNETWORK_CONFIG)
// ────────────────────────────────────────────────────────────────────────────

// NetworkConfigMinSize is the minimum NETWORK_CONFIG payload size.
const NetworkConfigMinSize = 69 // Type(1) + Version(4) + Signature(64)

// ConfigType identifies the kind of configuration being pushed.
type ConfigType uint8

const (
	ConfigPolicy      ConfigType = 0 // Security/enforcement policy
	ConfigRoles       ConfigType = 1 // Service roles and capabilities
	ConfigNetworkKeys ConfigType = 2 // Mesh network encryption keys
	ConfigRevocation  ConfigType = 3 // Key/cert revocation
)

// String returns a human-readable config type name.
func (c ConfigType) String() string {
	switch c {
	case ConfigPolicy:
		return "policy"
	case ConfigRoles:
		return "roles"
	case ConfigNetworkKeys:
		return "network-keys"
	case ConfigRevocation:
		return "revocation"
	default:
		return fmt.Sprintf("config(%d)", c)
	}
}

// NetworkConfigPayload is the decoded payload of a NETWORK_CONFIG frame.
type NetworkConfigPayload struct {
	ConfigType ConfigType // 1 byte
	Version    uint32     // 4 bytes: monotonically increasing config version
	Signature  [64]byte   // 64 bytes: Ed25519 signature over [ConfigType][Version][ConfigData]
	ConfigData []byte     // variable: the configuration blob
}

// ────────────────────────────────────────────────────────────────────────────
// HANDSHAKE payload (TypeHANDSHAKE)
// ────────────────────────────────────────────────────────────────────────────

// HandshakeType identifies the kind of in-band session renegotiation.
type HandshakeType uint8

const (
	HandshakeKeyRotation      HandshakeType = 0 // Rotate session encryption keys
	HandshakeCapUpdate        HandshakeType = 1 // Update capabilities (e.g., enable FEC)
	HandshakeSessionResume    HandshakeType = 2 // Resume an established session from its ticket
	HandshakeAddressMigration HandshakeType = 3 // Connection migration (IP/port change)
	HandshakeResumeMaterial   HandshakeType = 4 // Responder → initiator delivery of ticket + keys for next-time resume
)

// HandshakePayload is the decoded payload of a HANDSHAKE frame.
type HandshakePayload struct {
	HandshakeType HandshakeType // 1 byte
	Payload       []byte        // variable: type-specific handshake data
}
