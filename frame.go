/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package aether

import (
	"fmt"
)

// HeaderSize is the fixed size of every Aether frame header in bytes.
const HeaderSize = 50

// MaxPayloadSize is the maximum allowed payload size (16 MB).
const MaxPayloadSize = 16 << 20 // 16,777,216 bytes

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

// IsValid returns true if the frame type is a known type.
func (t FrameType) IsValid() bool {
	return t >= TypeDATA && t <= TypeCONGESTION
}

// ────────────────────────────────────────────────────────────────────────────
// Frame Flags
// ────────────────────────────────────────────────────────────────────────────

// FrameFlags is a bitfield of frame-level options.
type FrameFlags byte

const (
	FlagFIN        FrameFlags = 0x01 // Last frame in stream
	FlagSYN        FrameFlags = 0x02 // Stream open (zero-RTT in DATA frame)
	FlagACK        FrameFlags = 0x04 // Acknowledgment piggyback
	FlagPRIORITY   FrameFlags = 0x08 // Priority field present in payload
	FlagENCRYPTED  FrameFlags = 0x10 // Payload is AEAD encrypted
	FlagCOMPRESSED FrameFlags = 0x20 // Payload is DEFLATE compressed
	FlagANTIREPLAY FrameFlags = 0x40 // SeqNo doubles as anti-replay counter (sliding window)
	// 0x80 is reserved for FlagCOMPOSITE_ACK (defined below with CompositeACK types)
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
		parts = append(parts, "COMPOSITE_ACK")
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
	// Application streams (gossip, RPC, etc.) are consumer-defined and
	// not part of the session layout.
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
func (f *Frame) Validate() error {
	if !f.Type.IsValid() {
		return fmt.Errorf("aether: invalid frame type 0x%02X", byte(f.Type))
	}
	if f.Length > MaxPayloadSize {
		return fmt.Errorf("aether: payload too large (%d bytes, max %d)", f.Length, MaxPayloadSize)
	}
	if uint32(len(f.Payload)) != f.Length {
		return fmt.Errorf("aether: payload length mismatch (header=%d, actual=%d)", f.Length, len(f.Payload))
	}
	if f.Flags.Has(FlagENCRYPTED) && f.Nonce.IsZero() {
		return fmt.Errorf("aether: ENCRYPTED flag set but nonce is zero")
	}
	return nil
}

// IsControl returns true if this is a control frame (not DATA).
func (f *Frame) IsControl() bool {
	return f.Type != TypeDATA
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
	CACKHasExtRanges   CompositeACKFlags = 0x01 // Extended SACK ranges follow (max 8)
	CACKHasDropped     CompositeACKFlags = 0x02 // Dropped ranges follow (max 4, sorted, non-overlapping, merged)
	CACKHasLossDensity CompositeACKFlags = 0x04 // 2-byte advisory loss rate follows
	CACKHasECN         CompositeACKFlags = 0x08 // ECN extension: 4-byte CE-marked-byte counter (Concern #15)
	CACKInvertedBitmap CompositeACKFlags = 0x10 // Reserved for future use: bit=1 means MISSING. Interleaved FEC (FECInterleaved) now handles burst loss recovery via two offset XOR groups in the FEC layer; this flag is kept for forward-compatibility with a potential future ACK-layer loss signaling mode.
	CACKHasGaps        CompositeACKFlags = 0x20 // Receive window has gaps. ACK-lite (BitmapLen=0) ONLY valid when HasGaps=0
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
	LossRate      uint16      // loss% × 100 over last 256 packets (0-10000). Advisory only.
	CEBytes       uint32      // ECN: cumulative bytes of CE-marked packets observed since last ACK (#15)
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
//   [1 byte reason][1 byte severity 0-100][2 bytes backoff_ms][1 byte reserved]
const CongestionPayloadSize = 5

// CongestionReason identifies why the receiver is signalling congestion.
type CongestionReason byte

const (
	CongestionUnspecified  CongestionReason = 0
	CongestionQueueFull    CongestionReason = 1 // Receiver's recvCh is backlogged
	CongestionMemoryHigh   CongestionReason = 2 // Receiver near memory pressure
	CongestionCPUHigh      CongestionReason = 3 // Receiver can't keep up CPU-wise
	CongestionRateLimit    CongestionReason = 4 // Receiver policy rate-limit
	CongestionDownstream   CongestionReason = 5 // Receiver can't drain to its downstream
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

// FECHeaderSize is the wire size of the FEC_REPAIR header before the XOR payload.
const FECHeaderSize = 6

// FECHeader is the decoded header of an FEC_REPAIR frame.
type FECHeader struct {
	GroupID uint32 // FEC group identifier
	Index   uint8  // position within the group (0-based)
	Total   uint8  // total frames in the group (including this repair)
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

// OpenPayloadSize is the wire size of an OPEN frame payload.
const OpenPayloadSize = 10

// OpenPayload is the decoded payload of an OPEN frame.
type OpenPayload struct {
	Reliability Reliability // 1 byte: delivery guarantee
	Priority    uint8       // 1 byte: initial weight (1-255)
	Dependency  uint64      // 8 bytes: parent stream ID
}

// ────────────────────────────────────────────────────────────────────────────
// RESET payload
// ────────────────────────────────────────────────────────────────────────────

// ResetPayloadSize is the wire size of a RESET frame payload.
const ResetPayloadSize = 4

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
type LatencyClass uint8

const (
	// ClassREALTIME is strict-priority, never queued behind BULK.
	// Bandwidth-capped at 10% of link to prevent abuse.
	// Use for: PING/PONG, WHOIS, RENDEZVOUS, input events, emergency policy.
	ClassREALTIME LatencyClass = 0

	// ClassINTERACTIVE is medium priority, served after REALTIME, before BULK.
	// Use for: RPC dispatch, screen key frames, tunnels, normal policy.
	ClassINTERACTIVE LatencyClass = 1

	// ClassBULK is lowest priority, gets remaining bandwidth.
	// WFQ by weight within this class.
	// Use for: gossip, telemetry, file transfer, screen deltas.
	ClassBULK LatencyClass = 2
)

// String returns a human-readable class name.
func (c LatencyClass) String() string {
	switch c {
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
	HandshakeSessionResume    HandshakeType = 2 // Resume a previously established session
	HandshakeAddressMigration HandshakeType = 3 // Connection migration (IP/port change)
	HandshakeResumeMaterial   HandshakeType = 4 // Responder → initiator delivery of ticket + keys for next-time resume
)

// HandshakePayload is the decoded payload of a HANDSHAKE frame.
type HandshakePayload struct {
	HandshakeType HandshakeType // 1 byte
	Payload       []byte        // variable: type-specific handshake data
}
