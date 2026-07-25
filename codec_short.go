/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 *
 * Short Header v2 Compression System
 *
 * Replaces the v1 delta-based short header (0xFF/0x80) which had 4 critical bugs:
 *   1. Non-DATA frames compressed → decoded as wrong type
 *   2. uint16 Length overflow → stream misalignment on payloads > 65535
 *   3. Cross-stream delta corruption → frames routed to wrong stream
 *   4. Per-session state → encoder/decoder desync on interleaved streams
 *
 * v2 uses per-stream state, explicit uint16 StreamID, and format-specific
 * indicators for each frame type. No backward compatibility with v1.
 */
package aether

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"
)

// ────────────────────────────────────────────────────────────────────────────
// Indicator bytes — first byte of every frame determines the format
// ────────────────────────────────────────────────────────────────────────────

const (
	// 0x00-0x7F: Full 50-byte header (SenderID[0] is always < 0x80 for VL1 NodeIDs)

	ShortDataIndicator      byte = 0x82 // DATA frames, 9 bytes, uint32 Length
	ShortControlIndicator   byte = 0x83 // PING/PONG/CLOSE/RESET, 8 bytes
	ShortACKIndicator       byte = 0x84 // Composite ACK-lite, 11 bytes
	ShortBatchIndicator     byte = 0x85 // Batch of sub-frames, 2 + N×sub
	ShortDataVarIndicator   byte = 0x86 // DATA frames, varint Length, 6-10 bytes
	ShortEncryptedIndicator byte = 0x87 // Encrypted DATA, 9 bytes, Nonce-in-payload
	// AE-H-13: ACK-full carries its own indicator so the decoder never has
	// to infer lite-vs-full from payload bytes (a full ACK with AckDelay==0
	// was mis-decoded as lite and desynced the stream).
	ShortACKFullIndicator byte = 0x88 // Composite ACK-full, 5-byte hdr + payload

	ShortDataSize    = 9  // [indicator:1][streamID:2][seqDelta:2][length:4]
	ShortControlSize = 8  // [indicator:1][type:1][streamID:2][seqNo:4]
	ShortACKLiteSize = 11 // [indicator:1][streamID:2][baseACK:4][ackDelay:2][bitmapLen:1][flags:1]

	// Full header sent every N frames per stream for state resync
	ShortHeaderFullInterval = 64

	// MaxShortHeaderStreamID is the largest StreamID representable in the uint16
	// short-header StreamID field. Streams above it must use the full 50-byte
	// header, else the ID truncates on the wire and the decoder misroutes the
	// frame to the wrong stream (AE-H-14).
	MaxShortHeaderStreamID = 0xFFFF
)

// IsShortHeader returns true if the first byte indicates any v2 short header.
func IsShortHeader(firstByte byte) bool {
	return firstByte >= 0x82 && firstByte <= 0x8F
}

// ────────────────────────────────────────────────────────────────────────────
// Per-stream and session state
// ────────────────────────────────────────────────────────────────────────────

// StreamCompState tracks per-stream compression state for SeqNo deltas.
type StreamCompState struct {
	mu         sync.Mutex
	lastSeqNo  uint32
	frameCount int
}

// SessionCompState tracks session-level identity shared across all streams.
type SessionCompState struct {
	mu               sync.RWMutex
	lastSender       PeerID
	lastReceiver     PeerID
	globalFrameCount uint64
	identitySet      bool
}

// Compressor manages short header compression for a session.
// Combines session-level identity with per-stream SeqNo tracking.
type Compressor struct {
	Session *SessionCompState
	streams sync.Map // map[uint64]*StreamCompState
}

// NewCompressor creates a new v2 compressor.
func NewCompressor() *Compressor {
	return &Compressor{Session: &SessionCompState{}}
}

// GetOrCreateStream returns per-stream state, creating if needed.
func (c *Compressor) GetOrCreateStream(streamID uint64) *StreamCompState {
	if v, ok := c.streams.Load(streamID); ok {
		return v.(*StreamCompState)
	}
	s := &StreamCompState{}
	actual, _ := c.streams.LoadOrStore(streamID, s)
	return actual.(*StreamCompState)
}

// RemoveStream cleans up state for a closed stream.
func (c *Compressor) RemoveStream(streamID uint64) {
	c.streams.Delete(streamID)
}

// RecordFullHeader updates both session and stream state after a full header.
func (c *Compressor) RecordFullHeader(f *Frame) {
	c.Session.mu.Lock()
	c.Session.lastSender = f.SenderID
	c.Session.lastReceiver = f.ReceiverID
	c.Session.globalFrameCount++
	c.Session.identitySet = true
	c.Session.mu.Unlock()

	s := c.GetOrCreateStream(f.StreamID)
	s.mu.Lock()
	s.lastSeqNo = f.SeqNo
	s.frameCount++
	s.mu.Unlock()
}

// ────────────────────────────────────────────────────────────────────────────
// Compression decision
// ────────────────────────────────────────────────────────────────────────────

// ShouldCompressData returns true if a DATA frame can use 0x82/0x86.
// Encrypted frames (FlagENCRYPTED) must use 0x87 via the adapter's explicit
// encrypted path — ShouldCompressData rejects them to prevent accidental
// encoding as unencrypted 0x82.
//
// GENERAL RULE for the short forms: they have no Flags field, so ANY frame whose
// correct interpretation depends on a flag must take the full header. Today that
// means FlagENCRYPTED and FlagCOMPRESSED; a new flag that changes how the payload
// is read must be added here too, or it will be lost on the wire in silence.
func (c *Compressor) ShouldCompressData(f *Frame) bool {
	if f.Type != TypeDATA {
		return false
	}
	if f.Flags.Has(FlagENCRYPTED) {
		return false
	}
	// B3: the short DATA forms (0x82/0x86) carry NO Flags field, so a frame whose
	// payload is only interpretable WITH a flag cannot be expressed in them. The
	// receiver decompresses solely on FlagCOMPRESSED, so encoding a deflated
	// payload short drops the flag and hands the application raw DEFLATE bytes —
	// and because Length matches the compressed length, Validate() passes, no
	// guard trips and no abuse counter increments, making the corruption silent
	// (it surfaces downstream as an unmarshal error blamed on the consumer's
	// decoder). Fall back to the full header, which carries flags — same
	// capability-preserving fallback as AE-H-14 below. See M-108 (root cause),
	// M-134 (fix), and codec_short_b3_test.go (executable reproduction).
	if f.Flags.Has(FlagCOMPRESSED) {
		return false
	}
	// AE-H-14: the short-header StreamID field is uint16; a stream above
	// MaxShortHeaderStreamID would truncate on the wire and misroute on decode.
	// Fall back to the full 50-byte header (capability preserved) rather than
	// compress and corrupt routing.
	if f.StreamID > MaxShortHeaderStreamID {
		return false
	}
	c.Session.mu.RLock()
	if !c.Session.identitySet ||
		f.SenderID != c.Session.lastSender ||
		f.ReceiverID != c.Session.lastReceiver {
		c.Session.mu.RUnlock()
		return false
	}
	c.Session.mu.RUnlock()

	v, ok := c.streams.Load(f.StreamID)
	if !ok {
		return false // first frame on stream — must be full
	}
	s := v.(*StreamCompState)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.frameCount == 0 || s.frameCount%ShortHeaderFullInterval == 0 {
		return false // periodic resync
	}
	seqDelta := int64(f.SeqNo) - int64(s.lastSeqNo)
	return seqDelta >= 0 && seqDelta <= 65535
}

// ShouldCompressControl returns true if a control frame can use 0x83.
func (c *Compressor) ShouldCompressControl(f *Frame) bool {
	switch f.Type {
	case TypePING, TypePONG, TypeCLOSE, TypeRESET:
	default:
		return false
	}
	if f.Length > 0 {
		return false // has payload — use full header
	}
	// AE-H-14: uint16 short-header StreamID — oversized streams need the full header.
	if f.StreamID > MaxShortHeaderStreamID {
		return false
	}
	c.Session.mu.RLock()
	defer c.Session.mu.RUnlock()
	return c.Session.identitySet &&
		f.SenderID == c.Session.lastSender &&
		f.ReceiverID == c.Session.lastReceiver
}

// ShouldCompressACK returns true if an ACK frame can use 0x84.
//
// Subject to the same general rule as ShouldCompressData: the short forms have no
// Flags field, so a frame whose interpretation depends on a flag must take the
// full header.
func (c *Compressor) ShouldCompressACK(f *Frame) bool {
	if f.Type != TypeACK {
		return false
	}
	// B2: the ACK short forms carry no Flags field, and DecodeACKShortFull
	// reconstructs the Frame with Flags HARDCODED to FlagCOMPOSITE_ACK — so
	// FlagCOMPRESSED is not merely absent, it is overwritten. The receiver then
	// parses a raw DEFLATE stream as a CompositeACK: the high-entropy byte at the
	// BitmapLen offset usually exceeds the remaining length, DecodeCompositeACK
	// returns nil, and the peer is charged ReasonACKValidation for a well-formed
	// ACK. The v0.0.114 SACK fix made this reachable in the steady state by
	// routing mid-stream-gap recovery through bitmap-bearing ACKs, which are the
	// ones large enough to cross the 64-byte compression gate. Fall back to the
	// full header, which carries flags. See M-108 (root cause), M-111 (mapping).
	if f.Flags.Has(FlagCOMPRESSED) {
		return false
	}
	// AE-H-14: uint16 short-header StreamID — oversized streams need the full header.
	if f.StreamID > MaxShortHeaderStreamID {
		return false
	}
	// AER-053: the ACK-full short form carries a 2-byte length. A frame whose
	// Length exceeds 65535 would wrap that field while its full payload was
	// still written, desyncing the decoder byte stream. Fall back to the full
	// header for such frames (today's CompositeACK is <= ~375 B, so latent).
	if f.Length > 0xFFFF {
		return false
	}
	c.Session.mu.RLock()
	defer c.Session.mu.RUnlock()
	return c.Session.identitySet &&
		f.SenderID == c.Session.lastSender &&
		f.ReceiverID == c.Session.lastReceiver
}

// ────────────────────────────────────────────────────────────────────────────
// Data Short Header (0x82): 9 bytes
// ────────────────────────────────────────────────────────────────────────────

// reconstructSeqNo recovers a full 32-bit sequence number from the low 16
// bits carried on the wire, choosing the candidate closest to the expected
// next sequence number (QUIC packet-number decoding, RFC 9000 §A.3).
//
// AER-047: short DATA headers carry the low 16 bits of the ABSOLUTE SeqNo,
// not a delta from the previously decoded frame. Delta chaining assumed
// every short frame arrived in order — on lossy/reordering Noise-UDP a single
// dropped datagram left the decoder's reference stale, so the next frame's
// delta reconstructed the WRONG absolute seq and its payload was delivered
// under a lost frame's sequence number (silent transposition), while the real
// frame's retransmit was then dropped as a duplicate. Absolute-low-bits +
// closest-to-expected reconstruction tolerates any gap < 32768 with no chain.
func reconstructSeqNo(expected uint32, low uint16) uint32 {
	candidate := (expected & 0xFFFF0000) | uint32(low)
	if candidate < expected {
		if expected-candidate > 0x8000 {
			candidate += 0x10000
		}
	} else if candidate-expected > 0x8000 && candidate >= 0x10000 {
		candidate -= 0x10000
	}
	return candidate
}

// EncodeDataShort writes a 9-byte data short header + payload.
func (c *Compressor) EncodeDataShort(w io.Writer, f *Frame) (int, error) {
	s := c.GetOrCreateStream(f.StreamID)
	s.mu.Lock()
	seqLow := uint16(f.SeqNo) // AER-047: absolute low 16 bits, not a delta
	s.mu.Unlock()

	var hdr [ShortDataSize]byte
	hdr[0] = ShortDataIndicator
	binary.BigEndian.PutUint16(hdr[1:3], uint16(f.StreamID))
	binary.BigEndian.PutUint16(hdr[3:5], seqLow)
	binary.BigEndian.PutUint32(hdr[5:9], f.Length)

	n, err := w.Write(hdr[:])
	if err != nil {
		return n, fmt.Errorf("aether: write data short header: %w", err)
	}
	if f.Length > 0 && len(f.Payload) > 0 {
		pn, err := w.Write(f.Payload[:f.Length])
		n += pn
		if err != nil {
			return n, fmt.Errorf("aether: write data short payload: %w", err)
		}
	}

	s.mu.Lock()
	s.lastSeqNo = f.SeqNo
	s.frameCount++
	s.mu.Unlock()
	return n, nil
}

// maxShortPayloadPrealloc bounds how many bytes a short-header DATA decoder
// allocates from a peer's declared length before the peer proves it is actually
// delivering the body. The declared length (up to MaxPayloadSize) is honoured in
// full only after a first chunk of this size has been read, so a tiny header
// claiming MaxPayloadSize that never sends a body cannot force a transient
// full-size heap allocation (AE-P-31). Capability preserved: payloads up to
// MaxPayloadSize still decode in full.
const maxShortPayloadPrealloc = 64 * 1024

// readShortPayload reads exactly length bytes from r. For a declared length above
// maxShortPayloadPrealloc it first reads a bounded chunk into a small buffer as
// proof of delivery before allocating the full declared size (AE-P-31), so a peer
// that streams tiny headers declaring huge lengths cannot drive repeated 16 MB
// allocations at negligible cost.
func readShortPayload(r io.Reader, length uint32) ([]byte, error) {
	if length <= maxShortPayloadPrealloc {
		buf := make([]byte, length)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		return buf, nil
	}
	head := make([]byte, maxShortPayloadPrealloc)
	if _, err := io.ReadFull(r, head); err != nil {
		return nil, err
	}
	buf := make([]byte, length)
	copy(buf, head)
	if _, err := io.ReadFull(r, buf[maxShortPayloadPrealloc:]); err != nil {
		return nil, err
	}
	return buf, nil
}

// DecodeDataShort reads a 9-byte data short header (indicator already consumed).
func (c *Compressor) DecodeDataShort(r io.Reader) (*Frame, error) {
	var hdr [ShortDataSize - 1]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("aether: read data short header: %w", err)
	}

	streamID := uint64(binary.BigEndian.Uint16(hdr[0:2]))
	seqLow := binary.BigEndian.Uint16(hdr[2:4])
	length := binary.BigEndian.Uint32(hdr[4:8])

	c.Session.mu.RLock()
	sender := c.Session.lastSender
	receiver := c.Session.lastReceiver
	c.Session.mu.RUnlock()

	s := c.GetOrCreateStream(streamID)
	s.mu.Lock()
	// AER-047: reconstruct the absolute seq from the low 16 bits + the
	// expected next seq, rather than chaining a delta off lastSeqNo.
	seqNo := reconstructSeqNo(s.lastSeqNo+1, seqLow)
	s.mu.Unlock()

	f := &Frame{
		SenderID: sender, ReceiverID: receiver,
		StreamID: streamID, Type: TypeDATA,
		SeqNo: seqNo, Length: length,
		// B3: Flags is set EXPLICITLY to zero, not left implicit. The short DATA
		// forms carry no Flags field, so zero is the only honest value — and
		// ShouldCompressData now refuses any flag-dependent frame onto this path,
		// so a payload arriving here is plaintext by construction. Do NOT hardcode
		// a flag here: DecodeACKShortFull hardcodes FlagCOMPOSITE_ACK and that is
		// exactly how B2 loses FlagCOMPRESSED. See M-108/M-134.
		Flags: 0,
	}
	if length > 0 {
		if length > MaxPayloadSize {
			return nil, fmt.Errorf("aether: data short payload too large (%d)", length)
		}
		// AE-P-31: read incrementally so a 9-byte header declaring up to
		// MaxPayloadSize cannot force a full-size allocation before the body exists.
		p, err := readShortPayload(r, length)
		if err != nil {
			return nil, fmt.Errorf("aether: read data short payload: %w", err)
		}
		f.Payload = p
	}

	s.mu.Lock()
	s.lastSeqNo = seqNo
	s.frameCount++
	s.mu.Unlock()
	return f, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Encrypted Data Short Header (0x87): 9 bytes + Nonce-in-payload
// ────────────────────────────────────────────────────────────────────────────

// EncodeEncryptedDataShort writes a 9-byte header for an encrypted DATA frame.
// The payload must already be wrapped as [Nonce:12][Ciphertext][Tag:16].
// Same wire format as 0x82 but the indicator tells the decoder to extract
// the Nonce from the payload prefix before decryption.
func (c *Compressor) EncodeEncryptedDataShort(w io.Writer, f *Frame) (int, error) {
	s := c.GetOrCreateStream(f.StreamID)
	s.mu.Lock()
	seqLow := uint16(f.SeqNo) // AER-047: absolute low 16 bits, not a delta
	s.mu.Unlock()

	var hdr [ShortDataSize]byte
	hdr[0] = ShortEncryptedIndicator
	binary.BigEndian.PutUint16(hdr[1:3], uint16(f.StreamID))
	binary.BigEndian.PutUint16(hdr[3:5], seqLow)
	binary.BigEndian.PutUint32(hdr[5:9], f.Length)

	n, err := w.Write(hdr[:])
	if err != nil {
		return n, fmt.Errorf("aether: write encrypted short header: %w", err)
	}
	if f.Length > 0 && len(f.Payload) > 0 {
		pn, err := w.Write(f.Payload[:f.Length])
		n += pn
		if err != nil {
			return n, fmt.Errorf("aether: write encrypted short payload: %w", err)
		}
	}

	s.mu.Lock()
	s.lastSeqNo = f.SeqNo
	s.frameCount++
	s.mu.Unlock()
	return n, nil
}

// DecodeEncryptedDataShort reads a 9-byte encrypted data header (indicator consumed).
// The returned Frame has the raw encrypted payload including Nonce prefix.
// The caller must extract Nonce from payload[:12] before decryption.
func (c *Compressor) DecodeEncryptedDataShort(r io.Reader) (*Frame, error) {
	// Same wire layout as 0x82 — reuse DecodeDataShort logic
	return c.DecodeDataShort(r)
}

// ────────────────────────────────────────────────────────────────────────────
// Control Short Header (0x83): 8 bytes — AE-L-13
// Layout: [indicator:1][type:1][streamID:2][seqNo:4] (see ShortControlSize=8).
// This banner previously claimed 4 bytes, diverging from the constant and the
// encode/decode path. SeqNo is carried on the wire so PING<->PONG RTT
// correlation works; do NOT drop it back to 4 bytes (freezes the RTO estimator).
// ────────────────────────────────────────────────────────────────────────────

// EncodeControlShort writes an 8-byte control short header (no payload).
// Layout: [indicator:1][type:1][streamID:2][seqNo:4]. The seqNo round-
// trips PING <-> PONG so the receiver's pendingPingSeq gate in
// RecordPongRecv can correlate the matching pong and feed an RTT sample
// to the RFC 6298 estimator. Earlier 4-byte revisions dropped seqNo on
// the wire, leaving the estimator permanently at its InitialRTO seed.
func (c *Compressor) EncodeControlShort(w io.Writer, f *Frame) (int, error) {
	var hdr [ShortControlSize]byte
	hdr[0] = ShortControlIndicator
	hdr[1] = byte(f.Type)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(f.StreamID))
	binary.BigEndian.PutUint32(hdr[4:8], f.SeqNo)
	return w.Write(hdr[:])
}

// DecodeControlShort reads an 8-byte control header (indicator already
// consumed). Layout: [type:1][streamID:2][seqNo:4]. SeqNo is preserved
// so RecordPongRecv can match the inbound PONG against pendingPingSeq.
func (c *Compressor) DecodeControlShort(r io.Reader) (*Frame, error) {
	var hdr [ShortControlSize - 1]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("aether: read control short header: %w", err)
	}

	c.Session.mu.RLock()
	sender := c.Session.lastSender
	receiver := c.Session.lastReceiver
	c.Session.mu.RUnlock()

	return &Frame{
		SenderID:   sender,
		ReceiverID: receiver,
		Type:       FrameType(hdr[0]),
		StreamID:   uint64(binary.BigEndian.Uint16(hdr[1:3])),
		SeqNo:      binary.BigEndian.Uint32(hdr[3:7]),
	}, nil
}

// ────────────────────────────────────────────────────────────────────────────
// ACK Short Header (0x84): 11 bytes (lite) or 3+N bytes (full)
// ────────────────────────────────────────────────────────────────────────────

// EncodeACKShort writes a compressed ACK frame.
// ACK-lite (BitmapLen=0, Flags=0): inlined at 11 bytes.
// ACK-full: 3-byte header + payload.
func (c *Compressor) EncodeACKShort(w io.Writer, f *Frame) (int, error) {
	// Check if ACK-lite (payload is exactly CompositeACKMinSize = 8 bytes
	// and last two bytes are both 0 = BitmapLen=0, Flags=0)
	if f.Length == CompositeACKMinSize && len(f.Payload) >= 8 &&
		f.Payload[6] == 0 && f.Payload[7] == 0 {
		// ACK-lite: inline the 8-byte payload
		var hdr [ShortACKLiteSize]byte
		hdr[0] = ShortACKIndicator
		binary.BigEndian.PutUint16(hdr[1:3], uint16(f.StreamID))
		copy(hdr[3:11], f.Payload[:8])
		return w.Write(hdr[:])
	}

	// ACK-full: distinct indicator (AE-H-13) + header + payload
	var hdr [5]byte
	hdr[0] = ShortACKFullIndicator
	binary.BigEndian.PutUint16(hdr[1:3], uint16(f.StreamID))
	binary.BigEndian.PutUint16(hdr[3:5], uint16(f.Length))
	n, err := w.Write(hdr[:])
	if err != nil {
		return n, err
	}
	pn, err := w.Write(f.Payload[:f.Length])
	n += pn
	return n, err
}

// DecodeACKShort reads an ACK-lite short header (0x84 indicator already
// consumed). AE-H-13: lite and full ACKs now use distinct indicators
// (0x84 vs ShortACKFullIndicator 0x88), so this path unconditionally
// decodes the 11-byte lite form and never infers the layout from payload
// bytes — a full ACK with AckDelay==0 previously matched the lite
// discriminator here and desynced the byte stream.
func (c *Compressor) DecodeACKShort(r io.Reader) (*Frame, error) {
	var hdr [ShortACKLiteSize - 1]byte // streamID(2) + payload(8)
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("aether: read ACK short header: %w", err)
	}

	c.Session.mu.RLock()
	sender := c.Session.lastSender
	receiver := c.Session.lastReceiver
	c.Session.mu.RUnlock()

	streamID := uint64(binary.BigEndian.Uint16(hdr[0:2]))
	payload := make([]byte, CompositeACKMinSize)
	copy(payload, hdr[2:2+CompositeACKMinSize])
	return &Frame{
		SenderID: sender, ReceiverID: receiver,
		StreamID: streamID, Type: TypeACK,
		Flags:   FlagCOMPOSITE_ACK,
		AckNo:   binary.BigEndian.Uint32(hdr[2:6]),
		Length:  CompositeACKMinSize,
		Payload: payload,
	}, nil
}

// DecodeACKShortFull reads an ACK-full short header (0x88 indicator already
// consumed). Layout: [streamID:2][length:2][payload:length]. AE-H-13: the
// dedicated indicator removes the lite/full ambiguity, so the decoder no
// longer guesses the layout from AckDelay/BitmapLen/Flags byte values.
func (c *Compressor) DecodeACKShortFull(r io.Reader) (*Frame, error) {
	var hdr [4]byte // streamID(2) + length(2)
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("aether: read ACK full short header: %w", err)
	}

	c.Session.mu.RLock()
	sender := c.Session.lastSender
	receiver := c.Session.lastReceiver
	c.Session.mu.RUnlock()

	streamID := uint64(binary.BigEndian.Uint16(hdr[0:2]))
	length := uint32(binary.BigEndian.Uint16(hdr[2:4]))
	if length > MaxPayloadSize {
		return nil, fmt.Errorf("aether: ACK short payload too large (%d)", length)
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("aether: read ACK short payload: %w", err)
	}

	return &Frame{
		SenderID: sender, ReceiverID: receiver,
		StreamID: streamID, Type: TypeACK,
		Flags:   FlagCOMPOSITE_ACK,
		Length:  length,
		Payload: payload,
	}, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Varint helpers
// ────────────────────────────────────────────────────────────────────────────

// EncodeVarLength writes a variable-length uint32.
//
//	0-127:     1 byte  (value literal)
//	128-16383: 2 bytes (0x80|high, low)
//	16384+:    5 bytes (0xFF, uint32 big-endian)
func EncodeVarLength(w io.Writer, v uint32) (int, error) {
	if v <= 127 {
		return w.Write([]byte{byte(v)})
	}
	if v <= 16383 {
		return w.Write([]byte{byte(0x80 | (v >> 8)), byte(v & 0xFF)})
	}
	var buf [5]byte
	buf[0] = 0xFF
	binary.BigEndian.PutUint32(buf[1:5], v)
	return w.Write(buf[:])
}

// DecodeVarLength reads a variable-length uint32.
func DecodeVarLength(r io.Reader) (uint32, int, error) {
	var first [1]byte
	if _, err := io.ReadFull(r, first[:]); err != nil {
		return 0, 0, err
	}
	if first[0] <= 0x7F {
		return uint32(first[0]), 1, nil
	}
	if first[0] != 0xFF {
		var second [1]byte
		if _, err := io.ReadFull(r, second[:]); err != nil {
			return 0, 1, err
		}
		return uint32(first[0]&0x7F)<<8 | uint32(second[0]), 2, nil
	}
	var buf [4]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, 1, err
	}
	return binary.BigEndian.Uint32(buf[:]), 5, nil
}

// VarLengthSize returns how many bytes a varint would use.
func VarLengthSize(v uint32) int {
	if v <= 127 {
		return 1
	}
	if v <= 16383 {
		return 2
	}
	return 5
}

// ────────────────────────────────────────────────────────────────────────────
// Data Short Varint Header (0x86): 6-10 bytes
// ────────────────────────────────────────────────────────────────────────────

// EncodeDataShortVar writes a varint-length data short header + payload.
func (c *Compressor) EncodeDataShortVar(w io.Writer, f *Frame) (int, error) {
	s := c.GetOrCreateStream(f.StreamID)
	s.mu.Lock()
	seqLow := uint16(f.SeqNo) // AER-047: absolute low 16 bits, not a delta
	s.mu.Unlock()

	var hdr [5]byte // indicator + streamID + seqLow
	hdr[0] = ShortDataVarIndicator
	binary.BigEndian.PutUint16(hdr[1:3], uint16(f.StreamID))
	binary.BigEndian.PutUint16(hdr[3:5], seqLow)

	n, err := w.Write(hdr[:])
	if err != nil {
		return n, err
	}
	vn, err := EncodeVarLength(w, f.Length)
	n += vn
	if err != nil {
		return n, err
	}
	if f.Length > 0 && len(f.Payload) > 0 {
		pn, err := w.Write(f.Payload[:f.Length])
		n += pn
		if err != nil {
			return n, err
		}
	}

	s.mu.Lock()
	s.lastSeqNo = f.SeqNo
	s.frameCount++
	s.mu.Unlock()
	return n, nil
}

// DecodeDataShortVar reads a varint-length data short header (indicator consumed).
func (c *Compressor) DecodeDataShortVar(r io.Reader) (*Frame, error) {
	var hdr [4]byte // streamID + seqDelta
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}

	streamID := uint64(binary.BigEndian.Uint16(hdr[0:2]))
	seqLow := binary.BigEndian.Uint16(hdr[2:4])

	length, _, err := DecodeVarLength(r)
	if err != nil {
		return nil, err
	}

	c.Session.mu.RLock()
	sender := c.Session.lastSender
	receiver := c.Session.lastReceiver
	c.Session.mu.RUnlock()

	s := c.GetOrCreateStream(streamID)
	s.mu.Lock()
	// AER-047: reconstruct the absolute seq from the low 16 bits + expected.
	seqNo := reconstructSeqNo(s.lastSeqNo+1, seqLow)
	s.mu.Unlock()

	f := &Frame{
		SenderID: sender, ReceiverID: receiver,
		StreamID: streamID, Type: TypeDATA,
		SeqNo: seqNo, Length: length,
		// B3: Flags is set EXPLICITLY to zero, not left implicit. The short DATA
		// forms carry no Flags field, so zero is the only honest value — and
		// ShouldCompressData now refuses any flag-dependent frame onto this path,
		// so a payload arriving here is plaintext by construction. Do NOT hardcode
		// a flag here: DecodeACKShortFull hardcodes FlagCOMPOSITE_ACK and that is
		// exactly how B2 loses FlagCOMPRESSED. See M-108/M-134.
		Flags: 0,
	}
	if length > 0 {
		if length > MaxPayloadSize {
			return nil, fmt.Errorf("aether: varint payload too large (%d)", length)
		}
		// AE-P-31: read incrementally so a tiny varint header declaring up to
		// MaxPayloadSize cannot force a full-size allocation before the body exists.
		p, err := readShortPayload(r, length)
		if err != nil {
			return nil, err
		}
		f.Payload = p
	}

	s.mu.Lock()
	s.lastSeqNo = seqNo
	s.frameCount++
	s.mu.Unlock()
	return f, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Batch Header (0x85): 2 + N×(sub-header + payload)
// ────────────────────────────────────────────────────────────────────────────

// EncodeBatch writes multiple frames as a single batch.
func (c *Compressor) EncodeBatch(w io.Writer, frames []*Frame) (int, error) {
	if len(frames) == 0 || len(frames) > 255 {
		return 0, fmt.Errorf("aether: invalid batch size %d", len(frames))
	}
	hdr := [2]byte{ShortBatchIndicator, byte(len(frames))}
	n, err := w.Write(hdr[:])
	if err != nil {
		return n, err
	}
	for _, f := range frames {
		var pn int
		var perr error
		switch {
		case c.ShouldCompressControl(f):
			pn, perr = c.EncodeControlShort(w, f)
		case c.ShouldCompressACK(f):
			pn, perr = c.EncodeACKShort(w, f)
		case c.ShouldCompressData(f) && f.Length <= 127:
			pn, perr = c.EncodeDataShortVar(w, f)
		case c.ShouldCompressData(f):
			pn, perr = c.EncodeDataShort(w, f)
		default:
			pn, perr = EncodeFrame(w, f)
			if perr == nil {
				c.RecordFullHeader(f)
			}
		}
		n += pn
		if perr != nil {
			return n, perr
		}
	}
	return n, nil
}

// DecodeBatch reads a batch of sub-frames (indicator already consumed).
func (c *Compressor) DecodeBatch(r io.Reader) ([]*Frame, error) {
	var countBuf [1]byte
	if _, err := io.ReadFull(r, countBuf[:]); err != nil {
		return nil, err
	}
	count := int(countBuf[0])
	frames := make([]*Frame, 0, count)

	for i := 0; i < count; i++ {
		var peek [1]byte
		if _, err := io.ReadFull(r, peek[:]); err != nil {
			return frames, err
		}
		var f *Frame
		var err error
		switch peek[0] {
		case ShortDataIndicator:
			f, err = c.DecodeDataShort(r)
		case ShortControlIndicator:
			f, err = c.DecodeControlShort(r)
		case ShortACKIndicator:
			f, err = c.DecodeACKShort(r)
		case ShortACKFullIndicator:
			f, err = c.DecodeACKShortFull(r)
		case ShortDataVarIndicator:
			f, err = c.DecodeDataShortVar(r)
		case ShortEncryptedIndicator:
			// AE-P-27: reject 0x87 encrypted-data-short sub-frames inside a
			// batch. The honest encoder never batches encrypted frames —
			// EncodeBatch routes DATA through ShouldCompressData, which
			// excludes FlagENCRYPTED (see ShouldCompressData) — so a batched
			// 0x87 can only come from a crafted or buggy peer. If decoded it
			// yields a Type=DATA frame with no FlagENCRYPTED, while the outer
			// batch indicator (0x85) is what reaches processIncomingFrame;
			// neither decrypt gate (noise_dispatch.go indicator==0x87 /
			// FlagENCRYPTED) fires, so the raw [Nonce||Ciphertext||Tag]
			// payload would be delivered undecrypted. Fail closed rather than
			// surface un-decrypted bytes to the app.
			return frames, fmt.Errorf("aether: encrypted-data-short (0x87) sub-frame not allowed in batch")
		default:
			f, err = DecodeFrameWithFirstByte(r, peek[0])
			if err == nil {
				c.RecordFullHeader(f)
			}
		}
		if err != nil {
			return frames, err
		}
		frames = append(frames, f)
	}
	return frames, nil
}
