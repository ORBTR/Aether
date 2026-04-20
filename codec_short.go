/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
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
	ShortControlIndicator   byte = 0x83 // PING/PONG/CLOSE/RESET, 4 bytes
	ShortACKIndicator       byte = 0x84 // Composite ACK, 11 bytes (lite) or 3+N (full)
	ShortBatchIndicator     byte = 0x85 // Batch of sub-frames, 2 + N×sub
	ShortDataVarIndicator   byte = 0x86 // DATA frames, varint Length, 6-10 bytes
	ShortEncryptedIndicator byte = 0x87 // Encrypted DATA, 9 bytes, Nonce-in-payload

	ShortDataSize    = 9  // [indicator:1][streamID:2][seqDelta:2][length:4]
	ShortControlSize = 4  // [indicator:1][type:1][streamID:2]
	ShortACKLiteSize = 11 // [indicator:1][streamID:2][baseACK:4][ackDelay:2][bitmapLen:1][flags:1]

	// Full header sent every N frames per stream for state resync
	ShortHeaderFullInterval = 64
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
func (c *Compressor) ShouldCompressData(f *Frame) bool {
	if f.Type != TypeDATA {
		return false
	}
	if f.Flags.Has(FlagENCRYPTED) {
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
	c.Session.mu.RLock()
	defer c.Session.mu.RUnlock()
	return c.Session.identitySet &&
		f.SenderID == c.Session.lastSender &&
		f.ReceiverID == c.Session.lastReceiver
}

// ShouldCompressACK returns true if an ACK frame can use 0x84.
func (c *Compressor) ShouldCompressACK(f *Frame) bool {
	if f.Type != TypeACK {
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

// EncodeDataShort writes a 9-byte data short header + payload.
func (c *Compressor) EncodeDataShort(w io.Writer, f *Frame) (int, error) {
	s := c.GetOrCreateStream(f.StreamID)
	s.mu.Lock()
	seqDelta := uint16(f.SeqNo - s.lastSeqNo)
	s.mu.Unlock()

	var hdr [ShortDataSize]byte
	hdr[0] = ShortDataIndicator
	binary.BigEndian.PutUint16(hdr[1:3], uint16(f.StreamID))
	binary.BigEndian.PutUint16(hdr[3:5], seqDelta)
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

// DecodeDataShort reads a 9-byte data short header (indicator already consumed).
func (c *Compressor) DecodeDataShort(r io.Reader) (*Frame, error) {
	var hdr [ShortDataSize - 1]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("aether: read data short header: %w", err)
	}

	streamID := uint64(binary.BigEndian.Uint16(hdr[0:2]))
	seqDelta := binary.BigEndian.Uint16(hdr[2:4])
	length := binary.BigEndian.Uint32(hdr[4:8])

	c.Session.mu.RLock()
	sender := c.Session.lastSender
	receiver := c.Session.lastReceiver
	c.Session.mu.RUnlock()

	s := c.GetOrCreateStream(streamID)
	s.mu.Lock()
	seqNo := s.lastSeqNo + uint32(seqDelta)
	s.mu.Unlock()

	f := &Frame{
		SenderID: sender, ReceiverID: receiver,
		StreamID: streamID, Type: TypeDATA,
		SeqNo: seqNo, Length: length,
	}
	if length > 0 {
		if length > MaxPayloadSize {
			return nil, fmt.Errorf("aether: data short payload too large (%d)", length)
		}
		f.Payload = make([]byte, length)
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			return nil, fmt.Errorf("aether: read data short payload: %w", err)
		}
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
	seqDelta := uint16(f.SeqNo - s.lastSeqNo)
	s.mu.Unlock()

	var hdr [ShortDataSize]byte
	hdr[0] = ShortEncryptedIndicator
	binary.BigEndian.PutUint16(hdr[1:3], uint16(f.StreamID))
	binary.BigEndian.PutUint16(hdr[3:5], seqDelta)
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
// Control Short Header (0x83): 4 bytes
// ────────────────────────────────────────────────────────────────────────────

// EncodeControlShort writes a 4-byte control short header (no payload).
func (c *Compressor) EncodeControlShort(w io.Writer, f *Frame) (int, error) {
	var hdr [ShortControlSize]byte
	hdr[0] = ShortControlIndicator
	hdr[1] = byte(f.Type)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(f.StreamID))
	return w.Write(hdr[:])
}

// DecodeControlShort reads a 4-byte control header (indicator already consumed).
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

	// ACK-full: header + payload
	var hdr [5]byte
	hdr[0] = ShortACKIndicator
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

// DecodeACKShort reads an ACK short header (indicator already consumed).
func (c *Compressor) DecodeACKShort(r io.Reader) (*Frame, error) {
	// Read StreamID + first 8 bytes (enough for ACK-lite check)
	var hdr [10]byte // streamID(2) + potential ACK-lite payload(8)
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("aether: read ACK short header: %w", err)
	}

	c.Session.mu.RLock()
	sender := c.Session.lastSender
	receiver := c.Session.lastReceiver
	c.Session.mu.RUnlock()

	streamID := uint64(binary.BigEndian.Uint16(hdr[0:2]))

	// Check ACK-lite: BitmapLen=0 (byte 8) and Flags=0 (byte 9)
	if hdr[8] == 0 && hdr[9] == 0 {
		// ACK-lite — payload is the 8 bytes we already read
		payload := make([]byte, 8)
		copy(payload, hdr[2:10])
		return &Frame{
			SenderID: sender, ReceiverID: receiver,
			StreamID: streamID, Type: TypeACK,
			Flags:   FlagCOMPOSITE_ACK,
			AckNo:   binary.BigEndian.Uint32(hdr[2:6]),
			Length:   CompositeACKMinSize,
			Payload: payload,
		}, nil
	}

	// ACK-full — hdr[2:4] is the length, not ACK payload
	length := uint32(binary.BigEndian.Uint16(hdr[2:4]))
	if length > MaxPayloadSize {
		return nil, fmt.Errorf("aether: ACK short payload too large (%d)", length)
	}

	// We already read 8 bytes beyond streamID. The first 2 are Length.
	// The remaining 6 are the start of the payload. Read the rest.
	payload := make([]byte, length)
	alreadyRead := 6 // hdr[4:10] = 6 bytes of payload already consumed
	if alreadyRead > int(length) {
		alreadyRead = int(length)
	}
	copy(payload, hdr[4:4+alreadyRead])
	if int(length) > alreadyRead {
		if _, err := io.ReadFull(r, payload[alreadyRead:]); err != nil {
			return nil, fmt.Errorf("aether: read ACK short payload: %w", err)
		}
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
	seqDelta := uint16(f.SeqNo - s.lastSeqNo)
	s.mu.Unlock()

	var hdr [5]byte // indicator + streamID + seqDelta
	hdr[0] = ShortDataVarIndicator
	binary.BigEndian.PutUint16(hdr[1:3], uint16(f.StreamID))
	binary.BigEndian.PutUint16(hdr[3:5], seqDelta)

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
	seqDelta := binary.BigEndian.Uint16(hdr[2:4])

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
	seqNo := s.lastSeqNo + uint32(seqDelta)
	s.mu.Unlock()

	f := &Frame{
		SenderID: sender, ReceiverID: receiver,
		StreamID: streamID, Type: TypeDATA,
		SeqNo: seqNo, Length: length,
	}
	if length > 0 {
		if length > MaxPayloadSize {
			return nil, fmt.Errorf("aether: varint payload too large (%d)", length)
		}
		f.Payload = make([]byte, length)
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			return nil, err
		}
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
		case ShortDataVarIndicator:
			f, err = c.DecodeDataShortVar(r)
		case ShortEncryptedIndicator:
			f, err = c.DecodeEncryptedDataShort(r)
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
