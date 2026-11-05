/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package aether

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// payloadPool reduces GC pressure from per-frame []byte allocations.
// Payloads are returned to the pool once the frame is done with.
var payloadPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 0, 16*1024) // 16 KB initial capacity
		return &b
	},
}

// GetPayloadBuf returns a pooled byte slice with at least n bytes capacity.
func GetPayloadBuf(n int) []byte {
	bp := payloadPool.Get().(*[]byte)
	b := *bp
	if cap(b) < n {
		b = make([]byte, n)
	} else {
		b = b[:n]
	}
	return b
}

// PutPayloadBuf returns a byte slice to the pool.
func PutPayloadBuf(b []byte) {
	if cap(b) > 256*1024 {
		return // don't pool oversized buffers
	}
	b = b[:0]
	payloadPool.Put(&b)
}

// FullFrameDiscriminator is the first byte of every full frame in the frame
// grammar WireVersionFrame names, at WireVersionFrameCurrent. The 50-byte header follows it
// unchanged. ReadNextFrame tells a full frame from a short form by this byte
// alone, so no header field, SenderID[0] included, is ever read as a form.
const FullFrameDiscriminator byte = 0x01

// FullFrameHeaderWireSize is the bytes a full frame occupies before its
// payload: the discriminator and the header.
const FullFrameHeaderWireSize = 1 + HeaderSize

// ErrFrameDiscriminator is the refusal of a frame whose first byte is not a
// form the session's grammar reads: anything but FullFrameDiscriminator, and
// the short forms when the session did not choose WireVersionFrameShort.
// errors.Is matches it on a *FrameDiscriminatorError.
var ErrFrameDiscriminator = errors.New("aether: frame discriminator refused")

// FrameDiscriminatorError names the first byte a decoder refused and whether
// the session's grammar had the short forms at the time. The decoders return
// it after reading only that byte. The TCP and Noise read loops end the
// session with it.
type FrameDiscriminatorError struct {
	Discriminator byte
	ShortForms    bool
}

func (e *FrameDiscriminatorError) Error() string {
	return fmt.Sprintf("%v: first byte 0x%02x (short forms negotiated: %v)", ErrFrameDiscriminator, e.Discriminator, e.ShortForms)
}

// Is lets errors.Is(err, ErrFrameDiscriminator) match.
func (e *FrameDiscriminatorError) Is(target error) bool { return target == ErrFrameDiscriminator }

// putFullFrameHeader writes the discriminator and the header of f into
// hdr, which must hold FullFrameHeaderWireSize bytes.
func putFullFrameHeader(hdr []byte, f *Frame) {
	hdr[0] = FullFrameDiscriminator
	h := hdr[1:FullFrameHeaderWireSize]
	copy(h[0:8], f.SenderID[:])
	copy(h[8:16], f.ReceiverID[:])
	binary.BigEndian.PutUint64(h[16:24], f.StreamID)
	h[24] = byte(f.Type)
	h[25] = byte(f.Flags)
	binary.BigEndian.PutUint32(h[26:30], f.SeqNo)
	binary.BigEndian.PutUint32(h[30:34], f.AckNo)
	binary.BigEndian.PutUint32(h[34:38], f.Length)
	copy(h[38:50], f.Nonce[:])
}

// parseHeader reads the 50 header bytes that follow a full frame's
// discriminator into a new Frame, payload not yet read.
func parseHeader(h []byte) *Frame {
	f := &Frame{}
	copy(f.SenderID[:], h[0:8])
	copy(f.ReceiverID[:], h[8:16])
	f.StreamID = binary.BigEndian.Uint64(h[16:24])
	f.Type = FrameType(h[24])
	f.Flags = FrameFlags(h[25])
	f.SeqNo = binary.BigEndian.Uint32(h[26:30])
	f.AckNo = binary.BigEndian.Uint32(h[30:34])
	f.Length = binary.BigEndian.Uint32(h[34:38])
	copy(f.Nonce[:], h[38:50])
	return f
}

// EncodeFrame writes f as a full frame to w: FullFrameDiscriminator, the
// header, then the payload. It returns the bytes written. The TCP and Noise
// write paths, and EncodeBatch for a child no short form can carry, call it.
func EncodeFrame(w io.Writer, f *Frame) (int, error) {
	var hdr [FullFrameHeaderWireSize]byte
	putFullFrameHeader(hdr[:], f)

	n, err := w.Write(hdr[:])
	if err != nil {
		return n, fmt.Errorf("aether: write header: %w", err)
	}

	if f.Length > 0 && len(f.Payload) > 0 {
		pn, err := w.Write(f.Payload[:f.Length])
		n += pn
		if err != nil {
			return n, fmt.Errorf("aether: write payload: %w", err)
		}
	}

	return n, nil
}

// EncodeFrameToBytes returns f as a full frame in one slice, the form
// EncodeFrame writes. The Noise resume path sends it as one datagram.
func EncodeFrameToBytes(f *Frame) []byte {
	buf := make([]byte, FullFrameHeaderWireSize+len(f.Payload))
	putFullFrameHeader(buf, f)
	copy(buf[FullFrameHeaderWireSize:], f.Payload)
	return buf
}

// DecodeFrameFromBytes reads one full frame from data, which must begin with
// FullFrameDiscriminator; any other first byte is a *FrameDiscriminatorError.
// The payload aliases data and holds exactly the header's Length; a Length
// past MaxPayloadSize or past the bytes present is refused, so a consumer that
// trusts Length never reads beyond the payload.
func DecodeFrameFromBytes(data []byte) (*Frame, error) {
	if len(data) > 0 && data[0] != FullFrameDiscriminator {
		return nil, &FrameDiscriminatorError{Discriminator: data[0]}
	}
	if len(data) < FullFrameHeaderWireSize {
		return nil, fmt.Errorf("aether: frame too short (%d < %d)", len(data), FullFrameHeaderWireSize)
	}
	f := parseHeader(data[1:FullFrameHeaderWireSize])
	if f.Length > MaxPayloadSize {
		return nil, fmt.Errorf("%w (%d > %d)", ErrPayloadTooLarge, f.Length, MaxPayloadSize)
	}
	avail := len(data) - FullFrameHeaderWireSize
	if int(f.Length) > avail {
		return nil, fmt.Errorf("aether: truncated payload (have %d, need %d)", avail, f.Length)
	}
	if f.Length > 0 {
		f.Payload = data[FullFrameHeaderWireSize : FullFrameHeaderWireSize+int(f.Length)]
	}
	return f, nil
}

// DecodeFrame reads one full frame from r. A first byte other than
// FullFrameDiscriminator is refused with a *FrameDiscriminatorError before
// anything past it is read.
func DecodeFrame(r io.Reader) (*Frame, error) {
	var disc [1]byte
	if _, err := io.ReadFull(r, disc[:]); err != nil {
		return nil, fmt.Errorf("aether: read discriminator: %w", err)
	}
	return DecodeFrameWithFirstByte(r, disc[0])
}

// DecodeFrameWithFirstByte reads the rest of a full frame whose first byte, the
// discriminator, the caller has already read. ReadNextFrame and DecodeBatch
// call it once they have read that byte. A discriminator other than
// FullFrameDiscriminator is refused with a *FrameDiscriminatorError and
// nothing more is read; the payload is allocated only after its Length passes
// MaxPayloadSize.
func DecodeFrameWithFirstByte(r io.Reader, firstByte byte) (*Frame, error) {
	if firstByte != FullFrameDiscriminator {
		return nil, &FrameDiscriminatorError{Discriminator: firstByte}
	}
	var hdr [HeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("aether: read header: %w", err)
	}
	f := parseHeader(hdr[:])

	if f.Length > MaxPayloadSize {
		return nil, fmt.Errorf("%w (%d bytes, max %d)", ErrPayloadTooLarge, f.Length, MaxPayloadSize)
	}
	// The payload buffer comes from the payload pool; a failed read returns
	// it there.
	if f.Length > 0 {
		f.Payload = GetPayloadBuf(int(f.Length))
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			PutPayloadBuf(f.Payload)
			return nil, fmt.Errorf("aether: read payload: %w", err)
		}
	}
	return f, nil
}

// EncodeHeaderOnly writes f's discriminator and header without its payload,
// for a caller that writes the payload itself. It returns the
// FullFrameHeaderWireSize bytes written.
func EncodeHeaderOnly(w io.Writer, f *Frame) (int, error) {
	var hdr [FullFrameHeaderWireSize]byte
	putFullFrameHeader(hdr[:], f)
	return w.Write(hdr[:])
}

// HeaderBytes returns the first 38 bytes of the frame header (everything before the Nonce).
// Used as AEAD additional data for authenticated encryption — authenticates the header
// without encrypting it, so routers can inspect SenderID/ReceiverID.
func (f *Frame) HeaderBytes() []byte {
	var hdr [38]byte
	copy(hdr[0:8], f.SenderID[:])
	copy(hdr[8:16], f.ReceiverID[:])
	binary.BigEndian.PutUint64(hdr[16:24], f.StreamID)
	hdr[24] = byte(f.Type)
	hdr[25] = byte(f.Flags)
	binary.BigEndian.PutUint32(hdr[26:30], f.SeqNo)
	binary.BigEndian.PutUint32(hdr[30:34], f.AckNo)
	binary.BigEndian.PutUint32(hdr[34:38], f.Length)
	return hdr[:]
}

// ────────────────────────────────────────────────────────────────────────────
// Typed Payload Codecs
// ────────────────────────────────────────────────────────────────────────────

// EncodeSACKBlocks encodes SACK blocks into the payload of a TypeACK frame.
// Wire format: [block_count:2] [start:4 end:4]...
func EncodeSACKBlocks(blocks []SACKBlock) []byte {
	count := len(blocks)
	if count > MaxSACKBlocks {
		count = MaxSACKBlocks
	}
	data := make([]byte, 2+count*SACKBlockSize)
	binary.BigEndian.PutUint16(data[0:2], uint16(count))
	for i := 0; i < count; i++ {
		offset := 2 + i*SACKBlockSize
		binary.BigEndian.PutUint32(data[offset:offset+4], blocks[i].Start)
		binary.BigEndian.PutUint32(data[offset+4:offset+8], blocks[i].End)
	}
	return data
}

// DecodeSACKBlocks decodes SACK blocks from a TypeACK frame payload.
func DecodeSACKBlocks(data []byte) []SACKBlock {
	if len(data) < 2 {
		return nil
	}
	count := int(binary.BigEndian.Uint16(data[0:2]))
	if count > MaxSACKBlocks {
		count = MaxSACKBlocks
	}
	blocks := make([]SACKBlock, 0, count)
	for i := 0; i < count; i++ {
		offset := 2 + i*SACKBlockSize
		if offset+SACKBlockSize > len(data) {
			break
		}
		blocks = append(blocks, SACKBlock{
			Start: binary.BigEndian.Uint32(data[offset : offset+4]),
			End:   binary.BigEndian.Uint32(data[offset+4 : offset+8]),
		})
	}
	return blocks
}

// ────────────────────────────────────────────────────────────────────────────
// Composite ACK Codec
// ────────────────────────────────────────────────────────────────────────────

// EncodeCompositeACK encodes a Composite ACK into wire format.
// Wire: [BaseACK:4][AckDelay:2][BitmapLen:1][Bitmap:N][Flags:1][extensions...]
func EncodeCompositeACK(ack *CompositeACK) []byte {
	// BitmapLen is a single wire byte. A bitmap longer than 255
	// bytes would wrap when written (data[off] = byte(bitmapLen)) while all
	// its bytes were still copied, so the decoder would read Flags/extensions
	// from inside the bitmap and move the peer's send window on fabricated
	// ACK data. Clamp to 255 (valid CompositeACK bitmaps are <= 32 bytes).
	bitmapLen := len(ack.Bitmap)
	if bitmapLen > 255 {
		bitmapLen = 255
	}
	// Calculate total size
	size := 4 + 2 + 1 + bitmapLen + 1 // base fields
	if ack.Flags&CACKHasExtRanges != 0 {
		size += 1 + len(ack.ExtRanges)*SACKBlockSize
	}
	if ack.Flags&CACKHasDropped != 0 {
		size += 1 + len(ack.DroppedRanges)*SACKBlockSize
	}
	if ack.Flags&CACKHasLossDensity != 0 {
		size += 2
	}
	if ack.Flags&CACKHasECN != 0 {
		size += 4
	}
	if ack.Flags&CACKHasWindowCredit != 0 {
		size += 8
	}

	data := make([]byte, size)
	off := 0

	// BaseACK (4 bytes)
	binary.BigEndian.PutUint32(data[off:off+4], ack.BaseACK)
	off += 4

	// AckDelay (2 bytes, 8µs units)
	binary.BigEndian.PutUint16(data[off:off+2], ack.AckDelay)
	off += 2

	// BitmapLen (1 byte)
	data[off] = byte(bitmapLen)
	off++

	// Bitmap (N bytes)
	if bitmapLen > 0 {
		copy(data[off:off+bitmapLen], ack.Bitmap)
		off += bitmapLen
	}

	// Flags (1 byte)
	data[off] = byte(ack.Flags)
	off++

	// Optional: Extended ranges
	if ack.Flags&CACKHasExtRanges != 0 {
		count := len(ack.ExtRanges)
		if count > MaxExtRanges {
			count = MaxExtRanges
		}
		data[off] = byte(count)
		off++
		for i := 0; i < count; i++ {
			binary.BigEndian.PutUint32(data[off:off+4], ack.ExtRanges[i].Start)
			binary.BigEndian.PutUint32(data[off+4:off+8], ack.ExtRanges[i].End)
			off += SACKBlockSize
		}
	}

	// Optional: Dropped ranges
	if ack.Flags&CACKHasDropped != 0 {
		count := len(ack.DroppedRanges)
		if count > MaxDroppedRanges {
			count = MaxDroppedRanges
		}
		data[off] = byte(count)
		off++
		for i := 0; i < count; i++ {
			binary.BigEndian.PutUint32(data[off:off+4], ack.DroppedRanges[i].Start)
			binary.BigEndian.PutUint32(data[off+4:off+8], ack.DroppedRanges[i].End)
			off += SACKBlockSize
		}
	}

	// Optional: Loss density
	if ack.Flags&CACKHasLossDensity != 0 {
		binary.BigEndian.PutUint16(data[off:off+2], ack.LossRate)
		off += 2
	}

	// Optional: ECN — 4-byte cumulative CE-byte count.
	if ack.Flags&CACKHasECN != 0 {
		binary.BigEndian.PutUint32(data[off:off+4], ack.CEBytes)
		off += 4
	}

	// Optional: Window credit — 8-byte cumulative stream WINDOW_UPDATE
	// grant piggybacked on the ACK. Placed AFTER ECN so older receivers
	// that decode as far as they understand and stop (per the
	// truncation-tolerant decoder) can still handle all earlier
	// extensions.
	if ack.Flags&CACKHasWindowCredit != 0 {
		binary.BigEndian.PutUint64(data[off:off+8], ack.WindowCredit)
		off += 8
	}

	return data[:off]
}

// DecodeCompositeACK decodes a Composite ACK from wire format.
// Returns nil if the data is too short for a valid Composite ACK.
func DecodeCompositeACK(data []byte) *CompositeACK {
	if len(data) < CompositeACKMinSize {
		return nil
	}

	ack := &CompositeACK{}
	off := 0

	// BaseACK
	ack.BaseACK = binary.BigEndian.Uint32(data[off : off+4])
	off += 4

	// AckDelay
	ack.AckDelay = binary.BigEndian.Uint16(data[off : off+2])
	off += 2

	// BitmapLen
	bitmapLen := int(data[off])
	off++

	// Bitmap
	if bitmapLen > 0 {
		if off+bitmapLen > len(data) {
			return nil // truncated
		}
		ack.Bitmap = make([]byte, bitmapLen)
		copy(ack.Bitmap, data[off:off+bitmapLen])
		off += bitmapLen
	}

	// Flags
	if off >= len(data) {
		return nil // truncated
	}
	ack.Flags = CompositeACKFlags(data[off])
	off++

	// Optional: Extended ranges
	if ack.Flags&CACKHasExtRanges != 0 {
		if off >= len(data) {
			return ack // truncated but partial is ok
		}
		count := int(data[off])
		off++
		if count > MaxExtRanges {
			count = MaxExtRanges
		}
		for i := 0; i < count; i++ {
			if off+SACKBlockSize > len(data) {
				break
			}
			ack.ExtRanges = append(ack.ExtRanges, SACKBlock{
				Start: binary.BigEndian.Uint32(data[off : off+4]),
				End:   binary.BigEndian.Uint32(data[off+4 : off+8]),
			})
			off += SACKBlockSize
		}
	}

	// Optional: Dropped ranges
	if ack.Flags&CACKHasDropped != 0 {
		if off >= len(data) {
			return ack
		}
		count := int(data[off])
		off++
		if count > MaxDroppedRanges {
			count = MaxDroppedRanges
		}
		for i := 0; i < count; i++ {
			if off+SACKBlockSize > len(data) {
				break
			}
			ack.DroppedRanges = append(ack.DroppedRanges, SACKBlock{
				Start: binary.BigEndian.Uint32(data[off : off+4]),
				End:   binary.BigEndian.Uint32(data[off+4 : off+8]),
			})
			off += SACKBlockSize
		}
	}

	// Optional: Loss density
	if ack.Flags&CACKHasLossDensity != 0 {
		if off+2 <= len(data) {
			ack.LossRate = binary.BigEndian.Uint16(data[off : off+2])
			off += 2
		}
	}

	// Optional: ECN extension — 4-byte CE byte count.
	if ack.Flags&CACKHasECN != 0 {
		if off+4 <= len(data) {
			ack.CEBytes = binary.BigEndian.Uint32(data[off : off+4])
			off += 4
		}
	}

	// Optional: Window credit — 8-byte cumulative stream-level grant.
	if ack.Flags&CACKHasWindowCredit != 0 {
		if off+8 <= len(data) {
			ack.WindowCredit = binary.BigEndian.Uint64(data[off : off+8])
			// off += 8 // no further extensions after this one yet
		}
	}

	return ack
}

// EncodeWindowUpdate encodes a cumulative credit grant for a WINDOW_UPDATE
// frame payload. See WindowUpdateSize for why this carries a cumulative
// 64-bit total rather than a 32-bit delta.
func EncodeWindowUpdate(credit uint64) []byte {
	data := make([]byte, WindowUpdateSize)
	binary.BigEndian.PutUint64(data, credit)
	return data
}

// DecodeWindowUpdate decodes a cumulative credit grant from a WINDOW_UPDATE
// frame payload. Returns 0 on short input — the sender's ApplyUpdate then
// treats it as a stale/duplicate frame and drops it.
func DecodeWindowUpdate(data []byte) uint64 {
	if len(data) < WindowUpdateSize {
		return 0
	}
	return binary.BigEndian.Uint64(data)
}

// EncodeCongestion encodes a CongestionPayload for the CONGESTION frame.
// Wire format: [1 reason][1 severity][2 backoff_ms BE][1 reserved].
func EncodeCongestion(p CongestionPayload) []byte {
	data := make([]byte, CongestionPayloadSize)
	data[0] = byte(p.Reason)
	data[1] = p.Severity
	binary.BigEndian.PutUint16(data[2:4], p.BackoffMs)
	// data[4] reserved, leave zero.
	return data
}

// DecodeCongestion decodes a CONGESTION frame payload. Returns a zero-value
// payload (Reason=Unspecified, Severity=0 "all clear") on short or malformed
// input — the cautious default avoids senders over-reacting to garbage.
func DecodeCongestion(data []byte) CongestionPayload {
	if len(data) < CongestionPayloadSize {
		return CongestionPayload{}
	}
	return CongestionPayload{
		Reason:    CongestionReason(data[0]),
		Severity:  data[1],
		BackoffMs: binary.BigEndian.Uint16(data[2:4]),
	}
}

// EncodePriority encodes a PRIORITY frame payload.
func EncodePriority(p PriorityPayload) []byte {
	data := make([]byte, PriorityPayloadSize)
	data[0] = p.Weight
	binary.BigEndian.PutUint64(data[1:9], p.Dependency)
	return data
}

// DecodePriority decodes a PRIORITY frame payload.
func DecodePriority(data []byte) PriorityPayload {
	if len(data) < PriorityPayloadSize {
		return PriorityPayload{}
	}
	return PriorityPayload{
		Weight:     data[0],
		Dependency: binary.BigEndian.Uint64(data[1:9]),
	}
}

// EncodeOpenPayload encodes an OPEN frame payload:
// [1 reliability][1 priority][8 dependency, big-endian][4 initial credit, big-endian][1 FEC level]
// [8 generation, big-endian].
func EncodeOpenPayload(o OpenPayload) []byte {
	data := make([]byte, OpenPayloadSize)
	data[0] = byte(o.Reliability)
	data[1] = o.Priority
	binary.BigEndian.PutUint64(data[2:10], o.Dependency)
	binary.BigEndian.PutUint32(data[10:14], o.InitialCredit)
	data[14] = o.FECLevel
	binary.BigEndian.PutUint64(data[15:23], o.Generation)
	return data
}

// DecodeOpenPayload decodes an OPEN frame payload. Input shorter than
// OpenPayloadSize decodes to the zero value, whose InitialCredit and Generation
// of zero a NoiseSession refuses.
func DecodeOpenPayload(data []byte) OpenPayload {
	if len(data) < OpenPayloadSize {
		return OpenPayload{}
	}
	return OpenPayload{
		Reliability:   Reliability(data[0]),
		Priority:      data[1],
		Dependency:    binary.BigEndian.Uint64(data[2:10]),
		InitialCredit: binary.BigEndian.Uint32(data[10:14]),
		FECLevel:      data[14],
		Generation:    binary.BigEndian.Uint64(data[15:23]),
	}
}

// ValidStreamGeneration reports whether g is a generation an OPEN may state: from
// 1 to MaxStreamGeneration. The NoiseSession and TCP-family session's handleOpen
// refuse any other.
func ValidStreamGeneration(g uint64) bool {
	return g != 0 && g <= MaxStreamGeneration
}

// putIncarnation writes inc into the StreamIncarnationSize bytes of b.
func putIncarnation(b []byte, inc StreamIncarnation) {
	v := inc.Generation & MaxStreamGeneration
	if inc.WriterOpened {
		v |= 1 << 63
	}
	binary.BigEndian.PutUint64(b[:StreamIncarnationSize], v)
}

// incarnationAt reads the StreamIncarnation putIncarnation wrote into b.
func incarnationAt(b []byte) StreamIncarnation {
	v := binary.BigEndian.Uint64(b[:StreamIncarnationSize])
	return StreamIncarnation{Generation: v & MaxStreamGeneration, WriterOpened: v>>63 == 1}
}

// EncodeClosePayload encodes a CLOSE frame payload: the stream's incarnation.
func EncodeClosePayload(inc StreamIncarnation) []byte {
	data := make([]byte, ClosePayloadSize)
	putIncarnation(data, inc)
	return data
}

// DecodeClosePayload decodes a CLOSE frame payload. Input shorter than
// ClosePayloadSize decodes to the zero value, generation 0, which names no
// stream: Validate has refused such a frame on every session path that reads one.
func DecodeClosePayload(data []byte) StreamIncarnation {
	if len(data) < ClosePayloadSize {
		return StreamIncarnation{}
	}
	return incarnationAt(data)
}

// EncodeGoAway encodes a GOAWAY frame payload.
func EncodeGoAway(reason GoAwayReason, message string) []byte {
	data := make([]byte, 4+len(message))
	binary.BigEndian.PutUint32(data[0:4], uint32(reason))
	copy(data[4:], message)
	return data
}

// DecodeGoAway decodes a GOAWAY frame payload.
func DecodeGoAway(data []byte) (GoAwayReason, string) {
	if len(data) < 4 {
		return GoAwayNormal, ""
	}
	reason := GoAwayReason(binary.BigEndian.Uint32(data[0:4]))
	message := ""
	if len(data) > 4 {
		message = string(data[4:])
	}
	return reason, message
}

// EncodeFECHeader encodes an FEC_REPAIR payload's header and table of covered
// frames; the repair bytes follow what it returns.
func EncodeFECHeader(h FECHeader) []byte {
	data := make([]byte, FECRepairOverhead(len(h.Covered)))
	binary.BigEndian.PutUint32(data[0:4], h.GroupID)
	data[4] = h.Index
	data[5] = h.Total
	data[6] = h.Level
	data[7] = uint8(len(h.Covered))
	for i, c := range h.Covered {
		entry := data[FECHeaderSize+i*FECCoveredSize:]
		binary.BigEndian.PutUint32(entry[0:4], c.SeqNo)
		binary.BigEndian.PutUint16(entry[4:6], c.Length)
		if c.Fragment {
			entry[6] = 1
		}
	}
	return data
}

// DecodeFECHeader decodes an FEC_REPAIR payload into its header and the repair
// bytes behind the table. It returns aether.ErrFECRepairMalformed, before it
// allocates the table, for input shorter than the header, a covered count of zero
// or past MaxFECCovered, or a table the input cannot hold, and after reading the
// table for a frame it names twice, which no group of the sender's encoders holds.
func DecodeFECHeader(data []byte) (FECHeader, []byte, error) {
	if len(data) < FECHeaderSize {
		return FECHeader{}, nil, fmt.Errorf("%w: %d bytes", ErrFECRepairMalformed, len(data))
	}
	count := int(data[7])
	if count == 0 || count > MaxFECCovered {
		return FECHeader{}, nil, fmt.Errorf("%w: %d covered frames", ErrFECRepairMalformed, count)
	}
	end := FECRepairOverhead(count)
	if len(data) < end {
		return FECHeader{}, nil, fmt.Errorf("%w: %d bytes for %d covered frames", ErrFECRepairMalformed, len(data), count)
	}
	h := FECHeader{
		GroupID: binary.BigEndian.Uint32(data[0:4]),
		Index:   data[4],
		Total:   data[5],
		Level:   data[6],
		Covered: make([]FECCovered, count),
	}
	seen := make(map[uint32]struct{}, count)
	for i := range h.Covered {
		entry := data[FECHeaderSize+i*FECCoveredSize:]
		c := FECCovered{
			SeqNo:    binary.BigEndian.Uint32(entry[0:4]),
			Length:   binary.BigEndian.Uint16(entry[4:6]),
			Fragment: entry[6]&1 != 0,
		}
		if _, dup := seen[c.SeqNo]; dup {
			return FECHeader{}, nil, fmt.Errorf("%w: frame %d named twice", ErrFECRepairMalformed, c.SeqNo)
		}
		seen[c.SeqNo] = struct{}{}
		h.Covered[i] = c
	}
	return h, data[end:], nil
}

// EncodeReset encodes the RESET payload of a writer that states no credit counts
// and no incarnation. No session writes it: every RESET a session writes names its
// stream (ResetPayload.Incarnation), through EncodeResetPayload.
func EncodeReset(reason ResetReason) []byte {
	return EncodeResetPayload(ResetPayload{Reason: reason})
}

// EncodeResetPayload encodes a RESET frame payload.
func EncodeResetPayload(p ResetPayload) []byte {
	data := make([]byte, ResetPayloadSize)
	binary.BigEndian.PutUint32(data[0:4], uint32(p.Reason))
	binary.BigEndian.PutUint64(data[4:12], p.Charged)
	binary.BigEndian.PutUint64(data[12:20], p.Released)
	binary.BigEndian.PutUint64(data[20:28], p.Consumed)
	putIncarnation(data[28:36], p.Incarnation)
	return data
}

// DecodeReset decodes a RESET frame payload's reason, for a reader of no count.
func DecodeReset(data []byte) ResetReason {
	return DecodeResetPayload(data).Reason
}

// DecodeResetPayload decodes a RESET frame payload. Input shorter than
// ResetPayloadSize decodes to the zero value: Validate has refused such a frame on
// every session path that reads one, and this is a second guard for a caller that
// did not run it.
func DecodeResetPayload(data []byte) ResetPayload {
	if len(data) < ResetPayloadSize {
		return ResetPayload{}
	}
	return ResetPayload{
		Reason:      ResetReason(binary.BigEndian.Uint32(data[0:4])),
		Charged:     binary.BigEndian.Uint64(data[4:12]),
		Released:    binary.BigEndian.Uint64(data[12:20]),
		Consumed:    binary.BigEndian.Uint64(data[20:28]),
		Incarnation: incarnationAt(data[28:36]),
	}
}

// ────────────────────────────────────────────────────────────────────────────
// WHOIS Codec
// ────────────────────────────────────────────────────────────────────────────

// EncodeWhoisRequest encodes a WHOIS request (query for a PeerID's full identity).
func EncodeWhoisRequest(targetPeerID PeerID) []byte {
	data := make([]byte, WhoisMinSize)
	copy(data[0:8], targetPeerID[:])
	data[8] = 0x00 // request
	return data
}

// EncodeWhoisResponse encodes a WHOIS response (full identity for a PeerID).
func EncodeWhoisResponse(targetPeerID PeerID, nodeID string, pubKey [32]byte) []byte {
	data := make([]byte, WhoisMinSize+2+len(nodeID)+32)
	copy(data[0:8], targetPeerID[:])
	data[8] = 0x01 // response
	binary.BigEndian.PutUint16(data[9:11], uint16(len(nodeID)))
	copy(data[11:11+len(nodeID)], nodeID)
	copy(data[11+len(nodeID):], pubKey[:])
	return data
}

// DecodeWhois decodes a WHOIS frame payload.
func DecodeWhois(data []byte) WhoisPayload {
	if len(data) < WhoisMinSize {
		return WhoisPayload{}
	}
	p := WhoisPayload{}
	copy(p.TargetPeerID[:], data[0:8])
	p.IsResponse = data[8] == 0x01

	if p.IsResponse && len(data) >= WhoisMinSize+2 {
		nodeIDLen := int(binary.BigEndian.Uint16(data[9:11]))
		if len(data) >= 11+nodeIDLen+32 {
			p.NodeID = string(data[11 : 11+nodeIDLen])
			copy(p.PubKey[:], data[11+nodeIDLen:11+nodeIDLen+32])
		}
	}
	return p
}

// ────────────────────────────────────────────────────────────────────────────
// RENDEZVOUS Codec
// ────────────────────────────────────────────────────────────────────────────

// EncodeRendezvous encodes a RENDEZVOUS frame payload.
func EncodeRendezvous(p RendezvousPayload) []byte {
	data := make([]byte, RendezvousPayloadSize)
	copy(data[0:8], p.TargetPeerID[:])
	copy(data[8:24], p.ObservedIP[:])
	binary.BigEndian.PutUint16(data[24:26], p.ObservedPort)
	data[26] = byte(p.NATType)
	return data
}

// DecodeRendezvous decodes a RENDEZVOUS frame payload.
func DecodeRendezvous(data []byte) RendezvousPayload {
	if len(data) < RendezvousPayloadSize {
		return RendezvousPayload{}
	}
	p := RendezvousPayload{}
	copy(p.TargetPeerID[:], data[0:8])
	copy(p.ObservedIP[:], data[8:24])
	p.ObservedPort = binary.BigEndian.Uint16(data[24:26])
	p.NATType = NATType(data[26])
	return p
}

// ────────────────────────────────────────────────────────────────────────────
// NETWORK_CONFIG Codec
// ────────────────────────────────────────────────────────────────────────────

// EncodeNetworkConfig encodes a NETWORK_CONFIG frame payload.
func EncodeNetworkConfig(p NetworkConfigPayload) []byte {
	data := make([]byte, NetworkConfigMinSize+len(p.ConfigData))
	data[0] = byte(p.ConfigType)
	binary.BigEndian.PutUint32(data[1:5], p.Version)
	copy(data[5:69], p.Signature[:])
	copy(data[69:], p.ConfigData)
	return data
}

// DecodeNetworkConfig decodes a NETWORK_CONFIG frame payload.
func DecodeNetworkConfig(data []byte) NetworkConfigPayload {
	if len(data) < NetworkConfigMinSize {
		return NetworkConfigPayload{}
	}
	p := NetworkConfigPayload{
		ConfigType: ConfigType(data[0]),
		Version:    binary.BigEndian.Uint32(data[1:5]),
	}
	copy(p.Signature[:], data[5:69])
	if len(data) > NetworkConfigMinSize {
		p.ConfigData = make([]byte, len(data)-NetworkConfigMinSize)
		copy(p.ConfigData, data[NetworkConfigMinSize:])
	}
	return p
}

// ────────────────────────────────────────────────────────────────────────────
// HANDSHAKE Codec
// ────────────────────────────────────────────────────────────────────────────

// EncodeHandshake encodes a HANDSHAKE frame payload.
func EncodeHandshake(p HandshakePayload) []byte {
	data := make([]byte, 1+len(p.Payload))
	data[0] = byte(p.HandshakeType)
	copy(data[1:], p.Payload)
	return data
}

// DecodeHandshake decodes a HANDSHAKE frame payload.
func DecodeHandshake(data []byte) HandshakePayload {
	if len(data) < 1 {
		return HandshakePayload{}
	}
	p := HandshakePayload{
		HandshakeType: HandshakeType(data[0]),
	}
	if len(data) > 1 {
		p.Payload = make([]byte, len(data)-1)
		copy(p.Payload, data[1:])
	}
	return p
}

// ────────────────────────────────────────────────────────────────────────────
// STATS Codec
// ────────────────────────────────────────────────────────────────────────────

// StatsPayloadSize is the wire size of a STATS frame payload.
//
// Layout (74 bytes, big-endian):
//
//	[ 0: 4) RTT µs (uint32)
//	[ 4: 8) LossPpm (uint32; LossPercent × 10000)
//	[ 8:12) CWND bytes (uint32)
//	[12:16) Retransmits (uint32 — saturating)
//	[16:24) FramesSent (uint64)
//	[24:32) BytesSent (uint64)
//	[32:34) ActiveStreams (uint16)
//	[34:42) FramesRecv (uint64)
//	[42:50) BytesRecv (uint64)
//	[50:54) TotalReorders (uint32 — saturating; sum across StreamObserve)
//	[54:58) DroppedFrames (uint32 — saturating)
//	[58:62) RttP50 µs (uint32)
//	[62:66) RttP99 µs (uint32)
//	[66:70) TLPFiresTotal (uint32 — saturating)
//	[70:74) RACKMarksTotal (uint32 — saturating)
//
// The asymmetric-aware quality scorer (multipath.computeScoreLocked)
// needs the receive-direction counters (FramesRecv / BytesRecv /
// TotalReorders / DroppedFrames) and the peer's RTT distribution
// (RttP50/P99) so a path where downstream looks healthy on our side
// but upstream is silently lossy on the peer's side still scores low.
// The TLP/RACK counts are diagnostic — a peer running hot on loss
// recovery is a leading indicator the path is degrading even if the
// LossPpm field hasn't moved yet.
//
// Saturating casts on the uint32-narrowed fields: a u64 value past
// 0xFFFFFFFF is clamped, not truncated mod 2^32 — clamping preserves
// the "abnormally high" signal, truncating would silently roll over.
const StatsPayloadSize = 74

// saturU32 clamps a uint64 down to uint32 — values past MaxUint32
// stay at MaxUint32 instead of wrapping. Used by EncodeStats so
// saturating-cast counter fields preserve the "abnormally high"
// observability signal rather than rolling over to a small number.
func saturU32(v uint64) uint32 {
	if v > 0xFFFFFFFF {
		return 0xFFFFFFFF
	}
	return uint32(v)
}

// EncodeStats encodes a SessionMetrics into a STATS frame payload.
// See StatsPayloadSize for the wire layout. Saturating casts on the
// uint32-narrowed fields preserve the "abnormally high" signal.
func EncodeStats(m SessionMetrics) []byte {
	data := make([]byte, StatsPayloadSize)
	binary.BigEndian.PutUint32(data[0:4], saturU32(uint64(m.RTT.Microseconds())))
	binary.BigEndian.PutUint32(data[4:8], saturU32(uint64(m.LossPercent*10000))) // ppm
	binary.BigEndian.PutUint32(data[8:12], saturU32(uint64(m.CWND)))
	binary.BigEndian.PutUint32(data[12:16], saturU32(m.Retransmits))
	binary.BigEndian.PutUint64(data[16:24], m.FramesSent)
	binary.BigEndian.PutUint64(data[24:32], m.BytesSent)
	binary.BigEndian.PutUint16(data[32:34], uint16(m.ActiveStreams))
	binary.BigEndian.PutUint64(data[34:42], m.FramesRecv)
	binary.BigEndian.PutUint64(data[42:50], m.BytesRecv)
	// Sum stream-level reorder counts so the receiver's scorer can
	// fold the peer's reorder rate into the asymmetric-loss signal.
	// Per-stream detail isn't shipped — the dispatcher only needs the
	// summed signal, and StreamObserve serialisation would bloat the
	// 5s STATS cadence past the cheap-control-frame budget.
	var totalReorders uint64
	for _, sd := range m.StreamObserve {
		if sd.ReorderCount > 0 {
			totalReorders += uint64(sd.ReorderCount)
		}
	}
	binary.BigEndian.PutUint32(data[50:54], saturU32(totalReorders))
	binary.BigEndian.PutUint32(data[54:58], saturU32(m.DroppedFrames))
	binary.BigEndian.PutUint32(data[58:62], saturU32(uint64(m.RttP50.Microseconds())))
	binary.BigEndian.PutUint32(data[62:66], saturU32(uint64(m.RttP99.Microseconds())))
	binary.BigEndian.PutUint32(data[66:70], saturU32(m.TLPFiresTotal))
	binary.BigEndian.PutUint32(data[70:74], saturU32(m.RACKMarksTotal))
	return data
}

// DecodeStats decodes a STATS frame payload into SessionMetrics.
// Returns a zero-value SessionMetrics on short input (the handler in
// noise_dispatch.go gates on StatsPayloadSize before calling, so this
// is belt-and-suspenders against a malformed frame).
//
// The TotalReorders field is materialised back as a single synthetic
// StreamObserve entry keyed by `0` (broadcast stream sentinel) so the
// existing scorer reorder-sum loop in computeScoreLocked picks it up
// without per-stream detail — the peer didn't ship the per-stream
// breakdown, only the aggregate.
func DecodeStats(data []byte) SessionMetrics {
	if len(data) < StatsPayloadSize {
		return SessionMetrics{}
	}
	m := SessionMetrics{
		RTT:            time.Duration(binary.BigEndian.Uint32(data[0:4])) * time.Microsecond,
		LossPercent:    float64(binary.BigEndian.Uint32(data[4:8])) / 10000,
		CWND:           int64(binary.BigEndian.Uint32(data[8:12])),
		Retransmits:    uint64(binary.BigEndian.Uint32(data[12:16])),
		FramesSent:     binary.BigEndian.Uint64(data[16:24]),
		BytesSent:      binary.BigEndian.Uint64(data[24:32]),
		ActiveStreams:  int(binary.BigEndian.Uint16(data[32:34])),
		FramesRecv:     binary.BigEndian.Uint64(data[34:42]),
		BytesRecv:      binary.BigEndian.Uint64(data[42:50]),
		DroppedFrames:  uint64(binary.BigEndian.Uint32(data[54:58])),
		RttP50:         time.Duration(binary.BigEndian.Uint32(data[58:62])) * time.Microsecond,
		RttP99:         time.Duration(binary.BigEndian.Uint32(data[62:66])) * time.Microsecond,
		TLPFiresTotal:  uint64(binary.BigEndian.Uint32(data[66:70])),
		RACKMarksTotal: uint64(binary.BigEndian.Uint32(data[70:74])),
	}
	if totalReorders := binary.BigEndian.Uint32(data[50:54]); totalReorders > 0 {
		m.StreamObserve = map[uint64]StreamObserveData{
			0: {ReorderCount: int64(totalReorders)},
		}
	}
	return m
}

// ────────────────────────────────────────────────────────────────────────────
// TRACE Codec
// ────────────────────────────────────────────────────────────────────────────

// TraceHopSize is the size of a single trace hop entry (29 bytes).
const TraceHopSize = 29

// TraceHop is a single hop entry in a distributed RPC trace.
type TraceHop struct {
	TraceID   uint64 // 8 bytes: trace identifier
	HopIndex  uint8  // 1 byte: hop position (0 = origin)
	NodeID    PeerID // 8 bytes: this node's truncated ID
	Timestamp uint64 // 8 bytes: unix micros
	LatencyUs uint32 // 4 bytes: processing latency in microseconds
}

// EncodeTraceHop encodes a single trace hop.
func EncodeTraceHop(h TraceHop) []byte {
	data := make([]byte, TraceHopSize)
	binary.BigEndian.PutUint64(data[0:8], h.TraceID)
	data[8] = h.HopIndex
	copy(data[9:17], h.NodeID[:])
	binary.BigEndian.PutUint64(data[17:25], h.Timestamp)
	binary.BigEndian.PutUint32(data[25:29], h.LatencyUs)
	return data
}

// DecodeTraceHop decodes a single trace hop.
func DecodeTraceHop(data []byte) TraceHop {
	if len(data) < TraceHopSize {
		return TraceHop{}
	}
	h := TraceHop{
		TraceID:   binary.BigEndian.Uint64(data[0:8]),
		HopIndex:  data[8],
		Timestamp: binary.BigEndian.Uint64(data[17:25]),
		LatencyUs: binary.BigEndian.Uint32(data[25:29]),
	}
	copy(h.NodeID[:], data[9:17])
	return h
}

// ────────────────────────────────────────────────────────────────────────────
// PATH_PROBE Codec
// ────────────────────────────────────────────────────────────────────────────

// PathProbeMinSize is the minimum PATH_PROBE payload size.
const PathProbeMinSize = 6

// PathProbePayload is the decoded payload of a PATH_PROBE frame.
type PathProbePayload struct {
	ProbeID     uint32 // 4 bytes: echo this in response for RTT
	PayloadSize uint16 // 2 bytes: padding size (for PMTU discovery)
}

// EncodePathProbe encodes a PATH_PROBE frame payload with padding.
func EncodePathProbe(probeID uint32, paddingSize uint16) []byte {
	data := make([]byte, PathProbeMinSize+int(paddingSize))
	binary.BigEndian.PutUint32(data[0:4], probeID)
	binary.BigEndian.PutUint16(data[4:6], paddingSize)
	// Remaining bytes are zero padding for PMTU probing
	return data
}

// DecodePathProbe decodes a PATH_PROBE frame payload.
func DecodePathProbe(data []byte) PathProbePayload {
	if len(data) < PathProbeMinSize {
		return PathProbePayload{}
	}
	return PathProbePayload{
		ProbeID:     binary.BigEndian.Uint32(data[0:4]),
		PayloadSize: binary.BigEndian.Uint16(data[4:6]),
	}
}
