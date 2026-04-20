/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package aether

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"
)

// payloadPool reduces GC pressure from per-frame []byte allocations.
// Payloads are returned to the pool when the frame is no longer needed.
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

// EncodeFrame writes an Aether frame to w. Returns the total bytes written (header + payload).
func EncodeFrame(w io.Writer, f *Frame) (int, error) {
	var hdr [HeaderSize]byte

	// SenderID (offset 0, 8 bytes)
	copy(hdr[0:8], f.SenderID[:])
	// ReceiverID (offset 8, 8 bytes)
	copy(hdr[8:16], f.ReceiverID[:])
	// StreamID (offset 16, 8 bytes)
	binary.BigEndian.PutUint64(hdr[16:24], f.StreamID)
	// Type (offset 24, 1 byte)
	hdr[24] = byte(f.Type)
	// Flags (offset 25, 1 byte)
	hdr[25] = byte(f.Flags)
	// SeqNo (offset 26, 4 bytes)
	binary.BigEndian.PutUint32(hdr[26:30], f.SeqNo)
	// AckNo (offset 30, 4 bytes)
	binary.BigEndian.PutUint32(hdr[30:34], f.AckNo)
	// Length (offset 34, 4 bytes)
	binary.BigEndian.PutUint32(hdr[34:38], f.Length)
	// Nonce (offset 38, 12 bytes)
	copy(hdr[38:50], f.Nonce[:])

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

// EncodeFrameToBytes serialises a frame to a byte slice.
// Used by WASM adapter where io.Writer is not available.
func EncodeFrameToBytes(f *Frame) []byte {
	buf := make([]byte, HeaderSize+len(f.Payload))
	copy(buf[0:8], f.SenderID[:])
	copy(buf[8:16], f.ReceiverID[:])
	binary.BigEndian.PutUint64(buf[16:24], f.StreamID)
	buf[24] = byte(f.Type)
	buf[25] = byte(f.Flags)
	binary.BigEndian.PutUint32(buf[26:30], f.SeqNo)
	binary.BigEndian.PutUint32(buf[30:34], f.AckNo)
	binary.BigEndian.PutUint32(buf[34:38], f.Length)
	copy(buf[38:50], f.Nonce[:])
	copy(buf[50:], f.Payload)
	return buf
}

// DecodeFrameFromBytes deserialises a frame from a byte slice.
// Used by WASM adapter where io.Reader is not available.
func DecodeFrameFromBytes(data []byte) (*Frame, error) {
	if len(data) < HeaderSize {
		return nil, fmt.Errorf("aether: frame too short (%d < %d)", len(data), HeaderSize)
	}
	f := &Frame{}
	copy(f.SenderID[:], data[0:8])
	copy(f.ReceiverID[:], data[8:16])
	f.StreamID = binary.BigEndian.Uint64(data[16:24])
	f.Type = FrameType(data[24])
	f.Flags = FrameFlags(data[25])
	f.SeqNo = binary.BigEndian.Uint32(data[26:30])
	f.AckNo = binary.BigEndian.Uint32(data[30:34])
	f.Length = binary.BigEndian.Uint32(data[34:38])
	copy(f.Nonce[:], data[38:50])
	if len(data) > HeaderSize {
		f.Payload = data[HeaderSize:]
	}
	return f, nil
}

// DecodeFrame reads an Aether frame from r.
func DecodeFrame(r io.Reader) (*Frame, error) {
	var hdr [HeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("aether: read header: %w", err)
	}

	f := &Frame{}

	// SenderID
	copy(f.SenderID[:], hdr[0:8])
	// ReceiverID
	copy(f.ReceiverID[:], hdr[8:16])
	// StreamID
	f.StreamID = binary.BigEndian.Uint64(hdr[16:24])
	// Type
	f.Type = FrameType(hdr[24])
	// Flags
	f.Flags = FrameFlags(hdr[25])
	// SeqNo
	f.SeqNo = binary.BigEndian.Uint32(hdr[26:30])
	// AckNo
	f.AckNo = binary.BigEndian.Uint32(hdr[30:34])
	// Length
	f.Length = binary.BigEndian.Uint32(hdr[34:38])
	// Nonce
	copy(f.Nonce[:], hdr[38:50])

	// Validate length before allocating
	if f.Length > MaxPayloadSize {
		return nil, fmt.Errorf("aether: payload too large (%d bytes, max %d)", f.Length, MaxPayloadSize)
	}

	// Read payload (uses pooled buffer to reduce GC pressure)
	if f.Length > 0 {
		f.Payload = GetPayloadBuf(int(f.Length))
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			PutPayloadBuf(f.Payload)
			return nil, fmt.Errorf("aether: read payload: %w", err)
		}
	}

	return f, nil
}

// DecodeFrameWithFirstByte decodes a full Aether frame when the first byte of the
// header has already been read (e.g., to distinguish short vs full headers).
func DecodeFrameWithFirstByte(r io.Reader, firstByte byte) (*Frame, error) {
	var hdr [HeaderSize]byte
	hdr[0] = firstByte
	if _, err := io.ReadFull(r, hdr[1:]); err != nil {
		return nil, fmt.Errorf("aether: read header: %w", err)
	}

	f := &Frame{}
	copy(f.SenderID[:], hdr[0:8])
	copy(f.ReceiverID[:], hdr[8:16])
	f.StreamID = binary.BigEndian.Uint64(hdr[16:24])
	f.Type = FrameType(hdr[24])
	f.Flags = FrameFlags(hdr[25])
	f.SeqNo = binary.BigEndian.Uint32(hdr[26:30])
	f.AckNo = binary.BigEndian.Uint32(hdr[30:34])
	f.Length = binary.BigEndian.Uint32(hdr[34:38])
	copy(f.Nonce[:], hdr[38:50])

	if f.Length > MaxPayloadSize {
		return nil, fmt.Errorf("aether: payload too large (%d bytes, max %d)", f.Length, MaxPayloadSize)
	}
	if f.Length > 0 {
		f.Payload = GetPayloadBuf(int(f.Length))
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			PutPayloadBuf(f.Payload)
			return nil, fmt.Errorf("aether: read payload: %w", err)
		}
	}
	return f, nil
}

// EncodeHeaderOnly writes just the 50-byte header without payload.
// Useful for control frames where the payload is written separately.
func EncodeHeaderOnly(w io.Writer, f *Frame) (int, error) {
	var hdr [HeaderSize]byte
	copy(hdr[0:8], f.SenderID[:])
	copy(hdr[8:16], f.ReceiverID[:])
	binary.BigEndian.PutUint64(hdr[16:24], f.StreamID)
	hdr[24] = byte(f.Type)
	hdr[25] = byte(f.Flags)
	binary.BigEndian.PutUint32(hdr[26:30], f.SeqNo)
	binary.BigEndian.PutUint32(hdr[30:34], f.AckNo)
	binary.BigEndian.PutUint32(hdr[34:38], f.Length)
	copy(hdr[38:50], f.Nonce[:])
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
	bitmapLen := len(ack.Bitmap)
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

	// Optional: ECN — 4-byte cumulative CE-byte count (#15).
	if ack.Flags&CACKHasECN != 0 {
		binary.BigEndian.PutUint32(data[off:off+4], ack.CEBytes)
		off += 4
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

	// Optional: ECN extension (#15) — 4-byte CE byte count.
	if ack.Flags&CACKHasECN != 0 {
		if off+4 <= len(data) {
			ack.CEBytes = binary.BigEndian.Uint32(data[off : off+4])
		}
	}

	return ack
}

// EncodeWindowUpdate encodes a credit grant for a WINDOW_UPDATE frame payload.
func EncodeWindowUpdate(credit uint32) []byte {
	data := make([]byte, WindowUpdateSize)
	binary.BigEndian.PutUint32(data, credit)
	return data
}

// DecodeWindowUpdate decodes a credit grant from a WINDOW_UPDATE frame payload.
func DecodeWindowUpdate(data []byte) uint32 {
	if len(data) < WindowUpdateSize {
		return 0
	}
	return binary.BigEndian.Uint32(data)
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

// EncodeOpenPayload encodes an OPEN frame payload.
func EncodeOpenPayload(o OpenPayload) []byte {
	data := make([]byte, OpenPayloadSize)
	data[0] = byte(o.Reliability)
	data[1] = o.Priority
	binary.BigEndian.PutUint64(data[2:10], o.Dependency)
	return data
}

// DecodeOpenPayload decodes an OPEN frame payload.
func DecodeOpenPayload(data []byte) OpenPayload {
	if len(data) < OpenPayloadSize {
		return OpenPayload{}
	}
	return OpenPayload{
		Reliability: Reliability(data[0]),
		Priority:    data[1],
		Dependency:  binary.BigEndian.Uint64(data[2:10]),
	}
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

// EncodeFECHeader encodes an FEC_REPAIR frame header.
func EncodeFECHeader(h FECHeader) []byte {
	data := make([]byte, FECHeaderSize)
	binary.BigEndian.PutUint32(data[0:4], h.GroupID)
	data[4] = h.Index
	data[5] = h.Total
	return data
}

// DecodeFECHeader decodes an FEC_REPAIR frame header.
func DecodeFECHeader(data []byte) FECHeader {
	if len(data) < FECHeaderSize {
		return FECHeader{}
	}
	return FECHeader{
		GroupID: binary.BigEndian.Uint32(data[0:4]),
		Index:   data[4],
		Total:   data[5],
	}
}

// EncodeReset encodes a RESET frame payload.
func EncodeReset(reason ResetReason) []byte {
	data := make([]byte, ResetPayloadSize)
	binary.BigEndian.PutUint32(data, uint32(reason))
	return data
}

// DecodeReset decodes a RESET frame payload.
func DecodeReset(data []byte) ResetReason {
	if len(data) < ResetPayloadSize {
		return ResetCancel
	}
	return ResetReason(binary.BigEndian.Uint32(data))
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

// StatsPayloadSize is the fixed size of a STATS frame payload (34 bytes).
const StatsPayloadSize = 34

// EncodeStats encodes a SessionMetrics into a STATS frame payload.
func EncodeStats(m SessionMetrics) []byte {
	data := make([]byte, StatsPayloadSize)
	binary.BigEndian.PutUint32(data[0:4], uint32(m.RTT.Microseconds()))
	binary.BigEndian.PutUint32(data[4:8], uint32(m.LossPercent*10000)) // ppm
	binary.BigEndian.PutUint32(data[8:12], uint32(m.CWND))
	binary.BigEndian.PutUint32(data[12:16], uint32(m.Retransmits))
	binary.BigEndian.PutUint64(data[16:24], m.FramesSent)
	binary.BigEndian.PutUint64(data[24:32], m.BytesSent)
	binary.BigEndian.PutUint16(data[32:34], uint16(m.ActiveStreams))
	return data
}

// DecodeStats decodes a STATS frame payload into SessionMetrics.
func DecodeStats(data []byte) SessionMetrics {
	if len(data) < StatsPayloadSize {
		return SessionMetrics{}
	}
	return SessionMetrics{
		RTT:           time.Duration(binary.BigEndian.Uint32(data[0:4])) * time.Microsecond,
		LossPercent:   float64(binary.BigEndian.Uint32(data[4:8])) / 10000,
		CWND:          int64(binary.BigEndian.Uint32(data[8:12])),
		Retransmits:   uint64(binary.BigEndian.Uint32(data[12:16])),
		FramesSent:    binary.BigEndian.Uint64(data[16:24]),
		BytesSent:     binary.BigEndian.Uint64(data[24:32]),
		ActiveStreams: int(binary.BigEndian.Uint16(data[32:34])),
	}
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
