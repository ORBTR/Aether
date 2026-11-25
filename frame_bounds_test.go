/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package aether

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"testing"
)

// The tests in this file hold every form of frame grammar 2 to the limits of
// its fields: a payload one byte over MaxPayloadSize, a narrowed field whose
// value does not fit, a sequence reading that would leave the 32-bit space, a
// control type or ACK-lite byte the short-frame table does not admit, and a
// batch of no frames. Each is refused before the decoder slices or allocates a
// payload or records stream state, and before the encoder writes a byte.

// zeroReader yields zero bytes without end, so a header can declare a payload
// no test buffer holds and the count of bytes a decoder pulls is exact.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// headerThen returns a reader of hdr followed by zeros without end.
func headerThen(hdr []byte) io.Reader {
	return io.MultiReader(bytes.NewReader(hdr), zeroReader{})
}

// streamState returns the decoder's recorded sequence and frame count for a
// stream, and whether it holds any state for it.
func streamState(c *Compressor, streamID uint64) (seq uint32, frames int, ok bool) {
	v, loaded := c.streams.Load(streamID)
	if !loaded {
		return 0, 0, false
	}
	s := v.(*StreamCompState)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastSeqNo, s.frameCount, true
}

// fullHeaderBytes is a full frame's discriminator and header for a DATA frame
// on stream 5 declaring length.
func fullHeaderBytes(length uint32) []byte {
	f := goldenFullFrame
	f.Length = length
	f.Payload = nil
	var hdr [FullFrameHeaderWireSize]byte
	putFullFrameHeader(hdr[:], &f)
	return hdr[:]
}

// shortDataHeader is a 0x82 or 0x87 header on stream 5 with the given low
// sequence bits and length.
func shortDataHeader(indicator byte, seqLow uint16, length uint32) []byte {
	hdr := make([]byte, ShortDataSize)
	hdr[0] = indicator
	binary.BigEndian.PutUint16(hdr[1:3], 5)
	binary.BigEndian.PutUint16(hdr[3:5], seqLow)
	binary.BigEndian.PutUint32(hdr[5:9], length)
	return hdr
}

// shortVarHeader is a 0x86 header on stream 5 with the given low sequence
// bits and the canonical varint of length.
func shortVarHeader(seqLow uint16, length uint32) []byte {
	hdr := []byte{ShortDataVarIndicator, 0, 5, 0, 0}
	binary.BigEndian.PutUint16(hdr[3:5], seqLow)
	var v bytes.Buffer
	// A bytes.Buffer write never fails, so EncodeVarLength has no error to give.
	_, _ = EncodeVarLength(&v, length)
	return append(hdr, v.Bytes()...)
}

// TestOneOverLimitPayloadRefusedBeforeAllocationOnEveryForm: a header
// declaring MaxPayloadSize+1 is refused with ErrPayloadTooLarge after exactly
// the header is read, on the full form and on each short DATA form, and the
// refusal creates no stream state; a header declaring MaxPayloadSize decodes.
func TestOneOverLimitPayloadRefusedBeforeAllocationOnEveryForm(t *testing.T) {
	const over = MaxPayloadSize + 1
	cases := []struct {
		name   string
		hdr    []byte
		decode func(t *testing.T, r io.Reader) (*Frame, error)
	}{
		{"full frame, ReadNextFrame", fullHeaderBytes(over), func(t *testing.T, r io.Reader) (*Frame, error) {
			f, _, _, err := ReadNextFrame(r, shortFormCompressor(t))
			return f, err
		}},
		{"full frame, DecodeFrame", fullHeaderBytes(over), func(t *testing.T, r io.Reader) (*Frame, error) {
			return DecodeFrame(r)
		}},
		{"0x82 DATA", shortDataHeader(ShortDataIndicator, 1, over), func(t *testing.T, r io.Reader) (*Frame, error) {
			rx := shortFormCompressor(t)
			f, _, _, err := ReadNextFrame(r, rx)
			if _, _, ok := streamState(rx, 5); ok {
				t.Fatalf("the refused frame created state for stream 5")
			}
			return f, err
		}},
		{"0x87 encrypted DATA", shortDataHeader(ShortEncryptedIndicator, 1, over), func(t *testing.T, r io.Reader) (*Frame, error) {
			rx := shortFormCompressor(t)
			rx.AcceptEncryptedShort() // a session holding a frame key, the one that reads 0x87
			f, _, _, err := ReadNextFrame(r, rx)
			if _, _, ok := streamState(rx, 5); ok {
				t.Fatalf("the refused frame created state for stream 5")
			}
			return f, err
		}},
		{"0x86 DATA varint length", shortVarHeader(1, over), func(t *testing.T, r io.Reader) (*Frame, error) {
			rx := shortFormCompressor(t)
			f, _, _, err := ReadNextFrame(r, rx)
			if _, _, ok := streamState(rx, 5); ok {
				t.Fatalf("the refused frame created state for stream 5")
			}
			return f, err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cr := &countingReader{r: headerThen(tc.hdr)}
			f, err := tc.decode(t, cr)
			if !errors.Is(err, ErrPayloadTooLarge) {
				t.Fatalf("err = %v, want ErrPayloadTooLarge", err)
			}
			if f != nil {
				t.Fatalf("refusal returned a frame %+v", f)
			}
			if cr.n != len(tc.hdr) {
				t.Fatalf("read %d bytes before refusing, want the %d header bytes and no payload", cr.n, len(tc.hdr))
			}
		})
	}

	// From a byte slice the length check comes before the truncation check:
	// a header alone declaring one over the limit is refused for its length,
	// not for the bytes it lacks.
	if _, err := DecodeFrameFromBytes(fullHeaderBytes(over)); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("DecodeFrameFromBytes: err = %v, want ErrPayloadTooLarge", err)
	}
	f := goldenFullFrame
	f.Length = over
	f.Payload = make([]byte, 0)
	if err := f.Validate(); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("Validate: err = %v, want ErrPayloadTooLarge", err)
	}

	// At the limit every form decodes its payload whole.
	for _, tc := range []struct {
		name string
		hdr  []byte
	}{
		{"full frame", fullHeaderBytes(MaxPayloadSize)},
		{"0x82 DATA", shortDataHeader(ShortDataIndicator, 1, MaxPayloadSize)},
		{"0x86 DATA varint length", shortVarHeader(1, MaxPayloadSize)},
	} {
		t.Run("at the limit "+tc.name, func(t *testing.T) {
			rx := shortFormCompressor(t)
			r := io.LimitReader(headerThen(tc.hdr), int64(len(tc.hdr))+MaxPayloadSize)
			f, _, _, err := ReadNextFrame(r, rx)
			if err != nil || f == nil || f.Length != MaxPayloadSize || len(f.Payload) != MaxPayloadSize {
				t.Fatalf("a payload of exactly MaxPayloadSize: frame %v, err %v", f != nil, err)
			}
		})
	}
}

// TestNarrowedFieldsRefuseOverflowBeforeWriting: a short encoder given a
// StreamID the u16 field cannot carry, an ACK payload the 0x88 form's u16
// length cannot carry, or a batch of 0 or 256 frames refuses with a typed
// error and writes nothing; the ShouldCompress checks refuse the same frames,
// so the session write paths never reach the encoders with them; and the
// largest value each field carries encodes.
func TestNarrowedFieldsRefuseOverflowBeforeWriting(t *testing.T) {
	const oversized = uint64(MaxShortHeaderStreamID) + 1
	tx := shortFormCompressor(t)
	primeCompressor(tx)
	tx.RecordFullHeader(&Frame{SenderID: goldenSender, ReceiverID: goldenReceiver, StreamID: oversized, SeqNo: 1})

	data := &Frame{SenderID: goldenSender, ReceiverID: goldenReceiver, StreamID: oversized, Type: TypeDATA, SeqNo: 2, Length: 3, Payload: []byte("abc")}
	enc := &Frame{SenderID: goldenSender, ReceiverID: goldenReceiver, StreamID: oversized, Type: TypeDATA, Flags: FlagENCRYPTED, SeqNo: 2, Length: 3, Payload: []byte("abc")}
	ping := &Frame{SenderID: goldenSender, ReceiverID: goldenReceiver, StreamID: oversized, Type: TypePING, SeqNo: 3}
	ackLite := &Frame{SenderID: goldenSender, ReceiverID: goldenReceiver, StreamID: oversized, Type: TypeACK, Flags: FlagCOMPOSITE_ACK, Length: CompositeACKMinSize, Payload: make([]byte, CompositeACKMinSize)}
	ackFull := &Frame{SenderID: goldenSender, ReceiverID: goldenReceiver, StreamID: oversized, Type: TypeACK, Flags: FlagCOMPOSITE_ACK, Length: 12, Payload: append(make([]byte, 6), 0x04, 0x00, 0, 0, 0, byte(CACKHasGaps))}
	if tx.ShouldCompressData(data) || tx.ShouldCompressData(enc) || tx.ShouldCompressControl(ping) || tx.ShouldCompressACK(ackLite) || tx.ShouldCompressACK(ackFull) {
		t.Fatalf("a frame on stream %d was admitted to a short form", oversized)
	}
	overflow := map[string]func(w io.Writer) (int, error){
		"EncodeDataShort":          func(w io.Writer) (int, error) { return tx.EncodeDataShort(w, data) },
		"EncodeDataShortVar":       func(w io.Writer) (int, error) { return tx.EncodeDataShortVar(w, data) },
		"EncodeEncryptedDataShort": func(w io.Writer) (int, error) { return tx.EncodeEncryptedDataShort(w, enc) },
		"EncodeControlShort":       func(w io.Writer) (int, error) { return tx.EncodeControlShort(w, ping) },
		"EncodeACKShort lite":      func(w io.Writer) (int, error) { return tx.EncodeACKShort(w, ackLite) },
		"EncodeACKShort full":      func(w io.Writer) (int, error) { return tx.EncodeACKShort(w, ackFull) },
	}
	for name, encode := range overflow {
		var buf bytes.Buffer
		n, err := encode(&buf)
		if !errors.Is(err, ErrShortFormOverflow) || n != 0 || buf.Len() != 0 {
			t.Fatalf("%s on stream %d: n=%d err=%v wrote % x; want 0, ErrShortFormOverflow, nothing", name, oversized, n, err, buf.Bytes())
		}
	}

	// An ACK payload past the 0x88 length field, on a stream that fits.
	long := &Frame{SenderID: goldenSender, ReceiverID: goldenReceiver, StreamID: 3, Type: TypeACK, Flags: FlagCOMPOSITE_ACK, Length: 0x10000, Payload: make([]byte, 0x10000)}
	long.Payload[6] = 0x04 // a bitmap, so the frame is not lite
	if tx.ShouldCompressACK(long) {
		t.Fatalf("an ACK of %d bytes was admitted to a short form", long.Length)
	}
	var buf bytes.Buffer
	if n, err := tx.EncodeACKShort(&buf, long); !errors.Is(err, ErrShortFormOverflow) || n != 0 || buf.Len() != 0 {
		t.Fatalf("EncodeACKShort of %d bytes: n=%d err=%v wrote %d bytes", long.Length, n, err, buf.Len())
	}

	// A batch count outside the byte.
	for _, count := range []int{0, 256} {
		frames := make([]*Frame, count)
		for i := range frames {
			frames[i] = &Frame{SenderID: goldenSender, ReceiverID: goldenReceiver, StreamID: 2, Type: TypePING, SeqNo: uint32(i)}
		}
		buf.Reset()
		if n, err := tx.EncodeBatch(&buf, frames); !errors.Is(err, ErrShortFormInvalid) || n != 0 || buf.Len() != 0 {
			t.Fatalf("EncodeBatch of %d frames: n=%d err=%v wrote %d bytes", count, n, err, buf.Len())
		}
	}

	// The largest values the fields carry encode and decode whole.
	edge := shortFormCompressor(t)
	primeCompressor(edge)
	edge.RecordFullHeader(&Frame{SenderID: goldenSender, ReceiverID: goldenReceiver, StreamID: MaxShortHeaderStreamID, SeqNo: 1})
	top := &Frame{SenderID: goldenSender, ReceiverID: goldenReceiver, StreamID: MaxShortHeaderStreamID, Type: TypeDATA, SeqNo: 2, Length: 1, Payload: []byte{7}}
	if !edge.ShouldCompressData(top) {
		t.Fatalf("stream %d, the field's largest value, was not admitted", top.StreamID)
	}
	buf.Reset()
	if _, err := edge.EncodeDataShort(&buf, top); err != nil {
		t.Fatalf("EncodeDataShort on stream %d: %v", top.StreamID, err)
	}
	rx := shortFormCompressor(t)
	primeCompressor(rx)
	got, _, _, err := ReadNextFrame(&buf, rx)
	if err != nil || got.StreamID != MaxShortHeaderStreamID || !bytes.Equal(got.Payload, []byte{7}) {
		t.Fatalf("decoded %+v, %v", got, err)
	}
	ackTop := &Frame{SenderID: goldenSender, ReceiverID: goldenReceiver, StreamID: 3, Type: TypeACK, Flags: FlagCOMPOSITE_ACK, Length: 0xFFFF, Payload: make([]byte, 0xFFFF)}
	ackTop.Payload[6] = 0x04
	buf.Reset()
	if _, err := edge.EncodeACKShort(&buf, ackTop); err != nil {
		t.Fatalf("EncodeACKShort of %d bytes: %v", ackTop.Length, err)
	}
	if got, _, _, err = ReadNextFrame(&buf, rx); err != nil || got.Length != 0xFFFF || len(got.Payload) != 0xFFFF {
		t.Fatalf("decoded ACK of %d bytes, %v", got.Length, err)
	}
	full := make([]*Frame, 255)
	for i := range full {
		full[i] = &Frame{SenderID: goldenSender, ReceiverID: goldenReceiver, StreamID: 2, Type: TypePING, SeqNo: uint32(i)}
	}
	buf.Reset()
	if _, err := edge.EncodeBatch(&buf, full); err != nil {
		t.Fatalf("EncodeBatch of 255 frames: %v", err)
	}
	_, _, batch, err := ReadNextFrame(&buf, rx)
	if err != nil || len(batch) != 255 {
		t.Fatalf("decoded a batch of %d frames, %v", len(batch), err)
	}
}

// TestSequenceWrapRefusedBeforeReadOrState: on each short DATA form, low
// sequence bits that would place the frame past MaxUint32 are refused with
// ErrSequenceWrap after the header, with the payload unread and the stream's
// recorded sequence and frame count unchanged; low bits that name a sequence
// inside the space, a retransmit among them, decode. The encoder keeps a
// frame whose sequence is below the stream's last one in the full header,
// which is how a sequence that has wrapped reaches the peer.
func TestSequenceWrapRefusedBeforeReadOrState(t *testing.T) {
	type form struct {
		name string
		hdr  func(seqLow uint16) []byte
	}
	forms := []form{
		{"0x82 DATA", func(low uint16) []byte { return shortDataHeader(ShortDataIndicator, low, 1) }},
		{"0x87 encrypted DATA", func(low uint16) []byte { return shortDataHeader(ShortEncryptedIndicator, low, 1) }},
		{"0x86 DATA varint length", func(low uint16) []byte { return shortVarHeader(low, 1) }},
	}
	cases := []struct {
		name string
		last uint32
		low  uint16
		want uint32 // 0 with wrap true means refused
		wrap bool
	}{
		{"next after 0xFFFFFFF0", 0xFFFFFFF0, 0xFFF1, 0xFFFFFFF1, false},
		{"retransmit of 0xFFFFFFF0", 0xFFFFFFF0, 0xFFF0, 0xFFFFFFF0, false},
		{"32768 behind 0xFFFFFFF0", 0xFFFFFFF0, 0x7FF1, 0xFFFF7FF1, false},
		{"past the top from 0xFFFFFFF0", 0xFFFFFFF0, 0x0005, 0, true},
		{"just past the top from 0xFFFFFFF0", 0xFFFFFFF0, 0x7FF0, 0, true},
		{"retransmit of 0xFFFFFFFF", math.MaxUint32, 0xFFFF, math.MaxUint32, false},
		{"next after 0xFFFFFFFF", math.MaxUint32, 0x0000, 0, true},
		{"first block, far ahead", 5, 0xFFFF, 0xFFFF, false},
		{"first block, next", 5, 0x0006, 6, false},
	}
	for _, fm := range forms {
		for _, tc := range cases {
			t.Run(fm.name+" "+tc.name, func(t *testing.T) {
				rx := shortFormCompressor(t)
				primeCompressor(rx)
				rx.AcceptEncryptedShort() // 0x87 is read only where a frame key can authenticate it
				rx.RecordFullHeader(&Frame{SenderID: goldenSender, ReceiverID: goldenReceiver, StreamID: 5, Type: TypeDATA, SeqNo: tc.last})
				seqBefore, framesBefore, _ := streamState(rx, 5)
				hdr := fm.hdr(tc.low)
				cr := &countingReader{r: bytes.NewReader(append(hdr, 0xAA))}
				f, ind, _, err := ReadNextFrame(cr, rx)
				if tc.wrap {
					if !errors.Is(err, ErrSequenceWrap) {
						t.Fatalf("frame %+v, err %v; want ErrSequenceWrap", f, err)
					}
					if f != nil || ind != hdr[0] {
						t.Fatalf("refusal returned frame %v indicator 0x%02x", f, ind)
					}
					if cr.n != len(hdr) {
						t.Fatalf("read %d bytes before refusing, want the %d header bytes; the payload stays unread", cr.n, len(hdr))
					}
					seq, frames, _ := streamState(rx, 5)
					if seq != seqBefore || frames != framesBefore {
						t.Fatalf("stream state moved on a refused frame: seq %d->%d frames %d->%d", seqBefore, seq, framesBefore, frames)
					}
					return
				}
				if err != nil || f == nil || f.SeqNo != tc.want || !bytes.Equal(f.Payload, []byte{0xAA}) {
					t.Fatalf("frame %+v, err %v; want sequence %d", f, err, tc.want)
				}
				if seq, frames, _ := streamState(rx, 5); seq != tc.want || frames != framesBefore+1 {
					t.Fatalf("stream state after an admitted frame: seq %d frames %d, want %d and %d", seq, frames, tc.want, framesBefore+1)
				}
			})
		}
	}

	// A stream the decoder has not seen reads its low bits as the sequence
	// inside the first block; a refused header on it creates no state.
	rx := shortFormCompressor(t)
	primeCompressor(rx)
	hdr := shortDataHeader(ShortDataIndicator, 0x1234, 1)
	binary.BigEndian.PutUint16(hdr[1:3], 77)
	f, _, _, err := ReadNextFrame(bytes.NewReader(append(hdr, 1)), rx)
	if err != nil || f.StreamID != 77 || f.SeqNo != 0x1234 {
		t.Fatalf("first frame on an unseen stream: %+v, %v", f, err)
	}
	hdr = shortDataHeader(ShortDataIndicator, 1, MaxPayloadSize+1)
	binary.BigEndian.PutUint16(hdr[1:3], 78)
	if _, _, _, err := ReadNextFrame(headerThen(hdr), rx); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("err = %v", err)
	}
	if _, _, ok := streamState(rx, 78); ok {
		t.Fatalf("a refused header created state for an unseen stream")
	}

	// The encoder: a sequence below the stream's last one, the shape of a
	// wrap, is not admitted to a short form; the next in-space sequence is.
	tx := shortFormCompressor(t)
	primeCompressor(tx)
	tx.RecordFullHeader(&Frame{SenderID: goldenSender, ReceiverID: goldenReceiver, StreamID: 5, Type: TypeDATA, SeqNo: 0xFFFFFFF0})
	wrapped := &Frame{SenderID: goldenSender, ReceiverID: goldenReceiver, StreamID: 5, Type: TypeDATA, SeqNo: 5, Length: 1, Payload: []byte{1}}
	next := &Frame{SenderID: goldenSender, ReceiverID: goldenReceiver, StreamID: 5, Type: TypeDATA, SeqNo: 0xFFFFFFF5, Length: 1, Payload: []byte{1}}
	if tx.ShouldCompressData(wrapped) {
		t.Fatalf("a sequence below the stream's last one was admitted to a short form")
	}
	if !tx.ShouldCompressData(next) {
		t.Fatalf("control: the next sequence inside the space was not admitted")
	}
	tx.RecordFullHeader(&Frame{SenderID: goldenSender, ReceiverID: goldenReceiver, StreamID: 5, Type: TypeDATA, SeqNo: math.MaxUint32})
	if tx.ShouldCompressData(&Frame{SenderID: goldenSender, ReceiverID: goldenReceiver, StreamID: 5, Type: TypeDATA, SeqNo: 0, Length: 1, Payload: []byte{1}}) {
		t.Fatalf("the sequence after MaxUint32 was admitted to a short form")
	}
}

// TestControlShortTypeOutsideTheTableRefused: the 0x83 form carries PING,
// PONG, CLOSE and RESET; a decoder given any other type byte refuses with
// ErrShortFormInvalid and builds no frame, and an encoder given such a frame
// writes nothing. A DATA type in it would give a zero-length DATA frame a
// second encoding beside 0x82.
func TestControlShortTypeOutsideTheTableRefused(t *testing.T) {
	for _, typ := range []byte{0x00, byte(TypeDATA), byte(TypeOPEN), byte(TypeACK), byte(TypeWINDOW), byte(TypeGOAWAY), 0x09, 0x15, 0xFF} {
		rx := shortFormCompressor(t)
		primeCompressor(rx)
		wire := []byte{ShortControlIndicator, typ, 0x00, 0x02, 0, 0, 0, 7}
		f, _, _, err := ReadNextFrame(bytes.NewReader(wire), rx)
		if !errors.Is(err, ErrShortFormInvalid) || f != nil {
			t.Fatalf("control short type 0x%02x: frame %+v, err %v; want ErrShortFormInvalid", typ, f, err)
		}
	}
	for _, typ := range []FrameType{TypePING, TypePONG, TypeCLOSE, TypeRESET} {
		rx := shortFormCompressor(t)
		primeCompressor(rx)
		wire := []byte{ShortControlIndicator, byte(typ), 0x00, 0x02, 0, 0, 0, 7}
		f, _, _, err := ReadNextFrame(bytes.NewReader(wire), rx)
		if err != nil || f.Type != typ || f.StreamID != 2 || f.SeqNo != 7 {
			t.Fatalf("control short type %s: frame %+v, err %v", typ, f, err)
		}
	}
	tx := shortFormCompressor(t)
	primeCompressor(tx)
	for _, typ := range []FrameType{TypeDATA, TypeOPEN, TypeACK, TypeWINDOW} {
		f := &Frame{SenderID: goldenSender, ReceiverID: goldenReceiver, StreamID: 2, Type: typ, SeqNo: 7}
		if tx.ShouldCompressControl(f) {
			t.Fatalf("a %s frame was admitted to the control short form", typ)
		}
		var buf bytes.Buffer
		if n, err := tx.EncodeControlShort(&buf, f); !errors.Is(err, ErrShortFormInvalid) || n != 0 || buf.Len() != 0 {
			t.Fatalf("EncodeControlShort of %s: n=%d err=%v wrote %d bytes", typ, n, err, buf.Len())
		}
	}
}

// TestACKLiteWithBitmapOrFlagsRefused: the 0x84 form inlines an 8-byte
// CompositeACK whose bitmap-length and flags bytes are zero; a non-zero value
// in either claims bytes the fixed form has no room for and is refused with
// ErrShortFormInvalid. The encoder writes such an ACK in the 0x88 form.
func TestACKLiteWithBitmapOrFlagsRefused(t *testing.T) {
	base := []byte{ShortACKIndicator, 0x00, 0x03, 0, 0, 0, 0x2A, 0, 0}
	for _, tail := range [][2]byte{{4, 0}, {32, 0}, {0, byte(CACKHasGaps)}, {0, byte(CACKHasLossDensity)}, {0, byte(CACKNoCumulative)}, {4, byte(CACKHasGaps)}} {
		rx := shortFormCompressor(t)
		primeCompressor(rx)
		wire := append(append([]byte(nil), base...), tail[0], tail[1])
		f, _, _, err := ReadNextFrame(bytes.NewReader(wire), rx)
		if !errors.Is(err, ErrShortFormInvalid) || f != nil {
			t.Fatalf("ACK-lite bitmap length %d flags 0x%02x: frame %+v, err %v; want ErrShortFormInvalid", tail[0], tail[1], f, err)
		}
	}
	rx := shortFormCompressor(t)
	primeCompressor(rx)
	f, _, _, err := ReadNextFrame(bytes.NewReader(append(append([]byte(nil), base...), 0, 0)), rx)
	if err != nil || f.Type != TypeACK || f.AckNo != 42 || f.Length != CompositeACKMinSize {
		t.Fatalf("a well-formed ACK-lite: frame %+v, err %v", f, err)
	}

	tx := shortFormCompressor(t)
	primeCompressor(tx)
	for _, payload := range [][]byte{
		{0, 0, 0, 0x2A, 0, 0, 4, 0, 1, 2, 3, 4},
		{0, 0, 0, 0x2A, 0, 0, 0, byte(CACKHasGaps)},
	} {
		ack := &Frame{SenderID: goldenSender, ReceiverID: goldenReceiver, StreamID: 3, Type: TypeACK, Flags: FlagCOMPOSITE_ACK, Length: uint32(len(payload)), Payload: payload}
		var buf bytes.Buffer
		if _, err := tx.EncodeACKShort(&buf, ack); err != nil {
			t.Fatalf("EncodeACKShort: %v", err)
		}
		if buf.Bytes()[0] != ShortACKFullIndicator {
			t.Fatalf("an ACK with bitmap or flags was written as 0x%02x, want the 0x88 form", buf.Bytes()[0])
		}
	}
}

// TestZeroCountBatchRefused: a batch whose count byte is zero is a form no
// encoder of the grammar writes; the decoder refuses it with
// ErrShortFormInvalid after the count byte and reads nothing more.
func TestZeroCountBatchRefused(t *testing.T) {
	rx := shortFormCompressor(t)
	primeCompressor(rx)
	cr := &countingReader{r: bytes.NewReader(append([]byte{ShortBatchIndicator, 0x00}, goldenFullFrameBytes...))}
	f, _, batch, err := ReadNextFrame(cr, rx)
	if !errors.Is(err, ErrShortFormInvalid) || f != nil || batch != nil {
		t.Fatalf("frame %v batch %v err %v; want ErrShortFormInvalid", f, batch, err)
	}
	if cr.n != 2 {
		t.Fatalf("read %d bytes before refusing, want the indicator and the count", cr.n)
	}
	tx := shortFormCompressor(t)
	var buf bytes.Buffer
	if n, err := tx.EncodeBatch(&buf, nil); !errors.Is(err, ErrShortFormInvalid) || n != 0 || buf.Len() != 0 {
		t.Fatalf("EncodeBatch of no frames: n=%d err=%v wrote %d bytes", n, err, buf.Len())
	}
}
