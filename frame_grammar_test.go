/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package aether

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// shortFormCompressor returns a Compressor whose session chose frame.short,
// the grammar the short-form tests below and the older codec tests exercise.
func shortFormCompressor(t testing.TB) *Compressor {
	t.Helper()
	chosen, err := ChooseWireVersions(AetherWireVersions(), AetherWireVersions())
	if err != nil {
		t.Fatalf("ChooseWireVersions: %v", err)
	}
	c := NewCompressor()
	c.UseWireVersions(chosen)
	if !c.ShortForms() {
		t.Fatalf("a session that chose %v has no short forms", chosen)
	}
	return c
}

// fullOnlyVersions is the set a session chooses with a peer that offers the
// frame grammar and not the short-form table.
func fullOnlyVersions(t testing.TB) NegotiatedWireVersions {
	t.Helper()
	peer := WireVersions{{Name: WireVersionFrame, Versions: []uint16{wireVersionFrameCurrent}, Required: true}}
	chosen, err := ChooseWireVersions(AetherWireVersions(), peer)
	if err != nil {
		t.Fatalf("ChooseWireVersions: %v", err)
	}
	if _, ok := chosen.Version(WireVersionFrameShort); ok {
		t.Fatalf("set %v chose frame.short", chosen)
	}
	return chosen
}

// countingReader counts the bytes a decoder pulls, so a test can show a
// refusal read nothing past the discriminator.
type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// goldenFullFrame and goldenFullFrameBytes are one full frame and its exact
// wire form: the discriminator 0x01, the 50-byte header, then the payload.
// SenderID[0] is 0x82, a short-form value, which the discriminator makes
// irrelevant to the reader.
var goldenFullFrame = Frame{
	SenderID:   PeerID{0x82, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
	ReceiverID: PeerID{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18},
	StreamID:   0x0102030405060708,
	Type:       TypeDATA,
	Flags:      FlagSYN,
	SeqNo:      0x0A0B0C0D,
	AckNo:      0x01020304,
	Length:     3,
	Nonce:      [12]byte{0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B},
	Payload:    []byte("abc"),
}

var goldenFullFrameBytes = []byte{
	0x01,                                           // discriminator
	0x82, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // SenderID
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, // ReceiverID
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // StreamID
	0x01,                   // Type DATA
	0x02,                   // Flags SYN
	0x0A, 0x0B, 0x0C, 0x0D, // SeqNo
	0x01, 0x02, 0x03, 0x04, // AckNo
	0x00, 0x00, 0x00, 0x03, // Length
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, // Nonce
	'a', 'b', 'c',
}

func sameFullFrame(t *testing.T, got *Frame, want *Frame) {
	t.Helper()
	if got.SenderID != want.SenderID || got.ReceiverID != want.ReceiverID ||
		got.StreamID != want.StreamID || got.Type != want.Type || got.Flags != want.Flags ||
		got.SeqNo != want.SeqNo || got.AckNo != want.AckNo || got.Length != want.Length ||
		got.Nonce != want.Nonce || !bytes.Equal(got.Payload, want.Payload) {
		t.Fatalf("decoded %+v, want %+v", got, want)
	}
}

// TestFullFrameGolden: every full-frame encoder writes the discriminator and
// the unchanged header, and every full-frame decoder reads that form, whether
// or not the session chose the short forms.
func TestFullFrameGolden(t *testing.T) {
	f := goldenFullFrame

	var buf bytes.Buffer
	n, err := EncodeFrame(&buf, &f)
	if err != nil {
		t.Fatalf("EncodeFrame: %v", err)
	}
	if n != len(goldenFullFrameBytes) || !bytes.Equal(buf.Bytes(), goldenFullFrameBytes) {
		t.Fatalf("EncodeFrame wrote %d bytes % x\nwant % x", n, buf.Bytes(), goldenFullFrameBytes)
	}
	if got := EncodeFrameToBytes(&f); !bytes.Equal(got, goldenFullFrameBytes) {
		t.Fatalf("EncodeFrameToBytes wrote % x\nwant % x", got, goldenFullFrameBytes)
	}
	var hdr bytes.Buffer
	if n, err := EncodeHeaderOnly(&hdr, &f); err != nil || n != 1+HeaderSize {
		t.Fatalf("EncodeHeaderOnly = %d, %v; want %d bytes", n, err, 1+HeaderSize)
	}
	if !bytes.Equal(hdr.Bytes(), goldenFullFrameBytes[:1+HeaderSize]) {
		t.Fatalf("EncodeHeaderOnly wrote % x", hdr.Bytes())
	}

	got, err := DecodeFrame(bytes.NewReader(goldenFullFrameBytes))
	if err != nil {
		t.Fatalf("DecodeFrame: %v", err)
	}
	sameFullFrame(t, got, &f)

	got, err = DecodeFrameFromBytes(goldenFullFrameBytes)
	if err != nil {
		t.Fatalf("DecodeFrameFromBytes: %v", err)
	}
	sameFullFrame(t, got, &f)

	for _, c := range []struct {
		name string
		rx   *Compressor
	}{{"full-only", NewCompressor()}, {"short-forms", shortFormCompressor(t)}} {
		r := bytes.NewReader(goldenFullFrameBytes)
		got, ind, batch, err := ReadNextFrame(r, c.rx)
		if err != nil || batch != nil {
			t.Fatalf("%s: ReadNextFrame = %v, batch %v", c.name, err, batch)
		}
		if ind != FullFrameDiscriminator {
			t.Fatalf("%s: indicator 0x%02x, want 0x%02x", c.name, ind, FullFrameDiscriminator)
		}
		sameFullFrame(t, got, &f)
		if r.Len() != 0 {
			t.Fatalf("%s: %d bytes left unread", c.name, r.Len())
		}
	}
}

// TestFullFrameAnySenderIDFirstByteDecodesAsFull: a full frame is a full frame
// whatever byte its SenderID begins with. The values 0x82-0x8F lie in the
// short-form range; a reader that takes a full frame's first header byte as its
// form reads those as short frames and loses the session's byte stream.
func TestFullFrameAnySenderIDFirstByteDecodesAsFull(t *testing.T) {
	for _, short := range []bool{false, true} {
		for b := 0; b < 256; b++ {
			f := goldenFullFrame
			f.SenderID[0] = byte(b)
			wire := EncodeFrameToBytes(&f)
			rx := NewCompressor()
			if short {
				rx = shortFormCompressor(t)
			}
			// A second frame behind the first shows the reader consumed
			// exactly one frame's bytes.
			r := bytes.NewReader(append(append([]byte(nil), wire...), wire...))
			for i := 0; i < 2; i++ {
				got, ind, batch, err := ReadNextFrame(r, rx)
				if err != nil {
					t.Fatalf("short=%v SenderID[0]=0x%02x frame %d: %v", short, b, i, err)
				}
				if batch != nil || ind != FullFrameDiscriminator {
					t.Fatalf("short=%v SenderID[0]=0x%02x frame %d: read as indicator 0x%02x", short, b, i, ind)
				}
				sameFullFrame(t, got, &f)
			}
			if r.Len() != 0 {
				t.Fatalf("short=%v SenderID[0]=0x%02x: %d bytes left", short, b, r.Len())
			}
		}
	}
}

// shortGolden is one short form: the frame the encoder is given, the exact
// bytes it writes, and the frame the decoder rebuilds from them.
type shortGolden struct {
	name   string
	encode func(c *Compressor, w io.Writer) (int, error)
	wire   []byte
	check  func(t *testing.T, f *Frame, batch []*Frame)
}

var (
	goldenSender   = PeerID{0x8F, 1, 1, 1, 1, 1, 1, 1}
	goldenReceiver = PeerID{0x82, 2, 2, 2, 2, 2, 2, 2}
)

// primeCompressor records the full header that gives a short form its
// identity, as the first full frame of a session does.
func primeCompressor(c *Compressor) {
	c.RecordFullHeader(&Frame{SenderID: goldenSender, ReceiverID: goldenReceiver, StreamID: 5, SeqNo: 0x00010200})
}

func shortGoldens() []shortGolden {
	ackLite := []byte{0x00, 0x00, 0x00, 0x2A, 0x00, 0x00, 0x00, 0x00}
	ackFull := []byte{0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x02, 0xFF, 0x00, byte(CACKHasGaps)}
	ping := &Frame{SenderID: goldenSender, ReceiverID: goldenReceiver, StreamID: 2, Type: TypePING, SeqNo: 7}
	open := &Frame{SenderID: goldenSender, ReceiverID: goldenReceiver, StreamID: 9, Type: TypeOPEN}
	return []shortGolden{
		{
			name: "0x82 DATA",
			encode: func(c *Compressor, w io.Writer) (int, error) {
				return c.EncodeDataShort(w, &Frame{StreamID: 5, Type: TypeDATA, SeqNo: 0x00010203, Length: 3, Payload: []byte("abc")})
			},
			wire: []byte{0x82, 0x00, 0x05, 0x02, 0x03, 0x00, 0x00, 0x00, 0x03, 'a', 'b', 'c'},
			check: func(t *testing.T, f *Frame, _ []*Frame) {
				if f.Type != TypeDATA || f.StreamID != 5 || f.SeqNo != 0x00010203 || !bytes.Equal(f.Payload, []byte("abc")) || f.SenderID != goldenSender {
					t.Fatalf("decoded %+v", f)
				}
			},
		},
		{
			name: "0x83 control",
			encode: func(c *Compressor, w io.Writer) (int, error) {
				return c.EncodeControlShort(w, ping)
			},
			wire: []byte{0x83, 0x06, 0x00, 0x02, 0x00, 0x00, 0x00, 0x07},
			check: func(t *testing.T, f *Frame, _ []*Frame) {
				if f.Type != TypePING || f.StreamID != 2 || f.SeqNo != 7 || f.ReceiverID != goldenReceiver {
					t.Fatalf("decoded %+v", f)
				}
			},
		},
		{
			name: "0x84 ACK-lite",
			encode: func(c *Compressor, w io.Writer) (int, error) {
				return c.EncodeACKShort(w, &Frame{StreamID: 3, Type: TypeACK, Flags: FlagCOMPOSITE_ACK, Length: CompositeACKMinSize, Payload: ackLite})
			},
			wire: append([]byte{0x84, 0x00, 0x03}, ackLite...),
			check: func(t *testing.T, f *Frame, _ []*Frame) {
				if f.Type != TypeACK || f.StreamID != 3 || f.AckNo != 42 || !bytes.Equal(f.Payload, ackLite) {
					t.Fatalf("decoded %+v", f)
				}
			},
		},
		{
			name: "0x85 batch",
			encode: func(c *Compressor, w io.Writer) (int, error) {
				return c.EncodeBatch(w, []*Frame{ping, open})
			},
			wire: append([]byte{
				0x85, 0x02,
				0x83, 0x06, 0x00, 0x02, 0x00, 0x00, 0x00, 0x07,
				0x01,
				0x8F, 1, 1, 1, 1, 1, 1, 1,
				0x82, 2, 2, 2, 2, 2, 2, 2,
				0, 0, 0, 0, 0, 0, 0, 9,
				0x02, 0x00,
				0, 0, 0, 0,
				0, 0, 0, 0,
				0, 0, 0, 0,
			}, make([]byte, 12)...),
			check: func(t *testing.T, f *Frame, batch []*Frame) {
				if f != nil || len(batch) != 2 {
					t.Fatalf("decoded frame %v batch %d", f, len(batch))
				}
				if batch[0].Type != TypePING || batch[0].SeqNo != 7 {
					t.Fatalf("child 0 %+v", batch[0])
				}
				if batch[1].Type != TypeOPEN || batch[1].StreamID != 9 || batch[1].SenderID != goldenSender {
					t.Fatalf("child 1 %+v", batch[1])
				}
			},
		},
		{
			name: "0x86 DATA varint length",
			encode: func(c *Compressor, w io.Writer) (int, error) {
				return c.EncodeDataShortVar(w, &Frame{StreamID: 5, Type: TypeDATA, SeqNo: 0x00010204, Length: 3, Payload: []byte("xyz")})
			},
			wire: []byte{0x86, 0x00, 0x05, 0x02, 0x04, 0x03, 'x', 'y', 'z'},
			check: func(t *testing.T, f *Frame, _ []*Frame) {
				if f.Type != TypeDATA || f.StreamID != 5 || f.SeqNo != 0x00010204 || !bytes.Equal(f.Payload, []byte("xyz")) {
					t.Fatalf("decoded %+v", f)
				}
			},
		},
		{
			name: "0x87 encrypted DATA",
			encode: func(c *Compressor, w io.Writer) (int, error) {
				return c.EncodeEncryptedDataShort(w, &Frame{StreamID: 5, Type: TypeDATA, Flags: FlagENCRYPTED, SeqNo: 0x00010205, Length: 2, Payload: []byte{0xEE, 0xFF}})
			},
			wire: []byte{0x87, 0x00, 0x05, 0x02, 0x05, 0x00, 0x00, 0x00, 0x02, 0xEE, 0xFF},
			check: func(t *testing.T, f *Frame, _ []*Frame) {
				if f.StreamID != 5 || f.SeqNo != 0x00010205 || !bytes.Equal(f.Payload, []byte{0xEE, 0xFF}) {
					t.Fatalf("decoded %+v", f)
				}
			},
		},
		{
			name: "0x88 ACK-full",
			encode: func(c *Compressor, w io.Writer) (int, error) {
				return c.EncodeACKShort(w, &Frame{StreamID: 3, Type: TypeACK, Flags: FlagCOMPOSITE_ACK, Length: uint32(len(ackFull)), Payload: ackFull})
			},
			wire: append([]byte{0x88, 0x00, 0x03, 0x00, byte(len(ackFull))}, ackFull...),
			check: func(t *testing.T, f *Frame, _ []*Frame) {
				if f.Type != TypeACK || f.StreamID != 3 || !bytes.Equal(f.Payload, ackFull) {
					t.Fatalf("decoded %+v", f)
				}
			},
		},
	}
}

// TestShortFormGoldens: each short form a session that chose frame.short
// writes has the exact bytes of the short-frame table, and ReadNextFrame on
// such a session reads them back.
func TestShortFormGoldens(t *testing.T) {
	for _, g := range shortGoldens() {
		t.Run(g.name, func(t *testing.T) {
			tx := shortFormCompressor(t)
			primeCompressor(tx)
			var buf bytes.Buffer
			n, err := g.encode(tx, &buf)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			if n != len(g.wire) || !bytes.Equal(buf.Bytes(), g.wire) {
				t.Fatalf("wrote %d bytes % x\nwant % x", n, buf.Bytes(), g.wire)
			}
			rx := shortFormCompressor(t)
			primeCompressor(rx)
			r := bytes.NewReader(g.wire)
			f, ind, batch, err := ReadNextFrame(r, rx)
			if err != nil {
				t.Fatalf("ReadNextFrame: %v", err)
			}
			if ind != g.wire[0] {
				t.Fatalf("indicator 0x%02x, want 0x%02x", ind, g.wire[0])
			}
			if r.Len() != 0 {
				t.Fatalf("%d bytes left unread", r.Len())
			}
			g.check(t, f, batch)
		})
	}
}

// TestUnnegotiatedShortFormRefusedOnRead: a session that did not choose
// frame.short refuses every short-form discriminator with a
// *FrameDiscriminatorError and reads nothing past it, through ReadNextFrame
// and through each short decoder.
func TestUnnegotiatedShortFormRefusedOnRead(t *testing.T) {
	for _, g := range shortGoldens() {
		t.Run(g.name, func(t *testing.T) {
			for _, rx := range []*Compressor{NewCompressor(), func() *Compressor {
				c := NewCompressor()
				c.UseWireVersions(fullOnlyVersions(t))
				return c
			}()} {
				primeCompressor(rx)
				cr := &countingReader{r: bytes.NewReader(g.wire)}
				f, ind, batch, err := ReadNextFrame(cr, rx)
				var de *FrameDiscriminatorError
				if !errors.As(err, &de) || !errors.Is(err, ErrFrameDiscriminator) {
					t.Fatalf("ReadNextFrame err = %v, want a *FrameDiscriminatorError", err)
				}
				if de.Discriminator != g.wire[0] || de.ShortForms {
					t.Fatalf("error %+v", de)
				}
				if f != nil || batch != nil || ind != g.wire[0] {
					t.Fatalf("refusal returned frame %v batch %v indicator 0x%02x", f, batch, ind)
				}
				if cr.n != 1 {
					t.Fatalf("read %d bytes before refusing, want 1", cr.n)
				}
			}
		})
	}

	rx := NewCompressor()
	primeCompressor(rx)
	body := bytes.NewReader([]byte{0x00, 0x05, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00})
	direct := map[string]func() error{
		"DecodeDataShort":          func() error { _, err := rx.DecodeDataShort(body); return err },
		"DecodeDataShortVar":       func() error { _, err := rx.DecodeDataShortVar(body); return err },
		"DecodeEncryptedDataShort": func() error { _, err := rx.DecodeEncryptedDataShort(body); return err },
		"DecodeControlShort":       func() error { _, err := rx.DecodeControlShort(body); return err },
		"DecodeACKShort":           func() error { _, err := rx.DecodeACKShort(body); return err },
		"DecodeACKShortFull":       func() error { _, err := rx.DecodeACKShortFull(body); return err },
		"DecodeBatch":              func() error { _, err := rx.DecodeBatch(body); return err },
	}
	for name, decode := range direct {
		if err := decode(); !errors.Is(err, ErrFrameDiscriminator) {
			t.Fatalf("%s on a full-only session: err = %v, want ErrFrameDiscriminator", name, err)
		}
	}
	if body.Len() != 8 {
		t.Fatalf("the short decoders read %d bytes on a full-only session", 8-body.Len())
	}
}

// TestUnnegotiatedShortFormNeverWritten: a session that did not choose
// frame.short admits no frame to a short form and its short encoders write
// nothing; the same frames on a session that chose it do compress, so the
// refusal is the grammar's and not the frames'.
func TestUnnegotiatedShortFormNeverWritten(t *testing.T) {
	data := &Frame{SenderID: goldenSender, ReceiverID: goldenReceiver, StreamID: 5, Type: TypeDATA, SeqNo: 0x00010201, Length: 3, Payload: []byte("abc")}
	ping := &Frame{SenderID: goldenSender, ReceiverID: goldenReceiver, StreamID: 2, Type: TypePING, SeqNo: 7}
	ack := &Frame{SenderID: goldenSender, ReceiverID: goldenReceiver, StreamID: 5, Type: TypeACK, Flags: FlagCOMPOSITE_ACK, Length: CompositeACKMinSize, Payload: make([]byte, CompositeACKMinSize)}

	on := shortFormCompressor(t)
	primeCompressor(on)
	if !on.ShouldCompressData(data) || !on.ShouldCompressControl(ping) || !on.ShouldCompressACK(ack) {
		t.Fatalf("control: a session that chose frame.short does not compress these frames")
	}

	for name, off := range map[string]*Compressor{"no set": NewCompressor(), "full-only set": func() *Compressor {
		c := NewCompressor()
		c.UseWireVersions(fullOnlyVersions(t))
		return c
	}()} {
		primeCompressor(off)
		if off.ShortForms() {
			t.Fatalf("%s: ShortForms() is true", name)
		}
		if off.ShouldCompressData(data) || off.ShouldCompressControl(ping) || off.ShouldCompressACK(ack) {
			t.Fatalf("%s: a frame was admitted to a short form", name)
		}
		var buf bytes.Buffer
		encoders := map[string]func() (int, error){
			"EncodeDataShort":          func() (int, error) { return off.EncodeDataShort(&buf, data) },
			"EncodeDataShortVar":       func() (int, error) { return off.EncodeDataShortVar(&buf, data) },
			"EncodeEncryptedDataShort": func() (int, error) { return off.EncodeEncryptedDataShort(&buf, data) },
			"EncodeControlShort":       func() (int, error) { return off.EncodeControlShort(&buf, ping) },
			"EncodeACKShort":           func() (int, error) { return off.EncodeACKShort(&buf, ack) },
			"EncodeBatch":              func() (int, error) { return off.EncodeBatch(&buf, []*Frame{ping, data}) },
		}
		for enc, call := range encoders {
			if n, err := call(); !errors.Is(err, ErrShortFormsNotNegotiated) || n != 0 {
				t.Fatalf("%s: %s = %d, %v; want 0, ErrShortFormsNotNegotiated", name, enc, n, err)
			}
		}
		if buf.Len() != 0 {
			t.Fatalf("%s: short encoders wrote % x", name, buf.Bytes())
		}
	}
}

// TestReservedDiscriminatorsRefuseBeforeAllocation: every first byte that is
// neither 0x01 nor a short form the session chose is refused after reading
// that one byte, with nothing allocated for a header or payload.
func TestReservedDiscriminatorsRefuseBeforeAllocation(t *testing.T) {
	for _, short := range []bool{false, true} {
		rx := NewCompressor()
		if short {
			rx = shortFormCompressor(t)
		}
		for b := 0; b < 256; b++ {
			allowed := b == int(FullFrameDiscriminator) || (short && b >= 0x82 && b <= 0x88)
			if allowed {
				continue
			}
			// A body that would decode as a header and a large payload if a
			// reader went past the discriminator.
			wire := append([]byte{byte(b)}, bytes.Repeat([]byte{0x7F}, HeaderSize+64)...)
			cr := &countingReader{r: bytes.NewReader(wire)}
			_, ind, _, err := ReadNextFrame(cr, rx)
			var de *FrameDiscriminatorError
			if !errors.As(err, &de) || de.Discriminator != byte(b) || de.ShortForms != short {
				t.Fatalf("short=%v first byte 0x%02x: err = %v", short, b, err)
			}
			if ind != byte(b) || cr.n != 1 {
				t.Fatalf("short=%v first byte 0x%02x: indicator 0x%02x, read %d bytes", short, b, ind, cr.n)
			}
			r := bytes.NewReader(wire)
			allocs := testing.AllocsPerRun(20, func() {
				r.Reset(wire)
				_, _, _, _ = ReadNextFrame(r, rx)
			})
			// Two allocations remain: the one-byte read buffer, which escapes
			// through the io.Reader call, and the returned error.
			if allocs > 2 {
				t.Fatalf("short=%v first byte 0x%02x: %v allocations per refusal, want at most the read buffer and the error", short, b, allocs)
			}
		}
	}
}

// TestFullFrameDecodersRefuseOtherDiscriminators: the full-frame decoders that
// are entered directly refuse a first byte other than 0x01 before reading a
// header.
func TestFullFrameDecodersRefuseOtherDiscriminators(t *testing.T) {
	for _, b := range []byte{0x00, 0x02, 0x7F, 0x80, 0x82, 0x85, 0x8F, 0xFF} {
		wire := append([]byte{b}, goldenFullFrameBytes[1:]...)
		cr := &countingReader{r: bytes.NewReader(wire)}
		if _, err := DecodeFrame(cr); !errors.Is(err, ErrFrameDiscriminator) || cr.n != 1 {
			t.Fatalf("DecodeFrame first byte 0x%02x: err = %v after %d bytes", b, err, cr.n)
		}
		if _, err := DecodeFrameFromBytes(wire); !errors.Is(err, ErrFrameDiscriminator) {
			t.Fatalf("DecodeFrameFromBytes first byte 0x%02x: err = %v", b, err)
		}
		cr = &countingReader{r: bytes.NewReader(wire[1:])}
		if _, err := DecodeFrameWithFirstByte(cr, b); !errors.Is(err, ErrFrameDiscriminator) || cr.n != 0 {
			t.Fatalf("DecodeFrameWithFirstByte 0x%02x: err = %v after %d bytes", b, err, cr.n)
		}
	}
	if _, err := DecodeFrameFromBytes(goldenFullFrameBytes[:HeaderSize]); err == nil {
		t.Fatalf("DecodeFrameFromBytes accepted a frame one byte short of its header")
	}
}

// TestBatchChildDiscriminators: a batch child is a full frame behind 0x01 or
// one of the short forms a batch may carry; any other first byte, a nested
// batch among them, refuses the batch.
func TestBatchChildDiscriminators(t *testing.T) {
	for _, b := range []byte{0x00, 0x02, 0x7F, 0x80, 0x81, 0x85, 0x89, 0x8F, 0xFF} {
		body := append([]byte{0x01, b}, goldenFullFrameBytes[1:]...)
		rx := shortFormCompressor(t)
		frames, err := rx.DecodeBatch(bytes.NewReader(body))
		var de *FrameDiscriminatorError
		if !errors.As(err, &de) || de.Discriminator != b {
			t.Fatalf("batch child 0x%02x: frames %d err = %v", b, len(frames), err)
		}
	}
	rx := shortFormCompressor(t)
	frames, err := rx.DecodeBatch(bytes.NewReader(append([]byte{0x01}, goldenFullFrameBytes...)))
	if err != nil || len(frames) != 1 {
		t.Fatalf("a full-frame child: frames %d err %v", len(frames), err)
	}
	f := goldenFullFrame
	sameFullFrame(t, frames[0], &f)
}

// TestUseWireVersions: short forms follow the chosen set, frame.short at the
// version this build speaks; an empty set leaves full frames only.
func TestUseWireVersions(t *testing.T) {
	both, _ := ChooseWireVersions(AetherWireVersions(), AetherWireVersions())
	cases := []struct {
		name string
		set  NegotiatedWireVersions
		want bool
	}{
		{"aether's own set", both, true},
		{"frame only", fullOnlyVersions(t), false},
		{"empty set", NegotiatedWireVersions{}, false},
	}
	for _, c := range cases {
		comp := NewCompressor()
		comp.UseWireVersions(c.set)
		if comp.ShortForms() != c.want {
			t.Fatalf("%s: ShortForms() = %v, want %v", c.name, comp.ShortForms(), c.want)
		}
	}
	if NewCompressor().ShortForms() {
		t.Fatalf("a new Compressor has short forms before any set is applied")
	}
}
