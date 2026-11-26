/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package aether

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

// TestFrameGrammar5_CloseCarriesItsSequenceNumberAndIncarnation: a CLOSE's sequence
// number and the stream incarnation its payload states survive the full header,
// which is what lets its peer put it in the receive window, acknowledge it and tell
// it from the CLOSE of another stream under the ID. A CLOSE has a payload, so it
// never takes the eight-byte control short form, and a payload-less CLOSE, which is
// all that form can carry, is refused by Validate before any handler reads it.
func TestFrameGrammar5_CloseCarriesItsSequenceNumberAndIncarnation(t *testing.T) {
	inc := StreamIncarnation{Generation: 0x0102030405060708, WriterOpened: true}
	payload := EncodeClosePayload(inc)
	if want := []byte{0x81, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}; !bytes.Equal(payload, want) || ClosePayloadSize != len(want) {
		t.Fatalf("EncodeClosePayload = % x (size %d), want % x", payload, ClosePayloadSize, want)
	}
	close := &Frame{SenderID: goldenSender, ReceiverID: goldenReceiver, StreamID: 5, Type: TypeCLOSE, SeqNo: 0x01020304,
		Length: uint32(len(payload)), Payload: payload}

	wire := EncodeFrameToBytes(close)
	full, err := DecodeFrameFromBytes(wire)
	if err != nil {
		t.Fatalf("full form: %v", err)
	}
	if full.Type != TypeCLOSE || full.SeqNo != close.SeqNo || DecodeClosePayload(full.Payload) != inc {
		t.Fatalf("full form decoded %+v", full)
	}
	if err := full.Validate(); err != nil {
		t.Fatalf("Validate refused a current CLOSE: %v", err)
	}

	chosen, err := ChooseWireVersions(AetherWireVersions(), AetherWireVersions())
	if err != nil {
		t.Fatalf("ChooseWireVersions: %v", err)
	}
	tx := NewCompressor()
	tx.UseWireVersions(chosen)
	tx.RecordFullHeader(close)
	if tx.ShouldCompressControl(close) {
		t.Fatal("a CLOSE with its incarnation took the payload-less short form")
	}
	bare := &Frame{StreamID: 5, Type: TypeCLOSE, SeqNo: 0x01020304}
	if err := bare.Validate(); err == nil {
		t.Fatal("Validate admitted a CLOSE that names no stream")
	}
	if got := DecodeClosePayload(nil); got != (StreamIncarnation{}) {
		t.Fatalf("an empty CLOSE payload decoded to %+v", got)
	}
}

// TestFrameGrammar5_ResetGolden: a RESET payload is thirty-six bytes, the reason,
// its three credit counts and the stream incarnation big-endian, the incarnation's
// top bit saying the writer opened the stream. A payload of an earlier layout decodes
// to the zero value, and Validate refuses a frame carrying one.
func TestFrameGrammar5_ResetGolden(t *testing.T) {
	p := ResetPayload{Reason: ResetFlowCtrl, Charged: 0x0102030405060708, Released: 0x1112131415161718, Consumed: 0x2122232425262728,
		Incarnation: StreamIncarnation{Generation: 0x3132333435363738}}
	want := []byte{
		0x00, 0x00, 0x00, 0x03,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
	}
	got := EncodeResetPayload(p)
	if !bytes.Equal(got, want) || ResetPayloadSize != len(want) {
		t.Fatalf("EncodeResetPayload = % x (size %d), want % x", got, ResetPayloadSize, want)
	}
	if back := DecodeResetPayload(got); back != p {
		t.Fatalf("DecodeResetPayload = %+v, want %+v", back, p)
	}
	if DecodeReset(got) != ResetFlowCtrl {
		t.Fatalf("DecodeReset = %d", DecodeReset(got))
	}
	opened := p
	opened.Incarnation.WriterOpened = true
	if b := EncodeResetPayload(opened); b[28] != 0xB1 || DecodeResetPayload(b) != opened {
		t.Fatalf("the writer-opened bit: byte 28 = %#x, decoded %+v", b[28], DecodeResetPayload(b))
	}
	if !bytes.Equal(EncodeReset(ResetRefused), EncodeResetPayload(ResetPayload{Reason: ResetRefused})) {
		t.Fatal("EncodeReset states counts or an incarnation")
	}
	for _, n := range []int{4, 28} {
		earlier := got[:n]
		if back := DecodeResetPayload(earlier); back != (ResetPayload{}) {
			t.Fatalf("a %d-byte RESET decoded to %+v", n, back)
		}
		f := &Frame{StreamID: 9, Type: TypeRESET, Length: uint32(len(earlier)), Payload: earlier}
		if err := f.Validate(); err == nil {
			t.Fatalf("Validate admitted a %d-byte RESET frame", n)
		}
	}
	f := &Frame{StreamID: 9, Type: TypeRESET, Length: uint32(len(got)), Payload: got}
	if err := f.Validate(); err != nil {
		t.Fatalf("Validate refused a current RESET: %v", err)
	}
}

// TestFrameGrammar5_GenerationBounds: an OPEN may state a generation from 1 to
// MaxStreamGeneration, which leaves an incarnation's top bit to WriterOpened, and an
// incarnation's generation never reaches that bit however large it is stated.
func TestFrameGrammar5_GenerationBounds(t *testing.T) {
	for g, want := range map[uint64]bool{0: false, 1: true, MaxStreamGeneration: true, MaxStreamGeneration + 1: false, ^uint64(0): false} {
		if ValidStreamGeneration(g) != want {
			t.Fatalf("ValidStreamGeneration(%#x) = %v, want %v", g, !want, want)
		}
	}
	inc := DecodeClosePayload(EncodeClosePayload(StreamIncarnation{Generation: ^uint64(0)}))
	if inc.Generation != MaxStreamGeneration || inc.WriterOpened {
		t.Fatalf("an over-wide generation decoded to %+v", inc)
	}
}

// TestFrameGrammar4_FECRepairGolden: a repair's header is eight bytes, its table
// seven per frame, its repair bytes the rest.
func TestFrameGrammar4_FECRepairGolden(t *testing.T) {
	h := FECHeader{GroupID: 0x01020304, Index: 2, Total: 3, Level: 1, Covered: []FECCovered{
		{SeqNo: 0x0A0B0C0D, Length: 0x0102},
		{SeqNo: 0x0A0B0C0E, Length: 0x0003, Fragment: true},
	}}
	want := []byte{
		0x01, 0x02, 0x03, 0x04, 0x02, 0x03, 0x01, 0x02,
		0x0A, 0x0B, 0x0C, 0x0D, 0x01, 0x02, 0x00,
		0x0A, 0x0B, 0x0C, 0x0E, 0x00, 0x03, 0x01,
	}
	got := EncodeFECHeader(h)
	if !bytes.Equal(got, want) || FECRepairOverhead(2) != len(want) {
		t.Fatalf("EncodeFECHeader = % x (overhead %d), want % x", got, FECRepairOverhead(2), want)
	}
	back, repair, err := DecodeFECHeader(append(got, 0xEE))
	if err != nil || !reflect.DeepEqual(back, h) || !bytes.Equal(repair, []byte{0xEE}) {
		t.Fatalf("decoded %+v, %x, %v", back, repair, err)
	}

	short := &Frame{StreamID: 9, Type: TypeFEC_REPAIR, Length: FECHeaderSize - 1, Payload: got[:FECHeaderSize-1]}
	if err := short.Validate(); err == nil {
		t.Fatal("Validate admitted an FEC_REPAIR shorter than its header")
	}
}

// TestFrameGrammar4_FECRepairRefusals: DecodeFECHeader refuses what no encoder
// writes, before it allocates the table.
func TestFrameGrammar4_FECRepairRefusals(t *testing.T) {
	head := func(count byte) []byte { return []byte{0, 0, 0, 0, 2, 3, 1, count} }
	dup := append(head(2),
		0, 0, 0, 7, 0, 1, 0,
		0, 0, 0, 7, 0, 1, 0)
	cases := map[string][]byte{
		"short":            {1, 2, 3},
		"no frames":        head(0),
		"past the limit":   head(MaxFECCovered + 1),
		"table past input": append(head(2), 0, 0, 0, 7, 0, 1, 0),
		"a frame twice":    dup,
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := DecodeFECHeader(data); !errors.Is(err, ErrFECRepairMalformed) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

// TestShortForms_ASYNKeepsTheFullHeader: a stream ID whose compressor state is still
// held from an earlier stream on the ID does not take a SYN to a short form, which
// has no flags: the peer would read DATA for a stream it does not hold.
func TestShortForms_ASYNKeepsTheFullHeader(t *testing.T) {
	chosen, err := ChooseWireVersions(AetherWireVersions(), AetherWireVersions())
	if err != nil {
		t.Fatalf("ChooseWireVersions: %v", err)
	}
	tx := NewCompressor()
	tx.UseWireVersions(chosen)
	data := &Frame{SenderID: goldenSender, ReceiverID: goldenReceiver, StreamID: 54, Type: TypeDATA, SeqNo: 1, Length: 1, Payload: []byte{1}}
	tx.RecordFullHeader(data)
	data.SeqNo = 2
	if !tx.ShouldCompressData(data) {
		t.Fatal("premise: a plain DATA frame on the stream does not take a short form")
	}
	syn := *data
	syn.Flags = FlagSYN
	if tx.ShouldCompressData(&syn) {
		t.Fatal("a SYN takes a short form")
	}
}
