/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package aether

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

// TestFrameGrammar4_CloseCarriesItsSequenceNumberInBothForms: a CLOSE's sequence
// number survives the full header and the eight-byte control short form, which is
// what lets its peer put it in the receive window and acknowledge it.
func TestFrameGrammar4_CloseCarriesItsSequenceNumberInBothForms(t *testing.T) {
	close := &Frame{SenderID: goldenSender, ReceiverID: goldenReceiver, StreamID: 5, Type: TypeCLOSE, SeqNo: 0x01020304}

	wire := EncodeFrameToBytes(close)
	full, err := DecodeFrameFromBytes(wire)
	if err != nil {
		t.Fatalf("full form: %v", err)
	}
	if full.Type != TypeCLOSE || full.SeqNo != close.SeqNo {
		t.Fatalf("full form decoded %+v", full)
	}

	chosen, err := ChooseWireVersions(AetherWireVersions(), AetherWireVersions())
	if err != nil {
		t.Fatalf("ChooseWireVersions: %v", err)
	}
	tx, rx := NewCompressor(), NewCompressor()
	tx.UseWireVersions(chosen)
	rx.UseWireVersions(chosen)
	tx.RecordFullHeader(close)
	rx.RecordFullHeader(close)
	if !tx.ShouldCompressControl(close) {
		t.Fatal("a CLOSE, which has no payload, does not take the short form")
	}
	var buf bytes.Buffer
	if _, err := tx.EncodeControlShort(&buf, close); err != nil {
		t.Fatalf("encode short: %v", err)
	}
	want := []byte{ShortControlIndicator, byte(TypeCLOSE), 0x00, 0x05, 0x01, 0x02, 0x03, 0x04}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("short form % x, want % x", buf.Bytes(), want)
	}
	short, err := rx.DecodeControlShort(bytes.NewReader(buf.Bytes()[1:]))
	if err != nil {
		t.Fatalf("decode short: %v", err)
	}
	if short.Type != TypeCLOSE || short.SeqNo != close.SeqNo || short.StreamID != 5 {
		t.Fatalf("short form decoded %+v", short)
	}
}

// TestFrameGrammar4_ResetGolden: a RESET payload is twenty-eight bytes, the reason
// and its three credit counts big-endian. A payload of the four-byte layout decodes
// to the zero value, and Validate refuses a frame carrying one.
func TestFrameGrammar4_ResetGolden(t *testing.T) {
	p := ResetPayload{Reason: ResetFlowCtrl, Charged: 0x0102030405060708, Released: 0x1112131415161718, Consumed: 0x2122232425262728}
	want := []byte{
		0x00, 0x00, 0x00, 0x03,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
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
	if !bytes.Equal(EncodeReset(ResetRefused), EncodeResetPayload(ResetPayload{Reason: ResetRefused})) {
		t.Fatal("EncodeReset states counts")
	}
	earlier := got[:4]
	if back := DecodeResetPayload(earlier); back != (ResetPayload{}) {
		t.Fatalf("a four-byte RESET decoded to %+v", back)
	}
	f := &Frame{StreamID: 9, Type: TypeRESET, Length: uint32(len(earlier)), Payload: earlier}
	if err := f.Validate(); err == nil {
		t.Fatal("Validate admitted a RESET frame without the counts")
	}
	f = &Frame{StreamID: 9, Type: TypeRESET, Length: uint32(len(got)), Payload: got}
	if err := f.Validate(); err != nil {
		t.Fatalf("Validate refused a current RESET: %v", err)
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
