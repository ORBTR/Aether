/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package aether

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

func wv(name string, required bool, versions ...uint16) WireVersion {
	return WireVersion{Name: name, Versions: versions, Required: required}
}

func negotiated(pairs ...interface{}) NegotiatedWireVersions {
	var out []NegotiatedWireVersion
	for i := 0; i < len(pairs); i += 2 {
		out = append(out, NegotiatedWireVersion{Name: pairs[i].(string), Version: uint16(pairs[i+1].(int))})
	}
	return NegotiatedWireVersions{entries: out}
}

// TestChooseWireVersions holds the choice rule both ends of a session run:
// the highest version both list per name, a required name with no common
// version or omitted by the other side refuses naming the entry and both
// lists, and an optional name with no common version is left out. Every row
// runs with the sides swapped and must give the same answer.
func TestChooseWireVersions(t *testing.T) {
	cases := []struct {
		name      string
		a, b      WireVersions
		want      NegotiatedWireVersions
		wantEntry string // non-empty: refusal naming this entry
	}{
		{
			name: "equal sets",
			a:    WireVersions{wv("frame", true, 2), wv("frame.short", false, 1)},
			b:    WireVersions{wv("frame", true, 2), wv("frame.short", false, 1)},
			want: negotiated("frame", 2, "frame.short", 1),
		},
		{
			name: "highest common chosen",
			a:    WireVersions{wv("frame", true, 1, 2, 3, 7)},
			b:    WireVersions{wv("frame", true, 2, 3, 5)},
			want: negotiated("frame", 3),
		},
		{
			name:      "disjoint required",
			a:         WireVersions{wv("frame", true, 1)},
			b:         WireVersions{wv("frame", true, 2)},
			wantEntry: "frame",
		},
		{
			name:      "required on one side only, disjoint",
			a:         WireVersions{wv("frame", true, 1)},
			b:         WireVersions{wv("frame", false, 2)},
			wantEntry: "frame",
		},
		{
			name:      "required name the other side omits",
			a:         WireVersions{wv("frame", true, 2), wv("gossip.codec", true, 1)},
			b:         WireVersions{wv("frame", true, 2)},
			wantEntry: "gossip.codec",
		},
		{
			name: "optional name with no common version left out",
			a:    WireVersions{wv("frame", true, 2), wv("frame.short", false, 1)},
			b:    WireVersions{wv("frame", true, 2), wv("frame.short", false, 2)},
			want: negotiated("frame", 2),
		},
		{
			name: "optional name one side omits left out",
			a:    WireVersions{wv("frame", true, 2), wv("frame.short", false, 1)},
			b:    WireVersions{wv("frame", true, 2)},
			want: negotiated("frame", 2),
		},
		{
			name:      "empty offer against a required entry",
			a:         WireVersions{wv("frame", true, 2)},
			b:         nil,
			wantEntry: "frame",
		},
		{
			name: "both empty",
			a:    nil,
			b:    nil,
			want: NegotiatedWireVersions{},
		},
		{
			name:      "first failing entry in name order is reported",
			a:         WireVersions{wv("a.one", true, 1), wv("b.two", true, 1)},
			b:         WireVersions{wv("a.one", true, 2), wv("b.two", true, 2)},
			wantEntry: "a.one",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, swap := range []bool{false, true} {
				local, peer := tc.a, tc.b
				if swap {
					local, peer = tc.b, tc.a
				}
				got, err := ChooseWireVersions(local, peer)
				if tc.wantEntry != "" {
					if !errors.Is(err, ErrWireVersionMismatch) {
						t.Fatalf("swap=%v: err = %v, want ErrWireVersionMismatch", swap, err)
					}
					var mm *WireVersionMismatchError
					if !errors.As(err, &mm) {
						t.Fatalf("swap=%v: err %T is not *WireVersionMismatchError", swap, err)
					}
					if mm.Name != tc.wantEntry {
						t.Fatalf("swap=%v: refused entry %q, want %q", swap, mm.Name, tc.wantEntry)
					}
					if !reflect.DeepEqual(mm.Local, versionsOf(local, tc.wantEntry)) ||
						!reflect.DeepEqual(mm.Peer, versionsOf(peer, tc.wantEntry)) {
						t.Fatalf("swap=%v: error lists local=%v peer=%v, want %v and %v",
							swap, mm.Local, mm.Peer, versionsOf(local, tc.wantEntry), versionsOf(peer, tc.wantEntry))
					}
					if !strings.Contains(err.Error(), tc.wantEntry) {
						t.Fatalf("swap=%v: error text %q does not name %q", swap, err.Error(), tc.wantEntry)
					}
					if len(got.Entries()) != 0 {
						t.Fatalf("swap=%v: a refusal returned a set %v", swap, got.Entries())
					}
					continue
				}
				if err != nil {
					t.Fatalf("swap=%v: unexpected refusal: %v", swap, err)
				}
				if !got.Equal(tc.want) {
					t.Fatalf("swap=%v: chose %v, want %v", swap, got.Entries(), tc.want.Entries())
				}
			}
		})
	}
}

func versionsOf(w WireVersions, name string) []uint16 {
	for _, e := range w {
		if e.Name == name {
			return e.Versions
		}
	}
	return nil
}

// TestChooseWireVersions_RefusesMalformedOffers: an offer that is not in
// canonical form never reaches the choice.
func TestChooseWireVersions_RefusesMalformedOffers(t *testing.T) {
	good := WireVersions{wv("frame", true, 2)}
	bad := []WireVersions{
		{wv("frame", true)},                                 // no versions
		{wv("frame", true, 2, 1)},                           // descending
		{wv("frame", true, 2, 2)},                           // duplicate version
		{wv("frame.short", false, 1), wv("frame", true, 2)}, // names unsorted
		{wv("frame", true, 2), wv("frame", true, 2)},        // duplicate name
		{wv("", true, 2)},                                   // empty name
		{wv("Frame", true, 2)},                              // outside the name alphabet
	}
	for i, b := range bad {
		if _, err := ChooseWireVersions(good, b); !errors.Is(err, ErrWireVersionsMalformed) {
			t.Errorf("case %d: peer %v: err = %v, want ErrWireVersionsMalformed", i, b, err)
		}
		if _, err := ChooseWireVersions(b, good); !errors.Is(err, ErrWireVersionsMalformed) {
			t.Errorf("case %d: local %v: err = %v, want ErrWireVersionsMalformed", i, b, err)
		}
	}
}

// TestWireVersionsEncoding_RoundTrip: the canonical encoding decodes to the
// same set, and its bytes are exactly entries in name order, each
// [u8 name length][name][u8 count][count x u16 big-endian][u8 required].
func TestWireVersionsEncoding_RoundTrip(t *testing.T) {
	set := WireVersions{wv("frame", true, 2), wv("frame.short", false, 1), wv("gossip.codec", true, 1, 3, 0xFFFF)}
	enc, err := set.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	want := []byte{
		5, 'f', 'r', 'a', 'm', 'e', 1, 0x00, 0x02, 1,
		11, 'f', 'r', 'a', 'm', 'e', '.', 's', 'h', 'o', 'r', 't', 1, 0x00, 0x01, 0,
		12, 'g', 'o', 's', 's', 'i', 'p', '.', 'c', 'o', 'd', 'e', 'c', 3, 0x00, 0x01, 0x00, 0x03, 0xFF, 0xFF, 1,
	}
	if !bytes.Equal(enc, want) {
		t.Fatalf("encoding\n got %x\nwant %x", enc, want)
	}
	dec, err := DecodeWireVersions(enc)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !reflect.DeepEqual(dec, set) {
		t.Fatalf("round trip: got %+v want %+v", dec, set)
	}
	empty, err := WireVersions(nil).Encode()
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty set encodes to %x, %v; want no bytes", empty, err)
	}
	if d, err := DecodeWireVersions(nil); err != nil || len(d) != 0 {
		t.Fatalf("no bytes decode to %v, %v; want the empty set", d, err)
	}
}

// TestDecodeWireVersions_RefusesEveryMalformedForm: each non-canonical or
// truncated form is refused, never repaired.
func TestDecodeWireVersions_RefusesEveryMalformedForm(t *testing.T) {
	entry := func(name string, versions []uint16, req byte) []byte {
		b := []byte{byte(len(name))}
		b = append(b, name...)
		b = append(b, byte(len(versions)))
		for _, v := range versions {
			b = append(b, byte(v>>8), byte(v))
		}
		return append(b, req)
	}
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	frame := entry("frame", []uint16{2}, 1)
	cases := map[string][]byte{
		"names out of order":    cat(entry("frame.short", []uint16{1}, 0), frame),
		"duplicate name":        cat(frame, frame),
		"versions descending":   entry("frame", []uint16{3, 2}, 1),
		"duplicate version":     entry("frame", []uint16{2, 2}, 1),
		"zero versions":         entry("frame", nil, 1),
		"empty name":            entry("", []uint16{1}, 0),
		"name outside alphabet": entry("fr ame", []uint16{1}, 0),
		"required not 0 or 1":   entry("frame", []uint16{2}, 2),
		"trailing byte":         cat(frame, []byte{0x00}),
		"truncated in name":     frame[:3],
		"truncated in versions": frame[:8],
		"truncated before flag": frame[:len(frame)-1],
		"name length past end":  {40, 'a'},
		"count past end":        {1, 'a', 3, 0x00, 0x01},
	}
	for name, enc := range cases {
		if _, err := DecodeWireVersions(enc); !errors.Is(err, ErrWireVersionsMalformed) {
			t.Errorf("%s: err = %v, want ErrWireVersionsMalformed", name, err)
		}
	}
}

// TestWireVersionsEncoding_Bound: a set whose encoding exceeds 1 KiB is
// refused on both encode and decode; one at exactly 1 KiB is accepted.
func TestWireVersionsEncoding_Bound(t *testing.T) {
	// One entry: 1 + 8 name bytes + 1 count + 2n + 1 flag = 11 + 2n.
	// n = 255 gives 521; two such entries with names a0000000/a0000001
	// give 1042 > 1024. Build an exact-1024 set: 521 + 503 (n = 246).
	exact := WireVersions{
		{Name: "a0000000", Versions: seq(255), Required: false},
		{Name: "a0000001", Versions: seq(246), Required: false},
	}
	enc, err := exact.Encode()
	if err != nil {
		t.Fatalf("1024-byte set refused: %v", err)
	}
	if len(enc) != MaxWireVersionsEncodedSize {
		t.Fatalf("encoded %d bytes, want %d", len(enc), MaxWireVersionsEncodedSize)
	}
	if _, err := DecodeWireVersions(enc); err != nil {
		t.Fatalf("1024-byte encoding refused on decode: %v", err)
	}
	over := WireVersions{
		{Name: "a0000000", Versions: seq(255), Required: false},
		{Name: "a0000001", Versions: seq(247), Required: false},
	}
	if _, err := over.Encode(); !errors.Is(err, ErrWireVersionsMalformed) {
		t.Fatalf("1026-byte set: err = %v, want ErrWireVersionsMalformed", err)
	}
	overBytes := append(append([]byte(nil), enc...), 8, 'a', '0', '0', '0', '0', '0', '0', '2', 1, 0, 1, 0)
	if _, err := DecodeWireVersions(overBytes); !errors.Is(err, ErrWireVersionsMalformed) {
		t.Fatalf("over-bound bytes: err = %v, want ErrWireVersionsMalformed", err)
	}
	// A u8 count bounds one entry at 255 versions.
	if _, err := (WireVersions{{Name: "a", Versions: seq(256)}}).Encode(); !errors.Is(err, ErrWireVersionsMalformed) {
		t.Fatalf("256 versions: err = %v, want ErrWireVersionsMalformed", err)
	}
}

func seq(n int) []uint16 {
	out := make([]uint16, n)
	for i := range out {
		out[i] = uint16(i + 1)
	}
	return out
}

// TestNegotiatedWireVersionsEncoding: a chosen set round-trips through its
// encoding, and a chosen-set encoding with more than one version or a
// required flag is refused.
func TestNegotiatedWireVersionsEncoding(t *testing.T) {
	n := negotiated("frame", 2, "gossip.codec", 7)
	enc := n.Encode()
	got, err := DecodeNegotiatedWireVersions(enc)
	if err != nil || !got.Equal(n) {
		t.Fatalf("round trip: %v, %v; want %v", got.Entries(), err, n.Entries())
	}
	if v, ok := got.Version("gossip.codec"); !ok || v != 7 {
		t.Fatalf("Version(gossip.codec) = %d, %v", v, ok)
	}
	if _, ok := got.Version("absent"); ok {
		t.Fatalf("Version(absent) reported present")
	}
	twoVersions, _ := WireVersions{wv("frame", false, 1, 2)}.Encode()
	if _, err := DecodeNegotiatedWireVersions(twoVersions); !errors.Is(err, ErrWireVersionsMalformed) {
		t.Fatalf("two versions: err = %v", err)
	}
	required, _ := WireVersions{wv("frame", true, 2)}.Encode()
	if _, err := DecodeNegotiatedWireVersions(required); !errors.Is(err, ErrWireVersionsMalformed) {
		t.Fatalf("required flag: err = %v", err)
	}
	// Entries returns a copy the caller cannot use to change the set.
	e := got.Entries()
	e[0].Version = 99
	if v, _ := got.Version("frame"); v != 2 {
		t.Fatalf("Entries exposed the set's storage")
	}
}

// TestLocalWireVersions: aether's own entries are always present, an
// application's entries are added beside them in name order, and an
// application entry that names an aether entry or is malformed is refused.
func TestLocalWireVersions(t *testing.T) {
	got, err := LocalWireVersions(nil)
	if err != nil {
		t.Fatalf("LocalWireVersions(nil): %v", err)
	}
	want := WireVersions{wv(WireVersionFragment, true, 2), wv(WireVersionFrame, true, WireVersionFrameCurrent), wv(WireVersionFrameShort, false, 1), wv(WireVersionReliability, true, 1)}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("aether entries = %+v, want %+v", got, want)
	}
	app := WireVersions{wv("streams.registry", true, 1), wv("gossip.codec", true, 1)}
	got, err = LocalWireVersions(app)
	if err != nil {
		t.Fatalf("LocalWireVersions(app): %v", err)
	}
	want = WireVersions{wv("fragment", true, 2), wv("frame", true, WireVersionFrameCurrent), wv("frame.short", false, 1), wv("gossip.codec", true, 1), wv("reliability", true, 1), wv("streams.registry", true, 1)}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("merged = %+v, want %+v", got, want)
	}
	if !reflect.DeepEqual(app, WireVersions{wv("streams.registry", true, 1), wv("gossip.codec", true, 1)}) {
		t.Fatalf("LocalWireVersions reordered the caller's slice: %+v", app)
	}
	for _, bad := range []WireVersions{
		{wv(WireVersionFrame, true, 3)},
		{wv(WireVersionFrameShort, false, 1)},
		{wv("gossip.codec", true)},
		{wv("gossip.codec", true, 1), wv("gossip.codec", true, 1)},
	} {
		if _, err := LocalWireVersions(bad); !errors.Is(err, ErrWireVersionsMalformed) {
			t.Errorf("app %+v: err = %v, want ErrWireVersionsMalformed", bad, err)
		}
	}
}

// TestWireVersionsPreface: the preface is "AEWV", a big-endian u16 length,
// then the canonical encoding; the reader refuses a wrong magic, a length
// past the bound and a short body, and reads nothing past the preface.
func TestWireVersionsPreface(t *testing.T) {
	set := WireVersions{wv("frame", true, 2)}
	var buf bytes.Buffer
	if err := WriteWireVersionsPreface(&buf, set); err != nil {
		t.Fatalf("write: %v", err)
	}
	enc, _ := set.Encode()
	want := append([]byte{'A', 'E', 'W', 'V', 0, byte(len(enc))}, enc...)
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("preface %x, want %x", buf.Bytes(), want)
	}
	buf.Write([]byte{0x01, 0x02}) // the first frame's bytes
	got, err := ReadWireVersionsPreface(&buf)
	if err != nil || !reflect.DeepEqual(got, set) {
		t.Fatalf("read: %+v, %v", got, err)
	}
	if rest := buf.Bytes(); !bytes.Equal(rest, []byte{0x01, 0x02}) {
		t.Fatalf("reader consumed past the preface: %x left", rest)
	}

	refuse := map[string][]byte{
		"wrong magic":       append([]byte{'A', 'E', 'W', 'X', 0, byte(len(enc))}, enc...),
		"length past bound": {'A', 'E', 'W', 'V', 0x04, 0x01},
		"short body":        append([]byte{'A', 'E', 'W', 'V', 0, byte(len(enc) + 1)}, enc...),
		"malformed body":    {'A', 'E', 'W', 'V', 0, 1, 0},
	}
	for name, raw := range refuse {
		_, err := ReadWireVersionsPreface(bytes.NewReader(raw))
		if !errors.Is(err, ErrWireVersionsMalformed) && !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("%s: err = %v, want ErrWireVersionsMalformed or io.ErrUnexpectedEOF", name, err)
		}
		if name != "short body" && !errors.Is(err, ErrWireVersionsMalformed) {
			t.Errorf("%s: err = %v, want ErrWireVersionsMalformed", name, err)
		}
	}
}

// TestSessionWireVersions: the accessor reports a session's chosen set when
// the session reports one, and reports false for a session that does not.
func TestSessionWireVersions(t *testing.T) {
	if _, ok := SessionWireVersions(nil); ok {
		t.Fatalf("nil session reported a set")
	}
	r := reporterSession{set: negotiated("frame", 2)}
	got, ok := SessionWireVersions(r)
	if !ok || !got.Equal(r.set) {
		t.Fatalf("got %v, %v", got.Entries(), ok)
	}
}

type reporterSession struct {
	Session
	set NegotiatedWireVersions
}

func (r reporterSession) WireVersions() NegotiatedWireVersions { return r.set }
