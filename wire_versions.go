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
	"sort"
	"strings"
)

// WireVersion is one named wire grammar or envelope a peer offers in its
// handshake: the versions it can speak, ascending, and whether a session may
// exist without one of them chosen. aether names its own entries
// (WireVersionFragment, WireVersionFrame, WireVersionFrameShort); an
// application adds names of its own, which aether negotiates and reports
// without reading.
type WireVersion struct {
	Name     string
	Versions []uint16
	Required bool
}

// WireVersions is the set one side offers, in canonical form: entries
// strictly ascending by name, each with one to 255 strictly ascending
// versions. The Noise handshake (crypto/identity NodeInfo, noise
// DialOverConn's payload) and the byte-stream session preface carry it in the
// encoding Encode writes.
type WireVersions []WireVersion

// The entries aether registers for itself. fragment is the envelope a message
// larger than one frame travels in (adapter.FragmentEnvelope); it is required
// because a session that cannot read its peer's fragments cannot carry the
// messages they make up. frame is the full-frame grammar a session's frames are
// read and written in; it is required because no frame can be read without it.
// frame.short is the short-frame table; it is optional because a session that
// does not choose it writes full frames only.
const (
	WireVersionFragment   = "fragment"
	WireVersionFrame      = "frame"
	WireVersionFrameShort = "frame.short"

	// WireVersionFragmentCurrent is the fragment envelope version this build
	// writes and reads; adapter.FragmentEnvelope's version byte carries it.
	WireVersionFragmentCurrent   uint16 = 2
	wireVersionFrameCurrent      uint16 = 2
	wireVersionFrameShortCurrent uint16 = 1
)

// MaxWireVersionsEncodedSize bounds one encoded set. The preface reader and
// the NodeInfo decoders refuse a larger declaration before allocating for it,
// so a peer cannot make the handshake buffer an unbounded body.
const MaxWireVersionsEncodedSize = 1024

// wireVersionsPrefaceMagic opens the byte-stream session preface
// (WriteWireVersionsPreface). A conn whose first four bytes differ is refused
// before any frame decoder runs.
var wireVersionsPrefaceMagic = [4]byte{'A', 'E', 'W', 'V'}

// ErrWireVersionMismatch is the refusal both ends of a handshake return when
// a required entry has no version both sides list. errors.Is matches it on a
// *WireVersionMismatchError, which names the entry and both lists.
var ErrWireVersionMismatch = errors.New("transport: wire version mismatch")

// ErrWireVersionsMalformed is returned for a set that is not in canonical
// form or exceeds MaxWireVersionsEncodedSize, whether a peer sent it or a
// local option supplied it.
var ErrWireVersionsMalformed = errors.New("transport: wire versions malformed")

// WireVersionMismatchError reports the entry ChooseWireVersions refused on.
// Local and Peer are the versions each side listed for it, nil when that side
// did not list the name; the Required fields are each side's flag.
type WireVersionMismatchError struct {
	Name          string
	Local         []uint16
	Peer          []uint16
	LocalRequired bool
	PeerRequired  bool
}

func (e *WireVersionMismatchError) Error() string {
	side := func(v []uint16, req bool) string {
		if v == nil {
			return "omitted"
		}
		return fmt.Sprintf("%v required=%v", v, req)
	}
	return fmt.Sprintf("%v: entry %q: local %s, peer %s", ErrWireVersionMismatch, e.Name,
		side(e.Local, e.LocalRequired), side(e.Peer, e.PeerRequired))
}

// Is lets errors.Is(err, ErrWireVersionMismatch) match without unwrapping
// into a second error value.
func (e *WireVersionMismatchError) Is(target error) bool { return target == ErrWireVersionMismatch }

// AetherWireVersions returns the entries this build of aether offers for
// itself. LocalWireVersions adds them to every offer.
func AetherWireVersions() WireVersions {
	return WireVersions{
		{Name: WireVersionFragment, Versions: []uint16{WireVersionFragmentCurrent}, Required: true},
		{Name: WireVersionFrame, Versions: []uint16{wireVersionFrameCurrent}, Required: true},
		{Name: WireVersionFrameShort, Versions: []uint16{wireVersionFrameShortCurrent}},
	}
}

// LocalWireVersions returns the offer a transport or session sends: aether's
// own entries plus the application's, in canonical order. The application's
// entries come from NoiseTransportConfig, the over-conn configs and
// SessionOptions; an entry that names one of aether's, or that is not in
// canonical form on its own, is refused with ErrWireVersionsMalformed. The
// caller's slice is not reordered.
func LocalWireVersions(app WireVersions) (WireVersions, error) {
	own := AetherWireVersions()
	out := make(WireVersions, 0, len(own)+len(app))
	for _, e := range app {
		for _, o := range own {
			if e.Name == o.Name {
				return nil, fmt.Errorf("%w: application entry %q is aether's own", ErrWireVersionsMalformed, e.Name)
			}
		}
		out = append(out, WireVersion{Name: e.Name, Versions: append([]uint16(nil), e.Versions...), Required: e.Required})
	}
	out = append(out, own...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	if err := out.Validate(); err != nil {
		return nil, err
	}
	return out, nil
}

// Validate reports whether w is in canonical form: names strictly ascending
// (so no duplicate), each name 1-255 bytes of [a-z0-9._-], each entry with 1-255
// strictly ascending versions, and an encoding no larger than
// MaxWireVersionsEncodedSize. The byte alphabet keeps a name's comparison and
// its encoding one and the same on every peer.
func (w WireVersions) Validate() error {
	size := 0
	for i, e := range w {
		if err := validWireVersionName(e.Name); err != nil {
			return err
		}
		if i > 0 && w[i-1].Name >= e.Name {
			return fmt.Errorf("%w: entry %q is not after %q", ErrWireVersionsMalformed, e.Name, w[i-1].Name)
		}
		if len(e.Versions) == 0 || len(e.Versions) > 255 {
			return fmt.Errorf("%w: entry %q lists %d versions, need 1-255", ErrWireVersionsMalformed, e.Name, len(e.Versions))
		}
		for j := 1; j < len(e.Versions); j++ {
			if e.Versions[j-1] >= e.Versions[j] {
				return fmt.Errorf("%w: entry %q versions %v are not strictly ascending", ErrWireVersionsMalformed, e.Name, e.Versions)
			}
		}
		size += 1 + len(e.Name) + 1 + 2*len(e.Versions) + 1
	}
	if size > MaxWireVersionsEncodedSize {
		return fmt.Errorf("%w: encoding is %d bytes, bound %d", ErrWireVersionsMalformed, size, MaxWireVersionsEncodedSize)
	}
	return nil
}

func validWireVersionName(name string) error {
	if len(name) == 0 || len(name) > 255 {
		return fmt.Errorf("%w: entry name of %d bytes, need 1-255", ErrWireVersionsMalformed, len(name))
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' {
			continue
		}
		return fmt.Errorf("%w: entry name %q has byte 0x%02x outside [a-z0-9._-]", ErrWireVersionsMalformed, name, c)
	}
	return nil
}

// Encode writes the canonical encoding: for each entry in name order,
// [u8 name length][name][u8 count][count x u16 big-endian][u8 required].
// An empty set encodes to no bytes. A set that fails Validate is refused, so
// every encoding this returns decodes back to the same set.
func (w WireVersions) Encode() ([]byte, error) {
	if err := w.Validate(); err != nil {
		return nil, err
	}
	var out []byte
	for _, e := range w {
		out = append(out, byte(len(e.Name)))
		out = append(out, e.Name...)
		out = append(out, byte(len(e.Versions)))
		for _, v := range e.Versions {
			out = binary.BigEndian.AppendUint16(out, v)
		}
		if e.Required {
			out = append(out, 1)
		} else {
			out = append(out, 0)
		}
	}
	return out, nil
}

// DecodeWireVersions reads a set from its canonical encoding and refuses any
// other form: a length past MaxWireVersionsEncodedSize, a truncated entry,
// trailing bytes, a required byte other than 0 or 1, and anything Validate
// refuses. Every refusal wraps ErrWireVersionsMalformed.
func DecodeWireVersions(b []byte) (WireVersions, error) {
	if len(b) > MaxWireVersionsEncodedSize {
		return nil, fmt.Errorf("%w: %d bytes, bound %d", ErrWireVersionsMalformed, len(b), MaxWireVersionsEncodedSize)
	}
	var out WireVersions
	for p := 0; p < len(b); {
		nameLen := int(b[p])
		p++
		if p+nameLen+1 > len(b) {
			return nil, fmt.Errorf("%w: entry name runs past the end", ErrWireVersionsMalformed)
		}
		name := string(b[p : p+nameLen])
		p += nameLen
		count := int(b[p])
		p++
		if p+2*count+1 > len(b) {
			return nil, fmt.Errorf("%w: entry %q versions run past the end", ErrWireVersionsMalformed, name)
		}
		versions := make([]uint16, count)
		for i := range versions {
			versions[i] = binary.BigEndian.Uint16(b[p:])
			p += 2
		}
		var required bool
		switch b[p] {
		case 0:
		case 1:
			required = true
		default:
			return nil, fmt.Errorf("%w: entry %q required byte 0x%02x", ErrWireVersionsMalformed, name, b[p])
		}
		p++
		out = append(out, WireVersion{Name: name, Versions: versions, Required: required})
	}
	if err := out.Validate(); err != nil {
		return nil, err
	}
	return out, nil
}

func (w WireVersions) find(name string) (WireVersion, bool) {
	i := sort.Search(len(w), func(i int) bool { return w[i].Name >= name })
	if i < len(w) && w[i].Name == name {
		return w[i], true
	}
	return WireVersion{}, false
}

// NegotiatedWireVersion is one entry of a chosen set.
type NegotiatedWireVersion struct {
	Name    string
	Version uint16
}

// NegotiatedWireVersions is the set a session generation chose: one version
// per name both sides could speak, in name order. Sessions report it through
// WireVersions(); the layer that owns a name reads its version with Version
// and refuses its own traffic when the name is absent. The zero value is the
// empty set.
type NegotiatedWireVersions struct {
	entries []NegotiatedWireVersion
}

// Version returns the chosen version for name, and false when the session
// chose none for it.
func (n NegotiatedWireVersions) Version(name string) (uint16, bool) {
	i := sort.Search(len(n.entries), func(i int) bool { return n.entries[i].Name >= name })
	if i < len(n.entries) && n.entries[i].Name == name {
		return n.entries[i].Version, true
	}
	return 0, false
}

// Entries returns a copy of the chosen entries in name order.
func (n NegotiatedWireVersions) Entries() []NegotiatedWireVersion {
	return append([]NegotiatedWireVersion(nil), n.entries...)
}

// Equal reports whether two chosen sets name the same versions. A resume
// compares the set its ticket recorded with the set this build would choose.
func (n NegotiatedWireVersions) Equal(o NegotiatedWireVersions) bool {
	if len(n.entries) != len(o.entries) {
		return false
	}
	for i := range n.entries {
		if n.entries[i] != o.entries[i] {
			return false
		}
	}
	return true
}

func (n NegotiatedWireVersions) String() string {
	parts := make([]string, len(n.entries))
	for i, e := range n.entries {
		parts[i] = fmt.Sprintf("%s=%d", e.Name, e.Version)
	}
	return "{" + strings.Join(parts, " ") + "}"
}

// Encode writes the chosen set in the WireVersions encoding with one version
// per entry and every required byte 0. Session tickets and resume material
// carry it so a resumed session reports the set its first handshake chose.
func (n NegotiatedWireVersions) Encode() []byte {
	var out []byte
	for _, e := range n.entries {
		out = append(out, byte(len(e.Name)))
		out = append(out, e.Name...)
		out = append(out, 1)
		out = binary.BigEndian.AppendUint16(out, e.Version)
		out = append(out, 0)
	}
	return out
}

// DecodeNegotiatedWireVersions reads what Encode wrote, refusing an entry
// with other than one version or with its required byte set.
func DecodeNegotiatedWireVersions(b []byte) (NegotiatedWireVersions, error) {
	w, err := DecodeWireVersions(b)
	if err != nil {
		return NegotiatedWireVersions{}, err
	}
	var out []NegotiatedWireVersion
	for _, e := range w {
		if len(e.Versions) != 1 || e.Required {
			return NegotiatedWireVersions{}, fmt.Errorf("%w: chosen entry %q is not one optional version", ErrWireVersionsMalformed, e.Name)
		}
		out = append(out, NegotiatedWireVersion{Name: e.Name, Version: e.Versions[0]})
	}
	return NegotiatedWireVersions{entries: out}, nil
}

// ChooseWireVersions is the choice both ends of a handshake make from the
// two offers, before either creates session state. For each name either side
// lists, in name order: the highest version both list is chosen; with none in
// common, or with the name listed by one side only, the name is left out
// unless either side marks it required, which refuses with a
// *WireVersionMismatchError for the first such name. The result depends only
// on the pair of offers, never on which side is local, so the two ends reach
// the same set or the same refusal. Offers not in canonical form are refused
// with ErrWireVersionsMalformed.
func ChooseWireVersions(local, peer WireVersions) (NegotiatedWireVersions, error) {
	if err := local.Validate(); err != nil {
		return NegotiatedWireVersions{}, fmt.Errorf("local offer: %w", err)
	}
	if err := peer.Validate(); err != nil {
		return NegotiatedWireVersions{}, fmt.Errorf("peer offer: %w", err)
	}
	names := make([]string, 0, len(local)+len(peer))
	for _, e := range local {
		names = append(names, e.Name)
	}
	for _, e := range peer {
		if _, ok := local.find(e.Name); !ok {
			names = append(names, e.Name)
		}
	}
	sort.Strings(names)
	var out []NegotiatedWireVersion
	for _, name := range names {
		l, inLocal := local.find(name)
		p, inPeer := peer.find(name)
		if inLocal && inPeer {
			if v, ok := highestCommon(l.Versions, p.Versions); ok {
				out = append(out, NegotiatedWireVersion{Name: name, Version: v})
				continue
			}
		}
		if l.Required || p.Required {
			return NegotiatedWireVersions{}, &WireVersionMismatchError{
				Name:          name,
				Local:         l.Versions,
				Peer:          p.Versions,
				LocalRequired: l.Required,
				PeerRequired:  p.Required,
			}
		}
	}
	return NegotiatedWireVersions{entries: out}, nil
}

func highestCommon(a, b []uint16) (uint16, bool) {
	i, j := len(a)-1, len(b)-1
	for i >= 0 && j >= 0 {
		switch {
		case a[i] == b[j]:
			return a[i], true
		case a[i] > b[j]:
			i--
		default:
			j--
		}
	}
	return 0, false
}

// WriteWireVersionsPreface writes the byte-stream session preface: "AEWV", a
// big-endian u16 length, then w's canonical encoding. TCPSession writes it
// before its first frame and its peer reads it with ReadWireVersionsPreface
// before decoding any frame, which gives TCP, WebSocket, gRPC and QUIC stream
// sessions the negotiation the Noise handshake carries in NodeInfo.
func WriteWireVersionsPreface(w io.Writer, set WireVersions) error {
	enc, err := set.Encode()
	if err != nil {
		return err
	}
	buf := make([]byte, 0, 6+len(enc))
	buf = append(buf, wireVersionsPrefaceMagic[:]...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(enc)))
	buf = append(buf, enc...)
	_, err = w.Write(buf)
	return err
}

// ReadWireVersionsPreface reads exactly one preface from r and nothing past
// it. A wrong magic, a declared length past MaxWireVersionsEncodedSize (checked
// before the body is allocated) or a malformed body wraps
// ErrWireVersionsMalformed; a stream that ends inside the preface returns
// io.ErrUnexpectedEOF or io.EOF from the read.
func ReadWireVersionsPreface(r io.Reader) (WireVersions, error) {
	var head [6]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	if [4]byte(head[:4]) != wireVersionsPrefaceMagic {
		return nil, fmt.Errorf("%w: preface magic %x", ErrWireVersionsMalformed, head[:4])
	}
	n := int(binary.BigEndian.Uint16(head[4:]))
	if n > MaxWireVersionsEncodedSize {
		return nil, fmt.Errorf("%w: preface declares %d bytes, bound %d", ErrWireVersionsMalformed, n, MaxWireVersionsEncodedSize)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return DecodeWireVersions(body)
}

// WireVersionsReporter is implemented by sessions that negotiated a wire
// version set: NoiseSession over a Noise handshake and TCPSession, which
// serves TCP, WebSocket, gRPC and QUIC streams. SessionWireVersions is the
// accessor; it is an optional interface so that Session implementations
// outside this module are not obliged to grow the method.
type WireVersionsReporter interface {
	WireVersions() NegotiatedWireVersions
}

// SessionWireVersions returns the set s negotiated, and false when s does
// not report one.
func SessionWireVersions(s Session) (NegotiatedWireVersions, bool) {
	if r, ok := s.(WireVersionsReporter); ok {
		return r.WireVersions(), true
	}
	return NegotiatedWireVersions{}, false
}
