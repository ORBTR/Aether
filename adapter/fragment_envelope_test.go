/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math/rand"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

var (
	fxRealm       uint32 = 0x8badf00d
	fxPeer               = aether.PeerID{1, 2, 3, 4, 5, 6, 7, 8}
	fxIncarnation        = aether.ConnectionID{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18}
)

// fxBinding is the sending side of the fixtures: a session with the envelope
// negotiated and network key fxRealm, stream 7 at generation 3.
func fxBinding() FragmentBinding {
	return FragmentBinding{Version: aether.WireVersionFragmentCurrent, Realm: fxRealm, RealmBound: true,
		Peer: fxPeer, Incarnation: fxIncarnation, StreamID: 7, Generation: 3}
}

// fxReceiver is the receiving session matching fxBinding's sender.
func fxReceiver() *FragmentReceiver {
	return NewFragmentReceiver(aether.WireVersionFragmentCurrent, fxRealm, true, fxPeer)
}

func fxEnvelope() FragmentEnvelope {
	return FragmentEnvelope{Version: 2, Realm: fxRealm, Peer: fxPeer, Incarnation: fxIncarnation,
		StreamID: 7, Generation: 3, MessageID: 0x0000000100000002, Index: 1, Total: 3, OriginalLength: 2500}
}

func fxFragment(e FragmentEnvelope, chunk []byte) []byte {
	return append(e.Append(nil), chunk...)
}

func wantRefusal(t *testing.T, label string, err error, reason FragmentRefusal) {
	t.Helper()
	var fe *FragmentError
	if !errors.As(err, &fe) || !errors.Is(err, ErrFragmentRefused) || fe.Reason != reason {
		t.Fatalf("%s: err = %v, want a refusal %q", label, err, reason)
	}
}

// TestFragmentEnvelopeGolden pins the envelope's wire bytes.
func TestFragmentEnvelopeGolden(t *testing.T) {
	const golden = "02" + "8badf00d" + "0102030405060708" + "1112131415161718" +
		"0000000000000007" + "0000000000000003" + "0000000100000002" + "0001" + "0003" + "000009c4"
	got := hex.EncodeToString(fxEnvelope().Append(nil))
	if got != golden {
		t.Fatalf("envelope = %s\nwant       %s", got, golden)
	}
	if len(got)/2 != FragmentEnvelopeSize {
		t.Fatalf("envelope is %d bytes, FragmentEnvelopeSize %d", len(got)/2, FragmentEnvelopeSize)
	}
	raw, _ := hex.DecodeString(golden + "abcd")
	env, chunk, err := ParseFragment(raw)
	if err != nil || env != fxEnvelope() || string(chunk) != "\xab\xcd" {
		t.Fatalf("ParseFragment = %+v, %x, %v", env, chunk, err)
	}
}

// TestSplitMessage_PayloadBeginningFRIsOrdinaryData: a message that fits one
// frame is sent whole and unflagged whatever its first bytes, including the
// bytes 'F', 'R', 0, 1 a payload-prefix fragment test would read as a header.
func TestSplitMessage_PayloadBeginningFRIsOrdinaryData(t *testing.T) {
	for _, msg := range [][]byte{
		[]byte("FR"),
		append([]byte{'F', 'R', 0, 1}, "hello"...),
		append([]byte{2}, bytes.Repeat([]byte{0}, FragmentEnvelopeSize)...),
	} {
		frags, err := SplitMessage(fxBinding(), 1, msg, 1200)
		if err != nil || frags != nil {
			t.Fatalf("SplitMessage(%q) = %d fragments, %v; want whole (nil, nil)", msg, len(frags), err)
		}
	}
	// The same bytes arriving flagged as a fragment are not an envelope.
	fb := NewFragmentBuffer()
	got, _, err := fb.Add(fxReceiver(), 7, append([]byte{'F', 'R', 0, 1}, "hello"...))
	wantRefusal(t, "an FR-headed fragment payload", err, FragmentVersion)
	if got != nil || fb.Pending() != 0 {
		t.Fatalf("an FR-headed payload joined reassembly")
	}
}

// TestFragmentLargeMessageRoundTrips: two messages split and delivered in a
// shuffled, interleaved order each reassemble exactly once, byte for byte,
// leaving nothing buffered.
func TestFragmentLargeMessageRoundTrips(t *testing.T) {
	const maxPayload = 1134 // MSSToMaxPayload(1200)
	msgA := make([]byte, 250_000)
	msgB := make([]byte, 90_001)
	for i := range msgA {
		msgA[i] = byte(i*31 + 7)
	}
	for i := range msgB {
		msgB[i] = byte(i*17 + 3)
	}
	fa, err := SplitMessage(fxBinding(), 10, msgA, maxPayload)
	if err != nil {
		t.Fatalf("split A: %v", err)
	}
	fbFrags, err := SplitMessage(fxBinding(), 11, msgB, maxPayload)
	if err != nil {
		t.Fatalf("split B: %v", err)
	}
	all := append(append([][]byte{}, fa...), fbFrags...)
	rand.New(rand.NewSource(1)).Shuffle(len(all), func(i, j int) { all[i], all[j] = all[j], all[i] })

	fb := NewFragmentBuffer()
	r := fxReceiver()
	var done [][]byte
	for i, f := range all {
		got, released, err := fb.Add(r, 7, f)
		if err != nil || released != 0 {
			t.Fatalf("fragment %d: err %v released %d", i, err, released)
		}
		if got != nil {
			done = append(done, got)
		}
	}
	if len(done) != 2 {
		t.Fatalf("%d messages completed, want 2", len(done))
	}
	for _, m := range done {
		if !bytes.Equal(m, msgA) && !bytes.Equal(m, msgB) {
			t.Fatalf("a completed message (%d bytes) is neither sent message", len(m))
		}
	}
	if bytes.Equal(done[0], done[1]) {
		t.Fatalf("one message completed twice")
	}
	if fb.Pending() != 0 || fb.BufferedBytes() != 0 {
		t.Fatalf("left behind: %d groups, %d bytes", fb.Pending(), fb.BufferedBytes())
	}
}

// TestSplitMessageRefusals: the sender refuses a session that negotiated no
// envelope or has no realm, a zero message ID or generation, and a message past
// the fragment-count or byte ceiling, before writing any fragment.
func TestSplitMessageRefusals(t *testing.T) {
	big := make([]byte, 5000)
	for _, c := range []struct {
		name   string
		mutate func(*FragmentBinding)
		id     uint64
		reason FragmentRefusal
	}{
		{"not negotiated", func(b *FragmentBinding) { b.Version = 0 }, 1, FragmentNotNegotiated},
		{"another version", func(b *FragmentBinding) { b.Version = 1 }, 1, FragmentNotNegotiated},
		{"no realm", func(b *FragmentBinding) { b.RealmBound = false }, 1, FragmentNoRealm},
		{"message ID 0", func(*FragmentBinding) {}, 0, FragmentMessageID},
		{"generation 0", func(b *FragmentBinding) { b.Generation = 0 }, 1, FragmentGeneration},
	} {
		b := fxBinding()
		c.mutate(&b)
		frags, err := SplitMessage(b, c.id, big, 1200)
		wantRefusal(t, c.name, err, c.reason)
		if frags != nil {
			t.Fatalf("%s: fragments returned with the refusal", c.name)
		}
	}
	for name, run := range map[string]func() ([][]byte, error){
		"past the byte ceiling": func() ([][]byte, error) {
			return SplitMessage(fxBinding(), 1, make([]byte, MaxFragmentedMessageSize+1), 65536)
		},
		"past MaxFragments": func() ([][]byte, error) {
			return SplitMessage(fxBinding(), 1, make([]byte, MaxFragments*(200-FragmentEnvelopeSize)+1), 200)
		},
		"no room past the envelope": func() ([][]byte, error) {
			return SplitMessage(fxBinding(), 1, big, FragmentEnvelopeSize)
		},
	} {
		frags, err := run()
		if !errors.Is(err, ErrPayloadTooLarge) || frags != nil {
			t.Fatalf("%s: %d fragments, %v; want ErrPayloadTooLarge", name, len(frags), err)
		}
	}
	exact, err := SplitMessage(fxBinding(), 1, make([]byte, MaxFragments*(200-FragmentEnvelopeSize)), 200)
	if err != nil || len(exact) != MaxFragments {
		t.Fatalf("exactly MaxFragments: %d fragments, %v", len(exact), err)
	}
}

// TestFragmentReceiverRefusesBeforeAllocation: every malformed or foreign first
// fragment is refused with its reason, opens no group, holds no bytes, and
// reports its slice as released.
func TestFragmentReceiverRefusesBeforeAllocation(t *testing.T) {
	chunk := bytes.Repeat([]byte{0xee}, 100)
	cases := []struct {
		name     string
		receiver func() *FragmentReceiver
		stream   uint64
		mutate   func(*FragmentEnvelope)
		raw      func([]byte) []byte
		cap      int64
		reason   FragmentRefusal
	}{
		{name: "version 1", raw: func(b []byte) []byte { b[0] = 1; return b }, reason: FragmentVersion},
		{name: "version 3", raw: func(b []byte) []byte { b[0] = 3; return b }, reason: FragmentVersion},
		{name: "truncated envelope", raw: func(b []byte) []byte { return b[:FragmentEnvelopeSize-1] }, reason: FragmentTruncated},
		{name: "not negotiated", receiver: func() *FragmentReceiver { return NewFragmentReceiver(0, fxRealm, true, fxPeer) }, reason: FragmentNotNegotiated},
		{name: "no receiver", receiver: func() *FragmentReceiver { return nil }, reason: FragmentNotNegotiated},
		{name: "session without realm", receiver: func() *FragmentReceiver { return NewFragmentReceiver(2, 0, false, fxPeer) }, reason: FragmentNoRealm},
		{name: "cross-realm", mutate: func(e *FragmentEnvelope) { e.Realm++ }, reason: FragmentRealm},
		{name: "another peer", mutate: func(e *FragmentEnvelope) { e.Peer[0] ^= 0xff }, reason: FragmentPeer},
		{name: "cross-stream", stream: 8, reason: FragmentStream},
		{name: "generation 0", mutate: func(e *FragmentEnvelope) { e.Generation = 0 }, reason: FragmentGeneration},
		{name: "message ID 0", mutate: func(e *FragmentEnvelope) { e.MessageID = 0 }, reason: FragmentMessageID},
		{name: "total 0", mutate: func(e *FragmentEnvelope) { e.Total, e.Index = 0, 0 }, reason: FragmentTotal},
		{name: "total past MaxFragments", mutate: func(e *FragmentEnvelope) { e.Total = MaxFragments + 1 }, reason: FragmentTotal},
		{name: "total 65535", mutate: func(e *FragmentEnvelope) { e.Total = 0xffff }, reason: FragmentTotal},
		{name: "total above original length", mutate: func(e *FragmentEnvelope) { e.Total, e.OriginalLength = 200, 150 }, reason: FragmentTotal},
		{name: "index equals total", mutate: func(e *FragmentEnvelope) { e.Index = e.Total }, reason: FragmentIndex},
		{name: "index past total", mutate: func(e *FragmentEnvelope) { e.Index = 0xffff }, reason: FragmentIndex},
		{name: "original length 0", mutate: func(e *FragmentEnvelope) { e.OriginalLength = 0 }, reason: FragmentLength},
		{name: "oversize original", mutate: func(e *FragmentEnvelope) { e.OriginalLength = uint32(MaxFragmentedMessageSize) + 1 }, reason: FragmentLength},
		{name: "original 4 GiB", mutate: func(e *FragmentEnvelope) { e.OriginalLength = 0xffffffff }, reason: FragmentLength},
		{name: "original past the buffer cap", cap: 2000, reason: FragmentLength},
		{name: "empty slice", raw: func(b []byte) []byte { return b[:FragmentEnvelopeSize] }, reason: FragmentLength},
		{name: "slice longer than the message", mutate: func(e *FragmentEnvelope) { e.Total, e.OriginalLength = 1, 50 }, reason: FragmentLength},
	}
	for _, c := range cases {
		env := fxEnvelope()
		env.Index = 0
		if c.mutate != nil {
			c.mutate(&env)
		}
		data := fxFragment(env, chunk)
		if c.raw != nil {
			data = c.raw(data)
		}
		r := fxReceiver()
		if c.receiver != nil {
			r = c.receiver()
		}
		stream := uint64(7)
		if c.stream != 0 {
			stream = c.stream
		}
		fb := NewFragmentBuffer()
		if c.cap != 0 {
			fb.SetMaxBufferedBytes(c.cap)
		}
		got, released, err := fb.Add(r, stream, data)
		wantRefusal(t, c.name, err, c.reason)
		if got != nil || fb.Pending() != 0 || fb.BufferedBytes() != 0 || len(fb.streams) != 0 {
			t.Fatalf("%s: refused fragment left state: groups %d bytes %d streams %d", c.name, fb.Pending(), fb.BufferedBytes(), len(fb.streams))
		}
		if want := int64(len(data) - FragmentEnvelopeSize); want > 0 && released != want {
			t.Fatalf("%s: released %d, want the slice's %d", c.name, released, want)
		}
	}
}

// fxMessage splits a deterministic message of n bytes at 300-byte frames.
func fxMessage(t *testing.T, b FragmentBinding, id uint64, n int) ([]byte, [][]byte) {
	t.Helper()
	msg := make([]byte, n)
	for i := range msg {
		msg[i] = byte(int(id)*7 + i)
	}
	frags, err := SplitMessage(b, id, msg, 300)
	if err != nil {
		t.Fatalf("split %d: %v", id, err)
	}
	return msg, frags
}

// TestFragmentMessageIDReuse: a fragment whose metadata disagrees with the live
// group of its message ID, or that brings different bytes to an index already
// held, discards that group; no later fragment of a discarded or completed
// message ID joins anything; an exact duplicate is harmless.
func TestFragmentMessageIDReuse(t *testing.T) {
	r := fxReceiver()
	fb := NewFragmentBuffer()
	_, frags := fxMessage(t, fxBinding(), 5, 700) // 3 fragments
	if _, _, err := fb.Add(r, 7, frags[0]); err != nil {
		t.Fatalf("first: %v", err)
	}
	env, chunk, _ := ParseFragment(frags[1])
	env.Total = 4
	_, released, err := fb.Add(r, 7, fxFragment(env, chunk))
	wantRefusal(t, "same ID, another total", err, FragmentConflict)
	if fb.Pending() != 0 || fb.BufferedBytes() != 0 {
		t.Fatalf("conflicting metadata left the group: %d groups %d bytes", fb.Pending(), fb.BufferedBytes())
	}
	if want := int64(len(frags[0]) + len(chunk) - FragmentEnvelopeSize); released != want {
		t.Fatalf("released %d, want both slices %d", released, want)
	}
	for i := 1; i < 3; i++ {
		_, _, err := fb.Add(r, 7, frags[i])
		wantRefusal(t, "fragment of a discarded message", err, FragmentMessageID)
	}

	msg, frags := fxMessage(t, fxBinding(), 6, 700)
	if _, _, err := fb.Add(r, 7, frags[0]); err != nil {
		t.Fatalf("first: %v", err)
	}
	if got, released, err := fb.Add(r, 7, frags[0]); err != nil || got != nil || released != int64(len(frags[0])-FragmentEnvelopeSize) {
		t.Fatalf("exact duplicate: %v %v released %d", got != nil, err, released)
	}
	bad := append([]byte(nil), frags[1]...)
	bad[len(bad)-1] ^= 1
	if _, _, err := fb.Add(r, 7, frags[1]); err != nil {
		t.Fatalf("second: %v", err)
	}
	_, _, err = fb.Add(r, 7, bad)
	wantRefusal(t, "different bytes at a held index", err, FragmentConflict)
	if _, _, err := fb.Add(r, 7, frags[2]); err == nil {
		t.Fatalf("a poisoned message completed")
	}

	msg, frags = fxMessage(t, fxBinding(), 7, 700)
	var got []byte
	for _, f := range frags {
		if out, _, err := fb.Add(r, 7, f); err != nil {
			t.Fatalf("message 7: %v", err)
		} else if out != nil {
			got = out
		}
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("message 7 did not complete intact")
	}
	_, _, err = fb.Add(r, 7, frags[0])
	wantRefusal(t, "fragment of a completed message", err, FragmentMessageID)
	if fb.Pending() != 0 {
		t.Fatalf("a completed ID started a new group")
	}
	_, frags = fxMessage(t, fxBinding(), 7+fragmentIDWindow+1, 700)
	if _, _, err := fb.Add(r, 7, frags[0]); err != nil {
		t.Fatalf("a higher ID: %v", err)
	}
	_, frags = fxMessage(t, fxBinding(), 4, 700)
	_, _, err = fb.Add(r, 7, frags[0])
	wantRefusal(t, "an ID below the window", err, FragmentMessageID)
}

// TestFragmentCrossSessionAndGeneration: once a session's first fragment pins
// the sending incarnation, a fragment from another incarnation is refused and
// joins nothing; a fragment of an older stream generation is refused; a newer
// generation discards the older generation's groups, and the two never join.
func TestFragmentCrossSessionAndGeneration(t *testing.T) {
	r := fxReceiver()
	fb := NewFragmentBuffer()
	msg, frags := fxMessage(t, fxBinding(), 1, 700)
	if _, _, err := fb.Add(r, 7, frags[0]); err != nil {
		t.Fatalf("first: %v", err)
	}
	other := fxBinding()
	other.Incarnation[0] ^= 0xff
	_, otherFrags := fxMessage(t, other, 1, 700)
	for _, f := range otherFrags {
		_, _, err := fb.Add(r, 7, f)
		wantRefusal(t, "another session's fragment", err, FragmentIncarnation)
	}
	var got []byte
	for _, f := range frags[1:] {
		out, _, err := fb.Add(r, 7, f)
		if err != nil {
			t.Fatalf("own fragment after a foreign one: %v", err)
		}
		if out != nil {
			got = out
		}
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("the pinned session's message did not complete intact")
	}

	_, gen3 := fxMessage(t, fxBinding(), 2, 700)
	if _, _, err := fb.Add(r, 7, gen3[0]); err != nil {
		t.Fatalf("generation 3: %v", err)
	}
	older := fxBinding()
	older.Generation = 2
	_, gen2 := fxMessage(t, older, 9, 700)
	_, _, err := fb.Add(r, 7, gen2[0])
	wantRefusal(t, "an older generation", err, FragmentGeneration)

	// Generation 4 reuses message ID 2 for a message of the same length and
	// different bytes, so only discarding generation 3's group lets it join.
	newer := fxBinding()
	newer.Generation = 4
	msg4 := make([]byte, 700)
	for i := range msg4 {
		msg4[i] = byte(i*13 + 0x5a)
	}
	gen4, err := SplitMessage(newer, 2, msg4, 300)
	if err != nil {
		t.Fatalf("split generation 4: %v", err)
	}
	_, released, err := fb.Add(r, 7, gen4[0])
	if err != nil {
		t.Fatalf("generation 4: %v", err)
	}
	if want := int64(len(gen3[0]) - FragmentEnvelopeSize); released != want {
		t.Fatalf("a newer generation released %d, want the older group's %d", released, want)
	}
	_, _, err = fb.Add(r, 7, gen3[1])
	wantRefusal(t, "the older generation's remaining fragment", err, FragmentGeneration)
	got = nil
	for _, f := range gen4[1:] {
		if out, _, err := fb.Add(r, 7, f); err != nil {
			t.Fatalf("generation 4: %v", err)
		} else if out != nil {
			got = out
		}
	}
	if !bytes.Equal(got, msg4) {
		t.Fatalf("generation 4's message did not complete intact")
	}
}

// TestFragmentBufferBoundsStay: the per-stream group cap, the byte cap and the
// age cap still hold, and what each drops is released.
func TestFragmentBufferBoundsStay(t *testing.T) {
	r := fxReceiver()
	fb := NewFragmentBuffer()
	for id := uint64(1); id <= MaxGroupsPerStream; id++ {
		_, frags := fxMessage(t, fxBinding(), id, 700)
		if _, _, err := fb.Add(r, 7, frags[0]); err != nil {
			t.Fatalf("group %d: %v", id, err)
		}
	}
	_, frags := fxMessage(t, fxBinding(), MaxGroupsPerStream+1, 700)
	_, _, err := fb.Add(r, 7, frags[0])
	wantRefusal(t, "a group past MaxGroupsPerStream", err, FragmentCapacity)

	fb = NewFragmentBuffer()
	fb.SetMaxBufferedBytes(600)
	_, frags = fxMessage(t, fxBinding(), 1, 500)
	if _, _, err := fb.Add(r, 7, frags[0]); err != nil {
		t.Fatalf("under the cap: %v", err)
	}
	if _, _, err := fb.Add(r, 7, frags[1]); err != nil {
		t.Fatalf("under the cap: %v", err)
	}
	_, frags2 := fxMessage(t, fxBinding(), 2, 500)
	_, released, err := fb.Add(r, 7, frags2[0])
	wantRefusal(t, "past the byte cap", err, FragmentCapacity)
	if want := int64(len(frags2[0]) - FragmentEnvelopeSize); released != want {
		t.Fatalf("byte cap released %d, want %d", released, want)
	}

	fb = NewFragmentBuffer()
	fb.SetGroupMaxAge(time.Millisecond)
	_, frags = fxMessage(t, fxBinding(), 1, 700)
	if _, _, err := fb.Add(r, 7, frags[0]); err != nil {
		t.Fatalf("aging group: %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	_, frags2 = fxMessage(t, fxBinding(), 2, 700)
	_, released, err = fb.Add(r, 7, frags2[0])
	if err != nil {
		t.Fatalf("after the age cap: %v", err)
	}
	if want := int64(len(frags[0]) - FragmentEnvelopeSize); released != want {
		t.Fatalf("age prune released %d, want %d", released, want)
	}
	_, _, err = fb.Add(r, 7, frags[1])
	wantRefusal(t, "a fragment of an aged-out group", err, FragmentMessageID)
	if fb.Pending() != 1 {
		t.Fatalf("pending %d, want only the new group", fb.Pending())
	}
}
