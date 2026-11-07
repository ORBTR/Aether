//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/reliability"
)

// everyCopyOf is a filter rule that loses every copy of the given DATA frames, the
// retransmits too, so only a repair can bring them back.
func everyCopyOf(id uint64, seqs ...uint32) func(*aether.Frame) bool {
	return func(f *aether.Frame) bool {
		if f.Type != aether.TypeDATA || f.StreamID != id {
			return false
		}
		for _, s := range seqs {
			if f.SeqNo == s {
				return true
			}
		}
		return false
	}
}

func openFEC(t *testing.T, ctx context.Context, client, server *NoiseSession, id uint64, level reliability.FECLevel) (*noiseStream, *noiseStream) {
	t.Helper()
	cs, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: id, Reliability: aether.ReliableOrdered, Priority: 128, FECLevel: uint8(level)})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ss, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	return asNoiseStream(t, cs), asNoiseStream(t, ss)
}

// TestNoiseStream_ALostFrameComesBackThroughItsRepair runs each level over a real
// path with every copy of the lost frames dropped: each message reaches the reader
// once, in order, and the sender's window empties on the ACKs the recovered frames
// produce, since no retransmit could get through.
func TestNoiseStream_ALostFrameComesBackThroughItsRepair(t *testing.T) {
	cases := []struct {
		name   string
		level  reliability.FECLevel
		frames int
		lost   []uint32
	}{
		{"xor", reliability.FECBasicXOR, 8, []uint32{2, 5}},
		{"interleaved burst of two", reliability.FECInterleaved, 8, []uint32{3, 4}},
		{"reed-solomon two in a group", reliability.FECReedSolomon, 8, []uint32{1, 6}},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			client, server, toServer, _ := filteredPair(t, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			id := uint64(1100 + i)
			toServer.setRule(everyCopyOf(id, c.lost...))
			cs, ss := openFEC(t, ctx, client, server, id, c.level)
			sent := make([][]byte, c.frames)
			for k := range sent {
				sent[k] = burstMessage(k, 300+k*17)
				if err := cs.Send(ctx, sent[k]); err != nil {
					t.Fatalf("send %d: %v", k, err)
				}
			}
			for k, want := range sent {
				r := <-receiveAsync(ctx, ss, time.Minute)
				if r.err != nil || !bytes.Equal(r.data, want) {
					t.Fatalf("message %d: %d bytes, %v", k, len(r.data), r.err)
				}
			}
			waitLong(t, "the sender's window empty", func() bool { return cs.sendWindow.InFlight() == 0 })
			if _, dropped := toServer.count(aether.TypeDATA); dropped < len(c.lost) {
				t.Fatalf("%d copies dropped: the frames were not lost", dropped)
			}
			if got := server.Metrics().FECRecovered; got != uint64(len(c.lost)) {
				t.Fatalf("%d frames recovered, want %d", got, len(c.lost))
			}
			if r := <-receiveAsync(ctx, ss, 200*time.Millisecond); r.err == nil {
				t.Fatalf("a message of %d bytes past the last", len(r.data))
			}
		})
	}
}

// TestNoiseStream_ALostFragmentComesBackThroughItsRepair: the repair's table carries
// the fragment flag the lost frame's header had, so a recovered fragment rejoins its
// message and the message reaches the reader once, whole.
func TestNoiseStream_ALostFragmentComesBackThroughItsRepair(t *testing.T) {
	client, server, toServer, _ := filteredPair(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	toServer.setRule(everyCopyOf(1110, 1))
	cs, ss := openFEC(t, ctx, client, server, 1110, reliability.FECBasicXOR)
	msg := burstMessage(3, 6*client.pmtuProber.MSS()) // more than one group of frames
	if err := cs.Send(ctx, msg); err != nil {
		t.Fatalf("send: %v", err)
	}
	r := <-receiveAsync(ctx, ss, time.Minute)
	if r.err != nil || !bytes.Equal(r.data, msg) {
		t.Fatalf("message: %d bytes, %v", len(r.data), r.err)
	}
	if got := server.Metrics().FECRecovered; got != 1 {
		t.Fatalf("%d frames recovered", got)
	}
}

// TestNoiseStream_ARecoveredFrameAndItsRetransmitDeliverOnce: the frame comes back
// through its repair and then its DATA arrives too, as a retransmit on its way does.
// The message reaches the reader once, and the second copy meets the replay window.
func TestNoiseStream_ARecoveredFrameAndItsRetransmitDeliverOnce(t *testing.T) {
	client, server, toServer, _ := filteredPair(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	toServer.setRule(everyCopyOf(1111, 1))
	cs, ss := openFEC(t, ctx, client, server, 1111, reliability.FECBasicXOR)
	msgs := make([][]byte, 4)
	for k := range msgs {
		msgs[k] = burstMessage(k, 200)
		if err := cs.Send(ctx, msgs[k]); err != nil {
			t.Fatalf("send: %v", err)
		}
	}
	for k, want := range msgs {
		r := <-receiveAsync(ctx, ss, time.Minute)
		if r.err != nil || !bytes.Equal(r.data, want) {
			t.Fatalf("message %d: %d bytes, %v", k, len(r.data), r.err)
		}
	}
	server.handleData(&aether.Frame{Type: aether.TypeDATA, StreamID: 1111, SeqNo: 1, Flags: aether.FlagANTIREPLAY, Length: uint32(len(msgs[1])), Payload: msgs[1]})
	if r := <-receiveAsync(ctx, ss, 200*time.Millisecond); r.err == nil {
		t.Fatalf("the retransmit of a recovered frame reached the reader: %d bytes", len(r.data))
	}
}

// TestNoiseStream_ARepairFindsFramesThatArrivedAfterIt: a repair held for a group
// whose frames have not all arrived acts on the DATA frame that leaves one missing, in
// order behind that frame. Driven by hand so the repair is first.
func TestNoiseStream_ARepairFindsFramesThatArrivedAfterIt(t *testing.T) {
	client, server := noisePairWithRealms(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cs, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: 1112, Reliability: aether.ReliableOrdered, Priority: 128, FECLevel: uint8(reliability.FECBasicXOR)})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	waitFor(t, "the stream at the server", func() bool { return streamPresent(server, 1112) })
	_ = cs
	ssAny, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	ss := asNoiseStream(t, ssAny)
	enc := reliability.NewFECEncoder(4)
	msgs := [][]byte{[]byte("zero"), []byte("one, a bit longer"), []byte("two"), []byte("three")}
	var repair *aether.Frame
	for seq, m := range msgs {
		repair = enc.Add(uint32(seq), m, false)
	}
	repair.StreamID = 1112
	server.handleFECRepair(repair)
	injectFrame := func(seq uint32) {
		server.handleData(&aether.Frame{Type: aether.TypeDATA, StreamID: 1112, SeqNo: seq, Flags: aether.FlagANTIREPLAY, Length: uint32(len(msgs[seq])), Payload: msgs[seq]})
	}
	injectFrame(0)
	injectFrame(2)
	injectFrame(3)
	for k, want := range msgs {
		r := <-receiveAsync(ctx, ss, 10*time.Second)
		if r.err != nil || !bytes.Equal(r.data, want) {
			t.Fatalf("message %d: %q, %v", k, r.data, r.err)
		}
	}
}

// TestNoiseStream_FECStateIsPerStream: frames of two FEC streams interleaved on one
// session complete their own groups, and a stream at level none takes no part: a
// repair's table names only its own stream's frames, in that stream's sequence space.
func TestNoiseStream_FECStateIsPerStream(t *testing.T) {
	// Compression off: the filter reads each repair's table from the wire.
	client, server, toServer, _ := filteredPair(t, func(o *aether.SessionOptions) { o.Compression = false })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var mu sync.Mutex
	var repairs []aether.FECHeader
	repairStream := make(map[uint64]int)
	countFor := func(id uint64) int {
		mu.Lock()
		defer mu.Unlock()
		return repairStream[id]
	}
	toServer.setRule(func(f *aether.Frame) bool {
		if f.Type == aether.TypeFEC_REPAIR {
			h, _, err := aether.DecodeFECHeader(f.Payload)
			if err == nil {
				mu.Lock()
				repairs = append(repairs, h)
				repairStream[f.StreamID]++
				mu.Unlock()
			}
		}
		return false
	})
	a, _ := openFEC(t, ctx, client, server, 1120, reliability.FECBasicXOR)
	b, _ := openFEC(t, ctx, client, server, 1121, reliability.FECBasicXOR)
	none, _ := openFEC(t, ctx, client, server, 1122, reliability.FECNone)
	if none.fec != nil {
		t.Fatal("a stream at level none has FEC state")
	}
	if a.fec == b.fec {
		t.Fatal("two streams share FEC state")
	}
	for k := 0; k < 3; k++ {
		for _, st := range []*noiseStream{a, b, none} {
			if err := st.Send(ctx, burstMessage(k, 100)); err != nil {
				t.Fatalf("send: %v", err)
			}
		}
	}
	waitSendWindowEmpty(t, a, "a")
	waitSendWindowEmpty(t, b, "b")
	if countFor(1120)+countFor(1121)+countFor(1122) != 0 {
		t.Fatal("a repair after three frames per stream")
	}
	for _, st := range []*noiseStream{a, b, none} {
		if err := st.Send(ctx, burstMessage(9, 100)); err != nil {
			t.Fatalf("send: %v", err)
		}
	}
	waitLong(t, "a repair per FEC stream", func() bool { return countFor(1120) == 1 && countFor(1121) == 1 })
	if n := countFor(1122); n != 0 {
		t.Fatalf("a stream at level none wrote %d repairs", n)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, h := range repairs {
		for i, c := range h.Covered {
			if c.SeqNo != uint32(i) {
				t.Fatalf("table %+v: not one stream's sequence numbers", h.Covered)
			}
		}
	}
}

// TestNoiseStream_OpenStatesTheLevel: the accepting side runs the level the OPEN
// states; a level outside the registry is refused at OpenStream and, from a peer, with
// RESET(ResetRefused) and no state; a session with FEC disabled states none and writes
// no repairs for a stream that asked for it.
func TestNoiseStream_OpenStatesTheLevel(t *testing.T) {
	client, server, toServer, _ := filteredPair(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	_, ss := openFEC(t, ctx, client, server, 1130, reliability.FECInterleaved)
	if ss.fec == nil || ss.fec.Level() != reliability.FECInterleaved {
		t.Fatalf("accepted stream's FEC state: %+v", ss.fec)
	}
	if _, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: 1131, Priority: 128, FECLevel: 9}); !errors.Is(err, aether.ErrFECLevelUnsupported) {
		t.Fatalf("level 9 at OpenStream: %v", err)
	}
	if streamPresent(client, 1131) {
		t.Fatal("a refused level left a stream")
	}
	bad := aether.EncodeOpenPayload(aether.OpenPayload{Priority: 128, InitialCredit: uint32(1 << 20), FECLevel: 9})
	server.handleOpen(&aether.Frame{Type: aether.TypeOPEN, StreamID: 1132, Length: uint32(len(bad)), Payload: bad})
	if streamPresent(server, 1132) {
		t.Fatal("an OPEN at level 9 left a stream")
	}

	off, offServer, offToServer, _ := filteredPair(t, func(o *aether.SessionOptions) { o.FEC = false })
	cs, oss := openFEC(t, ctx, off, offServer, 1133, reliability.FECBasicXOR)
	if cs.fec != nil || oss.fec != nil {
		t.Fatal("a session with FEC disabled built FEC state")
	}
	for k := 0; k < 8; k++ {
		if err := cs.Send(ctx, burstMessage(k, 100)); err != nil {
			t.Fatalf("send: %v", err)
		}
	}
	waitSendWindowEmpty(t, cs, "the messages")
	if n, _ := offToServer.count(aether.TypeFEC_REPAIR); n != 0 {
		t.Fatalf("%d repairs on a session with FEC disabled", n)
	}
	_ = toServer
}

// TestNoiseStream_ARepairFitsWhereItsFramesFit: a repair is as long as the longest
// frame it covers plus its table, so a stream with FEC keeps its frames short by that
// much and no write passes the MSS the session runs at.
func TestNoiseStream_ARepairFitsWhereItsFramesFit(t *testing.T) {
	for i, level := range []reliability.FECLevel{reliability.FECBasicXOR, reliability.FECReedSolomon} {
		client, server, toServer, _ := filteredPair(t, func(o *aether.SessionOptions) { o.Compression = false })
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		cs, ss := openFEC(t, ctx, client, server, uint64(1140+i), level)
		// Send splits at the MSS of its call, so a sweep still raising it would make
		// this message fewer frames than a repair group needs and no repair would go.
		waitProbeSweepsDone(t, client, server)
		mss := client.pmtuProber.MSS()
		msg := make([]byte, 3*mss)
		for k := range msg {
			msg[k] = byte(k*31 + 7)
		}
		for k := 0; k < 3; k++ {
			if err := cs.Send(ctx, msg); err != nil {
				t.Fatalf("send: %v", err)
			}
			if r := <-receiveAsync(ctx, ss, time.Minute); r.err != nil || !bytes.Equal(r.data, msg) {
				t.Fatalf("message: %d bytes, %v", len(r.data), r.err)
			}
		}
		if n, _ := toServer.count(aether.TypeFEC_REPAIR); n == 0 {
			t.Fatal("no repair was written")
		}
		// No write of a frame is longer than the longest DATA frame a stream without
		// FEC writes, the frame header around MSSToMaxPayload's payload. The MSS read
		// here is the highest of the run: the PMTU sweep only raises it on this path.
		limit := aether.FullFrameHeaderWireSize + MSSToMaxPayload(client.pmtuProber.MSS())
		if got := toServer.largestWrite(aether.TypeFEC_REPAIR); got > limit {
			t.Fatalf("a repair of %d bytes past %d", got, limit)
		}
		if got := toServer.largestWrite(aether.TypeDATA); got > limit {
			t.Fatalf("a frame of %d bytes past %d", got, limit)
		}
		cancel()
	}
}

// TestNoiseStream_FECMemoryGoesWithTheStream: what a stream's decoder holds counts
// on the session while it runs and is gone when the stream leaves, by RESET or by its
// CLOSEs.
func TestNoiseStream_FECMemoryGoesWithTheStream(t *testing.T) {
	client, server, _, _ := filteredPair(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for k, end := range []string{"reset", "close"} {
		cs, ss := openFEC(t, ctx, client, server, uint64(1150+k), reliability.FECBasicXOR)
		if err := cs.Send(ctx, burstMessage(k, 500)); err != nil {
			t.Fatalf("send: %v", err)
		}
		if r := <-receiveAsync(ctx, ss, time.Minute); r.err != nil {
			t.Fatalf("read: %v", r.err)
		}
		if server.fecCached.Load() == 0 {
			t.Fatalf("%s: the decoder holds nothing while the stream runs", end)
		}
		if end == "reset" {
			_ = cs.Reset(aether.ResetCancel)
		} else {
			waitSendWindowEmpty(t, cs, "the message")
			_ = cs.Close()
			_ = ss.Close()
		}
		waitLong(t, end+": the stream gone and its memory back", func() bool {
			return !streamPresent(server, uint64(1150+k)) && !streamPresent(client, uint64(1150+k)) && server.fecCached.Load() == 0
		})
	}
}

// TestNoiseSession_AMalformedRepairIsChargedAndKeepsNothing: a repair that does not
// fit its stream is charged to the peer, and the stream runs on.
func TestNoiseSession_AMalformedRepairIsChargedAndKeepsNothing(t *testing.T) {
	client, server, _, _ := filteredPair(t, func(o *aether.SessionOptions) { o.SessionWarmupGrace = -1 })
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cs, ss := openFEC(t, ctx, client, server, 1160, reliability.FECBasicXOR)
	// reportAbuse's forensic tier records a delivering peer's malformed frames.
	if err := cs.Send(ctx, []byte("delivering")); err != nil {
		t.Fatalf("send: %v", err)
	}
	if r := <-receiveAsync(ctx, ss, time.Minute); r.err != nil {
		t.Fatalf("read: %v", r.err)
	}
	before := server.ForensicSuppressedCount()
	for _, payload := range [][]byte{
		{1, 2, 3, 4, 5, 6, 7, 8}, // no frames in the table
		append(aether.EncodeFECHeader(aether.FECHeader{Index: 1, Total: 2, Level: uint8(reliability.FECReedSolomon), Covered: []aether.FECCovered{{SeqNo: 1, Length: 1}}}), 9), // another level
	} {
		server.handleFECRepair(&aether.Frame{Type: aether.TypeFEC_REPAIR, StreamID: 1160, Length: uint32(len(payload)), Payload: payload})
	}
	if got := server.ForensicSuppressedCount() - before; got != 2 {
		t.Fatalf("%d of two malformed repairs charged", got)
	}
	if err := cs.Send(ctx, []byte("still running")); err != nil {
		t.Fatalf("send: %v", err)
	}
	if r := <-receiveAsync(ctx, ss, time.Minute); r.err != nil || string(r.data) != "still running" {
		t.Fatalf("read: %q, %v", r.data, r.err)
	}
}
