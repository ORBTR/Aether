//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/flow"
)

// reopenWhenFree opens id on client as soon as OpenStream stops refusing it with
// aether.ErrDuplicateStreamID, which it does while a RESET of the ID waits for its
// acknowledgment and through the ID's quiet time.
func reopenWhenFree(t *testing.T, ctx context.Context, client *NoiseSession, id uint64) *noiseStream {
	t.Helper()
	cfg := aether.StreamConfig{StreamID: id, Reliability: aether.ReliableOrdered, Priority: 128}
	var next aether.Stream
	waitLong(t, fmt.Sprintf("stream %d opening again", id), func() bool {
		st, err := client.OpenStream(ctx, cfg)
		if err == nil {
			next = st
			return true
		}
		if !errors.Is(err, aether.ErrDuplicateStreamID) {
			t.Fatalf("OpenStream: %v", err)
		}
		return false
	})
	return asNoiseStream(t, next)
}

// readAll takes messages off st until one Receive waits past within, returning them
// and the error that ended the reads.
func readAll(ctx context.Context, st aether.Stream, within time.Duration) ([]string, error) {
	var got []string
	for {
		r := <-receiveAsync(ctx, st, within)
		if r.err != nil {
			return got, r.err
		}
		got = append(got, string(r.data))
	}
}

// TestNoiseSession_ALostResetIsWrittenAgainAndItsIDWaitsForTheAcknowledgment: the
// client resets a stream and every copy of its RESET is lost for a while. OpenStream
// of the ID is refused with ErrDuplicateStreamID while the RESET waits, so the
// server's stream, still live, never takes a new stream's frames for its own. The
// RESET is written again, the server ends its stream and acknowledges it, the ID
// opens once its quiet time is over, and every message of the new stream reaches a
// newly accepted stream, none the old one's consumer.
func TestNoiseSession_ALostResetIsWrittenAgainAndItsIDWaitsForTheAcknowledgment(t *testing.T) {
	client, server, toServer, toClient := filteredPair(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	const id = 901
	cs, ss := openWithCredit(t, ctx, client, server, id, 0)
	for i := 0; i < 2; i++ {
		if err := cs.Send(ctx, []byte(fmt.Sprintf("old-%d", i))); err != nil {
			t.Fatalf("send: %v", err)
		}
	}
	waitSendWindowEmpty(t, cs, "old acknowledged")
	var lose atomic.Bool
	lose.Store(true)
	toServer.setRule(func(f *aether.Frame) bool { return lose.Load() && f.Type == aether.TypeRESET })
	if err := cs.Reset(aether.ResetCancel); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if st, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: id, Reliability: aether.ReliableOrdered}); st != nil || !errors.Is(err, aether.ErrDuplicateStreamID) {
		t.Fatalf("OpenStream while the RESET waits = %v, %v; want ErrDuplicateStreamID", st, err)
	}
	waitLong(t, "a second copy of the RESET", func() bool { w, _ := toServer.count(aether.TypeRESET); return w >= 2 })
	if !streamPresent(server, id) {
		t.Fatal("the server's stream ended with every RESET lost")
	}
	lose.Store(false)
	waitLong(t, "the server's stream ending at the RESET", func() bool { return !streamPresent(server, id) })
	waitLong(t, "the acknowledgment reaching the client", func() bool { return client.pendingResetCount.Load() == 0 })
	if acks, _ := toClient.count(aether.TypeRESET); acks == 0 {
		t.Fatal("no acknowledgment was written")
	}

	ns := reopenWhenFree(t, ctx, client, id)
	const n = 6
	for i := 0; i < n; i++ {
		if err := ns.Send(ctx, []byte(fmt.Sprintf("new-%d", i))); err != nil {
			t.Fatalf("new send %d: %v", i, err)
		}
	}
	acc, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	got, _ := readAll(ctx, acc, 2*time.Second)
	if len(got) != n {
		t.Fatalf("the new stream's consumer read %v, want new-0..new-%d", got, n-1)
	}
	for i, m := range got {
		if m != fmt.Sprintf("new-%d", i) {
			t.Fatalf("the new stream's consumer read %v out of order", got)
		}
	}
	old, end := readAll(ctx, ss, 500*time.Millisecond)
	if len(old) != 2 || old[0] != "old-0" || old[1] != "old-1" || !errors.Is(end, io.EOF) {
		t.Fatalf("the old stream's consumer read %v then %v; want old-0 old-1 then io.EOF", old, end)
	}
}

// TestNoiseSession_EveryResetIsAcknowledgedAndANamesakeAcknowledgmentStopsNothing:
// a RESET the server reads is answered with a RESET flagged FlagACK naming the same
// stream and stating, as Consumed, what the server's consumer returned of the client's
// sends on it, which stops the client's copies and starts the ID's quiet time. An
// acknowledgment naming another stream under the ID stops nothing, and the server
// answers a RESET for a stream it never held, which finds no stream and no note, with
// Consumed 0.
func TestNoiseSession_EveryResetIsAcknowledgedAndANamesakeAcknowledgmentStopsNothing(t *testing.T) {
	client, server, toServer, toClient := filteredPair(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cs, _ := openWithCredit(t, ctx, client, server, 905, 0)
	inc := cs.incarnation
	if !inc.WriterOpened || inc.Generation != cs.generation {
		t.Fatalf("an opened stream names itself %+v, generation %d", inc, cs.generation)
	}
	var acks []aether.ResetPayload
	var mu sync.Mutex
	toClient.setRule(func(f *aether.Frame) bool {
		if f.Type == aether.TypeRESET && f.Flags.Has(aether.FlagACK) {
			mu.Lock()
			acks = append(acks, aether.DecodeResetPayload(f.Payload))
			mu.Unlock()
		}
		return false
	})
	if err := cs.Reset(aether.ResetCancel); err != nil {
		t.Fatalf("reset: %v", err)
	}
	waitLong(t, "the acknowledgment", func() bool { return client.pendingResetCount.Load() == 0 })
	mu.Lock()
	if want := uint64(messageCredit(int64(len("hello")))); len(acks) != 1 || acks[0].Incarnation != inc ||
		acks[0].Charged != 0 || acks[0].Released != 0 || acks[0].Consumed != want {
		mu.Unlock()
		t.Fatalf("acknowledgments %+v; want one naming %+v stating Consumed %d and no other count", acks, inc, want)
	}
	mu.Unlock()
	client.mu.Lock()
	_, quiet := client.recentlyLeft[905]
	client.mu.Unlock()
	if !quiet {
		t.Fatal("the acknowledgment started no quiet time")
	}

	// A RESET waiting under another ID: an acknowledgment of a different stream
	// under it leaves it waiting, and its own stops it.
	wanted := aether.StreamIncarnation{Generation: 77, WriterOpened: true}
	var hold atomic.Bool
	hold.Store(true)
	toServer.setRule(func(f *aether.Frame) bool { return hold.Load() && f.Type == aether.TypeRESET && f.StreamID == 906 })
	if err := client.writeReset(906, aether.ResetPayload{Reason: aether.ResetCancel, Incarnation: wanted}, 50*time.Millisecond, nil); err != nil {
		t.Fatalf("writeReset: %v", err)
	}
	client.resetAcknowledged(906, aether.StreamIncarnation{Generation: 78, WriterOpened: true}, 0)
	client.resetAcknowledged(906, aether.StreamIncarnation{Generation: 77}, 0)
	if client.pendingResetCount.Load() != 1 {
		t.Fatal("an acknowledgment of another stream stopped the waiting RESET")
	}
	hold.Store(false)
	waitLong(t, "the server's acknowledgment of a RESET for a stream it never held", func() bool {
		return client.pendingResetCount.Load() == 0
	})
	mu.Lock()
	defer mu.Unlock()
	if len(acks) != 2 || acks[1].Incarnation != wanted || acks[1].Consumed != 0 {
		t.Fatalf("acknowledgments %+v; want the second naming %+v with Consumed 0", acks, wanted)
	}
}

// TestNoiseSession_AWaitingResetIsWrittenUntilAcknowledged: a RESET waits until its
// acknowledgment comes, written again at a wait that doubles from its stream's RTO up
// to resetRetransmitMaxWait and is never given up while the session lives. Past the
// session's stream cap of waiting RESETs, a RESET is not kept and its ID's quiet time
// starts at once.
func TestNoiseSession_AWaitingResetIsWrittenUntilAcknowledged(t *testing.T) {
	client, _ := noisePairWithRealms(t, nil, nil)
	inc := aether.StreamIncarnation{Generation: 5, WriterOpened: true}
	now := time.Now()
	ping := &aether.Frame{Type: aether.TypePING, StreamID: client.layout.Control}
	client.mu.Lock()
	if client.pendingResets == nil {
		client.pendingResets = make(map[uint64]*pendingReset)
	}
	p := &pendingReset{frame: ping, inc: inc, rto: 300 * time.Millisecond, wait: 300 * time.Millisecond, next: now.Add(300 * time.Millisecond)}
	client.pendingResets[910] = p
	client.pendingResetCount.Add(1)
	client.mu.Unlock()
	var waits []time.Duration
	at := now
	for i := 0; i < 6; i++ {
		client.mu.Lock()
		at = p.next
		client.mu.Unlock()
		client.retransmitResets(at)
		client.mu.Lock()
		waits = append(waits, p.wait)
		client.mu.Unlock()
	}
	want := []time.Duration{600 * time.Millisecond, 1200 * time.Millisecond, resetRetransmitMaxWait, resetRetransmitMaxWait, resetRetransmitMaxWait, resetRetransmitMaxWait}
	for i := range want {
		if waits[i] != want[i] {
			t.Fatalf("waits %v, want %v", waits, want)
		}
	}
	client.retransmitResets(at.Add(time.Hour))
	if client.pendingResetCount.Load() != 1 {
		t.Fatal("a waiting RESET was given up")
	}
	client.mu.Lock()
	delete(client.pendingResets, 910)
	client.pendingResetCount.Add(-1)
	client.mu.Unlock()

	limit := aether.DefaultMaxConcurrentStreams
	for i := 0; i < limit; i++ {
		client.mu.Lock()
		client.pendingResets[uint64(20000+i)] = &pendingReset{frame: ping, inc: inc, rto: time.Hour, wait: time.Hour, next: now.Add(time.Hour)}
		client.pendingResetCount.Add(1)
		client.mu.Unlock()
	}
	if err := client.writeReset(911, aether.ResetPayload{Incarnation: inc}, time.Second, nil); err != nil {
		t.Fatalf("writeReset past the cap: %v", err)
	}
	client.mu.Lock()
	_, pending := client.pendingResets[911]
	_, quiet := client.recentlyLeft[911]
	client.mu.Unlock()
	if pending || !quiet {
		t.Fatalf("past the cap: pending %v, quiet %v; want not kept and quiet", pending, quiet)
	}
}

// TestNoiseSession_ALateCloseOrResetEndsNothingOfTheNextStream: a copy of an
// earlier stream's CLOSE and of another stream's RESET, each late on the path,
// reach the stream that now holds the ID. Neither names it, so its receive side
// stays open and the next message reaches its consumer.
func TestNoiseSession_ALateCloseOrResetEndsNothingOfTheNextStream(t *testing.T) {
	client, server, toServer, _ := filteredPair(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	const id = 902
	var mu sync.Mutex
	var lateClose, lateReset *aether.Frame
	toServer.setRule(func(f *aether.Frame) bool {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case f.Type == aether.TypeCLOSE && f.StreamID == id && lateClose == nil:
			lateClose = f
		case f.Type == aether.TypeRESET && f.StreamID == id && lateReset == nil && !f.Flags.Has(aether.FlagACK):
			lateReset = f
		}
		return false
	})

	cs, ss := openWithCredit(t, ctx, client, server, id, 0)
	if err := cs.Send(ctx, []byte("a")); err != nil {
		t.Fatalf("send: %v", err)
	}
	if r := <-receiveAsync(ctx, ss, 10*time.Second); r.err != nil {
		t.Fatalf("read a: %v", r.err)
	}
	bothClose(t, client, cs, ss)
	waitLong(t, "the server's stream leaving", func() bool { return !streamPresent(server, id) })

	second := reopenWhenFree(t, ctx, client, id)
	if err := second.Send(ctx, []byte("b")); err != nil {
		t.Fatalf("send b: %v", err)
	}
	acc, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if r := <-receiveAsync(ctx, acc, 10*time.Second); r.err != nil || string(r.data) != "b" {
		t.Fatalf("read b: %q, %v", r.data, r.err)
	}
	if err := second.Reset(aether.ResetCancel); err != nil {
		t.Fatalf("reset: %v", err)
	}
	waitLong(t, "the second stream's RESET acknowledged", func() bool { return client.pendingResetCount.Load() == 0 })

	third := reopenWhenFree(t, ctx, client, id)
	if err := third.Send(ctx, []byte("c")); err != nil {
		t.Fatalf("send c: %v", err)
	}
	acc3, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept the third: %v", err)
	}
	if r := <-receiveAsync(ctx, acc3, 10*time.Second); r.err != nil || string(r.data) != "c" {
		t.Fatalf("read c: %q, %v", r.data, r.err)
	}
	mu.Lock()
	staleClose, staleReset := lateClose, lateReset
	mu.Unlock()
	if staleClose == nil || staleReset == nil {
		t.Fatalf("captured CLOSE %v, RESET %v", staleClose != nil, staleReset != nil)
	}
	if err := client.writeFrame(staleClose); err != nil {
		t.Fatalf("late CLOSE: %v", err)
	}
	if err := client.writeFrame(staleReset); err != nil {
		t.Fatalf("late RESET: %v", err)
	}
	for _, m := range []string{"d", "e"} {
		if err := third.Send(ctx, []byte(m)); err != nil {
			t.Fatalf("send %s: %v", m, err)
		}
	}
	got, end := readAll(ctx, acc3, 2*time.Second)
	if len(got) != 2 || got[0] != "d" || got[1] != "e" {
		t.Fatalf("after the late CLOSE and RESET the third stream read %v then %v; want d e", got, end)
	}
	if !streamPresent(server, id) {
		t.Fatal("a late frame ended the third stream at the server")
	}
}

// TestNoiseSession_AnOpenOfALaterGenerationReplacesAStreamItsResetNeverReached: the
// peer has left a stream it opened and its RESET never arrived. Its OPEN of the ID at
// a higher generation ends the stream as the RESET would have, the stream's consumer
// reading what it holds and then io.EOF, and admits the next stream. The server holds
// back none of its grants: the reader of a RESET never withholds, and its grants on
// the stream return what its consumer took. An OPEN at the same or a lower
// generation, a duplicate or a late copy, changes nothing.
func TestNoiseSession_AnOpenOfALaterGenerationReplacesAStreamItsResetNeverReached(t *testing.T) {
	client, server, _, _ := filteredPair(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	const id = 903
	cs, ss := openWithCredit(t, ctx, client, server, id, 4096)
	for i := 0; i < 8; i++ {
		if err := cs.Send(ctx, make([]byte, 1000)); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
		if r := <-receiveAsync(ctx, ss, 10*time.Second); r.err != nil {
			t.Fatalf("read %d: %v", i, r.err)
		}
	}
	reserved := ss.reserved.Load()
	waitLong(t, "the grants passing the stream's credit", func() bool { return ss.recvQ.grantedForTest() > reserved })
	if err := cs.Send(ctx, []byte("held")); err != nil {
		t.Fatalf("send: %v", err)
	}
	waitSendWindowEmpty(t, cs, "held acknowledged")
	if ss.incarnation != (aether.StreamIncarnation{Generation: cs.generation}) {
		t.Fatalf("the accepted stream names itself %+v; the opener's generation is %d", ss.incarnation, cs.generation)
	}
	open := func(generation uint64) {
		payload := aether.EncodeOpenPayload(aether.OpenPayload{
			Reliability: aether.ReliableOrdered, Priority: 128,
			InitialCredit: uint32(ss.window.CurrentWindow()), Generation: generation,
		})
		if err := client.writeFrame(&aether.Frame{
			SenderID: client.LocalPeerID(), ReceiverID: client.RemotePeerID(),
			StreamID: id, Type: aether.TypeOPEN, Length: uint32(len(payload)), Payload: payload,
		}); err != nil {
			t.Fatalf("OPEN: %v", err)
		}
	}
	before := server.admitted.held()
	creditBefore := server.connWindow.Stats().RecvCredit
	open(cs.generation)
	open(cs.generation - 1)
	time.Sleep(300 * time.Millisecond)
	server.mu.Lock()
	cur := server.streams[id]
	server.mu.Unlock()
	if cur != ss {
		t.Fatal("an OPEN at the stream's own or a lower generation replaced it")
	}
	open(cs.generation + 1)
	acc, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept the replacing stream: %v", err)
	}
	next := asNoiseStream(t, acc)
	if next == ss || next.incarnation.Generation != cs.generation+1 {
		t.Fatalf("accepted %+v", next.incarnation)
	}
	got, end := readAll(ctx, ss, 500*time.Millisecond)
	if len(got) != 1 || got[0] != "held" || !errors.Is(end, io.EOF) {
		t.Fatalf("the replaced stream's consumer read %v then %v; want held then io.EOF", got, end)
	}
	if after := server.admitted.held(); after != before {
		t.Fatalf("the server's ledger holds %d after the replacement, %d before: the replaced stream's reservation stayed", after, before)
	}
	if withheld := server.connWindow.Stats().RecvCredit - creditBefore; withheld > 0 {
		t.Fatalf("the replacement held back %d of the server's grants; want none", withheld)
	}
}

// TestNoiseSession_NamedByReadsTheGenerationAndTheOpener: a stream is named by a
// peer's frame stating its generation with the peer's opener bit the opposite of its
// own; the same generation from the other side's count, or another generation, names
// another stream, on both profiles.
func TestNoiseSession_NamedByReadsTheGenerationAndTheOpener(t *testing.T) {
	mine := &noiseStream{incarnation: aether.StreamIncarnation{Generation: 5, WriterOpened: true}}
	theirs := &noiseStream{incarnation: aether.StreamIncarnation{Generation: 5}}
	tcpMine := &tcpStream{incarnation: mine.incarnation}
	for _, c := range []struct {
		inc        aether.StreamIncarnation
		mine, them bool
	}{
		{aether.StreamIncarnation{Generation: 5}, true, false},
		{aether.StreamIncarnation{Generation: 5, WriterOpened: true}, false, true},
		{aether.StreamIncarnation{Generation: 6}, false, false},
		{aether.StreamIncarnation{Generation: 4, WriterOpened: true}, false, false},
	} {
		if mine.namedBy(c.inc) != c.mine || tcpMine.namedBy(c.inc) != c.mine || theirs.namedBy(c.inc) != c.them {
			t.Fatalf("%+v: names this side's stream %v (tcp %v), the peer's %v; want %v, %v",
				c.inc, mine.namedBy(c.inc), tcpMine.namedBy(c.inc), theirs.namedBy(c.inc), c.mine, c.them)
		}
	}
}

// TestNoiseSession_ACrossingResetOfAnotherStreamLeavesTheNote: a stream waiting at
// this side's RESET for the peer's statement is settled only by the peer's RESET of
// the same stream, at its Consumed; a RESET under the ID naming another stream leaves
// it waiting, and the note of what this side granted on it stays for the
// acknowledgment of any copy.
func TestNoiseSession_ACrossingResetOfAnotherStreamLeavesTheNote(t *testing.T) {
	_, server := noisePairWithRealms(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	inc := aether.StreamIncarnation{Generation: 7, WriterOpened: true}
	key := resetKey{id: 950, inc: inc}
	st := &noiseStream{streamID: 950, session: server, window: flow.NewStreamWindow(0), incarnation: inc}
	const charged, consumed = 1000, 400
	if err := server.connWindow.Consume(ctx, charged); err != nil {
		t.Fatalf("consume: %v", err)
	}
	st.commitConnCharge(charged)
	st.settleCharges()
	server.noteResetGrants(950, inc, 5000)
	server.mu.Lock()
	server.awaitingStatement = map[resetKey]*noiseStream{key: st}
	server.mu.Unlock()
	before := connOutstanding(server)
	reset := func(g uint64) {
		p := aether.EncodeResetPayload(aether.ResetPayload{Reason: aether.ResetCancel, Consumed: consumed, Incarnation: aether.StreamIncarnation{Generation: g}})
		server.handleReset(&aether.Frame{StreamID: 950, Type: aether.TypeRESET, Length: uint32(len(p)), Payload: p})
	}
	reset(8)
	server.mu.Lock()
	_, waiting := server.awaitingStatement[key]
	server.mu.Unlock()
	if !waiting || connOutstanding(server) != before {
		t.Fatalf("a RESET of another stream settled the waiting one (waiting %v, outstanding %d of %d)", waiting, connOutstanding(server), before)
	}
	reset(7)
	server.mu.Lock()
	_, waiting = server.awaitingStatement[key]
	_, noted := server.resetGrants[key]
	server.mu.Unlock()
	if waiting {
		t.Fatal("the crossing RESET of the same stream left it waiting")
	}
	if got := before - connOutstanding(server); got != charged-consumed {
		t.Fatalf("the crossing RESET returned %d; want the charge less its Consumed, %d", got, charged-consumed)
	}
	if !noted {
		t.Fatal("the crossing RESET took the note its copies' acknowledgments state")
	}
}

// TestNoiseSession_AnOpenNamingNoStreamIsRefused: an OPEN stating generation zero
// names no stream, so it is refused with RESET(ResetRefused) naming it, and nothing
// is admitted; a refusal of an OPEN for another reason names the OPEN's stream.
func TestNoiseSession_AnOpenNamingNoStreamIsRefused(t *testing.T) {
	client, server, _, toClient := filteredPair(t, nil)
	var refusal atomic.Pointer[aether.ResetPayload]
	toClient.setRule(func(f *aether.Frame) bool {
		if f.Type == aether.TypeRESET && !f.Flags.Has(aether.FlagACK) && f.StreamID == 904 {
			p := aether.DecodeResetPayload(f.Payload)
			refusal.CompareAndSwap(nil, &p)
		}
		return false
	})
	payload := aether.EncodeOpenPayload(aether.OpenPayload{Reliability: aether.ReliableOrdered, Priority: 128, InitialCredit: 1 << 20})
	if err := client.writeFrame(&aether.Frame{
		SenderID: client.LocalPeerID(), ReceiverID: client.RemotePeerID(),
		StreamID: 904, Type: aether.TypeOPEN, Length: uint32(len(payload)), Payload: payload,
	}); err != nil {
		t.Fatalf("OPEN: %v", err)
	}
	waitLong(t, "the refusal", func() bool { return refusal.Load() != nil })
	if p := refusal.Load(); p.Reason != aether.ResetRefused || p.Incarnation != (aether.StreamIncarnation{}) {
		t.Fatalf("refusal %+v", *p)
	}
	if streamPresent(server, 904) {
		t.Fatal("an OPEN naming no stream was admitted")
	}

	// An OPEN the server refuses for another reason, an FEC level outside the
	// registry, is answered with a refusal naming the stream the OPEN opened.
	refusal.Store(nil)
	bad := aether.EncodeOpenPayload(aether.OpenPayload{Reliability: aether.ReliableOrdered, Priority: 128, InitialCredit: 1 << 20, FECLevel: 9, Generation: 42})
	if err := client.writeFrame(&aether.Frame{
		SenderID: client.LocalPeerID(), ReceiverID: client.RemotePeerID(),
		StreamID: 904, Type: aether.TypeOPEN, Length: uint32(len(bad)), Payload: bad,
	}); err != nil {
		t.Fatalf("OPEN: %v", err)
	}
	waitLong(t, "the refusal of an OPEN at generation 42", func() bool { return refusal.Load() != nil })
	if p := refusal.Load(); p.Reason != aether.ResetRefused || p.Incarnation != (aether.StreamIncarnation{Generation: 42}) {
		t.Fatalf("refusal %+v; want it to name generation 42, opened by its reader", *p)
	}
}

// TestTCPSession_ACloseOrResetNamingAnotherStreamEndsNothing: on a byte-stream
// session a peer's CLOSE or RESET of a stream this side has reset can follow this
// side's reopening of the ID. A CLOSE and a RESET naming another stream than the one
// under the ID end nothing of it, the next message reaches its consumer, and a SYN
// naming no stream is refused and admits nothing.
func TestTCPSession_ACloseOrResetNamingAnotherStreamEndsNothing(t *testing.T) {
	client, server := tcpPairWithOptions(t, aether.DefaultSessionOptions())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	const id = 40
	cst, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: id, Reliability: aether.ReliableOrdered, Priority: 128})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := cst.Send(ctx, []byte("a")); err != nil {
		t.Fatalf("send: %v", err)
	}
	sst, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if r := <-receiveAsync(ctx, sst, 10*time.Second); r.err != nil || string(r.data) != "a" {
		t.Fatalf("read a: %q, %v", r.data, r.err)
	}
	cs := cst.(*tcpStream)
	if cs.incarnation.Generation == 0 || !cs.incarnation.WriterOpened ||
		sst.(*tcpStream).incarnation != (aether.StreamIncarnation{Generation: cs.incarnation.Generation}) {
		t.Fatalf("incarnations: opener %+v, accepter %+v", cs.incarnation, sst.(*tcpStream).incarnation)
	}
	other := aether.StreamIncarnation{Generation: cs.incarnation.Generation + 5}
	closePayload := aether.EncodeClosePayload(other)
	if err := server.writeFrame(&aether.Frame{SenderID: server.LocalPeerID(), ReceiverID: server.RemotePeerID(), StreamID: id,
		Type: aether.TypeCLOSE, Length: uint32(len(closePayload)), Payload: closePayload}); err != nil {
		t.Fatalf("late CLOSE: %v", err)
	}
	resetPayload := aether.EncodeResetPayload(aether.ResetPayload{Reason: aether.ResetCancel, Incarnation: other})
	if err := server.writeFrame(&aether.Frame{SenderID: server.LocalPeerID(), ReceiverID: server.RemotePeerID(), StreamID: id,
		Type: aether.TypeRESET, Length: uint32(len(resetPayload)), Payload: resetPayload}); err != nil {
		t.Fatalf("late RESET: %v", err)
	}
	ack := aether.EncodeResetPayload(aether.ResetPayload{Reason: aether.ResetCancel, Incarnation: aether.StreamIncarnation{Generation: cs.incarnation.Generation}})
	if err := server.writeFrame(&aether.Frame{SenderID: server.LocalPeerID(), ReceiverID: server.RemotePeerID(), StreamID: id,
		Type: aether.TypeRESET, Flags: aether.FlagACK, Length: uint32(len(ack)), Payload: ack}); err != nil {
		t.Fatalf("acknowledgment: %v", err)
	}
	if err := sst.Send(ctx, []byte("b")); err != nil {
		t.Fatalf("server send: %v", err)
	}
	if r := <-receiveAsync(ctx, cst, 10*time.Second); r.err != nil || string(r.data) != "b" {
		t.Fatalf("after frames naming another stream the client read %q, %v; want b", r.data, r.err)
	}
	if err := cst.Send(ctx, []byte("c")); err != nil {
		t.Fatalf("client send after: %v", err)
	}
	if r := <-receiveAsync(ctx, sst, 10*time.Second); r.err != nil || string(r.data) != "c" {
		t.Fatalf("server read %q, %v; want c", r.data, r.err)
	}

	refusedBefore := server.StreamRefusedCount()
	syn := aether.EncodeOpenPayload(aether.OpenPayload{Reliability: aether.ReliableOrdered, Priority: 128})
	if err := client.writeFrame(&aether.Frame{SenderID: client.LocalPeerID(), ReceiverID: client.RemotePeerID(), StreamID: 41,
		Type: aether.TypeDATA, Flags: aether.FlagSYN, Length: uint32(len(syn)), Payload: syn}); err != nil {
		t.Fatalf("SYN: %v", err)
	}
	waitLong(t, "the refusal of a SYN naming no stream", func() bool { return server.StreamRefusedCount() > refusedBefore })
	server.mu.Lock()
	_, admitted := server.streams[41]
	server.mu.Unlock()
	if admitted {
		t.Fatal("a SYN naming no stream was admitted")
	}
}

// peerClose is the CLOSE st's peer writes at sequence number seq: it names st as the
// peer states it, the opener bit the opposite of st's own.
func peerClose(st *noiseStream, seq uint32) *aether.Frame {
	p := aether.EncodeClosePayload(aether.StreamIncarnation{Generation: st.incarnation.Generation, WriterOpened: !st.incarnation.WriterOpened})
	return &aether.Frame{Type: aether.TypeCLOSE, StreamID: st.streamID, SeqNo: seq, Length: uint32(len(p)), Payload: p}
}

// peerReset is the RESET st's peer writes, naming st as the peer states it.
func peerReset(st *noiseStream, reason aether.ResetReason) *aether.Frame {
	p := aether.EncodeResetPayload(aether.ResetPayload{Reason: reason,
		Incarnation: aether.StreamIncarnation{Generation: st.incarnation.Generation, WriterOpened: !st.incarnation.WriterOpened}})
	return &aether.Frame{Type: aether.TypeRESET, StreamID: st.streamID, Length: uint32(len(p)), Payload: p}
}

// rawGeneration is the generation a liteRawPeer's SYN for stream id states (synFrame).
func rawGeneration(id uint64) uint64 { return id + 1 }

// rawClose and rawReset are the CLOSE and RESET a liteRawPeer writes for a stream it
// opened with synFrame, naming it as its opener.
func rawClose(id uint64) *aether.Frame {
	return &aether.Frame{StreamID: id, Type: aether.TypeCLOSE,
		Payload: aether.EncodeClosePayload(aether.StreamIncarnation{Generation: rawGeneration(id), WriterOpened: true})}
}

func rawReset(id uint64, reason aether.ResetReason) *aether.Frame {
	return &aether.Frame{StreamID: id, Type: aether.TypeRESET, Payload: aether.EncodeResetPayload(aether.ResetPayload{
		Reason: reason, Incarnation: aether.StreamIncarnation{Generation: rawGeneration(id), WriterOpened: true}})}
}

// closeTo and resetTo are the CLOSE and RESET a liteRawPeer writes for a stream the
// session opened (liteRawPeer.open), naming it by the session's generation.
func closeTo(st *tcpStream) *aether.Frame {
	return &aether.Frame{StreamID: st.streamID, Type: aether.TypeCLOSE,
		Payload: aether.EncodeClosePayload(aether.StreamIncarnation{Generation: st.incarnation.Generation})}
}

func resetTo(st *tcpStream, reason aether.ResetReason) *aether.Frame {
	return &aether.Frame{StreamID: st.streamID, Type: aether.TypeRESET, Payload: aether.EncodeResetPayload(aether.ResetPayload{
		Reason: reason, Incarnation: aether.StreamIncarnation{Generation: st.incarnation.Generation}})}
}
