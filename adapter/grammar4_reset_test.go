//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package adapter

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/flow"
)

// creditFrame reports a frame that returns credit to its reader: a WINDOW_UPDATE,
// or an ACK, which may carry one.
func creditFrame(f *aether.Frame) bool {
	return f.Type == aether.TypeWINDOW || f.Type == aether.TypeACK
}

func connOutstanding(s *NoiseSession) int64 { return s.connWindow.Stats().Outstanding }

// waitBooksAgree polls until the sender's connection outstanding equals what the
// reader's queues hold charged to it: credit returned once, no more and no less.
func waitBooksAgree(t *testing.T, what string, sender, reader *NoiseSession) {
	t.Helper()
	waitLong(t, what, func() bool { return connOutstanding(sender) == reader.recvCharged.Load() })
}

// TestNoiseStream_AGrantCrossingAResetIsNotReturnedTwice: the client's RESET crosses
// the grant for a message the server's consumer has just read. The server's
// acknowledgment states that message among what its consumer returned (Consumed), so
// the client takes back only the rest of its stream's charge, and the grant, which
// arrives anyway, returns the message's credit once: the client's outstanding credit
// on the connection returns to what the server's queues hold charged.
func TestNoiseStream_AGrantCrossingAResetIsNotReturnedTwice(t *testing.T) {
	client, server, _, toClient := filteredPair(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	other, otherServer := openWithCredit(t, ctx, client, server, 900, 0)
	resets, resetsServer := openWithCredit(t, ctx, client, server, 901, 0)
	const size = 4096
	c := messageCredit(size)
	for i := 0; i < 2; i++ {
		if err := other.Send(ctx, make([]byte, size)); err != nil {
			t.Fatalf("send: %v", err)
		}
	}
	for i := 0; i < 3; i++ {
		if err := resets.Send(ctx, make([]byte, size)); err != nil {
			t.Fatalf("send: %v", err)
		}
	}
	waitSendWindowEmpty(t, other, "the other stream acknowledged")
	waitSendWindowEmpty(t, resets, "the stream acknowledged")
	waitBooksAgree(t, "the opening messages' grants", client, server)

	var blocked atomic.Bool
	blocked.Store(true)
	toClient.setRule(func(f *aether.Frame) bool { return blocked.Load() && creditFrame(f) })
	if r := <-receiveAsync(ctx, resetsServer, 10*time.Second); r.err != nil {
		t.Fatalf("read before the RESET: %v", r.err)
	}
	if err := resets.Reset(aether.ResetCancel); err != nil {
		t.Fatalf("reset: %v", err)
	}
	waitFor(t, "the RESET at the server", func() bool { return !streamPresent(server, 901) })
	blocked.Store(false)

	// Two messages stay charged on the other stream, and the one read grant has
	// returned the read message's credit, which the client's settlement left to it.
	if r := <-receiveAsync(ctx, otherServer, 10*time.Second); r.err != nil {
		t.Fatalf("read: %v", r.err)
	}
	if got := server.recvCharged.Load(); got != c {
		t.Fatalf("the server holds %d charged, want one message's %d", got, c)
	}
	waitBooksAgree(t, "one message charged on both books", client, server)
	if r := <-receiveAsync(ctx, otherServer, 10*time.Second); r.err != nil {
		t.Fatalf("read: %v", r.err)
	}
	waitBooksAgree(t, "nothing charged on both books", client, server)
	if got := client.connWindow.Available(); got != flow.CurrentBounds().ConnCredit() {
		t.Fatalf("connection credit %d at rest", got)
	}
}

// TestNoiseStream_TheResetsReaderTakesBackOnlyWhatItsGrantsDoNotCover: the client's
// consumer read one of the server's messages and its grants are on the path when the
// client resets. The server, reading the RESET's Consumed, takes back the rest of its
// charge and leaves that message to the grant, which comes.
func TestNoiseStream_TheResetsReaderTakesBackOnlyWhatItsGrantsDoNotCover(t *testing.T) {
	client, server, toServer, _ := filteredPair(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cs, ss := openWithCredit(t, ctx, client, server, 902, 0)
	const size = 4096
	c := messageCredit(size)
	for i := 0; i < 3; i++ {
		if err := ss.Send(ctx, make([]byte, size)); err != nil {
			t.Fatalf("send: %v", err)
		}
	}
	waitSendWindowEmpty(t, ss, "the server's messages acknowledged")

	var blocked atomic.Bool
	blocked.Store(true)
	toServer.setRule(func(f *aether.Frame) bool { return blocked.Load() && creditFrame(f) })
	if r := <-receiveAsync(ctx, cs, 10*time.Second); r.err != nil {
		t.Fatalf("read: %v", r.err)
	}
	before := connOutstanding(server)
	if before < 3*c {
		t.Fatalf("premise: the server has %d outstanding with its grants on the path", before)
	}
	if err := cs.Reset(aether.ResetCancel); err != nil {
		t.Fatalf("reset: %v", err)
	}
	// handleReset takes the stream out of s.streams before settlePeerReset runs on the
	// same readLoop pass, so the count is polled: with the grants held on the path it
	// can only fall to the read message's charge, and never below it.
	waitFor(t, "the RESET at the server", func() bool { return !streamPresent(server, 902) })
	var got int64
	deadline := time.Now().Add(5 * time.Second)
	for got = connOutstanding(server); got != c && time.Now().Before(deadline); got = connOutstanding(server) {
		time.Sleep(5 * time.Millisecond)
	}
	if got != c {
		t.Fatalf("after the RESET the server has %d outstanding, want the read message's %d, whose grant is on its way", got, c)
	}
	blocked.Store(false)
	waitLong(t, "the grant", func() bool { return connOutstanding(server) == 0 })
}

// TestNoiseStream_CrossingResetsCorrectEachOther: both sides reset a stream and the
// RESETs pass on the path. The client's arrives where the stream has gone, and its
// Consumed settles the server's charge, for which the server's stream waits
// (awaitingStatement); the client's acknowledgment of the server's RESET, which states
// the same count, then settles nothing a second time. The path holds the client's RESET
// and its copies; the server keeps what its own consumer returned (resetGrants), the
// Consumed its acknowledgment of the client's RESET and of any copy of it states.
func TestNoiseStream_CrossingResetsCorrectEachOther(t *testing.T) {
	client, server, toServer, toClient := filteredPair(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	other, otherServer := openWithCredit(t, ctx, client, server, 903, 0)
	resets, resetsServer := openWithCredit(t, ctx, client, server, 904, 0)
	const size = 4096
	for i := 0; i < 2; i++ {
		if err := other.Send(ctx, make([]byte, size)); err != nil {
			t.Fatalf("send: %v", err)
		}
		if err := resets.Send(ctx, make([]byte, size)); err != nil {
			t.Fatalf("send: %v", err)
		}
	}
	waitSendWindowEmpty(t, other, "the other stream acknowledged")
	waitSendWindowEmpty(t, resets, "the stream acknowledged")
	waitBooksAgree(t, "the opening messages' grants", client, server)

	var blocked atomic.Bool
	blocked.Store(true)
	toClient.setRule(func(f *aether.Frame) bool { return blocked.Load() && creditFrame(f) })
	var held atomic.Pointer[aether.Frame]
	toServer.setRule(func(f *aether.Frame) bool {
		if f.Type == aether.TypeRESET && f.StreamID == 904 && !f.Flags.Has(aether.FlagACK) {
			held.Store(f)
			return true
		}
		return false
	})
	if r := <-receiveAsync(ctx, resetsServer, 10*time.Second); r.err != nil {
		t.Fatalf("read: %v", r.err)
	}
	if err := resets.Reset(aether.ResetCancel); err != nil {
		t.Fatalf("client reset: %v", err)
	}
	if err := resetsServer.Reset(aether.ResetCancel); err != nil {
		t.Fatalf("server reset: %v", err)
	}
	if held.Load() == nil {
		t.Fatal("the client's RESET was not on the path")
	}
	key := resetKey{id: 904, inc: resetsServer.incarnation}
	server.mu.Lock()
	_, noted := server.resetGrants[key]
	_, awaiting := server.awaitingStatement[key]
	server.mu.Unlock()
	if !noted || !awaiting {
		t.Fatalf("at its own RESET the server noted its count %v and waits for the client's statement %v", noted, awaiting)
	}
	server.handleReset(held.Load())
	server.mu.Lock()
	_, noted = server.resetGrants[key]
	_, awaiting = server.awaitingStatement[key]
	server.mu.Unlock()
	if !noted {
		t.Fatal("the crossing RESET took the count the server's acknowledgments state")
	}
	if awaiting {
		t.Fatal("the crossing RESET's Consumed did not settle the server's stream")
	}
	blocked.Store(false)
	toServer.setRule(nil)

	if r := <-receiveAsync(ctx, otherServer, 10*time.Second); r.err != nil {
		t.Fatalf("read: %v", r.err)
	}
	waitBooksAgree(t, "one message charged on both books", client, server)
	if r := <-receiveAsync(ctx, otherServer, 10*time.Second); r.err != nil {
		t.Fatalf("read: %v", r.err)
	}
	waitBooksAgree(t, "nothing charged on both books", client, server)
}

// TestNoiseSession_AResetsStatementCannotOverdrawAnything: a statement of consumption
// past what the stream's Sends charged cannot be true of any stream, so it is charged
// to the peer and returns nothing; a second statement after the first returns nothing
// either, and a true one returns the charge less what it states.
func TestNoiseSession_AResetsStatementCannotOverdrawAnything(t *testing.T) {
	client, server, _, toClient := filteredPair(t, func(o *aether.SessionOptions) { o.SessionWarmupGrace = -1 })
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	// openWithCredit's message makes each side's peer a delivering one, whose
	// malformed frames reportAbuse's forensic tier records.
	_, _ = openWithCredit(t, ctx, client, server, 905, 0)
	_, _ = openWithCredit(t, ctx, server, client, 909, 0)
	// The server holds its grants back, so what the client's sends charge stays
	// outstanding until the settlement below.
	toClient.setRule(creditFrame)
	for _, tc := range []struct {
		name     string
		consumed uint64
		returned int64
		abuse    uint64
	}{
		{name: "past the charge", consumed: 1 << 63, returned: 0, abuse: 1},
		{name: "a true statement", consumed: uint64(messageCredit(100)), returned: messageCredit(100), abuse: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := &noiseStream{streamID: 1, session: client, window: flow.NewStreamWindow(0)}
			n := 2 * messageCredit(100)
			if err := client.connWindow.Consume(ctx, n); err != nil {
				t.Fatalf("consume: %v", err)
			}
			if !st.commitConnCharge(n) {
				t.Fatal("the record refused a charge")
			}
			before, abused := connOutstanding(client), client.ForensicSuppressedCount()
			st.settleCharges()
			st.notePeerConsumed(tc.consumed)
			st.notePeerConsumed(0)
			if got := before - connOutstanding(client); got != tc.returned {
				t.Fatalf("Consumed %d of %d charged returned %d, want %d", tc.consumed, n, got, tc.returned)
			}
			if got := client.ForensicSuppressedCount() - abused; got != tc.abuse {
				t.Fatalf("charged to the peer %d times, want %d", got, tc.abuse)
			}
			client.connWindow.ReleaseUnsent(n - tc.returned)
		})
	}
}

// TestNoiseStream_AResetStatesItsCounts: the payload a stream's RESET carries: all
// its sends charged, what it took back, and what its consumer returned, both a read
// message's credit and the bytes reassembly refused, which its grants return too.
func TestNoiseStream_AResetStatesItsCounts(t *testing.T) {
	client, server, _, toClient := filteredPair(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cs, ss := openWithCredit(t, ctx, client, server, 907, 0)
	if err := ss.Send(ctx, make([]byte, 100)); err != nil {
		t.Fatalf("send: %v", err)
	}
	waitSendWindowEmpty(t, ss, "the server's message acknowledged")
	if r := <-receiveAsync(ctx, cs, 10*time.Second); r.err != nil {
		t.Fatalf("read: %v", r.err)
	}

	// A fragment envelope that does not parse is refused, and the sender's credit
	// for it is granted back at once.
	garbage := make([]byte, 400)
	server.handleData(&aether.Frame{
		Type: aether.TypeDATA, StreamID: 907, SeqNo: 1, Flags: aether.FlagANTIREPLAY | aether.FlagFRAGMENT,
		Length: uint32(len(garbage)), Payload: garbage,
	})

	var reset atomic.Pointer[aether.Frame]
	toClient.setRule(func(f *aether.Frame) bool {
		if f.Type == aether.TypeRESET {
			reset.Store(f)
		}
		return false
	})
	granted := ss.recvQ.grantedForTest()
	charged := ss.window.Charged()
	outstanding := ss.window.Outstanding()
	if err := ss.Reset(aether.ResetCancel); err != nil {
		t.Fatalf("reset: %v", err)
	}
	f := reset.Load()
	if f == nil {
		t.Fatal("no RESET was written")
	}
	p := aether.DecodeResetPayload(f.Payload)
	if p.Reason != aether.ResetCancel || p.Charged != uint64(charged) || p.Released != uint64(outstanding) || p.Consumed != uint64(granted) {
		t.Fatalf("stated %+v; charged %d, outstanding %d, granted %d", p, charged, outstanding, granted)
	}
	if want := messageCredit(5); granted <= want {
		t.Fatalf("granted %d: the refused fragment's bytes did not count beside the read's %d", granted, want)
	}
}

// TestNoiseSession_ResetNotesAreBounded: a note waits out resetGrantLifetime, is not
// kept for a stream that granted nothing, stays when its ID is opened again (it names
// the stream it was taken for, which the ID's next stream is not), and stops at the
// stream cap.
func TestNoiseSession_ResetNotesAreBounded(t *testing.T) {
	client, server := noisePairWithRealms(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	inc := aether.StreamIncarnation{Generation: 1}
	server.noteResetGrants(1000, inc, 0)
	server.noteResetGrants(1001, inc, 5)
	server.mu.Lock()
	if _, ok := server.resetGrants[resetKey{id: 1000, inc: inc}]; ok {
		server.mu.Unlock()
		t.Fatal("a stream that granted nothing kept a note")
	}
	server.mu.Unlock()

	now := time.Now()
	server.sweepResetGrants(now.Add(resetGrantLifetime - time.Second))
	server.mu.Lock()
	_, kept := server.resetGrants[resetKey{id: 1001, inc: inc}]
	server.mu.Unlock()
	if !kept {
		t.Fatal("the sweep dropped a young note")
	}
	server.sweepResetGrants(now.Add(resetGrantLifetime + time.Minute))
	server.mu.Lock()
	_, kept = server.resetGrants[resetKey{id: 1001, inc: inc}]
	server.mu.Unlock()
	if kept {
		t.Fatal("the sweep kept an old note")
	}

	earlier := aether.StreamIncarnation{Generation: 1 << 40}
	server.noteResetGrants(906, earlier, 5)
	_, ss := openWithCredit(t, ctx, client, server, 906, 0)
	server.mu.Lock()
	_, kept = server.resetGrants[resetKey{id: 906, inc: earlier}]
	_, shared := server.resetGrants[resetKey{id: 906, inc: ss.incarnation}]
	server.mu.Unlock()
	if !kept || shared {
		t.Fatalf("after the ID's next stream opened: the earlier stream's note kept %v, a note under the new stream %v", kept, shared)
	}

	limit := server.opts.MaxConcurrentStreams
	if limit <= 0 {
		limit = aether.DefaultMaxConcurrentStreams
	}
	for i := 0; i < limit+10; i++ {
		server.noteResetGrants(uint64(5000+i), inc, 1)
	}
	server.mu.Lock()
	n := len(server.resetGrants)
	server.mu.Unlock()
	if n > limit {
		t.Fatalf("%d notes held past the cap of %d", n, limit)
	}
}

// TestRecvQueue_ARESETsEndTakesNothingMore: from the moment a RESET's settlement reads
// the queue's granted count, the queue admits nothing: a push behind that read would
// count in the session's charged credit for a sender that has taken it back. A read
// after it replenishes nothing and leaves the count where the RESET stated it.
func TestRecvQueue_ARESETsEndTakesNothingMore(t *testing.T) {
	q := newRecvQueue(nil, nil)
	if got := q.push(make([]byte, 100), 0, 0); got != pushQueued {
		t.Fatalf("push: %v", got)
	}
	if got := q.push(make([]byte, 100), 0, 0); got != pushQueued {
		t.Fatalf("push: %v", got)
	}
	if _, credited, ok := q.pop(); !ok || !credited {
		t.Fatalf("pop before the RESET: credited %v, ok %v", credited, ok)
	}
	c := messageCredit(100)
	if got := q.peerEnded(); got != c {
		t.Fatalf("granted %d, want one message's %d", got, c)
	}
	if got := q.charged.Load(); got != 0 {
		t.Fatalf("charged %d after the RESET", got)
	}
	if got := q.push(make([]byte, 100), 0, 0); got != pushEnded {
		t.Fatalf("push after the RESET: %v", got)
	}
	if got := q.charged.Load(); got != 0 {
		t.Fatalf("charged %d after a push behind the RESET", got)
	}
	if _, credited, ok := q.pop(); !ok || credited {
		t.Fatalf("pop after the RESET: credited %v, ok %v", credited, ok)
	}
	if got := q.peerEnded(); got != c {
		t.Fatalf("granted %d after a read behind the RESET", got)
	}
}
