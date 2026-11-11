//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"context"
	"errors"
	"math/rand"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/flow"
	"github.com/ORBTR/aether/reliability"
)

// openRetryingDuplicate opens id on s, retrying while the ID is still held by a stream
// whose RESET waits for its acknowledgment or whose quiet time runs
// (aether.ErrDuplicateStreamID), for at most within.
func openRetryingDuplicate(ctx context.Context, s aether.Session, id uint64, within time.Duration) (aether.Stream, error) {
	start := time.Now()
	for {
		st, err := s.OpenStream(ctx, aether.StreamConfig{StreamID: id, Reliability: aether.ReliableOrdered, Priority: 128})
		if err == nil || !errors.Is(err, aether.ErrDuplicateStreamID) || time.Since(start) > within {
			return st, err
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// resetSettlementRounds runs rounds of four Sends racing a RESET on one stream ID after
// another, beside a stream whose one message the peer never reads, and returns the
// client's and the server's connection outstanding once both have settled, with the
// unread message's charge, which each side's window also holds for a message of its
// own the other side never reads. mode picks the RESET: "local" is the client's Reset,
// "localcross" the client's Reset with the server's own Reset crossing it, "peer" the
// server's Reset with the client's own Reset crossing it, "peeronly" the server's Reset
// alone, and "both" the two Resets at once from two goroutines. In every mode but
// "local" the server's stream sends three messages the client never reads before any
// Reset, so the server's own charge is settled too: the crossing modes settle each side
// on the other's crossing RESET (handleReset's crossing branch), the others on the
// acknowledgment (resetAcknowledged) or the peer's RESET that ends the stream.
func resetSettlementRounds(t *testing.T, mode string, rounds int) (client, server int64, held int64) {
	t.Helper()
	const unreadID = 990
	// The two unread streams stay idle for the whole run, so the stream GC, which would
	// reset them and settle their charge, leaves them alone.
	cl, sv, _, _ := filteredPair(t, func(o *aether.SessionOptions) {
		o.HeaderComp = aether.DefaultSessionOptions().HeaderComp
		o.SessionLifetimeStreams = append(o.SessionLifetimeStreams, unreadID, unreadID+2)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	other, _ := openWithCredit(t, ctx, cl, sv, unreadID, 0)
	unread := []byte("never read by the peer")
	if err := other.Send(ctx, unread); err != nil {
		t.Fatalf("send unread: %v", err)
	}
	held = messageCredit(int64(len(unread)))
	waitFor(t, "only the unread message charged", func() bool { return cl.connWindow.Stats().Outstanding == held })
	back, _ := openWithCredit(t, ctx, sv, cl, unreadID+2, 0)
	if err := back.Send(ctx, unread); err != nil {
		t.Fatalf("server send unread: %v", err)
	}
	waitFor(t, "only the server's unread message charged", func() bool { return sv.connWindow.Stats().Outstanding == held })

	accepted := make(chan aether.Stream, 1024)
	go func() {
		for {
			st, err := sv.AcceptStream(ctx)
			if err != nil {
				return
			}
			accepted <- st
			go func() {
				for {
					if _, err := st.Receive(ctx); err != nil {
						return
					}
				}
			}()
		}
	}()
	rng := rand.New(rand.NewSource(10))
	byPeer := mode != "local"
	for i := 0; i < rounds; i++ {
		id := uint64(700 + 2*(i%40))
		cs, err := openRetryingDuplicate(ctx, cl, id, 20*time.Second)
		if err != nil {
			t.Fatalf("round %d open %d: %v", i, id, err)
		}
		var ss aether.Stream
		if byPeer {
			if err := cs.Send(ctx, []byte("open")); err != nil {
				t.Fatalf("round %d first send: %v", i, err)
			}
			for ss == nil {
				select {
				case a := <-accepted:
					// A stream of an earlier round this side reset may arrive late.
					if a.StreamID() == id {
						ss = a
					}
				case <-time.After(20 * time.Second):
					t.Fatalf("round %d: the peer accepted nothing", i)
				}
			}
			for j := 0; j < 3; j++ {
				if err := ss.Send(ctx, make([]byte, 100+j)); err != nil {
					break
				}
			}
		}
		var wg sync.WaitGroup
		for g := 0; g < 4; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 50; j++ {
					if err := cs.Send(ctx, make([]byte, 200+j)); err != nil {
						return
					}
				}
			}()
		}
		time.Sleep(time.Duration(rng.Intn(1500)) * time.Microsecond)
		switch mode {
		case "local":
			_ = cs.Reset(aether.ResetCancel)
		case "localcross":
			_ = cs.Reset(aether.ResetCancel)
			_ = ss.Reset(aether.ResetCancel)
		case "peer", "peeronly":
			_ = ss.Reset(aether.ResetCancel)
		case "both":
			var resets sync.WaitGroup
			resets.Add(2)
			go func() { defer resets.Done(); _ = cs.Reset(aether.ResetCancel) }()
			go func() { defer resets.Done(); _ = ss.Reset(aether.ResetCancel) }()
			resets.Wait()
		default:
			t.Fatalf("unknown mode %q", mode)
		}
		wg.Wait()
		switch mode {
		case "peeronly":
			// No local Reset: the peer's RESET ends the stream here, after which a Send
			// fails, and the next round's open of the ID waits for nothing of this one.
			end := time.Now().Add(10 * time.Second)
			for cs.Send(ctx, []byte{1}) == nil && time.Now().Before(end) {
				time.Sleep(time.Millisecond)
			}
		case "peer":
			_ = cs.Reset(aether.ResetCancel)
		}
	}
	deadline := time.Now().Add(30 * time.Second)
	for (cl.connWindow.Stats().Outstanding != held || sv.connWindow.Stats().Outstanding != held) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	return cl.connWindow.Stats().Outstanding, sv.connWindow.Stats().Outstanding, held
}

// TestNoiseStream_SendsRacingResetsReturnExactlyTheirConnectionCharge: Sends racing a
// RESET on one stream after another leave each side's connection window holding exactly
// what no RESET ended, whichever side resets and whether the two sides' RESETs cross,
// in either order or at once:
// each ends at the charge of its one message the other side never reads, the server's
// sends on the reset streams, which the client never read, included. More is a leak; less is a charge returned twice, which shows as
// the unread message's credit handed back early (ReleaseUnsent caps at what is
// outstanding). RESET_SETTLEMENT_ROUNDS raises the rounds per mode.
func TestNoiseStream_SendsRacingResetsReturnExactlyTheirConnectionCharge(t *testing.T) {
	rounds := 200
	if v, err := strconv.Atoi(os.Getenv("RESET_SETTLEMENT_ROUNDS")); err == nil && v > 0 {
		rounds = v
	}
	for _, mode := range []string{"local", "localcross", "peer", "peeronly", "both"} {
		t.Run(mode, func(t *testing.T) {
			client, server, held := resetSettlementRounds(t, mode, rounds)
			t.Logf("%s, %d rounds: client outstanding %d, server outstanding %d, want %d each", mode, rounds, client, server, held)
			for _, side := range []struct {
				name string
				got  int64
			}{{"client", client}, {"server", server}} {
				if side.got > held {
					t.Errorf("%s leak: %d bytes outstanding beside the %d the unread message holds", side.name, side.got-held, held)
				}
				if side.got < held {
					t.Errorf("%s double return: %d outstanding, below the unread message's %d", side.name, side.got, held)
				}
			}
		})
	}
}

// TestNoiseSession_ACopyOfAResetIsAcknowledgedWithTheSameConsumed: the peer settles
// on the first acknowledgment that reaches it, so when the first is lost the copy of
// its RESET that the peer writes again, which finds the stream gone, is answered with
// the Consumed the first stated, from the note the RESET left (noteResetGrants); a
// RESET for a stream this side never held is answered with 0.
func TestNoiseSession_ACopyOfAResetIsAcknowledgedWithTheSameConsumed(t *testing.T) {
	client, server, toServer, toClient := filteredPair(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cs, ss := openWithCredit(t, ctx, client, server, 914, 0)
	waitSendWindowEmpty(t, cs, "the opening message acknowledged")
	var reset atomic.Pointer[aether.Frame]
	toServer.setRule(func(f *aether.Frame) bool {
		if f.Type == aether.TypeRESET && !f.Flags.Has(aether.FlagACK) && f.StreamID == 914 {
			reset.Store(f)
			return true
		}
		return false
	})
	var mu sync.Mutex
	var acks []aether.ResetPayload
	toClient.setRule(func(f *aether.Frame) bool {
		if f.Type == aether.TypeRESET && f.Flags.Has(aether.FlagACK) {
			mu.Lock()
			acks = append(acks, aether.DecodeResetPayload(f.Payload))
			mu.Unlock()
			return true
		}
		return false
	})
	if err := cs.Reset(aether.ResetCancel); err != nil {
		t.Fatalf("reset: %v", err)
	}
	waitFor(t, "the client's RESET on the path", func() bool { return reset.Load() != nil })
	want := uint64(ss.recvQ.grantedForTest())
	server.handleReset(reset.Load())
	server.handleReset(reset.Load())
	never := aether.EncodeResetPayload(aether.ResetPayload{Reason: aether.ResetCancel, Incarnation: aether.StreamIncarnation{Generation: 1 << 40, WriterOpened: true}})
	server.handleReset(&aether.Frame{StreamID: 916, Type: aether.TypeRESET, Length: uint32(len(never)), Payload: never})
	waitFor(t, "three acknowledgments", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(acks) == 3
	})
	mu.Lock()
	defer mu.Unlock()
	if want == 0 || acks[0].Consumed != want || acks[1].Consumed != want || acks[2].Consumed != 0 {
		t.Fatalf("acknowledgments stated %d, %d and %d; want %d for the RESET and its copy, 0 for a stream never held",
			acks[0].Consumed, acks[1].Consumed, acks[2].Consumed, want)
	}
}

// TestRecvQueue_NothingIsGrantedPastTheRESETsStatement: once a RESET has fixed what
// the queue's grants returned (peerEnded), the bytes reassembly or an expired frame
// would give back are not granted (addGranted reports false) and the count stays what
// the RESET stated, since the sender's settlement returns them; before it they are
// counted and granted.
func TestRecvQueue_NothingIsGrantedPastTheRESETsStatement(t *testing.T) {
	q := newRecvQueue(nil, nil)
	if !q.addGranted(10) {
		t.Fatal("a live queue refused to grant")
	}
	if got := q.peerEnded(); got != 10 {
		t.Fatalf("stated %d, want 10", got)
	}
	if q.addGranted(20) {
		t.Fatal("bytes past the RESET's statement were granted")
	}
	if got := q.peerEnded(); got != 10 {
		t.Fatalf("the statement moved to %d after the RESET", got)
	}
}

// TestNoiseStream_AFrameSettledPastTheRESETIsNotReturnedTwice: handleData looks a
// stream up and then delivers what its receive window hands back, and a Reset on
// another goroutine may end the stream between the two; a frame the window then gives
// up on (settleExpired) is one the peer's settlement already returns, since the RESET's
// Consumed did not count it, so granting it as well would hand its credit back twice.
// Over two live sessions the client's message A is lost on the path and the message
// after it, B, reaches the server's receive window and waits there for A; the server
// resets the stream and the client settles on the RESET; then the server's readLoop
// step is run on the ended stream with B expired. The client's connection window must
// hold exactly its unread message's charge: below it is B's credit returned twice,
// which ApplyUpdate shows only while an unread charge is outstanding above it.
func TestNoiseStream_AFrameSettledPastTheRESETIsNotReturnedTwice(t *testing.T) {
	const unreadID, id = 1030, 1032
	client, server, toServer, _ := filteredPair(t, func(o *aether.SessionOptions) {
		o.SessionLifetimeStreams = append(o.SessionLifetimeStreams, unreadID)
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	other, _ := openWithCredit(t, ctx, client, server, unreadID, 0)
	unread := make([]byte, 4096)
	if err := other.Send(ctx, unread); err != nil {
		t.Fatalf("send unread: %v", err)
	}
	held := messageCredit(int64(len(unread)))
	waitFor(t, "only the unread message charged", func() bool { return connOutstanding(client) == held })

	cs, ss := openWithCredit(t, ctx, client, server, id, 0)
	waitSendWindowEmpty(t, cs, "the opening message acknowledged")
	waitFor(t, "the opening message's credit back", func() bool { return connOutstanding(client) == held })
	var lostSeq atomic.Int64
	lostSeq.Store(-1)
	toServer.setRule(func(f *aether.Frame) bool {
		if f.StreamID != id || f.Type != aether.TypeDATA {
			return false
		}
		lostSeq.CompareAndSwap(-1, int64(f.SeqNo))
		return int64(f.SeqNo) == lostSeq.Load()
	})
	lost, waiting := []byte("message A, lost on the path"), []byte("message B, waiting for A")
	if err := cs.Send(ctx, lost); err != nil {
		t.Fatalf("send A: %v", err)
	}
	if err := cs.Send(ctx, waiting); err != nil {
		t.Fatalf("send B: %v", err)
	}
	waitFor(t, "B waiting in the server's receive window for A", func() bool { return ss.recvWindow.BufferedCount() == 1 })
	twice := messageCredit(int64(len(waiting)))
	charged := messageCredit(int64(len(lost))) + twice
	waitFor(t, "A and B charged", func() bool { return connOutstanding(client) == held+charged })
	if held < twice {
		t.Fatalf("premise: the unread charge %d is below B's %d, so a double return would be capped away", held, twice)
	}

	if err := ss.Reset(aether.ResetCancel); err != nil {
		t.Fatalf("server reset: %v", err)
	}
	waitFor(t, "the client settled on the server's RESET", func() bool { return connOutstanding(client) == held })
	// A grant the expiry would make goes out at once (ConnWindow.ReceiverConsume's timed
	// trigger) once GrantMaxInterval has passed since the server's last grant.
	time.Sleep(flow.GrantMaxInterval + 100*time.Millisecond)
	ss.settleExpired(reliability.RecvDelivery{Payload: waiting, Expired: true})

	end := time.Now().Add(3 * time.Second)
	for time.Now().Before(end) {
		if got := connOutstanding(client); got != held {
			t.Fatalf("client outstanding %d after the expiry past the RESET, want %d (B's credit is %d)", got, held, twice)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestRecvQueue_ACreditReleasedBeforeTheRESETCountsInItsStatement: credit the queue
// hands back for messages no consumer will read (releaseCharge, for a local Reset that
// finds the stream already gone; discard, for the sweep and makeQueueRoom) is granted
// to the sender, so a RESET's statement read after it (peerEnded) counts it in
// Consumed: otherwise the sender would take the same bytes back at its settlement and
// receive the grant as well. A Reset racing the peer's RESET can release the queue
// between the stream's leaving and the RESET's read of the statement.
func TestRecvQueue_ACreditReleasedBeforeTheRESETCountsInItsStatement(t *testing.T) {
	for _, release := range []struct {
		name string
		fn   func(q *recvQueue) int64
	}{
		{"releaseCharge", (*recvQueue).releaseCharge},
		{"discard", (*recvQueue).discard},
	} {
		t.Run(release.name, func(t *testing.T) {
			q := newRecvQueue(nil, nil)
			for i := 0; i < 3; i++ {
				if got := q.push(make([]byte, 100), 0, 0); got != pushQueued {
					t.Fatalf("push: %v", got)
				}
			}
			want := 3 * messageCredit(100)
			if got := release.fn(q); got != want {
				t.Fatalf("released %d, want %d", got, want)
			}
			if got := q.peerEnded(); got != want {
				t.Fatalf("the RESET's statement is %d, want the %d granted", got, want)
			}
			if got := release.fn(q); got != 0 {
				t.Fatalf("a second release granted %d", got)
			}
		})
	}
}

// TestNoiseStream_BothRESETExitsOnOneStreamReturnItsChargeOnce: this side's Reset and
// its handling of the peer's RESET can both run on one stream, in either order, each
// closing the stream's connection record and each reaching the settlement; the charge
// less the peer's Consumed comes back once whichever runs first.
func TestNoiseStream_BothRESETExitsOnOneStreamReturnItsChargeOnce(t *testing.T) {
	client, _ := noisePairWithRealms(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	const charged, consumed = 3000, 1000
	for _, peerFirst := range []bool{true, false} {
		st := &noiseStream{streamID: 1012, session: client, window: flow.NewStreamWindow(0), recvQ: newRecvQueue(nil, nil),
			incarnation: aether.StreamIncarnation{Generation: 1 << 41, WriterOpened: true}}
		if err := client.connWindow.Consume(ctx, charged); err != nil {
			t.Fatalf("consume: %v", err)
		}
		st.commitConnCharge(charged)
		before := connOutstanding(client)
		peer := aether.ResetPayload{Reason: aether.ResetCancel, Consumed: consumed}
		if peerFirst {
			st.settlePeerReset(peer, false)
			st.settleLocalReset(aether.ResetCancel)
		} else {
			st.settleLocalReset(aether.ResetCancel)
			st.settlePeerReset(peer, false)
		}
		if got := before - connOutstanding(client); got != charged-consumed {
			t.Fatalf("peer's RESET first %v: returned %d, want %d once", peerFirst, got, charged-consumed)
		}
		client.connWindow.ReleaseUnsent(consumed)
	}
}
