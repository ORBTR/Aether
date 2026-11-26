//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package adapter

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// TestNoiseStream_AQueuedStreamWhoseFirstFramesAreLostRecovers: one stream queues n
// messages while every DATA frame of it is lost on the path for its first 40 ms, and
// nothing is lost after that. The frames written in those 40 ms fill the congestion
// window with bytes no ACK will take back, and the receiver, waiting for the first of
// them, takes only the frames inside its reorder window, so the one frame that lets
// it deliver and acknowledge is the oldest unacknowledged one. Every message has to
// arrive, once and in order, and that frame has to be written again after the loss.
func TestNoiseStream_AQueuedStreamWhoseFirstFramesAreLostRecovers(t *testing.T) {
	for _, n := range []int{200, 400} {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			client, server, _, toClient := filteredPair(t, func(o *aether.SessionOptions) { o.SessionWarmupGrace = -1 })
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			const id = 1810
			ss, cs := openWithCredit(t, ctx, server, client, id, 0)

			var lossOver atomic.Bool
			var headSeq atomic.Int64
			var headAfter atomic.Int64
			headSeq.Store(-1)
			toClient.setRule(func(f *aether.Frame) bool {
				if f.StreamID != id || f.Type != aether.TypeDATA {
					return false
				}
				if !lossOver.Load() {
					headSeq.CompareAndSwap(-1, int64(f.SeqNo))
					return true
				}
				if int64(f.SeqNo) == headSeq.Load() {
					headAfter.Add(1)
				}
				return false
			})

			msg := func(i int) []byte {
				return []byte(fmt.Sprintf("lost head %05d %s", i, bytes.Repeat([]byte{'h'}, i%40)))
			}
			sendErr := make(chan error, 1)
			go func() {
				for i := 0; i < n; i++ {
					if err := ss.Send(ctx, msg(i)); err != nil {
						sendErr <- err
						return
					}
				}
				sendErr <- nil
			}()
			time.Sleep(40 * time.Millisecond)
			lossOver.Store(true)

			deadline := time.Now().Add(30 * time.Second)
			for i := 0; i < n; i++ {
				rctx, rc := context.WithDeadline(ctx, deadline)
				got, err := cs.Receive(rctx)
				rc()
				if err != nil {
					t.Fatalf("received %d of %d: %v; the receiver expects SeqNo %d with %d buffered; the first lost SeqNo %d was written %d times after the loss",
						i, n, err, cs.recvWindow.ExpectedSeqNo(), cs.recvWindow.BufferedCount(), headSeq.Load(), headAfter.Load())
				}
				if !bytes.Equal(got, msg(i)) {
					t.Fatalf("message %d: got %q, want %q", i, got, msg(i))
				}
			}
			if err := <-sendErr; err != nil {
				t.Fatalf("send: %v", err)
			}
			if headAfter.Load() == 0 {
				t.Fatalf("every message arrived, yet the first lost SeqNo %d was never written after the loss", headSeq.Load())
			}
		})
	}
}

// TestNoiseSession_KeyingOneSideFirstUnderTrafficLosesNoMessage: two streams each way
// carry numbered messages while the two sessions are keyed one after the other, 40 ms
// apart, or together with the short header forms on. A session keyed second refuses
// as malformed the sealed frames that reach it before its own key, which is a loss on
// the path for every stream the first-keyed side is sending on. Every message has to
// arrive once, in order and byte-equal.
func TestNoiseSession_KeyingOneSideFirstUnderTrafficLosesNoMessage(t *testing.T) {
	for _, mode := range []string{"server-first", "client-first", "together-short"} {
		t.Run(mode, func(t *testing.T) {
			client, server, _, _ := filteredPair(t, func(o *aether.SessionOptions) {
				o.SessionWarmupGrace = -1
				if mode == "together-short" {
					o.HeaderComp = true
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			const perStream = 400
			type pair struct {
				from, to *NoiseSession
				id       uint64
			}
			pairs := []pair{{client, server, 1110}, {client, server, 1112}, {server, client, 1115}, {server, client, 1117}}
			want := func(id uint64, i int) []byte {
				return []byte(fmt.Sprintf("stream %d message %05d %s", id, i, bytes.Repeat([]byte{byte('a' + i%26)}, 200+i%300)))
			}
			var wg sync.WaitGroup
			errs := make(chan error, 2*len(pairs))
			for _, p := range pairs {
				snd, rcv := openWithCredit(t, ctx, p.from, p.to, p.id, 0)
				wg.Add(2)
				go func() {
					defer wg.Done()
					for i := 0; i < perStream; i++ {
						if err := snd.Send(ctx, want(p.id, i)); err != nil {
							errs <- fmt.Errorf("stream %d send %d: %w", p.id, i, err)
							return
						}
						if i%20 == 0 {
							time.Sleep(time.Millisecond)
						}
					}
				}()
				go func() {
					defer wg.Done()
					for i := 0; i < perStream; i++ {
						got, err := rcv.Receive(ctx)
						if err != nil {
							errs <- fmt.Errorf("stream %d receive %d: %w; expects SeqNo %d with %d buffered", p.id, i, err, rcv.recvWindow.ExpectedSeqNo(), rcv.recvWindow.BufferedCount())
							return
						}
						if !bytes.Equal(got, want(p.id, i)) {
							errs <- fmt.Errorf("stream %d message %d: got %d bytes, want %d", p.id, i, len(got), len(want(p.id, i)))
							return
						}
					}
				}()
			}
			time.Sleep(30 * time.Millisecond)
			var key [32]byte
			key[0], key[31] = 0x14, 0x41
			switch mode {
			case "server-first":
				_ = server.SetSessionKey(key)
				time.Sleep(40 * time.Millisecond)
				_ = client.SetSessionKey(key)
			case "client-first":
				_ = client.SetSessionKey(key)
				time.Sleep(40 * time.Millisecond)
				_ = server.SetSessionKey(key)
			case "together-short":
				var kw sync.WaitGroup
				for _, s := range []*NoiseSession{client, server} {
					kw.Add(1)
					go func() { defer kw.Done(); _ = s.SetSessionKey(key) }()
				}
				kw.Wait()
			}
			done := make(chan struct{})
			go func() { wg.Wait(); close(done) }()
			select {
			case <-done:
			case err := <-errs:
				t.Fatal(err)
			case <-time.After(60 * time.Second):
				t.Fatal("the traffic did not finish in 60 s")
			}
			select {
			case err := <-errs:
				t.Fatal(err)
			default:
			}
		})
	}
}
