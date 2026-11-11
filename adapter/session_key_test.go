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
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/ORBTR/aether"
)

// TestNoiseSession_KeyingALiveSessionRacesNoFrameReadOrWrite: SetSessionKey on a
// session whose write loop, writers beside it (Ping) and read loop are running, as
// a mesh connection keys a session it has already started, installs the frame key
// with no frame path reading it half-written (run under -race), and of two
// concurrent installs exactly one takes effect.
func TestNoiseSession_KeyingALiveSessionRacesNoFrameReadOrWrite(t *testing.T) {
	client, server, _, _ := filteredPair(t, func(o *aether.SessionOptions) { o.SessionWarmupGrace = -1 })
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cs, ss := openWithCredit(t, ctx, client, server, 916, 0)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for _, s := range []*NoiseSession{client, server} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				pctx, pcancel := context.WithTimeout(ctx, 5*time.Millisecond)
				_, _ = s.Ping(pctx)
				pcancel()
				_ = s.SessionKey()
			}
		}()
	}
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if err := cs.Send(ctx, []byte("keyed while it runs")); err != nil {
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
	go func() {
		defer wg.Done()
		for {
			rctx, rcancel := context.WithTimeout(ctx, 20*time.Millisecond)
			_, err := ss.Receive(rctx)
			rcancel()
			select {
			case <-stop:
				return
			default:
			}
			if err != nil && rctx.Err() == nil {
				return
			}
		}
	}()

	time.Sleep(30 * time.Millisecond)
	var key [32]byte
	key[0] = 0x4b
	var installed atomic.Int32
	var keyers sync.WaitGroup
	for _, s := range []*NoiseSession{client, client, server, server} {
		keyers.Add(1)
		go func() {
			defer keyers.Done()
			if s.SetSessionKey(key) == nil {
				installed.Add(1)
			}
		}()
	}
	keyers.Wait()
	time.Sleep(30 * time.Millisecond)
	close(stop)
	wg.Wait()
	if got := installed.Load(); got != 2 {
		t.Fatalf("%d of four installs (two per session) took effect, want one per session", got)
	}
	if !bytes.Equal(client.SessionKey(), key[:]) || !bytes.Equal(server.SessionKey(), key[:]) {
		t.Fatal("a session does not report the key it was given")
	}
}

// readsEncryptedShort reports whether s's decoder reads past 0x87's first byte: a
// decoder that refuses the form answers aether.ErrFrameDiscriminator at that byte, one
// that reads it fails on the header the one-byte input lacks, before it touches any
// state the session's read loop shares.
func readsEncryptedShort(t *testing.T, s *NoiseSession) bool {
	t.Helper()
	_, _, _, err := aether.ReadNextFrame(bytes.NewReader([]byte{aether.ShortEncryptedIndicator}), s.rxCompressor)
	if err == nil {
		t.Fatal("a one-byte 0x87 decoded")
	}
	return !errors.Is(err, aether.ErrFrameDiscriminator)
}

// TestNoiseSession_ASessionKeySealsEveryFrameAndOpensTheEncryptedShortForm measures
// the wiring from SetSessionKey: before it the session's decoder refuses 0x87
// (aether.Compressor.AcceptEncryptedShort unset) and DATA travels unsealed; after
// it on both ends, DATA travels flagged FlagENCRYPTED and reaches the consumer as the
// plaintext, and a 0x87 frame sealed under the key over the header the receiver
// rebuilds reaches the consumer as its plaintext.
func TestNoiseSession_ASessionKeySealsEveryFrameAndOpensTheEncryptedShortForm(t *testing.T) {
	client, server, toServer, _ := filteredPair(t, func(o *aether.SessionOptions) { o.SessionWarmupGrace = -1 })
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	const id = 918
	cs, ss := openWithCredit(t, ctx, client, server, id, 0)
	var sealed, open atomic.Int32
	toServer.setRule(func(f *aether.Frame) bool {
		if f.StreamID == id && f.Type == aether.TypeDATA {
			if f.Flags.Has(aether.FlagENCRYPTED) {
				sealed.Add(1)
			} else {
				open.Add(1)
			}
		}
		return false
	})
	if !readsEncryptedShort(t, server) && !server.rxCompressor.ShortForms() {
		t.Fatal("premise: the session's grammar has no short forms")
	}
	if readsEncryptedShort(t, server) {
		t.Fatal("premise: the decoder reads 0x87 before any key is set")
	}
	if err := cs.Send(ctx, []byte("before the key")); err != nil {
		t.Fatalf("send: %v", err)
	}
	if r := <-receiveAsync(ctx, ss, 5*time.Second); r.err != nil || string(r.data) != "before the key" {
		t.Fatalf("before the key: read %q, %v", r.data, r.err)
	}
	if sealed.Load() != 0 || open.Load() == 0 {
		t.Fatalf("before the key: %d sealed and %d open DATA frames, want none sealed", sealed.Load(), open.Load())
	}

	var key [32]byte
	key[0] = 0x2f
	if err := client.SetSessionKey(key); err != nil {
		t.Fatalf("client key: %v", err)
	}
	if err := server.SetSessionKey(key); err != nil {
		t.Fatalf("server key: %v", err)
	}
	if !readsEncryptedShort(t, server) {
		t.Fatal("after SetSessionKey the decoder still refuses 0x87")
	}
	sealedBefore, openBefore := sealed.Load(), open.Load()
	if err := cs.Send(ctx, []byte("after the key")); err != nil {
		t.Fatalf("send: %v", err)
	}
	if r := <-receiveAsync(ctx, ss, 5*time.Second); r.err != nil || string(r.data) != "after the key" {
		t.Fatalf("after the key: read %q, %v", r.data, r.err)
	}
	if sealed.Load() == sealedBefore || open.Load() != openBefore {
		t.Fatalf("after the key: %d sealed and %d open DATA frames written, want only sealed ones",
			sealed.Load()-sealedBefore, open.Load()-openBefore)
	}

	// A 0x87 frame as the decoder hands it on: the envelope [Nonce][Ciphertext][Tag]
	// sealed over the header the receiver rebuilds (Flags 0, AckNo 0, Length the
	// ciphertext plus tag).
	plain := []byte("an encrypted short frame")
	seq := ss.recvWindow.ExpectedSeqNo()
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	nonce[11] = 0x87
	rebuilt := &aether.Frame{
		SenderID: client.LocalPeerID(), ReceiverID: server.LocalPeerID(),
		StreamID: id, Type: aether.TypeDATA, SeqNo: seq,
		Length: uint32(len(plain) + aead.Overhead()),
	}
	envelope := append(append([]byte{}, nonce...), aead.Seal(nil, nonce, plain, rebuilt.HeaderBytes())...)
	server.processIncomingFrame(&aether.Frame{
		SenderID: client.LocalPeerID(), ReceiverID: server.LocalPeerID(),
		StreamID: id, Type: aether.TypeDATA, SeqNo: seq,
		Length: uint32(len(envelope)), Payload: envelope,
	}, aether.ShortEncryptedIndicator)
	if r := <-receiveAsync(ctx, ss, 5*time.Second); r.err != nil || !bytes.Equal(r.data, plain) {
		t.Fatalf("0x87 under the key: read %q, %v", r.data, r.err)
	}
}

// TestNoiseSession_OfConcurrentKeyInstallsExactlyOneTakesEffect: installs that race
// each other on one session, started together, leave exactly one key in place and
// every other install refused, round after round.
func TestNoiseSession_OfConcurrentKeyInstallsExactlyOneTakesEffect(t *testing.T) {
	for round := 0; round < 300; round++ {
		s := &NoiseSession{rxCompressor: aether.NewCompressor()}
		start := make(chan struct{})
		var installed atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				var key [32]byte
				key[0] = byte(i + 1)
				<-start
				if s.SetSessionKey(key) == nil {
					installed.Add(1)
				}
			}(i)
		}
		close(start)
		wg.Wait()
		if got := installed.Load(); got != 1 {
			t.Fatalf("round %d: %d of eight racing installs took effect, want one", round, got)
		}
	}
}
