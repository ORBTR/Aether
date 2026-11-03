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
	"testing"
	"time"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/flow"
)

// TestNoiseStream_OpenCarriesTheOpenersCredit: for an initial credit under,
// at and over the default, the accepting side's window, its credit reservation
// and its queue bound for the stream are the credit the opener reserved, and
// the opener's own window is the same credit, so both ends of the stream start
// at one credit.
func TestNoiseStream_OpenCarriesTheOpenersCredit(t *testing.T) {
	for i, credit := range []int64{64 * 1024, 0, 2 << 20} {
		t.Run(fmt.Sprintf("credit=%d", credit), func(t *testing.T) {
			client, server := noisePairWithRealms(t, nil, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			want := credit
			if want == 0 {
				want = flow.DefaultStreamCredit
			}
			cs, ss := openWithCredit(t, ctx, client, server, uint64(150+i), credit)
			if got := cs.window.CurrentWindow(); got != want {
				t.Fatalf("premise: the opener's window is %d, want %d", got, want)
			}
			if got := ss.window.CurrentWindow(); got != want {
				t.Errorf("the accepted stream's window is %d, want the opener's credit %d", got, want)
			}
			if got := ss.reserved.Load(); got != want {
				t.Errorf("the accepted stream reserved %d, want the opener's credit %d", got, want)
			}
			if limit, _ := ss.receiveCeilings(); limit != want {
				t.Errorf("the accepted stream's queue bound is %d, want the opener's credit %d", limit, want)
			}
			if limit, _ := cs.receiveCeilings(); limit != want {
				t.Errorf("the opener's queue bound is %d, want its credit %d", limit, want)
			}
		})
	}
}

// TestNoiseStream_TheCreditReadFromOpenBoundsTheQueue: a stream opened with
// 64 KiB of credit, far under the connection window's initial credit, admits
// to its queue exactly what that credit covers. An honest sender filling it
// with no reader is acknowledged and keeps the stream open, and its reader
// gets every message; a sender queueing past it is refused and the stream is
// reset, at the stream's credit and not at the connection's.
func TestNoiseStream_TheCreditReadFromOpenBoundsTheQueue(t *testing.T) {
	const credit = 64 * 1024
	t.Run("honest", func(t *testing.T) {
		client, server := noisePairWithRealms(t, nil, nil)
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		cs, ss := openWithCredit(t, ctx, client, server, 160, credit)
		msg := make([]byte, 1024)
		n := int(credit / messageCredit(int64(len(msg))))
		for i := 0; i < n; i++ {
			if err := cs.Send(ctx, msg); err != nil {
				t.Fatalf("send %d of %d inside the credit: %v", i+1, n, err)
			}
		}
		waitSendWindowEmpty(t, cs, "the burst acknowledged")
		time.Sleep(200 * time.Millisecond)
		if !ss.IsOpen() || !cs.IsOpen() {
			t.Fatalf("an honest sender inside its %d of credit was reset", credit)
		}
		for i := 0; i < n; i++ {
			if got, err := ss.Receive(ctx); err != nil || len(got) != len(msg) {
				t.Fatalf("receive %d of %d: %d bytes, %v", i+1, n, len(got), err)
			}
		}
	})
	t.Run("past the credit", func(t *testing.T) {
		client, server := noisePairWithRealms(t, nil, nil)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, ss := openWithCredit(t, ctx, client, server, 161, credit)
		initial, _ := server.connWindow.ReceiveCeilings()
		if initial <= credit {
			t.Fatalf("premise: the connection's initial credit %d is not above the stream's %d", initial, credit)
		}
		const size = 1000
		n := int(credit / messageCredit(size))
		for i := 0; i < n; i++ {
			if !ss.enqueueDelivery(make([]byte, size)) {
				t.Fatalf("message %d of %d inside the stream's credit refused", i+1, n)
			}
		}
		if ss.enqueueDelivery(make([]byte, size)) {
			t.Fatalf("a message past the %d the OPEN stated was queued", credit)
		}
		if ss.IsOpen() {
			t.Fatalf("the stream stayed open after its sender went past the credit")
		}
	})
}

// TestNoiseSession_RefusesAnOpenWhoseCreditItCannotHold: an OPEN stating no
// credit, less than flow.MinGuaranteedWindow, or more than the stream ceiling
// builds no stream, reaches no acceptor and is counted as a refusal; the same
// OPEN with a credit inside the bounds is admitted, and a second OPEN for that
// live stream changes nothing and is not handed to the acceptor again.
func TestNoiseSession_RefusesAnOpenWhoseCreditItCannotHold(t *testing.T) {
	_, server := noisePairWithRealms(t, nil, nil)
	open := func(id uint64, credit uint32) *aether.Frame {
		p := aether.EncodeOpenPayload(aether.OpenPayload{Reliability: aether.ReliableOrdered, Priority: 128, InitialCredit: credit})
		return &aether.Frame{StreamID: id, Type: aether.TypeOPEN, Length: uint32(len(p)), Payload: p}
	}
	for i, credit := range []uint32{0, uint32(flow.MinGuaranteedWindow - 1), uint32(flow.MaxGrowableWindow + 1)} {
		id := uint64(170 + i)
		before := server.StreamRefusedCount()
		server.handleOpen(open(id, credit))
		if streamPresent(server, id) {
			t.Fatalf("an OPEN stating %d of credit built a stream", credit)
		}
		if got := server.StreamRefusedCount(); got != before+1 {
			t.Fatalf("an OPEN stating %d of credit: refusals %d, want %d", credit, got, before+1)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	if st, err := server.AcceptStream(ctx); err == nil {
		t.Fatalf("a refused OPEN reached the acceptor as stream %d", st.StreamID())
	}
	cancel()

	server.handleOpen(open(180, uint32(flow.MinGuaranteedWindow)))
	if !streamPresent(server, 180) {
		t.Fatalf("an OPEN stating the minimum credit was not admitted")
	}
	server.mu.Lock()
	st := server.streams[180]
	server.mu.Unlock()
	server.handleOpen(open(180, uint32(flow.DefaultStreamCredit)))
	if got := st.window.CurrentWindow(); got != flow.MinGuaranteedWindow {
		t.Fatalf("a second OPEN for a live stream changed its window to %d", got)
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := server.AcceptStream(ctx); err != nil {
		t.Fatalf("the admitted stream did not reach the acceptor: %v", err)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel2()
	if again, err := server.AcceptStream(ctx2); err == nil {
		t.Fatalf("a second OPEN handed stream %d to the acceptor again", again.StreamID())
	}
}

// TestNoiseSession_OpenStreamRefusesACreditOpenCannotState: an initial credit
// above aether.MaxOpenCredit, with a stream ceiling that would allow it, is
// refused with ErrStreamCreditRefused before the stream exists.
func TestNoiseSession_OpenStreamRefusesACreditOpenCannotState(t *testing.T) {
	client, _ := noisePairWithRealms(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := client.OpenStream(ctx, aether.StreamConfig{
		StreamID:      190,
		Reliability:   aether.ReliableOrdered,
		InitialCredit: aether.MaxOpenCredit + 1,
		MaxCredit:     aether.MaxOpenCredit + 2,
	})
	if st != nil || !errors.Is(err, aether.ErrStreamCreditRefused) {
		t.Fatalf("OpenStream = %v, %v; want ErrStreamCreditRefused", st, err)
	}
	if streamPresent(client, 190) {
		t.Fatalf("the refused stream is in the session")
	}
}

// TestTCPSession_RefusesAPeerOfferingOnlyTheEarlierFrameGrammar: a peer whose
// preface lists only the frame grammar before this build's closes the session
// with a *aether.WireVersionMismatchError naming the frame entry, OpenStream
// returns it, no stream exists, and the session writes nothing after its
// preface.
func TestTCPSession_RefusesAPeerOfferingOnlyTheEarlierFrameGrammar(t *testing.T) {
	sess, peer := rawPeer(t, aether.DefaultSessionOptions())
	_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	local, err := aether.ReadWireVersionsPreface(peer)
	if err != nil {
		t.Fatalf("read the session's preface: %v", err)
	}
	offer := make(aether.WireVersions, len(local))
	for i, e := range local {
		offer[i] = e
		if e.Name == aether.WireVersionFrame {
			offer[i].Versions = []uint16{aether.WireVersionFrameCurrent - 1}
		}
	}
	if err := aether.WriteWireVersionsPreface(peer, offer); err != nil {
		t.Fatalf("write the earlier offer: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	st, err := sess.OpenStream(ctx, aether.DefaultStreamConfig(10))
	if st != nil {
		t.Fatalf("OpenStream returned a stream to a peer of the earlier grammar")
	}
	var mm *aether.WireVersionMismatchError
	if !errors.As(err, &mm) || mm.Name != aether.WireVersionFrame {
		t.Fatalf("OpenStream err = %v, want a mismatch naming %q", err, aether.WireVersionFrame)
	}
	waitClosed(t, sess)
	if err := waitCloseErr(sess); !errors.Is(err, aether.ErrWireVersionMismatch) {
		t.Fatalf("close reason %v, want ErrWireVersionMismatch", err)
	}
	if n := sess.Metrics().ActiveStreams; n != 0 {
		t.Fatalf("the session holds %d streams after the refusal", n)
	}
	if got := sess.WireVersions(); len(got.Entries()) != 0 {
		t.Fatalf("the session reports set %v after the refusal", got)
	}
	var b [1]byte
	if n, err := peer.Read(b[:]); n != 0 || (err != io.EOF && !errors.Is(err, io.ErrClosedPipe)) {
		t.Fatalf("after its preface the session wrote %d bytes (%v)", n, err)
	}
}
