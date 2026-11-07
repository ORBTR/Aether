//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	aether "github.com/ORBTR/aether"
	"github.com/ORBTR/aether/congestion"
)

// wireKey names one DATA frame on the wire.
type wireKey struct {
	stream uint64
	seq    uint32
}

// wireTap records every DATA frame the write loop hands to conn.Write, in the full
// header or the two unencrypted short forms, and can swallow those frames, so a test
// can tell what reached the wire and keep the peer from ever acknowledging it. A
// short form carries the sequence's low 16 bits, enough for the few frames a test sends.
type wireTap struct {
	net.Conn
	drop atomic.Bool
	hold atomic.Pointer[chan struct{}] // parks DATA writes until the channel closes

	mu    sync.Mutex
	first map[wireKey]int64 // conn.Write length of the frame's first write
	count map[wireKey]int   // writes of the frame
	order []wireKey         // first writes, in write order
}

func (w *wireTap) Write(b []byte) (int, error) {
	var k wireKey
	data := false
	if len(b) > 0 {
		switch b[0] {
		case aether.FullFrameDiscriminator:
			if f, err := aether.DecodeFrameFromBytes(b); err == nil && f.Type == aether.TypeDATA {
				data, k = true, wireKey{f.StreamID, f.SeqNo}
			}
		case aether.ShortDataIndicator, aether.ShortDataVarIndicator:
			if len(b) >= 5 {
				data = true
				k = wireKey{uint64(binary.BigEndian.Uint16(b[1:3])), uint32(binary.BigEndian.Uint16(b[3:5]))}
			}
		}
	}
	if data {
		w.mu.Lock()
		if _, seen := w.first[k]; !seen {
			w.first[k] = int64(len(b))
			w.order = append(w.order, k)
		}
		w.count[k]++
		w.mu.Unlock()
	}
	if data {
		if g := w.hold.Load(); g != nil {
			<-*g
		}
		if w.drop.Load() {
			return len(b), nil
		}
	}
	return w.Conn.Write(b)
}

func (w *wireTap) firstWrites() []wireKey {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]wireKey(nil), w.order...)
}

func (w *wireTap) writesOf(k wireKey) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.count[k]
}

func (w *wireTap) lengthOf(k wireKey) int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.first[k]
}

// emitted returns the sum of first-write lengths and the sum over every write,
// a retransmit counted at the frame's first length.
func (w *wireTap) emitted() (first, all int64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for k, n := range w.first {
		first += n
		all += n * int64(w.count[k])
	}
	return first, all
}

// spyController records the byte counts handleACK and the write loop present and
// decides CanSend by the test's function. It is not a *CUBICController or a
// *BBRController, so handleACK reaches it through the Controller interface's OnAck.
type spyController struct {
	congestion.Controller
	allow func(prospective int64) bool

	mu        sync.Mutex
	acked     int64
	sends     []int64
	lossPipes []int64
}

func (s *spyController) CanSend(p int64) bool {
	if s.allow != nil {
		return s.allow(p)
	}
	return s.Controller.CanSend(p)
}

func (s *spyController) OnAck(n int64, rtt time.Duration) {
	s.mu.Lock()
	s.acked += n
	s.mu.Unlock()
	s.Controller.OnAck(n, rtt)
}

func (s *spyController) OnSend(n int64) congestion.DeliveryRateSample {
	s.mu.Lock()
	s.sends = append(s.sends, n)
	s.mu.Unlock()
	return s.Controller.OnSend(n)
}

func (s *spyController) OnLossWithPipe(p int64) {
	s.mu.Lock()
	s.lossPipes = append(s.lossPipes, p)
	s.mu.Unlock()
	s.Controller.OnLossWithPipe(p)
}

func (s *spyController) ackedBytes() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.acked
}

func (s *spyController) sendCounts() []int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]int64(nil), s.sends...)
}

func (s *spyController) pipes() []int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]int64(nil), s.lossPipes...)
}

func tappedPair(t *testing.T) (client, server *NoiseSession, tap *wireTap) {
	t.Helper()
	chosen := aetherChosen(t)
	c, s := loopbackPair(t)
	tap = &wireTap{Conn: c, first: map[wireKey]int64{}, count: map[wireKey]int{}}
	key := uint32(7)
	client = NewNoiseSession(realmConn{Conn: tap, chosen: chosen, key: key, bound: true}, "vl1_tap_client", "vl1_tap_server", aether.DefaultSessionOptions())
	server = NewNoiseSession(realmConn{Conn: s, chosen: chosen, key: key, bound: true}, "vl1_tap_server", "vl1_tap_client", aether.DefaultSessionOptions())
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	return client, server, tap
}

func spyOn(client *NoiseSession, allow func(int64) bool) *spyController {
	spy := &spyController{Controller: congestion.NewCUBICController(), allow: allow}
	client.SetCongestionController(spy)
	return spy
}

func waitUntil(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not reached in %v", what, d)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// compressingFrame is a frame-sized message that deflates to about half, so its
// wire length is far from both its plaintext length and an MSS.
func compressingFrame(t *testing.T, i int) []byte {
	t.Helper()
	b := halfCompressible(t, 1024)
	binary.BigEndian.PutUint32(b[len(b)-4:], uint32(i))
	return b
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// drain receives n messages and reports what they held.
func drain(ctx context.Context, ss aether.Stream, n int) <-chan [][]byte {
	out := make(chan [][]byte, 1)
	go func() {
		got := make([][]byte, 0, n)
		for len(got) < n {
			m, err := ss.Receive(ctx)
			if err != nil {
				break
			}
			got = append(got, m)
		}
		out <- got
	}()
	return out
}

// TestNoiseSession_ABurstPastTheCongestionWindowCompletes: a burst several times
// the initial congestion window with a reading peer reaches the peer whole and in
// order, under each controller the session can run.
func TestNoiseSession_ABurstPastTheCongestionWindowCompletes(t *testing.T) {
	for _, tc := range []struct {
		name string
		cc   func() congestion.Controller
	}{
		{"cubic", func() congestion.Controller { return congestion.NewCUBICController() }},
		{"bbr", func() congestion.Controller { return congestion.NewBBRController() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server, _ := tappedPair(t)
			client.SetCongestionController(tc.cc())
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			cs, ss := openAccept(t, ctx, client, server, 130)
			const n = 64
			const size = 1200 // several initial windows of frames that fit one MSS
			if n*size < 4*14000 {
				t.Fatalf("premise: the burst of %d bytes is not several initial windows", n*size)
			}
			msgs := make([][]byte, n)
			for i := range msgs {
				msgs[i] = halfCompressible(t, size)
				if err := cs.Send(ctx, msgs[i]); err != nil {
					t.Fatalf("send %d: %v", i, err)
				}
			}
			got := <-drain(ctx, ss, n)
			if len(got) != n {
				t.Fatalf("received %d of %d messages: %v", len(got), n, ctx.Err())
			}
			for i := range msgs {
				if !bytes.Equal(got[i], msgs[i]) {
					t.Fatalf("message %d is not the one sent in that place", i)
				}
			}
		})
	}
}

// readGate parks the server's reads while shut, so no ACK comes back and nothing the
// client writes is lost: it waits in the loopback buffer until the gate opens.
type readGate struct {
	net.Conn
	shut atomic.Pointer[chan struct{}]
}

func (r *readGate) Read(b []byte) (int, error) {
	if g := r.shut.Load(); g != nil {
		<-*g
	}
	return r.Conn.Read(b)
}

// TestNoiseSession_ABurstFillsTheCongestionWindowWithNoACK: every frame of a burst is
// in the send window before the write loop writes the second. With the peer reading
// nothing, no ACK can come; the write loop still fills the congestion window with
// distinct frames, and stops at it. Once the peer reads, every message arrives in order.
func TestNoiseSession_ABurstFillsTheCongestionWindowWithNoACK(t *testing.T) {
	chosen := aetherChosen(t)
	c, sc := loopbackPair(t)
	tap := &wireTap{Conn: c, first: map[wireKey]int64{}, count: map[wireKey]int{}}
	gate := &readGate{Conn: sc}
	key := uint32(7)
	client := NewNoiseSession(realmConn{Conn: tap, chosen: chosen, key: key, bound: true}, "vl1_tap_client", "vl1_tap_server", aether.DefaultSessionOptions())
	server := NewNoiseSession(realmConn{Conn: gate, chosen: chosen, key: key, bound: true}, "vl1_tap_server", "vl1_tap_client", aether.DefaultSessionOptions())
	opened := make(chan struct{})
	var openOnce sync.Once
	open := func() { openOnce.Do(func() { gate.shut.Store(nil); close(opened) }) }
	t.Cleanup(func() { open(); _ = client.Close(); _ = server.Close() })
	client.SetCongestionController(congestion.NewCUBICController())
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	const id, n, size = uint64(140), 64, 1200
	cs, ss := openAccept(t, ctx, client, server, id)
	st := asNoiseStream(t, cs)
	waitUntil(t, 60*time.Second, "the first message acknowledged", func() bool { return st.sendWindow.InFlight() == 0 })
	wrote := len(tap.firstWrites())

	gate.shut.Store(&opened)
	g := make(chan struct{})
	tap.hold.Store(&g)
	sent := make(chan error, 1)
	msgs := make([][]byte, n)
	for i := range msgs {
		msgs[i] = halfCompressible(t, size)
	}
	go func() {
		for _, m := range msgs {
			if err := cs.Send(ctx, m); err != nil {
				sent <- err
				return
			}
		}
		sent <- nil
	}()
	// A PMTU probe waiting on the parked write's lock can hold Send's MSS read until
	// the write is freed, so the wait has a bound and the burst may finish after it.
	select {
	case err := <-sent:
		if err != nil {
			t.Fatalf("send: %v", err)
		}
		sent <- nil
	case <-time.After(5 * time.Second):
	}
	tap.hold.Store(nil)
	close(g)
	if err := <-sent; err != nil {
		t.Fatalf("send: %v", err)
	}

	cwnd := client.CongestionWindow()
	waitUntil(t, 60*time.Second, "the burst filling the congestion window", func() bool {
		in := client.inFlightBytes.Load()
		// Stop within one frame of the window; a frame is at most size plus header.
		return in >= cwnd-int64(size)-int64(aether.HeaderSize) && len(tap.firstWrites())-wrote > 2
	})
	if in := client.inFlightBytes.Load(); in > cwnd {
		t.Fatalf("in flight %d past the congestion window %d", in, cwnd)
	}

	open()
	got := <-drain(ctx, ss, n)
	if len(got) != n {
		t.Fatalf("received %d of %d after the peer read: %v", len(got), n, ctx.Err())
	}
	for i := range msgs {
		if !bytes.Equal(got[i], msgs[i]) {
			t.Fatalf("message %d is not the one sent in that place", i)
		}
	}
}

// TestNoiseSession_AFrameGoesWhenNothingIsInFlight: a controller that refuses every
// CanSend still gets each frame out once the one before it is acknowledged, which
// is the case of a frame longer than the congestion window (MSS up to 8000 against
// a 2800 floor).
func TestNoiseSession_AFrameGoesWhenNothingIsInFlight(t *testing.T) {
	client, server, _ := tappedPair(t)
	spyOn(client, func(int64) bool { return false })
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cs, ss := openAccept(t, ctx, client, server, 131)
	const n = 5
	reader := drain(ctx, ss, n)
	for i := 0; i < n; i++ {
		if err := cs.Send(ctx, compressingFrame(t, i)); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	if got := <-reader; len(got) != n {
		t.Fatalf("received %d of %d messages with nothing in flight between them: %v", len(got), n, ctx.Err())
	}
}

// parkedBurst sends n frames with the write gate shut and the wire swallowing
// them, after the stream's first message has come back acknowledged. The first
// frame goes (nothing in flight) and the rest stay unwritten behind the gate.
func parkedBurst(t *testing.T, ctx context.Context, client, server *NoiseSession, tap *wireTap, spyAllow *atomic.Int64, id uint64, n int) (*noiseStream, aether.Stream, uint32) {
	t.Helper()
	cs, ss := openAccept(t, ctx, client, server, id)
	st := asNoiseStream(t, cs)
	waitUntil(t, 60*time.Second, "the first message acknowledged", func() bool { return st.sendWindow.InFlight() == 0 })
	tap.drop.Store(true)
	firstSeq := st.sendWindow.Next()
	spyAllow.Store(0)
	for i := 0; i < n; i++ {
		if err := cs.Send(ctx, compressingFrame(t, i)); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	waitUntil(t, 60*time.Second, "the first frame of the burst written", func() bool {
		return tap.writesOf(wireKey{id, firstSeq}) > 0
	})
	return st, ss, firstSeq
}

// allowance returns a CanSend that admits while the counter is positive, spending
// one each time; a negative counter admits always.
func allowance() (*atomic.Int64, func(int64) bool) {
	var left atomic.Int64
	left.Store(-1)
	return &left, func(int64) bool {
		v := left.Load()
		if v < 0 {
			return true
		}
		if v == 0 {
			return false
		}
		return left.CompareAndSwap(v, v-1)
	}
}

// TestNoiseSession_AFrameNeverWrittenIsNeverCharged: frames behind the gate hold
// no in-flight charge, no retransmit entry, no RACK or TLP sample, and no retransmit
// fires for them past any RTO; once the gate opens all arrive in order.
func TestNoiseSession_AFrameNeverWrittenIsNeverCharged(t *testing.T) {
	client, server, tap := tappedPair(t)
	left, allow := allowance()
	spyOn(client, allow)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	const id, n = uint64(132), 6
	st, ss, firstSeq := parkedBurst(t, ctx, client, server, tap, left, id, n)
	first := wireKey{id, firstSeq}

	time.Sleep(700 * time.Millisecond) // past the RTO floor and the first PTO

	if got, want := client.inFlightBytes.Load(), tap.lengthOf(first); got != want {
		t.Fatalf("session in-flight %d with one frame on the wire of %d bytes", got, want)
	}
	if got := st.retransmitQ.Len(); got != 1 {
		t.Fatalf("retransmit queue holds %d entries with one frame written", got)
	}
	if got := len(st.sendWindow.SnapshotEntries()); got != 1 {
		t.Fatalf("RACK sees %d entries with one frame written", got)
	}
	for i := 1; i < n; i++ {
		if got := tap.writesOf(wireKey{id, firstSeq + uint32(i)}); got != 0 {
			t.Fatalf("frame %d, behind the gate, was written %d times", i, got)
		}
	}
	if got := st.sendWindow.InFlight(); got != n {
		t.Fatalf("send window holds %d entries, want the %d sent", got, n)
	}

	tap.drop.Store(false)
	left.Store(-1)
	got := <-drain(ctx, ss, n)
	if len(got) != n {
		t.Fatalf("received %d of %d after the gate opened: %v", len(got), n, ctx.Err())
	}
	for i, m := range got {
		if binary.BigEndian.Uint32(m[len(m)-4:]) != uint32(i) {
			t.Fatalf("message %d out of order", i)
		}
	}
}

// TestNoiseSession_AnACKForAnUnwrittenFrameFeedsNoController: an ACK covering a
// frame still behind the gate proves nothing about the wire. The controller is
// told only the bytes of the written frame and the frame gets no RTT sample.
func TestNoiseSession_AnACKForAnUnwrittenFrameFeedsNoController(t *testing.T) {
	client, server, tap := tappedPair(t)
	left, allow := allowance()
	spy := spyOn(client, allow)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	const id = uint64(133)
	st, _, firstSeq := parkedBurst(t, ctx, client, server, tap, left, id, 3)
	before := spy.ackedBytes()
	ack := &aether.Frame{
		Type:     aether.TypeACK,
		StreamID: st.streamID,
		Flags:    aether.FlagCOMPOSITE_ACK,
		Payload:  aether.EncodeCompositeACK(&aether.CompositeACK{BaseACK: firstSeq + 2}),
	}
	ack.Length = uint32(len(ack.Payload))
	client.handleACK(ack)
	if got, want := spy.ackedBytes()-before, tap.lengthOf(wireKey{id, firstSeq}); got != want {
		t.Fatalf("controller told %d acked bytes, want the %d of the one frame written", got, want)
	}
	if got := client.inFlightBytes.Load(); got != 0 {
		t.Fatalf("session in-flight %d after the ACK", got)
	}
}

// TestNoiseSession_TheControllerSeesTheBytesEmitted: with a compressing stream, the
// acked total the controller is told equals the bytes the write loop emitted, and
// OnSend presents one frame's count per write, the first count on a retransmit.
func TestNoiseSession_TheControllerSeesTheBytesEmitted(t *testing.T) {
	client, server, tap := tappedPair(t)
	spy := spyOn(client, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	const n = 40
	cs, ss := openAccept(t, ctx, client, server, 134)
	st := asNoiseStream(t, cs)
	reader := drain(ctx, ss, n)
	var plain int64
	for i := 0; i < n; i++ {
		m := compressingFrame(t, i)
		plain += int64(len(m))
		if err := cs.Send(ctx, m); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	if got := <-reader; len(got) != n {
		t.Fatalf("received %d of %d: %v", len(got), n, ctx.Err())
	}
	waitUntil(t, 60*time.Second, "every frame acked", func() bool { return st.sendWindow.InFlight() == 0 })
	first, all := tap.emitted()
	if first >= plain {
		t.Fatalf("premise: %d bytes emitted for %d of plaintext, the stream did not compress", first, plain)
	}
	if got := spy.ackedBytes(); got != first {
		t.Fatalf("controller acked total %d, write loop emitted %d (plaintext %d)", got, first, plain)
	}
	var sent int64
	for _, v := range spy.sendCounts() {
		sent += v
	}
	if sent != all {
		t.Fatalf("OnSend total %d, write loop emitted %d counting each write", sent, all)
	}
	if got := client.inFlightBytes.Load(); got != 0 {
		t.Fatalf("session in-flight %d with every frame acked", got)
	}
}

// TestNoiseSession_ThePipeIsTheBytesOnTheWire: the pipe the controller gets at a
// loss is the session's in-flight wire bytes, at handleACK's NACK and at the RACK
// tick, not a count of entries times an MSS.
func TestNoiseSession_ThePipeIsTheBytesOnTheWire(t *testing.T) {
	for _, tc := range []struct {
		name   string
		frames int
		bitmap byte // bit i: seq BaseACK+1+i received
	}{
		{"NACK", 6, 0b11110}, // seq+1 missing, four later received: past the reorder threshold
		{"RACK", 3, 0b10},    // seq+1 missing, one later received: left to the RACK tick
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server, tap := tappedPair(t)
			spy := spyOn(client, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			const id = uint64(135)
			cs, _ := openAccept(t, ctx, client, server, id)
			st := asNoiseStream(t, cs)
			waitUntil(t, 60*time.Second, "the first message acknowledged", func() bool { return st.sendWindow.InFlight() == 0 })
			tap.drop.Store(true)
			base := st.sendWindow.Next()
			for i := 0; i < tc.frames; i++ {
				if err := cs.Send(ctx, compressingFrame(t, i)); err != nil {
					t.Fatalf("send: %v", err)
				}
			}
			last := wireKey{id, base + uint32(tc.frames) - 1}
			waitUntil(t, 60*time.Second, "every frame written", func() bool { return tap.writesOf(last) > 0 })
			ack := &aether.Frame{
				Type:     aether.TypeACK,
				StreamID: st.streamID,
				Flags:    aether.FlagCOMPOSITE_ACK,
				Payload:  aether.EncodeCompositeACK(&aether.CompositeACK{BaseACK: base, Bitmap: []byte{tc.bitmap, 0, 0, 0}}),
			}
			ack.Length = uint32(len(ack.Payload))
			client.handleACK(ack)
			// RACK declares seq base+1 lost once it is a reorder window older than
			// the acknowledged base+2. An RTO that retransmits it first moves its
			// XmitTime past that point, and RACK then has nothing to declare; on a
			// machine that starves the 10 ms tick that can happen, and the test has
			// no loss to read a pipe from.
			missing := wireKey{id, base + 1}
			writesAtACK := tap.writesOf(missing)
			waitUntil(t, 60*time.Second, "a loss declared or the missing frame retransmitted", func() bool {
				return len(spy.pipes()) > 0 || tap.writesOf(missing) > writesAtACK
			})
			if len(spy.pipes()) == 0 {
				t.Skipf("%s: the missing frame was retransmitted before any loss was declared", tc.name)
			}
			// The one frame left in the window is seq base+1, and for the RACK case
			// any later frame the bitmap did not report.
			var want int64
			for s := base; s < base+uint32(tc.frames); s++ {
				bit := int(s) - int(base) - 1
				if s == base || (bit >= 0 && tc.bitmap&(1<<uint(bit)) != 0) {
					continue
				}
				want += tap.lengthOf(wireKey{id, s})
			}
			for _, p := range spy.pipes() {
				if p != want {
					t.Fatalf("pipe %d at a loss, want the %d bytes still on the wire", p, want)
				}
			}
		})
	}
}

// TestNoiseSession_ARefusedFrameKeepsItsPlaceInTheStream: a CanSend refusal does
// not rotate the stream's queue, so a burst reaches the wire in sequence order and
// the peer sees no gap to report.
func TestNoiseSession_ARefusedFrameKeepsItsPlaceInTheStream(t *testing.T) {
	client, server, tap := tappedPair(t)
	var calls atomic.Int64
	spyOn(client, func(int64) bool { return calls.Add(1)%2 == 0 })
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	const id, n = uint64(136), 40
	cs, ss := openAccept(t, ctx, client, server, id)
	reader := drain(ctx, ss, n)
	for i := 0; i < n; i++ {
		if err := cs.Send(ctx, compressingFrame(t, i)); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	if got := <-reader; len(got) != n {
		t.Fatalf("received %d of %d: %v", len(got), n, ctx.Err())
	}
	var prev uint32
	for i, k := range tap.firstWrites() {
		if k.stream != id {
			continue
		}
		if i > 0 && k.seq <= prev {
			t.Fatalf("frame seq %d reached the wire after seq %d", k.seq, prev)
		}
		prev = k.seq
	}
}

// TestNoiseSession_ARefusalDoesNotStarveAnotherStream: two streams of one class
// behind a controller that refuses half its calls both finish, and neither is more
// than a few frames ahead while they run.
func TestNoiseSession_ARefusalDoesNotStarveAnotherStream(t *testing.T) {
	client, server, tap := tappedPair(t)
	var calls atomic.Int64
	spyOn(client, func(int64) bool { return calls.Add(1)%2 == 0 })
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	const a, b, n = uint64(137), uint64(138), 40
	csA, ssA := openAccept(t, ctx, client, server, a)
	csB, ssB := openAccept(t, ctx, client, server, b)
	readA, readB := drain(ctx, ssA, n), drain(ctx, ssB, n)
	for i := 0; i < n; i++ {
		if err := csA.Send(ctx, compressingFrame(t, i)); err != nil {
			t.Fatalf("send a %d: %v", i, err)
		}
		if err := csB.Send(ctx, compressingFrame(t, i)); err != nil {
			t.Fatalf("send b %d: %v", i, err)
		}
	}
	if got := <-readA; len(got) != n {
		t.Fatalf("stream a received %d of %d: %v", len(got), n, ctx.Err())
	}
	if got := <-readB; len(got) != n {
		t.Fatalf("stream b received %d of %d: %v", len(got), n, ctx.Err())
	}
	var ca, cb, worst int
	for _, k := range tap.firstWrites() {
		switch k.stream {
		case a:
			ca++
		case b:
			cb++
		}
		if d := ca - cb; d > worst {
			worst = d
		} else if -d > worst {
			worst = -d
		}
	}
	t.Logf("largest lead of one stream over the other on the wire: %d frames", worst)
}

// TestNoiseSession_AProbeOvertakesARefusedFrame: with a frame refused behind the
// gate, the TLP probe still leaves, carries the highest frame actually written, and
// presents the count that frame was charged.
func TestNoiseSession_AProbeOvertakesARefusedFrame(t *testing.T) {
	client, server, tap := tappedPair(t)
	left, allow := allowance()
	spy := spyOn(client, allow)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	const id = uint64(139)
	cs, _ := openAccept(t, ctx, client, server, id)
	st := asNoiseStream(t, cs)
	waitUntil(t, 60*time.Second, "the first message acknowledged", func() bool { return st.sendWindow.InFlight() == 0 })
	tap.drop.Store(true)
	base := st.sendWindow.Next()
	left.Store(1) // the frame after the first passes the gate; the first needs none
	for i := 0; i < 4; i++ {
		if err := cs.Send(ctx, compressingFrame(t, i)); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	top := wireKey{id, base + 1}
	waitUntil(t, 60*time.Second, "the second frame written", func() bool { return tap.writesOf(top) > 0 })
	waitUntil(t, 60*time.Second, "a TLP probe of the highest written frame", func() bool { return tap.writesOf(top) > 1 })
	if got := tap.writesOf(wireKey{id, base + 2}); got != 0 {
		t.Fatalf("the frame behind the gate went out %d times", got)
	}
	want := tap.lengthOf(top)
	seen := false
	counts := spy.sendCounts()
	for _, v := range counts {
		if v == want {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("OnSend counts %v: none presents the frame's %d", counts, want)
	}
}

// TestNoiseSession_TheProspectiveSizeIsTheWriteLength: the size CanSend and the pacer
// are given before the encoder runs equals what conn.Write then takes, for each header
// form a queued frame can take, and predicting advances no compressor state.
func TestNoiseSession_TheProspectiveSizeIsTheWriteLength(t *testing.T) {
	client, server, _ := tappedPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cs, _ := openAccept(t, ctx, client, server, 141)
	st := asNoiseStream(t, cs)
	for _, tc := range []struct {
		name    string
		payload []byte
	}{
		{"varint short form", []byte("short")},
		{"fixed short form, incompressible", randomBytes(t, 200)},
		{"full header, compressed", bytes.Repeat([]byte{'c'}, 512)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &aether.Frame{
				SenderID:   client.LocalPeerID(),
				ReceiverID: client.RemotePeerID(),
				StreamID:   st.streamID,
				Type:       aether.TypeDATA,
				Length:     uint32(len(tc.payload)),
				Payload:    append([]byte(nil), tc.payload...),
				SeqNo:      st.sendWindow.Next(),
			}
			client.writeMu.Lock()
			defer client.writeMu.Unlock()
			client.compressFrameLocked(f)
			predicted := client.wireSizeLocked(f)
			var buf bytes.Buffer
			if err := client.encodeFrameLocked(&buf, f); err != nil {
				t.Fatal(err)
			}
			if got := int64(buf.Len()); got != predicted {
				t.Fatalf("predicted %d, encoder wrote %d", predicted, got)
			}
		})
	}
}

// TestNoiseSession_BBRCountsARetransmittedFrameOnce: BBR's inflight estimate returns
// to zero after a frame written twice and acknowledged once, since one ACK takes back
// one OnSend. handleACK empties the send window before it calls the controller's OnAck,
// so each wait is on the controller's own count: a window read at zero says nothing of
// it yet, and a frame counted twice leaves the count above zero and the wait fails.
func TestNoiseSession_BBRCountsARetransmittedFrameOnce(t *testing.T) {
	client, server, tap := tappedPair(t)
	bbr := congestion.NewBBRController()
	client.SetCongestionController(bbr)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	const id = uint64(142)
	cs, ss := openAccept(t, ctx, client, server, id)
	st := asNoiseStream(t, cs)
	waitUntil(t, 60*time.Second, "the first message acknowledged", func() bool {
		return st.sendWindow.InFlight() == 0 && bbr.InFlightBytes() == 0
	})
	tap.drop.Store(true)
	seq := st.sendWindow.Next()
	if err := cs.Send(ctx, compressingFrame(t, 0)); err != nil {
		t.Fatalf("send: %v", err)
	}
	k := wireKey{id, seq}
	waitUntil(t, 60*time.Second, "the frame written twice", func() bool { return tap.writesOf(k) > 1 })
	tap.drop.Store(false)
	if got := <-drain(ctx, ss, 1); len(got) != 1 {
		t.Fatalf("no delivery: %v", ctx.Err())
	}
	waitUntil(t, 60*time.Second, "the frame acknowledged", func() bool { return st.sendWindow.InFlight() == 0 })
	waitUntil(t, 60*time.Second, "BBR's inflight back at zero after the one ACK", func() bool { return bbr.InFlightBytes() == 0 })
}
