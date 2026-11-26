//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package adapter

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/flow"
)

// TestTCPSession_TheReadLoopWaitsOnNoWrite: a peer that writes frames each needing an
// answer (a RESET to acknowledge, a PING, an OPEN to refuse, a message past a stream's
// delivery queue, another RESET) and reads nothing still has its later DATA delivered,
// because the readLoop hands every answer to the writeLoop and goes on reading. On
// net.Pipe a readLoop that wrote an answer itself would wait on the peer's read and
// deliver nothing after it. Once the peer reads, every answer is on the wire in the
// order the readLoop handled its frame.
func TestTCPSession_TheReadLoopWaitsOnNoWrite(t *testing.T) {
	p := newLiteRawPeer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	const id = 40
	writeFrames(t, p.conn, synFrame(id))
	st, err := p.sess.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	const full = 45
	writeFrames(t, p.conn, synFrame(full))
	if _, err := p.sess.AcceptStream(ctx); err != nil {
		t.Fatalf("accept %d: %v", full, err)
	}
	refused := &aether.Frame{StreamID: 43, Type: aether.TypeDATA, Flags: aether.FlagSYN,
		Payload: aether.EncodeOpenPayload(aether.OpenPayload{Reliability: aether.ReliableOrdered})}
	writeFrames(t, p.conn,
		rawReset(41, aether.ResetCancel),
		pingFrame(),
		refused,
		&aether.Frame{StreamID: full, Type: aether.TypeDATA, Payload: make([]byte, flow.CurrentBounds().StreamCredit)},
		rawReset(42, aether.ResetTimeout),
		&aether.Frame{StreamID: id, Type: aether.TypeDATA, Payload: []byte("after")})
	if r := <-receiveAsync(ctx, st, 5*time.Second); r.err != nil || string(r.data) != "after" {
		t.Fatalf("the DATA behind four frames needing an answer: %q, %v; the readLoop waited on its answer's write", r.data, r.err)
	}
	type want struct {
		id    uint64
		typ   aether.FrameType
		acked bool
	}
	for i, w := range []want{
		{41, aether.TypeRESET, true},
		{2, aether.TypePONG, false},
		{43, aether.TypeRESET, false},
		{full, aether.TypeRESET, false},
		{42, aether.TypeRESET, true},
	} {
		f := p.next()
		if f.StreamID != w.id || f.Type != w.typ || f.Flags.Has(aether.FlagACK) != w.acked {
			t.Fatalf("answer %d: %+v, want type %v on %d (acknowledgment %v)", i, f, w.typ, w.id, w.acked)
		}
	}
}

// TestTCPSession_APingReturnsUnderItsContextOnAConnThatTakesNothing: a Ping's PING
// write runs under the Ping's context, both while it waits for another writer that
// the conn holds and while its own write waits on the conn, so a keepalive probe on
// a conn that takes nothing returns at its context's end. A write that put no byte
// on the conn leaves the session open and the framing whole: once the peer reads,
// the next frame on the wire is the DATA the writeLoop was writing.
func TestTCPSession_APingReturnsUnderItsContextOnAConnThatTakesNothing(t *testing.T) {
	p := newLiteRawPeer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ping := func(what string) {
		t.Helper()
		done := make(chan error, 1)
		go func() {
			pctx, pc := context.WithTimeout(ctx, 300*time.Millisecond)
			defer pc()
			_, err := p.sess.Ping(pctx)
			done <- err
		}()
		select {
		case err := <-done:
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Ping %s: %v, want its context's end", what, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("Ping %s still blocked 5 s after it began under a 300 ms context", what)
		}
		if p.sess.IsClosed() {
			t.Fatalf("the session closed after a Ping %s: %v", what, p.sess.CloseErr())
		}
	}
	ping("whose own write the conn holds")
	st := p.open(ctx, 44)
	if err := st.Send(ctx, []byte("held")); err != nil {
		t.Fatalf("send: %v", err)
	}
	waitLong(t, "the writeLoop taking the DATA", func() bool { return p.sess.sched.QueueLen(44) == 0 })
	ping("behind the writeLoop's write the conn holds")
	if f := p.next(); f.StreamID != 44 || f.Type != aether.TypeDATA || string(f.Payload) != "held" {
		t.Fatalf("first frame once the peer reads: %+v, want the DATA the writeLoop held", f)
	}
}

// TestTCPSession_MutualResetsUnderBulkKeepBothSessionsLive: both ends of a TCP-family
// session open, fill and reset their own streams in a loop while every stream carries
// bulk traffic both ways, each RESET answered by an acknowledgment. Over net.Pipe,
// which buffers nothing, and over a loopback with 8 KiB socket buffers, the sessions
// keep delivering, a Ping on each answers within its 5 s context, and every sender
// and reader returns once the run stops.
func TestTCPSession_MutualResetsUnderBulkKeepBothSessionsLive(t *testing.T) {
	for _, kind := range []string{"pipe", "loopback-8KiB"} {
		t.Run(kind, func(t *testing.T) {
			var client, server *TCPSession
			payload := make([]byte, 16*1024)
			if kind == "pipe" {
				client, server = tcpPairWithOptions(t, aether.DefaultSessionOptions())
			} else {
				c, s := loopbackPair(t)
				for _, conn := range []net.Conn{c, s} {
					tc := conn.(*net.TCPConn)
					_ = tc.SetReadBuffer(8 * 1024)
					_ = tc.SetWriteBuffer(8 * 1024)
				}
				client = NewTCPSession(c, "vl1_mutual_client", "vl1_mutual_server", aether.ProtoTCP, aether.DefaultSessionOptions())
				server = NewTCPSession(s, "vl1_mutual_server", "vl1_mutual_client", aether.ProtoTCP, aether.DefaultSessionOptions())
				t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
				payload = make([]byte, 128*1024)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			runCtx, stopRun := context.WithCancel(ctx)
			defer stopRun()
			var delivered atomic.Int64
			var wg sync.WaitGroup
			for _, s := range []*TCPSession{client, server} {
				s := s
				wg.Add(1)
				go func() {
					defer wg.Done()
					for {
						st, err := s.AcceptStream(runCtx)
						if err != nil {
							return
						}
						wg.Add(1)
						go func() {
							defer wg.Done()
							for {
								if _, err := st.Receive(runCtx); err != nil {
									return
								}
								delivered.Add(1)
							}
						}()
					}
				}()
			}
			for side, s := range []*TCPSession{client, server} {
				for k := 0; k < 4; k++ {
					id := uint64(300 + side*10 + k)
					s := s
					wg.Add(1)
					go func() {
						defer wg.Done()
						rng := rand.New(rand.NewSource(int64(id)))
						for runCtx.Err() == nil {
							st, err := s.OpenStream(runCtx, aether.StreamConfig{StreamID: id, Reliability: aether.ReliableOrdered, Priority: 128})
							if errors.Is(err, aether.ErrDuplicateStreamID) {
								time.Sleep(5 * time.Millisecond)
								continue
							}
							if err != nil {
								return
							}
							n := 5 + rng.Intn(40)
							for i := 0; i < n && runCtx.Err() == nil; i++ {
								sctx, sc := context.WithTimeout(runCtx, 2*time.Second)
								err := st.Send(sctx, payload)
								sc()
								if err != nil {
									break
								}
							}
							_ = st.Reset(aether.ResetCancel)
						}
					}()
				}
			}
			time.Sleep(4 * time.Second)
			pingWithin := func(s *TCPSession) error {
				ch := make(chan error, 1)
				go func() {
					pctx, pc := context.WithTimeout(ctx, 5*time.Second)
					defer pc()
					_, err := s.Ping(pctx)
					ch <- err
				}()
				select {
				case err := <-ch:
					return err
				case <-time.After(8 * time.Second):
					return errors.New("still blocked 8 s after it began under a 5 s context")
				}
			}
			perrC, perrS := pingWithin(client), pingWithin(server)
			stopRun()
			done := make(chan struct{})
			go func() { wg.Wait(); close(done) }()
			wedged := false
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				wedged = true
			}
			t.Logf("%s: %d messages delivered, ping client %v server %v", kind, delivered.Load(), perrC, perrS)
			if perrC != nil || perrS != nil || wedged || delivered.Load() == 0 {
				t.Fatalf("%s: the sessions stopped under mutual resets: ping %v / %v, senders and readers still running %v, delivered %d",
					kind, perrC, perrS, wedged, delivered.Load())
			}
		})
	}
}

// TestTCPSession_ADirectWriteNeverOvertakesAFrameTheWriteLoopHasTaken: a frame written
// straight through writeFrame while the writeLoop holds a frame it has taken from the
// scheduler reaches the conn after that frame, because the writeLoop takes the write
// turn before its Dequeue and keeps it through the write. resetAcknowledged's reading
// that nothing of a reset stream follows its acknowledgment, and sendReset's and
// OpenStream's that nothing of the ID's earlier stream follows them, rest on that order.
func TestTCPSession_ADirectWriteNeverOvertakesAFrameTheWriteLoopHasTaken(t *testing.T) {
	p := newLiteRawPeer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	const id = 46
	st := p.open(ctx, id)
	direct := make(chan error, 1)
	var once sync.Once
	hook := func(f *aether.Frame) {
		if f.StreamID != id || f.Type != aether.TypeDATA {
			return
		}
		once.Do(func() {
			go func() {
				direct <- p.sess.writeFrame(&aether.Frame{SenderID: p.sess.LocalPeerID(), ReceiverID: p.sess.RemotePeerID(),
					StreamID: p.sess.layout.Keepalive, Type: aether.TypePING, SeqNo: 7})
			}()
			// Time for the direct write to reach the conn, were the turn free.
			time.Sleep(100 * time.Millisecond)
		})
	}
	p.sess.afterDequeue.Store(&hook)
	if err := st.Send(ctx, []byte("taken")); err != nil {
		t.Fatalf("send: %v", err)
	}
	first, second := p.next(), p.next()
	if first.StreamID != id || first.Type != aether.TypeDATA || second.Type != aether.TypePING {
		t.Fatalf("frames on the wire: %+v then %+v, want the DATA the writeLoop took, then the direct PING", first, second)
	}
	if err := <-direct; err != nil {
		t.Fatalf("direct write: %v", err)
	}
}

// TestTCPSession_ACloseOnAConnThatTakesNothingReturns: CloseWithError resets the
// streams the peer opened that no one accepted before it closes the conn. On a conn
// that takes nothing, a RESET that waits behind the writeLoop's write gives up at the
// close, and one with the turn to itself waits at most one keepalive probe's wait
// (sessionWriter.closeBound), so the close returns and the conn closes.
func TestTCPSession_ACloseOnAConnThatTakesNothingReturns(t *testing.T) {
	for _, held := range []bool{false, true} {
		name := "a free write turn"
		if held {
			name = "the writeLoop's write held"
		}
		t.Run(name, func(t *testing.T) {
			p := newLiteRawPeer(t)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if held {
				st := p.open(ctx, 48)
				if err := st.Send(ctx, []byte("held")); err != nil {
					t.Fatalf("send: %v", err)
				}
				waitLong(t, "the writeLoop taking the DATA", func() bool { return p.sess.sched.QueueLen(48) == 0 })
			}
			// Streams the peer opens and no one accepts, which the close resets.
			writeFrames(t, p.conn, synFrame(50), synFrame(52))
			waitLong(t, "the peer's opens admitted", func() bool { return inSession(p.sess, 50) && inSession(p.sess, 52) })
			bound := aether.KeepalivePlanFor(p.sess).ProbeTimeout
			done := make(chan struct{})
			start := time.Now()
			go func() { _ = p.sess.Close(); close(done) }()
			select {
			case <-done:
			case <-time.After(bound + 5*time.Second):
				t.Fatalf("Close still running %s after it began, the bound is %s", time.Since(start).Round(time.Millisecond), bound)
			}
		})
	}
}

// TestSessionWriter_AFailedWriterWritesNothingMore: once a write has failed, the
// framing on the conn may be cut, so a later Write puts no byte on the conn and answers
// the writer's failure.
func TestSessionWriter_AFailedWriterWritesNothingMore(t *testing.T) {
	c, s := net.Pipe()
	defer func() {
		if err := c.Close(); err != nil {
			t.Errorf("c.Close: %v", err)
		}
	}()
	defer func() {
		if err := s.Close(); err != nil {
			t.Errorf("s.Close: %v", err)
		}
	}()
	boom := errors.New("the conn broke")
	w := newSessionWriter(&flakyConn{Conn: c, failAfter: 1, fatal: boom}, make(chan struct{}), nil)
	read := make(chan int, 1)
	go func() {
		buf := make([]byte, 64)
		total := 0
		for {
			n, err := s.Read(buf)
			total += n
			if err != nil {
				read <- total
				return
			}
		}
	}()
	if _, err := w.Write(make([]byte, 8)); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if _, err := w.Write(make([]byte, 8)); !errors.Is(err, boom) || !w.failed() {
		t.Fatalf("second write: %v, failed %v; want the conn's error", err, w.failed())
	}
	if n, err := w.Write(make([]byte, 8)); n != 0 || !errors.Is(err, errSessionWriterFailed) {
		t.Fatalf("write after the failure: %d bytes, %v; want none and errSessionWriterFailed", n, err)
	}
	_ = c.Close()
	if got := <-read; got != 8 {
		t.Fatalf("the conn carried %d bytes, want the first write's 8", got)
	}
}

// TestTCPSession_AnAnswerForAnIDWithNoStreamLeavesNoCompressorState: the acknowledgment
// of a RESET for a stream the session does not hold goes out as a full frame, which
// records transmit compressor state for its ID, and the writeLoop drops that state
// once it is written (forgetTransmitState), so an ID reset and never reused keeps no
// entry. A DATA frame under the ID would take a short form only with that state.
func TestTCPSession_AnAnswerForAnIDWithNoStreamLeavesNoCompressorState(t *testing.T) {
	client, server := tcpPairWithOptions(t, aether.DefaultSessionOptions())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := client.Ping(ctx); err != nil {
		t.Fatalf("ping before: %v", err)
	}
	const id = 61
	if !server.txCompressor.ShortForms() {
		t.Fatal("the pair negotiated no short forms, so no state would be read")
	}
	reset := &aether.Frame{SenderID: client.LocalPeerID(), ReceiverID: client.RemotePeerID(), StreamID: id, Type: aether.TypeRESET,
		Payload: aether.EncodeResetPayload(aether.ResetPayload{Reason: aether.ResetCancel, Incarnation: aether.StreamIncarnation{Generation: 9, WriterOpened: true}})}
	reset.Length = uint32(len(reset.Payload))
	if err := client.writeFrame(reset); err != nil {
		t.Fatalf("reset: %v", err)
	}
	// The PONG follows the acknowledgment out of the server's control queue.
	if _, err := client.Ping(ctx); err != nil {
		t.Fatalf("ping after: %v", err)
	}
	data := &aether.Frame{SenderID: server.LocalPeerID(), ReceiverID: server.RemotePeerID(), StreamID: id, Type: aether.TypeDATA, Length: 1, Payload: []byte("x")}
	waitLong(t, "the acknowledgment's compressor state dropped", func() bool { return !server.txCompressor.ShouldCompressData(data) })
}
