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
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/flow"
)

// TestNoiseStream_ASendOnAClosedSessionIsTyped: once a NoiseSession closes, a Send
// on a stream it still holds answers aether.ErrSessionClosed, a whole message and a
// fragmented one alike, rather than nil for a frame its stopped write loop would
// never write. sendSingleFrame refuses each frame on its own as well, which is what
// answers a close that comes while a Send waits for credit, past Send's own check;
// it is called here as such a Send would call it once the credit came.
func TestNoiseStream_ASendOnAClosedSessionIsTyped(t *testing.T) {
	client, server := noisePairWithRealms(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cs, _ := openWithCredit(t, ctx, client, server, 960, 0)
	_ = client.Close()
	wantSessionClosed(t, "Send of a small message", cs.Send(ctx, []byte("x")))
	big := bytes.Repeat([]byte("f"), 3*MSSToMaxPayload(cs.session.pmtuProber.MSS()))
	wantSessionClosed(t, "Send of a fragmented message", cs.Send(ctx, big))
	wantSessionClosed(t, "a frame past Send's check", cs.sendSingleFrame(ctx, []byte("y"), 0))
	if got := client.sched.QueueLen(cs.streamID); got != 0 {
		t.Errorf("the closed session's scheduler holds %d frames of the stream, want 0", got)
	}
}

// TestNoiseStream_ASendTheSchedulerRefusesIsRefusedAndReturnsItsCredit: a Send on a
// stream the scheduler no longer holds, as after a RESET's exit, returns an error
// and leaves the connection window as it found it: the bytes it charged come back
// once, by releaseInFlight, and not a second time by Send's own release, which would
// hand the session credit another stream still holds (here a message the peer has
// not read). The scheduler's exit here has no RESET settlement before it, so
// releaseInFlight settles the stream itself, returning to the connection window what
// the stream's Sends charged there less what the stream's grants say came back
// (settleCharges); a stream grant still on its way would count the opening message
// as unreturned when its connection grant has come, and return it twice. The peer's
// stream grants are held on the path until the test's wait for them, which lets
// them through, so a wait that is missing leaves the grant held every time.
func TestNoiseStream_ASendTheSchedulerRefusesIsRefusedAndReturnsItsCredit(t *testing.T) {
	client, server, _, toClient := filteredPair(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	const id = 962
	var holdGrants atomic.Bool
	holdGrants.Store(true)
	toClient.setRule(func(f *aether.Frame) bool {
		return holdGrants.Load() && f.StreamID == id && f.Type == aether.TypeWINDOW
	})
	cs, _ := openWithCredit(t, ctx, client, server, id, 0)
	other, _ := openWithCredit(t, ctx, client, server, 964, 0)
	unread := []byte("unread by the peer")
	if err := other.Send(ctx, unread); err != nil {
		t.Fatalf("send on the other stream: %v", err)
	}
	held := messageCredit(int64(len(unread)))
	waitSendWindowEmpty(t, cs, "the opening message acknowledged")
	waitFor(t, "the connection charge down to the unread message", func() bool {
		return client.connWindow.Stats().Outstanding == held
	})
	deadline := time.Now().Add(15 * time.Second)
	for holdGrants.Store(false); cs.window.Outstanding() != 0; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the stream's grant of the opening message: %d outstanding after 15 s", cs.window.Outstanding())
		}
	}
	client.sched.Unregister(cs.streamID)
	if err := cs.Send(ctx, []byte("refused")); err == nil {
		t.Fatal("a Send the scheduler refused returned nil")
	}
	if got := client.connWindow.Stats().Outstanding; got != held {
		t.Fatalf("connection charge %d after the refused Send, want %d (the other stream's unread message)", got, held)
	}
	if got := cs.window.Outstanding(); got != 0 {
		t.Fatalf("stream credit outstanding %d after the refused Send, want 0", got)
	}
}

// TestNoiseStream_ACloseWakesASendWaitingForCredit: a Send waiting for stream credit,
// its peer reading nothing, returns aether.ErrSessionClosed as soon as its session
// closes, rather than waiting out flow.ConsumeTimeout and answering backpressure: the
// close ends the credit wait (flow.StreamWindow.ConsumeUntil).
func TestNoiseStream_ACloseWakesASendWaitingForCredit(t *testing.T) {
	client, server := noisePairWithRealms(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cs, _ := openWithCredit(t, ctx, client, server, 968, 0)
	done := make(chan error, 1)
	go func() {
		for {
			if err := cs.Send(ctx, make([]byte, 900)); err != nil {
				done <- err
				return
			}
		}
	}()
	waitFor(t, "the stream's credit spent", func() bool { return cs.window.Available() < messageCredit(900) })
	time.Sleep(100 * time.Millisecond) // the next Send is in its credit wait
	start := time.Now()
	_ = client.Close()
	select {
	case err := <-done:
		if !errors.Is(err, aether.ErrSessionClosed) || errors.Is(err, flow.ErrCreditExhausted) {
			t.Fatalf("the waiting Send returned %v, want aether.ErrSessionClosed", err)
		}
		if took := time.Since(start); took >= flow.ConsumeTimeout/2 {
			t.Fatalf("the waiting Send returned %s after the close", took)
		}
	case <-time.After(flow.ConsumeTimeout / 2):
		t.Fatalf("a Send waiting for credit still blocked %s after its session closed", flow.ConsumeTimeout/2)
	}
}

// TestNoiseStream_ASendPastItsCheckWhenAResetEndsTheStreamReturnsItsCredit: a Send
// that passed its state check before a RESET ended the stream, and charges its credit
// after the RESET's settlement, gives that credit back whether its frame reached the
// scheduler before the stream left it or after: a RESET's exit takes the stream out of
// the scheduler before it returns what the stream still holds
// (leaveSchedulerThenSettle). The test runs, at the exit's last point before the
// scheduler exit, what such a Send does once its stream credit is charged and its last
// state check passed (sendStreamCharged), for this side's Reset and for the peer's
// RESET, and the connection charge comes back to what it was.
func TestNoiseStream_ASendPastItsCheckWhenAResetEndsTheStreamReturnsItsCredit(t *testing.T) {
	for _, byPeer := range []bool{false, true} {
		name := "this side's Reset"
		if byPeer {
			name = "the peer's RESET"
		}
		t.Run(name, func(t *testing.T) {
			client, server := noisePairWithRealms(t, nil, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cs, ss := openWithCredit(t, ctx, client, server, 970, 0)
			waitSendWindowEmpty(t, cs, "the opening message acknowledged")
			waitFor(t, "the opening message's grants", func() bool {
				return cs.window.Outstanding() == 0 && client.connWindow.Stats().Outstanding == 0
			})
			ran := make(chan error, 1)
			msg := []byte("past its check")
			hook := func() {
				n := messageCredit(int64(len(msg)))
				if err := cs.window.Consume(ctx, n); err != nil {
					ran <- err
					return
				}
				ran <- cs.sendStreamCharged(ctx, msg, n)
			}
			cs.beforeSchedulerExit.Store(&hook)
			if byPeer {
				_ = ss.Reset(aether.ResetCancel)
			} else {
				_ = cs.Reset(aether.ResetCancel)
			}
			select {
			case err := <-ran:
				t.Logf("the Send past its check returned %v", err)
			case <-time.After(10 * time.Second):
				t.Fatal("the RESET's exit never reached its scheduler exit")
			}
			waitFor(t, "the connection charge back to none", func() bool { return client.connWindow.Stats().Outstanding == 0 })
			waitFor(t, "the session's in-flight count back to none", func() bool { return client.inFlightBytes.Load() == 0 })
		})
	}
}

// TestNoiseStream_AResetStreamQueuesNothingUnderTheIDsNextStream: a frame of a stream
// the session no longer holds under its ID, as from a Send that passed its checks
// before a RESET and resumes after the ID's next stream has opened, is refused and
// leaves the next stream's scheduler queue as it was: the scheduler keys its queues by
// ID, and the frame is numbered in the old stream's sequence (queueFrame).
func TestNoiseStream_AResetStreamQueuesNothingUnderTheIDsNextStream(t *testing.T) {
	client, server := noisePairWithRealms(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	const id = 972
	old, _ := openWithCredit(t, ctx, client, server, id, 0)
	if err := old.Reset(aether.ResetCancel); err != nil {
		t.Fatalf("reset: %v", err)
	}
	var next aether.Stream
	waitFor(t, "the ID open again", func() bool {
		st, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: id, Reliability: aether.ReliableOrdered, Priority: 128})
		if err != nil {
			return false
		}
		next = st
		return true
	})
	_ = next
	before := client.sched.QueueLen(id)
	if err := old.sendSingleFrame(ctx, []byte("late"), 0); !errors.Is(err, errLeftScheduler) {
		t.Fatalf("a frame of the reset stream: %v, want errLeftScheduler", err)
	}
	if got := client.sched.QueueLen(id); got != before {
		t.Fatalf("the next stream's queue went from %d to %d", before, got)
	}
}

// TestEveryEnqueueResultIsRead walks the module's non-test Go files and fails on a
// call to a method named Enqueue whose result is dropped, as a statement or into the
// blank identifier: the scheduler's Enqueue reports false for a stream it no longer
// holds, and a caller that drops that loses the frame without a word to its sender.
func TestEveryEnqueueResultIsRead(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var dropped []string
	files := 0
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && (strings.HasPrefix(d.Name(), ".") || d.Name() == "testdata" || d.Name() == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		files++
		isEnqueue := func(e ast.Expr) bool {
			call, ok := e.(*ast.CallExpr)
			if !ok {
				return false
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			return ok && sel.Sel.Name == "Enqueue"
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch s := n.(type) {
			case *ast.ExprStmt:
				if isEnqueue(s.X) {
					dropped = append(dropped, fset.Position(s.Pos()).String())
				}
			case *ast.AssignStmt:
				for i, rhs := range s.Rhs {
					if i < len(s.Lhs) && isEnqueue(rhs) {
						if id, ok := s.Lhs[i].(*ast.Ident); ok && id.Name == "_" {
							dropped = append(dropped, fset.Position(s.Pos()).String())
						}
					}
				}
			case *ast.GoStmt:
				if isEnqueue(s.Call) {
					dropped = append(dropped, fset.Position(s.Pos()).String())
				}
			case *ast.DeferStmt:
				if isEnqueue(s.Call) {
					dropped = append(dropped, fset.Position(s.Pos()).String())
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files == 0 {
		t.Fatalf("no Go files under %s", root)
	}
	for _, at := range dropped {
		t.Errorf("an Enqueue result is dropped at %s", at)
	}
}

// TestNoiseStream_ASendChargingConnCreditAfterTheResetsExitReturnsIt: a Send that
// charged its stream credit and passed its last state check before a RESET ended the
// stream, and charges its connection credit only once the RESET's exit has finished,
// leaves the connection window as it found it, for this side's Reset and for the
// peer's RESET. The exit has returned what the stream window held by then, this
// Send's stream charge among it, while the connection window had no charge of this
// Send's yet; the connection charge the Send makes afterwards meets a stream the
// scheduler no longer holds, and nothing but the Send itself is left to return it.
// The stream charge is made at the exit's last point before the scheduler exit
// (beforeSchedulerExit), and the rest of the Send (sendStreamCharged) runs once the
// exit has taken the stream out of the session.
func TestNoiseStream_ASendChargingConnCreditAfterTheResetsExitReturnsIt(t *testing.T) {
	for _, byPeer := range []bool{false, true} {
		name := "this side's Reset"
		if byPeer {
			name = "the peer's RESET"
		}
		t.Run(name, func(t *testing.T) {
			client, server := noisePairWithRealms(t, nil, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cs, ss := openWithCredit(t, ctx, client, server, 974, 0)
			waitSendWindowEmpty(t, cs, "the opening message acknowledged")
			waitFor(t, "the opening message's grants", func() bool {
				return cs.window.Outstanding() == 0 && client.connWindow.Stats().Outstanding == 0
			})
			msg := []byte("charged its stream before the reset")
			n := messageCredit(int64(len(msg)))
			charged := make(chan error, 1)
			hook := func() { charged <- cs.window.Consume(ctx, n) }
			cs.beforeSchedulerExit.Store(&hook)
			if byPeer {
				_ = ss.Reset(aether.ResetCancel)
			} else {
				_ = cs.Reset(aether.ResetCancel)
			}
			select {
			case err := <-charged:
				if err != nil {
					t.Fatalf("stream charge: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("the RESET's exit never reached its scheduler exit")
			}
			cs.beforeSchedulerExit.Store(nil)
			waitFor(t, "the exit finished", func() bool { return !holdsSelf(cs) })
			time.Sleep(50 * time.Millisecond)
			err := cs.sendStreamCharged(ctx, msg, n)
			if err == nil {
				t.Fatal("the resumed Send on the reset stream returned nil")
			}
			waitFor(t, "the connection charge back to none", func() bool { return client.connWindow.Stats().Outstanding == 0 })
		})
	}
}

// TestNoiseStream_ASendRacingAResetReturnsExactlyItsConnectionCharge: a Send charges
// its stream window, then its connection window, and a RESET can fall between the
// two. Whether its stream charge came before the RESET's settlement (the Send had
// passed its state check) or after it (the exit's last point before the scheduler
// exit, beforeSchedulerExit), the connection window ends where it would have without
// the Send: the settlement returns only what the stream's Sends had charged there,
// and the Send returns its own later charge. Beside another stream's unread message
// the connection window still holds that message's charge, so a settlement that
// returned this Send's stream charge as if it were a connection charge would show as
// the other stream's credit handed back early.
func TestNoiseStream_ASendRacingAResetReturnsExactlyItsConnectionCharge(t *testing.T) {
	for _, after := range []bool{false, true} {
		for _, beside := range []bool{false, true} {
			name := "stream charge before the RESET"
			if after {
				name = "stream charge after the settlement"
			}
			if beside {
				name += ", beside an unread message"
			}
			t.Run(name, func(t *testing.T) {
				client, server := noisePairWithRealms(t, nil, nil)
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				cs, _ := openWithCredit(t, ctx, client, server, 976, 0)
				var held int64
				if beside {
					other, _ := openWithCredit(t, ctx, client, server, 978, 0)
					unread := []byte("unread by the peer")
					if err := other.Send(ctx, unread); err != nil {
						t.Fatalf("send on the other stream: %v", err)
					}
					held = messageCredit(int64(len(unread)))
				}
				waitSendWindowEmpty(t, cs, "the opening message acknowledged")
				waitFor(t, "the opening message's grants", func() bool {
					return cs.window.Outstanding() == 0 && client.connWindow.Stats().Outstanding == held
				})
				msg := []byte("racing the reset")
				n := messageCredit(int64(len(msg)))
				if after {
					charged := make(chan error, 1)
					hook := func() { charged <- cs.window.Consume(ctx, n) }
					cs.beforeSchedulerExit.Store(&hook)
					_ = cs.Reset(aether.ResetCancel)
					if err := <-charged; err != nil {
						t.Fatalf("stream charge: %v", err)
					}
					cs.beforeSchedulerExit.Store(nil)
				} else {
					if err := cs.window.Consume(ctx, n); err != nil {
						t.Fatalf("stream charge: %v", err)
					}
					_ = cs.Reset(aether.ResetCancel)
				}
				waitFor(t, "the exit finished", func() bool { return !holdsSelf(cs) })
				if err := cs.sendStreamCharged(ctx, msg, n); err == nil {
					t.Fatal("the resumed Send on the reset stream returned nil")
				}
				if got := client.connWindow.Stats().Outstanding; got != held {
					t.Fatalf("connection charge %d after the Send, want %d", got, held)
				}
				cs.releaseInFlight()
				if got := client.connWindow.Stats().Outstanding; got != held {
					t.Fatalf("connection charge %d after releaseInFlight, want %d", got, held)
				}
			})
		}
	}
}
