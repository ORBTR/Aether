//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"bytes"
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
// not read).
func TestNoiseStream_ASendTheSchedulerRefusesIsRefusedAndReturnsItsCredit(t *testing.T) {
	client, server := noisePairWithRealms(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cs, _ := openWithCredit(t, ctx, client, server, 962, 0)
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
