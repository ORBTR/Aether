//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package grpc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ORBTR/aether"
	pb "github.com/ORBTR/aether/grpc/pb"
	"google.golang.org/grpc"
)

// pumpReturned reports whether the bridge pump whose done channel is done
// has returned.
func pumpReturned(done chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

// awaitClose runs conn.Close and fails the test unless it returns nil
// within bridgeHangBound with both of the bridge's pumps returned.
func awaitClose(t *testing.T, conn net.Conn, what string) {
	t.Helper()
	closed := make(chan error, 1)
	go func() { closed <- conn.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("%s: Close: %v", what, err)
		}
	case <-time.After(bridgeHangBound):
		t.Fatalf("%s: Close still blocked after %v", what, bridgeHangBound)
	}
	c := conn.(*grpcPipeConn)
	if !pumpReturned(c.recvDone) || !pumpReturned(c.sendDone) {
		t.Fatalf("%s: Close returned before both pumps had (receive %v, send %v)", what, pumpReturned(c.recvDone), pumpReturned(c.sendDone))
	}
}

// The session's Close ends its Stream RPC. The peer's Recv, blocked with
// nothing sent, returns io.EOF, which is how a client stream reads the
// RPC's clean end, and Close returns only once both pumps have returned.
// A second Close returns at once.
func TestGrpcServer_StreamBridgeCloseEndsTheRPC(t *testing.T) {
	serverT, _, serverNodeID := freshServerTransport(t)
	cc, cleanup := newBufconnServer(t, serverT)
	defer cleanup()
	stream, cancel, conn := openBridge(t, serverT, cc, serverNodeID)
	defer cancel()

	recvd := make(chan error, 1)
	go func() {
		_, err := stream.Recv()
		recvd <- err
	}()
	awaitClose(t, conn, "session Close")
	select {
	case err := <-recvd:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("peer Recv after the session's Close = %v, want io.EOF, the RPC's clean end", err)
		}
	case <-time.After(bridgeHangBound):
		t.Fatalf("peer Recv still blocked %v after the session's Close", bridgeHangBound)
	}
	awaitClose(t, conn, "second Close")
}

// A full Close while gRPC flow control holds the session's Writes (the
// peer receives nothing) unblocks the Write, ends the RPC and joins both
// pumps, without waiting for the peer to read or for the RPC's deadline,
// which is further off than bridgeHangBound. Fixed 64 KiB windows stop
// the Writes after a few hundred KiB; the test waits until they stop
// making progress, so the Close usually meets a Write that is blocked.
func TestGrpcServer_StreamBridgeCloseUnblocksAHeldWrite(t *testing.T) {
	serverT, _, serverNodeID := freshServerTransport(t)
	cc, cleanup := newBufconnServer(t, serverT,
		grpc.WithInitialWindowSize(1<<16),
		grpc.WithInitialConnWindowSize(1<<16),
	)
	defer cleanup()
	_, cancel, conn := openBridge(t, serverT, cc, serverNodeID)
	defer cancel()

	var written atomic.Int64
	writes := make(chan error, 1)
	go func() {
		chunk := make([]byte, 32<<10)
		for {
			n, err := conn.Write(chunk)
			written.Add(int64(n))
			if err != nil {
				writes <- err
				return
			}
		}
	}()
	for last, since := int64(-1), time.Now(); ; time.Sleep(20 * time.Millisecond) {
		if now := written.Load(); now != last {
			last, since = now, time.Now()
		} else if time.Since(since) > 100*time.Millisecond {
			break
		}
		if written.Load() > 64<<20 {
			t.Fatalf("%d bytes written to a peer that receives nothing; no Write was held", written.Load())
		}
	}
	awaitClose(t, conn, "Close under held Writes")
	select {
	case err := <-writes:
		if err == nil {
			t.Fatal("the held Write returned no error")
		}
	case <-time.After(bridgeHangBound):
		t.Fatalf("the held Write still blocked %v after Close", bridgeHangBound)
	}
}

// After the peer's CloseSend, the end of the RPC ends the session's write
// half too, with no call from the session: here the peer cancels, and
// the send pump returns although the session neither writes nor closes.
// The session's Close then joins both pumps.
func TestGrpcServer_StreamBridgeRPCEndAfterHalfCloseEndsTheSendPump(t *testing.T) {
	serverT, _, serverNodeID := freshServerTransport(t)
	cc, cleanup := newBufconnServer(t, serverT)
	defer cleanup()
	stream, cancel, conn := openBridge(t, serverT, cc, serverNodeID)
	defer cancel()

	if err := conn.SetReadDeadline(time.Now().Add(bridgeHangBound)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("CloseSend: %v", err)
	}
	if _, err := conn.Read(make([]byte, 8)); !errors.Is(err, io.EOF) {
		t.Fatalf("Read after the peer's CloseSend = %v, want io.EOF", err)
	}
	cancel()
	select {
	case <-conn.(*grpcPipeConn).sendDone:
	case <-time.After(bridgeHangBound):
		t.Fatalf("send pump still running %v after the RPC ended", bridgeHangBound)
	}
	if _, err := conn.Write([]byte("lost")); err == nil {
		t.Fatal("server Write after the RPC ended succeeded")
	}
	awaitClose(t, conn, "Close after the RPC ended")
}

// A Stream whose session cannot be handed over, because the transport's
// incoming buffer is full, ends at once with the refusal: the peer's Recv
// returns it rather than waiting on an RPC that no session will close.
func TestGrpcServer_StreamBridgeUndeliveredSessionEndsTheRPC(t *testing.T) {
	serverT, _, serverNodeID := freshServerTransport(t)
	cc, cleanup := newBufconnServer(t, serverT)
	defer cleanup()
	for len(serverT.incoming) < cap(serverT.incoming) {
		serverT.incoming <- aether.IncomingSession{}
	}

	clientPub, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	clientNodeID, err := aether.NewNodeID(clientPub)
	if err != nil {
		t.Fatalf("client NewNodeID: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*bridgeHangBound)
	defer cancel()
	ctx = makeAuthedContext(t, ctx, clientPriv, clientNodeID, serverNodeID)
	stream, err := pb.NewTransportServiceClient(cc).Stream(ctx)
	if err != nil {
		t.Fatalf("open Stream: %v", err)
	}
	recvd := make(chan error, 1)
	go func() {
		_, err := stream.Recv()
		recvd <- err
	}()
	select {
	case err := <-recvd:
		if err == nil || !strings.Contains(err.Error(), "incoming session buffer full") {
			t.Fatalf("peer Recv = %v, want the full buffer's refusal", err)
		}
	case <-time.After(bridgeHangBound):
		t.Fatalf("peer Recv still blocked %v after the server refused the session", bridgeHangBound)
	}
}
