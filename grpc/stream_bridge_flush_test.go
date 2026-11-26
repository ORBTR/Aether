//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package grpc

import (
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/ORBTR/aether/grpc/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// drainPeer reads stream until it ends and returns every byte it received
// and the error that ended it.
func drainPeer(stream pb.TransportService_StreamClient) ([]byte, error) {
	var got []byte
	for {
		f, err := stream.Recv()
		if err != nil {
			return got, err
		}
		got = append(got, f.GetData()...)
	}
}

// A Write that returned nil before the session's Close reaches the peer
// ahead of the RPC's end. net.Pipe hands a Write's bytes to the send pump
// before stream.Send runs, so the RPC must not end until that pump has sent
// what it holds; a peer reading a clean end with the bytes missing could not
// tell the stream was cut. Repeated, because whether Close or the pump's
// stream.Send runs first differs from one round to the next.
func TestGrpcServer_StreamBridgeCloseDeliversWhatAWriteReturned(t *testing.T) {
	serverT, _, serverNodeID := freshServerTransport(t)
	cc, cleanup := newBufconnServer(t, serverT)
	defer cleanup()

	const rounds = 60
	for i := 0; i < rounds; i++ {
		stream, cancel, conn := openBridge(t, serverT, cc, serverNodeID)
		want := fmt.Sprintf("final-%d", i)
		if _, err := conn.Write([]byte(want)); err != nil {
			cancel()
			t.Fatalf("round %d: Write: %v", i, err)
		}
		awaitClose(t, conn, fmt.Sprintf("round %d", i))
		got, err := drainPeer(stream)
		cancel()
		if !errors.Is(err, io.EOF) {
			t.Fatalf("round %d: the peer's stream ended with %v, want io.EOF after a Close that met no held Send", i, err)
		}
		if string(got) != want {
			t.Fatalf("round %d: the peer received %q before the clean end, want %q: a Write that returned nil was dropped", i, got, want)
		}
	}
}

// When gRPC's flow control still holds the send pump after the session's
// Close, the RPC ends with codes.Aborted rather than a clean end, so a peer
// that receives what it can and then reads the end knows the stream was cut.
// Fixed 64 KiB windows stop the Writes after a few hundred KiB.
func TestGrpcServer_StreamBridgeCloseUnderHeldWritesEndsAborted(t *testing.T) {
	serverT, _, serverNodeID := freshServerTransport(t)
	cc, cleanup := newBufconnServer(t, serverT,
		grpc.WithInitialWindowSize(1<<16),
		grpc.WithInitialConnWindowSize(1<<16),
	)
	defer cleanup()
	stream, cancel, conn := openBridge(t, serverT, cc, serverNodeID)
	defer cancel()

	var written atomic.Int64
	go func() {
		chunk := make([]byte, 32<<10)
		for {
			n, err := conn.Write(chunk)
			written.Add(int64(n))
			if err != nil {
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
	if _, err := drainPeer(stream); status.Code(err) != codes.Aborted {
		t.Fatalf("the peer's stream ended with %v, want codes.Aborted: its last writes were cut, and a clean end would hide that", err)
	}
}
