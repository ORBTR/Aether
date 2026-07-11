/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package client

import (
	"context"
	"errors"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	aether "github.com/ORBTR/aether"
	"github.com/ORBTR/aether/rpc/pb"
)

// fakeConn is a scriptable aether.Connection used to drive Client without any
// real transport. Send captures the marshaled request; Receive replays a
// configured response (or error). Hooks override the default behavior for
// tests that need per-call logic (deadline capture, serialization checks).
type fakeConn struct {
	sendHook func(ctx context.Context, payload []byte) error
	recvHook func(ctx context.Context) ([]byte, error)

	sendErr  error
	recvErr  error
	recvData []byte
	closeErr error

	mu          sync.Mutex
	sent        [][]byte
	sendCalls   int
	recvCalls   int
	closeCalls  int
	lastRecvCtx context.Context
}

func (f *fakeConn) Send(ctx context.Context, payload []byte) error {
	f.mu.Lock()
	f.sendCalls++
	f.sent = append(f.sent, append([]byte(nil), payload...))
	f.mu.Unlock()
	if f.sendHook != nil {
		return f.sendHook(ctx, payload)
	}
	return f.sendErr
}

func (f *fakeConn) Receive(ctx context.Context) ([]byte, error) {
	f.mu.Lock()
	f.recvCalls++
	f.lastRecvCtx = ctx
	f.mu.Unlock()
	if f.recvHook != nil {
		return f.recvHook(ctx)
	}
	if f.recvErr != nil {
		return nil, f.recvErr
	}
	return f.recvData, nil
}

func (f *fakeConn) Close() error {
	f.mu.Lock()
	f.closeCalls++
	f.mu.Unlock()
	return f.closeErr
}

func (f *fakeConn) RemoteAddr() net.Addr        { return nil }
func (f *fakeConn) RemoteNodeID() aether.NodeID { return aether.NodeID("test-node") }
func (f *fakeConn) NetConn() net.Conn           { return nil }
func (f *fakeConn) Protocol() aether.Protocol   { return aether.ProtoQUIC }
func (f *fakeConn) OnClose(fn func())           {}

// static assertion: fakeConn must satisfy the interface Client depends on.
var _ aether.Connection = (*fakeConn)(nil)

func mustMarshalResp(t *testing.T, r *pb.RPCResponse) []byte {
	t.Helper()
	b, err := pb.MarshalResponse(r)
	if err != nil {
		t.Fatalf("MarshalResponse: %v", err)
	}
	return b
}

// TestCallRequestEncoding verifies that Call serializes exactly the fields the
// caller supplies (handler/payload/metadata), stamps a generated "rpc-" id, and
// leaves the routing/hop fields untouched.
func TestCallRequestEncoding(t *testing.T) {
	fc := &fakeConn{recvData: mustMarshalResp(t, &pb.RPCResponse{Id: "resp-1", Success: true})}
	c := NewClient(fc)

	payload := []byte(`{"token":"abc"}`)
	meta := map[string]string{"scope": "t1", "trace": "xyz"}

	if _, err := c.Call(context.Background(), "auth.Enroll", payload, meta); err != nil {
		t.Fatalf("Call: %v", err)
	}

	if fc.sendCalls != 1 {
		t.Fatalf("sendCalls = %d, want 1", fc.sendCalls)
	}
	if len(fc.sent) != 1 {
		t.Fatalf("captured %d requests, want 1", len(fc.sent))
	}

	req, err := pb.UnmarshalRequest(fc.sent[0])
	if err != nil {
		t.Fatalf("UnmarshalRequest of sent bytes: %v", err)
	}
	if req.Handler != "auth.Enroll" {
		t.Errorf("Handler = %q, want %q", req.Handler, "auth.Enroll")
	}
	if string(req.Payload) != string(payload) {
		t.Errorf("Payload = %q, want %q", req.Payload, payload)
	}
	if len(req.Context) != 2 || req.Context["scope"] != "t1" || req.Context["trace"] != "xyz" {
		t.Errorf("Context = %v, want %v", req.Context, meta)
	}
	if !strings.HasPrefix(req.Id, "rpc-") {
		t.Errorf("request Id = %q, want prefix %q", req.Id, "rpc-")
	}
	// Routing fields must remain zero — Call never populates them.
	if req.TargetNodeId != "" || len(req.RouteList) != 0 || req.Hops != 0 ||
		req.RequestNonce != "" || req.Deadline != 0 || req.TimeoutNs != 0 {
		t.Errorf("unexpected routing fields set: %+v", req)
	}
}

// TestCallEmptyInputs covers the boundary where payload and metadata are nil:
// the request must still round-trip and the response must convert.
func TestCallEmptyInputs(t *testing.T) {
	fc := &fakeConn{recvData: mustMarshalResp(t, &pb.RPCResponse{Id: "r"})}
	c := NewClient(fc)

	resp, err := c.Call(context.Background(), "ping", nil, nil)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if resp.ID != "r" {
		t.Errorf("resp.ID = %q, want %q", resp.ID, "r")
	}

	req, err := pb.UnmarshalRequest(fc.sent[0])
	if err != nil {
		t.Fatalf("UnmarshalRequest: %v", err)
	}
	if req.Handler != "ping" {
		t.Errorf("Handler = %q, want ping", req.Handler)
	}
	if req.Payload != nil {
		t.Errorf("Payload = %v, want nil", req.Payload)
	}
	if len(req.Context) != 0 {
		t.Errorf("Context = %v, want empty", req.Context)
	}
}

// TestCallResponseConversion drives Call across a range of server responses and
// asserts the pb.RPCResponse -> RPCResponse field mapping, including the
// LatencyNs -> time.Duration conversion and nil-vs-populated metadata handling.
func TestCallResponseConversion(t *testing.T) {
	cases := []struct {
		name        string
		resp        *pb.RPCResponse
		wantID      string
		wantSuccess bool
		wantPayload string
		wantErrStr  string
		wantLatency time.Duration
		wantMeta    map[string]string // nil => expect nil client metadata
	}{
		{
			name:        "success with payload and metadata",
			resp:        &pb.RPCResponse{Id: "resp-ok", Success: true, Payload: []byte(`{"status":"ok"}`), LatencyNs: int64(150 * time.Millisecond), Metadata: map[string]string{"node": "abc"}},
			wantID:      "resp-ok",
			wantSuccess: true,
			wantPayload: `{"status":"ok"}`,
			wantLatency: 150 * time.Millisecond,
			wantMeta:    map[string]string{"node": "abc"},
		},
		{
			name:        "handler failure carries error string",
			resp:        &pb.RPCResponse{Id: "resp-err", Success: false, Error: "handler exploded", LatencyNs: int64(2 * time.Second)},
			wantID:      "resp-err",
			wantSuccess: false,
			wantErrStr:  "handler exploded",
			wantLatency: 2 * time.Second,
			wantMeta:    nil,
		},
		{
			name:     "empty response yields zero-value fields",
			resp:     &pb.RPCResponse{},
			wantMeta: nil,
		},
		{
			name:        "multi-key metadata converts every entry",
			resp:        &pb.RPCResponse{Id: "m", Success: true, Metadata: map[string]string{"a": "1", "b": "2", "c": "3"}},
			wantID:      "m",
			wantSuccess: true,
			wantMeta:    map[string]string{"a": "1", "b": "2", "c": "3"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fc := &fakeConn{recvData: mustMarshalResp(t, tc.resp)}
			c := NewClient(fc)

			got, err := c.Call(context.Background(), "h", nil, nil)
			if err != nil {
				t.Fatalf("Call: %v", err)
			}
			if got.ID != tc.wantID {
				t.Errorf("ID = %q, want %q", got.ID, tc.wantID)
			}
			if got.Success != tc.wantSuccess {
				t.Errorf("Success = %v, want %v", got.Success, tc.wantSuccess)
			}
			if string(got.Payload) != tc.wantPayload {
				t.Errorf("Payload = %q, want %q", got.Payload, tc.wantPayload)
			}
			if got.Error != tc.wantErrStr {
				t.Errorf("Error = %q, want %q", got.Error, tc.wantErrStr)
			}
			if got.Latency != tc.wantLatency {
				t.Errorf("Latency = %v, want %v", got.Latency, tc.wantLatency)
			}
			if tc.wantMeta == nil {
				if got.Metadata != nil {
					t.Errorf("Metadata = %v, want nil", got.Metadata)
				}
			} else {
				if len(got.Metadata) != len(tc.wantMeta) {
					t.Fatalf("Metadata len = %d, want %d (%v)", len(got.Metadata), len(tc.wantMeta), got.Metadata)
				}
				for k, want := range tc.wantMeta {
					v, ok := got.Metadata[k]
					if !ok {
						t.Errorf("Metadata missing key %q", k)
						continue
					}
					s, ok := v.(string)
					if !ok {
						t.Errorf("Metadata[%q] type = %T, want string", k, v)
						continue
					}
					if s != want {
						t.Errorf("Metadata[%q] = %q, want %q", k, s, want)
					}
				}
			}
		})
	}
}

// TestCallWriteError verifies the write-path failure is wrapped with the
// "write request" prefix, preserves the underlying error via errors.Is, and
// short-circuits before any Receive is attempted.
func TestCallWriteError(t *testing.T) {
	sentinel := errors.New("transport send exploded")
	fc := &fakeConn{sendErr: sentinel}
	c := NewClient(fc)

	resp, err := c.Call(context.Background(), "h", []byte("x"), nil)
	if err == nil {
		t.Fatalf("Call returned nil error, want failure")
	}
	if resp != nil {
		t.Errorf("resp = %v, want nil on error", resp)
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("errors.Is(err, sentinel) = false; err = %v", err)
	}
	if !strings.Contains(err.Error(), "write request") {
		t.Errorf("err = %q, want it to mention %q", err.Error(), "write request")
	}
	if fc.recvCalls != 0 {
		t.Errorf("recvCalls = %d, want 0 (write failed first)", fc.recvCalls)
	}
}

// TestCallReadError verifies the read-path failure is wrapped with the
// "read response" prefix and preserves the underlying error.
func TestCallReadError(t *testing.T) {
	sentinel := errors.New("transport recv exploded")
	fc := &fakeConn{recvErr: sentinel}
	c := NewClient(fc)

	resp, err := c.Call(context.Background(), "h", []byte("x"), nil)
	if err == nil {
		t.Fatalf("Call returned nil error, want failure")
	}
	if resp != nil {
		t.Errorf("resp = %v, want nil on error", resp)
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("errors.Is(err, sentinel) = false; err = %v", err)
	}
	if !strings.Contains(err.Error(), "read response") {
		t.Errorf("err = %q, want it to mention %q", err.Error(), "read response")
	}
	if fc.sendCalls != 1 {
		t.Errorf("sendCalls = %d, want 1 (write succeeded before read)", fc.sendCalls)
	}
}

// TestCallMalformedResponse feeds bytes that are valid on the wire but not a
// decodable protobuf message; the unmarshal error must surface as a
// "read response" failure rather than a panic or silent zero value.
func TestCallMalformedResponse(t *testing.T) {
	// tag 0x0a = field 1, wire-type 2 (length-delimited); declared length 5
	// but only 1 payload byte follows -> proto.Unmarshal reports EOF.
	fc := &fakeConn{recvData: []byte{0x0a, 0x05, 0x01}}
	c := NewClient(fc)

	resp, err := c.Call(context.Background(), "h", nil, nil)
	if err == nil {
		t.Fatalf("Call returned nil error, want unmarshal failure")
	}
	if resp != nil {
		t.Errorf("resp = %v, want nil on error", resp)
	}
	if !strings.Contains(err.Error(), "read response") {
		t.Errorf("err = %q, want it to mention %q", err.Error(), "read response")
	}
}

// TestCallDeadlinePropagation checks the read context Call hands to Receive:
// with no caller deadline it must synthesize the documented 30s default, and
// with a caller deadline it must forward that exact deadline.
func TestCallDeadlinePropagation(t *testing.T) {
	t.Run("default 30s when caller has none", func(t *testing.T) {
		fc := &fakeConn{recvData: mustMarshalResp(t, &pb.RPCResponse{Id: "r"})}
		c := NewClient(fc)

		before := time.Now()
		if _, err := c.Call(context.Background(), "h", nil, nil); err != nil {
			t.Fatalf("Call: %v", err)
		}
		after := time.Now()

		if fc.lastRecvCtx == nil {
			t.Fatalf("Receive never captured a context")
		}
		dl, ok := fc.lastRecvCtx.Deadline()
		if !ok {
			t.Fatalf("read context has no deadline, want a synthesized 30s one")
		}
		// The default is now+30s computed inside Call, so the deadline must
		// land within [before+30s, after+30s].
		lo := before.Add(30 * time.Second)
		hi := after.Add(30 * time.Second)
		if dl.Before(lo.Add(-time.Second)) || dl.After(hi.Add(time.Second)) {
			t.Errorf("deadline = %v, want ~30s ahead (window %v..%v)", dl, lo, hi)
		}
	})

	t.Run("forwards caller deadline", func(t *testing.T) {
		fc := &fakeConn{recvData: mustMarshalResp(t, &pb.RPCResponse{Id: "r"})}
		c := NewClient(fc)

		// Far-future deadline so it never trips during the test.
		want := time.Now().Add(time.Hour)
		ctx, cancel := context.WithDeadline(context.Background(), want)
		defer cancel()

		if _, err := c.Call(ctx, "h", nil, nil); err != nil {
			t.Fatalf("Call: %v", err)
		}
		dl, ok := fc.lastRecvCtx.Deadline()
		if !ok {
			t.Fatalf("read context has no deadline")
		}
		if diff := dl.Sub(want); diff > time.Millisecond || diff < -time.Millisecond {
			t.Errorf("read deadline = %v, want %v (diff %v)", dl, want, diff)
		}
	})
}

// TestClose verifies Close delegates to the underlying session exactly once and
// returns whatever the session returns (nil or error).
func TestClose(t *testing.T) {
	t.Run("propagates nil", func(t *testing.T) {
		fc := &fakeConn{}
		c := NewClient(fc)
		if err := c.Close(); err != nil {
			t.Errorf("Close = %v, want nil", err)
		}
		if fc.closeCalls != 1 {
			t.Errorf("closeCalls = %d, want 1", fc.closeCalls)
		}
	})

	t.Run("propagates session error", func(t *testing.T) {
		sentinel := errors.New("close boom")
		fc := &fakeConn{closeErr: sentinel}
		c := NewClient(fc)
		if err := c.Close(); !errors.Is(err, sentinel) {
			t.Errorf("Close = %v, want %v", err, sentinel)
		}
		if fc.closeCalls != 1 {
			t.Errorf("closeCalls = %d, want 1", fc.closeCalls)
		}
	})
}

// TestCallSerialization asserts Call holds its mutex across the whole
// send/receive exchange: with many concurrent callers on one Client, the
// in-flight count (incremented on Send, decremented on Receive) must never
// exceed 1. Uses runtime.Gosched to encourage interleaving without wall-clock
// sleeps, and every caller must still get the correct converted response.
func TestCallSerialization(t *testing.T) {
	const goroutines = 24

	fixed := mustMarshalResp(t, &pb.RPCResponse{Id: "shared", Success: true, Payload: []byte("pong")})

	var cur, max int32
	fc := &fakeConn{
		sendHook: func(ctx context.Context, payload []byte) error {
			n := atomic.AddInt32(&cur, 1)
			for {
				m := atomic.LoadInt32(&max)
				if n <= m || atomic.CompareAndSwapInt32(&max, m, n) {
					break
				}
			}
			runtime.Gosched()
			return nil
		},
		recvHook: func(ctx context.Context) ([]byte, error) {
			runtime.Gosched()
			atomic.AddInt32(&cur, -1)
			return fixed, nil
		},
	}
	c := NewClient(fc)

	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := c.Call(context.Background(), "h", nil, nil)
			if err != nil {
				errs <- err
				return
			}
			if resp.ID != "shared" || !resp.Success || string(resp.Payload) != "pong" {
				errs <- errors.New("unexpected response under concurrency")
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent Call failed: %v", err)
	}

	if got := atomic.LoadInt32(&max); got != 1 {
		t.Errorf("max in-flight = %d, want 1 (Call must serialize send+receive)", got)
	}
	if fc.sendCalls != goroutines || fc.recvCalls != goroutines {
		t.Errorf("sendCalls=%d recvCalls=%d, want %d each", fc.sendCalls, fc.recvCalls, goroutines)
	}
}
