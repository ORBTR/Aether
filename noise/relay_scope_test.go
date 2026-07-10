//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package noise

import (
	"context"
	"net"
	"testing"

	aether "github.com/ORBTR/aether"
	"github.com/ORBTR/aether/relay"
)

// fakeExtConn is a minimal aether.Connection standing in for a WS/QUIC/gRPC
// bridge session. Send records the last frame it was handed; every other
// method is a no-op. AE-H-08 regression tests only exercise Send.
type fakeExtConn struct {
	nodeID   aether.NodeID
	lastSent []byte
	sendCnt  int
}

func (f *fakeExtConn) Send(_ context.Context, payload []byte) error {
	f.lastSent = append([]byte(nil), payload...)
	f.sendCnt++
	return nil
}
func (f *fakeExtConn) Receive(_ context.Context) ([]byte, error) { return nil, nil }
func (f *fakeExtConn) Close() error                              { return nil }
func (f *fakeExtConn) RemoteAddr() net.Addr                      { return nil }
func (f *fakeExtConn) RemoteNodeID() aether.NodeID               { return f.nodeID }
func (f *fakeExtConn) NetConn() net.Conn                         { return nil }
func (f *fakeExtConn) Protocol() aether.Protocol                 { return aether.Protocol(0) }
func (f *fakeExtConn) OnClose(func())                            {}

// newRelayTestTransport builds a NoiseTransport with relay enabled plus a live
// RelayService so external-bridge registration/lookup works in tests.
func newRelayTestTransport() *NoiseTransport {
	tr := newTestTransport()
	tr.relayService = relay.NewRelayService(relay.RelayConfig{Enabled: true}, nil)
	return tr
}

// TestHandleRelayRequest_ExternalScopeIsolation proves the AE-H-08 fix: a Noise
// peer relaying into an external (bridge) session is subject to the same scope
// isolation as the Noise→Noise path. Cross-scope is denied with
// ErrTenantMismatch and nothing is forwarded; same-scope and dedicated-mode
// (empty scope on either side) are forwarded verbatim.
func TestHandleRelayRequest_ExternalScopeIsolation(t *testing.T) {
	sourceNode := testNodeID("source")
	bridgeNode := testNodeID("bridge")
	data := []byte("payload")

	cases := []struct {
		name        string
		sourceScope string
		bridgeScope string
		wantErr     error
		wantSend    bool
	}{
		{"cross-scope blocked", "scope-1", "scope-2", relay.ErrTenantMismatch, false},
		{"same-scope allowed", "scope-1", "scope-1", nil, true},
		{"target dedicated allowed", "scope-1", "", nil, true},
		{"source dedicated allowed", "", "scope-2", nil, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := newRelayTestTransport()
			source := newTestNoiseConn(tc.sourceScope, sourceNode)
			fake := &fakeExtConn{nodeID: bridgeNode}
			tr.RegisterExternalSession(bridgeNode, fake, tc.bridgeScope)

			payload := buildRelayPayload(bridgeNode, data)
			err := tr.handleRelayRequest(source, payload)
			if err != tc.wantErr {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if tc.wantSend {
				if fake.sendCnt != 1 {
					t.Fatalf("expected exactly one forwarded frame, got %d", fake.sendCnt)
				}
				wantFrame := append(append([]byte(nil), []byte(sourceNode)...), data...)
				if string(fake.lastSent) != string(wantFrame) {
					t.Fatalf("forwarded frame = %q, want [sourceNode][data]", fake.lastSent)
				}
			} else if fake.sendCnt != 0 {
				t.Fatalf("blocked relay must not forward, but Send was called %d times", fake.sendCnt)
			}
		})
	}
}

// TestHandleExternalRelayFrame_ExternalToExternal_ScopeIsolation proves AE-H-08
// on the reverse bridge→bridge path: a frame originating from one external
// session may only reach another external session in a compatible scope.
func TestHandleExternalRelayFrame_ExternalToExternal_ScopeIsolation(t *testing.T) {
	srcBridge := testNodeID("srcBridge")
	dstBridge := testNodeID("dstBridge")
	data := []byte("payload")

	cases := []struct {
		name        string
		sourceScope string
		targetScope string
		wantErr     error
		wantSend    bool
	}{
		{"cross-scope blocked", "scope-1", "scope-2", relay.ErrTenantMismatch, false},
		{"same-scope allowed", "scope-1", "scope-1", nil, true},
		{"target dedicated allowed", "scope-1", "", nil, true},
		{"source dedicated allowed", "", "scope-2", nil, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := newRelayTestTransport()
			srcFake := &fakeExtConn{nodeID: srcBridge}
			dstFake := &fakeExtConn{nodeID: dstBridge}
			tr.RegisterExternalSession(srcBridge, srcFake, tc.sourceScope)
			tr.RegisterExternalSession(dstBridge, dstFake, tc.targetScope)

			frame := buildRelayPayload(dstBridge, data)
			err := tr.HandleExternalRelayFrame(srcBridge, frame)
			if err != tc.wantErr {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if tc.wantSend {
				if dstFake.sendCnt != 1 {
					t.Fatalf("expected exactly one forwarded frame, got %d", dstFake.sendCnt)
				}
				wantFrame := append(append([]byte(nil), []byte(srcBridge)...), data...)
				if string(dstFake.lastSent) != string(wantFrame) {
					t.Fatalf("forwarded frame = %q, want [srcBridge][data]", dstFake.lastSent)
				}
			} else if dstFake.sendCnt != 0 {
				t.Fatalf("blocked relay must not forward, but Send was called %d times", dstFake.sendCnt)
			}
		})
	}
}

// TestHandleExternalRelayFrame_ToNoise_ScopeIsolation proves AE-H-08 on the
// bridge→Noise path: an external session in scope-1 cannot relay into a Noise
// session bound to scope-2. Only the isolation (deny) case is asserted here —
// the accept-and-deliver path requires a live cipher state and is covered by
// the cipher-free bridge→bridge test above.
func TestHandleExternalRelayFrame_ToNoise_ScopeIsolation(t *testing.T) {
	srcBridge := testNodeID("srcBridge")
	noiseTarget := testNodeID("noiseTarget")
	data := []byte("payload")

	tr := newRelayTestTransport()
	tr.RegisterExternalSession(srcBridge, &fakeExtConn{nodeID: srcBridge}, "scope-1")
	addListenerSession(tr, "scope-2", noiseTarget, newTestNoiseConn("scope-2", noiseTarget))

	frame := buildRelayPayload(noiseTarget, data)
	err := tr.HandleExternalRelayFrame(srcBridge, frame)
	if err != relay.ErrTenantMismatch {
		t.Fatalf("expected ErrTenantMismatch for cross-scope bridge→Noise relay, got: %v", err)
	}
}
