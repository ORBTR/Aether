//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// TestTCPSession_ACompressedFrameReachesItsConsumerInflated: a peer writes a DATA
// frame flagged FlagCOMPRESSED, its payload DEFLATE as the spec's flag says, and the
// consumer reads the message it inflates to. A frame so flagged whose payload does not
// inflate, or inflates past MaxPayloadSize, is refused as malformed and reaches no
// consumer, and the stream goes on carrying messages.
func TestTCPSession_ACompressedFrameReachesItsConsumerInflated(t *testing.T) {
	client, server := tcpPairWithOptions(t, aether.DefaultSessionOptions())
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	const id = 1150
	cs, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: id, Reliability: aether.ReliableOrdered})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := cs.Send(ctx, []byte("hello")); err != nil {
		t.Fatalf("send: %v", err)
	}
	ss, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if r := <-receiveAsync(ctx, ss, 5*time.Second); r.err != nil || string(r.data) != "hello" {
		t.Fatalf("first receive %q, %v", r.data, r.err)
	}
	compressed := func(payload []byte) *aether.Frame {
		return &aether.Frame{
			SenderID: client.LocalPeerID(), ReceiverID: client.RemotePeerID(), StreamID: id,
			Type: aether.TypeDATA, Flags: aether.FlagCOMPRESSED,
			Length: uint32(len(payload)), Payload: payload,
		}
	}

	msg := bytes.Repeat([]byte("a message DEFLATE shortens "), 20)
	if err := client.writeFrame(compressed(compressPayload(msg))); err != nil {
		t.Fatalf("write: %v", err)
	}
	if r := <-receiveAsync(ctx, ss, 5*time.Second); r.err != nil || !bytes.Equal(r.data, msg) {
		t.Fatalf("the consumer read %d bytes (%q...), %v; want the %d-byte message inflated", len(r.data), trimmed(r.data), r.err, len(msg))
	}

	// shortReset is a RESET flagged FlagCOMPRESSED whose payload inflates to fewer
	// bytes than a RESET payload holds, which Validate checks only once it is inflated.
	shortReset := compressed(compressPayload([]byte{0, 0, 0}))
	shortReset.Type = aether.TypeRESET
	for _, bad := range []struct {
		name  string
		frame *aether.Frame
	}{
		{"not DEFLATE", compressed([]byte("these bytes are no DEFLATE stream at all"))},
		{"past MaxPayloadSize", compressed(compressPayload(make([]byte, aether.MaxPayloadSize+1)))},
		{"a RESET short once inflated", shortReset},
	} {
		before := server.PeerAbuseScore()
		if err := client.writeFrame(bad.frame); err != nil {
			t.Fatalf("%s: write: %v", bad.name, err)
		}
		if err := cs.Send(ctx, []byte("after "+bad.name)); err != nil {
			t.Fatalf("%s: send: %v", bad.name, err)
		}
		if r := <-receiveAsync(ctx, ss, 5*time.Second); r.err != nil || string(r.data) != "after "+bad.name {
			t.Fatalf("%s: the consumer read %d bytes (%q...), %v; want only the message after it", bad.name, len(r.data), trimmed(r.data), r.err)
		}
		if server.PeerAbuseScore() <= before {
			t.Fatalf("%s: the refusal was not charged to the peer", bad.name)
		}
	}
}

func trimmed(b []byte) []byte {
	if len(b) > 24 {
		return b[:24]
	}
	return b
}
