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
	"time"
)

// TestAEL11_ResumePathIsRateLimited is the AE-L-11 regression guard. Before the
// fix, the resume (0xFA) branch in noiseListener.runReader (session.go) called
// handleResumePacket and `continue`d BEFORE the S6 throttles, so resume traffic
// was the only pre-auth path that skipped the per-source + global handshake
// flood limits. An attacker could spray 0xFA garbage from spoofed sources and
// burn responder CPU on ticket GCM.Open + per-datagram copies with no rate
// limit. The fix applies the same sourceLimit + rateLimiter guards the slow
// path uses, inside the resume branch.
//
// The test drives the real listener read loop over loopback UDP with a
// deterministic per-source limiter (burst 3, refillRate 0 = no token regen) and
// sends 10 garbage resume packets from one source. handleResumePacket emits
// exactly one reject byte per packet it processes, so counting reject replies
// measures how many packets got through:
//   - WITHOUT the fix: all 10 reach handleResumePacket -> ~10 rejects (> burst).
//   - WITH the fix:     the source limiter drops packets 4..10 -> <= burst rejects.
func TestAEL11_ResumePathIsRateLimited(t *testing.T) {
	const sends = 10
	const burst = 3

	// Deterministic per-source limiter. Constructed as a literal to force
	// refillRate=0 (newSourceLimiter clamps 0 up to its default rate), so no
	// tokens regenerate mid-test and exactly `burst` packets can pass.
	sl := &sourceLimiter{
		burst:      burst,
		refillRate: 0,
		maxEntries: 128,
		ttl:        time.Hour,
		buckets:    make(map[string]*sourceEntry),
	}
	// Global bucket sized so it never gates — isolates per-source behaviour.
	rl := newTokenBucket(1e9, 1e9, time.Second)

	tr := &NoiseTransport{
		maxPacket:   1500,
		sourceLimit: sl,
		rateLimiter: rl,
		// ticketStore left nil: handleResumePacket immediately rejects. The
		// point of the test is *whether* a packet reaches it, not the decode.
	}

	// Real loopback UDP socket for the listener; runReader reads it via ecnReader.
	lc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer lc.Close()
	srvAddr := lc.LocalAddr().(*net.UDPAddr)

	l := &noiseListener{transport: tr, conn: lc}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go l.runReader(ctx, lc)

	client, err := net.DialUDP("udp", nil, srvAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	// 0xFA prefix + junk. Junk fails any ticket decode -> no session created.
	garbage := make([]byte, 33)
	garbage[0] = resumePrefix
	for i := 1; i < len(garbage); i++ {
		garbage[i] = byte(i)
	}
	for i := 0; i < sends; i++ {
		if _, err := client.Write(garbage); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		time.Sleep(time.Millisecond) // pace so the single reader keeps up
	}

	// Count single-byte reject replies (0xF9). Read until a quiet gap.
	replies := 0
	reply := make([]byte, 8)
	for {
		_ = client.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		n, err := client.Read(reply)
		if err != nil {
			break // deadline elapsed: no more replies
		}
		if n == 1 && reply[0] == resumeRejectPrefix {
			replies++
		}
	}

	if replies < 1 {
		t.Fatalf("AE-L-11: reader processed no resume packets (0 rejects) — test did not exercise the path")
	}
	if replies > burst {
		t.Fatalf("AE-L-11: got %d reject replies, want <= burst (%d) — resume path is bypassing the S6 source limiter", replies, burst)
	}
}
