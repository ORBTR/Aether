/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package quality

import (
	"math"
	"time"
)

// KeepaliveInputs is what one keepalive decision reads: the round-trip, loss and
// stability measurements the keepalive's own probes produced. The session keepalive
// fills it from the session's health.Monitor (SRTT, RTO, SampleCount, ProbeLoss,
// Instability) and the WebSocket transport from the estimator it feeds with its ping
// and pong times, which measures no loss or instability and leaves both zero, so both
// decide from the path they measured and never from the transport or grade the session
// runs on.
type KeepaliveInputs struct {
	// SRTT is the smoothed round-trip time; zero before the first answered probe.
	SRTT time.Duration
	// RTO is the probe timeout the estimator derives (SRTT plus four mean
	// deviations, clamped); zero when no estimator exists.
	RTO time.Duration
	// Samples is how many answered probes SRTT and RTO were estimated from.
	Samples uint64
	// Loss is the smoothed fraction of probes that went unanswered on a path that
	// answered a later probe, from 0 to 1. A silence that ends the session is not
	// counted, so a dead peer's own misses never lengthen the bound it is let go
	// within. Zero when no probe has been lost or nothing is measured.
	Loss float64
	// Instability is one minus the path's stability: the smoothed jump between two
	// consecutive answered probes' round trips, as a fraction of SRTT, from 0 to 1.
	// Zero for a path whose round trips hold steady, or with fewer than two answers.
	Instability float64
}

// KeepalivePlan is the keepalive's decision for one probe cycle: how long a healthy
// session stays quiet between probes, how long one probe waits for an answer, and how
// many unanswered probes in a row end the session. aether.RunKeepalive probes on it and
// websocket.WSConn holds its pong deadline to Silence, so a peer that stops answering
// is let go on one derived bound at both layers. The Noise adapter's stall probe and
// multipath's standby probe take their budgets from it, and the quic package takes
// its connection keepalive and idle timeout from the plan for an unmeasured path.
type KeepalivePlan struct {
	Interval     time.Duration
	ProbeTimeout time.Duration
	Strikes      int
	RetryGap     time.Duration
}

// Silence is how long a peer may go unheard from the first unanswered probe before the
// keepalive ends the session: Strikes probes of ProbeTimeout each, with RetryGap
// between them.
func (p KeepalivePlan) Silence() time.Duration {
	return time.Duration(p.Strikes)*p.ProbeTimeout + time.Duration(p.Strikes-1)*p.RetryGap
}

// DeadPeerBound is the longest a peer that stops answering stays held after the last
// frame heard from it: at most one Interval until the probe that finds it silent, then
// Silence.
func (p KeepalivePlan) DeadPeerBound() time.Duration {
	return p.Interval + p.Silence()
}

const (
	// keepaliveIntervalFloor is the quietest a probe cycle starts at. The WebSocket
	// transport's own ping interval (websocket pingInterval) is sized under the idle
	// close of the HTTP edge proxies a worker's /ws socket crosses, and a session probe
	// slower than it on a new session would leave the estimator without samples for
	// longer than the socket carries pings.
	keepaliveIntervalFloor = 5 * time.Second
	// keepaliveIntervalCeiling bounds the quiet time on a slow, stable path so a peer
	// that vanishes is still found within a bounded DeadPeerBound.
	keepaliveIntervalCeiling = 30 * time.Second
	// keepaliveProbeFloor is the shortest a probe waits once the estimator has
	// converged; keepaliveProbeWarmupFloor is the wait before then. An estimator fed
	// fewer than keepaliveWarmupSamples answers is still dominated by its initial RTO
	// and the first samples' spread, so a 1 s wait would end a healthy new session on
	// one slow answer.
	keepaliveProbeFloor       = 1 * time.Second
	keepaliveProbeWarmupFloor = 5 * time.Second
	keepaliveProbeCeiling     = 15 * time.Second
	keepaliveWarmupSamples    = 8
	// keepaliveStrikes is how many probes in a row must go unanswered. One lost answer
	// on a datagram path, or a reliable transport retransmitting one, must not end a
	// session that is otherwise carrying traffic.
	keepaliveStrikes = 5
	// keepaliveStrikesCeiling bounds how far loss raises Strikes, so a lossy path's
	// dead peer is still let go within a bounded DeadPeerBound.
	keepaliveStrikesCeiling = 10
	// keepaliveFalseDeath is the chance a healthy peer on a lossy path is allowed of
	// losing Strikes probes in a row, which would end its session.
	keepaliveFalseDeath = 0.001
	// keepaliveRetryGap is the wait between probes once one has gone unanswered, so a
	// silent peer is found within Strikes probe timeouts rather than Strikes intervals.
	keepaliveRetryGap = 1 * time.Second
)

// Keepalive derives one probe cycle's plan from the measurements in in:
// Interval = clamp(2·SRTT, 5 s, 30 s), roughly one round trip plus jitter between
// probes; ProbeTimeout = clamp(4·RTO·(1+Instability), 1 s, 15 s), with a 5 s floor
// until the estimator has 8 samples, so a path whose round trips jump waits longer than
// its smoothed RTO trails them; Strikes = 5, raised on a lossy path to the fewest
// probes a healthy peer loses all of with chance at most 1 in 1000, at most 10; a 1 s
// gap between retries. A zero SRTT or RTO (no answered probe yet, or no estimator)
// takes the floor. It is a pure function of its inputs, so two sessions with the same
// measurements get the same plan and two with different measurements get plans that
// follow them.
func Keepalive(in KeepaliveInputs) KeepalivePlan {
	interval := clampDuration(2*in.SRTT, keepaliveIntervalFloor, keepaliveIntervalCeiling)
	probeFloor := keepaliveProbeFloor
	if in.Samples < keepaliveWarmupSamples {
		probeFloor = keepaliveProbeWarmupFloor
	}
	widen := 1 + clampFraction(in.Instability)
	probe := clampDuration(time.Duration(float64(4*in.RTO)*widen), probeFloor, keepaliveProbeCeiling)
	return KeepalivePlan{
		Interval:     interval,
		ProbeTimeout: probe,
		Strikes:      strikesFor(in.Loss),
		RetryGap:     keepaliveRetryGap,
	}
}

// strikesFor is how many unanswered probes in a row end a session on a path losing
// loss of its probes: the fewest whose all being lost has chance at most
// keepaliveFalseDeath, held between keepaliveStrikes and keepaliveStrikesCeiling.
func strikesFor(loss float64) int {
	loss = clampFraction(loss)
	if loss == 0 {
		return keepaliveStrikes
	}
	if loss >= 1 {
		return keepaliveStrikesCeiling
	}
	k := int(math.Ceil(math.Log(keepaliveFalseDeath) / math.Log(loss)))
	if k < keepaliveStrikes {
		return keepaliveStrikes
	}
	if k > keepaliveStrikesCeiling {
		return keepaliveStrikesCeiling
	}
	return k
}

// clampFraction holds f to [0, 1]; NaN reads as 0.
func clampFraction(f float64) float64 {
	if !(f > 0) {
		return 0
	}
	if f > 1 {
		return 1
	}
	return f
}

func clampDuration(d, lo, hi time.Duration) time.Duration {
	if d < lo {
		return lo
	}
	if d > hi {
		return hi
	}
	return d
}
