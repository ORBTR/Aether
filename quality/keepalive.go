/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package quality

import "time"

// KeepaliveInputs is what one keepalive decision reads: the round-trip measurements
// the keepalive's own answered probes produced. The session keepalive fills it from
// the session's health.Monitor (SRTT, RTO, SampleCount) and the WebSocket transport
// from the estimator it feeds with its ping and pong times, so both decide from the
// path they measured and never from the transport or grade the session runs on.
type KeepaliveInputs struct {
	// SRTT is the smoothed round-trip time; zero before the first answered probe.
	SRTT time.Duration
	// RTO is the probe timeout the estimator derives (SRTT plus four mean
	// deviations, clamped); zero when no estimator exists.
	RTO time.Duration
	// Samples is how many answered probes SRTT and RTO were estimated from.
	Samples uint64
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
	// keepaliveRetryGap is the wait between probes once one has gone unanswered, so a
	// silent peer is found within Strikes probe timeouts rather than Strikes intervals.
	keepaliveRetryGap = 1 * time.Second
)

// Keepalive derives one probe cycle's plan from the measurements in in:
// Interval = clamp(2·SRTT, 5 s, 30 s), roughly one round trip plus jitter between
// probes; ProbeTimeout = clamp(4·RTO, 1 s, 15 s), with a 5 s floor until the
// estimator has 8 samples; 5 strikes; a 1 s gap between retries. A zero SRTT or RTO
// (no answered probe yet, or no estimator) takes the floor. It is a pure function of
// its inputs, so two sessions with the same measurements get the same plan and two with
// different measurements get plans that follow them.
func Keepalive(in KeepaliveInputs) KeepalivePlan {
	interval := clampDuration(2*in.SRTT, keepaliveIntervalFloor, keepaliveIntervalCeiling)
	probeFloor := keepaliveProbeFloor
	if in.Samples < keepaliveWarmupSamples {
		probeFloor = keepaliveProbeWarmupFloor
	}
	probe := clampDuration(4*in.RTO, probeFloor, keepaliveProbeCeiling)
	return KeepalivePlan{
		Interval:     interval,
		ProbeTimeout: probe,
		Strikes:      keepaliveStrikes,
		RetryGap:     keepaliveRetryGap,
	}
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
