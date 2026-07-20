/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"bytes"
	"compress/flate"
	"context"
	"fmt"
	"io"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/abuse"
	"github.com/ORBTR/aether/congestion"
)

// writeLoop reads from the scheduler and writes frames to the Noise
// connection. Uses the pacer for rate-limited sending (supports both
// CUBIC and BBR). Parks on the scheduler's wake channel instead of
// polling — polling with time.Sleep(1ms) adds ~0.5 ms latency to every
// send and burns CPU when idle.
//
// A single goroutine owns writeLoop, so the local pacingTimer below
// is goroutine-private: no synchronisation needed. Reusing one
// *time.Timer across every paced frame avoids a per-frame runtimeTimer
// + channel allocation (~96 B + GC pressure under high-throughput
// bandwidth-limited streams). Go 1.23+ Timer semantics let us Reset
// without manual channel draining.
func (s *NoiseSession) writeLoop() {
	wake := s.sched.WakeCh()
	var pacingTimer *time.Timer
	// OBS-4 cubicCwndBlock_us: when CUBIC.CanSend returns false the
	// writeLoop re-enqueues + parks. We mark the wall-clock at first
	// rejection (cwndBlockStart non-zero), and on the next successful
	// CanSend we record the elapsed block duration. Single time.Time on
	// the goroutine stack — no atomic / mutex needed because writeLoop
	// is single-goroutine.
	var cwndBlockStart time.Time
	defer func() {
		if pacingTimer != nil {
			pacingTimer.Stop()
		}
		// Flush any in-progress cwnd-blocked duration into the
		// histogram on terminal exit. Without this the OBS-4 dashboard
		// is blind to exactly the case it exists to surface: a session
		// that black-holed long enough for the connection manager to
		// tear it down (CloseSignal fires while CanSend stays false).
		if !cwndBlockStart.IsZero() {
			s.cwndBlockHist.Record(time.Since(cwndBlockStart))
		}
	}()
	for {
		// Drain everything currently scheduled before re-parking.
		for {
			select {
			case <-s.CloseSignal():
				return
			default:
			}

			frame, isProbe := s.sched.Dequeue()
			if frame == nil {
				break // empty — fall through to park on wake/closed
			}

			frameSize := int(aether.HeaderSize) + int(frame.Length)

			// RFC 8985 §7.5: TLP loss probes MUST be transmitted outside
			// the congestion window so they can recover from cwnd-collapse
			// deadlocks. Without this bypass, a stream that has driven its
			// cwnd to zero through losses cannot send the very probe that
			// would elicit an ACK and reopen the window — leading to the
			// fleet-wide `tlp{scheduledIn=-29s probePending=true probes=1}`
			// wedge we saw in production. Regular frames still respect
			// CanSend (and re-enqueue + park until cwnd advances).
			//
			// CanSend's contract is `inFlight < cwnd` — pass cumulative
			// in-flight bytes across the session's streams plus the
			// prospective frameSize. Passing frameSize alone would make
			// CanSend ≡ true (frameSize ≪ cwnd) and disable CUBIC entirely.
			if !isProbe {
				inFlightBytes := s.totalInFlightBytes()
				if !s.congestion().CanSend(inFlightBytes + int64(frameSize)) {
					// Re-enqueue puts the frame back. Enqueue already calls
					// signalWake() internally so the writeLoop is re-armed
					// for its next park. The explicit Wake() below is
					// belt-and-suspenders against a park/wake race in the
					// scheduler: if another goroutine drained the wake
					// channel between Enqueue and the parking select below,
					// the writeLoop would otherwise wait for the next
					// external wake. Wake() is a non-blocking buffered send
					// (capped at 1); duplicates collapse and the call is cheap.
					s.sched.Enqueue(frame.StreamID, frame)
					atomic.AddUint64(&s.cansendFalseReenqueues, 1)
					// OBS-4: mark block-entry on the first reject in a
					// run. Subsequent rejects keep the earlier start so
					// the histogram captures the full cwnd-blocked
					// duration, not just the per-iteration retry cost.
					if cwndBlockStart.IsZero() {
						cwndBlockStart = time.Now()
					}
					s.sched.Wake()
					break
				}
				// CanSend returned true; if we were in a block run, close
				// it and record the duration. Reset cwndBlockStart so the
				// next run starts a fresh measurement.
				if !cwndBlockStart.IsZero() {
					s.cwndBlockHist.Record(time.Since(cwndBlockStart))
					cwndBlockStart = time.Time{}
				}
			}

			// Pacing: park exactly as long as the pacer says. Use the
			// session-scoped pacingTimer (allocated on first use) to
			// avoid a per-frame timer allocation that time.After would
			// otherwise incur on every paced send.
			wait := s.pacer.TimeUntilSend(frameSize)
			if wait > 0 {
				// AER-079: preserve probe status across a pacing deferral. A
				// TLP probe re-enqueued via plain Enqueue re-emerges with
				// isProbe=false and is then trapped behind the CanSend gate —
				// the exact cwnd-collapse the RFC 8985 §7.5 bypass exists to
				// escape. In the degraded-BBR regime (per-frame waits > PTO)
				// the probe would never reach the wire, converting a
				// recoverable tail loss into a session stall.
				if isProbe {
					s.sched.EnqueueProbe(frame.StreamID, frame)
				} else {
					s.sched.Enqueue(frame.StreamID, frame)
				}
				if pacingTimer == nil {
					pacingTimer = time.NewTimer(wait)
				} else {
					pacingTimer.Reset(wait)
				}
				select {
				case <-pacingTimer.C:
				case <-s.CloseSignal():
					return
				}
				continue
			}

			s.pacer.OnSend(frameSize)

			// OBS-10 cwnd-util permille: sample inFlight/cwnd once per
			// cwndUtilSamplePeriod writes. The full-rate version would
			// add ~1.5% overhead per send (an extra atomic load + ring
			// push); a 1-in-16 sample keeps cost negligible while still
			// filling the 256-entry ring within ~10 seconds of sustained
			// sending — long enough to be representative of the cwnd
			// regime the session is operating in.
			if c := atomic.AddUint64(&s.cwndUtilCounter, 1); c%cwndUtilSamplePeriod == 0 {
				if cw := s.congestion().CWND(); cw > 0 {
					inFlight := s.totalInFlightBytes()
					ratio := (inFlight * 1000) / cw
					if ratio < 0 {
						ratio = 0
					}
					if ratio > 1000 {
						ratio = 1000
					}
					s.cwndUtilRing.Record(uint32(ratio))
				}
			}

			if s.opts.FrameLogging {
				dbgNoise.Printf("TX stream=%d type=%d seq=%d len=%d",
					frame.StreamID, frame.Type, frame.SeqNo, frame.Length)
			}
			s.writeFrame(frame)

			// Notify congestion controller of the send. CUBIC accumulates
			// prr_out for PRR; BBR's OnSend stamps a delivery-rate sample
			// internally. The returned sample is used by ACK paths that
			// already stamp BBRSample on SendEntry — handled in the
			// upstream send-path that owns the SendEntry pointer (here we
			// only see the frame, not the entry, so we just notify).
			_ = s.congestion().OnSend(int64(frameSize))

			// Update pacer rate from congestion controller after each send.
			// Clamp controller pacing rate into the safe envelope
			// (congestion.ClampPacingRate) so a buggy/subverted
			// controller returning 0 or +Inf cannot lock the pacer at
			// "never send" or "never wait". A return of 0 is preserved
			// as the "pacing disabled" sentinel (CUBIC returns 0
			// intentionally to mean no pacing); any non-zero raw value
			// outside [MinPacingRate, MaxPacingRate] is clamped and
			// surfaced via dbgNoise so a misbehaving controller is
			// visible in debug builds rather than silently corrupting
			// the pacer. After clamping, pacingRate is guaranteed > 0
			// for the SetRate call below — the > 0 guard preserves the
			// pacing-disabled sentinel without forwarding a zero rate.
			rawPacingRate := s.congestion().PacingRate()
			pacingRate := congestion.ClampPacingRate(rawPacingRate)
			if pacingRate != rawPacingRate {
				dbgNoise.Printf("pacing-rate clamped: raw=%g clamped=%g (min=%g max=%g)",
					rawPacingRate, pacingRate, congestion.MinPacingRate, congestion.MaxPacingRate)
			}
			if pacingRate > 0 {
				s.pacer.SetRate(pacingRate)
			}
		}

		// OBS-9 aether_scheduler_depth: sample queue depth at the
		// "queue drained, about to park" moment so the histogram
		// captures the idle tail of the depth distribution in
		// addition to the work-arrives samples that signalWake
		// pushes inside the scheduler. Cost is one atomic.Load + one
		// mutex'd uint32 store — well under 100 ns and dominated by
		// the upcoming park anyway.
		s.sched.ObserveDepth()

		// Park until either new work arrives or the session closes.
		// OBS-2 aether_writeloop_park_us: time the writeLoop spent
		// blocked on the wake channel. High p99 here is the canonical
		// "no work, idle" signal — bimodal latency in this histogram
		// (low p50 with very long p99 spikes) usually means individual
		// frames arrive in clumps separated by long idle gaps, which
		// rules in app-side send pacing as the source of bimodality.
		//
		// cwnd-blocked busy-spin guard: when we just rejected a frame
		// in the inner loop (cwndBlockStart != zero), the re-Enqueue
		// path called signalWake AND we ourselves called Wake() — so
		// the wake channel holds a self-induced signal. Parking on it
		// fires immediately, we re-dequeue the same frame, CanSend
		// still returns false, repeat. Live capture showed 19,116,308
		// cansend_false_reenqueues vs 17 frames_sent (>1M:1 reject:send
		// ratio) — the writeLoop was burning CPU spinning against its
		// own wake. Fix: drain the self-wake, then park with a 1ms
		// timer arm so an ACK that arrives (via noise_dispatch.go:546
		// Wake()) still wakes us instantly, but absent any external
		// signal we re-check CanSend at 1kHz instead of MHz. The timer
		// also gives congestion-controller timer-driven advances a
		// chance to fire before our retry.
		parkStart := time.Now()
		if !cwndBlockStart.IsZero() {
			select {
			case <-wake: // drain self-induced wake
			default:
			}
			timer := time.NewTimer(cwndBlockedProbeInterval)
			select {
			case <-s.CloseSignal():
				timer.Stop()
				return
			case <-wake:
				timer.Stop()
			case <-timer.C:
			}
		} else {
			select {
			case <-s.CloseSignal():
				return
			case <-wake:
			}
		}
		s.writeloopParkHist.Record(time.Since(parkStart))
	}
}

// cwndBlockedProbeInterval bounds the writeLoop's CanSend retry rate
// when cwnd is blocking. 1ms gives ACKs (which wake via signalWake)
// instant priority while preventing the self-wake busy-spin observed
// in fleet capture (19M reject events / 17 frames sent — >1M:1 ratio).
// Tuned conservative: lower values risk spin-amplification; higher
// values delay legitimate cwnd-recovery beyond a typical SRTT.
const cwndBlockedProbeInterval = 1 * time.Millisecond

// cwndUtilSamplePeriod governs the per-N-writes sampling rate of OBS-10.
// 16 keeps cost negligible (single atomic add per write, ring push on
// every 16th) while still filling the 256-entry ring within ~10s of
// sustained sending. Power-of-two so the modulo compiles to a mask.
const cwndUtilSamplePeriod = 16

// totalInFlightBytes returns the session-wide in-flight byte count
// across every stream's SendWindow.
//
// Fast path: a single atomic.Load on the session-level counter that
// each SendWindow maintains as a side effect of Add/Ack (wired by
// SetSessionInFlightCounter in createStream). Per-send cost is O(1)
// — versus an O(streams × map-iteration + per-stream-lock) walk if
// it had to fold each window's InFlightBytes() directly.
//
// Negative results are clamped to zero defensively: a non-zero return
// is impossible from a correctly-wired SendWindow set, but the clamp
// keeps CanSend's invariant (inFlight >= 0) intact even under future
// audit regressions.
func (s *NoiseSession) totalInFlightBytes() int64 {
	v := s.inFlightBytes.Load()
	if v < 0 {
		return 0
	}
	return v
}

// reliabilityTick checks for retransmission timeouts periodically.
//
// Lock discipline: previously this function held s.mu across the full
// stream iteration (potentially 50+ streams). Inbound ACK frames hitting
// handleACK during that window blocked on s.mu, and the resulting
// readLoop stall caused the per-session noiseConn.inbox to fill, which
// caused the noise listener to drop inbound packets — including ACKs.
// Result: fleet-wide ACK starvation (sendBase=0, progressAge=n/a) while
// session-level Pings (handled pre-aether at the noise transport layer)
// continued to work.
//
// Fix: snapshot the stream list under a brief lock, then iterate without
// holding s.mu. Per-stream state is already atomic where the contention-
// sensitive readers (handleACK CAS loop, etc.) need it. session-level
// state (s.lastAnyProgressAt) is touched briefly under lock at the end.
func (s *NoiseSession) reliabilityTick() {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	var lastHealthDump time.Time
	// Emit a periodic TypeSTATS frame so peers can feed our observed
	// RTT/CWND/loss/etc. into their quality scorer. The receive handler
	// (handleStats in noise_dispatch.go) is paired with this 5s cadence.
	var lastStatsEmit time.Time
	type streamSnap struct {
		id uint64
		st *noiseStream
	}
	for {
		select {
		case <-s.CloseSignal():
			return
		case <-ticker.C:
			anyInFlight := false

			// Periodic per-stream health dump every 60s.
			emitHealth := time.Since(lastHealthDump) > 60*time.Second
			if emitHealth {
				lastHealthDump = time.Now()
			}

			// Periodic STATS frame emission every 5s. Lets the peer learn
			// our observed metrics (RTT/CWND/loss/etc.) for its quality
			// scorer. Off-band from per-stream ACK traffic so it never
			// delays an ACK; +34 bytes per peer every 5s ≈ 7B/s.
			//
			// INTENTIONAL: writeFrame is called directly (no pacer /
			// CanSend / scheduler.Enqueue). STATS is metadata about
			// session health, not data traffic — congestion control must
			// NEVER prevent the peer from learning our state. Same bypass
			// pattern as TLP probes (RFC 8985 §7.5): control-plane
			// signalling cannot be subject to the very congestion it is
			// used to diagnose.
			if time.Since(lastStatsEmit) > 5*time.Second {
				lastStatsEmit = time.Now()
				m := s.Metrics()
				statsFrame := &aether.Frame{
					SenderID:   s.LocalPeerID(),
					ReceiverID: s.RemotePeerID(),
					StreamID:   s.layout.Control,
					Type:       aether.TypeSTATS,
					Payload:    aether.EncodeStats(m),
				}
				statsFrame.Length = uint32(len(statsFrame.Payload))
				_ = s.writeFrame(statsFrame)
			}

			// Snapshot the stream list under a brief lock so we can
			// process per-stream work without contending with handleACK
			// / handleData / OpenStream which all acquire s.mu.
			s.mu.Lock()
			snap := make([]streamSnap, 0, len(s.streams))
			for streamID, st := range s.streams {
				snap = append(snap, streamSnap{id: streamID, st: st})
			}
			streamsCount := len(s.streams)
			s.mu.Unlock()

			if emitHealth {
				if dropper, ok := s.conn.(interface{ InboxDrops() uint64 }); ok {
					remoteShort := string(s.RemoteNodeID())
					if len(remoteShort) > 14 {
						remoteShort = remoteShort[:14] + "..."
					}
					log.Printf("[INBOX-HEALTH] peer=%s inboxDrops=%d streams=%d",
						remoteShort, dropper.InboxDrops(), streamsCount)
				}
			}

			tickNow := time.Now()
			mssBytes := int64(s.MSS())
			if mssBytes <= 0 {
				mssBytes = 1400
			}
			for _, e := range snap {
				streamID, st := e.id, e.st
				// RTO-driven retransmit (safety net). Pre-RACK, this path
				// also called OnLoss — every retransmit collapsed cwnd by
				// 30%, which produced the cwnd-stuck-at-floor pattern
				// FLOW-DIAG caught in production. RACK now owns the
				// loss-signal authority; RTO is just a re-send mechanism
				// for ACK-starved sessions where RACK has nothing to
				// work with (no fack established yet). BackoffRTO still
				// runs so the RTO interval grows on persistent loss.
				if frame := st.retransmitQ.Dequeue(); frame != nil {
					s.sched.MarkRetransmit(streamID)
					s.sched.Enqueue(streamID, frame)
					st.sendWindow.BumpXmitTime(frame.SeqNo, tickNow)
					// AER-065: back off at most once per RTO interval, not
					// once per retransmitted frame. A burst loss of N frames
					// drained one-per-tick otherwise doubled RTO N times,
					// pinning it at the 60s cap and stalling RTO-only recovery
					// for up to a minute (RFC 6298 §5.5 doubles once per
					// timeout event).
					if st.lastRTOBackoffAt.IsZero() || tickNow.Sub(st.lastRTOBackoffAt) >= st.rtt.RTO() {
						st.rtt.BackoffRTO()
						st.lastRTOBackoffAt = tickNow
					}
				}

				// Refresh RACK + TLP RTT estimates each tick so the
				// reorder window and probe timeout track current SRTT.
				srtt := st.rtt.SRTT()
				if srtt > 0 {
					st.rack.UpdateRTT(srtt)
					st.tlp.UpdateSRTT(srtt)
				}

				// RACK loss detection (RFC 8985). DetectLost returns the
				// seqs whose XmitTime is >= reoWnd older than fack — i.e.
				// presumed lost via time-based ordering rather than
				// dupack count. Each lost seq is bumped + re-enqueued and
				// we call OnLossWithPipe ONCE per tick (not once per
				// declared seq) — CUBIC's PRR seeds itself from the pipe
				// snapshot taken at this moment.
				inFlight := st.sendWindow.InFlight()
				if inFlight > 0 {
					anyInFlight = true
					rawSnap := st.sendWindow.SnapshotEntries()
					rackSnap := make([]congestion.SendEntrySnapshot, 0, len(rawSnap))
					for _, re := range rawSnap {
						rackSnap = append(rackSnap, congestion.SendEntrySnapshot{Seq: re.Seq, XmitTime: re.XmitTime})
					}
					lost, _ := st.rack.DetectLost(rackSnap, tickNow)
					if len(lost) > 0 {
						// OBS-11 aether_rack_marks_total: count only seqs
						// that were both RACK-flagged AND actually
						// retransmitted on the wire. RACK works off a
						// snapshot copy of the send window, so a
						// concurrent handleACK can evict entries between
						// DetectLost and GetEntry — those phantom marks
						// should NOT pollute the counter, otherwise the
						// TLP-vs-RACK ratio dashboard skews toward RACK
						// recovery under high ACK concurrency.
						pipe := int64(inFlight) * mssBytes
						var actuallyRetx uint64
						for _, seq := range lost {
							if entry := st.sendWindow.GetEntry(seq); entry != nil {
								s.sched.MarkRetransmit(streamID)
								s.sched.Enqueue(streamID, entry.Frame)
								st.sendWindow.BumpXmitTime(seq, tickNow)
								actuallyRetx++
							}
						}
						atomic.AddUint64(&s.rackMarksTotal, actuallyRetx)
						s.congestion().OnLossWithPipe(pipe)
					}

					// TLP — fire one probe outside cwnd if PTO elapsed
					// without an ACK. The probe is the highest in-flight
					// seq's frame (RFC 8985 §7.4: probe with the latest
					// data so the receiver's ACK reveals the gap).
					//
					// Use EnqueueProbe (NOT Enqueue) so the writeLoop's
					// CanSend gate is bypassed for this frame per §7.5 —
					// otherwise a collapsed cwnd traps the probe behind
					// the very condition it was meant to recover from.
					// Probes go into the per-stream probe slot in the
					// scheduler (at most one in flight, replaced on
					// re-arm), separate from the regular WFQ queue.
					probeFired := false
					if st.tlp.ShouldProbe(tickNow) {
						// AER-086: probe the highest REMAINING in-flight seq,
						// not strictly Next()-1. If that entry was selectively
						// ACKed/evicted, GetEntry returns nil and no probe ever
						// fired — recovery silently fell back to RTO. Scan down
						// to the highest still-in-flight entry.
						next := st.sendWindow.Next()
						base := st.sendWindow.Base()
						var probeFrame *aether.Frame
						var probeSeq uint32
						if next > base {
							for seq := next - 1; ; seq-- {
								if e := st.sendWindow.GetEntry(seq); e != nil {
									probeFrame, probeSeq = e.Frame, seq
									break
								}
								if seq == base {
									break
								}
							}
						}
						if probeFrame != nil {
							s.sched.EnqueueProbe(streamID, probeFrame)
							st.sendWindow.BumpXmitTime(probeSeq, tickNow)
							st.tlp.MarkProbeSent(probeSeq)
							// OBS-11 aether_tlp_fires_total: increment only when
							// a probe actually reaches the wire.
							atomic.AddUint64(&s.tlpFiresTotal, 1)
							probeFired = true
							log.Printf("[TLP] peer=%s stream=%d probeSeq=%d inFlight=%d cwnd=%d",
								s.RemoteNodeID().Short(), streamID, probeSeq, inFlight, s.congestion().CWND())
						}
					}

					// Re-arm TLP based on the freshest XmitTime in the
					// in-flight set. AER-080: if we fired a probe this tick its
					// XmitTime was bumped to tickNow — newer than anything in
					// the pre-probe snapshot — so seed `newest` with tickNow.
					// Re-arming from the stale snapshot left scheduledAt in the
					// past, firing probe #2 on the very next 10ms tick and
					// burning maxConsecutiveProbes into one loss burst.
					newest := time.Time{}
					if probeFired {
						newest = tickNow
					}
					for _, re := range rawSnap {
						if re.XmitTime.After(newest) {
							newest = re.XmitTime
						}
					}
					st.tlp.Arm(newest)
				} else {
					st.tlp.Disarm()
				}

				// Periodic per-stream health snapshot.
				if emitHealth {
					inFlight := st.sendWindow.InFlight()
					lastProgressNs := st.lastProgressAtUnixNano.Load()
					progressAge := "n/a"
					if lastProgressNs != 0 {
						progressAge = fmt.Sprintf("%v", time.Since(time.Unix(0, lastProgressNs)))
					}
					remoteShort := string(s.RemoteNodeID())
					if len(remoteShort) > 14 {
						remoteShort = remoteShort[:14] + "..."
					}
					log.Printf("[STREAM-HEALTH] peer=%s stream=%d inflight=%d sendBase=%d progressAge=%s",
						remoteShort, streamID, inFlight, st.sendWindow.Base(), progressAge)
				}

				// Credit-audit abuse signal: a peer that hoards granted
				// bandwidth without delivering data is either bug-broken
				// or actively stalling our receive path. The check
				// latches once per imbalance window so calling it on
				// every tick doesn't flood the scorer.
				if st.window != nil && st.window.CheckCreditAbuse() {
					s.reportAbuse(abuse.ReasonFlowControlAbuse)
					log.Printf("[CREDIT-ABUSE] peer=%s stream=%d sustained credit-vs-consume imbalance — reported",
						s.RemoteNodeID().Short(), streamID)
				}
			}

			// Session-level stall detector. Re-acquire lock briefly to
			// touch s.lastAnyProgressAt safely.
			stallThreshold := s.opts.SessionStallThreshold
			if stallThreshold == 0 {
				stallThreshold = aether.DefaultSessionStallThreshold
			}
			// Warmup grace: while the session is in its initial
			// lifetime window the effective threshold is doubled so a
			// freshly-installed session has time to demonstrate
			// stability before transient packet-loss bursts can
			// declare it stuck. Specifically targets the gossip-
			// migration race after a transport upgrade — see
			// SessionOptions.SessionWarmupGrace for the full
			// rationale. Negative warmup grace = caller explicitly
			// disabled the warmup (use the base threshold from t=0).
			warmupGrace := s.opts.SessionWarmupGrace
			if warmupGrace == 0 {
				warmupGrace = aether.DefaultSessionWarmupGrace
			}
			effectiveThreshold := stallThreshold
			if warmupGrace > 0 && time.Since(s.CreatedAt()) < warmupGrace {
				effectiveThreshold = stallThreshold * 2
			}
			s.mu.Lock()
			if s.lastAnyProgressAt.IsZero() {
				s.lastAnyProgressAt = time.Now()
			}
			// AER-002: reseed the progress clock when in-flight transitions
			// 0→N. lastAnyProgressAt otherwise advances only on ACK progress,
			// so a session idle past the stall threshold would trip the
			// detector on its first fresh frame — before any ACK could
			// arrive — falsely resetting cwnd and demoting a healthy path.
			if anyInFlight && !s.prevAnyInFlight {
				s.lastAnyProgressAt = time.Now()
			}
			s.prevAnyInFlight = anyInFlight
			lastProgressAt := s.lastAnyProgressAt
			s.mu.Unlock()
			sessionStuck := effectiveThreshold > 0 && anyInFlight &&
				time.Since(lastProgressAt) > effectiveThreshold
			if sessionStuck {
				// Probe-before-close: a stalled session might be a
				// transient false positive (CPU pause delayed our
				// processing of inbound ACKs, OR a short packet-loss
				// burst on a UDP path that recovers within seconds).
				// We send up to 3 Pings spaced 1 s apart; if any one
				// of them returns success the path is alive and we
				// reset the stall clock. Only if ALL three fail do we
				// declare the session stuck.
				//
				// Pre-v0.0.23 used a single Ping with a 2-second
				// timeout. On UDP paths with bursty loss (notably fly
				// cross-region anycast where a 200-ms blackout is
				// common) that single probe could land entirely in
				// the bad window and condemn an otherwise-healthy
				// session. The connection manager would then mark
				// noise-udp failed for 30 s-2 min, fall back to WS,
				// and the upgrade churn loop would dominate the
				// fleet's transport mix until the underlying loss
				// passed. Three 1-second probes cover ~3 s of wall
				// time which is long enough for typical fly loss
				// bursts to clear without being long enough to delay
				// genuine close-of-dead-session noticeably.
				const probeAttempts = 3
				const probeTimeout = 1 * time.Second
				const probeSpacing = 1 * time.Second
				probeOK := false
				var lastProbeErr error
				for attempt := 0; attempt < probeAttempts; attempt++ {
					probeCtx, probeCancel := context.WithTimeout(context.Background(), probeTimeout)
					_, lastProbeErr = s.Ping(probeCtx)
					probeCancel()
					if lastProbeErr == nil {
						probeOK = true
						break
					}
					if attempt < probeAttempts-1 {
						// Brief gap between probes so back-to-back
						// retries don't all hit the same loss burst.
						select {
						case <-time.After(probeSpacing):
						case <-s.CloseSignal():
							// Session was closed by another path
							// (e.g. external Close); stop probing.
							return
						}
					}
				}
				sessionAge := time.Since(s.CreatedAt())
				warmupActive := warmupGrace > 0 && sessionAge < warmupGrace
				if probeOK {
					s.mu.Lock()
					s.lastAnyProgressAt = time.Now()
					s.mu.Unlock()
					// Persistent-congestion exit (RFC 9002 §7.6 analog):
					// the path is provably alive because Ping returned, so
					// the cumulative OnLoss reductions that drove cwnd to
					// the floor were diagnosing transient loss as
					// persistent congestion. Restore cwnd so the
					// reliability layer can drain its in-flight backlog
					// instead of deadlocking on cwnd <= inFlight.
					//
					// Without this, every probe-rescue resets only the
					// stall clock — cwnd stays collapsed, reliability
					// can't make progress, the next stall fires within
					// effThresh again, and we loop until probe-before-
					// close eventually fails and the session is killed.
					prevCwnd := s.congestion().CWND()
					s.congestion().ResetCWND()
					newCwnd := s.congestion().CWND()
					// Reset per-stream TLP exhaustion counters. Without
					// this, streams whose `tlp.consecutiveProbes` reached
					// `maxConsecutiveProbes` during the loss burst that
					// triggered the stall stay frozen — `ShouldProbe()`
					// returns false forever, no further probes can fire,
					// and the cwnd we just restored is unusable because
					// reliability has no way to elicit an ACK.
					//
					// The session-level Pings that produced this
					// false-positive verdict ARE proof the path is alive,
					// which is exactly the signal `AnyAckReceived()` is
					// designed to consume (per `tlp.go` doc: "if real
					// data is being ACKed normally we don't want a stale
					// probe count to suppress future TLPs").
					var tlpResetCount int
					for _, e := range snap {
						state := e.st.tlp.Snapshot()
						if state.ConsecutiveProbes > 0 {
							e.st.tlp.AnyAckReceived()
							tlpResetCount++
						}
					}
					// Session-level false-positive observability — bump
					// even when no per-stream TLP needed resetting,
					// because the EVENT itself (cwnd-collapse + probe-
					// rescue) is the signal the multipath PathFlapping
					// demote tier consumes. See
					// SessionMetrics.TLPResetTotal docs +
					// multipath.Manager.RecordTLPReset.
					atomic.AddUint64(&s.tlpResetTotal, 1)
					log.Printf("[STALL-DETECT] false-positive peer=%s age=%v warmup=%v effThresh=%s cwnd=%d→%d tlpReset=%d (persistent-congestion exit)",
						s.RemoteNodeID().Short(), sessionAge, warmupActive, effectiveThreshold, prevCwnd, newCwnd, tlpResetCount)
					s.dumpFlowDiagOnStall("false-positive")
					// Wake the writeLoop so it re-evaluates CanSend with
					// the freshly-reset cwnd. Without this, the deadlock
					// would persist until the next external send.
					s.sched.Wake()
					continue
				}
				log.Printf("[STALL-DETECT] confirmed-stuck peer=%s age=%v warmup=%v effThresh=%s probesFailed=%d lastErr=%v — closing for fallback",
					s.RemoteNodeID().Short(), sessionAge, warmupActive, effectiveThreshold, probeAttempts, lastProbeErr)
				s.dumpFlowDiagOnStall("confirmed-stuck")
				s.CloseWithError(aether.ErrSessionStuck)
				return
			}

			// Per-stream stuck detector. STALL-DETECT above is session-
			// level: lastAnyProgressAt resets when ANY stream makes
			// progress, so a wedged stream-1 (BidiRPC) while stream-0
			// (gossip) ticks happily would never trip session-level
			// STALL-DETECT and the BidiRPC wedge could persist for
			// minutes.
			//
			// Per-stream rule: any stream with in-flight > 0 AND no
			// progress for stuckStreamThreshold while the SESSION is
			// healthy (some other stream just made progress) is
			// individually wedged. Reset that stream's TLP exhaustion
			// so probes can resume. Don't close the session — we have
			// evidence the path is alive via the other stream(s).
			const stuckStreamThreshold = 30 * time.Second
			nowNano := time.Now().UnixNano()
			for _, e := range snap {
				inFlight := e.st.sendWindow.InFlight()
				if inFlight == 0 {
					continue
				}
				lastProgressNs := e.st.lastProgressAtUnixNano.Load()
				if lastProgressNs == 0 {
					continue
				}
				if time.Duration(nowNano-lastProgressNs) < stuckStreamThreshold {
					continue
				}
				// Stream individually wedged. Reset its TLP so probes can
				// resume; the next ACK (or its absence) decides whether
				// the path is genuinely stuck or just under temporary
				// loss. Throttled to once per second per stream: the
				// 10ms reliability ticker would otherwise call
				// AnyAckReceived() on every iteration where TLP has just
				// re-armed a probe between ticks, producing a ~100Hz
				// reset/log loop on genuinely-stuck streams (observed
				// live on app-orbtr-io IAD under heavy 6PN loss).
				tlpState := e.st.tlp.Snapshot()
				if tlpState.ConsecutiveProbes > 0 {
					lastReset := e.st.lastStuckResetUnixNano.Load()
					if nowNano-lastReset >= int64(time.Second) &&
						e.st.lastStuckResetUnixNano.CompareAndSwap(lastReset, nowNano) {
						e.st.tlp.AnyAckReceived()
						log.Printf("[STREAM-STUCK-DETECT] peer=%s stream=%d inFlight=%d progressAge=%v tlpReset",
							s.RemoteNodeID().Short(), e.id, inFlight, time.Duration(nowNano-lastProgressNs))
					}
				}

				// [ACK-SILENT]: explicit warning when this stream has been
				// sending without ACK progress for >30s but TLP isn't
				// signalling anything wrong (e.g. no probes scheduled
				// because we already disarmed). One per stream per minute
				// so a wedge surfaces clearly without spamming the log.
				lastWarn := e.st.lastAckSilentLogUnixNano.Load()
				if nowNano-lastWarn > int64(time.Minute) &&
					e.st.lastAckSilentLogUnixNano.CompareAndSwap(lastWarn, nowNano) {
					log.Printf("[ACK-SILENT] peer=%s stream=%d inFlight=%d progressAge=%v sendBase=%d — no ACK progress",
						s.RemoteNodeID().Short(), e.id, inFlight,
						time.Duration(nowNano-lastProgressNs),
						e.st.sendWindow.Base())
				}
			}

			// PMTU probe timeout check + periodic re-probe (no s.mu needed)
			if s.pmtuProber.IsProbing() && s.pmtuProber.ProbeTimedOut() {
				s.pmtuProber.OnProbeTimeout()
			}
			if s.pmtuProber.ShouldReprobe() {
				s.pmtuProber.StartProbe()
			}

			// Idle session eviction. A session that hasn't seen any inbound
			// activity for idleTimeout has either been black-holed by the
			// network or the peer has gone silent — either way we should
			// reclaim the goroutines + memory instead of holding forever.
			// Without this, a slow-drip attacker who opens sessions and never
			// sends a byte pins resources indefinitely. The keepalive ticker
			// (separate subsystem) normally keeps LastActivity fresh on live
			// paths, so this threshold only trips on actually-dead sessions.
			idleTimeout := s.opts.SessionIdleTimeout
			if idleTimeout <= 0 {
				idleTimeout = aether.DefaultSessionIdleTimeout
			}
			if time.Since(s.Health().LastActivity()) > idleTimeout {
				s.CloseWithError(fmt.Errorf("session idle timeout (%s)", idleTimeout))
				return
			}

			// Flow-control auto-tune. Rate-limited to every 10s (the 10ms
			// tick is far too chatty for window adjustments). Disabled via
			// AETHER_AUTOTUNE=off. Feeds session RTT into each stream's
			// window then applies a bounded grow/shrink.
			if now := time.Now(); now.Sub(s.lastAutoTune) >= 10*time.Second {
				s.lastAutoTune = now
				s.autoTuneWindows()
			}

			// Periodic WINDOW_UPDATE re-emission — breaks the UDP-loss
			// deadlock where a dropped grant stalls the sender, the sender
			// stops producing data, no new threshold is crossed on our side,
			// no new grant fires, deadlock. Re-emitting the current cumulative
			// value from each active stream re-delivers any lost grant; the
			// peer's ApplyUpdate drops duplicates as stale, so this is
			// idempotent on happy paths.
			//
			// 2 s cadence: fast enough that a stalled sender recovers within
			// ConsumeTimeout (10 s), slow enough that wire overhead is
			// negligible (~30-byte frames, one per active stream).
			if now := time.Now(); now.Sub(s.lastGrantRefresh) >= 2*time.Second {
				s.lastGrantRefresh = now
				s.refreshWindowGrants()
			}

			// FEC decoder pruning (S2). Without this, FEC_REPAIR flooding
			// with unique GroupIDs causes unbounded memory growth.
			// Rate-limited to once per second so the 10ms tick stays cheap.
			// Both count-based (budget) and age-based (2×SRTT) pruning
			// must run — a slow trickle below the count cap still
			// accumulates memory over time.
			now := time.Now()
			if now.Sub(s.lastFECPrune) >= time.Second {
				maxGroups := s.opts.MaxFECGroups
				if maxGroups <= 0 {
					maxGroups = aether.DefaultMaxFECGroups
				}
				s.fecDecoder.Prune(maxGroups)
				s.interleavedDecoder.Prune(maxGroups)
				if s.rsDecoder != nil {
					s.rsDecoder.Prune(maxGroups)
				}

				// Age-based cutoff = 2×max(SRTT) across live streams, with
				// a floor to avoid over-pruning when RTT is unmeasured.
				// FEC recovery is useless after 2 RTTs — the sender's
				// retransmit will have already covered any missing frame.
				age := 2 * s.maxStreamSRTT()
				if age < 2*time.Second {
					age = 2 * time.Second
				}
				s.fecDecoder.PruneOlderThan(age)
				s.interleavedDecoder.PruneOlderThan(age)
				if s.rsDecoder != nil {
					s.rsDecoder.PruneOlderThan(age)
				}
				s.lastFECPrune = now
			}
		}
	}
}

// writeFrameDeadline bounds how long a single conn.Write inside
// writeFrame may block. conn.Write on a stream socket only blocks when
// the kernel send buffer is full — which only happens when the peer
// has stopped draining its receive side (an asymmetric path failure).
// A healthy socket's Write returns in microseconds, so a 10s ceiling
// never trips on a working link, but it caps the damage when a peer
// goes silent: keepalive Ping writes a PING frame before polling for
// the pong, and without this bound that write would hang for the full
// OS TCP retransmit window (~15-30s observed), dragging keepalive
// death detection out to 60-90s. With the bound, a stuck write fails
// fast and the session is torn down deterministically.
const writeFrameDeadline = 10 * time.Second

// writeDeadlineConn is the subset of net.Conn writeFrame needs to bound
// its writes. Real sockets (WebSocket, TLS, UDP) satisfy it with an
// effective implementation; the StreamConn sub-stream adapter satisfies
// it with a no-op (its writes enqueue to the scheduler and never block)
// and grpc wrappers likewise — so the type assertion is always safe and
// the bound simply has no effect where blocking can't occur.
type writeDeadlineConn interface {
	SetWriteDeadline(time.Time) error
}

// connWrite writes b to the transport conn. On any write error — most
// importantly a write-deadline timeout from a stuck send buffer — it
// tears the session down: a partial frame left on the wire desyncs the
// peer's framing, so the session is unusable and must not be written to
// again. CloseWithError is closeOnce-guarded and idempotent, so calling
// it here is safe even if another path is closing concurrently.
//
// AE-H-02: the teardown is dispatched on its OWN goroutine, never called
// inline. connWrite only ever runs while writeFrame holds s.writeMu, and
// CloseWithError re-enters writeFrame on the same goroutine — via the
// connGrantDebouncer flush (-> sendWindowUpdate) and the acceptor backlog
// Reset (-> RESET frame). A synchronous call would re-acquire the
// non-reentrant writeMu on the goroutine that already holds it and
// self-deadlock, wedging every other writeFrame caller and leaking the fd
// (s.conn.Close is never reached). Deferring to a goroutine lets this
// writeFrame unwind and release writeMu before the teardown's re-entrant
// writeFrame calls acquire it. SignalClose collapses duplicate closes, so
// the spawned goroutine is a bounded no-op on all but the first, and the
// graceful-close paths (idle/stall/application Close) are untouched — the
// final grant + RESET frames still reach a live peer from those callers.
func (s *NoiseSession) connWrite(b []byte) error {
	// OBS-1 aether_write_syscall_us: time the actual syscall (or the
	// transport adapter's effective send path) so operators can see
	// when kernel send-buffer pressure / TLS encode / WS framing is the
	// latency source vs in-process scheduling. Single time.Now() pair on
	// the success path; on error path we skip the histogram record since
	// the duration is meaningless (the session is being torn down).
	start := time.Now()
	if _, err := s.conn.Write(b); err != nil {
		go s.CloseWithError(fmt.Errorf("aether: frame write failed: %w", err))
		return err
	}
	s.writeSyscallHist.Record(time.Since(start))
	return nil
}

// writeFrame serializes and writes a single frame to the Noise connection.
// Applies compression (if enabled and payload > 64 bytes) and encryption (if key set).
func (s *NoiseSession) writeFrame(frame *aether.Frame) error {
	// Per-session frame and byte counters consumed by Metrics(). Count
	// at attempt-time rather than at conn.Write success so the
	// "bytes the session tried to send" is what gets surfaced — the
	// difference vs at-success is negligible since writeFrame only
	// errors during teardown / panicked conn.
	s.framesSent.Add(1)
	if frame != nil {
		s.bytesSent.Add(uint64(frame.Length))
		// A4: feed the per-CE-interval cap. handleACK drains this counter
		// when the peer's CompositeACK carries CACKHasECN, using the
		// drained value as the upper bound on a plausible CEBytes claim.
		s.bytesSentSinceLastCE.Add(uint64(frame.Length))
	}
	// Compression + encryption are IDEMPOTENT on the frame object. The
	// crypto/aead.go Encrypt path mutates frame.Payload in place
	// (plaintext → ciphertext + 16B auth tag), and compressPayload does
	// the same for the compression flag. We MUST skip those steps on
	// retransmits — the frame in the send window is shared between the
	// original send, RACK retransmits, RTO retransmits, and TLP probes,
	// and re-encrypting an already-encrypted payload produces double-
	// ciphertext that the receiver decrypts once into ciphertext_v1
	// (not plaintext), failing pb.UnmarshalRequest with "invalid
	// wire-format data". The receiver dedups duplicate SeqNos at
	// recvWindow.Insert, so resending the cached ciphertext bytes
	// (same nonce, same payload) is the correct retransmit behavior.
	//
	// The flag check keeps writeFrame safe to call on a frame any number
	// of times; the first call transforms it, subsequent calls are no-ops
	// that send the cached bytes.
	// Compress + encrypt INSIDE writeMu so the check-then-act FlagCOMPRESSED/
	// FlagENCRYPTED guards execute atomically with the mutation. Was
	// H-Noise-Frame-Race: two concurrent goroutines (e.g. RACK retx
	// fighting the original send on the same Frame pointer) could each
	// pass the !FlagXXX check before either mutated Payload, then both
	// compressed/encrypted the same plaintext — second one corrupted
	// the buffer the receiver dedup eventually expects to match. The
	// re-order moves both check + mutation into the writeMu critical
	// section. CPU cost: compressPayload + Encrypt run under a lock
	// the writeLoop already holds for its conn.Write, so the wall-clock
	// per-frame budget is unchanged.
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if s.compressionEnabled.Load() && len(frame.Payload) > 64 && !frame.Flags.Has(aether.FlagCOMPRESSED) {
		compressed := compressPayload(frame.Payload)
		if len(compressed) < len(frame.Payload) { // only use if smaller
			frame.Payload = compressed
			frame.Length = uint32(len(compressed))
			frame.Flags = frame.Flags.Set(aether.FlagCOMPRESSED)
		}
	}

	// Encryption: encrypt payload if key set and enabled.
	// MUST be idempotent — see comment above. Re-encrypting already-
	// encrypted bytes was the root cause of fleet-wide "proto: cannot
	// parse invalid wire-format data" Unmarshal errors on RPC paths
	// where retransmits (TLP probes especially after aether v0.0.60's
	// back-to-back probe fix) re-ran this code on a sendWindow frame
	// whose Payload had already been swapped to ciphertext by the
	// first send.
	if s.encryptor != nil && s.opts.Encryption && !frame.Flags.Has(aether.FlagENCRYPTED) {
		if err := s.encryptor.Encrypt(frame); err != nil {
			return fmt.Errorf("aether encrypt: %w", err)
		}
	}

	// Bound every socket write for this frame. See writeFrameDeadline.
	// No-op on non-blocking conns (StreamConn / grpc); cleared on exit
	// so the deadline never leaks into the next writer's window.
	if dl, ok := s.conn.(writeDeadlineConn); ok {
		_ = dl.SetWriteDeadline(time.Now().Add(writeFrameDeadline))
		defer dl.SetWriteDeadline(time.Time{})
	}

	var buf bytes.Buffer
	if s.opts.HeaderComp {
		// Control frames (not encrypted, no payload) → 4 bytes
		if s.txCompressor.ShouldCompressControl(frame) {
			s.txCompressor.EncodeControlShort(&buf, frame)
			return s.connWrite(buf.Bytes())
		}
		// ACK frames → 11 bytes (lite) or 3+N (full)
		if s.txCompressor.ShouldCompressACK(frame) {
			s.txCompressor.EncodeACKShort(&buf, frame)
			return s.connWrite(buf.Bytes())
		}
		// Encrypted DATA → 9 bytes + Nonce-in-payload
		if frame.Flags.Has(aether.FlagENCRYPTED) && s.txCompressor.ShouldCompressData(frame) {
			s.txCompressor.EncodeEncryptedDataShort(&buf, frame)
			return s.connWrite(buf.Bytes())
		}
		// Unencrypted DATA → 6-9 bytes
		if s.txCompressor.ShouldCompressData(frame) {
			if frame.Length <= 127 {
				s.txCompressor.EncodeDataShortVar(&buf, frame)
			} else {
				s.txCompressor.EncodeDataShort(&buf, frame)
			}
			return s.connWrite(buf.Bytes())
		}
	}

	// Full 50-byte header (fallback)
	if _, err := aether.EncodeFrame(&buf, frame); err != nil {
		return err
	}
	s.txCompressor.RecordFullHeader(frame)
	return s.connWrite(buf.Bytes())
}

// flateWriterPool reuses flate.Writer (~32KB each) to avoid per-frame allocation.
// Writers are retargeted to io.Discard on Put so the pool doesn't keep the
// caller's buf alive between uses.
var flateWriterPool = sync.Pool{
	New: func() interface{} {
		w, _ := flate.NewWriter(io.Discard, flate.BestSpeed)
		return w
	},
}

// flateReaderPool reuses flate.Reader to avoid per-frame allocation.
// Readers are retargeted to an empty source on Put (same rationale).
var flateReaderPool = sync.Pool{
	New: func() interface{} {
		return flate.NewReader(bytes.NewReader(nil))
	},
}

// emptyFlateSource is a shared, immutable reader used to re-target pooled
// flate.Readers on Put so they don't retain the caller's input buffer.
var emptyFlateSource = bytes.NewReader(nil)

// putFlateWriter returns w to the pool after re-targeting it to io.Discard
// so the pool entry doesn't keep the compressed output buffer alive.
func putFlateWriter(w *flate.Writer) {
	w.Reset(io.Discard)
	flateWriterPool.Put(w)
}

// putFlateReader returns r to the pool after re-targeting it to an empty
// source so the pool entry doesn't keep the compressed input buffer alive.
func putFlateReader(r io.ReadCloser) {
	if resetter, ok := r.(flate.Resetter); ok {
		_ = resetter.Reset(emptyFlateSource, nil)
	}
	flateReaderPool.Put(r)
}

// compressPayload compresses data using DEFLATE (fast, standard library).
func compressPayload(data []byte) []byte {
	var buf bytes.Buffer
	w := flateWriterPool.Get().(*flate.Writer)
	w.Reset(&buf)
	if _, err := w.Write(data); err != nil {
		putFlateWriter(w)
		return data
	}
	if err := w.Close(); err != nil {
		putFlateWriter(w)
		return data
	}
	putFlateWriter(w)
	return buf.Bytes()
}

// decompressPayload decompresses DEFLATE data with a hard cap on output size
// to defeat compression-bomb attacks (a 64-byte DEFLATE stream can expand to
// GB; without a cap, a single peer frame can OOM the process). Reads one
// byte past the cap so over-limit input is detected rather than silently
// truncated.
func decompressPayload(data []byte) ([]byte, error) {
	r := flateReaderPool.Get().(io.ReadCloser)
	if resetter, ok := r.(flate.Resetter); ok {
		resetter.Reset(bytes.NewReader(data), nil)
	}
	limited := io.LimitReader(r, int64(aether.MaxPayloadSize)+1)
	result, err := io.ReadAll(limited)
	putFlateReader(r)
	if err != nil {
		return nil, err
	}
	if len(result) > aether.MaxPayloadSize {
		return nil, fmt.Errorf("aether: decompressed payload exceeds MaxPayloadSize (%d)", aether.MaxPayloadSize)
	}
	return result, nil
}
