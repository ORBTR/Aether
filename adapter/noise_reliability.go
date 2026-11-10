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
	"github.com/ORBTR/aether/quality"
)

// stallProbe is one probeStalled answer, read by reliabilityTick's stall detector:
// answered sends the session down its persistent-congestion exit, closed ends the
// tick loop, and neither closes the session with ErrSessionStuck, whose log line
// carries attempts and err.
type stallProbe struct {
	answered bool
	closed   bool
	attempts int
	err      error
}

// probeStalled asks a session the stall detector found without progress whether its
// path still answers before the detector declares anything: up to plan.Strikes pings
// of plan.ProbeTimeout each, plan.RetryGap apart, returning at the first answer. plan
// is the keepalive's own decision from the session's round trips, so a slow path is
// given the time its measurements call for and a stalled session is judged on the
// numbers the keepalive judges a silent peer on. Probing more than once matters on a
// datagram path whose loss comes in bursts: one probe can land wholly inside a burst
// and condemn a healthy session, and ErrSessionStuck is what the owning connection
// manager reads as "fall back to the next protocol grade" (SessionStallThreshold), while
// the quality tracker's dial cooldown for a failed path starts at 30 s and doubles per
// failure to a 10 min cap (dialCooldownDuration), so the path stays abandoned at least 30 s.
//
// ping is the session's Ping; the tests pass their own. A close from another path
// during a gap ends the probing with closed set.
func (s *NoiseSession) probeStalled(plan quality.KeepalivePlan, ping func(context.Context) (time.Duration, error)) stallProbe {
	var out stallProbe
	for out.attempts < plan.Strikes {
		probeCtx, cancel := context.WithTimeout(context.Background(), plan.ProbeTimeout)
		_, out.err = ping(probeCtx)
		cancel()
		out.attempts++
		if out.err == nil {
			out.answered = true
			return out
		}
		if out.attempts == plan.Strikes {
			return out
		}
		select {
		case <-time.After(plan.RetryGap):
		case <-s.CloseSignal():
			out.closed = true
			return out
		}
	}
	return out
}

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
//
// A frame the CanSend gate refuses or the pacer defers stays in held, private to
// this goroutine, and is tried again before anything else the scheduler has, TLP
// probes aside. Handing it back to Scheduler.Enqueue would put it behind the rest
// of its stream, so the frames reach the wire out of sequence and the peer reports
// gaps nothing lost, and Dequeue would charge the stream's WFQ deficit and the
// REALTIME and BULK counters once per attempt for one frame sent.
func (s *NoiseSession) writeLoop() {
	wake := s.sched.WakeCh()
	var pacingTimer *time.Timer
	// held, heldSize and heldPlain: the frame waiting on the gate or the pacer,
	// its prospective wire size and its length before deflate, so a retry does
	// not deflate it again.
	var held *aether.Frame
	var heldSize, heldPlain int64
	// cwndBlockHist: when CanSend returns false the writeLoop holds the
	// frame + parks. We mark the wall-clock at first rejection
	// (cwndBlockStart non-zero), and on the next successful CanSend we
	// record the elapsed block duration. Single time.Time on the goroutine
	// stack — no atomic / mutex needed because writeLoop is single-goroutine.
	var cwndBlockStart time.Time
	endCwndBlock := func() {
		if !cwndBlockStart.IsZero() {
			s.cwndBlockHist.Record(time.Since(cwndBlockStart))
			cwndBlockStart = time.Time{}
		}
	}
	defer func() {
		if pacingTimer != nil {
			pacingTimer.Stop()
		}
		// Flush any in-progress cwnd-blocked duration into the
		// histogram on terminal exit. Without this the cwnd-block readout
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

			var frame *aether.Frame
			var isProbe bool
			if held != nil {
				frame = s.sched.DequeueProbe()
				isProbe = frame != nil
				if frame == nil {
					frame = held
				}
			} else {
				frame, isProbe = s.sched.Dequeue()
			}
			if frame == nil {
				break // empty — fall through to park on wake/closed
			}

			st := s.sequencedFrameStream(frame)
			if frame == held && st == nil && sequencedFrame(frame) {
				// The stream left while its frame waited here. Scheduler.Unregister
				// dropped every frame still in the stream's queue for the same reason.
				held = nil
				endCwndBlock()
				continue
			}

			// recorded is the frame's wire count from its first write, 0 before
			// that, and recordedPlain the payload count its window entry holds.
			var recorded, recordedPlain int64
			if st != nil {
				recorded, recordedPlain = st.sendWindow.RecordedBytes(frame)
			}
			frameSize, plain := heldSize, heldPlain
			if frame != held {
				frameSize, plain = s.prepareFrame(frame, recorded, recordedPlain)
			}

			// RFC 8985 §7.5: TLP loss probes MUST be transmitted outside
			// the congestion window so they can recover from cwnd-collapse
			// deadlocks. Without this bypass, a stream that has driven its
			// cwnd to zero through losses cannot send the very probe that
			// would elicit an ACK and reopen the window: the TLP stays armed
			// past its scheduled time with probePending set, and this loop
			// parks forever. Regular frames still respect CanSend (and wait
			// in held until cwnd advances).
			//
			// CanSend's contract is `inFlight < cwnd` — pass the wire bytes
			// already written across the session's streams plus this frame's
			// wire size. Passing frameSize alone would make CanSend ≡ true
			// (frameSize ≪ cwnd) and disable CUBIC entirely.
			//
			// A retransmit's bytes are already in the counter at the count
			// frameSize presents, so they are taken out of other and counted once.
			//
			// With nothing else on the wire the frame goes whatever its size: no
			// ACK can come to open the window, and a frame can exceed it (PMTU's
			// MSS reaches 8000 against the controllers' 2800 floor).
			if !isProbe {
				other := s.totalInFlightBytes() - recorded
				if other > 0 && !s.congestion().CanSend(other+frameSize) {
					held, heldSize, heldPlain = frame, frameSize, plain
					atomic.AddUint64(&s.cansendFalseReenqueues, 1)
					// Mark block-entry on the first reject in a
					// run. Subsequent rejects keep the earlier start so
					// the histogram captures the full cwnd-blocked
					// duration, not just the per-iteration retry cost.
					if cwndBlockStart.IsZero() {
						cwndBlockStart = time.Now()
					}
					break
				}
				// CanSend returned true; if we were in a block run, close
				// it and record the duration.
				endCwndBlock()
			}

			// Pacing: park exactly as long as the pacer says. Use the
			// session-scoped pacingTimer (allocated on first use) to
			// avoid a per-frame timer allocation that time.After would
			// otherwise incur on every paced send.
			wait := s.pacer.TimeUntilSend(int(frameSize))
			if wait > 0 {
				// Preserve probe status across a pacing deferral. A TLP probe
				// that came back as a regular frame would be trapped behind
				// the CanSend gate — the exact cwnd-collapse the RFC 8985 §7.5
				// bypass exists to escape. In the degraded-BBR regime (per-frame
				// waits > PTO) the probe would never reach the wire, converting
				// a recoverable tail loss into a session stall.
				if isProbe {
					// The probe goes back only to the stream whose send window wrote
					// it and only while s.streams still holds that stream: a stream
					// reset and reopened under the ID since the probe was dequeued
					// would take it as a frame of its own sequence (queueProbe).
					if st != nil && st.sendWindow.WrittenFrame(frame.SeqNo) == frame {
						st.queueProbe(frame)
					}
				} else {
					held, heldSize, heldPlain = frame, frameSize, plain
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

			s.pacer.OnSend(int(frameSize))
			if frame == held {
				held = nil
			}

			// cwndUtilRing permille: sample inFlight/cwnd once per
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
			s.countFrameSent(plain)
			presented, newOnWire, err := s.writeQueuedFrame(frame, st)
			if err != nil {
				continue
			}

			// Notify congestion controller of the send, in the wire bytes its
			// acked count and pipe use. CUBIC accumulates prr_out for PRR, which
			// counts every write. BBR's OnSend adds to its inflight estimate, which
			// only an ACK takes back and one ACK ends a frame however many times it
			// was written, so BBR hears of a frame at its first write only, and not
			// of a frame its window has already removed. recordWrite stamps BBRSample
			// on the entry; the sample OnSend returns is not used.
			cc := s.congestion()
			if _, isBBR := cc.(*congestion.BBRController); !isBBR || newOnWire {
				_ = cc.OnSend(presented)
			}

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

		// Scheduler depth: sample queue depth at the
		// "queue drained, about to park" moment so the histogram
		// captures the idle tail of the depth distribution in
		// addition to the work-arrives samples that signalWake
		// pushes inside the scheduler. Cost is one atomic.Load + one
		// mutex'd uint32 store — well under 100 ns and dominated by
		// the upcoming park anyway.
		s.sched.ObserveDepth()

		// Park until either new work arrives or the session closes.
		// writeloopParkHist: time the writeLoop spent
		// blocked on the wake channel. High p99 here is the canonical
		// "no work, idle" signal — bimodal latency in this histogram
		// (low p50 with very long p99 spikes) usually means individual
		// frames arrive in clumps separated by long idle gaps, which
		// rules in app-side send pacing as the source of bimodality.
		//
		// cwnd-blocked park: when we just rejected a frame in the inner loop
		// (cwndBlockStart != zero), park with a 1 ms timer
		// (cwndBlockedProbeInterval) so an ACK that arrives (handleACK's
		// Wake() in noise_dispatch.go) still wakes us instantly, but absent
		// any external signal we re-check CanSend at 1 kHz. The timer also
		// gives congestion-controller timer-driven advances a chance to fire
		// before our retry, and covers a wake that fired before this park.
		parkStart := time.Now()
		if !cwndBlockStart.IsZero() {
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
// when cwnd is blocking. 1 ms gives ACKs (which wake via signalWake)
// instant priority while bounding the retry of the held frame in writeLoop's
// park. Lower values risk spin-amplification; higher values delay legitimate
// cwnd-recovery beyond a typical SRTT.
const cwndBlockedProbeInterval = 1 * time.Millisecond

// cwndUtilSamplePeriod governs the per-N-writes sampling rate of cwndUtilRing.
// 16 keeps cost negligible (single atomic add per write, ring push on
// every 16th) while still filling the 256-entry ring within ~10s of
// sustained sending. Power-of-two so the modulo compiles to a mask.
const cwndUtilSamplePeriod = 16

// totalInFlightBytes returns the session's wire bytes in flight across
// every stream's SendWindow: SendEntry.InFlightBytes summed over the
// entries written and not yet acked, the kind the controller's acked
// bytes and CanSend's prospective size are also in. The writeLoop adds
// the dequeued frame's wire size for CanSend; handleACK and the RACK
// tick pass it to the controller as the pipe.
//
// Fast path: a single atomic.Load on the session-level counter that
// each SendWindow charges at MarkWritten and releases at every removal
// (wired by SetSessionInFlightCounter in createStream). Per-send cost is
// O(1) — versus an O(streams × map-iteration + per-stream-lock) walk if
// it had to fold each window's InFlightBytes() directly.
//
// Negative results are clamped to zero defensively: every SendWindow
// releases exactly the count it charged (SendEntry.InFlightBytes), so a
// negative value does not arise from the wired set, and the clamp keeps
// CanSend's invariant (inFlight >= 0) intact should a SendWindow ever
// decrement past what it added.
func (s *NoiseSession) totalInFlightBytes() int64 {
	v := s.inFlightBytes.Load()
	if v < 0 {
		return 0
	}
	return v
}

// tickSnapshotTaken is a test seam, nil outside tests: reliabilityTick calls it with
// its session once it has taken its snapshot of s.streams and before it works on any
// stream in it, so a test can end a stream and open the next one under its ID there,
// as a RESET, its acknowledgment and a local open can between the two on a running
// session, and see what the tick then does with the ended stream it still holds.
var tickSnapshotTaken atomic.Pointer[func(*NoiseSession)]

// reliabilityTick checks for retransmission timeouts periodically.
//
// Lock discipline: the stream list is snapshotted under a brief s.mu and
// iterated without it. Holding s.mu across the full iteration (50+
// streams) would block handleACK on every inbound ACK frame for that
// window; the readLoop stall then fills the per-session noiseConn.inbox
// and the noise listener drops inbound packets, ACKs included — ACK
// starvation (sendBase=0, progressAge=n/a) while session-level Pings,
// handled below aether at the noise transport, still succeed. Per-stream
// state is atomic where the contention-sensitive readers (handleACK's CAS
// loop) need it; session-level state (s.lastAnyProgressAt) is touched
// briefly under the lock at the end.
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

			// A RESET no acknowledgment has answered is written again here,
			// outside the congestion window like STATS: it ends a stream the
			// peer still holds, and the ID it frees waits for it.
			s.retransmitResets(time.Now())

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
			if hook := tickSnapshotTaken.Load(); hook != nil {
				(*hook)(s)
			}

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
			for _, e := range snap {
				streamID, st := e.id, e.st
				// RTO-driven retransmit (safety net). This path does not
				// call OnLoss: RACK (DetectLost below) is the loss-signal
				// authority and calls OnLossWithPipe once per tick, so
				// cwnd reacts once per actual loss and not once per
				// retransmit attempt (under CUBIC each OnLoss cuts cwnd
				// to cubicBeta, 70%). RTO is just a re-send mechanism for
				// ACK-starved sessions where RACK has nothing to work
				// with (no fack established yet). BackoffRTO still runs
				// so the RTO interval grows on persistent loss.
				// A stream a RESET has taken out of s.streams (its snapshot entry
				// outlives the removal) is owed no retransmit, and its clocks are
				// left alone; queueRetransmit keeps its frame off a later stream that
				// has taken the ID.
				if frame := st.retransmitQ.Dequeue(); frame != nil {
					if st.queueRetransmit(frame) {
						st.sendWindow.BumpXmitTime(frame.SeqNo, tickNow)
						// Back off at most once per RTO interval, not once per
						// retransmitted frame: a burst loss of N frames drained
						// one-per-tick would otherwise double RTO N times, pinning
						// it at the 60s cap and stalling RTO-only recovery for up
						// to a minute (RFC 6298 §5.5 doubles once per timeout
						// event).
						if st.lastRTOBackoffAt.IsZero() || tickNow.Sub(st.lastRTOBackoffAt) >= st.rtt.RTO() {
							st.rtt.BackoffRTO()
							st.lastRTOBackoffAt = tickNow
						}
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
				// snapshot taken at this moment. Only written frames count: one
				// still queued has no transmission to time and no loss to declare,
				// and the session stall detector below must not read a backlog as
				// an unanswered send.
				rawSnap := st.sendWindow.SnapshotEntries()
				inFlight := len(rawSnap)
				if inFlight > 0 {
					anyInFlight = true
					rackSnap := make([]congestion.SendEntrySnapshot, 0, len(rawSnap))
					for _, re := range rawSnap {
						rackSnap = append(rackSnap, congestion.SendEntrySnapshot{Seq: re.Seq, XmitTime: re.XmitTime})
					}
					lost, _ := st.rack.DetectLost(rackSnap, tickNow)
					if len(lost) > 0 {
						// rackMarksTotal: count only seqs
						// that were both RACK-flagged AND actually
						// retransmitted on the wire. RACK works off a
						// snapshot copy of the send window, so a
						// concurrent handleACK can evict entries between
						// DetectLost and GetEntry — those phantom marks
						// should NOT pollute the counter, otherwise the
						// TLP-vs-RACK ratio dashboard skews toward RACK
						// recovery under high ACK concurrency.
						pipe := s.totalInFlightBytes()
						var actuallyRetx uint64
						for _, seq := range lost {
							if written := st.sendWindow.WrittenFrame(seq); written != nil {
								if st.queueRetransmit(written) {
									st.sendWindow.BumpXmitTime(seq, tickNow)
									actuallyRetx++
								}
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
						// Probe the highest REMAINING written seq, not strictly
						// Next()-1: that entry may be selectively ACKed, evicted,
						// or still queued behind the CanSend gate, and with no
						// probe recovery would fall back to RTO silently.
						probeFrame, probeSeq := st.sendWindow.HighestWritten()
						if probeFrame != nil && st.queueProbe(probeFrame) {
							st.sendWindow.BumpXmitTime(probeSeq, tickNow)
							st.tlp.MarkProbeSent(probeSeq)
							// tlpFiresTotal: increment only when
							// a probe actually reaches the wire.
							atomic.AddUint64(&s.tlpFiresTotal, 1)
							probeFired = true
							log.Printf("[TLP] peer=%s stream=%d probeSeq=%d inFlight=%d cwnd=%d",
								s.RemoteNodeID().Short(), streamID, probeSeq, inFlight, s.congestion().CWND())
						}
					}

					// Re-arm TLP based on the freshest XmitTime in the
					// in-flight set. If we fired a probe this tick its XmitTime
					// was bumped to tickNow — newer than anything in the
					// pre-probe snapshot — so seed `newest` with tickNow.
					// Re-arming from the stale snapshot would leave scheduledAt
					// in the past, firing probe #2 on the very next 10ms tick
					// and burning maxConsecutiveProbes into one loss burst.
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
			// Reseed the progress clock when in-flight transitions 0→N.
			// lastAnyProgressAt otherwise advances only on ACK progress,
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
				// probeStalled asks the path before anything is declared
				// and returns at the first answer.
				probe := s.probeStalled(aether.KeepalivePlanFor(s), s.Ping)
				if probe.closed {
					// Session was closed by another path (e.g. external
					// Close); stop probing.
					return
				}
				probeOK := probe.answered
				sessionAge := time.Since(s.CreatedAt())
				warmupActive := warmupGrace > 0 && sessionAge < warmupGrace
				if probeOK {
					s.mu.Lock()
					s.lastAnyProgressAt = time.Now()
					s.mu.Unlock()
					// Persistent-congestion exit (RFC 9002 §7.6 analog):
					// the path is provably alive because Ping returned, so
					// the loss behind the cumulative OnLoss reductions that
					// drove cwnd to the floor is transient, not persistent
					// congestion. Restore cwnd so the
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
					// which congestion/tlp.go's AnyAckReceived takes as
					// equivalent to an ACK: it clears the probe count so
					// a stale count stops suppressing ShouldProbe.
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
					s.RemoteNodeID().Short(), sessionAge, warmupActive, effectiveThreshold, probe.attempts, probe.err)
				s.dumpFlowDiagOnStall("confirmed-stuck")
				s.CloseWithError(aether.ErrSessionStuck)
				return
			}

			// Per-stream stuck detector. STALL-DETECT above is session-
			// level: lastAnyProgressAt resets when ANY stream makes
			// progress, so a wedged stream-1 (the RPC stream) while
			// stream-0 (gossip) ticks happily would never trip
			// session-level STALL-DETECT and the RPC-stream wedge could
			// persist for minutes.
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
				// reset/log loop on a stuck stream under heavy loss.
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
			// window then applies a bounded grow/shrink. The same cadence
			// sweeps the queues of departed streams (sweepEndedQueues).
			if now := time.Now(); now.Sub(s.lastAutoTune) >= 10*time.Second {
				s.lastAutoTune = now
				s.autoTuneWindows()
				s.sweepEndedQueues(now)
				s.sweepRecentlyLeft(now)
				s.sweepResetGrants(now)
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

			// FEC decoder pruning by age. Each stream's decoder bounds its groups
			// and bytes as they arrive (reliability.FECBudget); a slow trickle below
			// those bounds would still hold its memory for the stream's life.
			// Rate-limited to once per second so the 10ms tick stays cheap.
			now := time.Now()
			if now.Sub(s.lastFECPrune) >= time.Second {
				// Age-based cutoff = 2×max(SRTT) across live streams, with
				// a floor to avoid over-pruning when RTT is unmeasured.
				// FEC recovery is useless after 2 RTTs — the sender's
				// retransmit will have already covered any missing frame.
				age := 2 * s.maxStreamSRTT()
				if age < 2*time.Second {
					age = 2 * time.Second
				}
				for _, e := range snap {
					if e.st.fec != nil {
						e.st.fec.PruneOlderThan(age)
					}
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
// its writes. Every net.Conn has it, so writeFrame's type assertion always
// holds, and the bound is as real as the conn's own method. A socket
// (WebSocket, TLS, UDP) and the StreamConn sub-stream view return a Write
// blocked past the deadline, so a StreamConn Write waiting on flow-control
// credit ends at writeFrameDeadline too. A conn whose method does nothing,
// or fails (the gRPC conn wrapper returns an error wrapping
// os.ErrNoDeadline when the conn it wraps has no deadlines), leaves the
// Write unbounded; writeFrame ignores that error, because the frame still
// has to be written.
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
// The teardown is dispatched on its OWN goroutine, never called inline.
// connWrite only ever runs while writeFrame holds s.writeMu, and
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
	// writeSyscallHist: time the actual syscall (or the
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

// sequencedFrame reports whether a frame takes a sequence number from its stream's
// send window: DATA, and the CLOSE finishSend queues.
func sequencedFrame(frame *aether.Frame) bool {
	return frame.Type == aether.TypeDATA || frame.Type == aether.TypeCLOSE
}

// sequencedFrameStream returns the stream whose send window may hold frame, or nil
// for any other frame or a stream that has left s.streams. The write loop calls it
// per frame before the CanSend gate, which needs the frame's recorded count from that
// window, and passes the stream on to the write boundary.
func (s *NoiseSession) sequencedFrameStream(frame *aether.Frame) *noiseStream {
	if !sequencedFrame(frame) {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.streams[frame.StreamID]
}

// countFrameSent feeds Metrics()'s per-session frame and byte counters. Count
// at attempt-time rather than at conn.Write success so the "bytes the session
// tried to send" is what gets surfaced — the difference vs at-success is
// negligible since a write only errors during teardown / panicked conn. plain is the
// frame's payload length before deflate and encryption, for the payload-byte
// semantics these counters document, on a first write and on every retransmit
// alike; the write loop counts once per write, so a frame the gate or pacer kept
// back is counted when it goes, and writeFrame counts its caller's frame.
func (s *NoiseSession) countFrameSent(plain int64) {
	s.framesSent.Add(1)
	s.bytesSent.Add(uint64(plain))
}

// prepareFrame readies a frame the write loop took from the scheduler and returns
// the wire size CanSend and the pacer are given, and the frame's length before
// deflate for countFrameSent. A retransmit (recorded > 0) keeps the frame's
// committed form and presents the recorded wire count and recordedPlain, the
// payload count its window entry took at Add: its Length is the committed
// (deflated) length by then, which is not a payload count. A first write
// compresses here, before the gate, because deflate is the one step that changes
// the size by an amount only running it can tell; it advances no state, so a frame
// the gate refuses has committed nothing. Encryption and the header stay at the
// write: Encrypt takes a nonce and the short-form encoders advance the directional
// compressor, and neither may happen for a frame that is not written.
func (s *NoiseSession) prepareFrame(frame *aether.Frame, recorded, recordedPlain int64) (wire, plain int64) {
	if recorded > 0 {
		return recorded, recordedPlain
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	plain = int64(frame.Length)
	s.compressFrameLocked(frame)
	return s.wireSizeLocked(frame), plain
}

// wireSizeLocked predicts the bytes emitFrameLocked would write for a frame the
// scheduler holds (DATA or FEC_REPAIR, whose short forms are the data ones, or a
// CLOSE, whose short form is smaller than the full header counted for it) with
// the compressor as it stands, reading no state it would advance. Caller holds
// writeMu. Another writer's frame can change the header form before the write, so
// the count the frame is charged is the one emitFrameLocked measures.
func (s *NoiseSession) wireSizeLocked(frame *aether.Frame) int64 {
	length := int64(frame.Length)
	if s.encryptsLocked(frame) {
		// An encrypted frame always takes the full header
		// (Compressor.ShouldCompressData refuses FlagENCRYPTED).
		return int64(aether.FullFrameHeaderWireSize) + length + int64(s.encryptor.Overhead())
	}
	if s.opts.HeaderComp && s.txCompressor.ShouldCompressData(frame) {
		return int64(aether.ShortDataWireSize(frame.Length)) + length
	}
	return int64(aether.FullFrameHeaderWireSize) + length
}

// encryptsLocked reports whether emitFrameLocked will seal this frame, the
// conditions there and in FrameEncryptor.Encrypt (which seals no empty frame).
func (s *NoiseSession) encryptsLocked(frame *aether.Frame) bool {
	return s.encryptor != nil && s.opts.Encryption && !frame.Flags.Has(aether.FlagENCRYPTED) &&
		frame.Payload != nil && frame.Length != 0
}

// writeQueuedFrame writes a frame the write loop has prepared and returns the
// count the controller is shown for this write (noiseStream.recordWrite) and
// whether the write puts new bytes in flight: a frame's first write, or a frame no
// send window tracks. st is the frame's stream, nil for a frame no send window tracks.
func (s *NoiseSession) writeQueuedFrame(frame *aether.Frame, st *noiseStream) (int64, bool, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.emitFrameLocked(frame, st)
}

// writeFrame serializes and writes a single frame to the Noise connection, for a
// caller beside the write loop: the frame is the caller's own and no send window
// tracks it. Applies compression (if enabled and payload > 64 bytes) and encryption
// (if key set).
func (s *NoiseSession) writeFrame(frame *aether.Frame) error {
	s.countFrameSent(int64(frame.Length))
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
	// FlagENCRYPTED guards execute atomically with the mutation: a retransmit
	// re-presents the sendWindow entry's Frame pointer to writeFrame (the
	// RACK, RTO and NACK paths and the TLP probe enqueue entry.Frame again),
	// the receiver inflates and decrypts each copy once (processIncomingFrame),
	// so every copy must carry the bytes the first pass produced, and
	// writeFrame has callers beside the writeLoop (reliabilityTick's STATS
	// frame, Ping, the control handlers and Reset) while
	// FrameEncryptor.Encrypt advances the session's nonce counter, so the
	// flag check, the payload swap and the write stay inside the one lock
	// every caller takes. CPU cost: compressPayload + Encrypt run under a
	// lock the writeLoop already holds for its conn.Write, so the wall-clock
	// per-frame budget is unchanged.
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.compressFrameLocked(frame)
	_, _, err := s.emitFrameLocked(frame, nil)
	return err
}

// compressFrameLocked swaps the payload for its DEFLATE form when that is shorter.
// Caller holds writeMu. A PATH_PROBE frame is never compressed: its payload is
// zero padding sized from the path size the pmtu.Prober tests, which DEFLATE
// would shrink to a few bytes, so the probe and its echo would cross any path and
// the sweep would raise MSS to the largest size whatever the path carries.
func (s *NoiseSession) compressFrameLocked(frame *aether.Frame) {
	if frame.Type == aether.TypePATH_PROBE {
		return
	}
	if s.compressionEnabled.Load() && len(frame.Payload) > 64 && !frame.Flags.Has(aether.FlagCOMPRESSED) {
		compressed := compressPayload(frame.Payload)
		if len(compressed) < len(frame.Payload) { // only use if smaller
			frame.Payload = compressed
			frame.Length = uint32(len(compressed))
			frame.Flags = frame.Flags.Set(aether.FlagCOMPRESSED)
		}
	}
}

// emitFrameLocked encrypts and encodes a frame and writes it: the write boundary,
// where the committed length exists. Caller holds writeMu. With st non-nil the
// frame's write is recorded on the stream's send window before conn.Write, so an
// ACK that follows finds the charge made; a failed conn.Write closes the session,
// which ends the charge with it. It returns the count the controller is shown and
// whether the write puts new bytes in flight (writeQueuedFrame).
func (s *NoiseSession) emitFrameLocked(frame *aether.Frame, st *noiseStream) (int64, bool, error) {
	// Encryption: encrypt payload if key set and enabled.
	// MUST be idempotent — see comment above: a retransmit (RACK, RTO, a
	// TLP probe, which can follow one another back to back) re-runs this
	// code on a sendWindow frame whose Payload the first send already
	// swapped to ciphertext, and the FlagENCRYPTED check is what keeps the
	// second pass from sealing ciphertext again.
	if s.encryptor != nil && s.opts.Encryption && !frame.Flags.Has(aether.FlagENCRYPTED) {
		if err := s.encryptor.Encrypt(frame); err != nil {
			return 0, false, fmt.Errorf("aether encrypt: %w", err)
		}
	}

	// Bound every conn write for this frame; writeFrameDeadline says why
	// and writeDeadlineConn which conns honour it. Cleared on exit so the
	// deadline never leaks into the next writer's window.
	if dl, ok := s.conn.(writeDeadlineConn); ok {
		_ = dl.SetWriteDeadline(time.Now().Add(writeFrameDeadline))
		defer dl.SetWriteDeadline(time.Time{})
	}

	var buf bytes.Buffer
	if err := s.encodeFrameLocked(&buf, frame); err != nil {
		return 0, false, err
	}
	wire := int64(buf.Len())
	// Feed the per-CE-interval cap. handleACK drains this counter when the
	// peer's CompositeACK carries CACKHasECN, using the drained value as the
	// upper bound on a plausible CEBytes claim, in the unit congestion reads.
	s.bytesSentSinceLastCE.Add(uint64(wire))
	presented, newOnWire := wire, true
	if st != nil {
		presented, newOnWire = st.recordWrite(frame, wire)
	}
	return presented, newOnWire, s.connWrite(buf.Bytes())
}

// encodeFrameLocked writes frame's wire form to buf. Caller holds writeMu; the
// short forms and RecordFullHeader advance the directional compressor.
func (s *NoiseSession) encodeFrameLocked(buf *bytes.Buffer, frame *aether.Frame) error {
	if s.opts.HeaderComp {
		// Control frames (not encrypted, no payload) → 4 bytes
		if s.txCompressor.ShouldCompressControl(frame) {
			s.txCompressor.EncodeControlShort(buf, frame)
			return nil
		}
		// ACK frames → 11 bytes (lite) or 3+N (full)
		if s.txCompressor.ShouldCompressACK(frame) {
			s.txCompressor.EncodeACKShort(buf, frame)
			return nil
		}
		// Encrypted DATA → 9 bytes + Nonce-in-payload
		if frame.Flags.Has(aether.FlagENCRYPTED) && s.txCompressor.ShouldCompressData(frame) {
			s.txCompressor.EncodeEncryptedDataShort(buf, frame)
			return nil
		}
		// Unencrypted DATA → 6-9 bytes
		if s.txCompressor.ShouldCompressData(frame) {
			if frame.Length <= aether.ShortDataVarMaxLength {
				s.txCompressor.EncodeDataShortVar(buf, frame)
			} else {
				s.txCompressor.EncodeDataShort(buf, frame)
			}
			return nil
		}
	}

	// Full 50-byte header (fallback)
	if _, err := aether.EncodeFrame(buf, frame); err != nil {
		return err
	}
	s.txCompressor.RecordFullHeader(frame)
	return nil
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
