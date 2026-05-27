//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
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
	"time"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/congestion"
)

// writeLoop reads from the scheduler and writes frames to the Noise
// connection. Uses the pacer for rate-limited sending (supports both
// CUBIC and BBR). Parks on the scheduler's wake channel instead of
// polling — polling with time.Sleep(1ms) adds ~0.5 ms latency to every
// send and burns CPU when idle.
func (s *NoiseSession) writeLoop() {
	wake := s.sched.WakeCh()
	for {
		// Drain everything currently scheduled before re-parking.
		for {
			select {
			case <-s.CloseSignal():
				return
			default:
			}

			frame := s.sched.Dequeue()
			if frame == nil {
				break // empty — fall through to park on wake/closed
			}

			frameSize := int(aether.HeaderSize) + int(frame.Length)

			// Congestion window check — re-enqueue and wait for next ACK
			// (the ACK path will re-signal wake when it advances cwnd).
			if !s.congestion().CanSend(int64(frameSize)) {
				s.sched.Enqueue(frame.StreamID, frame)
				break
			}

			// Pacing: park exactly as long as the pacer says.
			wait := s.pacer.TimeUntilSend(frameSize)
			if wait > 0 {
				s.sched.Enqueue(frame.StreamID, frame)
				select {
				case <-time.After(wait):
				case <-s.CloseSignal():
					return
				}
				continue
			}

			s.pacer.OnSend(frameSize)

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

			// Update pacer rate from congestion controller after each send
			if pacingRate := s.congestion().PacingRate(); pacingRate > 0 {
				s.pacer.SetRate(pacingRate)
			}
		}

		// Park until either new work arrives or the session closes.
		select {
		case <-s.CloseSignal():
			return
		case <-wake:
		}
	}
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
					st.rtt.BackoffRTO()
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
						pipe := int64(inFlight) * mssBytes
						for _, seq := range lost {
							if entry := st.sendWindow.GetEntry(seq); entry != nil {
								s.sched.MarkRetransmit(streamID)
								s.sched.Enqueue(streamID, entry.Frame)
								st.sendWindow.BumpXmitTime(seq, tickNow)
							}
						}
						s.congestion().OnLossWithPipe(pipe)
					}

					// TLP — fire one probe outside cwnd if PTO elapsed
					// without an ACK. The probe is the highest in-flight
					// seq's frame (RFC 8985 §7.4: probe with the latest
					// data so the receiver's ACK reveals the gap).
					if st.tlp.ShouldProbe(tickNow) {
						highSeq := st.sendWindow.Next() - 1
						if entry := st.sendWindow.GetEntry(highSeq); entry != nil {
							s.sched.MarkRetransmit(streamID)
							s.sched.Enqueue(streamID, entry.Frame)
							st.sendWindow.BumpXmitTime(highSeq, tickNow)
							st.tlp.MarkProbeSent(highSeq)
							log.Printf("[TLP] peer=%s stream=%d probeSeq=%d inFlight=%d cwnd=%d",
								s.RemoteNodeID().Short(), streamID, highSeq, inFlight, s.congestion().CWND())
						}
					}

					// Re-arm TLP based on the freshest XmitTime in the
					// in-flight set. PendingProbe state internally
					// suppresses spurious re-arming while a probe is
					// outstanding.
					var newest time.Time
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
			if warmupGrace > 0 && time.Since(s.createdAt) < warmupGrace {
				effectiveThreshold = stallThreshold * 2
			}
			s.mu.Lock()
			if s.lastAnyProgressAt.IsZero() {
				s.lastAnyProgressAt = time.Now()
			}
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
				sessionAge := time.Since(s.createdAt)
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
					log.Printf("[STALL-DETECT] false-positive peer=%s age=%v warmup=%v effThresh=%s cwnd=%d→%d (persistent-congestion exit)",
						s.RemoteNodeID().Short(), sessionAge, warmupActive, effectiveThreshold, prevCwnd, newCwnd)
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
func (s *NoiseSession) connWrite(b []byte) error {
	if _, err := s.conn.Write(b); err != nil {
		s.CloseWithError(fmt.Errorf("aether: frame write failed: %w", err))
		return err
	}
	return nil
}

// writeFrame serializes and writes a single frame to the Noise connection.
// Applies compression (if enabled and payload > 64 bytes) and encryption (if key set).
func (s *NoiseSession) writeFrame(frame *aether.Frame) error {
	// Compression: compress payload if enabled and worthwhile (>64 bytes)
	// Read the atomic toggle (not opts.Compression) so runtime flips
	// from SetCompressionEnabled / adaptive CPU controller / agent
	// netmon link-change handlers take effect immediately without
	// reconstructing the session.
	if s.compressionEnabled.Load() && len(frame.Payload) > 64 {
		compressed := compressPayload(frame.Payload)
		if len(compressed) < len(frame.Payload) { // only use if smaller
			frame.Payload = compressed
			frame.Length = uint32(len(compressed))
			frame.Flags = frame.Flags.Set(aether.FlagCOMPRESSED)
		}
	} else {
		frame.Flags = frame.Flags.Clear(aether.FlagCOMPRESSED)
	}

	// Encryption: encrypt payload if key set and enabled
	if s.encryptor != nil && s.opts.Encryption {
		if err := s.encryptor.Encrypt(frame); err != nil {
			return fmt.Errorf("aether encrypt: %w", err)
		}
	} else {
		frame.Flags = frame.Flags.Clear(aether.FlagENCRYPTED)
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

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
		if s.compressor.ShouldCompressControl(frame) {
			s.compressor.EncodeControlShort(&buf, frame)
			return s.connWrite(buf.Bytes())
		}
		// ACK frames → 11 bytes (lite) or 3+N (full)
		if s.compressor.ShouldCompressACK(frame) {
			s.compressor.EncodeACKShort(&buf, frame)
			return s.connWrite(buf.Bytes())
		}
		// Encrypted DATA → 9 bytes + Nonce-in-payload
		if frame.Flags.Has(aether.FlagENCRYPTED) && s.compressor.ShouldCompressData(frame) {
			s.compressor.EncodeEncryptedDataShort(&buf, frame)
			return s.connWrite(buf.Bytes())
		}
		// Unencrypted DATA → 6-9 bytes
		if s.compressor.ShouldCompressData(frame) {
			if frame.Length <= 127 {
				s.compressor.EncodeDataShortVar(&buf, frame)
			} else {
				s.compressor.EncodeDataShort(&buf, frame)
			}
			return s.connWrite(buf.Bytes())
		}
	}

	// Full 50-byte header (fallback)
	if _, err := aether.EncodeFrame(&buf, frame); err != nil {
		return err
	}
	s.compressor.RecordFullHeader(frame)
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
