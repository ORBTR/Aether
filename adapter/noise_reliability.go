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
			case <-s.closed:
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
				case <-s.closed:
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

			// Update pacer rate from congestion controller after each send
			if pacingRate := s.congestion().PacingRate(); pacingRate > 0 {
				s.pacer.SetRate(pacingRate)
			}
		}

		// Park until either new work arrives or the session closes.
		select {
		case <-s.closed:
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
		case <-s.closed:
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
					remoteShort := string(s.remoteNodeID)
					if len(remoteShort) > 14 {
						remoteShort = remoteShort[:14] + "..."
					}
					log.Printf("[INBOX-HEALTH] peer=%s inboxDrops=%d streams=%d",
						remoteShort, dropper.InboxDrops(), streamsCount)
				}
			}

			for _, e := range snap {
				streamID, st := e.id, e.st
				// Retransmit timeout dequeue
				if frame := st.retransmitQ.Dequeue(); frame != nil {
					s.sched.MarkRetransmit(streamID)
					s.sched.Enqueue(streamID, frame)
					s.congestion().OnLoss()
					st.rtt.BackoffRTO()
				}

				// Stall detection: per-stream atomic reads/writes — no s.mu needed.
				if st.sendWindow.InFlight() > 0 {
					anyInFlight = true
					srtt := st.rtt.SRTT()
					if srtt > 0 {
						lastProgressNs := st.lastProgressAtUnixNano.Load()
						if lastProgressNs != 0 && time.Since(time.Unix(0, lastProgressNs)) > 2*srtt {
							if entry := st.sendWindow.GetEntry(st.sendWindow.Base()); entry != nil {
								s.sched.MarkRetransmit(streamID)
								s.sched.Enqueue(streamID, entry.Frame)
								st.lastProgressAtUnixNano.Store(time.Now().UnixNano())
							}
						}
					}
				}

				// Periodic per-stream health snapshot.
				if emitHealth {
					inFlight := st.sendWindow.InFlight()
					lastProgressNs := st.lastProgressAtUnixNano.Load()
					progressAge := "n/a"
					if lastProgressNs != 0 {
						progressAge = fmt.Sprintf("%v", time.Since(time.Unix(0, lastProgressNs)))
					}
					remoteShort := string(s.remoteNodeID)
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
			s.mu.Lock()
			if s.lastAnyProgressAt.IsZero() {
				s.lastAnyProgressAt = time.Now()
			}
			lastProgressAt := s.lastAnyProgressAt
			s.mu.Unlock()
			sessionStuck := stallThreshold > 0 && anyInFlight &&
				time.Since(lastProgressAt) > stallThreshold
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
						case <-s.closed:
							// Session was closed by another path
							// (e.g. external Close); stop probing.
							return
						}
					}
				}
				if probeOK {
					s.mu.Lock()
					s.lastAnyProgressAt = time.Now()
					s.mu.Unlock()
					dbgNoise.Printf("session stall threshold exceeded but Ping succeeded — false positive, reset stall clock")
					continue
				}
				dbgNoise.Printf("session stuck: no ACK progress for %s with data in-flight, %d Pings also failed (last err: %v) — closing for transport fallback",
					stallThreshold, probeAttempts, lastProbeErr)
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
			if time.Since(s.healthMon.LastActivity()) > idleTimeout {
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

	var buf bytes.Buffer
	if s.opts.HeaderComp {
		// Control frames (not encrypted, no payload) → 4 bytes
		if s.compressor.ShouldCompressControl(frame) {
			s.compressor.EncodeControlShort(&buf, frame)
			_, err := s.conn.Write(buf.Bytes())
			return err
		}
		// ACK frames → 11 bytes (lite) or 3+N (full)
		if s.compressor.ShouldCompressACK(frame) {
			s.compressor.EncodeACKShort(&buf, frame)
			_, err := s.conn.Write(buf.Bytes())
			return err
		}
		// Encrypted DATA → 9 bytes + Nonce-in-payload
		if frame.Flags.Has(aether.FlagENCRYPTED) && s.compressor.ShouldCompressData(frame) {
			s.compressor.EncodeEncryptedDataShort(&buf, frame)
			_, err := s.conn.Write(buf.Bytes())
			return err
		}
		// Unencrypted DATA → 6-9 bytes
		if s.compressor.ShouldCompressData(frame) {
			if frame.Length <= 127 {
				s.compressor.EncodeDataShortVar(&buf, frame)
			} else {
				s.compressor.EncodeDataShort(&buf, frame)
			}
			_, err := s.conn.Write(buf.Bytes())
			return err
		}
	}

	// Full 50-byte header (fallback)
	if _, err := aether.EncodeFrame(&buf, frame); err != nil {
		return err
	}
	s.compressor.RecordFullHeader(frame)
	_, err := s.conn.Write(buf.Bytes())
	return err
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
