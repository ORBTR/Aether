//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"fmt"
	"io"
	"log"
	"os"
	"sync/atomic"
	"time"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/abuse"
	"github.com/ORBTR/aether/congestion"
	"github.com/ORBTR/aether/flow"
	"github.com/ORBTR/aether/reliability"
)

// isAckImmediateStream reports whether arriving DATA on streamID should
// elicit an immediate ACK (skip the delayed-ACK timer). Control frames
// always get immediate ACKs by RFC; the RPC stream opts in via
// layout.RPC because request/response pairs are latency-sensitive and
// the delayed-ACK timer (default ~25ms) stalls back-to-back calls.
func (s *NoiseSession) isAckImmediateStream(streamID uint64) bool {
	if streamID == s.layout.Control {
		return true
	}
	if s.layout.RPC != 0 && streamID == s.layout.RPC {
		return true
	}
	return false
}

// readLoop reads Aether frames from the Noise connection and dispatches to streams.
// Delegates decode to aether.ReadNextFrame; the post-decode pipeline
// (decrypt → decompress → anti-replay → dispatch) stays here in
// processIncomingFrame because each step is Noise-specific.
func (s *NoiseSession) readLoop() {
	defer s.CloseWithError(fmt.Errorf("readLoop exited"))
	for {
		frame, indicator, batch, err := aether.ReadNextFrame(s.conn, s.compressor)
		if err != nil {
			if err != io.EOF {
				s.SetCloseErr(err)
			}
			return
		}
		if batch != nil {
			for _, f := range batch {
				s.processIncomingFrame(f, indicator)
			}
			continue
		}
		s.processIncomingFrame(frame, indicator)
	}
}

// processIncomingFrame handles decrypt → decompress → anti-replay → dispatch.
func (s *NoiseSession) processIncomingFrame(frame *aether.Frame, indicator byte) {
	// Structural validation gate — short-header decoders (codec_short.go)
	// skip Validate(), so unknown FrameType bytes, oversize Length, or
	// payload/length mismatches would slip straight through to the dispatch
	// switch. Re-validate here so every inbound frame — short or full —
	// passes the same check before touching session state.
	if err := frame.Validate(); err != nil {
		s.reportAbuse(abuse.ReasonMalformedFrame)
		return
	}

	if s.opts.FrameLogging {
		dbgNoise.Printf("RX stream=%d type=%d seq=%d len=%d",
			frame.StreamID, frame.Type, frame.SeqNo, frame.Length)
	}

	// Decrypt — two paths:
	// 1. Encrypted short header (0x87): Nonce in first 12 bytes of payload
	// 2. Full header (FlagENCRYPTED): Nonce in frame.Nonce field
	if indicator == aether.ShortEncryptedIndicator {
		if s.encryptor != nil && len(frame.Payload) >= 12 {
			nonce := frame.Payload[:12]
			frame.Payload = frame.Payload[12:]
			frame.Length = uint32(len(frame.Payload))
			if err := s.encryptor.DecryptWithNonce(frame, nonce); err != nil {
				log.Printf("[AETHER-NOISE] Decrypt (short) error: %v", err)
				// Decrypt failure is a strong abuse signal — either the peer is
				// replaying stale ciphertexts, using a wrong key, or probing.
				// Feed S7 circuit breaker so repeated bad decrypts trip GoAway.
				s.reportAbuse(abuse.ReasonDecryptFail)
				return
			}
		}
	} else if frame.Flags.Has(aether.FlagENCRYPTED) && s.encryptor != nil {
		if err := s.encryptor.Decrypt(frame); err != nil {
			log.Printf("[AETHER-NOISE] Decrypt error: %v", err)
			s.reportAbuse(abuse.ReasonDecryptFail)
			return
		}
	}

	// Decompress if compressed
	if frame.Flags.Has(aether.FlagCOMPRESSED) {
		decompressed, err := decompressPayload(frame.Payload)
		if err != nil {
			log.Printf("[AETHER-NOISE] Decompress error: %v", err)
			// Decompress failure = malformed wire data. Feed abuse so a
			// peer can't DoS us with endless bad-gzip frames without
			// consequence.
			s.reportAbuse(abuse.ReasonMalformedFrame)
			return
		}
		frame.Payload = decompressed
		frame.Length = uint32(len(decompressed))
		frame.Flags = frame.Flags.Clear(aether.FlagCOMPRESSED)
	}

	// NOTE: connection-level packetReplay check removed. It was using
	// frame.SeqNo (per-stream sequence assigned by st.sendWindow.Add) as
	// if it were a connection-level packet counter. With multiple streams
	// open (5+ on ORBTR mesh sessions), each stream independently starts
	// at SeqNo=0; the second stream's first DATA frame collided with the
	// first stream's bit-0 in the connection-level bitmap and was silently
	// dropped as a "replay". As stream 0 (gossip) advanced past the
	// 128-packet window, EVERY frame from streams 1+ (rpc, keepalive,
	// control, reconcile) fell outside the window and was dropped. The
	// observable effect was UDP sessions where streams 1-4 had inFlight
	// frames that never received an ACK (peer never saw them), while
	// stream 0 gossip kept working.
	//
	// Replay protection is preserved by two correct mechanisms:
	//
	//   1. noise/nonce_window.go — connection-level: each encrypted UDP
	//      packet carries an 8-byte explicit nonce; the sliding 64-bit
	//      bitmap rejects duplicates BEFORE decryption. This is the right
	//      layer for transport-level replay protection.
	//
	//   2. noiseStream.replay (per-stream) at line 237 — application-level:
	//      catches reordering within an open stream. The per-stream SeqNo
	//      space is correctly used here because frame.SeqNo IS per-stream.
	//
	// The deleted check was a third, redundant, AND incorrect layer.
	s.Health().RecordActivity()
	// Per-session frame and byte counters consumed by Metrics() — the
	// receive-side companions to writeFrame's framesSent/bytesSent.
	// Counted at dispatchFrame so the payload reflects what reached
	// application-level decoding (not on-wire size including headers).
	s.framesRecv.Add(1)
	s.bytesRecv.Add(uint64(len(frame.Payload)))
	s.dispatchFrame(frame)
}

// dispatchFrame routes an incoming frame to the appropriate handler.
func (s *NoiseSession) dispatchFrame(frame *aether.Frame) {
	// AE-H-10: refresh stream-GC activity for ANY frame type on a
	// non-control stream — ACK / WINDOW_UPDATE are liveness just like
	// DATA. Recording only on inbound DATA (handleData) let StreamGC
	// reset a live upload-only stream: an uploader sees only ACK/WINDOW
	// returning on its app stream, so after the 5-min idle timeout the
	// sweep RESET its own actively-transmitting stream mid-transfer.
	// Mirrors adapter/tcp.go dispatchFrame.
	if s.streamGC != nil && frame.StreamID != 0 {
		s.streamGC.RecordActivity(frame.StreamID)
	}
	switch frame.Type {
	case aether.TypeDATA:
		s.handleData(frame)
	case aether.TypeOPEN:
		s.handleOpen(frame)
	case aether.TypeCLOSE:
		s.handleClose(frame)
	case aether.TypeRESET:
		s.handleReset(frame)
	case aether.TypeACK:
		s.handleACK(frame)
	case aether.TypeWINDOW:
		s.handleWindowUpdate(frame)
	case aether.TypePING:
		s.handlePing(frame)
	case aether.TypePONG:
		s.handlePong(frame)
	case aether.TypeGOAWAY:
		s.handleGoAway(frame)
	case aether.TypePRIORITY:
		s.handlePriority(frame)
	case aether.TypeFEC_REPAIR:
		s.handleFECRepair(frame)
	case aether.TypePATH_PROBE:
		s.handlePathProbe(frame)
	case aether.TypeHANDSHAKE:
		s.handleHandshake(frame)
	case aether.TypeCONGESTION:
		s.handleCongestion(frame)
	case aether.TypeSTATS:
		s.handleStats(frame)
	case aether.TypeWHOIS, aether.TypeRENDEZVOUS, aether.TypeNETWORK_CONFIG:
		// Control plane — deliver to control stream
		s.deliverToStream(s.layout.Control, frame.Payload)
	}
}

// handleCongestion processes an explicit CONGESTION frame — peer-driven
// sender throttle hint. Session's throttle state is updated; send-path
// consumers can check it before committing large sends.
func (s *NoiseSession) handleCongestion(frame *aether.Frame) {
	p := aether.HandleCongestionFrame(&s.throttle, frame)
	dbgNoise.Printf("CONGESTION recv severity=%d reason=%d backoff=%dms",
		p.Severity, p.Reason, p.BackoffMs)
}

// handleStats processes a peer's periodic STATS frame and stores the
// most-recent payload on the session for monitoring readers (Library
// MeshMetrics, multipath quality scorer). The frame is informational
// only — it never alters local protocol state and never triggers a
// peer reply. The emit path is in noise_reliability.go
// reliabilityTick (every 5s).
func (s *NoiseSession) handleStats(frame *aether.Frame) {
	if frame == nil || len(frame.Payload) < aether.StatsPayloadSize {
		return
	}
	m := aether.DecodeStats(frame.Payload)
	s.lastPeerStats.Store(&m)
}

// SendCongestion emits a CONGESTION frame to the peer.
func (s *NoiseSession) SendCongestion(p aether.CongestionPayload) error {
	return s.writeFrame(aether.BuildCongestionFrame(s.LocalPeerID(), s.RemotePeerID(), p))
}

// Throttle exposes the session's congestion-throttle state.
func (s *NoiseSession) Throttle() *aether.CongestionThrottle {
	return &s.throttle
}

// DeliveryStats exposes the session's receive-path delivery counters
// (OBS-8). The returned pointer is stable for the session's lifetime —
// callers can sample Delivered / Dropped / Backpressure / BytesDropped
// via Load() at monitoring cadence without holding any session lock.
// Updated by DeliverToRecvChWithSignals on every receive-side delivery
// attempt against any stream on this session.
func (s *NoiseSession) DeliveryStats() *DeliveryStats {
	return &s.deliveryStats
}

func (s *NoiseSession) handleData(frame *aether.Frame) {
	// Recover from a `send on closed channel` panic is scoped to the
	// delivery loop below — a broad function-wide recover would
	// silently swallow unrelated bugs (nil deref, internal state
	// corruption) and turn correctness regressions into invisible
	// drops.
	s.mu.Lock()
	st, ok := s.streams[frame.StreamID]
	s.mu.Unlock()

	if !ok {
		if frame.Flags.Has(aether.FlagSYN) {
			s.handleImplicitOpen(frame)
			return
		}
		return // unknown stream
	}

	// Anti-replay classification — distinguishes legitimate retransmits
	// (drop silently, NO abuse) from genuine anomalies (drop AND feed
	// abuse score). Conflating the two was the fleet-wide churn root
	// cause: aether's own reliability layer retransmits frames when an
	// ACK is lost or late, and on any path with non-zero loss those
	// retransmits arrive after their originals — landing inside the
	// replay window as ResultDuplicate. The old `Check()` returned
	// false for all reject reasons, so every retransmit fed
	// `abuse.ReasonReplayDetected` (weight 8). ~13 retransmits in
	// ~28 s crossed the abuse threshold (100) and killed the session.
	// On lossy paths this killed sessions faster than the connection
	// manager could re-establish them, producing the rising-churn
	// pattern.
	//
	// Classify separates the cases: only Ancient (SeqNo below window
	// bottom — a legitimate retransmit cannot land that far behind the
	// reliability layer's send window) and WrapAttack (SeqNo jumped past
	// half the uint32 space, impossible in a single rekey window) are
	// reported as abuse. Duplicate is the protocol-correct behaviour of
	// a working reliability layer under loss.
	// AER-061: Classify is read-only — it does NOT mark the SeqNo seen.
	// We commit the replay window (st.replay.Commit) only AFTER the frame is
	// durably buffered by recvWindow below. If we marked it seen here and the
	// reorder buffer then dropped it for capacity, every retransmit would
	// classify ResultDuplicate and be discarded forever, wedging the stream.
	switch result := st.replay.Classify(frame.SeqNo); result {
	case reliability.ResultNew:
		// fall through to delivery below; commit after a durable insert
	case reliability.ResultDuplicate:
		// Legitimate retransmit — the sender's reliability layer
		// re-sent a frame because its ACK was lost or arrived late.
		// The original was already delivered + ACKed; this copy
		// carries no new data.
		//
		// CRITICAL: force an immediate ACK so the sender's retransmit
		// timer clears. The default ACK engine batches with a 25 ms
		// delayed-ACK timer (Rule 5), but a duplicate is direct
		// evidence that the previous ACK was lost — the receiver
		// SHOULD be eager about replying to break the retransmit
		// storm. Matches RFC 5681 §4.2 (TCP) / RFC 9002 §B.7 (QUIC).
		// Without this, recovery from one lost ACK takes
		// O(maxRetries × RTO) instead of one extra round-trip, and
		// duplicate count climbs until the abuse-tracker fix
		// (CheckResult split) is the only thing keeping the session
		// alive — fix the symptom AND stop the storm.
		//
		// Skip recvWindow.Insert (already delivered) and
		// congestion.OnAck (would double-count bytes).
		if st.ackEngine != nil {
			st.ackEngine.OnDuplicateReceived(frame.SeqNo)
		}
		return
	case reliability.ResultWrapAttack:
		// Genuine forgery: SeqNo jumped past half the uint32 space, which
		// no legitimate sender produces inside one rekey window. Drop +
		// charge abuse (unchanged).
		s.reportAbuse(abuse.ReasonReplayDetected)
		return
	case reliability.ResultAncient:
		// AE-P-04: a SeqNo more than ReplayWindowSize(64) below topSeq is
		// NOT necessarily an adversarial replay. In-flight frame count is
		// bounded by CUBIC cwnd + byte-based flow-control credit (default
		// 1 MiB, growable to 8 MiB, and frames <= MinGuaranteedWindow=1KiB
		// bypass credit entirely -- flow/stream_window.go), NOT by the
		// 64-frame replay window. On any stream that bursts >64 frames (a
		// gossip convergence full-sync, an RPC/bulk pipeline) a single
		// early loss lets topSeq advance far past the lost SeqNo; the
		// sender's legitimate retransmit -- or a deep network reorder --
		// then lands >64 behind and is misclassified Ancient. Dropping it
		// here AND charging abuse re-opens the retransmit churn class the
		// ResultDuplicate/ResultAncient split was built to eliminate.
		//
		// The reorder authority is the recvWindow's cumulative delivery
		// floor (expected), not topSeq: any SeqNo at or above `expected`
		// was never delivered and is still needed. Route it through the
		// idempotent recvWindow (recv_window.go dedups < expected and
		// already-buffered SeqNos harmlessly) instead of dropping it --
		// preserving delivery (no stream stall) with no false abuse.
		if frame.SeqNo < st.recvWindow.ExpectedSeqNo() {
			// Genuinely below the delivery floor: already delivered. Almost
			// always a retransmit whose cumulative ACK was lost and which
			// arrived >64 behind an advanced topSeq. Force an eager ACK to
			// clear the sender's retransmit timer (same rationale as
			// ResultDuplicate at OnDuplicateReceived) so the storm stops in
			// one round-trip.
			//
			// AER-023: do NOT charge abuse here. A below-floor frame is the
			// same class of legitimate lost-ACK retransmit as an in-window
			// ResultDuplicate (which is never charged); on a lossy path a
			// >64-frame burst with a lost cumulative ACK produced ~13 of
			// these inside one RTT and tripped the abuse threshold, killing a
			// healthy session. Genuine forgeries are still caught by
			// ResultWrapAttack; a genuine replay flood is bounded by the
			// eager-ACK cost, not an abuse kill.
			if st.ackEngine != nil {
				st.ackEngine.OnDuplicateReceived(frame.SeqNo)
			}
			return
		}
		// At/above the delivery floor -- still-needed late/reordered/
		// retransmitted frame. Fall out of the switch to the idempotent
		// recvWindow delivery path below.
	default:
		return
	}

	// Reliability: insert into receive window for reordering. AER-061:
	// only mark the replay window seen once the frame is durably buffered.
	// A capacity drop leaves it un-committed so its retransmit is still
	// deliverable. Commit is idempotent and a no-op for below-floor/ancient
	// SeqNos, so the ResultAncient-at/above-floor fall-through is safe.
	delivered, accepted := st.recvWindow.InsertChecked(frame.SeqNo, frame.Payload)
	if accepted {
		st.replay.Commit(frame.SeqNo)
	}

	// Notify ACK engine BEFORE the delivery loop. DeliverToRecvCh-
	// WithSignals can block up to maxBackpressure (25ms) on a slow
	// consumer; if the ACK-engine notify were deferred behind that
	// stall the readLoop pipeline would hold off ACK generation for
	// EVERY frame on EVERY stream while one stream's recvCh was full,
	// and the noise inbox (128 slots) would overflow — silently
	// dropping inbound ACKs for OTHER streams (rack.fackAge would
	// climb across all streams concurrently).
	//
	// The ACK engine only does in-memory state updates + may emit a
	// CompositeACK; it never blocks on a stream's recvCh. Safe to
	// promote ahead of delivery.
	if st.ackEngine != nil {
		st.ackEngine.OnDataReceived(frame.SeqNo, s.isAckImmediateStream(frame.StreamID))
	}

	// Delivery loop: handleReset / local Reset / streamGC sweep can run
	// closeRecvOnce after this goroutine cached `st`, racing with the
	// channel-send inside DeliverToRecvChWithSignals. Recover is
	// narrowly scoped to that send only.
	func() {
		defer func() {
			if r := recover(); r != nil {
				dbgNoise.Printf("handleData: send-on-closed for stream %d (race with teardown): %v", frame.StreamID, r)
			}
		}()
		for _, payload := range delivered {
			// AE-M-02: hand the payload to the stream's own deliverLoop
			// goroutine (non-blocking enqueue) instead of blocking the shared
			// readLoop up to stream1MaxBackpressure=1s on a full recvCh. A slow
			// stream-1 consumer must not stall the readLoop, which would stop
			// draining the noiseConn inbox and silently drop inbound ACKs for
			// every other stream (noise/session.go:296-312).
			ok := st.enqueueDelivery(payload)
			// Conn-level flow control: successful delivery grants credit at
			// application-read time via the session debouncer (Receive →
			// connGrantDebouncer.Record). On drop, the debouncer will never
			// see these bytes so we must grant directly here to prevent a
			// permanent conn-level stall.
			if !ok {
				if grant := s.connWindow.ReceiverConsume(int64(len(payload))); grant > 0 {
					s.sendWindowUpdate(aether.StreamConnectionLevel, uint64(grant))
				}
			}
		}
	}()

	// AE-M-03: Do NOT feed inbound DATA bytes into congestion().OnAck here.
	// handleData processes DATA frames arriving FROM the peer; OnAck is the
	// acknowledgement-of-OUR-sent-data hook and grows the send-side cwnd
	// (CUBIC slow-start does cwnd += ackedBytes, cubic.go:115). Counting
	// received bytes into it inflates our congestion window in proportion to
	// how much the peer sends us — unrelated to our own in-flight/loss state
	// — and lets a later send burst past the safe window (self-induced loss).
	// Send-side cwnd advancement is driven solely by ACKs of locally-sent
	// data in handleACK. Receive-side flow control is already accounted by
	// the recvWindow/connWindow logic above; congestion state must not be.
}

func (s *NoiseSession) handleACK(frame *aether.Frame) {
	s.mu.Lock()
	st, ok := s.streams[frame.StreamID]
	s.mu.Unlock()
	if !ok {
		return
	}

	// Decode Composite ACK
	ack := aether.DecodeCompositeACK(frame.Payload)
	if ack == nil {
		s.reportAbuse(abuse.ReasonACKValidation)
		return // malformed
	}

	// Feed the peer's observed max_ack_delay (from the AckDelay field
	// on every inbound CompositeACK) into TLP's PTO calculation per
	// RFC 9002 §6.2 — an EWMA learned from actual ACK pacing rather
	// than a hardcoded constant, so PTO adapts to the peer's real ACK
	// cadence instead of over- or under-shooting. AckDelay is encoded
	// in AckDelayGranularity (8us) units on the wire.
	if st.tlp != nil {
		// AE-M-01: scale by time.Microsecond so the 8-unit (8µs) granularity
		// lands in Duration (ns); matches the sibling RTT-sample decode below
		// and the encoder (ack_engine.go: ackDelayUs / AckDelayGranularity).
		// Without it the value is 1000x too small and TLP's max_ack_delay EWMA
		// decays PTO below the peer's real ACK cadence, firing spurious probes.
		peerAckDelay := time.Duration(ack.AckDelay) * aether.AckDelayGranularity * time.Microsecond
		st.tlp.UpdateMaxAckDelay(peerAckDelay)
	}

	// Snapshot suspicious-ACK counter before ProcessCompositeACK so we can
	// detect rejections this call caused — the window increments the atomic
	// counter at every S1 guard (BaseACK jump, oversize range, out-of-window
	// bitmap, etc.). If the delta is > 0, the peer just sent an ACK that
	// tripped one of those guards → feed abuse score (S7).
	suspiciousBefore := st.sendWindow.SuspiciousACKsCount()

	// Process the Composite ACK with reorder threshold
	acked, nacks := st.sendWindow.ProcessCompositeACK(ack, reliability.ReorderThreshold)

	if st.sendWindow.SuspiciousACKsCount() > suspiciousBefore {
		s.reportAbuse(abuse.ReasonACKValidation)
	}

	// RTT sample from first non-retransmitted acked entry
	// Subtract ACK delay for accurate network RTT (QUIC RFC 9002 §5.3)
	maxDelay := s.classDefaults.KeepaliveInterval // use keepalive interval as max ACK delay clamp
	if maxDelay <= 0 {
		maxDelay = 25 * time.Millisecond
	}
	for _, entry := range acked {
		if entry.Retries == 0 {
			ackDelay := time.Duration(ack.AckDelay) * aether.AckDelayGranularity * time.Microsecond
			if ackDelay > maxDelay {
				ackDelay = maxDelay // upper clamp — caps RTT deflation
			}
			elapsed := time.Since(entry.SentAt)
			// Reject samples where the claimed delay is impossible
			// (would produce negative network RTT) or negative. Without
			// this a peer reporting AckDelay=0 or AckDelay>elapsed can
			// drive SRTT to absurdly low values, shrinking RTO and
			// triggering spurious retransmits.
			if ackDelay < 0 || ackDelay >= elapsed {
				break
			}
			st.rtt.UpdateWithDelay(elapsed, ackDelay)
			break // only one sample per ACK
		}
	}

	// Remove acked from retransmit queue, and feed RACK its delivery
	// timestamps. RACK uses XmitTime (set in sendWindow.Add /
	// BumpXmitTime), not SentAt, so we get the freshest transmission
	// of each acked seq — critical for retransmits where the original
	// xmit time would mis-classify a recently-delivered ACK.
	ackTime := time.Now()
	for _, entry := range acked {
		st.retransmitQ.Remove(entry.Frame.SeqNo)
		st.rack.Ack(entry.Frame.SeqNo, entry.XmitTime, ackTime)
	}
	if len(acked) > 0 {
		// Any ACK reset TLP — network is responsive, we don't need
		// to count consecutive probes against the cap.
		st.tlp.AnyAckReceived()
		// If the just-ACKed seq matches the in-flight TLP probe,
		// clear the pending-probe state so the next ShouldProbe
		// can fire when warranted.
		if probeSeq, pending := st.tlp.PendingProbeSeq(); pending {
			for _, e := range acked {
				if e.Frame.SeqNo == probeSeq {
					st.tlp.MarkProbeAcked()
					break
				}
			}
		}
	}

	// Implicit NACKs — fast retransmit (bitmap gaps beyond reorder
	// threshold). RACK will also catch these on the next tick, but the
	// peer's explicit NACK is faster — we trust their gap report and
	// retransmit now. OnLossWithPipe is idempotent within a recovery
	// window (see CUBICController.OnLossWithPipe) so RACK's later
	// declaration on the same seq won't compound the cwnd reduction.
	if len(nacks) > 0 {
		mss := int64(s.MSS())
		if mss <= 0 {
			mss = 1400
		}
		pipe := int64(st.sendWindow.InFlight()) * mss
		for _, nackSeqNo := range nacks {
			if entry := st.sendWindow.GetEntry(nackSeqNo); entry != nil {
				s.sched.MarkRetransmit(frame.StreamID)
				s.sched.Enqueue(frame.StreamID, entry.Frame)
				st.sendWindow.BumpXmitTime(nackSeqNo, ackTime)
			}
		}
		s.congestion().OnLossWithPipe(pipe)
	}

	// BBRv2 per-packet sampling. When the active controller is BBR and
	// the acked entry carries a stamped DeliveryRateSample, route through
	// OnAckSampled so the controller can compute true delivery rate.
	// Falls back to OnAck (degraded path) for CUBIC or when the sample is
	// missing (e.g. retransmitted entries).
	srtt := st.rtt.SRTT()
	// Always sum acked bytes once — used both for the CUBIC OnAck call
	// below and for the ACK-driven flow-control credit release that
	// happens regardless of congestion controller choice.
	var ackedBytes int64
	for _, entry := range acked {
		ackedBytes += int64(entry.Frame.Length)
	}
	if bbr, ok := s.congestion().(*congestion.BBRController); ok {
		for _, entry := range acked {
			// SendEntry.BBRSample is *DeliveryRateSample — nil when the
			// send happened under CUBIC and the BBR stamping path was
			// skipped, OR when this entry was created before BBR became
			// active on this session. Nil-check before deref.
			if entry.BBRSample != nil {
				bbr.OnAckSampled(int64(entry.Frame.Length), srtt, *entry.BBRSample)
			} else {
				bbr.OnAck(int64(entry.Frame.Length), srtt)
			}
		}
	} else {
		s.congestion().OnAck(ackedBytes, srtt)
	}
	// ACK-driven flow-control credit release. Every byte the peer has
	// acknowledged is no longer in-flight on this stream, so credit can
	// be returned to the sender NOW regardless of whether a matching
	// WINDOW_UPDATE frame has arrived. This closes the stuck-credit gap
	// on lossy Noise-UDP paths where WINDOW_UPDATE packets can be
	// dropped — ACKs have their own cumulative-retransmit path and are
	// fundamentally more robust.
	//
	// Per-stream and per-conn windows both get the same delta. Each caps
	// at its own dataOutstanding, so ACK-path + WINDOW_UPDATE-path
	// together never over-release (see StreamWindow.ReleaseOnACK).
	if ackedBytes > 0 {
		st.window.ReleaseOnACK(ackedBytes)
		s.connWindow.ReleaseOnACK(ackedBytes)
	}
	// ECN feedback: peer reported CE-marked bytes since last ACK. Notify
	// the controller so it can react one RTT before queue overflow.
	//
	// CEBytes is peer-supplied data — an inflated claim ("you sent 1GB
	// and 1GB got CE-marked" when we sent 1KB) would drive cwnd
	// collapses on a bad-faith peer. A4: cap against the strongest
	// upper bound available — the total bytes WE sent in this CE
	// interval (bytesSentSinceLastCE, drained per CE-bearing ACK). The
	// per-ACK ackedBytes and per-stream Outstanding() are used as a
	// fallback for sessions where the counter has been deliberately
	// reset (paranoid handlers / tests) but the interval counter is
	// the authoritative bound — the peer cannot have CE-marked more
	// bytes than they have actually received from us.
	if ack.Flags&aether.CACKHasECN != 0 && ack.CEBytes > 0 {
		intervalBytes := int64(s.bytesSentSinceLastCE.Swap(0))
		maxPlausibleCE := intervalBytes
		if maxPlausibleCE <= 0 {
			maxPlausibleCE = ackedBytes
		}
		if maxPlausibleCE <= 0 {
			maxPlausibleCE = st.window.Outstanding()
		}
		claimed := int64(ack.CEBytes)
		if claimed > maxPlausibleCE && maxPlausibleCE > 0 {
			if os.Getenv("AETHER_DEBUG_CE") == "1" {
				log.Printf("aether: A4 cap CEBytes claim=%d > interval=%d acked=%d outstanding=%d — clamping + flagging",
					claimed, intervalBytes, ackedBytes, st.window.Outstanding())
			}
			s.reportAbuse(abuse.ReasonACKValidation)
			claimed = maxPlausibleCE
		}
		if claimed > 0 {
			s.congestion().OnCE(claimed)
		}
	}
	// Piggybacked stream-level WINDOW_UPDATE. Same cumulative semantics
	// as a standalone WINDOW_UPDATE frame — ApplyUpdate drops stale/
	// duplicate values via its grantsReceived cursor and caps the release
	// at dataOutstanding so it composes safely with the ACK-driven
	// release above.
	if ack.Flags&aether.CACKHasWindowCredit != 0 && ack.WindowCredit > 0 {
		st.window.ApplyUpdate(int64(ack.WindowCredit))
	}
	// Congestion window may have advanced — wake the writeLoop so it
	// re-evaluates `CanSend`. Without this, frames re-enqueued after a
	// CanSend=false break would wait until the next Enqueue (or
	// indefinitely if traffic stops).
	//
	// Every ACK can advance cwnd via SACK info / PRR / BBR delivery
	// samples even when no new entries are in acked[] (duplicate /
	// reorder ACKs that still carry fresh window credit), so do NOT
	// gate on `len(acked) > 0`. Wake() is a non-blocking buffered
	// signal capped at 1 — duplicate calls collapse — so calling it
	// unconditionally is cheap and closes the missed-wake race on
	// the writeLoop park scheduler.
	s.sched.Wake()
	atomic.AddUint64(&s.wakeOnAckCalls, 1)

	// Track BaseACK progress for stall detection. State lives on the stream
	// (not a session-level map) so it dies with the stream. Atomic CAS on
	// lastBaseACKSeen keeps concurrent handleACK calls monotonic without
	// holding s.mu.
	for {
		prev := st.lastBaseACKSeen.Load()
		// AE-P-08: wrap-safe serial-number comparison (RFC 1982). A plain
		// `ack.BaseACK <= prev` freezes progress tracking for a full ~4B-frame
		// cycle after BaseACK wraps past 2^32 — the small post-wrap value
		// compares <= the near-2^32 prev, so lastProgressAtUnixNano (and the
		// session-wide lastAnyProgressAt) never advance while the stream is
		// actually progressing, tripping the stall detector into needless
		// probe-before-close / ResetCWND. int32(new-prev) > 0 is the
		// forward-progress test used elsewhere in the reliability layer
		// (send_window.go, antireplay.go); it also neutralises a peer that
		// seeds prev near 2^32-1, since the next genuine BaseACK still reads
		// as forward progress across the wrap.
		if int32(ack.BaseACK-prev) <= 0 {
			break
		}
		if st.lastBaseACKSeen.CompareAndSwap(prev, ack.BaseACK) {
			now := time.Now()
			st.lastProgressAtUnixNano.Store(now.UnixNano())
			// Session-level stall detector: any stream making progress
			// resets the session-wide no-progress clock. Guarded by s.mu
			// because reliabilityTick reads this under the same lock.
			s.mu.Lock()
			s.lastAnyProgressAt = now
			s.mu.Unlock()
			break
		}
	}
}

func (s *NoiseSession) handleFECRepair(frame *aether.Frame) {
	if len(frame.Payload) < aether.FECHeaderSize {
		return
	}
	fecHdr := aether.DecodeFECHeader(frame.Payload[:aether.FECHeaderSize])
	repairData := frame.Payload[aether.FECHeaderSize:]

	// The receiver doesn't know which FEC mode the sender used for this
	// group until it sees the repair frame, so we feed the repair into
	// every decoder; at most one actually reconstructs.
	//   1. Reed-Solomon — RS(k,m) recovers up to m losses
	//   2. Interleaved XOR — burst loss across offset groups
	//   3. Basic XOR — single loss per group
	// RSDecoder.AddRepair returns [][]byte (one slice per recovered data
	// shard); the other two return a single []byte.
	if s.rsDecoder != nil {
		if shards := s.rsDecoder.AddRepair(fecHdr, repairData); shards != nil {
			for _, shard := range shards {
				s.deliverToStream(frame.StreamID, shard)
			}
			return
		}
	}
	recovered := s.interleavedDecoder.AddRepair(fecHdr, repairData)
	if recovered == nil {
		recovered = s.fecDecoder.AddRepair(fecHdr, repairData)
	}
	if recovered != nil {
		s.deliverToStream(frame.StreamID, recovered)
	}
}

func (s *NoiseSession) handleOpen(frame *aether.Frame) {
	payload := aether.DecodeOpenPayload(frame.Payload)
	st := s.createStream(frame.StreamID, aether.StreamConfig{
		StreamID:    frame.StreamID,
		Reliability: payload.Reliability,
		Priority:    payload.Priority,
		Dependency:  payload.Dependency,
	}, true /* enforceRemoteCap */)
	if st == nil {
		return // refused by cap; RESET already sent
	}
	st.state.Transition(aether.EventRecvOpen)

	// Route via the ByID dispatcher first so a pinned consumer
	// (AcceptStreamByID) claims its stream regardless of wire order;
	// fallbacks to per-ID backlog then FIFO acceptCh.
	s.notifyStreamAccepted(st)
}

func (s *NoiseSession) handleImplicitOpen(frame *aether.Frame) {
	// Recover scoped to the delivery-loop channel-send only (same
	// reasoning as handleData). Any panic outside the channel-send is
	// a real bug and must not be silently swallowed.
	st := s.createStream(frame.StreamID, aether.DefaultStreamConfig(frame.StreamID), true /* enforceRemoteCap */)
	if st == nil {
		return
	}
	st.state.Transition(aether.EventRecvData)

	s.notifyStreamAccepted(st)

	// Reliability: insert into recv window.
	delivered := st.recvWindow.Insert(frame.SeqNo, frame.Payload)

	// Prime the ACK engine for the implicit-open's first frame BEFORE
	// the delivery loop — otherwise the first frame on a peer-initiated
	// stream sits un-ACKed until a SECOND frame arrives and triggers
	// handleData's notify, wasting a round-trip on every stream open.
	// Mirrors the ordering in handleData above.
	if st.ackEngine != nil {
		st.ackEngine.OnDataReceived(frame.SeqNo, s.isAckImmediateStream(frame.StreamID))
	}

	func() {
		defer func() {
			if r := recover(); r != nil {
				dbgNoise.Printf("handleImplicitOpen: send-on-closed for stream %d (race with teardown): %v", frame.StreamID, r)
			}
		}()
		for _, payload := range delivered {
			// AE-M-02: enqueue onto the per-stream deliverLoop (non-blocking)
			// rather than block the readLoop on a full recvCh. See handleData.
			ok := st.enqueueDelivery(payload)
			// Drop-only conn-level credit: see handleData.
			if !ok {
				if grant := s.connWindow.ReceiverConsume(int64(len(payload))); grant > 0 {
					s.sendWindowUpdate(aether.StreamConnectionLevel, uint64(grant))
				}
			}
		}
	}()
}

func (s *NoiseSession) handleClose(frame *aether.Frame) {
	s.compressor.RemoveStream(frame.StreamID)
	s.mu.Lock()
	st, ok := s.streams[frame.StreamID]
	s.mu.Unlock()
	if !ok {
		return
	}
	st.state.Transition(aether.EventRecvFIN)
	if st.state.IsOpen() {
		return // half-closed; wait for local Close/Reset to tear down
	}
	// Fully closed: flush final ACK, drain, and release all session-level
	// trackers. Without this path the s.streams entry would linger until
	// handleReset (the only other removal path), leaving the engine +
	// send window + streamGC map entry pinned for the lifetime of the
	// session.
	if st.ackEngine != nil {
		st.ackEngine.Flush()
		st.ackEngine.Stop()
	}
	remaining := st.recvWindow.Drain()
	// recvCh-close is idempotent via closeRecvOnce, but a concurrent local
	// Reset / streamGC sweep on the same streamID can close the channel
	// between when this loop checks "ok" and when it sends. recover() turns
	// the panic into a benign drop — matching the TCP adapter's
	// deliverToStream defense (tcp.go:354-360).
	func() {
		defer func() { _ = recover() }()
		for _, payload := range remaining {
			select {
			case st.recvCh <- payload:
			default:
			}
		}
	}()
	st.closeRecvOnce()
	st.teardown()
	s.mu.Lock()
	delete(s.streams, frame.StreamID)
	s.mu.Unlock()
	s.releaseStream(frame.StreamID)
}

func (s *NoiseSession) handleReset(frame *aether.Frame) {
	s.compressor.RemoveStream(frame.StreamID)
	s.mu.Lock()
	st, ok := s.streams[frame.StreamID]
	if ok {
		delete(s.streams, frame.StreamID)
	}
	s.mu.Unlock()
	if ok {
		st.state.Transition(aether.EventRecvReset)
		st.teardown()
		st.closeRecvOnce()
		s.releaseStream(frame.StreamID)
	}
}

// controlHandler returns a ControlFrameHandler bound to this session's
// scheduler, health monitor, conn-window and frame writer. Constructed
// per-call (cheap struct) so handler call sites stay independent of
// session lifecycle ordering. The stream-window lookup acquires s.mu
// around the streams-map read — the same locking the inlined handler
// used pre-refactor.
func (s *NoiseSession) controlHandler() *aether.ControlFrameHandler {
	return &aether.ControlFrameHandler{
		HealthMon:         s.Health(),
		Sched:             s.sched,
		ConnWindow:        s.connWindow,
		Writer:            s.writeFrame,
		Sender:            s.LocalPeerID(),
		Receiver:          s.RemotePeerID(),
		KeepaliveStreamID: s.layout.Keepalive,
		WakeScheduler:     true, // noise writeLoop blocks on Consume → wake on credit
		StreamWindowLookup: func(streamID uint64) *flow.StreamWindow {
			s.mu.Lock()
			st, ok := s.streams[streamID]
			s.mu.Unlock()
			if !ok {
				return nil
			}
			return st.window
		},
	}
}

func (s *NoiseSession) handleWindowUpdate(frame *aether.Frame) {
	s.controlHandler().HandleWindowUpdate(frame)
}

func (s *NoiseSession) handlePing(frame *aether.Frame) {
	s.controlHandler().HandlePing(frame)
}

func (s *NoiseSession) handlePong(frame *aether.Frame) {
	s.controlHandler().HandlePong(frame)
}

func (s *NoiseSession) handleGoAway(frame *aether.Frame) {
	aether.HandleGoAwayFrame(s.CloseWithError, s.RemoteNodeID().Short(), "NOISE", frame)
}

func (s *NoiseSession) handlePriority(frame *aether.Frame) {
	s.controlHandler().HandlePriority(frame)
}

// resumeMaterialRecorder is the optional surface a *noiseConn exposes
// for caching inbound HANDSHAKE_RESUME_MATERIAL payloads. We probe via
// interface so the adapter package doesn't import noise/ directly.
type resumeMaterialRecorder interface {
	RecordResumeMaterial([]byte)
}

func (s *NoiseSession) handleHandshake(frame *aether.Frame) {
	hs := aether.DecodeHandshake(frame.Payload)
	switch hs.HandshakeType {
	case aether.HandshakeAddressMigration:
		// Address migration — validate HMAC and update peer address
		sessionKey := s.SessionKey()
		if sessionKey == nil {
			log.Printf("[AETHER-NOISE] Migration rejected: no session key")
			return
		}
		if err := s.migrator.ValidateMigration(
			s.ConnectionID(),
			nil, 0, sessionKey, hs.Payload,
		); err != nil {
			log.Printf("[AETHER-NOISE] Migration validation failed: %v", err)
			return
		}
		log.Printf("[AETHER-NOISE] Address migration accepted from %s", string(s.RemoteNodeID()))
	case aether.HandshakeResumeMaterial:
		// Responder delivered ticket + plaintext-perspective keys for
		// future 0.5-RTT resume. Forward to the transport layer's
		// initiator-side cache via the noiseConn — that's where the
		// ticket store lives. Probe via interface so this file stays
		// decoupled from the noise/ package internals.
		if rec, ok := s.conn.(resumeMaterialRecorder); ok {
			rec.RecordResumeMaterial(hs.Payload)
		}
	default:
		// Other handshake types (key rotation, cap update, session resume
		// request) deliver to control stream for application handling.
		s.deliverToStream(s.layout.Control, frame.Payload)
	}
}

func (s *NoiseSession) handlePathProbe(frame *aether.Frame) {
	probe := aether.DecodePathProbe(frame.Payload)
	if frame.Flags.Has(aether.FlagACK) {
		// This is a probe response — record success and update congestion MSS
		s.pmtuProber.OnProbeResponse(probe.ProbeID)
		// Feed discovered PMTU into congestion controller (agnostic — works for CUBIC and BBR)
		s.congestion().SetMSS(s.pmtuProber.MSS())
	} else {
		// Echo back with ACK flag
		resp := &aether.Frame{
			SenderID:   s.LocalPeerID(),
			ReceiverID: s.RemotePeerID(),
			StreamID:   s.layout.Control,
			Type:       aether.TypePATH_PROBE,
			Flags:      aether.FlagACK,
			Length:     frame.Length,
			Payload:    frame.Payload,
		}
		s.writeFrame(resp)
	}
}

// sendCompositeACK sends a Composite ACK frame for a stream.
func (s *NoiseSession) sendCompositeACK(st *noiseStream, cack *aether.CompositeACK) {
	// ECN piggyback (#15). Two inputs feed the per-ACK CE-byte total:
	//   1. The adapter-level ceObservedBytes — populated by test code or
	//      by future path layers that sit above the Noise conn.
	//   2. The transport-level counter on the underlying *noiseConn,
	//      drained via the noiseConnCE interface. The listener's
	//      ecnReader writes to this counter whenever the kernel
	//      delivers an IP_TOS/IPV6_TCLASS cmsg with the CE codepoint.
	// Combining both keeps the ACK piggyback accurate even when ECN
	// detection is split across layers on exotic platforms.
	ce := atomic.SwapUint64(&s.ceObservedBytes, 0)
	if drainer, ok := s.conn.(noiseConnCE); ok {
		ce += drainer.DrainCEBytes()
	}
	if ce > 0 {
		cack.Flags |= aether.CACKHasECN
		// CE bytes is uint32 on the wire; clamp to MaxUint32 if a long
		// stretch of CE-marking somehow overflowed.
		if ce > 0xFFFFFFFF {
			cack.CEBytes = 0xFFFFFFFF
		} else {
			cack.CEBytes = uint32(ce)
		}
	}
	payload := aether.EncodeCompositeACK(cack)
	frame := &aether.Frame{
		SenderID:   s.LocalPeerID(),
		ReceiverID: s.RemotePeerID(),
		StreamID:   st.streamID,
		Type:       aether.TypeACK,
		Flags:      aether.FlagCOMPOSITE_ACK, // marks as Composite ACK format
		AckNo:      cack.BaseACK,             // mirror the cumulative ACK in the header field for peers that only decode the header
		Length:     uint32(len(payload)),
		Payload:    payload,
	}
	s.writeFrame(frame)
}

// RecordCEBytes is called by the receive socket layer when an inbound
// packet's IP/IPv6 TOS field carries the CE codepoint (0x03). The bytes
// are folded into the next outbound CompositeACK via CEBytes/CACKHasECN
// so the sender's congestion controller sees the ECN signal.
func (s *NoiseSession) RecordCEBytes(n int) {
	if n <= 0 {
		return
	}
	atomic.AddUint64(&s.ceObservedBytes, uint64(n))
}

// sendWindowUpdate sends a WINDOW_UPDATE frame granting additional credit to the sender.
func (s *NoiseSession) sendWindowUpdate(streamID uint64, credit uint64) {
	s.writeFrame(aether.BuildWindowUpdateFrame(s.LocalPeerID(), s.RemotePeerID(), streamID, credit))
}

// sendWindowUpdateAgnostic adapts sendWindowUpdate to the WindowUpdater signature.
func (s *NoiseSession) sendWindowUpdateAgnostic(streamID uint64, credit uint64) {
	s.sendWindowUpdate(streamID, credit)
}

// deliverToStream delivers raw payload to a stream's receive channel.
func (s *NoiseSession) deliverToStream(streamID uint64, payload []byte) {
	s.mu.Lock()
	st, ok := s.streams[streamID]
	s.mu.Unlock()
	if !ok {
		return
	}
	// Recover narrowly scoped to the channel-send only. handleReset /
	// local Reset / streamGC sweep can run closeRecvOnce after the
	// lookup above, racing the send on the recv channel.
	defer func() {
		if r := recover(); r != nil {
			dbgNoise.Printf("deliverToStream: send-on-closed for stream %d (race with teardown): %v", streamID, r)
		}
	}()
	// AE-M-02: enqueue onto the per-stream deliverLoop (non-blocking) rather
	// than block the readLoop on a full recvCh. See handleData. The enqueue
	// send-on-closed race (teardown closes deliverCh) is caught by this
	// function's deferred recover, same benign-drop semantics as before.
	delivered := st.enqueueDelivery(payload)
	// Drop-only conn-level credit: see handleData.
	if !delivered {
		if grant := s.connWindow.ReceiverConsume(int64(len(payload))); grant > 0 {
			s.sendWindowUpdate(aether.StreamConnectionLevel, uint64(grant))
		}
	}
}
