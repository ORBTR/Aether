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
		frame, indicator, batch, err := aether.ReadNextFrame(s.conn, s.rxCompressor)
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
				// Feed the abuse breaker (reportAbuse) so repeated bad decrypts trip GoAway.
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

		// Re-validate now that the payload is INFLATED. Validate() skips the
		// per-type minimum while FlagCOMPRESSED is set (the deflated wire length
		// is legitimately below the uncompressed minimum), so this is where that
		// deferred check is actually enforced — against the true size, with the
		// flag cleared above. Without this call the minimum would go unenforced
		// for every compressed frame, silently disarming a deliberate anti-abuse
		// gate; with it, a genuinely undersized frame is still rejected and still
		// scored, as an uncompressed undersized frame is at the first Validate
		// above. See frame.go Validate() and minPayloadSizes.
		if err := frame.Validate(); err != nil {
			s.reportAbuse(abuse.ReasonMalformedFrame)
			return
		}
	}

	// Replay protection is two layers, and no check here keys on
	// frame.SeqNo at the connection level:
	//
	//   1. noise/nonce_window.go — connection-level: each encrypted UDP
	//      packet carries an 8-byte explicit nonce; the sliding 64-bit
	//      bitmap rejects duplicates BEFORE decryption. This is the
	//      layer for transport-level replay protection.
	//
	//   2. noiseStream.replay — per stream, in handleData's Classify and
	//      Commit: the space frame.SeqNo lives in, since st.sendWindow.Add
	//      numbers every stream from 0 on its own. A bitmap shared by all
	//      streams would read the second stream's first frame as the first
	//      stream's bit 0.
	s.Health().RecordActivity()
	// Per-session frame and byte counters consumed by Metrics() — the
	// receive-side companions to countFrameSent's framesSent/bytesSent.
	// Counted at dispatchFrame so the payload reflects what reached
	// application-level decoding (not on-wire size including headers).
	s.framesRecv.Add(1)
	s.bytesRecv.Add(uint64(len(frame.Payload)))
	s.dispatchFrame(frame)
}

// dispatchFrame routes an incoming frame to the appropriate handler.
func (s *NoiseSession) dispatchFrame(frame *aether.Frame) {
	// Refresh stream-GC activity for ANY frame type on a non-control
	// stream — ACK / WINDOW_UPDATE are liveness just like DATA. Recorded
	// only on inbound DATA (handleData), StreamGC would reset a live
	// upload-only stream: an uploader sees only ACK/WINDOW returning on
	// its app stream, so after the idle timeout the sweep would RESET its
	// own actively-transmitting stream mid-transfer. Mirrors
	// adapter/tcp.go dispatchFrame.
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
		s.deliverToControl(frame.Payload)
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
// most-recent payload on the session for monitoring readers (the
// multipath quality scorer, the consumer that sums a session's stats).
// The frame is informational only — it never alters local protocol state
// and never triggers a peer reply. The emit path is in
// noise_reliability.go reliabilityTick (every 5s).
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

// DeliveryStats exposes the session's receive-path delivery counters to
// the consumer that sums a session's stats. The returned pointer is
// stable for the session's lifetime —
// callers can sample Delivered / Dropped / Backpressure / BytesDropped
// via Load() at monitoring cadence without holding any session lock.
// Updated by enqueueDelivery and enqueueControl on every message the readLoop
// hands to a stream on this session: Delivered when it is queued for the
// consumer, Dropped when a credit violation or the control-frame limit refuses
// it. Backpressure stays 0 on this session, since nothing here waits.
func (s *NoiseSession) DeliveryStats() *DeliveryStats {
	return &s.deliveryStats
}

func (s *NoiseSession) handleData(frame *aether.Frame) {
	// The stream looked up here may be torn down by another goroutine
	// (Reset, the stream GC) before the delivery below runs; enqueueDelivery
	// finds the queue ended and returns false, and no recover is needed here,
	// which keeps an unrelated panic visible.
	s.mu.Lock()
	st, ok := s.streams[frame.StreamID]
	s.mu.Unlock()

	// A SYN frame opens its stream and carries no message, the meaning TCPSession
	// reads too: it goes through the one admission OPEN has, which leaves a live
	// stream as it is and takes the frame's payload as the stream's OpenPayload.
	if frame.Flags.Has(aether.FlagSYN) {
		s.handleOpen(frame)
		return
	}
	if !ok {
		return // unknown stream
	}

	// The payload joins the stream's FEC decoder first, so what it lets a held
	// repair rebuild follows it into the receive window.
	var recovered []reliability.FECRecovered
	if st.fec != nil {
		recovered = st.fec.AddData(frame.SeqNo, frame.Payload)
	}
	s.admitSequenced(st, frame.SeqNo, frame.Payload, frame.IsFragment(), false)
	s.admitRecovered(st, recovered)
}

// admitSequenced takes one frame of the stream's sequence number space through
// the replay window and the receive window, acknowledges it and delivers what its
// arrival puts in order: a DATA frame (handleData), a frame the FEC decoder rebuilt
// (admitRecovered) and a CLOSE (handleClose, end set). A payload recovered and then
// retransmitted, or the reverse, meets the replay window here and reaches its
// consumer once, in its place. Runs on the session's readLoop.
func (s *NoiseSession) admitSequenced(st *noiseStream, seq uint32, payload []byte, fragment, end bool) {
	// Anti-replay classification — distinguishes legitimate retransmits
	// (drop silently, NO abuse) from genuine anomalies (drop AND feed
	// abuse score). The two must be told apart because aether's own
	// reliability layer (reliabilityTick, the NACK path in handleACK)
	// retransmits a frame when its ACK is lost or late, and on any path with
	// loss those retransmits arrive after their originals — landing inside
	// the replay window as ResultDuplicate — while reportAbuse scores
	// abuse.ReasonReplayDetected at weight 8 against a threshold of 100.
	//
	// Classify separates the cases, and only WrapAttack (SeqNo jumped past
	// half the uint32 space, impossible in a single rekey window) is charged
	// (reportAbuse below). Duplicate is the protocol-correct behaviour of a
	// working reliability layer under loss and is eager-ACKed, uncharged.
	// Ancient (SeqNo below the replay window's bottom) is routed by the
	// recvWindow's delivery floor in its arm below: below the floor it is
	// eager-ACKed, uncharged; at or above it, it is still needed and goes
	// through the recvWindow like a new frame.
	// Classify is read-only — it does NOT mark the SeqNo seen.
	// We commit the replay window (st.replay.Commit) only AFTER the frame is
	// durably buffered by recvWindow below. If we marked it seen here and the
	// reorder buffer then dropped it for capacity, every retransmit would
	// classify ResultDuplicate and be discarded forever, wedging the stream.
	switch result := st.replay.Classify(seq); result {
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
		// O(maxRetries × RTO) instead of one extra round-trip, and the
		// sender's retransmits keep arriving as duplicates for that whole
		// time: this arm's uncharged drop keeps the session alive through
		// the storm, and the eager ACK is what ends it.
		//
		// Skip recvWindow.Insert (already delivered) and
		// congestion.OnAck (would double-count bytes).
		if st.ackEngine != nil {
			st.ackEngine.OnDuplicateReceived(seq)
		}
		return
	case reliability.ResultWrapAttack:
		// Genuine forgery: SeqNo jumped past half the uint32 space, which
		// no legitimate sender produces inside one rekey window. Drop +
		// charge abuse.
		s.reportAbuse(abuse.ReasonReplayDetected)
		return
	case reliability.ResultAncient:
		// A SeqNo more than ReplayWindowSize(64) below topSeq is NOT
		// necessarily an adversarial replay. In-flight frame count is
		// bounded by CUBIC cwnd + byte-based flow-control credit (default
		// 1 MiB, growable to 8 MiB -- flow/stream_window.go), NOT by the
		// 64-frame replay window. On any stream that bursts >64 frames (a
		// gossip convergence full-sync, an RPC/bulk pipeline) a single
		// early loss lets topSeq advance far past the lost SeqNo; the
		// sender's legitimate retransmit -- or a deep network reorder --
		// then lands >64 behind and is misclassified Ancient. Dropping it
		// here AND charging abuse would score a legitimate retransmit at
		// weight 8 against the threshold of 100, the same churn the
		// uncharged ResultDuplicate arm above exists to absorb.
		//
		// The reorder authority is the recvWindow's cumulative delivery
		// floor (expected), not topSeq: any SeqNo at or above `expected`
		// was never delivered and is still needed. Route it through the
		// idempotent recvWindow (recv_window.go dedups < expected and
		// already-buffered SeqNos harmlessly) instead of dropping it --
		// preserving delivery (no stream stall) with no false abuse.
		if seq < st.recvWindow.ExpectedSeqNo() {
			// Genuinely below the delivery floor: already delivered. Almost
			// always a retransmit whose cumulative ACK was lost and which
			// arrived >64 behind an advanced topSeq. Force an eager ACK to
			// clear the sender's retransmit timer (same rationale as
			// ResultDuplicate at OnDuplicateReceived) so the storm stops in
			// one round-trip.
			//
			// Do NOT charge abuse here. A below-floor frame is the same
			// class of legitimate lost-ACK retransmit as an in-window
			// ResultDuplicate (which is never charged); on a lossy path a
			// >64-frame burst with a lost cumulative ACK yields ~13 of these
			// inside one RTT, enough to trip the abuse threshold and kill a
			// healthy session. Genuine forgeries are still caught by
			// ResultWrapAttack; a genuine replay flood is bounded by the
			// eager-ACK cost, not an abuse kill.
			if st.ackEngine != nil {
				st.ackEngine.OnDuplicateReceived(seq)
			}
			return
		}
		// At/above the delivery floor -- still-needed late/reordered/
		// retransmitted frame. Fall out of the switch to the idempotent
		// recvWindow delivery path below.
	default:
		return
	}

	// Reliability: insert into receive window for reordering. The replay
	// window is marked seen only once the frame is durably buffered.
	// A capacity drop leaves it un-committed so its retransmit is still
	// deliverable. Commit is idempotent and a no-op for below-floor/ancient
	// SeqNos, so the ResultAncient-at/above-floor fall-through is safe.
	var (
		delivered []reliability.RecvDelivery
		accepted  bool
	)
	if end {
		delivered, accepted = st.recvWindow.InsertEnd(seq)
	} else {
		delivered, accepted = st.recvWindow.InsertMarked(seq, payload, fragment)
	}
	if accepted {
		st.replay.Commit(seq)
	}

	// Notify the ACK engine before delivery. An ACK says the frame reached
	// this side and takes it out of the sender's flight; it returns no credit,
	// which only the consumer's Receive replenishes, so it does not depend on
	// the consumer. It is safe ahead of delivery because enqueueDelivery always
	// admits what a sender's credit covered: the acknowledged frame sits in a
	// queue bounded by that credit and only a stream's end or a peer past its
	// credit (reset by enqueueDelivery, whose reader and sender both read it as
	// aether.ErrStreamOverrun) can lose it. The ACK engine does
	// in-memory state updates and may emit a CompositeACK, which never waits
	// on a stream's consumer.
	if st.ackEngine != nil {
		st.ackEngine.OnDataReceived(seq, end || s.isAckImmediateStream(st.streamID))
	}

	// Delivery: each whole in-order message goes to the stream's recvQ through
	// enqueueDelivery, and a CLOSE, once every frame before it has gone, ends the
	// receive side. A Reset or stream GC sweep on another goroutine may tear
	// the stream down after the lookup above; enqueueDelivery then returns false.
	for _, d := range delivered {
		if d.End {
			s.endReceive(st)
			continue
		}
		if d.Expired {
			st.settleExpired(d)
			continue
		}
		payload, whole := st.reassemble(d)
		if !whole {
			continue // a fragment of a message not yet complete, or refused
		}
		// Never waits: a slow consumer must not stall the readLoop, which
		// would stop draining the noiseConn inbox and drop inbound ACKs for
		// every other stream.
		ok := st.enqueueDelivery(payload)
		if ok {
			// Count only bytes admitted in order (delivered) and handed to the
			// app stream: reportAbuse reads appBytesDelivered to tell an
			// established, delivering peer (its forensic-only tier) from one
			// that only ever sends garbage. A replay, out-of-order or
			// malformed flooder produces an empty delivered or a failed
			// enqueue, so it never accrues here, where s.bytesRecv (counted at
			// dispatch, before any check) would.
			s.appBytesDelivered.Add(uint64(len(payload)))
		}
	}

	// Do NOT feed inbound DATA bytes into congestion().OnAck here.
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
	// A stream Close has ended queues its CLOSE on the ACK that empties its send
	// window, and on that CLOSE's own ACK leaves the session if the peer's CLOSE
	// has come (finishSend).
	defer func() { _ = st.finishSend() }()

	// Decode Composite ACK
	ack := aether.DecodeCompositeACK(frame.Payload)
	if ack == nil {
		// Diagnostic (env-gated AETHER_DEBUG_ACKDECODE=1) for a CompositeACK
		// that fails to decode between two peers of one build, whose codec is
		// byte-symmetric: log the RAW failing payload so the cause can be read
		// from the bytes. frameLen!=payloadLen or payloadLen<8 ⇒ truncation /
		// sizing / pool; otherwise a full-length garbage hex ⇒ buffer aliasing
		// / multipath corruption AFTER Validate but BEFORE this decode.
		if os.Getenv("AETHER_DEBUG_ACKDECODE") == "1" {
			log.Printf("[ACKDECODE-NIL] peer=%s type=%d stream=%d seqno=%d frameLen=%d payloadLen=%d payload=%x",
				s.RemoteNodeID().Short(), frame.Type, frame.StreamID, frame.SeqNo,
				frame.Length, len(frame.Payload), frame.Payload)
		}
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
		// Scale by time.Microsecond so the 8-unit (8µs) granularity lands in
		// Duration (ns); matches the sibling RTT-sample decode below
		// and the encoder (ack_engine.go: ackDelayUs / AckDelayGranularity).
		// Without it the value is 1000x too small and TLP's max_ack_delay EWMA
		// decays PTO below the peer's real ACK cadence, firing spurious probes.
		peerAckDelay := time.Duration(ack.AckDelay) * aether.AckDelayGranularity * time.Microsecond
		st.tlp.UpdateMaxAckDelay(peerAckDelay)
	}

	// Snapshot suspicious-ACK counter before ProcessCompositeACK so we can
	// detect rejections this call caused — the window increments the atomic
	// counter at every validation guard (BaseACK jump, oversize range,
	// out-of-window bitmap, etc.). If the delta is > 0, the peer just sent
	// an ACK that tripped one of those guards → feed the abuse score.
	suspiciousBefore := st.sendWindow.SuspiciousACKsCount()

	// Process the Composite ACK with reorder threshold
	acked, nacks := st.sendWindow.ProcessCompositeACK(ack, reliability.ReorderThreshold)

	if st.sendWindow.SuspiciousACKsCount() > suspiciousBefore {
		s.reportAbuse(abuse.ReasonACKValidation)
	}

	// RTT sample from the LARGEST-acked non-retransmitted entry.
	// RFC 9002 §5.1 requires sampling the largest acked packet, not the
	// oldest. `acked` is lowest-seq-first, so taking the first Retries==0
	// entry would sample the OLDEST frame while AckDelay is measured
	// against the newest received frame — every sample would then include
	// the inter-frame send gap (≥2 frames per ACK under MaxPackets=2) and,
	// after an ACK loss, the whole lost-ACK interval, systematically
	// inflating SRTT/RTO/RACK/TLP. Pick the most-recently-sent
	// unretransmitted entry so the sample and AckDelay refer to the same
	// frame.
	maxDelay := s.classDefaults.KeepaliveInterval // use keepalive interval as max ACK delay clamp
	if maxDelay <= 0 {
		maxDelay = 25 * time.Millisecond
	}
	var sampleEntry *reliability.SendEntry
	for _, entry := range acked {
		// An unwritten entry has no send time for an ACK to close an interval on.
		if entry.Written && entry.Retries == 0 && (sampleEntry == nil || entry.SentAt.After(sampleEntry.SentAt)) {
			sampleEntry = entry
		}
	}
	if sampleEntry != nil {
		ackDelay := time.Duration(ack.AckDelay) * aether.AckDelayGranularity * time.Microsecond
		if ackDelay > maxDelay {
			ackDelay = maxDelay // upper clamp — caps RTT deflation
		}
		elapsed := time.Since(sampleEntry.SentAt)
		// Reject samples where the claimed delay is impossible (would
		// produce negative network RTT) or negative. Without this a peer
		// reporting AckDelay=0 or AckDelay>elapsed can drive SRTT to
		// absurdly low values, shrinking RTO and triggering spurious
		// retransmits. UpdateWithDelay additionally floors the adjusted
		// sample at min_rtt.
		if ackDelay >= 0 && ackDelay < elapsed {
			st.rtt.UpdateWithDelay(elapsed, ackDelay)
		}
	}

	// Remove acked from retransmit queue, and feed RACK its delivery
	// timestamps. RACK uses XmitTime (set in SendWindow.MarkWritten /
	// BumpXmitTime), not SentAt, so we get the freshest transmission
	// of each acked seq — critical for retransmits where the original
	// xmit time would mis-classify a recently-delivered ACK. An unwritten
	// entry has no transmission to report. Frame.SeqNo is the one Frame field
	// read here: the write loop may still be rewriting the rest.
	ackTime := time.Now()
	for _, entry := range acked {
		st.retransmitQ.Remove(entry.Frame.SeqNo)
		if entry.Written {
			st.rack.Ack(entry.Frame.SeqNo, entry.XmitTime, ackTime)
		}
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
		pipe := s.totalInFlightBytes()
		for _, nackSeqNo := range nacks {
			if written := st.sendWindow.WrittenFrame(nackSeqNo); written != nil {
				s.sched.MarkRetransmit(frame.StreamID)
				// A stream a RESET has taken out of the scheduler is owed no
				// retransmit, and its clock is left alone.
				if s.sched.Enqueue(frame.StreamID, written) {
					st.sendWindow.BumpXmitTime(nackSeqNo, ackTime)
				}
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
	// Sum acked bytes once for the CUBIC OnAck call below. An ACK returns no
	// flow-control credit: it proves the frame reached the peer, not that the
	// peer's consumer took it, and the peer's receive queue is bounded only
	// while credit stays charged until then. Credit comes back through the
	// cumulative grant (WINDOW_UPDATE, the CompositeACK piggyback applied
	// below, and refreshWindowGrants' re-emission for a grant lost on the path).
	//
	// The controller's bytes are each entry's recorded wire count, the unit CanSend
	// and the pipe read. No live Frame field: writeFrame rewrites Length under
	// writeMu, which this readLoop path does not take, and a frame a peer acks
	// while it is queued can be under rewrite right now. An unwritten entry counts 0.
	var ackedBytes int64
	for _, entry := range acked {
		ackedBytes += entry.InFlightBytes
	}
	if bbr, ok := s.congestion().(*congestion.BBRController); ok {
		for _, entry := range acked {
			if !entry.Written {
				continue
			}
			// SendEntry.BBRSample is *DeliveryRateSample — nil when the
			// write happened under CUBIC and the BBR stamping path was
			// skipped. Nil-check before deref.
			if entry.BBRSample != nil {
				bbr.OnAckSampled(entry.InFlightBytes, srtt, *entry.BBRSample)
			} else {
				bbr.OnAck(entry.InFlightBytes, srtt)
			}
		}
	} else if cubic, ok := s.congestion().(*congestion.CUBICController); ok {
		// Thread the current in-flight bytes into CUBIC (OnAckWithPipe) so
		// Proportional Rate Reduction runs during fast recovery: with pipe=0
		// the PRR branch never runs and recovery exits after the FIRST ACK, so
		// a multi-packet loss burst compounds ×0.7 per tick instead of one
		// reduction per RTT. totalInFlightBytes() here is the post-ACK pipe.
		cubic.OnAckWithPipe(ackedBytes, srtt, s.totalInFlightBytes())
	} else {
		s.congestion().OnAck(ackedBytes, srtt)
	}
	// ECN feedback: peer reported CE-marked bytes since last ACK. Notify
	// the controller so it can react one RTT before queue overflow.
	//
	// CEBytes is peer-supplied data — an inflated claim ("you sent 1GB
	// and 1GB got CE-marked" when we sent 1KB) would drive cwnd
	// collapses on a bad-faith peer. The claim and every bound it is
	// compared with count frame wire bytes, the buffer emitFrameLocked
	// passes to conn.Write and the unit OnAck and OnCE read: the peer's
	// noiseConn records a CE-marked datagram as the DATA packet payload
	// it decrypts, which is that buffer. The bound is the wire bytes this
	// session wrote in the CE interval (bytesSentSinceLastCE, drained per
	// CE-bearing ACK); when that drains 0, this ACK's ackedBytes; when
	// that is 0 too, the wire bytes still in flight on the session. The
	// peer cannot have CE-marked more bytes than it has received from us.
	//
	// When all three read 0, no byte this session sent stands behind the
	// claim, so it is evidence of nothing: the controller is not told of it
	// and no abuse is charged. A charge there could fall on an honest peer,
	// since bytesSentSinceLastCE is drained by the first CE-bearing ACK of any
	// stream and a second stream's ACK in the same interval finds it at 0.
	if ack.Flags&aether.CACKHasECN != 0 && ack.CEBytes > 0 {
		intervalBytes := int64(s.bytesSentSinceLastCE.Swap(0))
		maxPlausibleCE := intervalBytes
		if maxPlausibleCE <= 0 {
			maxPlausibleCE = ackedBytes
		}
		if maxPlausibleCE <= 0 {
			maxPlausibleCE = s.totalInFlightBytes()
		}
		claimed := int64(ack.CEBytes)
		if maxPlausibleCE <= 0 {
			claimed = 0
		} else if claimed > maxPlausibleCE {
			if os.Getenv("AETHER_DEBUG_CE") == "1" {
				log.Printf("aether: CEBytes claim=%d past its bound (wire bytes: interval=%d acked=%d inflight=%d) — clamping + flagging",
					claimed, intervalBytes, ackedBytes, s.totalInFlightBytes())
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
	// at dataOutstanding.
	if ack.Flags&aether.CACKHasWindowCredit != 0 && ack.WindowCredit > 0 {
		st.window.ApplyUpdate(int64(ack.WindowCredit))
	}
	// Congestion window may have advanced — wake the writeLoop so it
	// re-evaluates `CanSend`. Without this, a frame held after a
	// CanSend=false break would wait for the writeLoop's retry timer
	// (cwndBlockedProbeInterval).
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
		// Wrap-safe serial-number comparison (RFC 1982). A plain
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

// admitRecovered puts frames the stream's FEC decoder rebuilt through the path a
// frame from the wire takes.
func (s *NoiseSession) admitRecovered(st *noiseStream, recovered []reliability.FECRecovered) {
	for _, r := range recovered {
		s.fecRecovered.Add(1)
		s.admitSequenced(st, r.SeqNo, r.Payload, r.Fragment, false)
	}
}

// handleFECRepair takes a FEC_REPAIR frame into its stream's decoder and delivers
// what it recovers. The repair names the frames it covers by sequence number, so a
// recovered payload takes its place in the stream's receive window: the sender stops
// retransmitting it on the ACK that window now produces, and a retransmit already on
// its way meets the replay window. A stream with no FEC state ignores the repair: its
// session has FEC disabled, or the stream has left and the frame came too late to
// matter. A repair that cannot be read or does not fit the stream is charged to the
// peer, which writes neither.
func (s *NoiseSession) handleFECRepair(frame *aether.Frame) {
	s.mu.Lock()
	st, ok := s.streams[frame.StreamID]
	s.mu.Unlock()
	if !ok || st.fec == nil {
		return
	}
	header, repair, err := aether.DecodeFECHeader(frame.Payload)
	if err == nil {
		var recovered []reliability.FECRecovered
		if recovered, err = st.fec.AddRepair(header, repair); err == nil {
			s.admitRecovered(st, recovered)
			return
		}
	}
	dbgNoise.Printf("stream %d: FEC repair refused: %v", frame.StreamID, err)
	s.reportAbuse(abuse.ReasonMalformedFrame)
}

// handleOpen admits a stream the peer opened. The OPEN states the credit the
// opener reserved for the stream (OpenPayload.InitialCredit), and the stream's
// window, its credit reservation and its queue bound (receiveCeilings) are
// built from it, so the sender's credit on each side is the credit the other
// side holds for it. A credit below flow.MinGuaranteedWindow, zero included, or
// above this side's stream ceiling (streamCreditCeiling) is refused with
// RESET(ResetRefused) and an abuse charge, and no state is kept:
// flow.NewStreamWindowWithCap would raise a smaller credit to the minimum,
// leaving this window larger than the opener's, and would take a larger one
// as its growth ceiling, so a peer's declaration would raise this side's
// ceiling. An FEC level outside the registry is refused the same way: the
// opener would write repairs this side cannot read. A generation of zero or above
// aether.MaxStreamGeneration is refused the same way: it names no stream, so this
// side could not tell the stream's CLOSE and RESET from those of another. An OPEN
// for a stream already in s.streams changes nothing: that stream keeps its window
// and reservation, and the acceptor is not handed it a second time. Two exceptions
// let the OPEN admit the next stream. A stream both sides have closed: an opener
// reuses an ID only once its own stream under it has left, which takes this side's
// CLOSE and the ACK of its own, so the stream goes (peerReopened). And a stream the
// peer opened whose generation is below the OPEN's: the peer has left that stream,
// since it opens an ID only once its stream under it is gone, and the RESET that
// ended it there never arrived: its one copy, written when the peer's waiting RESETs
// were at its stream cap (writeReset), was lost. The stream ends here as at that
// RESET (endSuperseded). Left in place, either would take
// the new stream's frames and acknowledge them. A DATA frame flagged aether.FlagSYN
// comes here from handleData.
func (s *NoiseSession) handleOpen(frame *aether.Frame) {
	payload := aether.DecodeOpenPayload(frame.Payload)
	cfg := aether.StreamConfig{
		StreamID:      frame.StreamID,
		Reliability:   payload.Reliability,
		Priority:      payload.Priority,
		Dependency:    payload.Dependency,
		InitialCredit: int64(payload.InitialCredit),
		FECLevel:      payload.FECLevel,
	}
	valid := cfg.InitialCredit >= flow.MinGuaranteedWindow && cfg.InitialCredit <= streamCreditCeiling(cfg) &&
		reliability.ValidFECLevel(cfg.FECLevel) && aether.ValidStreamGeneration(payload.Generation)
	s.mu.Lock()
	live, ok := s.streams[frame.StreamID]
	s.mu.Unlock()
	if ok && !live.peerReopened() {
		if !valid || !live.supersededBy(payload.Generation) {
			return
		}
		s.endSuperseded(live)
	}
	if !valid {
		atomic.AddUint64(&s.streamRefused, 1)
		s.reportAbuse(abuse.ReasonStreamRefused)
		s.sendRefused(frame.StreamID, payload.Generation)
		return
	}
	st, _ := s.createStream(frame.StreamID, cfg, true /* enforceRemoteCap */, payload.Generation)
	if st == nil {
		// Refused by the cap or the credit reservation, with the RESET sent; or a
		// local OpenStream of the ID took it first, whose OPEN the peer will meet.
		return
	}
	st.state.Transition(aether.EventRecvOpen)

	// Route via the ByID dispatcher first so a pinned consumer
	// (AcceptStreamByID) claims its stream regardless of wire order;
	// fallbacks to per-ID backlog then FIFO acceptCh.
	s.notifyStreamAccepted(st)
}

// supersededBy reports whether a peer's OPEN stating generation opens a later
// stream than this one under the ID: this stream is the peer's, and the peer numbers
// its streams rising. A stream this side opened is never superseded this way, the
// peer's numbers counting another side's streams.
func (st *noiseStream) supersededBy(generation uint64) bool {
	return !st.incarnation.WriterOpened && generation > st.incarnation.Generation
}

// endSuperseded ends a stream a later OPEN of the peer's has replaced (handleOpen)
// as the peer's RESET of it would have, had one arrived. The RESET's counts are
// unknown. The peer wrote it at least the ID's quiet time ago, so the grants it sent
// before it have had several round trips to arrive: of this
// side's charge, all that no grant has returned is taken back (Consumed 0), and of
// this side's grants on the stream, the peer's RESET took back at most the stream's
// credit, which comes off this side's later grants (Charged the grants, Released at
// most the reservation, supersededReset). The error left is credit this side holds
// back, at most the stream's credit, and a grant still on the path, which returns
// what this side has taken back already.
func (s *NoiseSession) endSuperseded(st *noiseStream) {
	s.mu.Lock()
	cur, ok := s.streams[st.streamID]
	if ok && cur == st {
		delete(s.streams, st.streamID)
	}
	s.mu.Unlock()
	if !ok || cur != st {
		return
	}
	s.txCompressor.RemoveStream(st.streamID)
	s.rxCompressor.RemoveStream(st.streamID)
	s.endByPeerReset(st, aether.ResetPayload{Reason: aether.ResetCancel, Incarnation: st.incarnation}, true)
}

// handleClose takes the peer's CLOSE, which holds the next sequence number of the
// peer's frames on the stream: it goes through the receive window like a frame of
// DATA, so it is acknowledged like one, a retransmit of it is answered like one, and
// it ends the receive side only once every frame before it has been delivered
// (endReceive). A CLOSE naming another stream than the one under the ID
// (aether.StreamIncarnation), a copy of an earlier stream's late on the path, is
// dropped unanswered: an ACK under the ID would reach the stream there now, which
// never sent it, and acknowledge its frames at the old stream's sequence numbers; and
// the stream's header compression stays. A CLOSE for a stream this side no longer
// holds is a retransmit whose ACK was lost, of a stream that has left on both
// CLOSEs, or a stream this side never held, its OPEN lost: the peer writes its CLOSE
// only once all its frames are acknowledged (finishSend), so a cumulative ACK up to
// the CLOSE says only that and lets the peer's stream end, at the cost of a frame
// answering a frame.
func (s *NoiseSession) handleClose(frame *aether.Frame) {
	s.mu.Lock()
	st, ok := s.streams[frame.StreamID]
	s.mu.Unlock()
	if !ok {
		s.txCompressor.RemoveStream(frame.StreamID)
		s.rxCompressor.RemoveStream(frame.StreamID)
		s.sendCompositeACK(frame.StreamID, &aether.CompositeACK{BaseACK: frame.SeqNo})
		return
	}
	if !st.namedBy(aether.DecodeClosePayload(frame.Payload)) {
		return
	}
	s.admitSequenced(st, frame.SeqNo, nil, false, true)
}

// endReceive ends the stream's receive side at the peer's CLOSE, whether or not
// this side has closed: every frame sequenced before the CLOSE has been delivered
// (admitSequenced) and no more will come. Flush the final ACK, stop the queue's
// admission and close recvDone: Receive returns what the queue holds, then io.EOF.
// Reading them grants credit back, after the stream has left too
// (recvQueue.leftSession). A retransmit of the CLOSE whose ACK was lost meets the
// replay window in admitSequenced, which acknowledges it at once.
func (s *NoiseSession) endReceive(st *noiseStream) {
	st.state.Transition(aether.EventRecvFIN)
	if st.peerClosed.Swap(true) {
		return // a repeated CLOSE ends nothing more
	}
	s.txCompressor.RemoveStream(st.streamID)
	s.rxCompressor.RemoveStream(st.streamID)
	if st.ackEngine != nil {
		st.ackEngine.Flush()
	}
	st.recvQ.end()
	st.closeRecvOnce()
	// The send side stays until this side's CLOSE is acknowledged: Send works on a
	// stream only the peer has closed, and handleACK still finds the stream for
	// the frames it has in flight. Once both CLOSEs are done the stream leaves
	// (leaveIfEnded), here or in finishSend.
	st.leaveIfEnded()
}

// handleReset takes the peer's RESET, which ends both halves of the stream it names
// (aether.StreamIncarnation). Every RESET is acknowledged (acknowledgeReset), what
// it finds or not, so the peer stops writing it again and may open the ID; a RESET
// flagged FlagACK is that acknowledgment of one of this side's (resetAcknowledged)
// and changes nothing else. A RESET naming another stream than the one under the
// ID, a copy of an earlier stream's late on the path, ends nothing, and leaves the
// stream's header compression alone. A RESET for a stream this side has itself reset crossed this
// side's on the path, and each side's corrects the other's settlement from the count
// this side kept (noteResetGrants). A RESET for any other stream this side does not
// hold has nothing to end: this side kept no grants for it, or a copy of it has
// already been read here.
func (s *NoiseSession) handleReset(frame *aether.Frame) {
	payload := aether.DecodeResetPayload(frame.Payload)
	if frame.Flags.Has(aether.FlagACK) {
		s.resetAcknowledged(frame.StreamID, payload.Incarnation)
		return
	}
	s.acknowledgeReset(frame.StreamID, payload)
	s.mu.Lock()
	st, ok := s.streams[frame.StreamID]
	stale := ok && !st.namedBy(payload.Incarnation)
	if ok && !stale {
		delete(s.streams, frame.StreamID)
	}
	crossed, wasReset := s.resetGrants[frame.StreamID]
	wasReset = wasReset && crossed.inc.Generation == payload.Incarnation.Generation &&
		crossed.inc.WriterOpened != payload.Incarnation.WriterOpened
	if wasReset {
		delete(s.resetGrants, frame.StreamID)
	}
	s.mu.Unlock()
	if stale {
		return
	}
	s.txCompressor.RemoveStream(frame.StreamID)
	s.rxCompressor.RemoveStream(frame.StreamID)
	if !ok {
		if wasReset {
			s.withholdGranted(crossed.granted, payload)
		}
		return
	}
	s.endByPeerReset(st, payload, false)
}

// acknowledgeReset answers the peer's RESET under streamID with a RESET flagged
// FlagACK that names the stream as the RESET did, stating the same reason and no
// counts (aether.ResetPayload). It is written once: a lost acknowledgment is answered
// again at the RESET's next copy.
func (s *NoiseSession) acknowledgeReset(streamID uint64, p aether.ResetPayload) {
	payload := aether.EncodeResetPayload(aether.ResetPayload{Reason: p.Reason, Incarnation: p.Incarnation})
	_ = s.writeFrame(&aether.Frame{
		SenderID:   s.LocalPeerID(),
		ReceiverID: s.RemotePeerID(),
		StreamID:   streamID,
		Type:       aether.TypeRESET,
		Flags:      aether.FlagACK,
		Length:     uint32(len(payload)),
		Payload:    payload,
	})
}

// supersededReset states the counts of the RESET that never arrived for a stream
// endSuperseded ends: Consumed 0, taking the grants the peer sent before that RESET
// to have arrived; Charged what this side granted on the stream and Released at most the
// stream's reservation, so withholdGranted takes off this side's later grants
// min(granted, reserved), what the peer's RESET can have taken back.
func supersededReset(p aether.ResetPayload, granted, reserved int64) aether.ResetPayload {
	p.Consumed = 0
	p.Charged = uint64(max(granted, 0))
	p.Released = uint64(max(min(granted, reserved), 0))
	return p
}

// endByPeerReset ends a stream the peer's RESET ended, which the caller has taken out
// of s.streams: handleReset with the RESET, and endSuperseded, for a RESET that never
// arrived, with superseded set, whose counts it states here from the grants and the
// stream's reservation.
func (s *NoiseSession) endByPeerReset(st *noiseStream, payload aether.ResetPayload, superseded bool) {
	reserved := st.reserved.Load()
	// A refusal (createStream's cap or credit reservation on the peer) and
	// an overrun (the peer's enqueueDelivery) are recorded first, so Send
	// and Receive name them once the stream ends.
	switch payload.Reason {
	case aether.ResetRefused:
		st.refusedByPeer.Store(true)
	case aether.ResetFlowCtrl:
		st.overrun.Store(true)
	}
	st.left.Store(true)
	st.state.Transition(aether.EventRecvReset)
	// The peer's RESET ends the send side too: no CLOSE follows it.
	st.closeSent.Store(true)
	st.closeDone.Store(true)
	st.teardown()
	granted := st.recvQ.peerEnded()
	st.closeRecvOnce()
	if superseded {
		payload = supersededReset(payload, granted, reserved)
	}
	st.settlePeerReset(payload, granted)
	// Out of s.streams, so no ACK reaches this stream again: what the
	// peer's RESET leaves charged goes back to the session's in-flight
	// counter and connection window.
	st.releaseInFlight()
	st.releaseReservation()
	s.releaseStream(st.streamID)
	s.trackEnded(st.recvQ)
}

// withholdGranted takes off this session's later connection grants what it granted
// on a stream past what the peer's RESET says its grants had returned there
// (aether.ResetPayload, Charged minus Released): the peer took those bytes back at
// its RESET. A release above the charge cannot be true of any stream, so the
// statement is charged to the peer and withholds nothing.
func (s *NoiseSession) withholdGranted(granted int64, p aether.ResetPayload) {
	if p.Released > p.Charged {
		s.reportAbuse(abuse.ReasonMalformedFrame)
		return
	}
	returned := p.Charged - p.Released
	if uint64(granted) > returned {
		s.connWindow.Withhold(granted - int64(returned))
	}
}

// noteResetGrants keeps what a stream this side has reset granted, for a RESET of
// the peer's that crosses this side's on the path and so finds the stream gone
// (handleReset), with the stream as this side's RESET names it (inc), which the
// crossing RESET names too. A count of zero needs no note, nothing can have been
// granted twice; the map is bounded by the session's stream cap, past which a note
// is dropped and a crossing costs the sender only the credit it held twice, and by
// sweepResetGrants' lifetime. createStream drops the note when the ID is reused.
func (s *NoiseSession) noteResetGrants(streamID uint64, granted int64, inc aether.StreamIncarnation) {
	if granted <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	limit := s.opts.MaxConcurrentStreams
	if limit <= 0 {
		limit = aether.DefaultMaxConcurrentStreams
	}
	if s.resetGrants == nil {
		s.resetGrants = make(map[uint64]resetGrant)
	}
	if len(s.resetGrants) >= limit {
		return
	}
	s.resetGrants[streamID] = resetGrant{granted: granted, at: time.Now(), inc: inc}
}

// sweepResetGrants drops notes older than resetGrantLifetime: the peer's RESET was
// not crossing this side's.
func (s *NoiseSession) sweepResetGrants(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, g := range s.resetGrants {
		if now.Sub(g.at) > resetGrantLifetime {
			delete(s.resetGrants, id)
		}
	}
}

// controlHandler returns a ControlFrameHandler bound to this session's
// scheduler, health monitor, conn-window and frame writer. Constructed
// per-call (cheap struct) so handler call sites stay independent of
// session lifecycle ordering. The stream-window lookup acquires s.mu
// around the streams-map read, as every reader of s.streams does.
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
		s.deliverToControl(frame.Payload)
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
func (s *NoiseSession) sendCompositeACK(streamID uint64, cack *aether.CompositeACK) {
	// ECN piggyback. Two inputs feed the per-ACK CE-byte total:
	//   1. The adapter-level ceObservedBytes, written by
	//      NoiseSession.RecordCEBytes for a layer above the Noise conn
	//      that observes CE itself; no caller in this repository writes
	//      it, so this input is 0 unless a consumer calls RecordCEBytes.
	//   2. The transport-level counter on the underlying *noiseConn,
	//      drained via the noiseConnCE interface. When the TOS byte the
	//      listener's ecnReader returns carries the CE codepoint, the
	//      conn's decryptAndDeliver adds the decrypted DATA packet's
	//      payload length, the frame bytes the peer wrote, through
	//      noiseConn.RecordCEBytes.
	// Summing both lets either source reach the sender's OnCE through
	// the same CompositeACK, whichever layer observed the mark.
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
		StreamID:   streamID,
		Type:       aether.TypeACK,
		Flags:      aether.FlagCOMPOSITE_ACK, // marks as Composite ACK format
		AckNo:      cack.BaseACK,             // mirror the cumulative ACK in the header field for peers that only decode the header
		Length:     uint32(len(payload)),
		Payload:    payload,
	}
	s.writeFrame(frame)
}

// RecordCEBytes takes n bytes of inbound packets whose IP/IPv6 TOS field
// carried the CE codepoint (0x03), for a consumer that observes CE above the
// Noise conn; no caller in this repository calls it (the listener's socket
// path feeds the noiseConn's own counter, which sendCompositeACK drains
// through noiseConnCE). n counts frame bytes, what this session's conn.Read
// returns for those packets, because the peer caps the claim against the
// frame bytes it wrote (bytesSentSinceLastCE); a datagram's size would add the
// transport's own header and tag. The bytes are folded into the next outbound
// CompositeACK via CEBytes/CACKHasECN so the sender's congestion controller
// sees the ECN signal.
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

// deliverToControl queues a control-plane frame (handled in dispatch and
// handleHandshake) for the control stream's consumer. No stream on a session
// whose control stream is not open receives it.
func (s *NoiseSession) deliverToControl(payload []byte) {
	s.mu.Lock()
	st, ok := s.streams[s.layout.Control]
	s.mu.Unlock()
	if ok {
		st.enqueueControl(payload)
	}
}
