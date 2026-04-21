//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package adapter

import (
	"fmt"
	"io"
	"log"
	"sync/atomic"
	"time"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/abuse"
	"github.com/ORBTR/aether/congestion"
	"github.com/ORBTR/aether/reliability"
)

// readLoop reads Aether frames from the Noise connection and dispatches to streams.
// Supports both full 50-byte headers and v2 short headers (0x82-0x87).
func (s *NoiseSession) readLoop() {
	defer s.CloseWithError(fmt.Errorf("readLoop exited"))
	buf := make([]byte, 1)
	for {
		if _, err := io.ReadFull(s.conn, buf); err != nil {
			if err != io.EOF {
				s.closeErr = err
			}
			return
		}

		var frame *aether.Frame
		var err error
		indicator := buf[0]

		if aether.IsShortHeader(buf[0]) {
			switch buf[0] {
			case aether.ShortDataIndicator:
				frame, err = s.compressor.DecodeDataShort(s.conn)
			case aether.ShortControlIndicator:
				frame, err = s.compressor.DecodeControlShort(s.conn)
			case aether.ShortACKIndicator:
				frame, err = s.compressor.DecodeACKShort(s.conn)
			case aether.ShortDataVarIndicator:
				frame, err = s.compressor.DecodeDataShortVar(s.conn)
			case aether.ShortEncryptedIndicator:
				frame, err = s.compressor.DecodeEncryptedDataShort(s.conn)
			case aether.ShortBatchIndicator:
				var frames []*aether.Frame
				frames, err = s.compressor.DecodeBatch(s.conn)
				if err == nil {
					for _, f := range frames {
						s.processIncomingFrame(f, indicator)
					}
					continue
				}
			default:
				err = fmt.Errorf("aether: unknown short header 0x%02x", buf[0])
			}
		} else {
			frame, err = aether.DecodeFrameWithFirstByte(s.conn, buf[0])
			if err == nil {
				s.compressor.RecordFullHeader(frame)
			}
		}
		if err != nil {
			if err != io.EOF {
				s.closeErr = err
			}
			return
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

	// Packet-level anti-replay check — DATA frames only.
	// Control frames (WINDOW, ACK, PING, PONG, GOAWAY, CLOSE, RESET, PRIORITY)
	// have SeqNo=0 and are not subject to replay attacks. Checking them against
	// the replay window causes all but the first to be silently dropped as
	// "duplicate", breaking flow control (WINDOW_UPDATE never reaches sender).
	if frame.Type == aether.TypeDATA && !s.packetReplay.Check(uint64(frame.SeqNo)) {
		return // replayed DATA frame — drop
	}
	s.healthMon.RecordActivity()
	s.dispatchFrame(frame)
}

// dispatchFrame routes an incoming frame to the appropriate handler.
func (s *NoiseSession) dispatchFrame(frame *aether.Frame) {
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
	case aether.TypeWHOIS, aether.TypeRENDEZVOUS, aether.TypeNETWORK_CONFIG:
		// Control plane — deliver to control stream
		s.deliverToStream(s.layout.Control, frame.Payload)
	}
}

// handleCongestion processes an explicit CONGESTION frame — peer-driven
// sender throttle hint. Session's throttle state is updated; send-path
// consumers can check it before committing large sends.
func (s *NoiseSession) handleCongestion(frame *aether.Frame) {
	p := aether.DecodeCongestion(frame.Payload)
	s.throttle.Apply(p)
	dbgNoise.Printf("CONGESTION recv severity=%d reason=%d backoff=%dms",
		p.Severity, p.Reason, p.BackoffMs)
}

// SendCongestion emits a CONGESTION frame to the peer.
func (s *NoiseSession) SendCongestion(p aether.CongestionPayload) error {
	payload := aether.EncodeCongestion(p)
	frame := &aether.Frame{
		SenderID:   s.localPeerID,
		ReceiverID: s.remotePeerID,
		StreamID:   aether.StreamConnectionLevel,
		Type:       aether.TypeCONGESTION,
		Length:     uint32(len(payload)),
		Payload:    payload,
	}
	return s.writeFrame(frame)
}

// Throttle exposes the session's congestion-throttle state.
func (s *NoiseSession) Throttle() *aether.CongestionThrottle {
	return &s.throttle
}

func (s *NoiseSession) handleData(frame *aether.Frame) {
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

	// Record stream activity for GC
	s.streamGC.RecordActivity(frame.StreamID)

	// Anti-replay check — unconditional for DATA (S7: feeds abuse score).
	// Previously gated on FlagANTIREPLAY, which a peer could suppress to
	// bypass per-stream replay protection. The connection-level
	// packetReplay above catches identical duplicates, but the per-stream
	// window defends against adversarial reordering within an open stream
	// and must not be opt-out.
	if !st.replay.Check(frame.SeqNo) {
		s.reportAbuse(abuse.ReasonReplayDetected)
		return // replayed frame — drop silently
	}

	// Reliability: insert into receive window for reordering
	delivered := st.recvWindow.Insert(frame.SeqNo, frame.Payload)
	for _, payload := range delivered {
		DeliverToRecvChWithSignals(st.recvCh, payload, st.window, st.streamID, s.sendWindowUpdateAgnostic, s.SendCongestion)
		// Connection-level flow control: track aggregate consumption.
		// Stream 0 WINDOW_UPDATE = connection-level grant (HTTP/2 convention).
		if grant := s.connWindow.ReceiverConsume(int64(len(payload))); grant > 0 {
			s.sendWindowUpdate(aether.StreamConnectionLevel, uint64(grant))
		}
	}

	// Notify ACK engine — it decides when to send based on adaptive policy
	if st.ackEngine != nil {
		st.ackEngine.OnDataReceived(frame.SeqNo, frame.StreamID == s.layout.Control)
	}

	// Congestion controller: record data received
	s.congestion().OnAck(int64(frame.Length), st.rtt.SRTT())
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

	// Remove acked from retransmit queue
	for _, entry := range acked {
		st.retransmitQ.Remove(entry.Frame.SeqNo)
	}

	// Implicit NACKs — fast retransmit (bitmap gaps beyond reorder threshold)
	for _, nackSeqNo := range nacks {
		if entry := st.sendWindow.GetEntry(nackSeqNo); entry != nil {
			s.sched.MarkRetransmit(frame.StreamID)
			s.sched.Enqueue(frame.StreamID, entry.Frame)
			s.congestion().OnLoss()
		}
	}

	// BBRv2 per-packet sampling (Concern #3). When the active controller
	// is BBR and the acked entry carries a stamped DeliveryRateSample,
	// route through OnAckSampled so the controller can compute true
	// delivery rate. Falls back to OnAck (degraded path) for CUBIC or
	// when the sample is missing (e.g. retransmitted entries).
	srtt := st.rtt.SRTT()
	if bbr, ok := s.congestion().(*congestion.BBRController); ok {
		for _, entry := range acked {
			if sample, ok := entry.BBRSample.(congestion.DeliveryRateSample); ok {
				bbr.OnAckSampled(int64(entry.Frame.Length), srtt, sample)
			} else {
				bbr.OnAck(int64(entry.Frame.Length), srtt)
			}
		}
	} else {
		var ackedBytes int64
		for _, entry := range acked {
			ackedBytes += int64(entry.Frame.Length)
		}
		s.congestion().OnAck(ackedBytes, srtt)
	}
	// ECN feedback (#15): peer reported CE-marked bytes since last ACK.
	// Notify the controller so it can react one RTT before queue overflow.
	if ack.Flags&aether.CACKHasECN != 0 && ack.CEBytes > 0 {
		s.congestion().OnCE(int64(ack.CEBytes))
	}
	// Congestion window may have advanced — wake the writeLoop so it
	// re-evaluates `CanSend`. Without this, frames re-enqueued after a
	// CanSend=false break would wait until the next Enqueue (or
	// indefinitely if traffic stops).
	if len(acked) > 0 {
		s.sched.Wake()
	}

	// Track BaseACK progress for stall detection. State lives on the stream
	// (not a session-level map) so it dies with the stream. Atomic CAS on
	// lastBaseACKSeen keeps concurrent handleACK calls monotonic without
	// holding s.mu.
	for {
		prev := st.lastBaseACKSeen.Load()
		if ack.BaseACK <= prev {
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
	//   1. Reed-Solomon — RS(k,m) recovers up to m losses (Concern #8)
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

	select {
	case s.acceptCh <- st:
	default:
	}
}

func (s *NoiseSession) handleImplicitOpen(frame *aether.Frame) {
	st := s.createStream(frame.StreamID, aether.DefaultStreamConfig(frame.StreamID), true /* enforceRemoteCap */)
	if st == nil {
		return
	}
	st.state.Transition(aether.EventRecvData)

	select {
	case s.acceptCh <- st:
	default:
	}

	// Deliver the data
	delivered := st.recvWindow.Insert(frame.SeqNo, frame.Payload)
	for _, payload := range delivered {
		DeliverToRecvChWithSignals(st.recvCh, payload, st.window, st.streamID, s.sendWindowUpdateAgnostic, s.SendCongestion)
		if grant := s.connWindow.ReceiverConsume(int64(len(payload))); grant > 0 {
			s.sendWindowUpdate(aether.StreamConnectionLevel, uint64(grant))
		}
	}
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
	// trackers. Before this fix, the s.streams entry lingered indefinitely
	// (only handleReset removed it), leaving the engine + send window +
	// streamGC map entry pinned.
	if st.ackEngine != nil {
		st.ackEngine.Flush()
		st.ackEngine.Stop()
	}
	remaining := st.recvWindow.Drain()
	for _, payload := range remaining {
		select {
		case st.recvCh <- payload:
		default:
		}
	}
	close(st.recvCh)
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
		close(st.recvCh)
		s.releaseStream(frame.StreamID)
	}
}

func (s *NoiseSession) handleWindowUpdate(frame *aether.Frame) {
	credit := aether.DecodeWindowUpdate(frame.Payload)
	if frame.StreamID == aether.StreamConnectionLevel {
		s.connWindow.ApplyUpdate(int64(credit))
	} else {
		s.mu.Lock()
		st, ok := s.streams[frame.StreamID]
		s.mu.Unlock()
		if ok {
			st.window.ApplyUpdate(int64(credit))
		}
	}
	// A stalled writeLoop (blocked on Consume because cwnd=0 / stream
	// credit exhausted) won't unblock on its own — Enqueue is the only
	// other thing that signals wake. Kick the scheduler so it re-evaluates
	// Consume the moment credit arrives. Without this the session
	// deadlocks on slow-receiver flows.
	if credit > 0 {
		s.sched.Wake()
	}
}

func (s *NoiseSession) handlePing(frame *aether.Frame) {
	pong := &aether.Frame{
		SenderID:   s.localPeerID,
		ReceiverID: s.remotePeerID,
		StreamID:   s.layout.Keepalive,
		Type:       aether.TypePONG,
		SeqNo:      frame.SeqNo,
	}
	s.writeFrame(pong)
}

func (s *NoiseSession) handlePong(frame *aether.Frame) {
	s.healthMon.RecordActivity()
	sentAt := time.Unix(0, int64(frame.SeqNo))
	s.healthMon.RecordPongRecv(frame.SeqNo, sentAt)
}

func (s *NoiseSession) handleGoAway(frame *aether.Frame) {
	reason, message := aether.DecodeGoAway(frame.Payload)
	// %q Go-quotes the peer-supplied message, neutralising log-injection
	// via embedded newlines / ANSI escapes that would otherwise forge
	// fake log lines in aggregators.
	log.Printf("[AETHER-NOISE] GOAWAY from %s: reason=%d msg=%q", string(s.remoteNodeID)[:12], reason, message)
	s.CloseWithError(fmt.Errorf("peer sent GOAWAY (reason=%d): %s", reason, message))
}

func (s *NoiseSession) handlePriority(frame *aether.Frame) {
	p := aether.DecodePriority(frame.Payload)
	s.sched.SetWeight(frame.StreamID, p.Weight)
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
			s.connID,
			nil, 0, sessionKey, hs.Payload,
		); err != nil {
			log.Printf("[AETHER-NOISE] Migration validation failed: %v", err)
			return
		}
		log.Printf("[AETHER-NOISE] Address migration accepted from %s", string(s.remoteNodeID))
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
			SenderID:   s.localPeerID,
			ReceiverID: s.remotePeerID,
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
		SenderID:   s.localPeerID,
		ReceiverID: s.remotePeerID,
		StreamID:   st.streamID,
		Type:       aether.TypeACK,
		Flags:      aether.FlagCOMPOSITE_ACK, // marks as Composite ACK format
		AckNo:      cack.BaseACK,             // piggyback in header for backward compat
		Length:     uint32(len(payload)),
		Payload:    payload,
	}
	s.writeFrame(frame)
}

// RecordCEBytes is called by the receive socket layer when an inbound
// packet's IP/IPv6 TOS field carries the CE codepoint (0x03). The bytes
// are folded into the next outbound CompositeACK via CEBytes/CACKHasECN.
// Concern #15.
func (s *NoiseSession) RecordCEBytes(n int) {
	if n <= 0 {
		return
	}
	atomic.AddUint64(&s.ceObservedBytes, uint64(n))
}

// sendWindowUpdate sends a WINDOW_UPDATE frame granting additional credit to the sender.
func (s *NoiseSession) sendWindowUpdate(streamID uint64, credit uint64) {
	payload := aether.EncodeWindowUpdate(credit)
	frame := &aether.Frame{
		SenderID:   s.localPeerID,
		ReceiverID: s.remotePeerID,
		StreamID:   streamID,
		Type:       aether.TypeWINDOW,
		Length:     uint32(len(payload)),
		Payload:    payload,
	}
	s.writeFrame(frame)
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
	if ok {
		DeliverToRecvChWithSignals(st.recvCh, payload, st.window, streamID, s.sendWindowUpdateAgnostic, s.SendCongestion)
		if grant := s.connWindow.ReceiverConsume(int64(len(payload))); grant > 0 {
			s.sendWindowUpdate(aether.StreamConnectionLevel, uint64(grant))
		}
	}
}
