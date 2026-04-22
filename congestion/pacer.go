/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package congestion

import (
	"sync"
	"time"
)

// PacingPolicy is the common interface satisfied by both the token-bucket
// Pacer and the send-time SendTimePacer. The writeLoop holds one of these
// regardless of which congestion controller is active.
type PacingPolicy interface {
	// TimeUntilSend returns how long to wait before n bytes can be sent.
	TimeUntilSend(n int) time.Duration
	// OnSend records that n bytes were just transmitted.
	OnSend(n int)
	// SetRate updates the pacing rate (bytes/sec).
	SetRate(rateBytesSec float64)
	// Rate returns the current pacing rate (bytes/sec).
	Rate() float64
}

// Pacer implements a token bucket pacing algorithm.
// Controls the rate at which frames are sent to avoid bursts.
// Rate = cwnd / RTT (bytes per second).
type Pacer struct {
	mu        sync.Mutex
	tokens    float64       // available tokens (bytes)
	maxBurst  float64       // maximum burst size (tokens)
	rate      float64       // refill rate (bytes/sec)
	lastRefill time.Time
}

// NewPacer creates a token bucket pacer with the given rate and burst.
func NewPacer(rateBytesSec float64, maxBurstBytes int) *Pacer {
	return &Pacer{
		tokens:     float64(maxBurstBytes),
		maxBurst:   float64(maxBurstBytes),
		rate:       rateBytesSec,
		lastRefill: time.Now(),
	}
}

// SetRate updates the pacing rate (typically called when cwnd or RTT changes).
func (p *Pacer) SetRate(rateBytesSec float64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rate = rateBytesSec
}

// CanSend returns true if enough tokens are available to send n bytes.
func (p *Pacer) CanSend(n int) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refill()
	return p.tokens >= float64(n)
}

// Consume takes n tokens (bytes) from the bucket.
// Returns false if insufficient tokens (caller should wait).
func (p *Pacer) Consume(n int) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refill()
	if p.tokens < float64(n) {
		return false
	}
	p.tokens -= float64(n)
	return true
}

// TimeUntilSend returns how long to wait before n bytes can be sent.
// Returns 0 if tokens are already available.
func (p *Pacer) TimeUntilSend(n int) time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refill()
	if p.tokens >= float64(n) {
		return 0
	}
	deficit := float64(n) - p.tokens
	if p.rate <= 0 {
		return time.Hour // no rate set
	}
	return time.Duration(deficit / p.rate * float64(time.Second))
}

// refill adds tokens based on elapsed time. Must be called with mu held.
func (p *Pacer) refill() {
	now := time.Now()
	elapsed := now.Sub(p.lastRefill).Seconds()
	if elapsed <= 0 {
		return
	}
	p.tokens += elapsed * p.rate
	if p.tokens > p.maxBurst {
		p.tokens = p.maxBurst
	}
	p.lastRefill = now
}

// Rate returns the current pacing rate.
func (p *Pacer) Rate() float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.rate
}

// Available returns the currently available tokens.
func (p *Pacer) Available() float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refill()
	return p.tokens
}

// OnSend records that n bytes were sent (PacingPolicy interface).
// For the token-bucket Pacer this is just Consume — the writeLoop should
// have called CanSend / Consume before sending, but this satisfies the
// interface uniformly with SendTimePacer.OnSend.
func (p *Pacer) OnSend(n int) { p.Consume(n) }

// Compile-time check
var _ PacingPolicy = (*Pacer)(nil)
var _ PacingPolicy = (*SendTimePacer)(nil)

// ────────────────────────────────────────────────────────────────────────────
// SendTimePacer — send-time-based pacing
// ────────────────────────────────────────────────────────────────────────────

// SendTimePacer paces frames by computing each packet's earliest send time
// from the previous send time and the configured rate, instead of refilling
// a token bucket. This matches BBR's pacing model (the controller computes
// `send_time = last_send_time + packet_size / pacing_rate`) and produces
// smoother packet spacing than token-bucket pacing because there is no
// burst credit to accumulate.
//
// Use SendTimePacer when the congestion controller is BBR; the legacy
// token-bucket Pacer remains the right choice for CUBIC, which has no
// pacing model.
type SendTimePacer struct {
	mu       sync.Mutex
	rate     float64   // bytes/sec (set by congestion controller)
	lastSend time.Time // when the last packet was sent
}

// NewSendTimePacer creates a send-time pacer with the given initial rate.
func NewSendTimePacer(rateBytesPerSec float64) *SendTimePacer {
	return &SendTimePacer{
		rate:     rateBytesPerSec,
		lastSend: time.Now(),
	}
}

// SetRate updates the pacing rate (called by the congestion controller).
func (p *SendTimePacer) SetRate(rateBytesPerSec float64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rate = rateBytesPerSec
}

// Rate returns the current pacing rate (bytes/sec).
func (p *SendTimePacer) Rate() float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.rate
}

// TimeUntilSend returns how long the writeLoop should wait before sending
// a packet of size n bytes. Returns 0 if it can be sent immediately.
// When rate is non-positive, pacing is disabled and returns 0.
func (p *SendTimePacer) TimeUntilSend(n int) time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.rate <= 0 {
		return 0
	}
	interval := time.Duration(float64(n) / p.rate * float64(time.Second))
	nextSend := p.lastSend.Add(interval)
	wait := time.Until(nextSend)
	if wait < 0 {
		return 0
	}
	return wait
}

// OnSend records that a packet of size n was transmitted. Advances the
// next-send schedule. Falling-behind sends do NOT accumulate credit
// (lastSend snaps to now) — that's the key difference from token-bucket
// pacing, which would burst out N packets to "catch up".
func (p *SendTimePacer) OnSend(n int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.rate <= 0 {
		p.lastSend = time.Now()
		return
	}
	now := time.Now()
	interval := time.Duration(float64(n) / p.rate * float64(time.Second))
	nextSend := p.lastSend.Add(interval)
	if now.After(nextSend) {
		// Behind schedule — snap to now so we don't accumulate burst credit.
		p.lastSend = now
	} else {
		p.lastSend = nextSend
	}
}
