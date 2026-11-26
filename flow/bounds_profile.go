/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package flow

import (
	"errors"
	"fmt"
	"math"
)

// BoundsProfileVersion is the version of the credit numbers CurrentBounds
// holds. aether.WireVersionBounds carries it in every session's negotiated
// set, because a sender's connection credit is only safe against the memory
// ceiling of a receiver running the same numbers: a change to any value in the
// profile is a new version, and peers on different versions refuse each other
// before a session exists.
const BoundsProfileVersion uint16 = 2

// DefaultSessionMemoryCeiling is the most a session's receive queues hold of
// what its peer's credit paid for (16 MiB), the profile's session ceiling.
const DefaultSessionMemoryCeiling int64 = 16 * 1024 * 1024

// DefaultPeerMemoryCeiling is the most the receive queues of every session to one
// peer hold together (24 MiB), the profile's per-peer ceiling: one session's ceiling
// and half of another's, so a second session to the peer has room beside one at its
// own ceiling, and no number of sessions brings a peer a fresh ceiling each.
const DefaultPeerMemoryCeiling int64 = 24 * 1024 * 1024

// DefaultStreamCap is the profile's cap on a session's concurrent streams;
// aether.DefaultMaxConcurrentStreams is this value.
const DefaultStreamCap = 1024

// ErrBoundsProfileInvalid is what NewBoundsProfile wraps when the numbers it
// is given do not fit together.
var ErrBoundsProfileInvalid = errors.New("aether flow: bounds profile invalid")

// BoundsProfile is one set of credit and queue bounds, derived and validated
// together: a sender holds StreamCredit per stream and ConnCredit across a
// session, a receiver's queues hold at most SessionMemoryCeiling, and the two
// are one number, so credit a sender holds always fits what the receiver can
// queue, and a session stalls on its connection credit once
// SessionMemoryCeiling/StreamCredit streams have their credit unread. A peer's
// sessions together queue at most PeerMemoryCeiling, which a sender's credit does
// not cover: connection credit is per session, so a sender with several sessions can
// be inside its credit on each and past this, and the refusal is a stream's typed
// reset and no charge against the sender. Values come from NewBoundsProfile, which
// refuses numbers that do not fit.
type BoundsProfile struct {
	Version              uint16
	StreamCredit         int64
	SessionMemoryCeiling int64
	PeerMemoryCeiling    int64
	StreamCap            int
}

// NewBoundsProfile validates a set of bounds and returns the profile, or an
// error wrapping ErrBoundsProfileInvalid that names what does not fit:
//   - the version is not one this build runs;
//   - stream credit is below MinGuaranteedWindow, which a window never drops
//     under, or above MaxGrowableWindow, the capacity NewStreamWindowWithCap
//     builds it with;
//   - the ceiling, and so the connection credit, is below one stream's credit,
//     so that one stream's credit could never be spent;
//   - the per-peer ceiling is below the session's, so that one session to a peer
//     could never reach its own ceiling;
//   - the stream cap is not positive, or its admitted credit overflows or
//     stays below the ceiling, so that the streams a session may admit could
//     never reach the connection credit it declares.
func NewBoundsProfile(version uint16, streamCredit, sessionMemoryCeiling, peerMemoryCeiling int64, streamCap int) (BoundsProfile, error) {
	p := BoundsProfile{
		Version:              version,
		StreamCredit:         streamCredit,
		SessionMemoryCeiling: sessionMemoryCeiling,
		PeerMemoryCeiling:    peerMemoryCeiling,
		StreamCap:            streamCap,
	}
	refuse := func(format string, args ...any) (BoundsProfile, error) {
		return BoundsProfile{}, fmt.Errorf("%w: "+format, append([]any{ErrBoundsProfileInvalid}, args...)...)
	}
	switch {
	case version != BoundsProfileVersion:
		return refuse("version %d, this build runs %d", version, BoundsProfileVersion)
	case streamCredit < MinGuaranteedWindow:
		return refuse("stream credit %d below the guaranteed window %d", streamCredit, MinGuaranteedWindow)
	case streamCredit > MaxGrowableWindow:
		return refuse("stream credit %d above the window capacity %d", streamCredit, MaxGrowableWindow)
	case sessionMemoryCeiling < streamCredit:
		return refuse("session ceiling %d below one stream's credit %d", sessionMemoryCeiling, streamCredit)
	case peerMemoryCeiling < sessionMemoryCeiling:
		return refuse("peer ceiling %d below the session ceiling %d", peerMemoryCeiling, sessionMemoryCeiling)
	case streamCap <= 0:
		return refuse("stream cap %d", streamCap)
	case int64(streamCap) > math.MaxInt64/streamCredit:
		return refuse("stream cap %d at credit %d overflows", streamCap, streamCredit)
	case int64(streamCap)*streamCredit < sessionMemoryCeiling:
		return refuse("stream cap %d at credit %d admits less than the session ceiling %d", streamCap, streamCredit, sessionMemoryCeiling)
	}
	return p, nil
}

// ConnCredit is the connection credit a session's sender holds. It is the
// session's memory ceiling, derived and never set apart from it: a smaller
// credit would stall a session with memory to spare, and a larger one would
// let a sender inside its credit overrun a receiver.
func (p BoundsProfile) ConnCredit() int64 { return p.SessionMemoryCeiling }

// AdmittedCreditCeiling is the most receive credit a session's streams may
// hold admitted at once: the session's stream cap, or the profile's when
// streamCap is not positive, at the profile's stream credit. Streams opened at
// the profile's credit meet the stream cap first, and the ceiling binds when
// streams declare more than that. It bounds what streams are promised, which
// exceeds SessionMemoryCeiling by design: a session may have more streams than
// can fall behind at once, and it is the connection credit that stalls them
// when too many do. A cap too large to multiply gives the largest whole
// multiple of the stream credit.
func (p BoundsProfile) AdmittedCreditCeiling(streamCap int) int64 {
	streams := int64(streamCap)
	if streams <= 0 {
		streams = int64(p.StreamCap)
	}
	if most := math.MaxInt64 / p.StreamCredit; streams > most {
		streams = most
	}
	return streams * p.StreamCredit
}

// currentBounds is the profile this build runs. Its numbers are checked here
// so a build whose constants do not fit cannot start a session.
var currentBounds = mustBoundsProfile(BoundsProfileVersion, DefaultStreamCredit, DefaultSessionMemoryCeiling, DefaultPeerMemoryCeiling, DefaultStreamCap)

func mustBoundsProfile(version uint16, streamCredit, sessionMemoryCeiling, peerMemoryCeiling int64, streamCap int) BoundsProfile {
	p, err := NewBoundsProfile(version, streamCredit, sessionMemoryCeiling, peerMemoryCeiling, streamCap)
	if err != nil {
		panic(err)
	}
	return p
}

// CurrentBounds returns the profile this build runs: 1 MiB of stream credit, a
// 16 MiB session ceiling and connection credit, a 24 MiB per-peer ceiling, and 1024
// streams. NoiseSession builds its connection window and credit ledgers from it, a
// TCPSession bounds its delivery queues at its stream credit and session ceiling,
// and both hold what they queue for one peer at its per-peer ceiling.
func CurrentBounds() BoundsProfile { return currentBounds }
