/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package aether

import (
	"time"

	"github.com/ORBTR/aether/flow"
)

// AutoTuneResult describes the outcome of a single AutoTuneWindow call
// — what the delta evaluation decided to do for one stream window.
//
// Action is "grow", "shrink", or "noop". Delta is the post-cap signed
// step the window would have applied (positive for grow, negative for
// shrink, zero for noop). Applied is what the window actually moved by
// — flow.StreamWindow.GrowWindow / ShrinkWindow can return less than
// the requested delta if the window hit a cap. Current is what the
// window's CurrentWindow() reports after the call.
//
// Adapters use the result for per-stream debug logging without having
// to re-query the window state.
type AutoTuneResult struct {
	Action  string
	Delta   int64
	Applied int64
	Current int64
}

// AutoTuneWindow feeds an RTT sample into the stream's flow.StreamWindow
// and applies a bounded grow / shrink based on SuggestedWindow(). Step
// is capped at ±25% of the current window to avoid oscillation.
//
// Returns an AutoTuneResult describing what happened so the adapter can
// emit a per-stream log line. ResetPeak() is invoked regardless so the
// next pass starts from a fresh peak measurement.
//
// It is AutoTuneWindowWithin with flow.MaxGrowableWindow as the ceiling, which
// GrowWindow never passes anyway. Only tests call it in this repository:
// noiseStream.autoTune goes through AutoTuneWindowWithin and a byte-stream session
// keeps no window.
//
// Returns the zero AutoTuneResult{Action:"noop"} when rtt <= 0 or when
// suggested == current — i.e. no work needed.
func AutoTuneWindow(w *flow.StreamWindow, rtt time.Duration) AutoTuneResult {
	return AutoTuneWindowWithin(w, rtt, flow.MaxGrowableWindow)
}

// AutoTuneWindowWithin is the tuning step with growth stopped at ceiling: a
// grow step takes the window to ceiling at most, and a window at or above
// ceiling does not grow; shrinking is unchanged. The step is pure: the adapter
// supplies the RTT and the ceiling, and logs the result.
//
// The Noise adapter passes the credit its session reserved for the stream at
// admission (noiseStream.autoTune). That one window is both the sender's credit,
// which Send consumes, and the receiver's grant accounting and per-stream queue
// ceiling (noiseStream.receiveCeilings), so growing it past the reservation
// would let one side take or admit credit the other side never granted and the
// session's ledger never reserved.
func AutoTuneWindowWithin(w *flow.StreamWindow, rtt time.Duration, ceiling int64) AutoTuneResult {
	if w == nil || rtt <= 0 {
		return AutoTuneResult{Action: "noop"}
	}
	w.SetRTT(rtt)
	current := w.CurrentWindow()
	suggested := w.SuggestedWindow()
	if suggested == current {
		// Still call ResetPeak — keeps adapter call sites uniform.
		w.ResetPeak()
		return AutoTuneResult{Action: "noop", Current: current}
	}
	delta := suggested - current
	maxStep := current / 4 // ±25 % per tick
	if delta > maxStep {
		delta = maxStep
	} else if delta < -maxStep {
		delta = -maxStep
	}
	if room := ceiling - current; delta > 0 && delta > room {
		delta = room
		if delta < 0 {
			delta = 0
		}
	}
	res := AutoTuneResult{Action: "noop", Delta: delta, Current: current}
	if delta > 0 {
		res.Applied = w.GrowWindow(delta)
		res.Action = "grow"
		res.Current = current + res.Applied
	} else if delta < 0 {
		res.Applied = w.ShrinkWindow(-delta)
		res.Action = "shrink"
		res.Current = current - res.Applied
	}
	w.ResetPeak()
	return res
}
