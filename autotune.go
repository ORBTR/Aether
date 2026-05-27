/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
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
// Adapters (Noise + TCP) used to inline an identical 30-line copy of
// this math, varying only in where the RTT comes from and how they log
// — those concerns stay in the adapter (the per-stream snapshot under
// s.mu happens there). AutoTuneWindow is the pure inner step.
//
// Returns the zero AutoTuneResult{Action:"noop"} when rtt <= 0 or when
// suggested == current — i.e. no work needed.
func AutoTuneWindow(w *flow.StreamWindow, rtt time.Duration) AutoTuneResult {
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
	res := AutoTuneResult{Delta: delta, Current: current}
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
