/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import "github.com/ORBTR/aether"

// MaxAppMessageBudget returns the largest fully-encoded application message, in
// bytes, that fits one Aether frame of the given transport class without
// fragmentation. It reads the class frame size from aether.DefaultsForClass and
// subtracts the per-frame overhead through MSSToMaxPayload, which is the sole
// owner of the Aether-header + Noise-AEAD-tag figure, so that overhead is not
// duplicated here. A caller that keeps every encoded message at or below the
// budget for the class it actually rides never reaches SplitMessage, leaving
// fragmentation as anomaly-only defence.
//
// An unrecognised class resolves to the ClassSTREAM budget, matching
// DefaultsForClass. That is compatibility behaviour only and is NOT
// fail-closed: the ClassSTREAM budget (65470) far exceeds the ClassRAW frame
// (1334), so an unknown value that in fact rides a ClassRAW path returns a
// budget larger than the frame can carry. This accessor cannot make an unknown
// class safe; a caller must not treat an unknown class as transport-eligible,
// must validate the eligible class set first, and must take the reachable
// minimum, which is MaxAppMessageBudget(ClassRAW).
func MaxAppMessageBudget(class aether.TransportClass) int {
	return MSSToMaxPayload(aether.DefaultsForClass(class).MaxFrameSize)
}
