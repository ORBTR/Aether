/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package aether

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
)

// CaptureCallerChain returns a `file:line<-file:line<-…` string covering
// `depth` frames starting `skip` frames up from the call site.
//
// Pre-refactor the Noise and TCP adapters' CloseWithError each carried a
// 20-line copy of this runtime.Callers + frames loop because identifying
// the first closer in a close cascade ("which goroutine started the
// teardown?") was load-bearing for diagnosing churn. One definition keeps
// the log format identical across transports — operators grep one shape.
//
// skip is the number of frames above this helper to elide before
// recording — typically 1 (i.e. start at the function that called
// CaptureCallerChain). depth caps the number of frames included; the
// loop exits early on frames.Next reporting !more.
func CaptureCallerChain(skip, depth int) string {
	if depth <= 0 {
		return ""
	}
	// +1 to step past this helper itself.
	pcs := make([]uintptr, depth)
	n := runtime.Callers(skip+1, pcs)
	if n == 0 {
		return ""
	}
	frames := runtime.CallersFrames(pcs[:n])
	out := ""
	for i := 0; i < depth; i++ {
		fr, more := frames.Next()
		file := fr.File
		if idx := strings.LastIndex(file, "/"); idx >= 0 {
			file = file[idx+1:]
		}
		if out != "" {
			out += "<-"
		}
		out += fmt.Sprintf("%s:%d", file, fr.Line)
		if !more {
			break
		}
	}
	return out
}

// DebugLogger provides conditional debug logging, enabled by the DEBUG
// environment variable. All Aether namespaces are prefixed "aether.*"
// (e.g. "aether", "aether.gossip", "aether.transport", "aether.flow")
// so they coexist with the HSTLES Library debug system which uses the
// same DEBUG var.
//
// Matching is hierarchical with comma-separated entries:
//
//	DEBUG=*                           — enable every namespace
//	DEBUG=aether                      — enable aether + all aether.* descendants
//	DEBUG=aether.flow                 — enable aether.flow + aether.flow.* descendants
//	DEBUG=aether.flow,aether.gossip   — enable both explicitly
//
// An entry matches a namespace when the namespace equals the entry or
// starts with "entry.". Prior versions used plain substring matching in
// the wrong direction, so DEBUG=aether did not enable aether.flow.
type DebugLogger struct {
	namespace string
	enabled   bool
}

// debugEntries is the parsed list of comma-separated DEBUG entries
// (populated at package init). A nil/empty slice means nothing is enabled.
// The literal "*" entry short-circuits matchAnyDebugEntry to always true.
var debugEntries []string

func init() {
	debugEntries = parseDebugEntries(os.Getenv("DEBUG"))
}

// parseDebugEntries splits the DEBUG env var on commas, trims whitespace,
// and drops empty entries. Exported-looking "parse" style so tests can drive it.
func parseDebugEntries(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := parts[:0]
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// matchesAnyDebugEntry reports whether the given namespace matches any
// entry in debugEntries. An entry matches when:
//   - entry == "*" (enable everything), or
//   - namespace == entry (exact match), or
//   - namespace starts with entry + "." (entry is an ancestor).
func matchesAnyDebugEntry(namespace string) bool {
	for _, e := range debugEntries {
		if e == "*" {
			return true
		}
		if namespace == e {
			return true
		}
		if strings.HasPrefix(namespace, e+".") {
			return true
		}
	}
	return false
}

// NewDebugLogger creates a debug logger for the given namespace.
// Enabled when DEBUG matches the namespace or any ancestor (see top-of-file doc).
func NewDebugLogger(namespace string) *DebugLogger {
	return &DebugLogger{namespace: namespace, enabled: matchesAnyDebugEntry(namespace)}
}

// Printf logs a formatted message if this namespace is enabled.
func (d *DebugLogger) Printf(format string, args ...interface{}) {
	if d.enabled {
		log.Printf("["+d.namespace+"] "+format, args...)
	}
}

// Enabled returns whether this logger is active.
func (d *DebugLogger) Enabled() bool { return d.enabled }

// Root package debug loggers (used by files merged from aether/ and transport/).
var (
	dbgAether    = NewDebugLogger("aether")
	dbgGossip    = NewDebugLogger("aether.gossip")
	dbgTransport = NewDebugLogger("aether.transport")
)

// autoTuneDisabled caches the AETHER_AUTOTUNE kill switch read at init so
// every session tick doesn't re-parse the env. Set AETHER_AUTOTUNE=off
// (or "0", "false", "no", "disable") to disable runtime window tuning on
// all sessions — windows keep their configured initial size for the
// lifetime of the session.
var autoTuneDisabled bool

func init() {
	switch strings.ToLower(os.Getenv("AETHER_AUTOTUNE")) {
	case "off", "0", "false", "no", "disable", "disabled":
		autoTuneDisabled = true
	}
}

// AutoTuneDisabled reports whether the flow-control auto-tuner is disabled
// via the AETHER_AUTOTUNE env var. Session housekeeping ticks consult this
// before calling any Grow/Shrink on stream windows.
func AutoTuneDisabled() bool { return autoTuneDisabled }
