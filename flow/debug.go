/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package flow

import (
	"log"
	"os"
	"strings"
)

// Flow package debug logger. Mirrors the top-level aether/debug.go matcher
// without importing the parent package (would create an import cycle).
// Namespace: "aether.flow".
//
// Matching rules (same as aether/debug.go):
//
//	DEBUG=*          — everything
//	DEBUG=aether     — enables aether.flow (ancestor match)
//	DEBUG=aether.flow — exact match
var dbgFlow = newDbg("aether.flow")

type dbgLogger struct {
	prefix  string
	enabled bool
}

func newDbg(ns string) *dbgLogger {
	enabled := false
	raw := os.Getenv("DEBUG")
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if entry == "*" || ns == entry || strings.HasPrefix(ns, entry+".") {
			enabled = true
			break
		}
	}
	return &dbgLogger{prefix: "[" + ns + "] ", enabled: enabled}
}

func (d *dbgLogger) Printf(format string, args ...interface{}) {
	if d.enabled {
		log.Printf(d.prefix+format, args...)
	}
}
