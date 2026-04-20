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

// Flow package debug logger. Mirrors the top-level aether/debug.go logger but
// avoids the import cycle that would come from importing the parent package.
// Namespace: "aether.flow". Enable with DEBUG=aether.flow (or DEBUG=*).
var dbgFlow = newDbg("aether.flow")

type dbgLogger struct {
	prefix  string
	enabled bool
}

func newDbg(ns string) *dbgLogger {
	env := os.Getenv("DEBUG")
	enabled := env == "*" || strings.Contains(env, ns)
	return &dbgLogger{prefix: "[" + ns + "] ", enabled: enabled}
}

func (d *dbgLogger) Printf(format string, args ...interface{}) {
	if d.enabled {
		log.Printf(d.prefix+format, args...)
	}
}
