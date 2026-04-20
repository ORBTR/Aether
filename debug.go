/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package aether

import (
	"log"
	"os"
	"strings"
)

// DebugLogger provides conditional debug logging, enabled by the AETHER_DEBUG
// environment variable. Set AETHER_DEBUG=* for all, or AETHER_DEBUG=noise,tcp
// for specific namespaces.
type DebugLogger struct {
	namespace string
	enabled   bool
}

var debugNamespaces string

func init() {
	debugNamespaces = os.Getenv("AETHER_DEBUG")
}

// NewDebugLogger creates a debug logger for the given namespace.
// Enabled when AETHER_DEBUG contains the namespace or "*".
func NewDebugLogger(namespace string) *DebugLogger {
	enabled := debugNamespaces == "*" || strings.Contains(debugNamespaces, namespace)
	return &DebugLogger{namespace: namespace, enabled: enabled}
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
