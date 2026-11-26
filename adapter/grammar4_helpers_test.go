//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package adapter

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ORBTR/aether"
)

// frameFilterConn is a net.Conn whose Write decodes the one full-header frame a
// NoiseSession hands it per write and drops it when the rule set on it says so,
// which is a frame lost on the path: the writer's own accounting sees it written.
// A session over it takes full headers (filteredPair), so every frame decodes.
type frameFilterConn struct {
	net.Conn
	rule atomic.Pointer[func(*aether.Frame) bool]

	mu      sync.Mutex
	written map[aether.FrameType]int
	dropped map[aether.FrameType]int
	largest map[aether.FrameType]int
}

func (c *frameFilterConn) setRule(rule func(*aether.Frame) bool) {
	if rule == nil {
		c.rule.Store(nil)
		return
	}
	c.rule.Store(&rule)
}

func (c *frameFilterConn) count(t aether.FrameType) (written, dropped int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.written[t], c.dropped[t]
}

func (c *frameFilterConn) largestWrite(t aether.FrameType) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.largest[t]
}

func (c *frameFilterConn) Write(b []byte) (int, error) {
	f, err := aether.DecodeFrameFromBytes(b)
	if err != nil {
		return c.Conn.Write(b)
	}
	drop := false
	if rule := c.rule.Load(); rule != nil {
		drop = (*rule)(f)
	}
	c.mu.Lock()
	if c.written == nil {
		c.written, c.dropped, c.largest = make(map[aether.FrameType]int), make(map[aether.FrameType]int), make(map[aether.FrameType]int)
	}
	c.written[f.Type]++
	if len(b) > c.largest[f.Type] {
		c.largest[f.Type] = len(b)
	}
	if drop {
		c.dropped[f.Type]++
	}
	c.mu.Unlock()
	if drop {
		return len(b), nil
	}
	return c.Conn.Write(b)
}

// filteredPair runs two NoiseSessions over one loopback connection, each writing
// through its own frameFilterConn, with the short forms off so a filter reads every
// frame. Both conns report one realm, so the sessions can fragment.
func filteredPair(t *testing.T, change func(*aether.SessionOptions)) (client, server *NoiseSession, toServer, toClient *frameFilterConn) {
	t.Helper()
	chosen := aetherChosen(t)
	c, s := loopbackPair(t)
	toServer, toClient = &frameFilterConn{Conn: c}, &frameFilterConn{Conn: s}
	opts := aether.DefaultSessionOptions()
	opts.HeaderComp = false
	if change != nil {
		change(&opts)
	}
	key := uint32(0x5eed5eed)
	client = NewNoiseSession(realmConn{Conn: toServer, chosen: chosen, key: key, bound: true}, "vl1_filter_client", "vl1_filter_server", opts)
	server = NewNoiseSession(realmConn{Conn: toClient, chosen: chosen, key: key, bound: true}, "vl1_filter_server", "vl1_filter_client", opts)
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	return client, server, toServer, toClient
}

// grantedForTest reads the queue's granted count without ending the queue.
func (q *recvQueue) grantedForTest() int64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.granted
}
