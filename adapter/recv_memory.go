/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/flow"
)

// recvMemory is what one session's receive queues hold, which NoiseSession and
// TCPSession embed: the profile's session and per-peer ceilings bound it on every
// profile, whatever paces the sender. recvQueued is the cost of every stream's
// recvQ, and recvCharged the part of it no RESET has taken out of what a sender is
// held to, which a queue's push compares with the session ceiling. Both are written
// under each stream's queue lock and read without one.
//
// peerShare is this session's share of what every session to the peer holds, under
// the peer's entry in peerMemoryLedgers (or a parent of its own): a queue reserves
// each message's cost on it, so a peer's sessions together stay at the ceiling however
// many it opens. The session's close gives the share back at once, since a closed
// session's queues are read by consumers only.
//
// endedQueues are the receive queues of streams that have left the session with
// messages still unread. Their cost stays counted until the consumer takes them;
// sweepEnded discards a queue nobody has taken from for
// aether.DefaultStreamIdleTimeout, so a consumer that abandons a stream does not hold
// the session's budget for the session's life, and makeQueueRoom discards one a RESET
// ended when a message needs its room. Guarded by endedMu, which nothing else is held
// under but the queue locks trackEnded and the sweep take after it.
type recvMemory struct {
	recvQueued  atomic.Int64
	recvCharged atomic.Int64

	peerShare  *creditLedger
	peerShared bool

	endedMu     sync.Mutex
	endedQueues map[*recvQueue]struct{}
}

// joinPeerMemory builds the session's share. sharedPeer joins the remote node ID's
// entry in peerMemoryLedgers, which leavePeerMemory leaves; false gives the session a
// parent of its own at the same ceiling, for a session whose remote node ID is a
// stated label, since sharing it would let one peer spend another's room.
func (m *recvMemory) joinPeerMemory(remote aether.NodeID, sharedPeer bool) {
	ceiling := flow.CurrentBounds().PeerMemoryCeiling
	var parent *creditLedger
	if sharedPeer {
		parent = peerMemoryLedgers.join(remote, ceiling)
		m.peerShared = true
	} else {
		parent = newCreditLedger("peer memory", ceiling, nil)
	}
	m.peerShare = newCreditLedger("session memory", math.MaxInt64, parent)
	m.endedQueues = make(map[*recvQueue]struct{})
}

// leavePeerMemory ends the session's share, on the session's one close path. A
// session built without one has none to end.
func (m *recvMemory) leavePeerMemory(remote aether.NodeID) {
	if m.peerShare == nil {
		return
	}
	m.peerShare.close()
	if m.peerShared {
		peerMemoryLedgers.leave(remote, m.peerShare.parent)
	}
}

// newQueue builds a stream's receive queue counting into this session's totals.
func (m *recvMemory) newQueue() *recvQueue {
	q := newRecvQueue(&m.recvQueued, &m.recvCharged)
	q.peerShare = m.peerShare
	return q
}

// trackEnded puts the queue of a stream leaving the session on endedQueues when it
// still holds messages. Its callers are the stream's exits: from then on the stream GC
// does not see the stream, and the queue's cost stays in recvQueued until the consumer
// takes its messages or sweepEnded discards them.
func (m *recvMemory) trackEnded(q *recvQueue) {
	if q == nil || q.len() == 0 {
		return
	}
	m.endedMu.Lock()
	m.endedQueues[q] = struct{}{}
	m.endedMu.Unlock()
}

// sweepEnded runs on the session's ten-second tick. It drops endedQueues entries
// the consumer has emptied, and discards the messages of a queue nobody has taken from
// for aether.DefaultStreamIdleTimeout, the same idle bound the stream GC gives a stream
// still in the session; the discard takes their cost off recvQueued, and grant, nil on a
// profile whose sender holds no credit, returns the credit its sender still had charged
// for them, which no later Receive will record.
func (m *recvMemory) sweepEnded(now time.Time, grant func(int64)) {
	for _, q := range m.endedQueueList() {
		empty, idle := q.idleSince(now)
		if !empty && idle < aether.DefaultStreamIdleTimeout {
			continue
		}
		if !empty {
			n := q.discard()
			if grant != nil {
				grant(n)
			}
		}
		m.forgetEnded(q)
	}
}

// makeQueueRoom keeps the session's queues inside ceiling, and the peer's inside its
// own, for a message of cost need that the readLoop is about to queue. What a push
// holds a sender to counts only recvCharged, so the memory past it is queues a RESET
// ended, which no sender is held to, and control frames. The readLoop discards the
// longest-idle such queue until the message fits: that stream has already ended, and
// its consumer, if it returns, reads aether.ErrStreamOverrun. Control frames are never
// discarded; they are bounded by their own count on the one control stream, and that
// count is what the session's queues can stand past the ceiling once no RESET's queue
// is left.
func (m *recvMemory) makeQueueRoom(need, ceiling int64) {
	for m.recvQueued.Load()+need > ceiling || !m.peerShare.fits(need) {
		q := m.longestIdleResetQueue()
		if q == nil {
			return
		}
		q.discard()
		m.forgetEnded(q)
	}
}

// longestIdleResetQueue returns the endedQueues entry a RESET ended that has gone
// longest with nothing taken from it, or nil when there is none.
func (m *recvMemory) longestIdleResetQueue() *recvQueue {
	var (
		oldest   *recvQueue
		earliest int64
	)
	for _, q := range m.endedQueueList() {
		if last, ok := q.idleResetQueue(); ok && (oldest == nil || last < earliest) {
			oldest, earliest = q, last
		}
	}
	return oldest
}

// endedQueueList copies endedQueues, so its readers can take each queue's lock
// without holding endedMu.
func (m *recvMemory) endedQueueList() []*recvQueue {
	m.endedMu.Lock()
	defer m.endedMu.Unlock()
	queues := make([]*recvQueue, 0, len(m.endedQueues))
	for q := range m.endedQueues {
		queues = append(queues, q)
	}
	return queues
}

func (m *recvMemory) forgetEnded(q *recvQueue) {
	m.endedMu.Lock()
	delete(m.endedQueues, q)
	m.endedMu.Unlock()
}
