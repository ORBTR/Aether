/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"sync"
	"sync/atomic"
)

// recvQueueEntryCost is what one queued message costs the session's aggregate
// ceiling beyond its payload bytes: the queue entry and the allocation behind
// a payload. A peer's empty or one-byte messages charge its credit nothing or
// next to nothing, so this is what makes the ceiling bound memory for them.
const recvQueueEntryCost = 64

// recvItem is one whole message waiting for the stream's consumer. metered
// says the sender charged credit for it, so taking it replenishes credit; the
// control-plane frames deliverToControl queues were never charged.
type recvItem struct {
	payload []byte
	metered bool
}

// pushResult is what recvQueue.push did with a message.
type pushResult int

const (
	pushQueued pushResult = iota
	// pushEnded: the stream's teardown has run; nothing will read this.
	pushEnded
	// pushOverCredit: the message would take the stream or the session past
	// the ceiling a sender honouring its credit cannot reach.
	pushOverCredit
)

// recvQueue holds a noiseStream's whole in-order messages between the
// session's readLoop and the stream's one consumer. The readLoop pushes without
// waiting, so a slow consumer on one stream holds up neither the noiseConn
// inbox nor the inbound ACKs of any other stream; and it is bounded in bytes and
// not in a count of messages, because credit is what the sender has been
// admitted by and a count would turn a sender within its credit into a loss.
//
// Receive takes messages off under mu, and a stream's end does not lose what
// the queue holds: pop keeps returning it after end, which only stops further
// pushes.
//
// budget is the session-wide count of queued cost (payload bytes plus
// recvQueueEntryCost a message). A detached queue has given its share back and
// keeps only what a late consumer may still read. Once the stream has ended the
// sender has its credit back from its own side (noiseStream.releaseInFlight),
// so nothing taken after that is credited.
type recvQueue struct {
	mu        sync.Mutex
	items     []recvItem
	head      int
	bytes     int64 // metered payload bytes queued, the credit not yet replenished
	unmetered int   // messages queued that no credit was charged for
	cost      int64 // this queue's share of budget
	ended     bool
	noCredit  bool
	detached  bool
	budget    *atomic.Int64

	// wake holds one token while a Receive may find a message. push and pop
	// (for the next of several consumers) leave it non-blocking; a stale token
	// costs Receive one empty pop.
	wake chan struct{}
}

func newRecvQueue(budget *atomic.Int64) *recvQueue {
	if budget == nil {
		budget = new(atomic.Int64)
	}
	return &recvQueue{budget: budget, wake: make(chan struct{}, 1)}
}

func (q *recvQueue) signal() {
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

func recvItemCost(payload []byte) int64 { return int64(len(payload)) + recvQueueEntryCost }

// retained returns the slice the queue keeps. A short payload that is a window
// on a much larger decode buffer is copied, so the queue's bytes and cost
// describe what it actually holds in memory.
func retained(payload []byte) []byte {
	if cap(payload) > 2*len(payload)+recvQueueEntryCost {
		return append(make([]byte, 0, len(payload)), payload...)
	}
	return payload
}

// push queues one metered message unless the stream has ended or it would
// take the queue past streamLimit (metered bytes) or the session past
// sessionLimit (cost). A limit of 0 or less is no limit.
func (q *recvQueue) push(payload []byte, streamLimit, sessionLimit int64) pushResult {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.ended {
		return pushEnded
	}
	n := int64(len(payload))
	c := recvItemCost(payload)
	if streamLimit > 0 && q.bytes+n > streamLimit {
		return pushOverCredit
	}
	if sessionLimit > 0 && q.budget.Load()+c > sessionLimit {
		return pushOverCredit
	}
	q.appendLocked(recvItem{payload: retained(payload), metered: true}, c)
	return pushQueued
}

// pushUnmetered queues a message no credit was charged for, up to limit such
// messages at a time. Nothing paces their sender and no retransmit depends on
// them, so past the limit the caller counts them as dropped.
func (q *recvQueue) pushUnmetered(payload []byte, limit int) pushResult {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.ended {
		return pushEnded
	}
	if q.unmetered >= limit {
		return pushOverCredit
	}
	q.appendLocked(recvItem{payload: retained(payload)}, recvItemCost(payload))
	return pushQueued
}

// pushFinal queues what handleClose drains from the receive window after the
// local side has already closed: the stream's end has run for the local send
// side, and these are the last messages the reader sees before the end.
func (q *recvQueue) pushFinal(payload []byte) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.appendLocked(recvItem{payload: retained(payload), metered: true}, recvItemCost(payload))
}

func (q *recvQueue) appendLocked(it recvItem, c int64) {
	q.items = append(q.items, it)
	if it.metered {
		q.bytes += int64(len(it.payload))
	} else {
		q.unmetered++
	}
	if !q.detached {
		q.cost += c
		q.budget.Add(c)
	}
	q.signal()
}

// pop returns the oldest message. credited says the caller must record its
// bytes as consumed: the message was metered and its sender still counts it.
func (q *recvQueue) pop() (payload []byte, credited, ok bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.head == len(q.items) {
		return nil, false, false
	}
	it := q.items[q.head]
	q.items[q.head] = recvItem{}
	q.head++
	if q.head == len(q.items) {
		q.items, q.head = q.items[:0], 0
	} else if q.head > 1024 && q.head*2 > len(q.items) {
		n := copy(q.items, q.items[q.head:])
		for i := n; i < len(q.items); i++ {
			q.items[i] = recvItem{}
		}
		q.items, q.head = q.items[:n], 0
	}
	if it.metered {
		q.bytes -= int64(len(it.payload))
	} else {
		q.unmetered--
	}
	if !q.detached {
		c := recvItemCost(it.payload)
		q.cost -= c
		q.budget.Add(-c)
	}
	if q.head < len(q.items) {
		q.signal()
	}
	return it.payload, it.metered && !q.noCredit, true
}

// end stops further pushes; what the queue holds stays readable. Idempotent.
func (q *recvQueue) end() {
	q.mu.Lock()
	q.ended = true
	q.mu.Unlock()
}

// peerEnded records that the peer has left the stream: its sender has taken its
// credit back, so a later Receive replenishes nothing. The messages stay charged
// to the session budget until they are read or the stream is detached, so a
// peer that resets streams it has filled cannot grow memory past the ceiling
// behind a consumer that is not reading.
func (q *recvQueue) peerEnded() {
	q.mu.Lock()
	q.noCredit = true
	q.mu.Unlock()
}

// detach gives the queue's share of the session budget back once its consumer
// has given it up. discard also frees the messages. Idempotent. A nil queue is a
// stream built outside createStream, which Reset and Close may still reach.
func (q *recvQueue) detach(discard bool) {
	if q == nil {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.ended = true
	q.noCredit = true
	if !q.detached {
		q.detached = true
		q.budget.Add(-q.cost)
		q.cost = 0
	}
	if discard {
		q.items, q.head, q.bytes, q.unmetered = nil, 0, 0, 0
	}
}

// queuedBytes returns the metered payload bytes the queue holds.
func (q *recvQueue) queuedBytes() int64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.bytes
}

// len returns the number of messages the queue holds.
func (q *recvQueue) len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items) - q.head
}
