/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"sync"
	"sync/atomic"
	"time"
)

// recvQueueEntryCost is what one queued message holds beyond its payload
// bytes: the queue entry and the allocation behind a payload. Credit charges
// it too (messageCredit), so the stream and connection credit a sender spends
// on a message is the cost the receiver's queue holds it at, and an empty
// message, which holds memory for no payload, is not free to send.
const recvQueueEntryCost = 64

// messageCredit is the credit one message of n payload bytes takes: what
// noiseStream.Send consumes from the stream and connection windows, what
// Receive records as consumed when it takes the message (the grants that
// replenish the sender), and what recvQueue counts against the stream and
// session ceilings. One count on both sides is what lets a sender inside its
// credit never meet a ceiling that counts more than credit does.
func messageCredit(n int64) int64 { return n + recvQueueEntryCost }

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
// inbox nor the inbound ACKs of any other stream; and it is bounded in credit
// (messageCredit) and not in a count of messages, because credit is what the
// sender has been admitted by and a count would turn a sender within its
// credit into a loss.
//
// Receive takes messages off under mu, and a stream's end does not lose what
// the queue holds: pop keeps returning it after end, which only stops further
// pushes.
//
// budget is the session-wide count of queued cost (messageCredit of every
// message). A message's cost stays in it until the message is taken (pop) or
// thrown away (discard): a stream's end, by either side, leaves what the queue
// holds charged, since a late consumer may still read it and the memory is
// held until then. Once the stream has ended the sender has its credit back
// from its own side (noiseStream.releaseInFlight), so nothing taken after that
// is credited.
type recvQueue struct {
	mu        sync.Mutex
	items     []recvItem
	head      int
	bytes     int64 // metered payload bytes queued
	credit    int64 // metered credit queued (messageCredit each), not yet replenished
	unmetered int   // messages queued that no credit was charged for
	cost      int64 // this queue's share of budget
	ended     bool
	noCredit  bool
	discarded bool
	// lastTake is the UnixNano of the last pop or of peerEnded, whichever is
	// later: sweepEndedQueues reads it to tell an abandoned queue from one a
	// late consumer is still draining.
	lastTake int64
	budget   *atomic.Int64

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

func recvItemCost(payload []byte) int64 { return messageCredit(int64(len(payload))) }

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
// take the queue past streamLimit (metered credit) or the session past
// sessionLimit (cost). Both count messageCredit, the unit the sender's credit
// is charged in. A limit of 0 or less is no limit.
func (q *recvQueue) push(payload []byte, streamLimit, sessionLimit int64) pushResult {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.ended {
		return pushEnded
	}
	c := recvItemCost(payload)
	if streamLimit > 0 && q.credit+c > streamLimit {
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

// appendLocked adds a message and charges its cost to budget. A discarded
// queue takes nothing: no consumer is left to read it.
func (q *recvQueue) appendLocked(it recvItem, c int64) {
	if q.discarded {
		return
	}
	q.items = append(q.items, it)
	if it.metered {
		q.bytes += int64(len(it.payload))
		q.credit += c
	} else {
		q.unmetered++
	}
	q.cost += c
	q.budget.Add(c)
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
	c := recvItemCost(it.payload)
	if it.metered {
		q.bytes -= int64(len(it.payload))
		q.credit -= c
	} else {
		q.unmetered--
	}
	q.cost -= c
	q.budget.Add(-c)
	q.lastTake = time.Now().UnixNano()
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

// peerEnded records that the stream has ended for the sender: its credit comes
// back from its own side (noiseStream.releaseInFlight, on its RESET or its last
// CLOSE), so a later Receive replenishes nothing. The messages stay charged to
// the session budget until they are read or discarded, so a peer that fills
// streams and then closes or resets them cannot grow memory past the ceiling
// behind a consumer that is not reading. Its callers are every exit of a stream
// that has queued what it may still hold (handleClose, handleReset, Close,
// Reset), and each then hands the queue to trackEnded. A nil queue is a stream
// built outside createStream, which Reset and Close may still reach.
func (q *recvQueue) peerEnded() {
	if q == nil {
		return
	}
	q.mu.Lock()
	q.noCredit = true
	q.lastTake = time.Now().UnixNano()
	q.mu.Unlock()
}

// discard throws away what the queue holds, returns its cost to the session
// budget and ends it for good. Its callers are enqueueDelivery, for a sender
// past every ceiling, and sweepEndedQueues, for a queue its consumer abandoned.
// Idempotent; nil-safe like peerEnded.
func (q *recvQueue) discard() {
	if q == nil {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.ended = true
	q.noCredit = true
	q.discarded = true
	q.budget.Add(-q.cost)
	q.cost = 0
	q.items, q.head, q.bytes, q.credit, q.unmetered = nil, 0, 0, 0, 0
}

// idleSince reports whether the queue is empty and how long since its consumer
// last took a message or the stream ended (peerEnded), for sweepEndedQueues.
func (q *recvQueue) idleSince(now time.Time) (empty bool, idle time.Duration) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.head == len(q.items), now.Sub(time.Unix(0, q.lastTake))
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
