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

// recvQueue holds a stream's whole in-order messages between the session's
// readLoop and the stream's one consumer. The readLoop pushes without waiting,
// so a slow consumer on one stream holds up neither the noiseConn inbox nor the
// inbound ACKs of any other stream; and it is bounded in credit (messageCredit)
// and not in a count of messages, because credit is what the sender has been
// admitted by and a count would turn a sender within its credit into a loss. A
// tcpStream's sender holds no credit: the same count bounds its queue at the
// bounds profile's stream credit (enqueueDelivery), and it uses neither session
// total nor the credit a pop reports.
//
// Receive takes messages off under mu, and a stream's end does not lose what
// the queue holds: pop keeps returning it after end, which only stops further
// pushes.
//
// Two session-wide counts follow the queue. budget is the cost (messageCredit)
// of every queued message, which is what the session's memory holds: it falls
// only when a message is taken (pop) or thrown away (discard), since a late
// consumer may still read a message after the stream's end. charged is the part
// of budget the sender still has charged to its connection window, the count
// push holds a sender to: a sender inside its credit cannot take it past the
// ceiling however far behind the consumers are.
//
// A message stays charged to the sender until the receiver's grant returns it,
// so taking it or sweeping it replenishes the sender even after the stream has
// left the session (a late reader of a closed stream, noiseStream.leaveIfEnded).
// A RESET is the one exit that settles the credit otherwise: the sender takes
// back what the stream still had charged and what its grants do not cover, since
// it cannot tell what reached this queue (aether.ResetPayload), so peerEnded takes
// the queue out of charged and nothing taken after it is credited. Such a queue's
// cost is memory no sender is paying for, and NoiseSession.makeQueueRoom discards it
// when a credited message needs the room.
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
	// granted is the credit of this stream's messages the receiver has returned
	// or will return through connection grants: each credited pop, and what
	// reassembly gave back (addGranted). peerEnded reads it at the moment the
	// grants stop, which is what a RESET states as Consumed (aether.ResetPayload).
	granted int64
	// lastTake is the UnixNano of the last pop or of the stream's leaving the
	// session (leftSession, peerEnded), whichever is later: sweepEndedQueues
	// reads it to tell an abandoned queue from one a late consumer is still
	// draining, and makeQueueRoom to pick the longest-idle queue.
	lastTake int64
	budget   *atomic.Int64
	charged  *atomic.Int64

	// wake holds one token while a Receive may find a message. push and pop
	// (for the next of several consumers) leave it non-blocking; a stale token
	// costs Receive one empty pop.
	wake chan struct{}
}

// newRecvQueue builds a queue counting into the session's two totals
// (NoiseSession.recvQueued and recvCharged); a nil total counts to itself, which
// is what a tcpStream's queue passes.
func newRecvQueue(budget, charged *atomic.Int64) *recvQueue {
	if budget == nil {
		budget = new(atomic.Int64)
	}
	if charged == nil {
		charged = new(atomic.Int64)
	}
	return &recvQueue{budget: budget, charged: charged, wake: make(chan struct{}, 1)}
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
// take the queue past streamLimit or the session's charged credit past
// sessionLimit, both counted in messageCredit, the unit the sender's credit is
// charged in. Unmetered cost and the queues a RESET ended are not part of what
// sessionLimit compares: no sender's credit pays for them, so they cannot be
// why a sender inside its credit is refused (makeQueueRoom makes their room).
// A limit of 0 or less is no limit.
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
	if sessionLimit > 0 && q.charged.Load()+c > sessionLimit {
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
		q.charged.Add(c)
	} else {
		q.unmetered++
	}
	q.cost += c
	q.budget.Add(c)
	q.signal()
}

// pop returns the oldest message. credited says the caller must record its
// bytes as consumed: the message was metered and its sender still has it
// charged, which holds until a RESET ended the stream (peerEnded).
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
		if !q.noCredit {
			q.charged.Add(-c)
			q.granted += c
		}
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

// leftSession records that the stream left the session with what the queue
// holds still charged to the sender (noiseStream.leaveIfEnded, once both CLOSEs
// are done): a later pop credits it, and the sweep measures idleness from here.
// A nil queue is a stream built outside createStream.
func (q *recvQueue) leftSession() {
	if q == nil {
		return
	}
	q.mu.Lock()
	q.lastTake = time.Now().UnixNano()
	q.mu.Unlock()
}

// peerEnded records that a RESET has ended the stream, sent by either side: the
// sender takes back what the stream had charged beyond the grants this side has
// made (aether.ResetPayload), so a later pop replenishes nothing and the queue
// leaves the session's charged count. The messages stay in its budget until they
// are read or discarded, so a peer that fills streams and resets them cannot grow
// memory past the ceiling behind a consumer that is not reading. It returns the
// credit this queue's stream granted, final from here on (granted). Its callers are
// the RESET exits (handleReset, Reset), and each then hands the queue to trackEnded.
// A nil queue is a stream built outside createStream, which Reset may still reach.
func (q *recvQueue) peerEnded() (granted int64) {
	if q == nil {
		return 0
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	// The queue takes nothing more: a push behind this would count in charged for a
	// sender that has taken its credit back, and in the count this returns.
	q.ended = true
	if !q.noCredit {
		q.noCredit = true
		q.charged.Add(-q.credit)
	}
	q.lastTake = time.Now().UnixNano()
	return q.granted
}

// addGranted records credit of this stream's messages returned other than by a
// pop: the bytes noiseStream.reassemble gives back when reassembly will not deliver
// them. Nil-safe like peerEnded.
func (q *recvQueue) addGranted(n int64) {
	if q == nil {
		return
	}
	q.mu.Lock()
	q.granted += n
	q.mu.Unlock()
}

// releaseCharge takes the queue out of the session's charged count and returns
// the credit its sender still has charged for it, which the caller grants back,
// for a local Reset of a stream that left on both CLOSEs: the consumer has said
// it will not read, and the peer's stream is gone, so only a grant can return
// that credit. The messages stay readable and in budget, like a RESET's queue
// (makeQueueRoom may discard them). Nil-safe like peerEnded.
func (q *recvQueue) releaseCharge() (grant int64) {
	if q == nil {
		return 0
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.noCredit {
		return 0
	}
	q.noCredit = true
	q.charged.Add(-q.credit)
	return q.credit
}

// discard throws away what the queue holds, returns its cost to the session
// budget and ends it for good, and returns the credit its sender still has
// charged for those messages, which the caller grants back. Its callers are
// sweepEndedQueues, for a queue its consumer abandoned, and makeQueueRoom. A
// consumer that comes back reads aether.ErrStreamOverrun (discardedMessages).
// Idempotent; nil-safe like peerEnded.
func (q *recvQueue) discard() (grant int64) {
	if q == nil {
		return 0
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.noCredit {
		grant = q.credit
		q.charged.Add(-q.credit)
	}
	q.ended = true
	q.noCredit = true
	q.discarded = true
	q.budget.Add(-q.cost)
	q.cost = 0
	q.items, q.head, q.bytes, q.credit, q.unmetered = nil, 0, 0, 0, 0
	return grant
}

// discardedMessages reports whether the queue threw messages away, so Receive
// can say so once it has returned the rest.
func (q *recvQueue) discardedMessages() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.discarded
}

// idleResetQueue reports whether a RESET ended this queue's stream with messages
// unread, and when it was last taken from: makeQueueRoom picks among such queues.
func (q *recvQueue) idleResetQueue() (lastTake int64, ok bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.lastTake, q.noCredit && q.head < len(q.items)
}

// idleSince reports whether the queue is empty and how long since its consumer
// last took a message or the stream left the session (leftSession, peerEnded),
// for sweepEndedQueues.
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
