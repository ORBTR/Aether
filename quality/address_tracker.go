package quality

import (
	"sync"
	"time"
)

// AddressScore is the per-(peer, transport, address) success/RTT history.
// Distinct from the session-level Score: this is the dial-side picture
// used to decide which IP/port to try next, while Score answers "is
// the established session healthy?".
type AddressScore struct {
	PeerID    string
	Transport string
	Address   string

	Attempts            int
	Successes           int
	ConsecutiveFailures int

	SuccessRate float64
	RTT         time.Duration

	LastSuccess time.Time
	LastFailure time.Time
	DeadUntil   time.Time
}

// IsAlive reports whether the address is outside its dead-cooldown window.
func (a *AddressScore) IsAlive() bool {
	return time.Now().After(a.DeadUntil)
}

// IsDead is the inverse of IsAlive.
func (a *AddressScore) IsDead() bool { return !a.IsAlive() }

const (
	// AddressDeadCooldown is how long an address sits in cooldown after
	// crossing the consecutive-failure threshold. Long enough that a
	// permanently-broken endpoint stops being retried in a tight loop;
	// short enough that a recovered endpoint comes back into rotation
	// without a process restart.
	AddressDeadCooldown = 30 * time.Minute

	// AddressFailuresBeforeDead is the consecutive failure count that
	// flips an address into the dead-cooldown window. Three matches
	// the legacy PathScorer threshold.
	AddressFailuresBeforeDead = 3
)

// AddressTracker tracks dial-level success and RTT per
// (peer, transport, address) so the connect path can pick the address
// most likely to work, demote permanently-broken endpoints, and forget
// data for peers we no longer talk to.
//
// Distinct from Tracker (session-level health EMA) because the unit of
// work is different: AddressTracker scores attempts to *establish* a
// session, Tracker scores the session once it exists.
type AddressTracker struct {
	mu      sync.RWMutex
	entries map[addressKey]*AddressScore
}

type addressKey struct {
	peerID    string
	transport string
	address   string
}

// NewAddressTracker creates an empty tracker.
func NewAddressTracker() *AddressTracker {
	return &AddressTracker{entries: make(map[addressKey]*AddressScore)}
}

// RecordSuccess credits a successful dial/exchange. Resets the
// consecutive-failure run, clears any dead-cooldown, and updates RTT.
func (t *AddressTracker) RecordSuccess(peerID, transport, address string, rtt time.Duration) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	k := addressKey{peerID, transport, address}
	a := t.entries[k]
	if a == nil {
		a = &AddressScore{PeerID: peerID, Transport: transport, Address: address}
		t.entries[k] = a
	}
	a.Attempts++
	a.Successes++
	a.ConsecutiveFailures = 0
	if rtt > 0 {
		a.RTT = rtt
	}
	a.SuccessRate = float64(a.Successes) / float64(a.Attempts)
	a.LastSuccess = time.Now()
	a.DeadUntil = time.Time{}
}

// RecordFailure debits a failed dial/exchange. Crossing
// AddressFailuresBeforeDead consecutive failures starts a cooldown.
func (t *AddressTracker) RecordFailure(peerID, transport, address string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	k := addressKey{peerID, transport, address}
	a := t.entries[k]
	if a == nil {
		a = &AddressScore{PeerID: peerID, Transport: transport, Address: address}
		t.entries[k] = a
	}
	a.Attempts++
	a.ConsecutiveFailures++
	a.SuccessRate = float64(a.Successes) / float64(a.Attempts)
	a.LastFailure = time.Now()
	if a.ConsecutiveFailures >= AddressFailuresBeforeDead {
		a.DeadUntil = time.Now().Add(AddressDeadCooldown)
	}
}

// Score returns a copy of the current AddressScore for an address, or
// (zero, false) if no history exists.
func (t *AddressTracker) Score(peerID, transport, address string) (AddressScore, bool) {
	if t == nil {
		return AddressScore{}, false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	a, ok := t.entries[addressKey{peerID, transport, address}]
	if !ok || a == nil {
		return AddressScore{}, false
	}
	return *a, true
}

// IsAddressDead returns true if the address is in cooldown.
func (t *AddressTracker) IsAddressDead(peerID, transport, address string) bool {
	if t == nil {
		return false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	a, ok := t.entries[addressKey{peerID, transport, address}]
	if !ok || a == nil {
		return false
	}
	return a.IsDead()
}

// ProtoIsDead returns true when every recorded address for
// (peer, transport) is either in dead cooldown or has a confirmed-low
// success rate over a meaningful sample. Used to short-circuit picking
// a transport that's been demonstrably broken across all known
// addresses for the peer; if no history exists the answer is false so
// fresh peers always get a chance.
func (t *AddressTracker) ProtoIsDead(peerID, transport string) bool {
	if t == nil {
		return false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()

	const minAttemptsForSignal = 5
	const failingSuccessRate = 0.30
	hasAny := false
	for k, a := range t.entries {
		if k.peerID != peerID || k.transport != transport {
			continue
		}
		hasAny = true
		if a.IsAlive() && a.Attempts < minAttemptsForSignal {
			return false
		}
		if a.IsAlive() && a.SuccessRate >= failingSuccessRate {
			return false
		}
	}
	return hasAny
}

// ForgetPeer drops every entry for a peer. Called when a peer is evicted
// from the connection manager so stale dial history doesn't keep a
// terminated peer's ghost alive across rejoin.
func (t *AddressTracker) ForgetPeer(peerID string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for k := range t.entries {
		if k.peerID == peerID {
			delete(t.entries, k)
		}
	}
}

// PruneOlderThan removes entries whose last activity (success or
// failure) is older than maxAge. Bounded memory across long-running
// processes that have seen many distinct addresses.
func (t *AddressTracker) PruneOlderThan(maxAge time.Duration) int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	removed := 0
	for k, a := range t.entries {
		last := a.LastSuccess
		if a.LastFailure.After(last) {
			last = a.LastFailure
		}
		if last.Before(cutoff) {
			delete(t.entries, k)
			removed++
		}
	}
	return removed
}

// PeerAttempts returns the total number of dial attempts recorded for
// this peer across all transports. Useful for the diagnostic surface
// to render a "have we ever talked to this peer?" indicator.
func (t *AddressTracker) PeerAttempts(peerID string) int {
	if t == nil {
		return 0
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	total := 0
	for k, a := range t.entries {
		if k.peerID == peerID {
			total += a.Attempts
		}
	}
	return total
}
