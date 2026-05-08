package quality

import (
	"testing"
	"time"
)

func TestAddressTracker_RecordSuccessThenFailureUpdatesScore(t *testing.T) {
	tk := NewAddressTracker()
	tk.RecordSuccess("peerA", "noise-udp", "1.2.3.4:9000", 50*time.Millisecond)
	tk.RecordSuccess("peerA", "noise-udp", "1.2.3.4:9000", 60*time.Millisecond)
	tk.RecordFailure("peerA", "noise-udp", "1.2.3.4:9000")

	got, ok := tk.Score("peerA", "noise-udp", "1.2.3.4:9000")
	if !ok {
		t.Fatal("expected score to exist")
	}
	if got.Attempts != 3 {
		t.Errorf("Attempts = %d, want 3", got.Attempts)
	}
	if got.Successes != 2 {
		t.Errorf("Successes = %d, want 2", got.Successes)
	}
	if got.ConsecutiveFailures != 1 {
		t.Errorf("ConsecutiveFailures = %d, want 1", got.ConsecutiveFailures)
	}
	if got.RTT != 60*time.Millisecond {
		t.Errorf("RTT = %v, want last recorded sample 60ms", got.RTT)
	}
	if got.SuccessRate < 0.66 || got.SuccessRate > 0.67 {
		t.Errorf("SuccessRate = %.3f, want ~0.667", got.SuccessRate)
	}
}

func TestAddressTracker_DeadAfterConsecutiveFailures(t *testing.T) {
	tk := NewAddressTracker()
	for i := 0; i < AddressFailuresBeforeDead; i++ {
		tk.RecordFailure("peer", "tcp", "addr")
	}
	if !tk.IsAddressDead("peer", "tcp", "addr") {
		t.Error("address should be dead after threshold consecutive failures")
	}
	tk.RecordSuccess("peer", "tcp", "addr", 10*time.Millisecond)
	if tk.IsAddressDead("peer", "tcp", "addr") {
		t.Error("address should be alive after a successful record")
	}
}

func TestAddressTracker_ProtoIsDead(t *testing.T) {
	tk := NewAddressTracker()

	if tk.ProtoIsDead("p", "noise-udp") {
		t.Error("empty tracker must never report a proto as dead")
	}

	for i := 0; i < 5; i++ {
		tk.RecordFailure("p", "noise-udp", "addr1")
	}
	for i := 0; i < 5; i++ {
		tk.RecordFailure("p", "noise-udp", "addr2")
	}
	if !tk.ProtoIsDead("p", "noise-udp") {
		t.Error("two addresses both fully failing should mark proto dead")
	}

	tk.RecordSuccess("p", "noise-udp", "addr3", 5*time.Millisecond)
	for i := 0; i < 4; i++ {
		tk.RecordSuccess("p", "noise-udp", "addr3", 5*time.Millisecond)
	}
	if tk.ProtoIsDead("p", "noise-udp") {
		t.Error("a healthy alternate address should rescue the proto")
	}
}

func TestAddressTracker_ForgetPeerAndPrune(t *testing.T) {
	tk := NewAddressTracker()
	tk.RecordSuccess("peerA", "tcp", "a1", 10*time.Millisecond)
	tk.RecordSuccess("peerB", "tcp", "b1", 10*time.Millisecond)

	tk.ForgetPeer("peerA")
	if _, ok := tk.Score("peerA", "tcp", "a1"); ok {
		t.Error("ForgetPeer must drop entries for the named peer")
	}
	if _, ok := tk.Score("peerB", "tcp", "b1"); !ok {
		t.Error("ForgetPeer must not drop entries for other peers")
	}

	if removed := tk.PruneOlderThan(0); removed == 0 {
		t.Error("PruneOlderThan(0) should drop all remaining entries")
	}
	if _, ok := tk.Score("peerB", "tcp", "b1"); ok {
		t.Error("Prune must remove entries past the cutoff")
	}
}
