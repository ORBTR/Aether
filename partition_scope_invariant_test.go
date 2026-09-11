/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package aether

import (
	"net"
	"testing"
	"time"
)

// Behavioural invariants for accept-side partition scope.
//
// WHAT THIS GUARDS. loom's accept loop does, once per inbound session:
//
//	if tas, ok := session.(aether.PartitionAwareSession); ok {
//	    if tid := tas.ScopeID(); tid != "" { partitionID = tid }
//	}
//
// MEASURED: that assertion cannot succeed today. Accept returns
// IncomingSession.Session, typed Connection; all five non-test construction
// sites in this module assign NewConnection(...) and hand over a
// *BaseConnection; *BaseConnection has no ScopeID. The *noiseConn that DOES
// carry the preamble-resolved scope is handed over on Reader/Writer, which
// nothing reads for identity. The scope is resolved correctly, then dropped at
// the type boundary.
//
// 🛑 THE INVARIANT IS BEHAVIOURAL, NOT STRUCTURAL, AND THE DIFFERENCE IS THE
// WHOLE POINT OF THIS FILE.
//
// An earlier version of these tests asserted "*BaseConnection must not satisfy
// PartitionAwareSession". That was wrong, and wrong in a way worth recording,
// because it was well-built enough to be believed:
//
//   - what was refused is a method returning "" UNCONDITIONALLY — a type
//     claiming partition-awareness it cannot honour;
//   - what is NOT refused is a DELEGATING method that forwards to the inner
//     conn (BaseConnection holds `Conn net.Conn`, and on the noise accept path
//     that field holds the scope-bearing *noiseConn). Such a method reports
//     exactly what is there and lies about nothing.
//
// A presence check cannot tell those apart: both make the type assertion
// succeed. Keying the guard on METHOD PRESENCE therefore forbade a whole family
// of correct fixes in order to forbid one defect. Keying it on the method's
// ANSWER forbids the defect and permits the fixes.
//
// ⚠ SO THESE TESTS ARE LATENT BY DESIGN. While BaseConnection has no ScopeID
// they assert the measured absence and report it. The moment the method appears
// they become live and constrain what it may answer. That is deliberate: the
// guard must survive the change it is guarding.

// scopeBearingConn is a net.Conn that also carries a scope — the shape of the
// real *noiseConn as far as BaseConnection is concerned (BaseConnection stores
// it in a `net.Conn` field, so only net.Conn plus ScopeID matters here).
type scopeBearingConn struct {
	net.Conn
	scope string
}

func (c *scopeBearingConn) ScopeID() string { return c.scope }

// plainTestConn is a net.Conn with no scope — the websocket/grpc accept shape.
type plainTestConn struct{ net.Conn }

// nopConn satisfies net.Conn so the two fixtures above can embed something
// non-nil. No method is exercised; these tests never do I/O.
type nopConn struct{}

func (nopConn) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (nopConn) Write(b []byte) (int, error)      { return len(b), nil }
func (nopConn) Close() error                     { return nil }
func (nopConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (nopConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (nopConn) SetDeadline(time.Time) error      { return nil }
func (nopConn) SetReadDeadline(time.Time) error  { return nil }
func (nopConn) SetWriteDeadline(time.Time) error { return nil }

// TestPartitionScope_BaseConnectionMustNotInventAScope is the invariant.
//
// It is the executable form of "if BaseConnection reports a scope, that scope
// must be the inner conn's; if the inner conn has none, it must report none."
//
// 🔬 IT DISCRIMINATES THE TWO SHAPES, which the previous structural version did
// not:
//   - an unconditional `return ""` stub answers "" for the SCOPE-BEARING inner
//     conn  -> FAILS here, which is the refusal being enforced;
//   - a delegating implementation answers "partition-alpha" for that conn and ""
//     for the plain one -> PASSES here, so the workable fix is not blocked.
func TestPartitionScope_BaseConnectionMustNotInventAScope(t *testing.T) {
	const want = "partition-alpha"

	scoped := NewConnection(
		NodeID("vl1_local_scope_delegate_aaaa"),
		NodeID("vl1_remote_scope_delegate_bbb"),
		&scopeBearingConn{Conn: nopConn{}, scope: want},
		ProtoNoise,
	)
	plain := NewConnection(
		NodeID("vl1_local_scope_plain_cccc"),
		NodeID("vl1_remote_scope_plain_dddd"),
		&plainTestConn{Conn: nopConn{}},
		ProtoWebSocket,
	)

	scopedTAS, scopedOK := Connection(scoped).(PartitionAwareSession)
	plainTAS, plainOK := Connection(plain).(PartitionAwareSession)

	if !scopedOK {
		// Pre-fix tree. Record the measured state rather than passing silently:
		// a guard that is quiet in both worlds teaches the next reader nothing.
		t.Logf("MEASURED: *BaseConnection does not implement ScopeID, so the accept-side " +
			"scope cannot reach loom on ANY transport. This test is latent and becomes " +
			"live when the method is added; it then requires the method to delegate.")
		if plainOK {
			t.Error("inconsistent: the same concrete type satisfied PartitionAwareSession for " +
				"one inner conn and not the other — that is impossible for a Go method set " +
				"and means this test's fixtures no longer produce *BaseConnection")
		}
		return
	}

	// Live from here: BaseConnection now reports a scope, so constrain the answer.
	if got := scopedTAS.ScopeID(); got != want {
		t.Errorf("BaseConnection over a scope-bearing conn reported ScopeID()=%q, want %q. "+
			"If this is an unconditional `return \"\"`, THAT IS THE SHAPE THAT WAS REFUSED: "+
			"it makes every connection claim partition-awareness while answering nothing, the "+
			"caller's `tid != \"\"` guard discards it, behaviour is unchanged, and the "+
			"interface now asserts a property it cannot honour. Delegate to the inner conn "+
			"instead", got, want)
	}

	if !plainOK {
		t.Fatal("the two fixtures disagree on the type assertion, which is impossible for " +
			"one concrete type — fixtures are broken")
	}
	if got := plainTAS.ScopeID(); got != "" {
		t.Errorf("BaseConnection over a conn with NO scope reported ScopeID()=%q, want \"\". "+
			"Reporting a scope that the inner conn does not hold is the same defect in the "+
			"opposite direction — it would silently attribute a session to a partition", got)
	}
}

// TestPartitionScope_BaseConnectionIsAConnection is POSITIVE CONTROL A.
//
// Without it the invariant passes for uninteresting reasons — a nil value, a
// wrong constructor, a fixture that is not the accept path's type at all.
func TestPartitionScope_BaseConnectionIsAConnection(t *testing.T) {
	bc := NewConnection(
		NodeID("vl1_local_partition_control_eeee"),
		NodeID("vl1_remote_partition_control_ffff"),
		nopConn{},
		ProtoNoise,
	)

	var _ Connection = bc // compile-time: the accept path's concrete type

	if bc.Protocol() != ProtoNoise {
		t.Errorf("Protocol() = %v, want ProtoNoise — the control object is not the "+
			"one this file reasons about", bc.Protocol())
	}
	if bc.NetConn() == nil {
		t.Error("NetConn() returned nil — the inner conn is what a delegating ScopeID() " +
			"would have to consult, so this file's reasoning depends on it being reachable")
	}
}

// scopedTestConn is POSITIVE CONTROL B's subject: a type embedding the real
// *BaseConnection that additionally carries a scope. It is NOT a proposed
// implementation and nothing in production refers to it.
type scopedTestConn struct {
	*BaseConnection
	scope string
}

func (c *scopedTestConn) ScopeID() string { return c.scope }

// TestPartitionScope_AScopedTypeSatisfiesBoth is POSITIVE CONTROL B.
//
// ① It keeps the invariant NON-VACUOUS: if PartitionAwareSession were unsatisfiable
// for any reason, the latent branch above would report "not implemented" forever
// and prove nothing. This shows the assertion machinery does detect a
// scope-bearing type.
//
// ② It demonstrates as a COMPILED FACT that a type can satisfy Connection and
// PartitionAwareSession simultaneously by embedding *BaseConnection — the eight
// wrapper methods promote and the scope is additive. That answers "is a wrapper
// shape type-correct?" without selecting it over delegation; which shape ships,
// and where it is constructed, is not decided here.
func TestPartitionScope_AScopedTypeSatisfiesBoth(t *testing.T) {
	const want = "partition-beta"

	sc := &scopedTestConn{
		BaseConnection: NewConnection(
			NodeID("vl1_local_partition_scoped_gggg"),
			NodeID("vl1_remote_partition_scoped_hhhh"),
			nopConn{},
			ProtoNoise,
		),
		scope: want,
	}

	var conn Connection = sc // compile-time: embedding promotes all 8 methods

	tas, ok := conn.(PartitionAwareSession)
	if !ok {
		t.Fatal("a type embedding *BaseConnection and defining ScopeID() does NOT satisfy " +
			"PartitionAwareSession. That breaks one demonstrated type-correct route to an " +
			"accept-side scope and makes the invariant above unfalsifiable — fix this " +
			"before trusting it")
	}
	if got := tas.ScopeID(); got != want {
		t.Errorf("ScopeID() = %q, want %q", got, want)
	}
}
