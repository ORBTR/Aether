/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package flow

import (
	"errors"
	"math"
	"testing"
)

// TestCurrentBounds_TheNumbersFitTogether: the shipped profile, and what a
// session derives from it: 1 MiB per stream, connection credit equal to the
// 16 MiB ceiling, sixteen streams' credit before the connection credit is spent,
// and the default constants the windows build from.
func TestCurrentBounds_TheNumbersFitTogether(t *testing.T) {
	p := CurrentBounds()
	if p.Version != BoundsProfileVersion || p.StreamCredit != 1<<20 || p.SessionMemoryCeiling != 16<<20 || p.StreamCap != 1024 {
		t.Fatalf("profile %+v", p)
	}
	if p.ConnCredit() != p.SessionMemoryCeiling {
		t.Fatalf("connection credit %d, ceiling %d", p.ConnCredit(), p.SessionMemoryCeiling)
	}
	if got := p.SessionMemoryCeiling / p.StreamCredit; got != 16 {
		t.Fatalf("%d streams fall behind before the session stalls, want 16", got)
	}
	if p.StreamCredit != DefaultStreamCredit || p.ConnCredit() != DefaultConnCredit || p.StreamCap != DefaultStreamCap {
		t.Fatalf("profile %+v against constants %d, %d, %d", p, DefaultStreamCredit, DefaultConnCredit, DefaultStreamCap)
	}
	w := NewConnWindow(p.ConnCredit())
	if initial, maximum := w.ReceiveCeilings(); initial != maximum || maximum != p.SessionMemoryCeiling {
		t.Fatalf("connection window initial %d, maximum %d", initial, maximum)
	}
	if got := NewConnWindow(0).Available(); got != p.ConnCredit() {
		t.Fatalf("a default connection window holds %d", got)
	}
}

// TestNewBoundsProfile_RefusesNumbersThatDoNotFit: each way a profile can fail to
// fit is refused at construction with ErrBoundsProfileInvalid, and the numbers at
// each edge are accepted.
func TestNewBoundsProfile_RefusesNumbersThatDoNotFit(t *testing.T) {
	const ceiling, credit, streams = 16 << 20, 1 << 20, 1024
	for _, c := range []struct {
		name    string
		version uint16
		credit  int64
		ceiling int64
		cap     int
	}{
		{"an unknown version", BoundsProfileVersion + 1, credit, ceiling, streams},
		{"version zero", 0, credit, ceiling, streams},
		{"zero stream credit", BoundsProfileVersion, 0, ceiling, streams},
		{"negative stream credit", BoundsProfileVersion, -1, ceiling, streams},
		{"stream credit below the guaranteed window", BoundsProfileVersion, MinGuaranteedWindow - 1, ceiling, streams},
		{"stream credit above the window capacity", BoundsProfileVersion, MaxGrowableWindow + 1, 1 << 40, streams},
		{"a ceiling below one stream's credit", BoundsProfileVersion, credit, credit - 1, streams},
		{"a zero ceiling", BoundsProfileVersion, credit, 0, streams},
		{"a zero stream cap", BoundsProfileVersion, credit, ceiling, 0},
		{"a negative stream cap", BoundsProfileVersion, credit, ceiling, -1},
		{"a stream cap whose credit overflows", BoundsProfileVersion, credit, ceiling, math.MaxInt},
		{"streams that cannot reach the ceiling", BoundsProfileVersion, credit, ceiling, 15},
	} {
		p, err := NewBoundsProfile(c.version, c.credit, c.ceiling, c.cap)
		if !errors.Is(err, ErrBoundsProfileInvalid) || p != (BoundsProfile{}) {
			t.Errorf("%s: profile %+v, err %v; want ErrBoundsProfileInvalid", c.name, p, err)
		}
	}
	for _, c := range []struct {
		name    string
		credit  int64
		ceiling int64
		cap     int
	}{
		{"credit at the guaranteed window", MinGuaranteedWindow, ceiling, 1 << 15},
		{"credit at the window capacity", MaxGrowableWindow, MaxGrowableWindow, 1},
		{"streams exactly reaching the ceiling", credit, ceiling, 16},
	} {
		if _, err := NewBoundsProfile(BoundsProfileVersion, c.credit, c.ceiling, c.cap); err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// TestBoundsProfile_AdmittedCreditCeilingReadsTheStreamCap: the ceiling is the
// session's cap at the profile's credit, the profile's cap when the session names
// none, and a cap too large to multiply stays a finite multiple of the credit.
func TestBoundsProfile_AdmittedCreditCeilingReadsTheStreamCap(t *testing.T) {
	p := CurrentBounds()
	if got := p.AdmittedCreditCeiling(8); got != 8*p.StreamCredit {
		t.Fatalf("cap 8: %d", got)
	}
	if got := p.AdmittedCreditCeiling(0); got != int64(p.StreamCap)*p.StreamCredit {
		t.Fatalf("no cap named: %d", got)
	}
	if got := p.AdmittedCreditCeiling(math.MaxInt); got%p.StreamCredit != 0 || got <= 0 {
		t.Fatalf("a cap too large to multiply: %d", got)
	}
}
