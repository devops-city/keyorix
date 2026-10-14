// drive_sink_test.go — the reporting seam that lets a test DRIVE the fault
// harness for one case without the harness's own verdict terminating that test.
//
// Why this exists. driveFaultCase's whole purpose is to inspect what the oracle
// would see for one (op, method, nth, kind) case. Its doc comment claimed it ran
// the harness "against a throwaway *testing.T-shaped sink so only the
// observation escapes" — but it passed the caller's real *testing.T, and the
// harness calls t.Skipf when the fault-free reference run errors or fails, when
// Setup errors, and t.Fatalf when a snapshot fails. On a *testing.T those are
// not reports, they are control flow: the first one ends the CALLING test.
//
// That broke both staleness checks, in the direction that makes them useless:
//
//   - TestKnownOpenTolerances_AreLoadBearing iterates every tolerance in one
//     test function, so the FIRST row whose reference run happened to skip ended
//     the whole test as SKIP — every row after it unexamined, and a SKIP reads
//     as "nothing to report" in CI.
//   - TestOracleAByDesign_RowsAreLoadBearing runs a subtest per row, and a
//     subtest that SKIPS is not a subtest that passed a check. A row that could
//     not be evaluated came out looking fine.
//
// Both are the "a check that silently skips its own population" shape: green,
// and green for a reason unrelated to the property. So the sink below is real
// now, and "could not be evaluated" is a distinct outcome the callers must
// handle rather than a bool they can conflate with "not applicable".
//
// Design note: Errorf is deliberately NOT an abort. An oracle violation reported
// through Errorf is exactly what these checks are LOOKING for — a tolerance is
// load-bearing precisely because the oracle still flags its case. Recording it
// and continuing is what lets the caller observe that. Skip/Fatal are aborts
// because they mean the iteration produced no observation at all.
package faultops

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// fuzzVerdict is the subset of *testing.T through which the fault harness
// reports what it concluded about one iteration. *testing.T satisfies it, so
// every existing caller is unchanged; driveSink satisfies it too, which is the
// point.
//
// It deliberately does NOT cover the resource side of *testing.T (TempDir,
// Cleanup, and the Fatalf calls inside newFaultWorld): building a world is
// harness infrastructure, and a failure there is a genuine breakage that should
// take the whole test down loudly rather than be recorded as one row's
// "could not evaluate". Those keep using the real *testing.T.
type fuzzVerdict interface {
	Helper()
	Log(args ...any)
	Logf(format string, args ...any)
	Skip(args ...any)
	Skipf(format string, args ...any)
	Fatalf(format string, args ...any)
	Errorf(format string, args ...any)
}

// driveAborted is the sentinel panic driveSink uses to unwind the harness when
// it would have called Skip/Fatal on a real *testing.T. Only driveFaultCase
// recovers it, via rethrowUnlessDriveAbort.
//
// Safety of panicking from those call sites, stated rather than assumed: every
// Skip/Fatal in runOneFuzzIterationReporting sits OUTSIDE the inner
// recover-wrapped func that guards op.Execute — checked by reading it, which is
// the honest extent of the verification. If a future edit moved one inside that
// block, this sentinel would be caught there and misreported as "panic escaped
// the transport layer entirely". That is a confusing failure, but a LOUD one:
// the mistake cannot pass silently, which is why it is left as a reading check
// rather than a source-position assertion.
type driveAborted struct{}

// rethrowUnlessDriveAbort swallows driveAborted and re-panics anything else.
//
// Split out of driveFaultCase's deferred closure so the re-panic branch is
// directly testable: a recover() that swallows unrelated panics would turn a
// genuine crash in the harness into a silently inconclusive row, which is the
// same class of defect as the skip-based one this file exists to fix.
func rethrowUnlessDriveAbort(r any) {
	if r == nil {
		return
	}
	if _, ours := r.(driveAborted); ours {
		return
	}
	panic(r)
}

// driveSink is a fuzzVerdict that records the harness's verdict instead of
// acting on it.
type driveSink struct {
	t *testing.T

	// notEvaluated is the reason the harness gave up before the oracle ran —
	// empty when it ran to completion. Non-empty is a FAILURE for a staleness
	// check, not a skip: a row whose own case cannot be exercised cannot be
	// shown to still tolerate anything.
	notEvaluated string
	// findings are the Errorf messages the harness produced — i.e. the oracle
	// violations it would have failed on. Recorded, not propagated.
	findings []string
}

func (s *driveSink) Helper()                         { s.t.Helper() }
func (s *driveSink) Log(args ...any)                 { s.t.Log(args...) }
func (s *driveSink) Logf(format string, args ...any) { s.t.Logf(format, args...) }
func (s *driveSink) Skip(args ...any)                { s.abort("harness skipped: " + fmt.Sprint(args...)) }
func (s *driveSink) Skipf(format string, args ...any) {
	s.abort("harness skipped: " + fmt.Sprintf(format, args...))
}
func (s *driveSink) Fatalf(format string, args ...any) {
	s.abort("harness error: " + fmt.Sprintf(format, args...))
}

func (s *driveSink) Errorf(format string, args ...any) {
	s.findings = append(s.findings, fmt.Sprintf(format, args...))
}

func (s *driveSink) abort(reason string) {
	s.notEvaluated = reason
	panic(driveAborted{})
}

// driveOutcome says what happened when driveFaultCase ran one case. Callers
// must branch on it; a bool cannot express the difference between "this row is
// not applicable here" and "this row could not be checked", and conflating
// those is how the staleness checks came to pass while checking nothing.
type driveOutcome int

const (
	// driveObserved: the iteration reached the oracle and oracleInput is valid.
	driveObserved driveOutcome = iota
	// driveNotInCatalog: the op key is not in opCatalog, or the method is not a
	// storage.Storage method. A structural fact about the catalog, knowable
	// without running anything.
	driveNotInCatalog
	// driveFaultNeverFired: the harness ran, but the armed fault never fired —
	// NthCall exceeded the real call count for that method during Execute. The
	// case is reachable in principle; this (method, nth) pair is not.
	driveFaultNeverFired
	// driveNotEvaluated: the harness itself skipped or failed before the oracle
	// ran (reference run errored/failed, Setup errored, a snapshot failed).
	// reason carries which.
	driveNotEvaluated
)

func (o driveOutcome) String() string {
	switch o {
	case driveObserved:
		return "observed"
	case driveNotInCatalog:
		return "not in catalog"
	case driveFaultNeverFired:
		return "fault never fired"
	case driveNotEvaluated:
		return "not evaluated"
	}
	return "unknown"
}

// ── Guards on the sink itself ───────────────────────────────────────────────

// TestDriveSink_RecordsVerdictsInsteadOfActingOnThem pins the three semantics
// the staleness checks depend on, each of which would silently break one of
// them if it drifted:
//
//   - Errorf RECORDS and does not abort. An oracle violation is the signal a
//     tolerance is load-bearing; aborting on it would make every live row look
//     inconclusive.
//   - Skipf ABORTS and records why. This is the one that matters most: a skip
//     that did not abort would let the harness keep running past a point where
//     it has no valid reference state, and a skip that propagated to the real
//     *testing.T is the original bug.
//   - Fatalf ABORTS and records why, distinctly labelled, because "the harness
//     broke" and "this case is not a finding" need different follow-up.
func TestDriveSink_RecordsVerdictsInsteadOfActingOnThem(t *testing.T) {
	t.Parallel()

	t.Run("Errorf records without aborting", func(t *testing.T) {
		s := &driveSink{t: t}
		reached := false
		func() {
			defer func() { rethrowUnlessDriveAbort(recover()) }()
			s.Errorf("violation %d", 1)
			s.Errorf("violation %d", 2)
			reached = true
		}()
		if !reached {
			t.Fatal("Errorf aborted the run; it must only record, or a load-bearing tolerance reads as inconclusive")
		}
		if len(s.findings) != 2 {
			t.Errorf("recorded %d findings, want 2: %v", len(s.findings), s.findings)
		}
		if s.notEvaluated != "" {
			t.Errorf("Errorf set notEvaluated to %q; only Skip/Fatal may do that", s.notEvaluated)
		}
	})

	for _, c := range []struct {
		name       string
		call       func(*driveSink)
		wantPrefix string
	}{
		{"Skip aborts", func(s *driveSink) { s.Skip("empty catalog") }, "harness skipped: "},
		{"Skipf aborts", func(s *driveSink) { s.Skipf("setup errored: %v", errDriveSinkProbe) }, "harness skipped: "},
		{"Fatalf aborts", func(s *driveSink) { s.Fatalf("snapshot failed: %v", errDriveSinkProbe) }, "harness error: "},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := &driveSink{t: t}
			pastTheCall := false
			func() {
				defer func() { rethrowUnlessDriveAbort(recover()) }()
				c.call(s)
				pastTheCall = true
			}()
			if pastTheCall {
				t.Fatalf("%s: execution continued past the call. On a real *testing.T this method does not "+
					"return, so the harness code after it assumes it was never reached", c.name)
			}
			if !strings.HasPrefix(s.notEvaluated, c.wantPrefix) {
				t.Errorf("notEvaluated = %q, want the %q prefix so the caller can tell a harness break from "+
					"a not-a-finding skip", s.notEvaluated, c.wantPrefix)
			}
			if !strings.Contains(s.notEvaluated, "catalog") && !strings.Contains(s.notEvaluated, errDriveSinkProbe.Error()) {
				t.Errorf("notEvaluated = %q, which does not carry the reason the harness gave — the staleness "+
					"check reports that reason verbatim, so losing it makes the failure undiagnosable",
					s.notEvaluated)
			}
		})
	}
}

var errDriveSinkProbe = errors.New("drive-sink probe")

// TestRethrowUnlessDriveAbort_ReThrowsEverythingElse is the calibration for the
// recover() in driveFaultCase. Swallowing an unrelated panic there would
// convert a genuine harness crash into an inconclusive row — the same shape of
// defect as the skip this file fixes, just arriving by a different route.
func TestRethrowUnlessDriveAbort_ReThrowsEverythingElse(t *testing.T) {
	t.Parallel()

	t.Run("nil is a no-op", func(t *testing.T) {
		rethrowUnlessDriveAbort(nil) // must not panic
	})

	t.Run("driveAborted is swallowed", func(t *testing.T) {
		survived := false
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("driveAborted was re-thrown as %v; the sink's own abort must be absorbed", r)
				}
			}()
			rethrowUnlessDriveAbort(driveAborted{})
			survived = true
		}()
		if !survived {
			t.Error("rethrowUnlessDriveAbort did not return normally for its own sentinel")
		}
	})

	for _, c := range []struct {
		name  string
		value any
	}{
		{"a runtime error", errDriveSinkProbe},
		{"a bare string", "something exploded"},
		{"a nil-pointer-shaped value", (*driveSink)(nil)},
	} {
		t.Run(c.name+" is re-thrown", func(t *testing.T) {
			var got any
			func() {
				defer func() { got = recover() }()
				rethrowUnlessDriveAbort(c.value)
			}()
			if got == nil {
				t.Fatalf("%v was SWALLOWED. A real panic inside the harness must take the test down, not be "+
					"recorded as one row that could not be evaluated", c.value)
			}
		})
	}
}
