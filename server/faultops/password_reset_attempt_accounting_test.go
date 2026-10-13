// password_reset_attempt_accounting_test.go — #2837 shape 2 on
// REST POST /auth/password-reset (FIX-2837B), now passing every oracle with NO
// by-design row, NO best-effort table and NO tolerance.
//
// The finding (FUZZ-SEEDS-1, input ae01600000, committed as
// testdata/fuzz/FuzzStorageFaultOperations/2837_passwordreset_recordloginattempt_error):
// RecordLoginAttempt#1/error. The handler counts the request against the
// per-IP password_reset budget (core.RecordPasswordResetAttempt ->
// budgetRecord) BEFORE RequestPasswordReset runs. That write was one plain
// RecordLoginAttempt: when it failed, the attempt went to the per-process
// in-memory fallback, which audits auth.rate_limit_error, and the request still
// answered 200. So the run lacked the reference run's pwreset LoginAttempt row
// and carried an extra AuditEvent: oracle (a), [LoginAttempt AuditEvent].
//
// Fixed the way the login reservation was (#3050): every login_attempts budget
// write is keyed before the write and retried once with the same key against
// the idempotent store (core budgetWriteKeyed). The faulted method is now
// ReserveLoginAttempt; a write that failed once lands on the retry, and a
// write that landed but reported an error is found again by its key, so the
// attempt is stored exactly once and no fallback (and no fallback audit)
// happens. Only a write that fails twice still falls back, which a single
// injected fault cannot produce.
package faultops

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

const passwordResetOp = "REST POST /auth/password-reset"

func TestPasswordResetAttemptAccounting_PassesEveryOracleWithoutARow(t *testing.T) {
	for _, kind := range []faultstorage.FaultKind{
		faultstorage.KindError,
		faultstorage.KindEffectThenError,
		faultstorage.KindPanic,
	} {
		t.Run("ReserveLoginAttempt#1/"+kind.String(), func(t *testing.T) {
			in, outcome, reason := driveFaultCase(t, passwordResetOp, "ReserveLoginAttempt", 1, kind)
			if outcome != driveObserved {
				t.Fatalf("could not drive %s ReserveLoginAttempt#1/%s (%s: %s): a pin that cannot run proves nothing",
					passwordResetOp, kind, outcome, reason)
			}
			if kind != faultstorage.KindPanic && !in.result.Success {
				t.Errorf("a reservation the retry recovers must not change the response; got failure %q", in.result.Detail)
			}
			sink := &driveSink{t: t}
			checkOraclesReporting(sink, in)
			for _, f := range sink.findings {
				t.Error(f)
			}
		})
	}
}

// TestPasswordResetAttemptAccounting_NoUnkeyedWrite pins that the op no longer
// reaches the non-idempotent RecordLoginAttempt at all, so the committed
// finding seed cannot regress by the write moving back to it unnoticed: if it
// did, this would observe the fault instead of never firing it, and the seed
// itself would be red again.
func TestPasswordResetAttemptAccounting_NoUnkeyedWrite(t *testing.T) {
	_, outcome, reason := driveFaultCase(t, passwordResetOp, "RecordLoginAttempt", 1, faultstorage.KindError)
	if outcome != driveFaultNeverFired {
		t.Fatalf("%s RecordLoginAttempt#1/error: outcome %s (%s), want %s: the password-reset budget write is no "+
			"longer the keyed, retried ReserveLoginAttempt (core budgetWriteKeyed)",
			passwordResetOp, outcome, reason, driveFaultNeverFired)
	}
}
