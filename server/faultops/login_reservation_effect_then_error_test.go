// login_reservation_effect_then_error_test.go — the five effect-then-error
// tuples #2956 added to the exhaustive login-op sweep (AUTH-AUDIT-1, comment on
// #2956), now passing every oracle with NO by-design row and NO tolerance:
//
//   - ReserveLoginAttempt#1/effect-then-error on /auth/login, /auth/mfa/verify,
//     /auth/webauthn/login/finish: the reservation row landed but the write
//     reported an error, so the request had no id to release when it delivered
//     the login, and a success stayed counted. Fixed by identifiable
//     reservations: core generates the key before the write and retries once
//     with it (internal/core/rate_limit.go ReserveLoginAttempt), and storage is
//     idempotent per key (local_login_attempts.go).
//   - CreateSession#1/effect-then-error on /auth/login and /auth/mfa/verify: the
//     session row landed but the write reported an error, so the login was
//     denied post-verdict (slot kept, auth.login_error) while the session stayed
//     live. Fixed by #3046's read-back (internal/core/session_undelivered.go):
//     the committed session is delivered and the slot returned.
package faultops

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

func TestLoginEffectThenErrorTuples_PassEveryOracleWithoutARow(t *testing.T) {
	cases := []struct{ op, method string }{
		{"REST POST /auth/login", "ReserveLoginAttempt"},
		{"REST POST /auth/mfa/verify", "ReserveLoginAttempt"},
		{"REST POST /auth/webauthn/login/finish", "ReserveLoginAttempt"},
		{"REST POST /auth/login", "CreateSession"},
		{"REST POST /auth/mfa/verify", "CreateSession"},
	}
	for _, c := range cases {
		t.Run(c.op+"/"+c.method, func(t *testing.T) {
			in, outcome, reason := driveFaultCase(t, c.op, c.method, 1, faultstorage.KindEffectThenError)
			if outcome != driveObserved {
				t.Fatalf("could not drive %s %s#1/effect-then-error (%s: %s): a pin that cannot run proves nothing",
					c.op, c.method, outcome, reason)
			}
			if !in.result.Success {
				t.Errorf("the write committed, so the login must be delivered; got failure %q", in.result.Detail)
			}
			sink := &driveSink{t: t}
			checkOraclesReporting(sink, in)
			for _, f := range sink.findings {
				t.Error(f)
			}
		})
	}
}
