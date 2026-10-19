// mint_session_enforce_limit_panic_test.go — regression for
// docs/findings/2026-10-02-FINDING-mfa-verify-enforcesessionlimit-panic-masks-successful-login.md
// (found by FuzzStorageFaultOperations extending REST POST /auth/mfa/verify
// coverage on PR #2392, SESSION-FI2, out of that session's OWNS): mintSession's
// EnforceSessionLimit call discards a RETURNED error (matching its own
// "best-effort" comment) but had no recover() for a PANIC, so a panic there
// propagated straight past an already-committed CreateSession, misreporting a
// genuinely successful login as a failure.
package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// panicOnEnforceSessionLimitStorage wraps a real storage.Storage and makes
// EnforceSessionLimit panic unconditionally, mirroring the failOnce*/mfaSecretReadErrStub
// stub idiom used elsewhere in this package.
func panicOnEnforceSessionLimitStorage(inner storage.Storage) storage.Storage {
	return hooked(inner, &storeHooks{
		EnforceSessionLimit: func(_ storage.Storage, _ context.Context, _ uint, _ int) error {
			panic("injected fault: EnforceSessionLimit")
		},
	})
}

// TestLogin_EnforceSessionLimitPanic_StillSucceeds: a panic in mintSession's
// best-effort EnforceSessionLimit call must not turn an otherwise-successful
// login into a reported failure — the session row (and, for the MFA path,
// the consumed TOTP step) already committed before this call runs, so letting
// the panic propagate would tell a caller with the CORRECT credentials that
// their login failed while a session they can never retrieve sits in the
// table. Confirmed red on the unfixed code (panics, Login returns no session
// and the recovered-panic value as an error — or crashes the test binary
// outright without a recover anywhere in the call chain).
func TestLogin_EnforceSessionLimitPanic_StillSucceeds(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	c.storage = panicOnEnforceSessionLimitStorage(st)

	session, user, err := c.Login(ctx, &LoginRequest{Username: "admin", Password: "BootstrapPass123!"})
	require.NoError(t, err, "a panic in the best-effort session-limit enforcement must not fail an otherwise-correct login")
	require.NotNil(t, session)
	assert.NotEmpty(t, session.SessionToken)
	assert.Equal(t, "admin", user.Username)

	// The session this call reported back must actually be the one that
	// committed — not a value fabricated after discarding a real failure.
	reloaded, rerr := st.GetSession(ctx, session.SessionToken)
	require.NoError(t, rerr)
	require.NotNil(t, reloaded)
	assert.Equal(t, session.ID, reloaded.ID)
}
