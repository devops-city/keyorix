// webauthn_persist_credential_panic_test.go — regression for a gap found by
// GUARD-1's new besteffort_guard_test.go sweep: persistUpdatedCredential (the
// best-effort signature-counter advance every WebAuthn login/reauth finish
// runs) discarded AdvanceWebAuthnCredentialCounter's returned error with a
// bare `_, _ =` and had NO recover() at all — unlike every other best-effort
// call site in this package, a panic here was completely unprotected. Called
// from FinishWebAuthnLogin/FinishWebAuthnPasswordlessLogin AFTER
// checkLockAndClearLoginFailures may already have cleared this user's
// lockout counters but BEFORE mintSession, an unrecovered panic here would
// propagate past that already-committed write and report the whole login as
// failed.
package core

import (
	"context"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/stretchr/testify/assert"
)

// panicOnAdvanceWebAuthnCredentialCounterStorage wraps a real storage.Storage
// and makes AdvanceWebAuthnCredentialCounter panic unconditionally, mirroring
// the panicOnEnforceSessionLimitStorage stub idiom used elsewhere in this
// package.
func panicOnAdvanceWebAuthnCredentialCounterStorage(inner storage.Storage) storage.Storage {
	return hooked(inner, &storeHooks{
		AdvanceWebAuthnCredentialCounter: func(_ storage.Storage, _ context.Context, _ []byte, _ uint, _ []byte, _ uint32, _ time.Time) (bool, error) {
			panic("injected fault: AdvanceWebAuthnCredentialCounter")
		},
	})
}

// TestPersistUpdatedCredential_PanicDoesNotEscape: pre-fix, this call had no
// recover() anywhere, so a panic in AdvanceWebAuthnCredentialCounter would
// crash straight through persistUpdatedCredential and every one of its three
// callers (FinishWebAuthnLogin, FinishWebAuthnPasswordlessLogin,
// VerifyMFAStepUp's reauth path) with nothing to catch it until the
// transport's own Recovery middleware — turning an in-progress login/reauth
// into a reported failure regardless of what already committed.
// besteffort.Run must recover the panic and let the caller continue.
func TestPersistUpdatedCredential_PanicDoesNotEscape(t *testing.T) {
	t.Parallel()
	c, db := newWebAuthnTestCore(t, true)
	ctx := context.Background()
	seedCredential(t, c, db, 1, "cred-1")

	c.storage = panicOnAdvanceWebAuthnCredentialCounterStorage(c.storage)

	assert.NotPanics(t, func() {
		c.persistUpdatedCredential(ctx, 1, &webauthn.Credential{ID: []byte("cred-1"), Authenticator: webauthn.Authenticator{SignCount: 1}})
	}, "a panic in the best-effort signature-counter advance must not escape persistUpdatedCredential")
}
