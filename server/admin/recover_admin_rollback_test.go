package admin

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestPerformRecoverAdmin_OneTimePasswordExpiryFault_RollsBack is FIX-3052's guard:
// recover-admin's reset (account state, one-time password hash, its expiry, MFA,
// WebAuthn credentials, lockout state, sessions) is ONE storage transaction, and a
// failure in SetOneTimePasswordExpiry, the third write, must leave the account exactly
// as it was. If it did not, the operator would be left with the old password already
// replaced by a one-time hash that has no expiry (SetPasswordHash clears it), a
// credential that never expires, and an error telling them nothing was recovered.
//
// The fault goes in below the command: `keyorix-server admin recover-admin` opens its
// own storage from the config file (withUsableStorage), so there is no seam to wrap it
// from a test, and runRecoverAdmin only adds the "recover-admin: " prefix to what
// performRecoverAdminWithTTL returns (RunE error -> exit status 1, as its help text
// states). Both fault kinds run:
//   - error: SetOneTimePasswordExpiry fails without writing;
//   - effect-then-error: the expiry write lands inside the transaction and the call then
//     reports failure, the case where only a real rollback restores the old state.
//
// Each case also requires that the fault fired AFTER SetPasswordHash had been applied in
// the same run, so "unchanged" is a rollback and not a write that never happened.
func TestPerformRecoverAdmin_OneTimePasswordExpiryFault_RollsBack(t *testing.T) {
	errInjected := errors.New("injected SetOneTimePasswordExpiry failure")

	for _, kind := range []faultstorage.FaultKind{faultstorage.KindError, faultstorage.KindEffectThenError} {
		t.Run(kind.String(), func(t *testing.T) {
			ctx := context.Background()
			store := newRecoverAdminTestStore(t)
			user := seedAdminUser(t, ctx, store, "admin1", "admin1@example.com", "OldPassw0rd!")
			rawKey := seedRecoveryKey(t, ctx, store)

			// State a locked-out admin might have, all of which the transaction clears.
			if err := store.SetUserMFAEnabled(ctx, user.ID, true); err != nil {
				t.Fatalf("enable MFA: %v", err)
			}
			if err := store.CreateWebAuthnCredential(ctx, &models.WebAuthnCredential{
				UserID: user.ID, CredentialID: []byte("cred-1"), Name: "Test Key", CreatedAt: time.Now(),
			}); err != nil {
				t.Fatalf("create webauthn credential: %v", err)
			}
			sessExp := time.Now().Add(time.Hour)
			if _, err := store.CreateSession(ctx, &models.Session{
				UserID: user.ID, SessionToken: "sesshash1", ExpiresAt: &sessExp, CreatedAt: time.Now(),
			}); err != nil {
				t.Fatalf("create session: %v", err)
			}
			lockedUntil := time.Now().Add(10 * time.Minute)
			if err := store.UpdateLoginLockoutState(ctx, user.ID, 5, &lockedUntil, &lockedUntil, 2); err != nil {
				t.Fatalf("seed lockout state: %v", err)
			}
			// A non-nil expiry on the old credential, so "expiry unchanged" can fail: a
			// rollback that did not happen leaves the new expiry (or none, once
			// SetPasswordHash cleared it) here instead.
			oldExpiry := time.Now().Add(6 * time.Hour).UTC().Truncate(time.Second)
			if err := store.SetOneTimePasswordExpiry(ctx, user.ID, &oldExpiry, time.Now()); err != nil {
				t.Fatalf("seed one-time password expiry: %v", err)
			}

			before, err := store.GetUser(ctx, user.ID)
			if err != nil {
				t.Fatalf("GetUser before: %v", err)
			}
			if before.OneTimePasswordExpiresAt == nil {
				t.Fatal("fixture: the seeded expiry was not stored, so this test could not tell an unchanged expiry from a cleared one")
			}

			faulty := faultstorage.NewFaultyStorage(store, &faultstorage.FaultSpec{
				Method: "SetOneTimePasswordExpiry", NthCall: 1, Kind: kind, Err: errInjected,
			})
			summary, err := performRecoverAdmin(ctx, faulty, fmt.Sprintf("%d", user.ID), rawKey, false)

			// The command must report failure, naming the step, and not hand out a password.
			if err == nil {
				t.Fatal("performRecoverAdmin returned nil although SetOneTimePasswordExpiry failed: the command would print a one-time password for an account whose reset did not complete")
			}
			if !errors.Is(err, errInjected) {
				t.Errorf("error does not wrap the injected failure: %v", err)
			}
			if !strings.Contains(err.Error(), "set one-time password expiry") {
				t.Errorf("error does not name the failing step (the operator needs to know what failed): %v", err)
			}
			if summary != nil {
				t.Errorf("a summary (with a one-time password) was returned alongside the error: %+v", summary)
			}

			// Premise: the fault fired, and only after the hash write in the same run.
			if !faulty.Fired() {
				t.Fatal("the armed SetOneTimePasswordExpiry fault never fired: the test proved nothing")
			}
			hashSeq, expirySeq := 0, 0
			for _, c := range faulty.Calls() {
				switch {
				case c.Method == "SetPasswordHash" && hashSeq == 0:
					hashSeq = c.Seq
				case c.Method == "SetOneTimePasswordExpiry" && expirySeq == 0:
					expirySeq = c.Seq
				}
			}
			if hashSeq == 0 || expirySeq == 0 || hashSeq > expirySeq {
				t.Fatalf("expected SetPasswordHash (seq %d) to run before the faulted SetOneTimePasswordExpiry (seq %d); "+
					"without that the unchanged hash below is not a rollback", hashSeq, expirySeq)
			}

			// The account is exactly as it was.
			after, err := store.GetUser(ctx, user.ID)
			if err != nil {
				t.Fatalf("GetUser after: %v", err)
			}
			if after.PasswordHash != before.PasswordHash {
				t.Errorf("password hash changed although the transaction failed (rollback missing): the old password no longer works and an unprinted one-time hash is live")
			}
			if after.OneTimePasswordExpiresAt == nil || !after.OneTimePasswordExpiresAt.Equal(*before.OneTimePasswordExpiresAt) {
				t.Errorf("one-time password expiry changed: before %v, after %v", before.OneTimePasswordExpiresAt, after.OneTimePasswordExpiresAt)
			}
			if after.AccountState != before.AccountState {
				t.Errorf("account state changed: %q -> %q", before.AccountState, after.AccountState)
			}
			if !after.MFAEnabled {
				t.Error("MFA enrollment was cleared although the transaction failed")
			}
			if after.FailedLoginAttempts != 5 || after.LoginLockedUntil == nil || after.LoginLockoutCount != 2 {
				t.Errorf("lockout state was cleared although the transaction failed: %+v", after)
			}
			creds, err := store.ListWebAuthnCredentials(ctx, user.ID)
			if err != nil {
				t.Fatalf("ListWebAuthnCredentials: %v", err)
			}
			if len(creds) != 1 {
				t.Errorf("WebAuthn credentials: got %d, want the 1 seeded (deleted although the transaction failed)", len(creds))
			}
			tokens, err := store.ListSessionTokenHashesForUser(ctx, user.ID)
			if err != nil {
				t.Fatalf("ListSessionTokenHashesForUser: %v", err)
			}
			if len(tokens) != 1 {
				t.Errorf("sessions: got %d, want the 1 seeded (revoked although the transaction failed)", len(tokens))
			}

			// A failed recovery is not audited as a recovery.
			action := "admin.recover_admin"
			events, _, err := store.GetAuditLogs(ctx, &storage.AuditFilter{Action: &action, PageSize: 10})
			if err != nil {
				t.Fatalf("GetAuditLogs: %v", err)
			}
			if len(events) != 0 {
				t.Errorf("%d admin.recover_admin audit event(s) written for a recovery that failed", len(events))
			}
		})
	}
}
