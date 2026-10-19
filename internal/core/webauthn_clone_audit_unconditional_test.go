// webauthn_clone_audit_unconditional_test.go — #2836, a review finding against
// #2700's own fix earlier in this same branch (never on main).
//
// #2700 replaced markWebAuthnCredentialClonedDisabled's full-row GORM Save with
// a column-scoped conditional UPDATE, because the Save's 0-rows fallback
// re-INSERTED a passkey the user had concurrently deleted. Correct, and it
// introduced a regression: the new code returned early when the UPDATE matched
// no rows, and when it failed outright, in both cases BEFORE the
// EventWebAuthnCloneDetected audit write. The Save it replaced always reached
// that write (it upserted the row back), so a clone signal that previously left
// an audit trail now left nothing at all whenever the credential vanished — or
// the database hiccuped — in the window between the assertion check and the
// disable.
//
// The regression was additionally covered by a comment asserting that
// "the caller's rejectIfCloned path already audits the clone signal separately
// for the credential-missing case". It does not: rejectIfCloned's else branch
// fires only when the LOOKUP fails, never when a lookup succeeds and the
// following UPDATE matches nothing. That cover was asserted, never checked. The
// tests here are the check.
//
// Both subtests assert the EFFECT — an audit row that exists, with a detail
// that says what actually happened to the credential — not a return value.
// They have to: the failure mode is silence, and markWebAuthnCredentialClonedDisabled's
// error return is DISCARDED by its only login-time caller, so no return value
// anywhere in the chain distinguishes "audited" from "silently skipped".
package core

import (
	"context"
	"errors"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// credentialVanishingStore returns the real row from
// GetWebAuthnCredentialByCredID and then hard-deletes it, so the following
// DisableWebAuthnCredential matches zero rows against a real database. That is
// precisely the production interleaving — a passkey deleted between the
// assertion check and the disable — reproduced without interleaving machinery,
// and it drives the FULL rejectIfCloned path rather than the inner function in
// isolation, so the caller's discarded error is part of what is under test.
type credentialVanishingStore struct {
	inner corestorage.Storage
	db    *gorm.DB
}

func (s *credentialVanishingStore) GetWebAuthnCredentialByCredID(next corestorage.Storage, ctx context.Context, credID []byte, userID uint) (*models.WebAuthnCredential, error) {
	row, err := next.GetWebAuthnCredentialByCredID(ctx, credID, userID)
	if err != nil {
		return nil, err
	}
	// WebAuthnCredential is hard-deleted (no DeletedAt), which is why #2700's
	// Save-upsert resurrected it in the first place.
	if derr := s.db.Unscoped().Delete(&models.WebAuthnCredential{}, row.ID).Error; derr != nil {
		return nil, derr
	}
	return row, nil
}

// wrap returns inner decorated with credentialVanishingStore's overrides.
func (s *credentialVanishingStore) wrap(inner corestorage.Storage) corestorage.Storage {
	return hooked(inner, &storeHooks{
		GetWebAuthnCredentialByCredID: s.GetWebAuthnCredentialByCredID,
	})
}

// store returns s.inner decorated with credentialVanishingStore's overrides.
func (s *credentialVanishingStore) store() corestorage.Storage { return s.wrap(s.inner) }

// credentialDisableFailingStore fails the disable UPDATE outright. The clone
// verdict was already reached before this call (CloneWarning was true), so
// unlike an MFA storage failure this does NOT leave the security question
// unanswered — the incident is real and must be recorded; only the mitigation
// failed.
func credentialDisableFailingStore(inner corestorage.Storage) corestorage.Storage {
	return hooked(inner, &storeHooks{
		DisableWebAuthnCredential: func(corestorage.Storage, context.Context, uint) (bool, error) {
			return false, errors.New("pq: connection reset by peer")
		},
	})
}

func TestRejectIfCloned_AuditsTheCloneEvenWhenTheDisableDoesNotTakeEffect(t *testing.T) {
	t.Parallel()

	t.Run("credential deleted between the lookup and the disable", func(t *testing.T) {
		c, db := newWebAuthnTestCore(t, true)
		credID := []byte("cred-2836-vanished")
		seedCredential(t, c, db, 1, string(credID))
		c.storage = (&credentialVanishingStore{inner: c.storage, db: db}).store()

		cred := &webauthn.Credential{ID: credID, Authenticator: webauthn.Authenticator{CloneWarning: true}}
		err := c.rejectIfCloned(context.Background(), 1, cred, "203.0.113.9")
		require.Error(t, err, "a regressed signature counter must still refuse the authentication")

		// The row really is gone, so this subtest is exercising the !matched
		// branch and not accidentally the happy path.
		var remaining int64
		require.NoError(t, db.Model(&models.WebAuthnCredential{}).Where("credential_id = ?", credID).Count(&remaining).Error)
		require.Zero(t, remaining, "fixture precondition: the credential must have been deleted before the disable ran")

		ev := soleCloneDetectedEvent(t, db)
		assert.Contains(t, ev.Description, "already deleted",
			"the audit detail must say the credential was already gone — recording it as 'disabled pending "+
				"re-registration' would claim a mitigation that never happened (#2836)")
	})

	t.Run("the disable UPDATE fails", func(t *testing.T) {
		c, db := newWebAuthnTestCore(t, true)
		credID := []byte("cred-2836-disable-down")
		seedCredential(t, c, db, 1, string(credID))
		c.storage = credentialDisableFailingStore(c.storage)

		cred := &webauthn.Credential{ID: credID, Authenticator: webauthn.Authenticator{CloneWarning: true}}
		err := c.rejectIfCloned(context.Background(), 1, cred, "203.0.113.9")
		require.Error(t, err, "a regressed signature counter must still refuse the authentication")

		ev := soleCloneDetectedEvent(t, db)
		assert.Contains(t, ev.Description, "could NOT be disabled",
			"the audit detail must say the credential is still live — an operator reading this incident has to "+
				"know the mitigation did not apply and the passkey needs removing by hand (#2836)")
	})
}

// soleCloneDetectedEvent asserts exactly one clone-detected event exists and
// returns it. Exactly one, not at-least-one: the unconditional audit write must
// not double up with rejectIfCloned's own lookup-failure write, which is the
// obvious wrong way to fix this.
func soleCloneDetectedEvent(t *testing.T, db *gorm.DB) models.AuditEvent {
	t.Helper()
	var events []models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", EventWebAuthnCloneDetected).Find(&events).Error)
	require.Len(t, events, 1,
		"a clone signal must produce exactly one clone-detected audit event whatever happens to the row — "+
			"zero means the incident went unrecorded (#2836), two means the fix double-counts it")
	return events[0]
}
