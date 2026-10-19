// keep_session_lookup_fail_closed_test.go — #2835: ChangePassword, ActivateMFA,
// and DisableMFA each spare the caller's own session from their post-change
// session purge by resolving keepSessionToken via storage.GetSession. When that
// one lookup fails, the purge correctly still widens to include the caller's own
// session (the deliberate fail-closed fallback — see resolveKeepSession's doc
// comment, account.go) but previously did so completely silently: no audit event,
// no log line distinguished "no session to spare" from "could not tell which
// session to spare, so we killed them all". These tests prove the widening is now
// observable, at all three call sites, without changing the widening itself.
package core

import (
	"context"
	"errors"
	"testing"
	"time"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// getSessionErrStub wraps a real storage.Storage and overrides exactly GetSession
// to inject a fixed error, mirroring mfaSecretReadErrStub (mfa_login_storage_error_test.go).
func getSessionErrStub(inner corestorage.Storage, err error) corestorage.Storage {
	return hooked(inner, &storeHooks{
		GetSession: func(next corestorage.Storage, ctx context.Context, token string) (*models.Session, error) {
			if err != nil {
				return nil, err
			}
			return next.GetSession(ctx, token)
		},
	})
}

// TestChangePassword_KeepSessionLookupFailure_WidensAndAudits: a GetSession
// failure on a NON-EMPTY keepSessionToken must still purge every session for the
// user (including the one that would have been spared) and must write an
// EventKeepSessionLookupFailed audit row recording why.
func TestChangePassword_KeepSessionLookupFailure_WidensAndAudits(t *testing.T) {
	t.Parallel()
	c, db, _ := newMFATestCore(t)
	require.NoError(t, db.AutoMigrate(&models.Session{}))
	ctx := context.Background()

	require.NoError(t, db.Create(&models.Session{UserID: 1, SessionToken: hashSessionTokenForLookup("caller-token")}).Error)

	realStorage := c.storage
	faultErr := errors.New("fault-fuzz injected failure")
	c.storage = getSessionErrStub(realStorage, faultErr)

	err := c.ChangePassword(ctx, 1, mfaTestPassword, "NewSecret#Passw0rd!", "caller-token")
	require.NoError(t, err, "a keep-session lookup failure must not fail the password change itself")

	var remaining int64
	require.NoError(t, db.Model(&models.Session{}).Where("user_id = ?", 1).Count(&remaining).Error)
	assert.Zero(t, remaining, "every session, including the caller's own, must be purged when it cannot be resolved")

	var events []models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", EventKeepSessionLookupFailed).Find(&events).Error)
	require.Len(t, events, 1, "exactly one EventKeepSessionLookupFailed row must be written")
	assert.Equal(t, uint(1), *events[0].UserID)
	assert.Contains(t, events[0].Description, "change_password")
}

// TestActivateMFA_KeepSessionLookupFailure_WidensAndAudits mirrors the
// ChangePassword case for ActivateMFA's own keepSessionToken resolution.
func TestActivateMFA_KeepSessionLookupFailure_WidensAndAudits(t *testing.T) {
	t.Parallel()
	c, db, fixed := newMFATestCore(t)
	require.NoError(t, db.AutoMigrate(&models.Session{}))
	ctx := context.Background()

	_, secret, err := c.BeginMFAEnrollment(ctx, 1)
	require.NoError(t, err)
	actCode, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)

	require.NoError(t, db.Create(&models.Session{UserID: 1, SessionToken: hashSessionTokenForLookup("caller-token")}).Error)

	realStorage := c.storage
	faultErr := errors.New("fault-fuzz injected failure")
	c.storage = getSessionErrStub(realStorage, faultErr)

	_, err = c.ActivateMFA(ctx, 1, actCode, mfaTestPassword, "caller-token")
	require.NoError(t, err, "a keep-session lookup failure must not fail MFA activation itself")

	var remaining int64
	require.NoError(t, db.Model(&models.Session{}).Where("user_id = ?", 1).Count(&remaining).Error)
	assert.Zero(t, remaining, "every session, including the caller's own, must be purged when it cannot be resolved")

	var events []models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", EventKeepSessionLookupFailed).Find(&events).Error)
	require.Len(t, events, 1, "exactly one EventKeepSessionLookupFailed row must be written")
	assert.Contains(t, events[0].Description, "activate_mfa")
}

// TestDisableMFA_KeepSessionLookupFailure_WidensAndAudits mirrors the
// ChangePassword case for DisableMFA's own keepSessionToken resolution.
func TestDisableMFA_KeepSessionLookupFailure_WidensAndAudits(t *testing.T) {
	t.Parallel()
	c, db, fixed := newMFATestCore(t)
	require.NoError(t, db.AutoMigrate(&models.Session{}))
	ctx := context.Background()

	_, secret, err := c.BeginMFAEnrollment(ctx, 1)
	require.NoError(t, err)
	actCode, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)
	_, err = c.ActivateMFA(ctx, 1, actCode, mfaTestPassword, "")
	require.NoError(t, err)

	require.NoError(t, db.Create(&models.Session{UserID: 1, SessionToken: hashSessionTokenForLookup("caller-token")}).Error)

	disCode, err := totp.GenerateCode(secret, fixed.Add(30*time.Second))
	require.NoError(t, err)

	realStorage := c.storage
	faultErr := errors.New("fault-fuzz injected failure")
	c.storage = getSessionErrStub(realStorage, faultErr)

	err = c.DisableMFA(ctx, 1, disCode, "caller-token")
	require.NoError(t, err, "a keep-session lookup failure must not fail MFA disable itself")

	var remaining int64
	require.NoError(t, db.Model(&models.Session{}).Where("user_id = ?", 1).Count(&remaining).Error)
	assert.Zero(t, remaining, "every session, including the caller's own, must be purged when it cannot be resolved")

	var events []models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", EventKeepSessionLookupFailed).Find(&events).Error)
	require.Len(t, events, 1, "exactly one EventKeepSessionLookupFailed row must be written")
	assert.Contains(t, events[0].Description, "disable_mfa")
}

// TestResolveKeepSession_EmptyToken_NeverAudits: the ordinary "no session to
// spare" case (keepSessionToken == "", e.g. a PAT-authenticated caller) must NOT
// be confused with a lookup failure — no GetSession call, no audit event.
func TestResolveKeepSession_EmptyToken_NeverAudits(t *testing.T) {
	t.Parallel()
	c, db, _ := newMFATestCore(t)
	ctx := context.Background()

	keepID, keepHash := c.resolveKeepSession(ctx, 1, "", "change_password")
	assert.Zero(t, keepID)
	assert.Empty(t, keepHash)

	var count int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", EventKeepSessionLookupFailed).Count(&count).Error)
	assert.Zero(t, count, "an empty keepSessionToken is not a lookup failure and must not be audited as one")
}

// deleteSessionsForUserExceptErrStub wraps a real storage.Storage and overrides
// exactly DeleteSessionsForUserExcept to inject a fixed error.
func deleteSessionsForUserExceptErrStub(inner corestorage.Storage, err error) corestorage.Storage {
	return hooked(inner, &storeHooks{
		DeleteSessionsForUserExcept: func(next corestorage.Storage, ctx context.Context, userID, keepID uint) error {
			if err != nil {
				return err
			}
			return next.DeleteSessionsForUserExcept(ctx, userID, keepID)
		},
	})
}

// TestDeleteSessionsForUserAndEvict_PurgeFailure_Audits: the purge call itself
// failing (not panicking) previously vanished the instant any of its 8 call sites
// discarded the returned error (`_ = c.deleteSessionsForUserAndEvict(...)`). It
// must now write an EventSessionRevocationFailed row — the returned-error sibling
// of EventSessionRevocationPanicked, which already covers the panic case.
func TestDeleteSessionsForUserAndEvict_PurgeFailure_Audits(t *testing.T) {
	t.Parallel()
	c, db, _ := newMFATestCore(t)
	ctx := context.Background()

	realStorage := c.storage
	faultErr := errors.New("fault-fuzz injected failure")
	c.storage = deleteSessionsForUserExceptErrStub(realStorage, faultErr)

	err := c.deleteSessionsForUserAndEvict(ctx, 1, 0, "")
	assert.Error(t, err, "the real failure must still be returned to the (test) caller")

	var events []models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", EventSessionRevocationFailed).Find(&events).Error)
	require.Len(t, events, 1, "exactly one EventSessionRevocationFailed row must be written")
	assert.Equal(t, uint(1), *events[0].UserID)
}
