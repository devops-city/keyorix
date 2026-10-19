// mfa_atomicity_test.go — #G08 detection_idea: force a storage failure between the
// two (or three) writes each of DisableMFA/RegenerateMFARecoveryCodes/ActivateMFA
// makes, and assert — by reading the raw DB directly, not just checking the
// returned error — that NO state exists where the enforcement flag and the
// credential material disagree. Each test wraps a real SQLite-backed
// storage.Storage with failingStorage, which forwards every call to the real
// implementation except one method (the SECOND write in the pair/triple), which it
// fails outright — proving the fix's WithTransaction wrapping causes a genuine
// rollback of the FIRST write too, not just an early return.
package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failingStorage wraps a real storage.Storage and fails every call to the named
// method with errInjectedFailure — every other method (including WithTransaction,
// which re-wraps the transactional storage.Storage handed to the callback so the
// injected failure applies INSIDE the transaction, not just at the outer layer)
// passes through untouched.
func failingStorage(inner storage.Storage, failMethod string) storage.Storage {
	return hooked(inner, &storeHooks{
		WrapTx: true,
		ActivateMFASecret: func(next storage.Storage, ctx context.Context, userID uint, secretEnc []byte) (bool, error) {
			if failMethod == "ActivateMFASecret" {
				return false, errInjectedFailure
			}
			return next.ActivateMFASecret(ctx, userID, secretEnc)
		},
		SetUserMFAEnabled: func(next storage.Storage, ctx context.Context, userID uint, enabled bool) error {
			if failMethod == "SetUserMFAEnabled" {
				return errInjectedFailure
			}
			return next.SetUserMFAEnabled(ctx, userID, enabled)
		},
		CreateMFARecoveryCodes: func(next storage.Storage, ctx context.Context, userID uint, hashes []string) error {
			if failMethod == "CreateMFARecoveryCodes" {
				return errInjectedFailure
			}
			return next.CreateMFARecoveryCodes(ctx, userID, hashes)
		},
		DeleteMFAForUser: func(next storage.Storage, ctx context.Context, userID uint) error {
			if failMethod == "DeleteMFAForUser" {
				return errInjectedFailure
			}
			return next.DeleteMFAForUser(ctx, userID)
		},
		DeleteMFARecoveryCodes: func(next storage.Storage, ctx context.Context, userID uint) error {
			if failMethod == "DeleteMFARecoveryCodes" {
				return errInjectedFailure
			}
			return next.DeleteMFARecoveryCodes(ctx, userID)
		},
		AssignPermissionToRole: func(next storage.Storage, ctx context.Context, roleID, permissionID uint) error {
			if failMethod == "AssignPermissionToRole" {
				return errInjectedFailure
			}
			return next.AssignPermissionToRole(ctx, roleID, permissionID)
		},
	})
}

var errInjectedFailure = errors.New("injected storage failure")

// AssignPermissionToRole: used by alerts_write_role_reconcile_test.go's
// TestSeedAlertOperatorRole_AtomicOnPermissionGrantFailure (same package, same
// failingStorage wrapper — not MFA-specific despite this file's name).
// TestActivateMFA_AtomicOnRecoveryCodesFailure: CreateMFARecoveryCodes (the LAST of
// the three writes) fails — ActivateMFASecret and SetUserMFAEnabled must both roll
// back too, or the account would end up MFA-enabled with zero recovery codes and no
// fallback if the device is ever lost.
func TestActivateMFA_AtomicOnRecoveryCodesFailure(t *testing.T) {
	t.Parallel()
	c, db, fixed := newMFATestCore(t)
	ctx := context.Background()
	_, secret, err := c.BeginMFAEnrollment(ctx, 1)
	require.NoError(t, err)
	code, err := totp.GenerateCode(secret, fixed.Add(-30*time.Second))
	require.NoError(t, err)

	c.storage = failingStorage(c.storage, "CreateMFARecoveryCodes")
	_, err = c.ActivateMFA(ctx, 1, code, mfaTestPassword, "")
	require.Error(t, err)

	var user models.User
	require.NoError(t, db.First(&user, 1).Error)
	assert.False(t, user.MFAEnabled, "MFAEnabled must roll back to false when recovery-code creation fails")

	var secretRow models.MFASecret
	require.NoError(t, db.Where("user_id = ?", 1).First(&secretRow).Error)
	assert.False(t, secretRow.Activated, "the MFA secret must roll back to NOT activated")

	var codeCount int64
	require.NoError(t, db.Model(&models.MFARecoveryCode{}).Where("user_id = ?", 1).Count(&codeCount).Error)
	assert.Zero(t, codeCount, "no recovery codes may exist after a failed activation")
}

// TestDisableMFA_AtomicOnDeleteFailure: DeleteMFAForUser (the second write) fails —
// SetUserMFAEnabled's flip to false must roll back too, or the account would report
// MFA disabled while the TOTP secret and recovery codes are still live in storage.
func TestDisableMFA_AtomicOnDeleteFailure(t *testing.T) {
	t.Parallel()
	c, db, fixed := newMFATestCore(t)
	ctx := context.Background()
	activateMFAForTest(t, c, fixed)

	// MFA is enrolled, so password alone no longer satisfies requireReauth's
	// second-factor requirement (#372-follow-up); seed an active step-up grant so
	// re-auth succeeds and the test actually reaches (and exercises) the injected
	// storage failure below, rather than failing earlier at re-auth.
	require.NoError(t, db.Create(&models.MFAStepUpGrant{UserID: 1, Purpose: models.MFAStepUpPurposeReauth, ExpiresAt: fixed.Add(15 * time.Minute)}).Error)

	c.storage = failingStorage(c.storage, "DeleteMFAForUser")
	err := c.DisableMFA(ctx, 1, mfaTestPassword, "")
	require.Error(t, err)

	var user models.User
	require.NoError(t, db.First(&user, 1).Error)
	assert.True(t, user.MFAEnabled, "MFAEnabled must roll back to true when clearing credential material fails")

	var secretCount int64
	require.NoError(t, db.Model(&models.MFASecret{}).Where("user_id = ?", 1).Count(&secretCount).Error)
	assert.Equal(t, int64(1), secretCount, "the TOTP secret must still exist — DeleteMFAForUser's failure must not have partially cleared it while MFAEnabled reports true")
}

// TestRegenerateMFARecoveryCodes_AtomicOnCreateFailure: CreateMFARecoveryCodes (the
// second write) fails — the prior DeleteMFARecoveryCodes must roll back too, or the
// account would be left with ZERO recovery codes: no old set (deleted) and no new
// set (creation failed), an unsafe state the API nonetheless reports as a clean
// failure to the caller.
func TestRegenerateMFARecoveryCodes_AtomicOnCreateFailure(t *testing.T) {
	t.Parallel()
	c, db, fixed := newMFATestCore(t)
	ctx := context.Background()
	_, original := activateMFAForTest(t, c, fixed)
	require.Len(t, original, mfaRecoveryCodeCount)

	// MFA is enrolled, so password alone no longer satisfies requireReauth's
	// second-factor requirement (#372-follow-up); seed an active step-up grant so
	// re-auth succeeds and the test actually reaches (and exercises) the injected
	// storage failure below, rather than failing earlier at re-auth.
	require.NoError(t, db.Create(&models.MFAStepUpGrant{UserID: 1, Purpose: models.MFAStepUpPurposeReauth, ExpiresAt: fixed.Add(15 * time.Minute)}).Error)

	c.storage = failingStorage(c.storage, "CreateMFARecoveryCodes")
	_, err := c.RegenerateMFARecoveryCodes(ctx, 1, mfaTestPassword)
	require.Error(t, err)

	var codeCount int64
	require.NoError(t, db.Model(&models.MFARecoveryCode{}).Where("user_id = ?", 1).Count(&codeCount).Error)
	assert.Equal(t, int64(mfaRecoveryCodeCount), codeCount,
		"the ORIGINAL recovery codes must still be present — deleting them must roll back when creating the replacement set fails")
}
