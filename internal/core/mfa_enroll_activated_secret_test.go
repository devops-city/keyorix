package core

import (
	"context"
	"testing"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/ports"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// afterFirstGetUser runs hook once, right after the first GetUser returns: the
// window between a function's pre-read of the user row and its later write.
func afterFirstGetUser(inner storage.Storage, hook func()) storage.Storage {
	done := false
	var st storage.Storage
	st = hooked(inner, &storeHooks{
		GetUser: func(next storage.Storage, ctx context.Context, id uint) (*models.User, error) {
			u, err := next.GetUser(ctx, id)
			if !done {
				done = true
				hook()
			}
			return u, err
		},
		// Forwards over the wrapper itself, so a session cache hit meets the
		// GetUser override too (session_auth_read_wrapper_forwarding_guard_test.go).
		GetSessionAuthLiveness: func(_ storage.Storage, ctx context.Context, userID, sessionID uint) (*storage.SessionAuthLiveness, error) {
			return storage.ComposeSessionAuthLiveness(ctx, st, userID, sessionID), nil
		},
	})
	return st
}

// TestBeginMFAEnrollment_DoesNotReplaceActivatedSecret (#2692): an ActivateMFA
// that commits between BeginMFAEnrollment's MFAEnabled=false read and its
// upsert must not have its activated secret replaced by a fresh pending one.
// Before the fix the OnConflict{UpdateAll} upsert overwrote the activated row
// with Activated=false and a seed it then returned to the enroller; login
// verification does not consult Activated, so that seed satisfied MFA on an
// MFA-enabled account.
func TestBeginMFAEnrollment_DoesNotReplaceActivatedSecret(t *testing.T) {
	c, db, _ := newMFATestCore(t)
	ctx := context.Background()
	c.storage = afterFirstGetUser(c.storage, func() {
		// a concurrent ActivateMFA commits between the MFAEnabled read and the upsert
		require.NoError(t, db.Create(&models.MFASecret{UserID: 1, SecretEnc: []byte("live-secret"), Activated: true}).Error)
		require.NoError(t, db.Model(&models.User{}).Where("id = 1").Update("mfa_enabled", true).Error)
	})
	uri, secret, err := c.BeginMFAEnrollment(ctx, 1)
	require.ErrorIs(t, err, ErrMFAAlreadyEnabled, "the late enrolment must be refused, not silently succeed")
	require.Equal(t, ErrMFAAlreadyEnabled.Error(), err.Error(),
		"the handler passes this text through as a safe message only on an exact match (mfaSafeMessages)")
	require.Empty(t, uri)
	require.Empty(t, secret, "no seed may be handed to the enroller")

	var s models.MFASecret
	require.NoError(t, db.Where("user_id = 1").First(&s).Error)
	require.True(t, s.Activated, "#2692: the activated secret was replaced by a pending one (Activated=false)")
	require.Equal(t, "live-secret", string(s.SecretEnc))

	var audits int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", "mfa.enrolled").Count(&audits).Error)
	require.Zero(t, audits, "a refused enrolment must not be audited as mfa.enrolled")
}

// TestBeginMFAEnrollment_StillSupersedesPendingSecret is the calibration case:
// the conditional upsert must still replace a PENDING (not-activated) secret,
// which is what re-running enrolment before activating does.
func TestBeginMFAEnrollment_StillSupersedesPendingSecret(t *testing.T) {
	c, db, _ := newMFATestCore(t)
	ctx := context.Background()
	_, first, err := c.BeginMFAEnrollment(ctx, 1)
	require.NoError(t, err)
	var before models.MFASecret
	require.NoError(t, db.Where("user_id = 1").First(&before).Error)

	_, second, err := c.BeginMFAEnrollment(ctx, 1)
	require.NoError(t, err)
	require.NotEqual(t, first, second)

	var rows []models.MFASecret
	require.NoError(t, db.Where("user_id = 1").Find(&rows).Error)
	require.Len(t, rows, 1)
	require.False(t, rows[0].Activated)
	require.NotEqual(t, before.SecretEnc, rows[0].SecretEnc, "the pending secret must be superseded by the new one")
	got, err := c.decryptAuthSecret(rows[0].SecretEnc, rows[0].SecretMeta, ports.MFASecretAAD(1))
	require.NoError(t, err)
	require.Equal(t, second, got, "the stored secret is the one returned to the enroller")
}

// TestMFAVerifiers_PendingSecretIsNotASecondFactor (#2692, defence in depth):
// the end state the race produced — MFAEnabled=true over a PENDING secret whose
// seed the enroller holds — must not let that seed pass any verifier. All of
// them read the seed through loadTOTPSecret, which now refuses a pending row.
// Calibrated: once the same row is activated, the same code passes.
func TestMFAVerifiers_PendingSecretIsNotASecondFactor(t *testing.T) {
	c, db, fixed := newMFATestCore(t)
	ctx := context.Background()
	_, seed, err := c.BeginMFAEnrollment(ctx, 1)
	require.NoError(t, err)
	require.NoError(t, db.Model(&models.User{}).Where("id = 1").Update("mfa_enabled", true).Error)
	code, err := totp.GenerateCode(seed, fixed)
	require.NoError(t, err)

	ch, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	sess, _, _, err := c.VerifyMFALogin(ctx, ch, code, "ua", "1.2.3.4")
	require.Error(t, err, "login: a pending seed must not complete the second factor")
	require.Nil(t, sess)
	require.Error(t, c.VerifyMFAStepUp(ctx, 1, code), "step-up: a pending seed must not satisfy step-up")
	_, err = c.RegenerateMFARecoveryCodes(ctx, 1, code)
	require.Error(t, err, "re-auth: a pending seed must not re-authenticate")

	require.NoError(t, db.Model(&models.MFASecret{}).Where("user_id = 1").Update("activated", true).Error)
	ch, err = c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	sess, _, _, err = c.VerifyMFALogin(ctx, ch, code, "ua", "1.2.3.4")
	require.NoError(t, err, "calibration: the same code passes once the secret is activated")
	require.NotNil(t, sess)
}
