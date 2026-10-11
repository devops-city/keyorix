// mfa_login_storage_error_test.go — deterministic unit test for
// docs/findings/2026-10-02-FINDING-mfa-login-getmfasecret-storage-error-counted-as-wrong-code.md:
// a transient GetMFASecret storage error during TOTP login verification used to
// collapse into "wrong code" — audited as a failed attempt and counted toward the
// account lockout, even though the code supplied was never actually checked.
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

// mfaSecretReadErrStub wraps a real storage.Storage and overrides exactly
// GetMFASecret to inject a fixed error, mirroring the secretReadErrStub /
// webauthnStorageErrStub pattern used elsewhere in this package.
type mfaSecretReadErrStub struct {
	corestorage.Storage
	err error
}

func (s *mfaSecretReadErrStub) GetMFASecret(ctx context.Context, userID uint) (*models.MFASecret, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.Storage.GetMFASecret(ctx, userID)
}

// TestVerifyMFALogin_GetMFASecretErrorDoesNotFeedLockout: N GetMFASecret
// failures (N > the lockout's MaxAttempts) with the CORRECT code must leave
// the account unlocked — a storage read failure is not a confirmed wrong
// code, and must not be audited or counted as one. Once the fault clears, the
// SAME correct code must still verify successfully.
func TestVerifyMFALogin_GetMFASecretErrorDoesNotFeedLockout(t *testing.T) {
	t.Parallel()
	c, db, fixed := newMFATestCore(t)
	c.loginLockout = LoginLockoutPolicy{Enabled: true, MaxAttempts: 3, Window: time.Hour, BaseCooldown: 15 * time.Minute, MaxCooldown: time.Hour}
	ctx := context.Background()

	_, secret, err := c.BeginMFAEnrollment(ctx, 1)
	require.NoError(t, err)
	// Activate with the PREVIOUS step so the current step (fixed) stays fresh for
	// the login checks below — mirrors TestVerifyMFALogin_RejectsReplayedTOTPCode's
	// own technique; activation and login both consume a step via MarkTOTPStepUsed,
	// so reusing the same step would make the later "good code" check a replay.
	actCode, err := totp.GenerateCode(secret, fixed.Add(-30*time.Second))
	require.NoError(t, err)
	_, err = c.ActivateMFA(ctx, 1, actCode, mfaTestPassword, "")
	require.NoError(t, err)

	good, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)

	realStorage := c.storage
	faultErr := errors.New("fault-fuzz injected failure")
	c.storage = &mfaSecretReadErrStub{Storage: realStorage, err: faultErr}

	// 5 attempts with the CORRECT code, each failing to even check it because
	// GetMFASecret errors every time — more than MaxAttempts (3), so if this
	// were (wrongly) counted toward the lockout, the account would now be locked.
	for i := 0; i < 5; i++ {
		ch, cerr := c.CreateMFAChallenge(ctx, 1)
		require.NoError(t, cerr)
		_, _, _, verr := c.VerifyMFALogin(ctx, ch, good, "ua", "9.9.9.9")
		require.Error(t, verr, "attempt %d: a storage error must still refuse the login", i)
		assert.NotContains(t, verr.Error(), "invalid code",
			"attempt %d: a storage error must not be reported as a wrong code", i)
	}

	var afterFaults models.User
	require.NoError(t, db.First(&afterFaults, 1).Error)
	assert.Nil(t, afterFaults.LoginLockedUntil,
		"account must NOT be locked — none of the 5 storage-error attempts was a confirmed wrong code")

	// Only mfa.error events, never mfa.failed, for the 5 faulted attempts.
	var failedCount, errorCount int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ? AND user_id = ?", "mfa.failed", uint(1)).Count(&failedCount).Error)
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ? AND user_id = ?", "mfa.error", uint(1)).Count(&errorCount).Error)
	assert.Zero(t, failedCount, "a storage-error attempt must not be audited as a failed (wrong-code) MFA attempt")
	assert.EqualValues(t, 5, errorCount, "each storage-error attempt must be audited distinctly as an error")

	// Fault clears: the SAME correct code (never consumed — MarkTOTPStepUsed was
	// never reached while GetMFASecret kept failing) now verifies successfully,
	// proving the account was genuinely never locked, not just not-yet-checked.
	c.storage = realStorage
	ch, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	sess, _, _, err := c.VerifyMFALogin(ctx, ch, good, "ua", "9.9.9.9")
	require.NoError(t, err)
	require.NotNil(t, sess)
}

// markTOTPStepErrStub wraps a real storage.Storage and overrides exactly
// MarkTOTPStepUsed to inject a fixed error -- the ANTI-REPLAY consumption
// write, reached only AFTER the TOTP code has already been found correct.
type markTOTPStepErrStub struct {
	corestorage.Storage
	err error
}

func (s *markTOTPStepErrStub) MarkTOTPStepUsed(ctx context.Context, userID uint, step int64) (bool, error) {
	if s.err != nil {
		return false, s.err
	}
	return s.Storage.MarkTOTPStepUsed(ctx, userID, step)
}

// TestVerifyMFALogin_MarkTOTPStepUsedErrorAfterMatch_StillCountsTowardLockout
// is #2888 round 2's proving test, the mirror image of the test above: N
// MarkTOTPStepUsed failures with the CORRECT code -- which, unlike
// GetMFASecret's pre-verdict failure, happen AFTER the code was confirmed
// right -- MUST still count toward the lockout exactly like a genuine wrong
// code would. The earlier version of this code path skipped
// recordFailedLogin here (the same branch GetMFASecret's genuinely-
// unevaluated case correctly skips it in), which meant a correct guess whose
// consumption write failed was strictly CHEAPER, lockout-wise, than a wrong
// one -- and, at the HTTP layer, the login-attempt rate-limit slot for this
// exact case used to be released too (same bug, same root cause), a side
// channel confirming correctness by watching when 429s start.
func TestVerifyMFALogin_MarkTOTPStepUsedErrorAfterMatch_StillCountsTowardLockout(t *testing.T) {
	t.Parallel()
	c, db, fixed := newMFATestCore(t)
	c.loginLockout = LoginLockoutPolicy{Enabled: true, MaxAttempts: 3, Window: time.Hour, BaseCooldown: 15 * time.Minute, MaxCooldown: time.Hour}
	ctx := context.Background()

	_, secret, err := c.BeginMFAEnrollment(ctx, 1)
	require.NoError(t, err)
	actCode, err := totp.GenerateCode(secret, fixed.Add(-30*time.Second))
	require.NoError(t, err)
	_, err = c.ActivateMFA(ctx, 1, actCode, mfaTestPassword, "")
	require.NoError(t, err)

	good, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)

	realStorage := c.storage
	faultErr := errors.New("fault-fuzz injected failure")
	c.storage = &markTOTPStepErrStub{Storage: realStorage, err: faultErr}

	// MaxAttempts (3) attempts with the CORRECT code -- it matches every time
	// (never actually consumed, since MarkTOTPStepUsed never succeeds), but
	// the write failure must still be treated as costing the account exactly
	// what a confirmed wrong code would.
	for i := 0; i < 3; i++ {
		ch, cerr := c.CreateMFAChallenge(ctx, 1)
		require.NoError(t, cerr)
		_, _, _, verr := c.VerifyMFALogin(ctx, ch, good, "ua", "9.9.9.9")
		require.Error(t, verr, "attempt %d: a post-match storage error must still refuse the login", i)
	}

	var afterFaults models.User
	require.NoError(t, db.First(&afterFaults, 1).Error)
	assert.NotNil(t, afterFaults.LoginLockedUntil,
		"account MUST be locked after MaxAttempts correct-but-write-failed attempts -- a correct guess must never be cheaper, lockout-wise, than a wrong one")

	// Still audited distinctly (mfa.error, never mfa.failed) despite counting
	// toward the lockout -- an operator must be able to tell this apart from a
	// genuine wrong-code streak even though the account pays the same price.
	var failedCount, errorCount int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ? AND user_id = ?", "mfa.failed", uint(1)).Count(&failedCount).Error)
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ? AND user_id = ?", "mfa.error", uint(1)).Count(&errorCount).Error)
	assert.Zero(t, failedCount, "a post-match storage-error attempt must be audited as mfa.error, not mfa.failed")
	assert.EqualValues(t, 3, errorCount, "each post-match storage-error attempt must still be audited distinctly")
}
