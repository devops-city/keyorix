// mfa_stepup_storage_error_test.go — FIX-1 sibling of
// mfa_login_storage_error_test.go (#2548): verifyMFAStepUpCode used to return
// a bare bool, collapsing a storage-read failure into the same "invalid code"
// result a genuinely wrong code produces. VerifyMFAStepUp then audited it as
// mfa.failed and counted it toward the account lockout, for a code that was
// never actually checked. Found during the FIX-1 sweep for siblings of
// #2548's TOTP-login fix — the login path (VerifyMFACredentials) was fixed by
// PR #2398, but this explicit step-up path (VerifyMFAStepUp) was not.
package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVerifyMFAStepUp_GetMFASecretErrorDoesNotFeedLockout: N GetMFASecret
// failures (N > the lockout's MaxAttempts) with the CORRECT code must leave
// the account unlocked and must not report "invalid code" — a storage read
// failure is not a confirmed wrong code. Once the fault clears, the SAME
// correct code must still verify (and create the step-up grant).
func TestVerifyMFAStepUp_GetMFASecretErrorDoesNotFeedLockout(t *testing.T) {
	t.Parallel()
	c, db, fixed := newMFATestCore(t)
	c.loginLockout = LoginLockoutPolicy{Enabled: true, MaxAttempts: 3, Window: time.Hour, BaseCooldown: 15 * time.Minute, MaxCooldown: time.Hour}
	ctx := context.Background()

	secret, _ := activateMFAForTest(t, c, fixed)
	good, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)

	realStorage := c.storage
	faultErr := errors.New("fault-fuzz injected failure")
	c.storage = &mfaSecretReadErrStub{Storage: realStorage, err: faultErr}

	// 5 attempts with the CORRECT code, each failing to even check it because
	// GetMFASecret errors every time — more than MaxAttempts (3), so if this
	// were (wrongly) counted toward the lockout, the account would now be locked.
	for i := 0; i < 5; i++ {
		verr := c.VerifyMFAStepUp(ctx, 1, good)
		require.Error(t, verr, "attempt %d: a storage error must still refuse the step-up", i)
		assert.NotContains(t, verr.Error(), "invalid code",
			"attempt %d: a storage error must not be reported as a wrong code", i)
	}

	var afterFaults models.User
	require.NoError(t, db.First(&afterFaults, 1).Error)
	assert.Nil(t, afterFaults.LoginLockedUntil,
		"account must NOT be locked — none of the 5 storage-error attempts was a confirmed wrong code")

	var grantCount int64
	require.NoError(t, db.Model(&models.MFAStepUpGrant{}).Where("user_id = ?", 1).Count(&grantCount).Error)
	assert.Zero(t, grantCount, "no grant must be created while the code was never actually evaluated")

	// Only mfa.error events, never mfa.failed, for the 5 faulted attempts.
	var failedCount, errorCount int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ? AND user_id = ?", "mfa.failed", uint(1)).Count(&failedCount).Error)
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ? AND user_id = ?", "mfa.error", uint(1)).Count(&errorCount).Error)
	assert.Zero(t, failedCount, "a storage-error attempt must not be audited as a failed (wrong-code) MFA attempt")
	assert.EqualValues(t, 5, errorCount, "each storage-error attempt must be audited distinctly as an error")

	// Fault clears: the SAME correct code (never consumed — MarkTOTPStepUsed was
	// never reached while GetMFASecret kept failing) now verifies successfully.
	c.storage = realStorage
	require.NoError(t, c.VerifyMFAStepUp(ctx, 1, good))
	require.NoError(t, db.Model(&models.MFAStepUpGrant{}).Where("user_id = ?", 1).Count(&grantCount).Error)
	assert.EqualValues(t, 1, grantCount, "the never-actually-wrong code must still create the grant once the fault clears")
}

// TestVerifyMFAStepUp_MarkTOTPStepUsedErrorAfterMatch_StillCountsTowardLockout
// is #2888 round 2's proving test, the mirror image of the test above: N
// MarkTOTPStepUsed failures with the CORRECT code -- unlike GetMFASecret's
// pre-verdict failure, this happens AFTER the code was confirmed right --
// must still count toward the lockout exactly like a genuine wrong code
// would. markTOTPStepErrStub is shared with mfa_login_storage_error_test.go.
func TestVerifyMFAStepUp_MarkTOTPStepUsedErrorAfterMatch_StillCountsTowardLockout(t *testing.T) {
	t.Parallel()
	c, db, fixed := newMFATestCore(t)
	c.loginLockout = LoginLockoutPolicy{Enabled: true, MaxAttempts: 3, Window: time.Hour, BaseCooldown: 15 * time.Minute, MaxCooldown: time.Hour}
	ctx := context.Background()

	secret, _ := activateMFAForTest(t, c, fixed)
	good, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)

	realStorage := c.storage
	faultErr := errors.New("fault-fuzz injected failure")
	c.storage = &markTOTPStepErrStub{Storage: realStorage, err: faultErr}

	for i := 0; i < 3; i++ {
		verr := c.VerifyMFAStepUp(ctx, 1, good)
		require.Error(t, verr, "attempt %d: a post-match storage error must still refuse the step-up", i)
	}

	var afterFaults models.User
	require.NoError(t, db.First(&afterFaults, 1).Error)
	assert.NotNil(t, afterFaults.LoginLockedUntil,
		"account MUST be locked after MaxAttempts correct-but-write-failed attempts -- a correct guess must never be cheaper, lockout-wise, than a wrong one")

	var grantCount int64
	require.NoError(t, db.Model(&models.MFAStepUpGrant{}).Where("user_id = ?", 1).Count(&grantCount).Error)
	assert.Zero(t, grantCount, "no grant must be created while the consumption write kept failing")

	var failedCount, errorCount int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ? AND user_id = ?", "mfa.failed", uint(1)).Count(&failedCount).Error)
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ? AND user_id = ?", "mfa.error", uint(1)).Count(&errorCount).Error)
	assert.Zero(t, failedCount, "a post-match storage-error attempt must be audited as mfa.error, not mfa.failed")
	assert.EqualValues(t, 3, errorCount, "each post-match storage-error attempt must still be audited distinctly")
}
