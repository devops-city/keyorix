// require_reauth_storage_error_test.go — FIX-1 sibling of #2548 found during
// the session's sibling sweep: requireReauth (internal/core/mfa.go) is the
// gate behind DisableMFA/ActivateMFA/RegenerateMFARecoveryCodes/account email
// change/WebAuthn register+delete. Like VerifyMFACredentials before PR #2398
// and VerifyMFAStepUp before this session's own fix, it collapsed a storage
// read failure (GetMFASecret/MarkTOTPStepUsed/ConsumeMFAStepUpGrant) into the
// exact same "invalid code or password" result a genuinely wrong credential
// produces -- audited as mfa.failed and counted toward the account lockout,
// for a credential that was never actually checked.
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

// TestRequireReauth_GetMFASecretErrorDoesNotFeedLockout: N GetMFASecret
// failures (N > the lockout's MaxAttempts) with the CORRECT TOTP code, via
// DisableMFA (a direct requireReauth caller), must leave the account
// unlocked and must not report "invalid code or password" -- a storage read
// failure is not a confirmed wrong credential. Once the fault clears, the
// SAME correct code must still succeed.
func TestRequireReauth_GetMFASecretErrorDoesNotFeedLockout(t *testing.T) {
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
	// GetMFASecret errors every time -- more than MaxAttempts (3), so if this
	// were (wrongly) counted toward the lockout, the account would now be locked.
	for i := 0; i < 5; i++ {
		derr := c.DisableMFA(ctx, 1, good, "")
		require.Error(t, derr, "attempt %d: a storage error must still refuse the reauth", i)
		assert.NotContains(t, derr.Error(), "invalid code or password",
			"attempt %d: a storage error must not be reported as a wrong credential", i)
	}

	var afterFaults models.User
	require.NoError(t, db.First(&afterFaults, 1).Error)
	assert.Nil(t, afterFaults.LoginLockedUntil,
		"account must NOT be locked -- none of the 5 storage-error attempts was a confirmed wrong credential")
	assert.True(t, afterFaults.MFAEnabled, "MFA must still be enabled -- the disable never actually succeeded")

	var failedCount, errorCount int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ? AND user_id = ?", "mfa.failed", uint(1)).Count(&failedCount).Error)
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ? AND user_id = ?", "mfa.error", uint(1)).Count(&errorCount).Error)
	assert.Zero(t, failedCount, "a storage-error attempt must not be audited as a failed (wrong-credential) reauth")
	assert.EqualValues(t, 5, errorCount, "each storage-error attempt must be audited distinctly as an error")

	// Fault clears: the SAME correct code (never consumed -- MarkTOTPStepUsed
	// was never reached while GetMFASecret kept failing) now succeeds.
	c.storage = realStorage
	require.NoError(t, c.DisableMFA(ctx, 1, good, ""))
	var afterSuccess models.User
	require.NoError(t, db.First(&afterSuccess, 1).Error)
	assert.False(t, afterSuccess.MFAEnabled, "the never-actually-wrong code must still disable MFA once the fault clears")
}

// TestRequireReauth_MarkTOTPStepUsedErrorAfterMatch_StillCountsTowardLockout
// is #2888 round 2's proving test, the mirror image of the test above: N
// MarkTOTPStepUsed failures with the CORRECT TOTP code -- which, unlike
// GetMFASecret's pre-verdict failure, happens AFTER the code was confirmed
// right -- must still count toward the lockout exactly like a genuine wrong
// credential would. The pre-fix requireReauth discarded MarkTOTPStepUsed's
// error entirely for this shape (neither storageErr nor any other signal),
// so it fell through to the generic wrong-credential bucket for EXTERNAL
// purposes (same response, same lockout count) but WITHOUT any distinct
// audit trail -- an operator reviewing mfa.failed events could not tell a
// write failure apart from a real bad guess. markTOTPStepErrStub is shared
// with mfa_login_storage_error_test.go.
//
// #2894 review note — WHICH HALF OF THIS TEST IS A RED PROOF: only the audit
// half. The LoginLockedUntil assertion below is green against main too, for a
// mechanical reason worth writing down so nobody reads it as proof that it
// isn't: main discarded MarkTOTPStepUsed's error outright, so the attempt fell
// through to the generic wrong-credential arm, which already called
// recordFailedLogin. The lockout cost was therefore already correct here, and
// #2888 only gave the case its own distinct audit event. The lockout claim is
// pinned precisely — against a wrong-code CONTROL rather than a bare "is it
// locked" — by TestRequireReauth_PostVerdictFaultCostsTheSameAsAWrongCode in
// login_lockout_post_verdict_parity_test.go, which is red under the one
// regression that can now happen: the postVerdictErr arm ceasing to count.
func TestRequireReauth_MarkTOTPStepUsedErrorAfterMatch_StillCountsTowardLockout(t *testing.T) {
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
		derr := c.DisableMFA(ctx, 1, good, "")
		require.Error(t, derr, "attempt %d: a post-match storage error must still refuse the reauth", i)
	}

	var afterFaults models.User
	require.NoError(t, db.First(&afterFaults, 1).Error)
	assert.NotNil(t, afterFaults.LoginLockedUntil,
		"account MUST be locked after MaxAttempts correct-but-write-failed attempts -- a correct guess must never be cheaper, lockout-wise, than a wrong one")
	assert.True(t, afterFaults.MFAEnabled, "MFA must still be enabled -- the disable never actually succeeded")

	var failedCount, errorCount int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ? AND user_id = ?", "mfa.failed", uint(1)).Count(&failedCount).Error)
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ? AND user_id = ?", "mfa.error", uint(1)).Count(&errorCount).Error)
	assert.Zero(t, failedCount, "a post-match storage-error attempt must be audited as mfa.error, not mfa.failed")
	assert.EqualValues(t, 3, errorCount, "each post-match storage-error attempt must still be audited distinctly")
}
