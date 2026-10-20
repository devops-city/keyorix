package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// AUTH-2 item 4: VerifyMFAStepUp's refusals that core counts toward the lockout
// (a wrong code, a locked account, a post-verdict anti-replay fault) carry
// ErrReauthRejected so the transport keeps the per-IP slot; their text is
// unchanged. A refusal that evaluated nothing (MFA not enabled) does not.
func TestVerifyMFAStepUp_RejectionsCarryTheSentinel(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	c, db, fixed := newMFATestCore(t)
	err := c.VerifyMFAStepUp(ctx, 1, "000000")
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrReauthRejected), "MFA not enabled: nothing was evaluated")

	activateMFAForTest(t, c, fixed)
	err = c.VerifyMFAStepUp(ctx, 1, "000000")
	require.ErrorIs(t, err, ErrReauthRejected)
	assert.Equal(t, "invalid code", err.Error())

	until := fixed.Add(time.Hour)
	c.loginLockout = postVerdictParityPolicy
	require.NoError(t, db.Model(&models.User{}).Where("id = ?", 1).Update("login_locked_until", until).Error)
	err = c.VerifyMFAStepUp(ctx, 1, "000000")
	require.ErrorIs(t, err, ErrReauthRejected)
	assert.Equal(t, "account temporarily locked due to repeated failed logins; try again later", err.Error())
}

// The counted storage branch (the code matched, the anti-replay mark failed)
// keeps ErrMFAVerificationStorageFailure in the chain for the handler's
// wrong-code answer, and adds the sentinel.
func TestVerifyMFAStepUp_CountedStorageFaultCarriesBoth(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, _, fixed := newMFATestCore(t)
	secret, _ := activateMFAForTest(t, c, fixed)
	code, gerr := totp.GenerateCode(secret, fixed)
	require.NoError(t, gerr)
	base := c.storage
	c.storage = faultstorage.NewFaultyStorage(base, &faultstorage.FaultSpec{
		Method: "MarkTOTPStepUsed", NthCall: 1, Kind: faultstorage.KindError, Err: errors.New("injected: MarkTOTPStepUsed"),
	})
	err := c.VerifyMFAStepUp(ctx, 1, code)
	c.storage = base
	require.ErrorIs(t, err, ErrMFAVerificationStorageFailure)
	require.ErrorIs(t, err, ErrReauthRejected)
	assert.NotContains(t, err.Error(), "re-authentication rejected", "the text is the storage failure's, unchanged")
}
