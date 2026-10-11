// mfa_challenge_consume_storage_error_test.go — VerifyMFACredentials'
// ConsumeMFAChallenge call is the EARLIEST pre-verdict position on the MFA
// login path: it runs before the submitted code has been looked at at all.
// A genuine storage failure there must therefore be tagged
// ErrMFAVerificationStorageFailure/ErrMFAVerificationUnavailable (so the HTTP
// handler releases the IP login-attempt slot it reserved and answers 503),
// while the expected negative result the same call reports for a
// missing/expired/already-consumed challenge (storage.ErrMFAChallengeInvalid)
// must keep counting against the per-IP budget exactly as before.
//
// Split out from mfa_login_storage_error_test.go deliberately: that file is
// being edited concurrently by PR #2894.
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

// consumeMFAChallengeErrStorage wraps a real storage.Storage and overrides
// exactly ConsumeMFAChallenge to inject a fixed error, mirroring
// mfaSecretReadErrStub (mfa_login_storage_error_test.go).
type consumeMFAChallengeErrStorage struct {
	corestorage.Storage
	err error
}

func (s *consumeMFAChallengeErrStorage) ConsumeMFAChallenge(ctx context.Context, tokenHash string, now time.Time) (*models.MFAChallenge, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.Storage.ConsumeMFAChallenge(ctx, tokenHash, now)
}

// TestVerifyMFACredentials_ChallengeConsumeStorageError_IsTaggedPreVerdict:
// a non-sentinel (i.e. genuine storage) failure from ConsumeMFAChallenge must
// be reported as a pre-verdict storage failure, so the caller can tell it apart
// from a stale/guessed challenge token and refrain from spending the IP's
// login-attempt budget on a request that reached no verdict.
func TestVerifyMFACredentials_ChallengeConsumeStorageError_IsTaggedPreVerdict(t *testing.T) {
	t.Parallel()
	c, _, fixed := newMFATestCore(t)
	ctx := context.Background()

	_, secret, err := c.BeginMFAEnrollment(ctx, 1)
	require.NoError(t, err)
	// Activate with the PREVIOUS step so the step at `fixed` stays fresh for the
	// login checks below (same technique as mfa_login_storage_error_test.go).
	actCode, err := totp.GenerateCode(secret, fixed.Add(-30*time.Second))
	require.NoError(t, err)
	_, err = c.ActivateMFA(ctx, 1, actCode, mfaTestPassword, "")
	require.NoError(t, err)
	good, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)

	ch, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)

	realStorage := c.storage
	c.storage = &consumeMFAChallengeErrStorage{Storage: realStorage, err: errors.New("fault-fuzz injected failure")}

	_, _, _, _, verr := c.VerifyMFACredentials(ctx, ch, good)
	require.Error(t, verr)
	assert.ErrorIs(t, verr, ErrMFAVerificationStorageFailure,
		"a genuine ConsumeMFAChallenge storage error reached no verdict on the code — it must be tagged as a storage failure so the caller releases the IP attempt slot")
	assert.ErrorIs(t, verr, ErrMFAVerificationUnavailable,
		"the fault landed BEFORE the code was evaluated, so the caller must be told to retry, not that its credential was wrong")

	// Fault clears: the same correct code still verifies — the failed attempt
	// burned neither the TOTP step nor the account.
	c.storage = realStorage
	ch2, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	user, _, _, _, err := c.VerifyMFACredentials(ctx, ch2, good)
	require.NoError(t, err)
	require.NotNil(t, user)
}

// TestVerifyMFACredentials_InvalidChallenge_IsNotTaggedStorageFailure is the
// other half, and the regression guard for the behaviour the fix must NOT
// change: a missing/expired/already-consumed challenge is a confirmed negative
// result, legitimately counted against the per-IP throttle. That is why the
// whole branch was deliberately left untagged before — tagging it wholesale
// broke FuzzLoginThrottleConcurrency's oracle (a).
func TestVerifyMFACredentials_InvalidChallenge_IsNotTaggedStorageFailure(t *testing.T) {
	t.Parallel()
	c, _, _ := newMFATestCore(t)
	ctx := context.Background()

	_, _, _, _, verr := c.VerifyMFACredentials(ctx, "no-such-challenge-token", "000000")
	require.Error(t, verr)
	assert.NotErrorIs(t, verr, ErrMFAVerificationStorageFailure,
		"a stale/guessed challenge token is a confirmed negative result, not a storage ambiguity — tagging it would hand an attacker free per-IP budget")
	assert.NotErrorIs(t, verr, ErrMFAVerificationUnavailable,
		"a stale/guessed challenge token must stay a plain refusal, not become a retry-later")
}
