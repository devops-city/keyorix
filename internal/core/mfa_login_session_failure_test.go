// mfa_login_session_failure_test.go — #2567: VerifyMFACredentials calls
// storage.MarkTOTPStepUsed (consuming the TOTP step, anti-replay) BEFORE
// VerifyMFALogin's own, independent mintSession/CreateSession call. If
// CreateSession fails, the whole verify is reported as an error, but the
// TOTP step was already consumed — the caller cannot retry with the SAME
// correct code; they had to wait for the next 30s time-step, for a storage
// hiccup that had nothing to do with the code they entered. Fixed by
// releasing the just-marked step (CAS-guarded) when mintSession fails.
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

// createSessionErrStub wraps a real storage.Storage, injecting a one-shot
// CreateSession failure and then behaving normally — mirrors
// mfaSecretReadErrStub's pattern (mfa_login_storage_error_test.go).
type createSessionErrStub struct {
	inner    corestorage.Storage
	failNext bool
	err      error
}

func (s *createSessionErrStub) CreateSession(next corestorage.Storage, ctx context.Context, sess *models.Session) (*models.Session, error) {
	if s.failNext {
		s.failNext = false
		return nil, s.err
	}
	return next.CreateSession(ctx, sess)
}

// wrap returns inner decorated with createSessionErrStub's overrides.
func (s *createSessionErrStub) wrap(inner corestorage.Storage) corestorage.Storage {
	return hooked(inner, &storeHooks{
		CreateSession: s.CreateSession,
	})
}

// store returns s.inner decorated with createSessionErrStub's overrides.
func (s *createSessionErrStub) store() corestorage.Storage { return s.wrap(s.inner) }

// TestVerifyMFALogin_CreateSessionFailure_ReleasesTOTPStepForRetry is the
// RED/GREEN regression for #2567: a CreateSession failure right after a
// correct TOTP code was consumed must let the SAME code be retried once the
// storage hiccup clears, instead of burning the code for nothing.
func TestVerifyMFALogin_CreateSessionFailure_ReleasesTOTPStepForRetry(t *testing.T) {
	t.Parallel()
	c, _, fixed := newMFATestCore(t)
	ctx := context.Background()

	_, secret, err := c.BeginMFAEnrollment(ctx, 1)
	require.NoError(t, err)
	actCode, err := totp.GenerateCode(secret, fixed.Add(-30*time.Second))
	require.NoError(t, err)
	_, err = c.ActivateMFA(ctx, 1, actCode, mfaTestPassword, "")
	require.NoError(t, err)

	good, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)

	faultErr := errors.New("fault-fuzz injected CreateSession failure")
	stub := &createSessionErrStub{inner: c.storage, failNext: true, err: faultErr}
	c.storage = stub.store()

	ch, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	sess, _, _, verr := c.VerifyMFALogin(ctx, ch, good, "ua", "9.9.9.9")
	require.Error(t, verr, "a CreateSession failure must still refuse this login attempt")
	require.Nil(t, sess)
	require.False(t, stub.failNext, "the fault must actually have fired")

	// Fault clears: a fresh challenge with the SAME code (never actually
	// accepted — no session was minted) must now succeed.
	ch2, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	sess2, user, _, err := c.VerifyMFALogin(ctx, ch2, good, "ua", "9.9.9.9")
	require.NoError(t, err, "the same code must be usable again once the storage hiccup clears")
	require.NotNil(t, sess2)
	assert.Equal(t, uint(1), user.ID)
}

// TestVerifyMFALogin_CreateSessionFailure_StepStaysConsumedIfRaced guards the
// CAS-release's own safety property: if, between the failed mintSession and
// the release, some OTHER request has already legitimately advanced the
// user's last_used_step past the step this release would otherwise revert,
// the release must be a no-op — never regress anti-replay for a step a later
// request already consumed. Simulated directly against storage rather than a
// real race, since the release call itself is what's under test.
func TestVerifyMFALogin_CreateSessionFailure_StepStaysConsumedIfRaced(t *testing.T) {
	t.Parallel()
	c, _, fixed := newMFATestCore(t)
	ctx := context.Background()

	_, secret, err := c.BeginMFAEnrollment(ctx, 1)
	require.NoError(t, err)
	actCode, err := totp.GenerateCode(secret, fixed.Add(-30*time.Second))
	require.NoError(t, err)
	_, err = c.ActivateMFA(ctx, 1, actCode, mfaTestPassword, "")
	require.NoError(t, err)

	step := fixed.Unix() / totpPeriod
	// Simulate a LATER request having already advanced the stored step past
	// the one this release call is trying to undo.
	fresh, err := c.storage.MarkTOTPStepUsed(ctx, 1, step+1)
	require.NoError(t, err)
	require.True(t, fresh)

	released, err := c.storage.ReleaseTOTPStepIfUnchanged(ctx, 1, step)
	require.NoError(t, err)
	assert.False(t, released, "must not release when the stored step no longer matches (CAS guard)")

	// The later-advanced step is unaffected.
	again, err := c.storage.MarkTOTPStepUsed(ctx, 1, step+1)
	require.NoError(t, err)
	assert.False(t, again, "the later step must still read as consumed — the CAS-guarded release must not have touched it")
}
