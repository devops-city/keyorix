package core

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// swapOnMarkStepStorage runs onMark once, immediately before ActivateMFA's
// MarkTOTPStepUsed, i.e. after the code was validated against the pending
// secret and before the activating write.
type swapOnMarkStepStorage struct {
	inner  storage.Storage
	once   sync.Once
	onMark func()
}

func (s *swapOnMarkStepStorage) MarkTOTPStepUsed(next storage.Storage, ctx context.Context, userID uint, step int64) (bool, error) {
	s.once.Do(s.onMark)
	return next.MarkTOTPStepUsed(ctx, userID, step)
}

// wrap returns inner decorated with swapOnMarkStepStorage's overrides.
func (s *swapOnMarkStepStorage) wrap(inner storage.Storage) storage.Storage {
	return hooked(inner, &storeHooks{
		MarkTOTPStepUsed: s.MarkTOTPStepUsed,
	})
}

// store returns s.inner decorated with swapOnMarkStepStorage's overrides.
func (s *swapOnMarkStepStorage) store() storage.Storage { return s.wrap(s.inner) }

// TestActivateMFA_SecretSwappedAfterValidation_FailsClosed is the default-CI
// (SQLite) form of #2655's Postgres repro: a re-enrolment that replaces the
// pending TOTP secret after ActivateMFA validated the code must not be
// activated. ActivateMFASecret's WHERE pins the validated ciphertext, so the
// activation matches zero rows and the whole transaction rolls back.
func TestActivateMFA_SecretSwappedAfterValidation_FailsClosed(t *testing.T) {
	t.Parallel()
	c, _, fixed := newMFATestCore(t)
	ctx := context.Background()
	_, s1, err := c.BeginMFAEnrollment(ctx, 1)
	require.NoError(t, err)
	code, err := totp.GenerateCode(s1, fixed.Add(-30*time.Second))
	require.NoError(t, err)

	base := c.storage
	c.storage = (&swapOnMarkStepStorage{inner: base, onMark: func() {
		c.storage = base // BeginMFAEnrollment below must not re-enter the hook
		_, _, berr := c.BeginMFAEnrollment(ctx, 1)
		require.NoError(t, berr)
	}}).store()
	_, err = c.ActivateMFA(ctx, 1, code, mfaTestPassword, "")
	c.storage = base
	assertActivationNeverBindsUnvalidatedSecret(t, c, 1, s1, err)
}

// TestActivateMFA_UnchangedSecret_StillActivates is the green side: with no
// concurrent re-enrolment the pinned write matches and activation succeeds.
func TestActivateMFA_UnchangedSecret_StillActivates(t *testing.T) {
	t.Parallel()
	c, _, fixed := newMFATestCore(t)
	ctx := context.Background()
	_, s1, err := c.BeginMFAEnrollment(ctx, 1)
	require.NoError(t, err)
	code, err := totp.GenerateCode(s1, fixed.Add(-30*time.Second))
	require.NoError(t, err)
	codes, err := c.ActivateMFA(ctx, 1, code, mfaTestPassword, "")
	require.NoError(t, err)
	require.NotEmpty(t, codes)
	row, err := c.storage.GetMFASecret(ctx, 1)
	require.NoError(t, err)
	require.True(t, row.Activated)
}
