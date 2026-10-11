// pre_verdict_storage_error_labelling_test.go — the still-needed half of #2846
// (#2744, #2745, #2746), ported onto the #2888/#2894/#2936 rules.
//
// A storage failure BEFORE any credential was checked is not a failed login:
// it is audited as an error event and does not keep the per-IP slot. The
// client response stays exactly what it is today, so these tests also pin the
// halves that must NOT change: an absent account stays indistinguishable from
// a wrong password, an attacker-supplied passkey handle naming no user stays a
// failed attempt, a confirmed TOTP replay stays mfa.failed, and the messages a
// caller sees are byte-for-byte the old ones.
package core

import (
	"context"
	"errors"
	"testing"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

var errPreVerdictStorageDown = errors.New("pq: connection reset by peer")

func auditCount(t *testing.T, db *gorm.DB, eventType string) int64 {
	t.Helper()
	var n int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", eventType).Count(&n).Error)
	return n
}

// markStepUsedFaultStub overrides exactly MarkTOTPStepUsed: err makes it a
// storage failure, replay makes it a confirmed "step already used".
type markStepUsedFaultStub struct {
	corestorage.Storage
	err    error
	replay bool
}

func (s *markStepUsedFaultStub) MarkTOTPStepUsed(ctx context.Context, userID uint, step int64) (bool, error) {
	if s.err != nil {
		return false, s.err
	}
	if s.replay {
		return false, nil
	}
	return s.Storage.MarkTOTPStepUsed(ctx, userID, step)
}

// TestActivateMFA_StorageErrorAuditsMFAError is item 3 (#2744).
func TestActivateMFA_StorageErrorAuditsMFAError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("a storage error audits mfa.error, never mfa.failed, and answers exactly like a wrong code", func(t *testing.T) {
		c, db, fixed := newMFATestCore(t)
		_, secret, err := c.BeginMFAEnrollment(ctx, 1)
		require.NoError(t, err)
		code, err := totp.GenerateCode(secret, fixed)
		require.NoError(t, err)

		real := c.storage
		c.storage = &markStepUsedFaultStub{Storage: real, err: errPreVerdictStorageDown}
		_, err = c.ActivateMFA(ctx, 1, code, mfaTestPassword, "")
		require.Error(t, err)
		assert.EqualError(t, err, "invalid code", "the caller-visible error must stay the wrong-code one")

		assert.EqualValues(t, 1, auditCount(t, db, "mfa.error"), "the storage error must be audited as mfa.error")
		assert.Zero(t, auditCount(t, db, "mfa.failed"), "and never as mfa.failed (#2744)")

		// The step was never marked, so the same correct code still works.
		c.storage = real
		_, err = c.ActivateMFA(ctx, 1, code, mfaTestPassword, "")
		require.NoError(t, err, "the same correct code must still activate once storage recovers")
	})

	t.Run("a confirmed replay still audits mfa.failed", func(t *testing.T) {
		c, db, fixed := newMFATestCore(t)
		_, secret, err := c.BeginMFAEnrollment(ctx, 1)
		require.NoError(t, err)
		code, err := totp.GenerateCode(secret, fixed)
		require.NoError(t, err)

		c.storage = &markStepUsedFaultStub{Storage: c.storage, replay: true}
		_, err = c.ActivateMFA(ctx, 1, code, mfaTestPassword, "")
		require.EqualError(t, err, "invalid code")
		assert.EqualValues(t, 1, auditCount(t, db, "mfa.failed"), "a replay IS a failed attempt")
		assert.Zero(t, auditCount(t, db, "mfa.error"))
	})
}

// usernameLookupFaultStub overrides exactly GetUserByUsername.
type usernameLookupFaultStub struct {
	corestorage.Storage
	err error
}

func (s *usernameLookupFaultStub) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.Storage.GetUserByUsername(ctx, username)
}

// TestVerifyPasswordCredentials_UsernameLookupStorageErrorIsNotEvaluated is
// item 1's core half (#2745).
func TestVerifyPasswordCredentials_UsernameLookupStorageErrorIsNotEvaluated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("a storage error is not-evaluated, with the same text", func(t *testing.T) {
		c, _, _ := newMFATestCore(t)
		c.storage = &usernameLookupFaultStub{Storage: c.storage, err: errPreVerdictStorageDown}
		_, err := c.VerifyPasswordCredentials(ctx, "alice", mfaTestPassword)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrLoginNotEvaluated)
		assert.NotErrorIs(t, err, errPreVerdictStorageDown, "driver text must not travel towards an unauthenticated caller")
		assert.EqualError(t, err, "invalid credentials", "the error text a transport might render is unchanged")
	})

	t.Run("no such user stays an ordinary invalid-credentials result", func(t *testing.T) {
		c, _, _ := newMFATestCore(t)
		_, err := c.VerifyPasswordCredentials(ctx, "nobody-at-all", mfaTestPassword)
		require.EqualError(t, err, "invalid credentials")
		assert.NotErrorIs(t, err, ErrLoginNotEvaluated,
			"an absent account must not be distinguishable from a wrong password (anti-enumeration)")
	})

	t.Run("a wrong password for a real account is the same class as no such user", func(t *testing.T) {
		c, _, _ := newMFATestCore(t)
		_, err := c.VerifyPasswordCredentials(ctx, "alice", "not-the-password")
		require.EqualError(t, err, "invalid credentials")
		assert.NotErrorIs(t, err, ErrLoginNotEvaluated)
	})
}

// userReadFaultStub overrides exactly GetUser, which loadWebAuthnUser reads first.
type userReadFaultStub struct {
	corestorage.Storage
	err error
}

func (s *userReadFaultStub) GetUser(ctx context.Context, id uint) (*models.User, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.Storage.GetUser(ctx, id)
}

// TestLoadWebAuthnUser_PreservesNotFoundVsStorageError is item 2's enabling
// half (#2746): the class is preserved, the message is not changed (callers
// such as BeginWebAuthnLogin render "user not found" to the client today).
func TestLoadWebAuthnUser_PreservesNotFoundVsStorageError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("a storage error does not masquerade as not-found", func(t *testing.T) {
		c, _, _ := newMFATestCore(t)
		c.storage = &userReadFaultStub{Storage: c.storage, err: errPreVerdictStorageDown}
		_, err := c.loadWebAuthnUser(ctx, 1)
		require.Error(t, err)
		assert.False(t, corestorage.IsUserNotFound(err))
		assert.EqualError(t, err, "user not found", "the client-visible text is unchanged")
	})

	t.Run("a genuinely absent user stays not-found", func(t *testing.T) {
		c, _, _ := newMFATestCore(t)
		_, err := c.loadWebAuthnUser(ctx, 9999)
		require.Error(t, err)
		assert.True(t, corestorage.IsUserNotFound(err))
		assert.EqualError(t, err, "user not found")
	})
}
