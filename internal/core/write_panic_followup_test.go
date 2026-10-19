package core

// #3277 follow-up: the same rule as login_write_panic_test.go for the
// post-verdict writes outside the four login paths: the MFA step-up (the TOTP
// mark and the grant), impersonation start and setup consume. A panic must be
// refused exactly like the write's error, and a write that committed before it
// failed must leave no usable session or elevation behind.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

type grantFaultMode int

const (
	grantPanicBeforeWrite grantFaultMode = iota
	grantPanicAfterCommit
	// The grant commits and the call reports an error. With grantErrorCopy the
	// row is inserted from a copy, so the caller's grant never learns its ID:
	// a lost acknowledgement, detected by CreatedAt alone.
	grantErrorAfterCommit
	grantErrorAfterCommitCopy
	grantErrorBeforeWrite
)

type grantFaultStorage struct {
	inner corestorage.Storage
	mode  grantFaultMode
	fired bool
}

func (s *grantFaultStorage) CreateMFAStepUpGrant(next corestorage.Storage, ctx context.Context, g *models.MFAStepUpGrant) error {
	if s.fired {
		return next.CreateMFAStepUpGrant(ctx, g)
	}
	s.fired = true
	switch s.mode {
	case grantPanicBeforeWrite:
		panic("injected panic: CreateMFAStepUpGrant")
	case grantPanicAfterCommit:
		_ = next.CreateMFAStepUpGrant(ctx, g)
		panic("injected panic after commit: CreateMFAStepUpGrant")
	case grantErrorAfterCommit:
		_ = next.CreateMFAStepUpGrant(ctx, g)
	case grantErrorAfterCommitCopy:
		cp := *g
		_ = next.CreateMFAStepUpGrant(ctx, &cp)
	}
	return errors.New("injected: CreateMFAStepUpGrant")
}

// wrap returns inner decorated with grantFaultStorage's overrides.
func (s *grantFaultStorage) wrap(inner corestorage.Storage) corestorage.Storage {
	return hooked(inner, &storeHooks{
		CreateMFAStepUpGrant: s.CreateMFAStepUpGrant,
	})
}

// store returns s.inner decorated with grantFaultStorage's overrides.
func (s *grantFaultStorage) store() corestorage.Storage { return s.wrap(s.inner) }

func liveStepUpGrants(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var n int64
	require.NoError(t, db.Model(&models.MFAStepUpGrant{}).Where("consumed_at IS NULL").Count(&n).Error)
	return n
}

// TestVerifyMFAStepUp_GrantWriteFailureLeavesNoElevation: for every way the
// grant write can fail after the code matched, the step-up is refused as the
// error kind refuses it (no panic escapes, counted toward the lockout) and no
// grant from it is live afterwards.
func TestVerifyMFAStepUp_GrantWriteFailureLeavesNoElevation(t *testing.T) {
	for name, mode := range map[string]grantFaultMode{
		"panic-before-write":         grantPanicBeforeWrite,
		"panic-after-commit":         grantPanicAfterCommit,
		"error-after-commit":         grantErrorAfterCommit,
		"error-after-commit-lost-id": grantErrorAfterCommitCopy,
		"error-before-write":         grantErrorBeforeWrite,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			c, db, _, good := newActivatedMFACore(t)
			c.loginLockout = postVerdictParityPolicy
			putAtThresholdMinusOne(t, db, 1)
			base := c.storage
			st := &grantFaultStorage{inner: base, mode: mode}
			c.storage = st.store()
			var err error
			require.NotPanics(t, func() { err = c.VerifyMFAStepUp(ctx, 1, good) },
				"a grant-write panic must come back as its error, not reach the Recovery middleware")
			c.storage = base
			require.True(t, st.fired)
			require.ErrorIs(t, err, ErrLoginPostVerdict, "refused through the error kind's branch")
			assert.True(t, readLockoutState(t, db, 1).Locked, "counted like a wrong code: the account locks at threshold-1")
			assert.Zero(t, liveStepUpGrants(t, db), "a refused step-up must leave no live grant")
			if mode == grantPanicAfterCommit || mode == grantErrorAfterCommit || mode == grantErrorAfterCommitCopy {
				assert.EqualValues(t, 1, auditCount(t, db, EventUndeliveredStepUpGrantRevoked),
					"the grant that landed must be consumed and audited")
			}
		})
	}
}

// TestVerifyMFAStepUp_HonestGrantFailureKeepsAnEarlierGrant is the calibration
// for the revocation's scope: when nothing of this call landed, a live grant
// from an earlier, delivered step-up is left alone.
func TestVerifyMFAStepUp_HonestGrantFailureKeepsAnEarlierGrant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db, _, good := newActivatedMFACore(t)
	earlier := &models.MFAStepUpGrant{
		UserID: 1, Purpose: models.MFAStepUpPurposeRestrictedSecretRead,
		ExpiresAt: c.now().Add(time.Hour),
	}
	require.NoError(t, c.storage.CreateMFAStepUpGrant(ctx, earlier))
	require.NoError(t, db.Model(earlier).Update("created_at", time.Now().Add(-time.Hour)).Error)

	base := c.storage
	c.storage = (&grantFaultStorage{inner: base, mode: grantErrorBeforeWrite}).store()
	require.Error(t, c.VerifyMFAStepUp(ctx, 1, good))
	c.storage = base
	assert.EqualValues(t, 1, liveStepUpGrants(t, db), "the earlier, delivered grant must survive an honest write failure")
	assert.Zero(t, auditCount(t, db, EventUndeliveredStepUpGrantRevoked))
}

// TestVerifyMFAStepUp_MarkPanicIsDeniedLikeItsError: the anti-replay write's
// panic, before and after it committed. Refused, counted, no grant; a mark
// that committed keeps the code burned.
func TestVerifyMFAStepUp_MarkPanicIsDeniedLikeItsError(t *testing.T) {
	for _, afterCommit := range []bool{false, true} {
		t.Run(commitLabel(afterCommit), func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			c, db, _, good := newActivatedMFACore(t)
			c.loginLockout = postVerdictParityPolicy
			putAtThresholdMinusOne(t, db, 1)
			base := c.storage
			st := &panicLoginWriteStorage{inner: base, method: "MarkTOTPStepUsed", afterCommit: afterCommit}
			c.storage = st.store()
			var err error
			require.NotPanics(t, func() { err = c.VerifyMFAStepUp(ctx, 1, good) })
			c.storage = base
			require.True(t, st.fired)
			require.ErrorIs(t, err, ErrMFAVerificationStorageFailure)
			require.NotErrorIs(t, err, ErrMFAVerificationUnavailable, "the code matched: counted, not 'unavailable'")
			assert.True(t, readLockoutState(t, db, 1).Locked, "counted like a wrong code")
			assert.Zero(t, liveStepUpGrants(t, db))

			// Replay on a core with room under the lockout.
			rc, _, _, rgood := newActivatedMFACore(t)
			rbase := rc.storage
			rc.storage = (&panicLoginWriteStorage{inner: rbase, method: "MarkTOTPStepUsed", afterCommit: afterCommit}).store()
			require.NotPanics(t, func() { _ = rc.VerifyMFAStepUp(ctx, 1, rgood) })
			rc.storage = rbase
			rerr := rc.VerifyMFAStepUp(ctx, 1, rgood)
			if afterCommit {
				require.Error(t, rerr, "the mark committed before the panic: the code must stay burned")
			} else {
				require.NoError(t, rerr, "calibration: the mark never landed, so the code was never accepted")
			}
		})
	}
}

// TestStartImpersonation_SessionWritePanicIsRefusedLikeItsError: no panic
// escapes, no impersonation session survives (a row that committed is
// deleted and audited), no token is returned.
func TestStartImpersonation_SessionWritePanicIsRefusedLikeItsError(t *testing.T) {
	for _, afterCommit := range []bool{false, true} {
		t.Run(commitLabel(afterCommit), func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			c, st := newBootstrappedCore(t)
			admin, err := st.GetUserByUsername(ctx, "admin")
			require.NoError(t, err)
			target, err := c.CreateUser(ctx, &CreateUserRequest{
				Username: "imptarget", Email: "imptarget@example.com", DisplayName: "Imp Target",
				Password: "Qx#Vr9$Mn2!Zp4@Lw",
			})
			require.NoError(t, err)
			c.storage = (&panicLoginWriteStorage{inner: st, method: "CreateSession", afterCommit: afterCommit}).store()
			var session *models.Session
			require.NotPanics(t, func() { session, _, err = c.StartImpersonation(ctx, admin.ID, target.ID, "203.0.113.9") })
			c.storage = st
			require.ErrorIs(t, err, ErrLoginWritePanicked)
			assert.Nil(t, session)
			rows, lerr := st.ListSessionsByUser(ctx, target.ID)
			require.NoError(t, lerr)
			assert.Empty(t, rows, "no impersonation session may survive a refused start")
			if afterCommit {
				assert.EqualValues(t, 1, auditEventCount(t, st, EventUndeliveredSessionRevoked))
			}
		})
	}
}
