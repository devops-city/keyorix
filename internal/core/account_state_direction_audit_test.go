package core

// account_state_direction_audit_test.go -- MERGE-FIX-3482F item 5 (REVIEW-3482 F5): the
// audit direction of an account-state change depends on the CURRENT state as well as
// the target. suspended -> password_reset_required targets a "restricted" state but
// lets a login-blocked user log in again, so it widens access: with the audit log
// refusing, it must fail closed (nothing changes), not commit as an owed revocation.
// active -> password_reset_required still narrows and stays owed.
//
// Red before the fix: the direction came from the target alone, so the suspended user
// below was moved to password_reset_required with the row only queued.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestAccountStateTransitionRevokes(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		from, to string
		want     bool
	}{
		{AccountActive, AccountSuspended, true},
		{AccountActive, AccountPasswordResetRequired, true},
		{AccountPendingFirstLogin, AccountPasswordResetRequired, true},
		{AccountPasswordResetRequired, AccountSuspended, true},
		{AccountSuspended, AccountSuspended, true},
		{AccountSuspended, AccountDeprovisioned, true},
		{AccountSuspended, AccountPasswordResetRequired, false}, // F5: login-blocked -> restricted widens
		{AccountDeprovisioned, AccountPasswordResetRequired, false},
		{AccountSuspended, AccountPendingFirstLogin, false},
		{"", AccountPasswordResetRequired, false}, // unreadable / unrecognised current state: the safe side
		{"no-such-state", AccountPasswordResetRequired, false},
		{AccountSuspended, AccountActive, false}, // toward active is a grant
		{AccountPasswordResetRequired, AccountActive, false},
		{"", AccountSuspended, true}, // a blocking target never widens
	} {
		assert.Equal(t, c.want, accountStateTransitionRevokes(1, c.from, c.to), "%q -> %q", c.from, c.to)
	}
}

func (w *txClosureWorld) setAccountStateRaw(t *testing.T, id uint, state string) {
	t.Helper()
	require.NoError(t, w.db.Model(&models.User{}).Where("id = ?", id).Update("account_state", state).Error)
}

func (w *txClosureWorld) accountStateOf(t *testing.T, id uint) string {
	t.Helper()
	var u models.User
	require.NoError(t, w.db.First(&u, id).Error)
	return u.AccountState
}

func TestRequirePasswordReset_AuditRefused_DirectionFollowsCurrentState(t *testing.T) {
	refuse := func(w *txClosureWorld) {
		w.fs.Arm(&faultstorage.FaultSpec{Method: "LogAuditEvent", NthCall: 1, Kind: faultstorage.KindError, Err: errors.New("audit log refused")})
	}

	t.Run("suspended user: widening, fails closed", func(t *testing.T) {
		txClosureBackends(t, func(t *testing.T, w *txClosureWorld) {
			id := w.seedDeactivationTarget(t, "f5-suspended")
			w.setAccountStateRaw(t, id, AccountSuspended)
			refuse(w)
			runWithDeadline(t, 30*time.Second, func() {
				err := w.c.RequirePasswordReset(context.Background(), 0, id)
				require.Error(t, err, "re-opening login of a suspended account needs its audit row")
			})
			require.True(t, w.fs.Fired())
			assert.Equal(t, AccountSuspended, w.accountStateOf(t, id), "nothing changed")
			assert.Zero(t, w.pendingCount(t), "no owed row: the change did not commit")
			assert.Zero(t, w.auditCount(t, "account.password_reset_required"))
		})
	})

	t.Run("active user: narrowing, owed and never blocked", func(t *testing.T) {
		txClosureBackends(t, func(t *testing.T, w *txClosureWorld) {
			id := w.seedDeactivationTarget(t, "f5-active")
			refuse(w)
			runWithDeadline(t, 30*time.Second, func() {
				require.NoError(t, w.c.RequirePasswordReset(context.Background(), 0, id))
			})
			require.True(t, w.fs.Fired())
			assert.Equal(t, AccountPasswordResetRequired, w.accountStateOf(t, id))
			assert.Equal(t, int64(1), w.pendingCount(t), "the row is owed")
		})
	})

	t.Run("suspended user, audit healthy: still allowed, row written with it", func(t *testing.T) {
		txClosureBackends(t, func(t *testing.T, w *txClosureWorld) {
			id := w.seedDeactivationTarget(t, "f5-healthy")
			w.setAccountStateRaw(t, id, AccountSuspended)
			require.NoError(t, w.c.RequirePasswordReset(context.Background(), 0, id))
			assert.Equal(t, AccountPasswordResetRequired, w.accountStateOf(t, id))
			assert.Equal(t, int64(1), w.auditCount(t, "account.password_reset_required"))
			assert.Zero(t, w.pendingCount(t))
		})
	})
}

// staleGetUserStore runs afterGetUser once, right after the first GetUser returns: the
// state the caller just read is then out of date, the way another replica's suspension
// landing between setAccountState's read and its transaction is.
func staleGetUserStore(inner storage.Storage, afterGetUser func()) storage.Storage {
	var once sync.Once
	return hooked(inner, &storeHooks{
		GetUser: func(next storage.Storage, ctx context.Context, id uint) (*models.User, error) {
			u, err := next.GetUser(ctx, id)
			once.Do(afterGetUser)
			return u, err
		},
	})
}

// An account read as active that is suspended by the time the row lock is taken is a
// widening, not a revocation: the in-transaction re-check must catch it, and the retry
// then takes the fail-closed path (audit refused -> nothing changes).
func TestRequirePasswordReset_StateChangedAfterRead_RechecksUnderLock(t *testing.T) {
	txClosureBackends(t, func(t *testing.T, w *txClosureWorld) {
		id := w.seedDeactivationTarget(t, "f5-stale")
		c := NewKeyorixCore(staleGetUserStore(w.fs, func() { w.setAccountStateRaw(t, id, AccountSuspended) }))
		w.fs.Arm(&faultstorage.FaultSpec{Method: "LogAuditEvent", NthCall: 1, Kind: faultstorage.KindError, Err: errors.New("audit log refused")})
		runWithDeadline(t, 30*time.Second, func() {
			require.Error(t, c.RequirePasswordReset(context.Background(), 0, id))
		})
		assert.Equal(t, AccountSuspended, w.accountStateOf(t, id), "nothing changed")
		assert.Zero(t, w.pendingCount(t))
	})
}
