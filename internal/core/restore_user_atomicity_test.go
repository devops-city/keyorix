package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failOnceUpdateUserStorage makes RestoreUser's LAST write (SetAccountState,
// after the undelete and the is_active write already ran in the transaction)
// fail once, mirroring the failOnceStorage idiom from #2295. It used to fail
// the full-row UpdateUser, which RestoreUser no longer calls (#2677 sweep).
type failOnceUpdateUserStorage struct {
	storage.Storage
	armed *bool
}

func (s *failOnceUpdateUserStorage) WithTransaction(ctx context.Context, fn func(storage.Storage) error) error {
	return s.Storage.WithTransaction(ctx, func(tx storage.Storage) error {
		return fn(&failOnceUpdateUserStorage{Storage: tx, armed: s.armed})
	})
}

func (s *failOnceUpdateUserStorage) SetAccountState(ctx context.Context, id uint, state string, updatedAt time.Time) error {
	if *s.armed {
		*s.armed = false
		return errors.New("injected fault: SetAccountState")
	}
	return s.Storage.SetAccountState(ctx, id, state, updatedAt)
}

// TestRestoreUser_UpdateFailureRollsBackUndelete is the red-proof for Session
// O's O3 RestoreUser fix: a failure setting IsActive/AccountState after the
// undelete must roll back the undelete too -- not the pre-fix behavior where
// the user was left visible in listings again (deleted_at cleared) but in a
// stale/inconsistent state, with the caller's error suggesting nothing
// happened.
func TestRestoreUser_UpdateFailureRollsBackUndelete(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	u, err := st.CreateUser(ctx, foldedTestUser(t, "deleted-user", "deleted-user@example.com"))
	require.NoError(t, err)
	require.NoError(t, c.DeleteUser(ctx, 1, u.ID))

	armed := true
	c.storage = &failOnceUpdateUserStorage{Storage: st, armed: &armed}

	err = c.RestoreUser(ctx, 1, u.ID)
	require.Error(t, err)
	require.False(t, armed, "the injected fault must actually have fired")

	// The user must still read as deleted -- the undelete must not have landed.
	_, gerr := st.GetUser(ctx, u.ID)
	assert.Error(t, gerr, "a failed IsActive/AccountState update must roll back the undelete too -- the user must still be soft-deleted")

	// Retry (fault disarmed) must fully succeed.
	require.NoError(t, c.RestoreUser(ctx, 1, u.ID))
	restored, gerr := st.GetUser(ctx, u.ID)
	require.NoError(t, gerr)
	assert.True(t, restored.IsActive)
	assert.Equal(t, AccountPasswordResetRequired, restored.AccountState)
}
