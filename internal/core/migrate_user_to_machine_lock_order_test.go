package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMigrateUserToMachine_LockAcquisitionFailureLeavesNothingCommitted is the
// regression test for #2413 (FuzzStorageFaultOperations input decoding, on
// current main, to op="REST POST /api/v1/projects/{id}/machine-identities/migrate-from-user"
// fault=(method=WithNamedLock, NthCall=1, kind=error)): SuspendUser used to
// acquire its own lock AFTER CreateMachineIdentity had already committed, so
// a failure to even acquire that lock reported an error for an identity that,
// in fact, already existed. MigrateUserToMachine now takes the same lock
// first, so CreateMachineIdentity only runs once the lock is actually held --
// a lock-acquisition failure leaves nothing committed.
func TestMigrateUserToMachine_LockAcquisitionFailureLeavesNothingCommitted(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	proj, err := st.CreateProject(ctx, &models.Project{Name: "migrate-lock-proj", Description: "d"})
	require.NoError(t, err)
	svc, err := st.CreateUser(ctx, foldedTestUser(t, "svc-account", "svc-account@example.com"))
	require.NoError(t, err)

	faulty := faultstorage.NewFaultyStorage(st, nil)
	c.storage = faulty
	faulty.Arm(&faultstorage.FaultSpec{
		Method: "WithNamedLock", NthCall: 1, Kind: faultstorage.KindError,
		Err: assert.AnError,
	})

	m, err := c.MigrateUserToMachine(ctx, svc.Username, proj.ID, "", "", 1, 0, true)
	require.Error(t, err, "a failed lock acquisition must be reported as an error")
	assert.Nil(t, m)

	// Confirm via a fresh, unfaulted read: no machine identity was created at
	// all -- the lock is acquired BEFORE CreateMachineIdentity runs, so a
	// failure to acquire it leaves nothing committed (not a machine identity
	// with no corresponding suspension).
	identities, lerr := st.ListMachineIdentities(ctx, proj.ID)
	require.NoError(t, lerr)
	assert.Empty(t, identities, "no machine identity should exist after a failed lock acquisition")

	// And the source user must still be active -- SuspendUser's own write
	// never ran either.
	reread, rerr := st.GetUser(ctx, svc.ID)
	require.NoError(t, rerr)
	assert.Equal(t, "active", reread.AccountState)
}

// TestMigrateUserToMachine_LockAcquisitionFailureLeavesNothingCommitted_Postgres
// is the real-Postgres sibling: WithNamedLock holds a real pg_advisory_lock
// on Postgres (a no-op process mutex on SQLite), so the reentrancy and
// ordering this fix relies on deserve a real-backend check too. Skips when
// KEYORIX_TEST_PG_DSN is unset.
func TestMigrateUserToMachine_LockAcquisitionFailureLeavesNothingCommitted_Postgres(t *testing.T) {
	base := pgTestDSN(t)
	db := pgOpen(t, pgMigratedDatabaseDSN(t, base))
	st := store.NewLocalStorage(db)
	c := NewKeyorixCore(st)
	ctx := context.Background()

	proj, err := st.CreateProject(ctx, &models.Project{Name: "pg-migrate-lock-proj", Description: "d"})
	require.NoError(t, err)
	svc, err := st.CreateUser(ctx, foldedTestUser(t, "pg-svc-account", "pg-svc-account@example.com"))
	require.NoError(t, err)

	faulty := faultstorage.NewFaultyStorage(st, nil)
	c.storage = faulty
	faulty.Arm(&faultstorage.FaultSpec{
		Method: "WithNamedLock", NthCall: 1, Kind: faultstorage.KindError,
		Err: assert.AnError,
	})

	m, err := c.MigrateUserToMachine(ctx, svc.Username, proj.ID, "", "", 1, 0, true)
	require.Error(t, err)
	assert.Nil(t, m)

	identities, lerr := st.ListMachineIdentities(ctx, proj.ID)
	require.NoError(t, lerr)
	assert.Empty(t, identities, "no machine identity should exist after a failed lock acquisition (Postgres)")

	reread, rerr := st.GetUser(ctx, svc.ID)
	require.NoError(t, rerr)
	assert.Equal(t, "active", reread.AccountState)
}
