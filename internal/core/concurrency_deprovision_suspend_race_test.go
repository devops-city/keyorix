package core_test

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// TestConcurrency_DeprovisionSCIMUser_DoesNotRevertConcurrentSuspend is the regression
// for the residual stale-struct-overwrite bug in DeprovisionSCIMUser (SCIM DELETE):
// unlike scimUpdateUserTx/setAccountState — which both re-read the row via
// LockUserForUpdate INSIDE the critical section, immediately before the write — this
// function used to capture its working copy via a plain, UNLOCKED c.storage.GetUser
// call BEFORE acquiring accountStateMu (the #G03 fix), then reused that same
// now-possibly-stale struct for its final tx.UpdateUser call after the lock. A
// concurrent SuspendUser call (setAccountState) that committed its own account_state
// write in the window between that initial unlocked read and DeprovisionSCIMUser's
// later locked write got silently reverted back to AccountDeprovisioned by
// DeprovisionSCIMUser's blind write of the stale struct — with SuspendUser itself
// reporting success and no error surfaced to either caller.
//
// Mirrors TestConcurrency_SuspendUser_SurvivesConcurrentSCIMResync's rigor (many
// distinct users, each with its own SuspendUser/DeprovisionSCIMUser pair, ALL released
// from a single start barrier at once on a real, file-backed SQLite DB) for this
// narrower shape of the same #344 race family — narrower because DeprovisionSCIMUser
// always ends by soft-deleting the row regardless of who "wins", so the row must be
// read via Unscoped() to observe the persisted account_state afterward, and a
// SuspendUser call that lost the race outright (the row was already gone by the time
// it tried to lock it) is excluded from the assertion — that ordering is a clean
// "too late" error, not silent corruption.
func TestConcurrency_DeprovisionSCIMUser_DoesNotRevertConcurrentSuspend(t *testing.T) {
	t.Parallel()
	dsn := "file:" + filepath.Join(t.TempDir(), "deprovision_suspend_race.db") + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Session{}, &models.AuditEvent{}, &models.PersonalAccessToken{},
		&models.Role{}, &models.UserRole{}, &models.Project{}, &models.Environment{},
		// Group/UserGroup/GroupRole are needed by guardLastAdminDeactivation (#G02),
		// which both SuspendUser and DeprovisionSCIMUser call.
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{},
	))

	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	ctx := context.Background()

	const users = 200 // many concurrent (suspend, SCIM-deprovision) pairs racing at once
	for i := range users {
		require.NoError(t, db.Create(&models.User{
			ID: uint(i + 1), Username: fmt.Sprintf("user%d", i), Email: fmt.Sprintf("user%d@x.io", i),
			IsActive: true, AccountState: core.AccountActive, ExternalID: fmt.Sprintf("okta|user%d", i),
		}).Error)
	}

	suspendErrs := make([]error, users)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range users {
		uid := uint(i + 1)
		idx := i
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			suspendErrs[idx] = c.SuspendUser(ctx, 99, uid) // admin incident response
		}()
		go func() {
			defer wg.Done()
			<-start
			_ = c.DeprovisionSCIMUser(ctx, 2, uid) // routine IdP DELETE
		}()
	}
	close(start) // release every pair at once
	wg.Wait()

	var reverted []uint
	for i := range users {
		uid := uint(i + 1)
		if suspendErrs[i] != nil {
			// SuspendUser lost the race outright — the row was already soft-deleted
			// before it could even lock it. A clean "too late" error, not the bug
			// this test targets.
			continue
		}
		var got models.User
		// Unscoped: DeprovisionSCIMUser soft-deletes the row regardless of outcome,
		// but the persisted account_state must still reflect the successful suspend.
		require.NoError(t, db.Unscoped().First(&got, uid).Error)
		if got.AccountState != core.AccountSuspended {
			reverted = append(reverted, uid)
		}
	}
	assert.Empty(t, reverted,
		"SuspendUser reported success but a concurrent DeprovisionSCIMUser silently reverted "+
			"the suspension back to deprovisioned for these users: %v", reverted)
}
