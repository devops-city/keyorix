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

// TestConcurrency_SuspendUser_SurvivesConcurrentSCIMResync is the #344 regression: an
// admin's incident-response SuspendUser and a routine SCIM/IdP resync's UpdateSCIMUser
// (active=true — the ordinary "this user is still active in the directory" payload,
// not even an attack) racing for the SAME user. Both used to be a plain
// read-modify-full-row-Save with no transaction, row lock, or mutex: the SCIM call's
// GetUser could read the row before the suspend committed, and if its Save then landed
// AFTER the suspend's, the suspension was silently reverted back to active, with no
// error to either caller and no audit signal distinguishing "still suspended" from
// "un-suspended by a race".
//
// Mirrors TestConcurrency_SetupLinkResendThrottle's / TestConcurrency_
// UpdateSCIMUser_NoDuplicateEmail's rigor for the analogous cross-call races those
// regressions cover: many distinct users, each with its own SuspendUser/UpdateSCIMUser
// pair, ALL released from a single start barrier at once — maximizing genuine
// goroutine-scheduling contention on the shared, real, file-backed SQLite DB, so the
// interleaving that the #344 finding describes actually has a chance to occur (a
// single isolated pair rarely races on a mostly-idle machine; hundreds racing at once
// reliably do). Before accountStateMu + LockUserForUpdate, a meaningful fraction of
// users end up silently reactivated by the race; with the fix, the admin suspension
// wins every single trial, regardless of which call's read happened to observe the
// stale state first.
func TestConcurrency_SuspendUser_SurvivesConcurrentSCIMResync(t *testing.T) {
	t.Parallel()
	dsn := "file:" + filepath.Join(t.TempDir(), "suspend_scim_race.db") + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Session{}, &models.AuditEvent{}, &models.PersonalAccessToken{},
		&models.Role{}, &models.UserRole{}, &models.Project{}, &models.Environment{},
		// Group/UserGroup/GroupRole are needed by guardLastAdminDeactivation
		// (#G02), which SuspendUser now calls.
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{},
	))

	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	ctx := context.Background()

	const users = 200 // many concurrent (suspend, SCIM-resync) pairs racing at once
	for i := range users {
		require.NoError(t, db.Create(&models.User{
			ID: uint(i + 1), Username: fmt.Sprintf("user%d", i), Email: fmt.Sprintf("user%d@x.io", i),
			IsActive: true, AccountState: core.AccountActive,
		}).Error)
	}

	yes := true
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range users {
		uid := uint(i + 1)
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_ = c.SuspendUser(ctx, 99, uid) // admin incident response
		}()
		go func() {
			defer wg.Done()
			<-start
			_, _ = c.UpdateSCIMUser(ctx, 2, uid, nil, nil, &yes) // routine IdP resync
		}()
	}
	close(start) // release every pair at once
	wg.Wait()

	var reverted []uint
	for i := range users {
		uid := uint(i + 1)
		var got models.User
		require.NoError(t, db.First(&got, uid).Error)
		if got.AccountState != core.AccountSuspended {
			reverted = append(reverted, uid)
		}
	}
	assert.Empty(t, reverted,
		"an admin suspension must survive a concurrent SCIM resync regardless of interleaving; "+
			"these users were silently un-suspended by the race: %v", reverted)
}

// TestConcurrency_SuspendUser_SurvivesConcurrentSCIMDeactivateReactivate is the same
// #344 race, but against UpdateSCIMUser's deactivate→reactivate path (active=false then
// active=true) instead of a single active=true resync — the other call shape
// setAccountState races against per the backlog finding. setAccountState
// unconditionally sets AccountSuspended, and UpdateSCIMUser's reactivation only ever
// clears AccountDeprovisioned (never AccountSuspended — see UpdateSCIMUser's doc
// comment), so every possible total ordering of {suspend, deactivate, reactivate} ends
// in AccountSuspended once accountStateMu enforces one call at a time: the final state
// is not just "some login-blocked value" but deterministically the suspension itself.
func TestConcurrency_SuspendUser_SurvivesConcurrentSCIMDeactivateReactivate(t *testing.T) {
	t.Parallel()
	dsn := "file:" + filepath.Join(t.TempDir(), "suspend_scim_deact_race.db") + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Session{}, &models.AuditEvent{}, &models.PersonalAccessToken{},
		&models.Role{}, &models.UserRole{}, &models.Project{}, &models.Environment{},
		// Group/UserGroup/GroupRole are needed by guardLastAdminDeactivation
		// (#G02), which SuspendUser now calls.
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{},
	))

	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	ctx := context.Background()

	const users = 200
	for i := range users {
		require.NoError(t, db.Create(&models.User{
			ID: uint(i + 1), Username: fmt.Sprintf("user%d", i), Email: fmt.Sprintf("user%d@x.io", i),
			IsActive: true, AccountState: core.AccountActive,
		}).Error)
	}

	no, yes := false, true
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range users {
		uid := uint(i + 1)
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_ = c.SuspendUser(ctx, 99, uid) // admin incident response
		}()
		go func() {
			defer wg.Done()
			<-start
			// A routine SCIM deactivate immediately followed by a reactivate (e.g. a
			// bounce during directory sync), racing the admin's suspend.
			_, _ = c.UpdateSCIMUser(ctx, 2, uid, nil, nil, &no)
			_, _ = c.UpdateSCIMUser(ctx, 2, uid, nil, nil, &yes)
		}()
	}
	close(start)
	wg.Wait()

	var reverted []uint
	for i := range users {
		uid := uint(i + 1)
		var got models.User
		require.NoError(t, db.First(&got, uid).Error)
		if got.AccountState != core.AccountSuspended {
			reverted = append(reverted, uid)
		}
	}
	assert.Empty(t, reverted,
		"the admin suspension must be the terminal state after racing a SCIM deactivate/reactivate "+
			"cycle, under every possible interleaving; these users were not: %v", reverted)
}
