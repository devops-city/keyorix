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
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// #340: guardLastGlobalAdmin's prior read-then-conditional-write was a TOCTOU —
// with exactly two global admins, each concurrently removing the OTHER's role
// assignment could both observe "another admin still exists" before either write
// landed, stranding the install with zero admins. This drives the real
// RemoveUserRole path from two goroutines racing to remove each other's admin
// grant and asserts the install is NEVER left with zero: exactly one removal must
// succeed and the other must be refused, however the goroutines interleave.
// File-backed SQLite (real multi-connection concurrency) run under -race.
func TestConcurrency_RemoveUserRole_CannotStrandLastTwoAdmins(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	dsn := "file:" + filepath.Join(t.TempDir(), "c.db") + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Role{}, &models.Permission{}, &models.RolePermission{}, &models.UserRole{}, &models.User{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.AuditEvent{},
	))
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "admin", BypassesPermissionChecks: true}).Error)
	// #2658: the last-admin guard counts only live (existing, active) holders,
	// so each admin grant needs a real user row behind it.
	for _, id := range []uint{100, 101} {
		require.NoError(t, db.Create(&models.User{ID: id, Username: fmt.Sprintf("admin-%d", id), Email: fmt.Sprintf("admin-%d@example.com", id), IsActive: true, AccountState: "active"}).Error)
	}
	require.NoError(t, db.Create(&models.UserRole{UserID: 100, RoleID: 1}).Error) // admin #1, global
	require.NoError(t, db.Create(&models.UserRole{UserID: 101, RoleID: 1}).Error) // admin #2, global

	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	ctx := context.Background()

	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make(chan error, 2)
	// Each goroutine removes the OTHER admin's role — the exact race #340 describes.
	for _, uid := range []uint{100, 101} {
		wg.Add(1)
		go func(target uint) {
			defer wg.Done()
			<-start
			results <- c.RemoveUserRole(ctx, 0, target, 1, core.Scope{})
		}(uid)
	}
	close(start)
	wg.Wait()
	close(results)

	var succeeded, refused int
	for e := range results {
		if e == nil {
			succeeded++
		} else {
			refused++
		}
	}
	assert.Equal(t, 1, succeeded, "exactly one of the two concurrent removals must succeed")
	assert.Equal(t, 1, refused, "exactly one of the two concurrent removals must be refused")

	// The install must have exactly one admin left standing — never zero.
	var remaining int64
	require.NoError(t, db.Model(&models.UserRole{}).Where("role_id = ?", 1).Count(&remaining).Error)
	assert.Equal(t, int64(1), remaining, "the install must never be left with zero global admins")
}

// A higher-concurrency variant of the same invariant: N goroutines all racing to
// remove role grants from a small, fixed set of global admins must never drive the
// admin count to zero, regardless of scheduling. Repeats several independent
// two-admin scenarios in the same run to make a would-be race window more likely
// to be hit than a single pair alone.
func TestConcurrency_RemoveUserRole_RepeatedPairsNeverStrandInstall(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())

	const trials = 8
	for trial := range trials {
		t.Run(fmt.Sprintf("trial-%d", trial), func(t *testing.T) {
			dsn := "file:" + filepath.Join(t.TempDir(), "c.db") + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
			db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
			require.NoError(t, err)
			require.NoError(t, db.AutoMigrate(
				&models.Role{}, &models.Permission{}, &models.RolePermission{}, &models.UserRole{}, &models.User{},
				&models.Group{}, &models.UserGroup{}, &models.GroupRole{},
				&models.Project{}, &models.Environment{}, &models.AuditEvent{},
			))
			require.NoError(t, db.Create(&models.Role{ID: 1, Name: "admin", BypassesPermissionChecks: true}).Error)
			// #2658: the last-admin guard counts only live (existing, active) holders,
			// so each admin grant needs a real user row behind it.
			for _, id := range []uint{200, 201} {
				require.NoError(t, db.Create(&models.User{ID: id, Username: fmt.Sprintf("admin-%d", id), Email: fmt.Sprintf("admin-%d@example.com", id), IsActive: true, AccountState: "active"}).Error)
			}
			require.NoError(t, db.Create(&models.UserRole{UserID: 200, RoleID: 1}).Error)
			require.NoError(t, db.Create(&models.UserRole{UserID: 201, RoleID: 1}).Error)

			c := core.NewKeyorixCore(store.NewLocalStorage(db))
			ctx := context.Background()

			start := make(chan struct{})
			var wg sync.WaitGroup
			for _, uid := range []uint{200, 201} {
				wg.Add(1)
				go func(target uint) {
					defer wg.Done()
					<-start
					_ = c.RemoveUserRole(ctx, 0, target, 1, core.Scope{})
				}(uid)
			}
			close(start)
			wg.Wait()

			var remaining int64
			require.NoError(t, db.Model(&models.UserRole{}).Where("role_id = ?", 1).Count(&remaining).Error)
			assert.Equal(t, int64(1), remaining, "the install must never be left with zero global admins")
		})
	}
}
