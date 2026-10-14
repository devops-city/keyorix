// concurrency_deletegroup_lastadmin_race_test.go — SESSION-AT: DeleteGroup's
// guard-then-delete sequence (guardLastGlobalAdminGroupDelete,
// guardLastProjectAdminGroupDelete, storage.DeleteGroup) ran with NO lock at
// all, unlike DeleteUser's lastAdminGuardLockKey wrap (#1646) for the
// identical invariant. Two concurrent DeleteGroup calls on two DIFFERENT
// admin-holding groups could each observe "the other group's grant still
// covers the install" and both pass their guard, jointly leaving zero
// admins. Same technique as concurrency_last_admin_race_test.go's
// TestConcurrency_DeleteUser_ExactlyOneOfTwoAdminsRemoved: a fresh,
// file-backed SQLite DB (WAL + busy_timeout) per trial, two real goroutines
// released from one start barrier.
package core_test

import (
	"context"
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

const deleteGroupRaceTrials = 50

// newTwoGlobalAdminGroupFixture creates a fresh file-backed DB with exactly
// two groups (10, 20), each independently holding the install's only
// global "admin" role grant, each with exactly one distinct GLOBAL-scope
// human member (resolveGlobalAdminHolders traces a group's grant down to
// its real member users -- an admin-holding group with zero members
// resolves to zero holders and would make this fixture refuse every
// delete unconditionally, not exercise the race at all) -- deleting BOTH
// groups is the exact "zero admins" outcome this guard exists to prevent.
func newTwoGlobalAdminGroupFixture(t *testing.T, dbFile string) (*core.KeyorixCore, *gorm.DB) {
	t.Helper()
	dsn := "file:" + dbFile + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Session{}, &models.AuditEvent{}, &models.PersonalAccessToken{},
		&models.Role{}, &models.UserRole{}, &models.Project{}, &models.Environment{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{},
	))
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "a", IsActive: true, AccountState: core.AccountActive, ExternalID: "okta|a"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "b", IsActive: true, AccountState: core.AccountActive, ExternalID: "okta|b"}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 10, Name: "admin-group-a"}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 20, Name: "admin-group-b"}).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 10, RoleID: 10}).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 20, RoleID: 10}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 1, GroupID: 10}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 2, GroupID: 20}).Error)
	return core.NewKeyorixCore(store.NewLocalStorage(db)), db
}

func groupIsGone(db *gorm.DB, groupID uint) bool {
	var g models.Group
	err := db.First(&g, groupID).Error
	return err != nil
}

// TestConcurrency_DeleteGroup_ExactlyOneOfTwoAdminGroupsRemoved is the
// SESSION-AT regression for internal/core/groups.go's DeleteGroup.
func TestConcurrency_DeleteGroup_ExactlyOneOfTwoAdminGroupsRemoved(t *testing.T) {
	t.Parallel()
	var bothGone, neitherGone int
	for range deleteGroupRaceTrials {
		c, db := newTwoGlobalAdminGroupFixture(t, filepath.Join(t.TempDir(), "delete_group.db"))
		ctx := context.Background()

		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); <-start; _ = c.DeleteGroup(ctx, 99, 10) }()
		go func() { defer wg.Done(); <-start; _ = c.DeleteGroup(ctx, 99, 20) }()
		close(start)
		wg.Wait()

		aGone, bGone := groupIsGone(db, 10), groupIsGone(db, 20)
		switch {
		case aGone && bGone:
			bothGone++
		case !aGone && !bGone:
			neitherGone++
		}
	}
	assert.Zero(t, bothGone, "%d/%d trials deleted BOTH admin groups, stranding the install with zero admins", bothGone, deleteGroupRaceTrials)
	assert.Zero(t, neitherGone, "%d/%d trials refused BOTH deletes (should allow exactly one)", neitherGone, deleteGroupRaceTrials)
}
