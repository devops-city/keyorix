package core_test

import (
	"context"
	"path/filepath"
	"strings"
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

// TestConcurrency_InviteMember_NoDuplicateActiveMembership is the (#309) TOCTOU
// regression: InviteMember's "no active membership" read and its CreateProjectMembership
// write are two separate calls with no transaction, so concurrent invites for the same
// (project, user) can both pass the read before either commits, producing two non-revoked
// ProjectMembership rows. This drives many concurrent invites for the same pair against a
// real file-backed SQLite (through the same migration path production uses, so the
// uniq_project_memberships_active partial unique index is actually in place) and asserts
// exactly one membership row survives, with every loser getting a clean "already has a
// membership" error rather than a raw constraint-violation message or a silently-orphaned
// row.
func TestConcurrency_InviteMember_NoDuplicateActiveMembership(t *testing.T) {
	t.Parallel()
	dsn := "file:" + filepath.Join(t.TempDir(), "invite.db") + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.Role{}, &models.ProjectMembership{}, &models.AuditEvent{}, &models.Permission{}, &models.RolePermission{}))
	// Mirror factory.go's ensureProjectMembershipIndex exactly, so this test exercises the
	// same DB-level guard production installs get (rather than only the in-process check).
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_project_memberships_active "+
		"ON project_memberships (project_id, user_id) WHERE state <> 'revoked'").Error)

	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "proj"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 6, Name: "project_viewer"}).Error)
	// F6 sweep (2026-09-22): inviting now ALSO requires roles.assign as a
	// baseline, independent of "project_viewer"'s own (here empty) permission
	// bundle. Give the inviter (actor 9) a real roles.assign grant at the
	// project so this test still isolates the concurrent-invite race (its
	// actual subject) from that separate baseline. GetUserGroupRoleIDsAt
	// (the baseline check's group-role side) needs Group/UserGroup/GroupRole
	// migrated too, even though this test seeds no groups.
	require.NoError(t, db.AutoMigrate(&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{}, &models.Environment{}))
	require.NoError(t, db.Create(&models.Permission{ID: 900, Name: "roles.assign", Resource: "roles", Action: "assign"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 7, Name: "invite-actor"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 7, PermissionID: 900}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 9, RoleID: 7, ProjectID: 1}).Error)

	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	c.SetMembershipValidationMode(core.ValidationModeAllowlist)

	const attackers = 40 // many concurrent invites racing for the same (project, user)
	start := make(chan struct{})
	errs := make([]error, attackers)
	var wg sync.WaitGroup
	for i := range attackers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, err := c.InviteMember(context.Background(), 1, 2, "project_viewer", 9, 0, false)
			errs[i] = err
		}(i)
	}
	close(start) // release every invite at once
	wg.Wait()

	// Exactly one Create must have won the race.
	var successes int
	var duplicateRejections int
	for _, err := range errs {
		if err == nil {
			successes++
			continue
		}
		// The loser of the race gets either the original sequential check's message
		// ("user already has a <state> membership...") or, when it loses the DB-level
		// race instead, the translated ErrDuplicateActiveMembership message. Both read
		// as "already has" + "membership"; neither is a raw constraint-violation string.
		if strings.Contains(err.Error(), "already has") && strings.Contains(err.Error(), "membership") {
			duplicateRejections++
		}
	}
	assert.Equal(t, 1, successes, "exactly one concurrent invite must succeed")
	assert.Equal(t, attackers-1, duplicateRejections,
		"every other concurrent invite must get a clean 'already has ... membership' error, not a raw DB error")

	// And the DB must hold exactly one non-revoked membership row for the pair — no
	// orphaned duplicate from a TOCTOU window.
	var count int64
	require.NoError(t, db.Model(&models.ProjectMembership{}).
		Where("project_id = ? AND user_id = ? AND state <> ?", 1, 2, "revoked").
		Count(&count).Error)
	assert.Equal(t, int64(1), count, "exactly one active membership row must exist for the pair")
}
