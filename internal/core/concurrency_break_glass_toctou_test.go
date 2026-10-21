// concurrency_break_glass_toctou_test.go — TOCTOU-1 sibling: break_glass.go's
// RevokeBreakGlassActivationAtomic (introduced by #2018) copied the same
// guard-then-unlock-then-write pattern RemoveUserRole originally had
// (concurrency_remove_user_role_toctou_test.go's doc comment has the full
// mechanism rationale — same reasoning applies here verbatim, just against
// RevokeBreakGlassActivationAtomic instead of RemoveUserRole). Reuses the
// SAME delayedRemoveRoleStorage decorator that file defines (same package,
// core_test) — the pausing technique doesn't care which production function
// calls the wrapped RemoveRole/GetUserRoleIDsExact, only that it does.
//
// Fixture note: ActivateBreakGlass's own policy refuses to configure an
// emergency role that carries roles.assign (break_glass.go), so a BreakGlassActivation
// created through that path can never itself be the project's last
// administrator — guardLastProjectAdmin would have nothing to refuse. This
// test constructs the DB state directly (AssignRole + CreateBreakGlassActivation,
// bypassing ActivateBreakGlass's policy checks), matching
// break_glass_revoke_atomicity_pg_test.go's own fixture pattern, to reach the
// "a role's permission set was edited after activation" case the guard's own
// doc comment says it still defends against.
package core_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestConcurrency_RevokeBreakGlassActivationAtomic_TOCTOU_Deterministic(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "break_glass_toctou.db") + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.AuditEvent{}, &models.PendingAuditEvent{}, &models.SecretNode{},
		&models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{}, &models.Session{}, &models.BreakGlassActivation{},
	))
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "roles.assign"}).Error)
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "proj"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "proj_admin"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 10, PermissionID: 1}).Error)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "bgadmin1"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "bgadmin2"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 10, ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 10, ProjectID: 1}).Error)

	expiresAt := time.Now().Add(2 * time.Hour)
	realStorage := store.NewLocalStorage(db)
	ctx := context.Background()
	activation1, err := realStorage.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID: 1, UserID: 1, RoleID: 10, RoleName: "proj_admin",
		Justification: "toctou test 1", State: core.BreakGlassActive, ExpiresAt: &expiresAt,
	})
	require.NoError(t, err)
	activation2, err := realStorage.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID: 1, UserID: 2, RoleID: 10, RoleName: "proj_admin",
		Justification: "toctou test 2", State: core.BreakGlassActive, ExpiresAt: &expiresAt,
	})
	require.NoError(t, err)

	wrapped := &delayedRemoveRoleStorage{
		Storage:      realStorage,
		targetUserID: 1, targetRoleID: 10,
		blocked: make(chan struct{}), release: make(chan struct{}),
	}
	c := core.NewKeyorixCore(wrapped)

	var errA, errB error
	doneA, doneB := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(doneA)
		errA = c.RevokeBreakGlassActivationAtomic(ctx, 99, 0, activation1, time.Now())
	}()

	<-wrapped.blocked // revoking activation1 passed the guard and is paused right before its write lands

	go func() {
		defer close(doneB)
		errB = c.RevokeBreakGlassActivationAtomic(ctx, 99, 0, activation2, time.Now())
	}()

	// Give activation2's revoke a generous bounded window to run to COMPLETION
	// before releasing activation1's delayed write -- see
	// concurrency_remove_user_role_toctou_test.go's file doc comment for why
	// waiting for completion (not merely "started reading") is required: the
	// guard's decision chain (GetUserRoleIDsExact, ListProjectRoleAssignments,
	// one GetUser per surviving holder) has more than one storage call, and
	// releasing after only the first would leave a real window where the
	// unfixed code's bug is masked by test-harness timing luck rather than
	// exposed.
	select {
	case <-doneB:
	case <-time.After(2 * time.Second):
	}
	close(wrapped.release)
	<-doneA
	<-doneB

	t.Logf("revoke activation1 result: %v", errA)
	t.Logf("revoke activation2 result: %v", errB)

	remainingA, err := realStorage.GetUserRoleIDsExact(ctx, 1, storage.Scope{ProjectID: 1})
	require.NoError(t, err)
	remainingB, err := realStorage.GetUserRoleIDsExact(ctx, 2, storage.Scope{ProjectID: 1})
	require.NoError(t, err)
	aSurvives, bSurvives := len(remainingA) > 0, len(remainingB) > 0

	if !aSurvives && !bSurvives {
		t.Errorf("LAST-PROJECT-ADMIN GUARD BYPASSED (break-glass TOCTOU-1): both concurrent break-glass "+
			"revokes raced through the guard before either write committed and both succeeded -- the "+
			"project is left with ZERO roles.assign holders (errA=%v errB=%v)", errA, errB)
	}
	assert.False(t, !aSurvives && !bSurvives, "at least one of the two racing revokes must be refused")
	assert.True(t, aSurvives || bSurvives, "exactly one admin's grant should survive")
}
