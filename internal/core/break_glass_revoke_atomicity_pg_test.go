// break_glass_revoke_atomicity_pg_test.go — PostgreSQL-only: proves
// RevokeBreakGlassActivationAtomic's transaction (break_glass.go) through the
// real production code path, against a real Postgres server, the same
// discipline create_ops_pg_savepoint_test.go uses for CreateProject/CreateUser.
//
// Two properties, each needing genuine Postgres semantics no SQLite/mock test
// can demonstrate:
//
//  1. A GENUINE mid-transaction failure (a real aborting SQL error — here, a
//     BEFORE DELETE trigger that raises an exception on user_roles) must roll
//     back BOTH the role removal AND the activation-state update together:
//     the activation must still read "active" and no audit event must exist.
//     This is the actual defect this fix closes
//     (docs/findings/2026-09-23-FINDING-breakglass-revoke-half-commit.md):
//     before the fix, RemoveUserRole and RevokeBreakGlassActivation were two
//     independent top-level storage calls, so a genuine failure in the first
//     never undid anything (there was nothing to undo — it wasn't inside a
//     transaction at all).
//
//  2. The DELIBERATELY tolerated "already gone" case (RemoveRole's DELETE
//     matches zero rows — the grant already auto-expired, or a racing revoke
//     already removed it) must NOT poison the surrounding transaction: the
//     activation update and audit write must still commit. Unlike
//     CreateRole/CreateUser's own non-fatal steps (create_ops_pg_savepoint_test.go),
//     this one needs NO SAVEPOINT: a DELETE that matches zero rows is not a
//     failing SQL statement at the Postgres protocol level at all (RowsAffected
//     == 0 is a successful result GORM turns into a Go-level
//     storage.ErrRoleNotAssigned after the fact) — there is nothing for a
//     savepoint to contain. Test 2 exists to make that claim machine-checked
//     rather than asserted in this comment.
package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/require"
)

var breakGlassAtomicityPgModels = []any{
	&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
	&models.UserRole{}, &models.BreakGlassActivation{}, &models.AuditEvent{}, &models.PendingAuditEvent{},
}

// setupBreakGlassAtomicityFixture creates a user, a permission-less role (so
// guardLastProjectAdmin's hadAssign check is trivially false and never
// escalates to ListProjectRoleAssignments), grants that role to the user at
// project scope, and records a matching active BreakGlassActivation row —
// the minimal state RevokeBreakGlassActivationAtomic operates on, built
// through real production storage calls rather than raw inserts.
func setupBreakGlassAtomicityFixture(t *testing.T, c *KeyorixCore) *models.BreakGlassActivation {
	t.Helper()
	ctx := context.Background()

	user, err := c.CreateUser(ctx, &CreateUserRequest{
		Username: "pg-atomic-bguser", Email: "pg-atomic-bguser@example.com",
		DisplayName: "BG User", Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)

	role, _, err := c.CreateRole(ctx, 0, "pg-atomic-emergency-role", "contained, no roles.assign", nil)
	require.NoError(t, err)

	scope := storage.Scope{ProjectID: 55}
	require.NoError(t, c.storage.AssignRole(ctx, user.ID, role.ID, scope))

	expiresAt := time.Now().Add(2 * time.Hour)
	activation, err := c.storage.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID: 55, UserID: user.ID, RoleID: role.ID, RoleName: role.Name,
		Justification: "pg atomicity proof", State: BreakGlassActive, ExpiresAt: &expiresAt,
	})
	require.NoError(t, err)
	return activation
}

// TestRevokeBreakGlassActivationAtomic_PostgresTransaction_GenuineFailureRollsBackBoth
// is property 1 above.
func TestRevokeBreakGlassActivationAtomic_PostgresTransaction_GenuineFailureRollsBackBoth(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	base := pgTestDSN(t)
	dsn := pgIsolatedSchemaDSN(t, base)

	db := pgOpen(t, dsn)
	require.NoError(t, db.AutoMigrate(breakGlassAtomicityPgModels...))

	c := NewKeyorixCore(localstore.NewLocalStorage(db))
	activation := setupBreakGlassAtomicityFixture(t, c)

	// Force EVERY delete from user_roles to genuinely fail — a real aborting
	// Postgres error (raised exception), not a synthetic fault and not a mere
	// zero-rows result. A CHECK constraint cannot do this (CHECK never fires
	// on DELETE); a BEFORE DELETE trigger that raises does.
	require.NoError(t, db.Exec(`
		CREATE OR REPLACE FUNCTION pg_atomic_force_role_delete_fail() RETURNS trigger AS $$
		BEGIN
			RAISE EXCEPTION 'forced role-removal failure for atomicity test';
		END;
		$$ LANGUAGE plpgsql
	`).Error)
	require.NoError(t, db.Exec(`
		CREATE TRIGGER pg_atomic_force_role_delete_fail
		BEFORE DELETE ON user_roles
		FOR EACH ROW EXECUTE FUNCTION pg_atomic_force_role_delete_fail()
	`).Error)

	err := c.RevokeBreakGlassActivationAtomic(context.Background(), 1, 0, activation, time.Now())
	require.Error(t, err, "a genuine mid-transaction failure must surface as an error")

	// Re-read from a fresh query (not the failed in-flight transaction): the
	// activation must still be "active" — the whole transaction rolled back,
	// not just the role removal.
	fresh, gerr := c.storage.GetBreakGlassActivation(context.Background(), activation.ID)
	require.NoError(t, gerr)
	require.Equal(t, BreakGlassActive, fresh.State, "the activation-state update must have rolled back together with the failed role removal")

	// The role grant itself must still be present — the DELETE never actually
	// committed either.
	var roleCount int64
	require.NoError(t, db.Model(&models.UserRole{}).
		Where("user_id = ? AND role_id = ? AND project_id = ?", activation.UserID, activation.RoleID, activation.ProjectID).
		Count(&roleCount).Error)
	require.Equal(t, int64(1), roleCount, "the role grant must survive the rolled-back transaction")

	// No audit event for this revoke must exist — audit is written strictly
	// after commit, and there was no commit.
	var auditCount int64
	require.NoError(t, db.Model(&models.AuditEvent{}).
		Where("event_type = ?", EventBreakGlassRevoked).Count(&auditCount).Error)
	require.Zero(t, auditCount, "no break_glass.revoked audit event may exist when the transaction never committed")
}

// TestRevokeBreakGlassActivationAtomic_PostgresTransaction_AlreadyGoneRoleRemovalCommits
// is property 2 above: the tolerated ErrRoleNotAssigned continuation must not
// poison the outer transaction, on real Postgres, with no savepoint involved.
func TestRevokeBreakGlassActivationAtomic_PostgresTransaction_AlreadyGoneRoleRemovalCommits(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	base := pgTestDSN(t)
	dsn := pgIsolatedSchemaDSN(t, base)

	db := pgOpen(t, dsn)
	require.NoError(t, db.AutoMigrate(breakGlassAtomicityPgModels...))

	c := NewKeyorixCore(localstore.NewLocalStorage(db))
	activation := setupBreakGlassAtomicityFixture(t, c)

	// Simulate "already gone" for real: delete the grant directly, exactly as
	// an independent auto-expiry sweep or a racing revoke would have.
	// RemoveRole's own DELETE will then genuinely match zero rows.
	require.NoError(t, db.Where("user_id = ? AND role_id = ? AND project_id = ?",
		activation.UserID, activation.RoleID, activation.ProjectID).Delete(&models.UserRole{}).Error)

	now := time.Now()
	err := c.RevokeBreakGlassActivationAtomic(context.Background(), 1, 0, activation, now)
	require.NoError(t, err, "a zero-rows RemoveRole must not abort the outer transaction — it is not a failing SQL statement")

	fresh, gerr := c.storage.GetBreakGlassActivation(context.Background(), activation.ID)
	require.NoError(t, gerr)
	require.Equal(t, BreakGlassRevoked, fresh.State, "the activation must have committed as revoked despite the zero-rows role removal")

	var auditCount int64
	require.NoError(t, db.Model(&models.AuditEvent{}).
		Where("event_type = ?", EventBreakGlassRevoked).Count(&auditCount).Error)
	require.Equal(t, int64(1), auditCount, "the revoke committed, so its audit event must exist")

	// Calling it again must now hit the real state guard (ErrBreakGlassNotActive),
	// not a second silent success.
	err = c.RevokeBreakGlassActivationAtomic(context.Background(), 1, 0, fresh, now)
	require.True(t, errors.Is(err, storage.ErrBreakGlassNotActive), "a second revoke of an already-revoked activation must be refused")
}
