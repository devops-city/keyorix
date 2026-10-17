// create_ops_pg_savepoint_test.go — PostgreSQL-only: proves the SAVEPOINT
// mechanism (see catalog.go's CreateProject/CreateProjectWithEnvs and
// users.go's CreateUser) through the REAL production code path, not the
// synthetic raw-SQL harness in
// internal/storage/store/local_transaction_pg_savepoint_test.go.
//
// Both tests here force a genuinely failing SQL statement (a CHECK
// constraint that always evaluates false) directly on the table the
// intentionally-non-fatal step writes to — not faultstorage's synthetic fault
// injection, which never reaches the database at all (KindError) or lets the
// real call genuinely succeed (KindEffectThenError). Neither can reproduce
// PostgreSQL's "a failed statement poisons the whole transaction" behavior,
// which is exactly what these tests need.
//
// Each proves three things about the SAME call:
//  1. The outer create SUCCEEDS (the non-fatal step's failure does not
//     propagate as the caller's error).
//  2. A warning is logged — the failure is observable, not silently
//     swallowed.
//  3. The outer transaction actually COMMITTED (re-read from a fresh query)
//     with the non-fatal step's effect absent — proving PostgreSQL did not
//     poison the whole transaction and did not downgrade COMMIT to ROLLBACK
//     (pgx's ErrTxCommitRollback).
//
// Red-proofed manually against this same code (not committed): temporarily
// replacing the nested tx.WithTransaction(savepoint) call in catalog.go /
// users.go with a direct, unwrapped call reproduces exactly the failure mode
// these tests exist to rule out — CreateProject/CreateUser returns a non-nil
// error whose chain contains pgx's "commit unexpectedly resulted in
// rollback", and the outer transaction's own otherwise-successful row
// (the project itself, in CreateProject's case) does not survive either.
package core

import (
	"bytes"
	"context"
	"log"
	"sync"
	"testing"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/require"
)

// capturedLogMu serializes withCapturedLog. The standard logger is global and
// the savepoint tests run in parallel: without it, a second capture that starts
// while the first is running takes over the output, and the first test's lines
// land in the second test's buffer (CI run 38935925421: the env-seed test's
// buffer held its later audit failures but none of its "Warning: project" lines).
var capturedLogMu sync.Mutex

// withCapturedLog redirects the standard logger to a buffer for the
// duration of fn, restoring it afterward.
func withCapturedLog(t *testing.T, fn func()) string {
	t.Helper()
	capturedLogMu.Lock()
	defer capturedLogMu.Unlock()
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)
	fn()
	return buf.String()
}

// TestCreateProject_PostgresSavepoint_EnvSeedFailureIsNonFatal is the GREEN
// case for CreateProject's default-environment seeding loop (catalog.go).
func TestCreateProject_PostgresSavepoint_EnvSeedFailureIsNonFatal(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	base := pgTestDSN(t)
	dsn := pgIsolatedSchemaDSN(t, base)

	db := pgOpen(t, dsn)
	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.Environment{}))
	// Force EVERY insert into environments to fail for real — a genuine
	// PostgreSQL statement failure (SQLSTATE 23514, check_violation), not a
	// synthetic fault. CreateProject's env-seeding loop tries 3 default
	// names (development/staging/production); all 3 must fail identically.
	require.NoError(t, db.Exec("ALTER TABLE environments ADD CONSTRAINT force_env_fail CHECK (1=0)").Error)

	c := NewKeyorixCore(localstore.NewLocalStorage(db))

	var project *models.Project
	logOutput := withCapturedLog(t, func() {
		var err error
		project, err = c.CreateProject(context.Background(), "pg-savepoint-env-proof", "")
		require.NoError(t, err, "CreateProject must succeed even though every default-environment insert fails")
	})
	require.NotZero(t, project.ID)
	require.Contains(t, logOutput, "Warning: project", "the swallowed per-environment failure must be logged, not silent")

	// The project row itself must have genuinely committed — re-read via a
	// fresh query, not the same in-flight transaction.
	var projectCount int64
	require.NoError(t, db.Model(&models.Project{}).Where("id = ?", project.ID).Count(&projectCount).Error)
	require.Equal(t, int64(1), projectCount, "the project row must have survived — the savepoint must have contained the failure, not the whole transaction")

	// It must have NONE of its default environments — the failure was real,
	// not silently treated as a no-op success.
	var envCount int64
	require.NoError(t, db.Model(&models.Environment{}).Where("project_id = ?", project.ID).Count(&envCount).Error)
	require.Zero(t, envCount, "every default-environment insert was sabotaged; none should have landed")
}

// TestCreateUser_PostgresSavepoint_RoleAssignFailureIsNonFatal is the GREEN
// case for CreateUser's baseline system_viewer role grant (users.go).
func TestCreateUser_PostgresSavepoint_RoleAssignFailureIsNonFatal(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	base := pgTestDSN(t)
	dsn := pgIsolatedSchemaDSN(t, base)

	db := pgOpen(t, dsn)
	require.NoError(t, db.AutoMigrate(dualControlModels...))

	c := NewKeyorixCore(localstore.NewLocalStorage(db))
	c.SetBootstrapToken("pg-savepoint-role-token")
	_, err := c.BootstrapSystem(context.Background(), &BootstrapRequest{
		Username: "admin", Email: "admin@example.com", Password: "BootstrapPass123!",
		DisplayName: "Admin", Token: "pg-savepoint-role-token",
	})
	require.NoError(t, err, "bootstrap seeds the system_viewer role CreateUser looks up")

	// Force EVERY new insert into user_roles to fail for real, AFTER
	// bootstrap's own admin role grant already landed — NOT VALID skips
	// validating that pre-existing row (which would otherwise itself violate
	// CHECK (1=0) and make this ALTER TABLE fail outright) while still
	// enforcing the check on every subsequent insert, which is all this test
	// needs: the sabotage must only affect the CreateUser call under test,
	// not bootstrap itself.
	require.NoError(t, db.Exec("ALTER TABLE user_roles ADD CONSTRAINT force_role_fail CHECK (1=0) NOT VALID").Error)

	var user *models.User
	logOutput := withCapturedLog(t, func() {
		var err error
		user, err = c.CreateUser(context.Background(), &CreateUserRequest{
			Username: "pg-savepoint-user", Email: "pg-savepoint-user@example.com", Password: "Qr7#Kp2$Lm5@Vn9!",
		})
		require.NoError(t, err, "CreateUser must succeed even though the system_viewer AssignRole insert fails")
	})
	require.NotZero(t, user.ID)
	require.Contains(t, logOutput, "users.CreateUser.AssignBaselineRole", "the swallowed AssignRole failure must be logged (via besteffort.Run), not silent")

	var userCount int64
	require.NoError(t, db.Model(&models.User{}).Where("id = ?", user.ID).Count(&userCount).Error)
	require.Equal(t, int64(1), userCount, "the user row must have survived — the savepoint must have contained the failure, not the whole transaction")

	var roleCount int64
	require.NoError(t, db.Model(&models.UserRole{}).Where("user_id = ?", user.ID).Count(&roleCount).Error)
	require.Zero(t, roleCount, "the sabotaged AssignRole insert must not have landed")
}
