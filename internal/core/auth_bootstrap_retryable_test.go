// auth_bootstrap_retryable_test.go — regression tests for a first-boot
// failure that left an install unable to bootstrap ever again (FINDINGS-inbox,
// Session J, 2026-09-28, reproduced on a kind cluster via the Helm quick-start).
//
// bootstrapSystemLocked seeded permissions and roles, THEN called CreateUser,
// whose personal-info password check ("must not contain your username, email,
// or display name") is stricter than the pre-check it ran first (which passed
// a nil user). A password like "Change-This-Admin-Pw1" for user "admin" passed
// the pre-check, was rejected by CreateUser AFTER the permission rows were
// committed, and every later /system/init — with any password — failed with a
// duplicate-key 500 on the first permission. Only wiping the DB recovered.
package core

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

const retryToken = "retry-bootstrap-token"

// The password Session J actually used: 16+ chars with upper/lower/digit/special,
// but it contains the username "admin" (case-insensitively).
func personalInfoPasswordReq() *BootstrapRequest {
	return &BootstrapRequest{
		Username: "admin", Email: "admin@example.com",
		Password: "Change-This-Admin-Pw1", DisplayName: "Administrator", Token: retryToken,
	}
}

func goodRetryReq() *BootstrapRequest {
	return &BootstrapRequest{
		Username: "admin", Email: "admin@example.com",
		Password: "Kx7!Bootstrap-Pwd", DisplayName: "Administrator", Token: retryToken,
	}
}

// TestBootstrapSystem_PersonalInfoPasswordRejectedBeforeAnyWrite: the rejection
// must happen before anything is written, so nothing is left behind.
func TestBootstrapSystem_PersonalInfoPasswordRejectedBeforeAnyWrite(t *testing.T) {
	c := freshBootstrapCore(t)
	c.SetBootstrapToken(retryToken)
	ctx := context.Background()

	_, err := c.BootstrapSystem(ctx, personalInfoPasswordReq())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not contain your username, email, or display name")

	perms, err := c.storage.ListPermissions(ctx)
	require.NoError(t, err)
	assert.Empty(t, perms, "a rejected bootstrap must not have seeded any permission")
	roles, err := c.storage.ListRoles(ctx)
	require.NoError(t, err)
	assert.Empty(t, roles, "a rejected bootstrap must not have seeded any role")
	_, total, err := c.storage.ListUsers(ctx, &storage.UserFilter{Page: 1, PageSize: 1})
	require.NoError(t, err)
	assert.Zero(t, total)
}

// TestBootstrapSystem_RetryAfterRejectedPasswordSucceeds is Session J's exact
// live sequence: a rejected first attempt, then a corrected password on the
// same install. Red before the fix (500: duplicate permission).
func TestBootstrapSystem_RetryAfterRejectedPasswordSucceeds(t *testing.T) {
	c := freshBootstrapCore(t)
	c.SetBootstrapToken(retryToken)
	ctx := context.Background()

	_, err := c.BootstrapSystem(ctx, personalInfoPasswordReq())
	require.Error(t, err)

	res, err := c.BootstrapSystem(ctx, goodRetryReq())
	require.NoError(t, err, "a corrected password on the same fresh install must bootstrap")
	require.NotNil(t, res.User)
	assert.False(t, res.AlreadyInitialized)
	assert.Equal(t, "admin", res.User.Username)
}

// TestBootstrapSystem_RetryAfterPartialSeedSucceeds covers the general case: a
// failure anywhere after seeding started (not only the password check) left
// some default permissions / roles / links committed. The next attempt must
// reuse them, finish, and leave exactly one copy of each.
func TestBootstrapSystem_RetryAfterPartialSeedSucceeds(t *testing.T) {
	c := freshBootstrapCore(t)
	c.SetBootstrapToken(retryToken)
	ctx := context.Background()

	// Simulate a half-finished earlier attempt: the first two default
	// permissions, and the first default role linked to one of them.
	require.GreaterOrEqual(t, len(defaultPermissions), 2)
	var firstPerm *models.Permission
	for i, def := range defaultPermissions[:2] {
		p, err := c.storage.CreatePermission(ctx, &models.Permission{
			Name: def.Name, Description: def.Description, Resource: def.Resource, Action: def.Action,
		})
		require.NoError(t, err)
		if i == 0 {
			firstPerm = p
		}
	}
	rdef := defaultRoles[0]
	folded, err := identity.NewFoldedName(rdef.Name)
	require.NoError(t, err)
	role, err := c.storage.CreateRole(ctx, folded, rdef.Description)
	require.NoError(t, err)
	for _, name := range rdef.Permissions {
		if name == firstPerm.Name {
			require.NoError(t, c.storage.AssignPermissionToRole(ctx, role.ID, firstPerm.ID))
		}
	}

	res, err := c.BootstrapSystem(ctx, goodRetryReq())
	require.NoError(t, err, "bootstrap must finish on top of a partial seed")
	require.NotNil(t, res.User)

	perms, err := c.storage.ListPermissions(ctx)
	require.NoError(t, err)
	assert.Len(t, perms, len(defaultPermissions), "exactly one row per default permission")
	roles, err := c.storage.ListRoles(ctx)
	require.NoError(t, err)
	assert.Len(t, roles, len(defaultRoles), "exactly one row per default role")

	got, err := c.storage.GetRolePermissions(ctx, role.ID)
	require.NoError(t, err)
	assert.Len(t, got, len(rdef.Permissions), "the reused role ends with its full default permission set, no duplicates")

	// And the admin really is an admin.
	userRoles, err := c.storage.GetUserRoles(ctx, res.User.ID)
	require.NoError(t, err)
	names := make([]string, 0, len(userRoles))
	for _, r := range userRoles {
		names = append(names, r.Name)
	}
	assert.Contains(t, names, "admin")
}

// failOnceStorage makes one named storage step fail during the first
// bootstrap attempt only, and follows WithTransaction so the failure also
// fires on the transaction-scoped handle.
type failOnceStorage struct {
	storage.Storage
	failStep string
	armed    *bool
}

func (s *failOnceStorage) WithTransaction(ctx context.Context, fn func(storage.Storage) error) error {
	return s.Storage.WithTransaction(ctx, func(tx storage.Storage) error {
		return fn(&failOnceStorage{Storage: tx, failStep: s.failStep, armed: s.armed})
	})
}

func (s *failOnceStorage) trip(step string) error {
	if *s.armed && s.failStep == step {
		*s.armed = false
		return errors.New("injected fault: " + step)
	}
	return nil
}

func (s *failOnceStorage) AssignRole(ctx context.Context, userID, roleID uint, scope Scope) error {
	if err := s.trip("AssignRole"); err != nil {
		return err
	}
	return s.Storage.AssignRole(ctx, userID, roleID, scope)
}

func (s *failOnceStorage) CreateProject(ctx context.Context, p *models.Project) (*models.Project, error) {
	if err := s.trip("CreateProject"); err != nil {
		return nil, err
	}
	return s.Storage.CreateProject(ctx, p)
}

func (s *failOnceStorage) SetSystemMetadata(ctx context.Context, key, value string) error {
	if err := s.trip("SetSystemMetadata"); err != nil {
		return err
	}
	return s.Storage.SetSystemMetadata(ctx, key, value)
}

// TestBootstrapSystem_FailureAfterUserCreateRollsBackEverything: a failure at
// any write step after the admin user row is created must leave NOTHING
// behind (no user, no seed rows, no marker), and the next attempt must produce
// a complete admin. Red before the single-transaction change: the user row
// survived, the retry took the "users exist, no marker" backfill path and
// reported AlreadyInitialized with an admin lacking the admin role.
func TestBootstrapSystem_FailureAfterUserCreateRollsBackEverything(t *testing.T) {
	for _, step := range []string{"AssignRole", "CreateProject", "SetSystemMetadata"} {
		t.Run(step, func(t *testing.T) {
			base := freshBootstrapCore(t)
			armed := true
			c := NewKeyorixCore(&failOnceStorage{Storage: base.storage, failStep: step, armed: &armed})
			c.SetBootstrapToken(retryToken)
			ctx := context.Background()

			_, err := c.BootstrapSystem(ctx, goodRetryReq())
			require.Error(t, err)
			require.False(t, armed, "the injected fault must actually have fired")

			_, total, err := base.storage.ListUsers(ctx, &storage.UserFilter{Page: 1, PageSize: 1})
			require.NoError(t, err)
			assert.Zero(t, total, "the failed bootstrap must not leave a user behind")
			perms, err := base.storage.ListPermissions(ctx)
			require.NoError(t, err)
			assert.Empty(t, perms, "the failed bootstrap must not leave seed permissions behind")
			_, found, err := base.storage.GetSystemMetadata(ctx, systemInitializedKey)
			require.NoError(t, err)
			assert.False(t, found, "the failed bootstrap must not leave the initialised marker behind")

			res, err := c.BootstrapSystem(ctx, goodRetryReq())
			require.NoError(t, err)
			require.False(t, res.AlreadyInitialized, "the retry must perform a real bootstrap, not the backfill path")
			require.NotNil(t, res.User)
			require.NotNil(t, res.Project)

			userRoles, err := base.storage.GetUserRoles(ctx, res.User.ID)
			require.NoError(t, err)
			names := map[string]bool{}
			for _, r := range userRoles {
				names[r.Name] = true
			}
			assert.True(t, names["admin"], "the admin must hold the admin role")
			assert.True(t, names["system_viewer"], "the admin must hold the system_viewer baseline")
		})
	}
}

// TestBootstrapSystem_FailureAfterUserCreateRollsBackEverything_Postgres runs
// the same rollback check on a real, isolated PostgreSQL schema migrated as
// production does. PostgreSQL aborts the whole transaction on a failed
// statement, so this is where a partial commit would show up. Skips when
// KEYORIX_TEST_PG_DSN is unset.
func TestBootstrapSystem_FailureAfterUserCreateRollsBackEverything_Postgres(t *testing.T) {
	base := pgTestDSN(t)
	db := pgOpen(t, pgMigratedDatabaseDSN(t, base))
	st := store.NewLocalStorage(db)
	ctx := context.Background()

	armed := true
	c := NewKeyorixCore(&failOnceStorage{Storage: st, failStep: "CreateProject", armed: &armed})
	c.SetBootstrapToken(retryToken)

	_, err := c.BootstrapSystem(ctx, goodRetryReq())
	require.Error(t, err)
	require.False(t, armed)

	_, total, err := st.ListUsers(ctx, &storage.UserFilter{Page: 1, PageSize: 1})
	require.NoError(t, err)
	assert.Zero(t, total)
	perms, err := st.ListPermissions(ctx)
	require.NoError(t, err)
	assert.Empty(t, perms)

	res, err := c.BootstrapSystem(ctx, goodRetryReq())
	require.NoError(t, err)
	require.False(t, res.AlreadyInitialized)
	userRoles, err := st.GetUserRoles(ctx, res.User.ID)
	require.NoError(t, err)
	names := map[string]bool{}
	for _, r := range userRoles {
		names[r.Name] = true
	}
	assert.True(t, names["admin"])
	assert.True(t, names["system_viewer"])
}

// TestBootstrapSystem_RetryAfterRejectedPasswordSucceeds_Postgres is
// TestBootstrapSystem_RetryAfterRejectedPasswordSucceeds's real-Postgres
// counterpart — Session W (2026-09-29), verifying BUGS-FOUND.md's Bug 1
// against current main on the backend the original repro's duplicate-key
// error (SQLSTATE 23505) actually came from. The SQLite-only version above
// already covers the same code path (backend-agnostic), but Postgres is
// where the pre-#2295 bug's failure signature was actually observed, so it
// gets its own gated proof rather than relying solely on the shared logic
// argument. Skips when KEYORIX_TEST_PG_DSN is unset.
func TestBootstrapSystem_RetryAfterRejectedPasswordSucceeds_Postgres(t *testing.T) {
	base := pgTestDSN(t)
	db := pgOpen(t, pgMigratedDatabaseDSN(t, base))
	st := store.NewLocalStorage(db)
	ctx := context.Background()

	c := NewKeyorixCore(st)
	c.SetBootstrapToken(retryToken)

	_, err := c.BootstrapSystem(ctx, personalInfoPasswordReq())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not contain your username, email, or display name")

	perms, err := st.ListPermissions(ctx)
	require.NoError(t, err)
	assert.Empty(t, perms, "a rejected bootstrap must not have seeded any permission")

	res, err := c.BootstrapSystem(ctx, goodRetryReq())
	require.NoError(t, err, "a corrected password on the same fresh install must bootstrap, not 500 on a duplicate-key error")
	require.NotNil(t, res.User)
	assert.False(t, res.AlreadyInitialized)
	assert.Equal(t, "admin", res.User.Username)
}
