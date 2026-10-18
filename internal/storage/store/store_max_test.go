// store_max_test.go — coverage-maximization sweep for internal/storage/store.
//
// Targets every locally-testable branch still below 100 % after the s1–s4 sweeps:
// error paths, not-found sentinels, conditional-update misses, zero-element guards
// and other edges in local_auth, local_access_activity, local_access_review_campaigns,
// local_audit, local_audit_checkpoint_lock, local_break_glass, local_dynamic,
// local_invitations, local_legal_hold, local_machine_credentials,
// local_machine_identities, local_memberships, local_mfa, local_notifications,
// local_purge, local_rbac, local_risk_exceptions, local_rotation_policies,
// local_scheduler_lock, local_secret_dependencies, local_secrets, local_sharing,
// local_sod, local_sso, local_system_metadata, local_users, local_webauthn,
// classification_count, and query.go.
//
// Remote-proxy functions (remote_*.go — 429 functions) require a live HTTP server
// and are deliberately excluded.
package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ---------------------------------------------------------------------------
// helper: newMaxStore — unique in-memory SQLite DB auto-migrated for many models
// ---------------------------------------------------------------------------

func newMaxStore(t *testing.T, tag string, ms ...any) *LocalStorage {
	t.Helper()
	db := sqlitetest.OpenWithDialector(t, "storemax_", sqlite.Open, &gorm.Config{})
	if len(ms) > 0 {
		require.NoError(t, db.AutoMigrate(ms...))
	}
	return NewLocalStorage(db)
}

// sessionModels lists the GORM models needed for session tests.
var sessionModels = []any{&models.Session{}, &models.User{}}

// userModels extends sessionModels with groups and group memberships.
var userModels = []any{
	&models.User{}, &models.Group{}, &models.UserGroup{},
	&models.Role{}, &models.UserRole{}, &models.GroupRole{},
	&models.PasswordHistory{},
}

// ---------------------------------------------------------------------------
// local_auth — uncovered error paths
// ---------------------------------------------------------------------------

// GetSessionAny — not-found path (75%).
func TestGetSessionAny_NotFound(t *testing.T) {
	ls := newMaxStore(t, "gsany", sessionModels...)
	_, err := ls.GetSessionAny(context.Background(), "no-such-token")
	require.Error(t, err)
}

// ListSessionsByUser — empty result (75%).
func TestListSessionsByUser_Empty(t *testing.T) {
	ls := newMaxStore(t, "lsbu", sessionModels...)
	sessions, err := ls.ListSessionsByUser(context.Background(), 999)
	require.NoError(t, err)
	assert.Empty(t, sessions)
}

// ListSessionTokenHashesByFamily — empty result.
func TestListSessionTokenHashesByFamily_Empty(t *testing.T) {
	ls := newMaxStore(t, "lsthbf", sessionModels...)
	hashes, err := ls.ListSessionTokenHashesByFamily(context.Background(), "no-family")
	require.NoError(t, err)
	assert.Empty(t, hashes)
}

// EnforceSessionLimit — at-cap path (keep > 0, user has fewer than keep sessions) and keep=0.
func TestEnforceSessionLimit_NeedsToPrune(t *testing.T) {
	ls := newMaxStore(t, "esl", sessionModels...)
	// #2701: a session/PAT insert now re-reads its owning user and rolls back if
	// it is not live, so this fixture needs the owners it references to exist.
	seedCredentialOwners(t, ls.db)
	ctx := context.Background()

	// Create 3 sessions.
	for i := range 3 {
		_, err := ls.CreateSession(ctx, &models.Session{
			UserID:       1,
			SessionToken: fmt.Sprintf("tok%d", i),
		})
		require.NoError(t, err)
	}

	// Keep only 2 — should delete the oldest one.
	require.NoError(t, ls.EnforceSessionLimit(ctx, 1, 2))
	sessions, err := ls.ListSessionsByUser(ctx, 1)
	require.NoError(t, err)
	assert.Len(t, sessions, 2)
}

func TestEnforceSessionLimit_ZeroKeep(t *testing.T) {
	ls := newMaxStore(t, "eslz", sessionModels...)
	// keep=0 → no-op.
	require.NoError(t, ls.EnforceSessionLimit(context.Background(), 1, 0))
}

func TestEnforceSessionLimit_NegativeKeep(t *testing.T) {
	ls := newMaxStore(t, "esln", sessionModels...)
	require.NoError(t, ls.EnforceSessionLimit(context.Background(), 1, -5))
}

// DeleteSessionsForUserExcept — exercises the impersonated_by clause.
func TestDeleteSessionsForUserExcept_Noop(t *testing.T) {
	ls := newMaxStore(t, "dsfue", sessionModels...)
	// No sessions exist: must be a silent no-op.
	require.NoError(t, ls.DeleteSessionsForUserExcept(context.Background(), 1, 99))
}

// ListSessionTokenHashesForUser — empty result.
func TestListSessionTokenHashesForUser_Empty(t *testing.T) {
	ls := newMaxStore(t, "lsthfu", sessionModels...)
	hashes, err := ls.ListSessionTokenHashesForUser(context.Background(), 999)
	require.NoError(t, err)
	assert.Empty(t, hashes)
}

// CreatePersonalAccessToken + GetPersonalAccessTokenByID — success + not-found.
func TestPersonalAccessToken_CreateAndGetByID(t *testing.T) {
	ls := newMaxStore(t, "patid", &models.PersonalAccessToken{}, &models.User{})
	// #2701: a session/PAT insert now re-reads its owning user and rolls back if
	// it is not live, so this fixture needs the owners it references to exist.
	seedCredentialOwners(t, ls.db)
	ctx := context.Background()

	pat, err := ls.CreatePersonalAccessToken(ctx, &models.PersonalAccessToken{
		UserID:    1,
		TokenHash: "hash-xyz",
		Name:      "ci-deploy",
		Revoked:   false,
	})
	require.NoError(t, err)
	require.NotZero(t, pat.ID)

	got, err := ls.GetPersonalAccessTokenByID(ctx, pat.ID)
	require.NoError(t, err)
	assert.Equal(t, pat.ID, got.ID)

	// not-found
	_, err = ls.GetPersonalAccessTokenByID(ctx, 9999)
	require.Error(t, err)
}

// ListPersonalAccessTokensByUser — empty result.
func TestListPersonalAccessTokensByUser_Empty(t *testing.T) {
	ls := newMaxStore(t, "lpatbu", &models.PersonalAccessToken{})
	tokens, err := ls.ListPersonalAccessTokensByUser(context.Background(), 999)
	require.NoError(t, err)
	assert.Empty(t, tokens)
}

// ---------------------------------------------------------------------------
// local_users — uncovered error paths
// ---------------------------------------------------------------------------

func newUserStoreMax(t *testing.T) *LocalStorage {
	t.Helper()
	ls := newMaxStore(t, "usr_"+t.Name(), userModels...)
	// Replicate the partial unique index that migrateDatabase creates in production.
	// SQLite surfaces it in error messages, allowing isDuplicateEmailViolation to
	// match the index name and convert it to storage.ErrDuplicateEmail.
	ls.db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_users_email_active ON users(email) WHERE deleted_at IS NULL AND email != ''")
	return ls
}

// CreateUser — duplicate-email error path (exercises the collision branch).
// The exact sentinel (ErrDuplicateEmail) only propagates when the partial index
// name appears in the driver error, which is Postgres-only; on SQLite we just
// verify a non-nil error is returned.
func TestCreateUser_DuplicateEmailSentinel(t *testing.T) {
	ls := newUserStoreMax(t)
	ctx := context.Background()

	u := &models.User{Email: "dup@example.com", EmailFolded: "dup@example.com", Username: "dup1", UsernameFolded: "dup1"}
	_, err := ls.CreateUser(ctx, u)
	require.NoError(t, err)

	u2 := &models.User{Email: "dup@example.com", EmailFolded: "dup@example.com", Username: "dup2", UsernameFolded: "dup2"}
	_, err = ls.CreateUser(ctx, u2)
	require.Error(t, err)
}

// UpdateUser — success and duplicate-email error path.
func TestUpdateUser_Errors(t *testing.T) {
	ls := newUserStoreMax(t)
	ctx := context.Background()

	u1, err := ls.CreateUser(ctx, &models.User{Email: "a@b.com", EmailFolded: "a@b.com", Username: "aUser", UsernameFolded: "auser"})
	require.NoError(t, err)
	u2, err := ls.CreateUser(ctx, &models.User{Email: "c@d.com", EmailFolded: "c@d.com", Username: "cUser", UsernameFolded: "cuser"})
	require.NoError(t, err)

	// Happy path: update u1's display name.
	u1.DisplayName = "Alice"
	updated, err := ls.UpdateUser(ctx, u1)
	require.NoError(t, err)
	assert.Equal(t, "Alice", updated.DisplayName)

	// Collision path: try to give u2 the same email as u1.
	// On SQLite the error is returned without the ErrDuplicateEmail sentinel
	// (the partial-index name doesn't appear in SQLite's error text, only Postgres).
	u2.Email = "a@b.com"
	_, err = ls.UpdateUser(ctx, u2)
	require.Error(t, err)
}

// UpdateLastLogin — success path.
func TestUpdateLastLogin_Max(t *testing.T) {
	ls := newUserStoreMax(t)
	ctx := context.Background()

	u, err := ls.CreateUser(ctx, &models.User{Email: "login@test.com", EmailFolded: "login@test.com", Username: "loginUser", UsernameFolded: "loginuser"})
	require.NoError(t, err)
	require.NoError(t, ls.UpdateLastLogin(ctx, u.ID, time.Now()))
}

// SetAccountState — not-found path.
func TestSetAccountState_NotFound(t *testing.T) {
	ls := newUserStoreMax(t)
	err := ls.SetAccountState(context.Background(), 9999, "suspended", time.Now())
	require.Error(t, err)
}

// SetPasswordHash — not-found path.
func TestSetPasswordHash_NotFound(t *testing.T) {
	ls := newUserStoreMax(t)
	err := ls.SetPasswordHash(context.Background(), 9999, "$2a$...", time.Now())
	require.Error(t, err)
}

// UpdateLoginLockoutState — not-found path.
func TestUpdateLoginLockoutState_NotFound(t *testing.T) {
	ls := newUserStoreMax(t)
	locked := time.Now().Add(time.Minute)
	err := ls.UpdateLoginLockoutState(context.Background(), 9999, 5, nil, &locked, 1)
	require.Error(t, err)
}

// DeleteUser — not-found path.
func TestDeleteUser_NotFound(t *testing.T) {
	ls := newUserStoreMax(t)
	err := ls.DeleteUser(context.Background(), 9999)
	require.Error(t, err)
}

// CreateUserWithRoleGrants — error path (duplicate email inside transaction).
// The ErrDuplicateEmail sentinel only fires when the partial index name appears
// in the driver error (Postgres only); on SQLite we just verify an error is returned.
func TestCreateUserWithRoleGrants_DuplicateEmailError(t *testing.T) {
	ls := newMaxStore(t, "cuwrg_dup",
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Group{})
	// Create the partial unique index so a duplicate email is rejected.
	ls.db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_users_email_active ON users(email) WHERE deleted_at IS NULL AND email != ''")
	ctx := context.Background()

	_, err := ls.CreateUser(ctx, &models.User{Email: "uniq@dup.com", EmailFolded: "uniq@dup.com", Username: "u1", UsernameFolded: "u1"})
	require.NoError(t, err)

	_, err = ls.CreateUserWithRoleGrants(ctx, &models.User{Email: "uniq@dup.com", EmailFolded: "uniq@dup.com", Username: "u2", UsernameFolded: "u2"}, nil)
	require.Error(t, err)
}

// ListUsersInStateBefore — empty result.
func TestListUsersInStateBefore_Empty(t *testing.T) {
	ls := newUserStoreMax(t)
	users, err := ls.ListUsersInStateBefore(context.Background(), "pending", time.Now())
	require.NoError(t, err)
	assert.Empty(t, users)
}

// GetGroup — not-found path.
func TestGetGroup_NotFound(t *testing.T) {
	ls := newUserStoreMax(t)
	_, err := ls.GetGroup(context.Background(), 9999)
	require.Error(t, err)
}

// UpdateGroup — success path.
func TestUpdateGroup_Success(t *testing.T) {
	ls := newUserStoreMax(t)
	ctx := context.Background()
	g, err := ls.CreateGroup(ctx, &models.Group{Name: "g-upd", NameFolded: "g-upd"})
	require.NoError(t, err)
	name, folded := "g-upd-v2", "g-upd-v2"
	matched, err := ls.UpdateGroupFields(ctx, g.ID, &name, &folded, nil, time.Now())
	require.NoError(t, err)
	require.True(t, matched)
	got, err := ls.GetGroup(ctx, g.ID)
	require.NoError(t, err)
	assert.Equal(t, "g-upd-v2", got.Name)
}

// DeleteGroup — not-found path.
func TestDeleteGroup_NotFoundMax(t *testing.T) {
	ls := newUserStoreMax(t)
	err := ls.DeleteGroup(context.Background(), 9999)
	require.Error(t, err)
}

// RestoreGroup — not-found path.
func TestRestoreGroup_NotFoundMax(t *testing.T) {
	ls := newUserStoreMax(t)
	// 9999 doesn't exist at all.
	err := ls.RestoreGroup(context.Background(), 9999)
	require.Error(t, err)
}

// ListGroups — empty result.
func TestListGroups_Empty(t *testing.T) {
	ls := newUserStoreMax(t)
	groups, err := ls.ListGroups(context.Background())
	require.NoError(t, err)
	assert.Empty(t, groups)
}

// RemoveUserFromGroup — silent no-op when no row exists.
func TestRemoveUserFromGroup_Noop(t *testing.T) {
	ls := newUserStoreMax(t)
	require.NoError(t, ls.RemoveUserFromGroup(context.Background(), 1, 1, 0))
}

// AddPasswordHistory + PrunePasswordHistory.
func TestPasswordHistory_AddAndPrune(t *testing.T) {
	ls := newMaxStore(t, "pwhist", &models.User{}, &models.PasswordHistory{})
	ctx := context.Background()

	for i := range 5 {
		require.NoError(t, ls.AddPasswordHistory(ctx, 1, fmt.Sprintf("hash%d", i), time.Now()))
	}

	hashes, err := ls.RecentPasswordHashes(ctx, 1, 3)
	require.NoError(t, err)
	assert.Len(t, hashes, 3)

	// PrunePasswordHistory: keep 2, should delete 3.
	require.NoError(t, ls.PrunePasswordHistory(ctx, 1, 2))
	after, err := ls.RecentPasswordHashes(ctx, 1, 10)
	require.NoError(t, err)
	assert.Len(t, after, 2)
}

func TestPasswordHistory_LimitZero(t *testing.T) {
	ls := newMaxStore(t, "pwhist0", &models.PasswordHistory{})
	// limit=0 → nil slice, no error.
	hashes, err := ls.RecentPasswordHashes(context.Background(), 1, 0)
	require.NoError(t, err)
	assert.Nil(t, hashes)
}

func TestPrunePasswordHistory_KeepAll(t *testing.T) {
	ls := newMaxStore(t, "pwhist_keepall", &models.PasswordHistory{})
	ctx := context.Background()
	// No rows; keeping 5 must be a no-op.
	require.NoError(t, ls.PrunePasswordHistory(ctx, 1, 5))
}

// ---------------------------------------------------------------------------
// local_secrets — uncovered paths
// ---------------------------------------------------------------------------

func newSecretsStore(t *testing.T) *LocalStorage {
	t.Helper()
	ls := newMaxStore(t, "sec_"+t.Name(),
		&models.Project{}, &models.Environment{}, &models.SecretNode{},
		&models.SecretVersion{}, &models.Tag{}, &models.SecretTag{},
		&models.ShareRecord{}, &models.SecretACL{}, &models.AccessRequest{}, &models.DynamicSecretConfig{},
		&models.UserRole{}, &models.GroupRole{},
	)
	// Partial unique indexes for name uniqueness (replicate migrateDatabase).
	ls.db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_projects_name_active ON projects(name) WHERE deleted_at IS NULL")
	// Unique index on (secret_node_id, version_number) for version dedup sentinel.
	ls.db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uq_secret_versions ON secret_versions(secret_node_id, version_number)")
	return ls
}

// UpdateProject — duplicate-name error path.
// On SQLite the partial index name doesn't appear in the driver error text, so
// ErrDuplicateProjectName won't be in the chain — but an error IS returned.
func TestUpdateProject_DuplicateNameError(t *testing.T) {
	ls := newSecretsStore(t)
	ctx := context.Background()

	p1, err := ls.CreateProject(ctx, &models.Project{Name: "proj-alpha"})
	require.NoError(t, err)
	_, err = ls.CreateProject(ctx, &models.Project{Name: "proj-beta"})
	require.NoError(t, err)

	// Rename p1 to "proj-beta" — must hit the unique-name collision.
	_, err = ls.UpdateProjectFields(ctx, p1.ID, "proj-beta", p1.Description, nil, time.Now())
	require.Error(t, err)
}

// GetProject — error path (no such project).
func TestGetProject_NotFound(t *testing.T) {
	ls := newSecretsStore(t)
	_, err := ls.GetProject(context.Background(), 9999)
	require.Error(t, err)
}

// DeleteEnvironment — active-secrets blocking path and not-found path.
func TestDeleteEnvironment_BlockedBySecrets(t *testing.T) {
	ls := newSecretsStore(t)
	ctx := context.Background()

	p, err := ls.CreateProject(ctx, &models.Project{Name: "proj-delenv"})
	require.NoError(t, err)
	e, err := ls.CreateEnvironment(ctx, &models.Environment{ProjectID: p.ID, Name: "prod"})
	require.NoError(t, err)

	// Active secret in the environment blocks deletion.
	_, err = ls.CreateSecret(ctx, &models.SecretNode{
		ProjectID:     p.ID,
		EnvironmentID: e.ID,
		Name:          "KEY",
		Status:        "active",
		IsSecret:      true,
	})
	require.NoError(t, err)

	err = ls.DeleteEnvironment(ctx, e.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "active secret")
}

func TestDeleteEnvironment_NotFound(t *testing.T) {
	ls := newSecretsStore(t)
	err := ls.DeleteEnvironment(context.Background(), 9999)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// RestoreEnvironment — deleted-project guard.
func TestRestoreEnvironment_DeletedProjectGuard(t *testing.T) {
	ls := newSecretsStore(t)
	ctx := context.Background()

	p, err := ls.CreateProject(ctx, &models.Project{Name: "proj-renv"})
	require.NoError(t, err)
	e, err := ls.CreateEnvironment(ctx, &models.Environment{ProjectID: p.ID, Name: "dev"})
	require.NoError(t, err)

	// Soft-delete the environment first, then the project.
	require.NoError(t, ls.DeleteEnvironment(ctx, e.ID))
	require.NoError(t, ls.DeleteProject(ctx, p.ID))

	// Should fail because parent project is deleted.
	err = ls.RestoreEnvironment(ctx, p.ID, e.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parent project is deleted")
}

// GetSecret — not-found path.
func TestGetSecret_NotFound(t *testing.T) {
	ls := newSecretsStore(t)
	_, err := ls.GetSecret(context.Background(), 9999)
	require.Error(t, err)
}

// GetSecretsByIDs — empty IDs.
func TestGetSecretsByIDs_Empty(t *testing.T) {
	ls := newSecretsStore(t)
	result, err := ls.GetSecretsByIDs(context.Background(), nil)
	require.NoError(t, err)
	assert.Nil(t, result)
}

// UpdateSecret — success path.
func TestUpdateSecret_Success(t *testing.T) {
	ls := newSecretsStore(t)
	ctx := context.Background()

	p, _ := ls.CreateProject(ctx, &models.Project{Name: "proj-updsec"})
	e, _ := ls.CreateEnvironment(ctx, &models.Environment{ProjectID: p.ID, Name: "env"})
	s, err := ls.CreateSecret(ctx, &models.SecretNode{ProjectID: p.ID, EnvironmentID: e.ID, Name: "K", IsSecret: true})
	require.NoError(t, err)

	s.Name = "K2"
	updated, err := ls.UpdateSecret(ctx, s)
	require.NoError(t, err)
	assert.Equal(t, "K2", updated.Name)
}

// DeleteSecret — not-found path.
func TestDeleteSecret_NotFound(t *testing.T) {
	ls := newSecretsStore(t)
	err := ls.DeleteSecret(context.Background(), 9999)
	require.Error(t, err)
}

// GetSecretIncludingDeleted — deleted secret is reachable.
func TestGetSecretIncludingDeleted(t *testing.T) {
	ls := newSecretsStore(t)
	ctx := context.Background()

	p, _ := ls.CreateProject(ctx, &models.Project{Name: "proj-gsdel"})
	e, _ := ls.CreateEnvironment(ctx, &models.Environment{ProjectID: p.ID, Name: "env"})
	s, err := ls.CreateSecret(ctx, &models.SecretNode{ProjectID: p.ID, EnvironmentID: e.ID, Name: "DEL", IsSecret: true})
	require.NoError(t, err)
	require.NoError(t, ls.DeleteSecret(ctx, s.ID))

	got, err := ls.GetSecretIncludingDeleted(ctx, s.ID)
	require.NoError(t, err)
	assert.Equal(t, s.ID, got.ID)
}

// CreateSecretVersion — duplicate sentinel.
func TestCreateSecretVersion_DuplicateSentinel(t *testing.T) {
	ls := newSecretsStore(t)
	ctx := context.Background()

	p, _ := ls.CreateProject(ctx, &models.Project{Name: "proj-csvd"})
	e, _ := ls.CreateEnvironment(ctx, &models.Environment{ProjectID: p.ID, Name: "env"})
	s, _ := ls.CreateSecret(ctx, &models.SecretNode{ProjectID: p.ID, EnvironmentID: e.ID, Name: "SV", IsSecret: true})

	_, err := ls.CreateSecretVersion(ctx, &models.SecretVersion{SecretNodeID: s.ID, VersionNumber: 1, EncryptedValue: []byte("enc1")})
	require.NoError(t, err)

	_, err = ls.CreateSecretVersion(ctx, &models.SecretVersion{SecretNodeID: s.ID, VersionNumber: 1, EncryptedValue: []byte("enc2")})
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrDuplicateSecretVersion)
}

// GetLatestSecretVersion — not-found path.
func TestGetLatestSecretVersion_NotFound(t *testing.T) {
	ls := newSecretsStore(t)
	_, err := ls.GetLatestSecretVersion(context.Background(), 9999)
	require.Error(t, err)
}

// IncrementSecretReadCount — success.
func TestIncrementSecretReadCount_Success(t *testing.T) {
	ls := newSecretsStore(t)
	ctx := context.Background()

	p, _ := ls.CreateProject(ctx, &models.Project{Name: "proj-irc"})
	e, _ := ls.CreateEnvironment(ctx, &models.Environment{ProjectID: p.ID, Name: "env"})
	s, _ := ls.CreateSecret(ctx, &models.SecretNode{ProjectID: p.ID, EnvironmentID: e.ID, Name: "RCS"})
	v, _ := ls.CreateSecretVersion(ctx, &models.SecretVersion{SecretNodeID: s.ID, VersionNumber: 1, EncryptedValue: []byte("e")})

	require.NoError(t, ls.IncrementSecretReadCount(ctx, v.ID))
}

// TryIncrementSecretReadCount — capped.
func TestTryIncrementSecretReadCount_Capped(t *testing.T) {
	ls := newSecretsStore(t)
	ctx := context.Background()

	p, _ := ls.CreateProject(ctx, &models.Project{Name: "proj-tirc"})
	e, _ := ls.CreateEnvironment(ctx, &models.Environment{ProjectID: p.ID, Name: "env"})
	s, _ := ls.CreateSecret(ctx, &models.SecretNode{ProjectID: p.ID, EnvironmentID: e.ID, Name: "TRY"})
	v, _ := ls.CreateSecretVersion(ctx, &models.SecretVersion{SecretNodeID: s.ID, VersionNumber: 1, EncryptedValue: []byte("e")})

	// First increment within cap succeeds.
	ok, err := ls.TryIncrementSecretReadCount(ctx, v.ID, 1)
	require.NoError(t, err)
	assert.True(t, ok)

	// Second increment: read_count is now 1 which equals max, so fails.
	ok, err = ls.TryIncrementSecretReadCount(ctx, v.ID, 1)
	require.NoError(t, err)
	assert.False(t, ok)
}

// TryIncrementSecretNodeReadCount — success and capped.
func TestTryIncrementSecretNodeReadCount(t *testing.T) {
	ls := newSecretsStore(t)
	ctx := context.Background()

	p, _ := ls.CreateProject(ctx, &models.Project{Name: "proj-tinrc"})
	e, _ := ls.CreateEnvironment(ctx, &models.Environment{ProjectID: p.ID, Name: "env"})
	s, _ := ls.CreateSecret(ctx, &models.SecretNode{ProjectID: p.ID, EnvironmentID: e.ID, Name: "NRCS"})

	ok, err := ls.TryIncrementSecretNodeReadCount(ctx, s.ID, 1)
	require.NoError(t, err)
	assert.True(t, ok)

	ok, err = ls.TryIncrementSecretNodeReadCount(ctx, s.ID, 1)
	require.NoError(t, err)
	assert.False(t, ok)
}

// SetSecretCertNotAfter — success.
func TestSetSecretCertNotAfter(t *testing.T) {
	ls := newSecretsStore(t)
	ctx := context.Background()

	p, _ := ls.CreateProject(ctx, &models.Project{Name: "proj-certna"})
	e, _ := ls.CreateEnvironment(ctx, &models.Environment{ProjectID: p.ID, Name: "env"})
	s, _ := ls.CreateSecret(ctx, &models.SecretNode{ProjectID: p.ID, EnvironmentID: e.ID, Name: "CRT"})

	exp := time.Now().Add(time.Hour)
	require.NoError(t, ls.SetSecretCertNotAfter(ctx, s.ID, &exp))
	require.NoError(t, ls.SetSecretCertNotAfter(ctx, s.ID, nil))
}

// ListLiveSecretNamesByProject — empty ids.
func TestListLiveSecretNamesByProject_EmptyIDs(t *testing.T) {
	ls := newSecretsStore(t)
	rows, truncated, err := ls.ListLiveSecretNamesByProject(context.Background(), nil, 10)
	require.NoError(t, err)
	assert.Nil(t, rows)
	assert.False(t, truncated)
}

// requireLiveProject / requireLiveEnvironment via RestoreSecret (indirectly).
func TestRestoreSecret_DeletedProjectGuard(t *testing.T) {
	ls := newSecretsStore(t)
	ctx := context.Background()

	p, _ := ls.CreateProject(ctx, &models.Project{Name: "proj-rsg"})
	e, _ := ls.CreateEnvironment(ctx, &models.Environment{ProjectID: p.ID, Name: "env"})
	s, _ := ls.CreateSecret(ctx, &models.SecretNode{ProjectID: p.ID, EnvironmentID: e.ID, Name: "RSG"})

	// Delete the secret then the project.
	require.NoError(t, ls.DeleteSecret(ctx, s.ID))
	require.NoError(t, ls.DeleteProject(ctx, p.ID))

	// RestoreSecret should fail because project is deleted.
	err := ls.RestoreSecret(ctx, s.ID)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_memberships — uncovered paths
// ---------------------------------------------------------------------------

func newMembStore(t *testing.T) *LocalStorage {
	t.Helper()
	ls := newMaxStore(t, "memb_"+t.Name(),
		&models.ProjectMembership{}, &models.User{}, &models.Project{})
	// Replicate the partial unique index from ensureProjectMembershipIndex.
	ls.db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_project_memberships_active ON project_memberships(project_id, user_id) WHERE state <> 'revoked'")
	return ls
}

// CreateProjectMembership — duplicate sentinel.
func TestCreateProjectMembership_Duplicate(t *testing.T) {
	ls := newMembStore(t)
	ctx := context.Background()

	m := &models.ProjectMembership{ProjectID: 1, UserID: 1, State: "active"}
	_, err := ls.CreateProjectMembership(ctx, m)
	require.NoError(t, err)

	_, err = ls.CreateProjectMembership(ctx, &models.ProjectMembership{ProjectID: 1, UserID: 1, State: "active"})
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrDuplicateActiveMembership)
}

// GetProjectMembership — not-found path.
func TestGetProjectMembership_NotFound(t *testing.T) {
	ls := newMembStore(t)
	_, err := ls.GetProjectMembership(context.Background(), 9999)
	require.Error(t, err)
}

// CountProjectMembershipsByUsers — empty ids.
func TestCountProjectMembershipsByUsers_Empty(t *testing.T) {
	ls := newMembStore(t)
	counts, err := ls.CountProjectMembershipsByUsers(context.Background(), nil)
	require.NoError(t, err)
	assert.Empty(t, counts)
}

// ---------------------------------------------------------------------------
// local_notifications — uncovered paths
// ---------------------------------------------------------------------------

func newNotifsStore(t *testing.T) *LocalStorage {
	t.Helper()
	return newMaxStore(t, "notif_"+t.Name(), &models.Notification{}, &models.User{})
}

// CountUnreadNotifications — zero result.
func TestCountUnreadNotifications_Zero(t *testing.T) {
	ls := newNotifsStore(t)
	n, err := ls.CountUnreadNotifications(context.Background(), 999)
	require.NoError(t, err)
	assert.Zero(t, n)
}

// MarkNotificationRead — not-found path.
func TestMarkNotificationRead_NotFound(t *testing.T) {
	ls := newNotifsStore(t)
	err := ls.MarkNotificationRead(context.Background(), 9999, 1)
	require.Error(t, err)
}

// MarkAllNotificationsRead — zero rows is not an error.
func TestMarkAllNotificationsRead_NoRows(t *testing.T) {
	ls := newNotifsStore(t)
	require.NoError(t, ls.MarkAllNotificationsRead(context.Background(), 999))
}

// HasUnreadNotification — false (no matching row).
func TestHasUnreadNotification_False(t *testing.T) {
	ls := newNotifsStore(t)
	ok, err := ls.HasUnreadNotification(context.Background(), 1, "rotation_reminder", 1)
	require.NoError(t, err)
	assert.False(t, ok)
}

// UpdateNotification — not-found path.
func TestUpdateNotification_NotFound(t *testing.T) {
	ls := newNotifsStore(t)
	err := ls.UpdateNotification(context.Background(), &models.Notification{ID: 9999, UserID: 1, Title: "x", Message: "y"})
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_access_activity — uncovered branch (empty userID zero-skip)
// ---------------------------------------------------------------------------

func newAAStore(t *testing.T) *LocalStorage {
	t.Helper()
	return newMaxStore(t, "aa_"+t.Name(), &models.AuditEvent{})
}

// lastUserActivityByEventTypes — empty result (no events).
func TestLastUserActivityByEventTypes_NoEvents(t *testing.T) {
	ls := newAAStore(t)
	m, err := ls.LastUserSecretActivity(context.Background(), 1, time.Time{})
	require.NoError(t, err)
	assert.Empty(t, m)
}

// ---------------------------------------------------------------------------
// local_access_review_campaigns — uncovered paths
// ---------------------------------------------------------------------------

func newARCStoreMax(t *testing.T) *LocalStorage {
	t.Helper()
	return newMaxStore(t, "arc_"+t.Name(),
		&models.AccessReviewCampaign{}, &models.AccessReviewItem{})
}

// CreateAccessReviewCampaign — error path (wrong table).
func TestCreateAccessReviewCampaign_ErrorPath(t *testing.T) {
	// DB without the table → should fail.
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	ls := NewLocalStorage(db)
	_, err = ls.CreateAccessReviewCampaign(context.Background(), &models.AccessReviewCampaign{})
	require.Error(t, err)
}

// ListAccessReviewCampaigns — empty result.
func TestListAccessReviewCampaigns_Empty(t *testing.T) {
	ls := newARCStoreMax(t)
	rows, err := ls.ListAccessReviewCampaigns(context.Background(), 999)
	require.NoError(t, err)
	assert.Empty(t, rows)
}

// GetOpenAccessReviewCampaign — no-open-campaign nil result.
func TestGetOpenAccessReviewCampaign_NilWhenNone(t *testing.T) {
	ls := newARCStoreMax(t)
	got, err := ls.GetOpenAccessReviewCampaign(context.Background(), 1)
	require.NoError(t, err)
	assert.Nil(t, got)
}

// GetLatestClosedAccessReviewCampaign — no-closed-campaign nil result.
func TestGetLatestClosedAccessReviewCampaign_NilWhenNone(t *testing.T) {
	ls := newARCStoreMax(t)
	got, err := ls.GetLatestClosedAccessReviewCampaign(context.Background(), 1)
	require.NoError(t, err)
	assert.Nil(t, got)
}

// UpdateAccessReviewCampaign — already-closed (conditional miss).
func TestUpdateAccessReviewCampaign_AlreadyClosed(t *testing.T) {
	ls := newARCStoreMax(t)
	ctx := context.Background()

	c, err := ls.CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{ProjectID: 1, State: "closed"})
	require.NoError(t, err)

	c.State = "closed"
	ok, err := ls.UpdateAccessReviewCampaign(ctx, c)
	require.NoError(t, err)
	assert.False(t, ok, "conditional UPDATE must miss because campaign is not open")
}

// CreateAccessReviewItems — empty slice no-op.
func TestCreateAccessReviewItems_EmptySlice(t *testing.T) {
	ls := newARCStoreMax(t)
	require.NoError(t, ls.CreateAccessReviewItems(context.Background(), nil))
}

// ListAccessReviewItems — empty result.
func TestListAccessReviewItems_Empty(t *testing.T) {
	ls := newARCStoreMax(t)
	items, err := ls.ListAccessReviewItems(context.Background(), 1)
	require.NoError(t, err)
	assert.Empty(t, items)
}

// CountPendingAccessReviewItems — zero result.
func TestCountPendingAccessReviewItems_Zero(t *testing.T) {
	ls := newARCStoreMax(t)
	n, err := ls.CountPendingAccessReviewItems(context.Background(), 1)
	require.NoError(t, err)
	assert.Zero(t, n)
}

// UpdateAccessReviewItem — conditional miss (wrong campaign state).
func TestUpdateAccessReviewItem_ConditionalMiss(t *testing.T) {
	ls := newARCStoreMax(t)
	ctx := context.Background()

	c, err := ls.CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{ProjectID: 1, State: "closed"})
	require.NoError(t, err)
	err = ls.CreateAccessReviewItems(ctx, []*models.AccessReviewItem{
		{CampaignID: c.ID, PrincipalID: 2, RoleID: 3, Decision: "pending"},
	})
	require.NoError(t, err)

	// Retrieve the created item.
	items, err := ls.ListAccessReviewItems(ctx, c.ID)
	require.NoError(t, err)
	require.Len(t, items, 1)

	items[0].Decision = "attested"
	ok, err := ls.UpdateAccessReviewItem(ctx, items[0])
	require.NoError(t, err)
	assert.False(t, ok, "campaign not open → conditional UPDATE must miss")
}

// ---------------------------------------------------------------------------
// local_audit — uncovered paths
// ---------------------------------------------------------------------------

func newAuditStoreMax(t *testing.T) *LocalStorage {
	t.Helper()
	return newMaxStore(t, "aud_"+t.Name(),
		&models.AuditEvent{}, &models.AnomalyAlert{},
		&models.SecretAccessLog{}, &models.SecretNode{}, &models.Project{},
		&models.Environment{},
	)
}

// MostAccessedSecrets — empty result.
func TestMostAccessedSecrets_Empty(t *testing.T) {
	ls := newAuditStoreMax(t)
	var pid uint = 1
	result, err := ls.MostAccessedSecrets(context.Background(), &pid, nil, time.Now().Add(-time.Hour), 10)
	require.NoError(t, err)
	assert.Empty(t, result)
}

// UnusedSecrets — empty result.
func TestUnusedSecrets_Empty(t *testing.T) {
	ls := newAuditStoreMax(t)
	var pid uint = 1
	result, err := ls.UnusedSecrets(context.Background(), &pid, nil, time.Now())
	require.NoError(t, err)
	assert.Empty(t, result)
}

// AuditRetentionStats — empty result.
func TestAuditRetentionStats_EmptyMax(t *testing.T) {
	ls := newAuditStoreMax(t)
	stats, err := ls.AuditRetentionStats(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, stats) // Should return a valid zero struct.
}

// CreateAnomalyAlert — missing table path.
func TestCreateAnomalyAlert_Succeeds(t *testing.T) {
	ls := newAuditStoreMax(t)
	ctx := context.Background()
	now := time.Now()
	err := ls.CreateAnomalyAlert(ctx, &models.AnomalyAlert{
		SecretNodeID: 1,
		AlertType:    "unusual_access",
		DetectedAt:   now,
		Severity:     "high",
		Description:  "test",
	})
	require.NoError(t, err)
}

// AcknowledgeAnomalyAlert — not-found path.
func TestAcknowledgeAnomalyAlert_NotFound(t *testing.T) {
	ls := newAuditStoreMax(t)
	err := ls.AcknowledgeAnomalyAlert(context.Background(), 9999, 1, time.Now())
	require.Error(t, err)
}

// ListUnalertedAnomalyAlerts — empty result.
func TestListUnalertedAnomalyAlerts_Empty(t *testing.T) {
	ls := newAuditStoreMax(t)
	alerts, err := ls.ListUnalertedAnomalyAlerts(context.Background())
	require.NoError(t, err)
	assert.Empty(t, alerts)
}

// PrincipalSecretFirstSeen — empty result.
func TestPrincipalSecretFirstSeen_Empty(t *testing.T) {
	ls := newAuditStoreMax(t)
	result, err := ls.PrincipalSecretFirstSeen(context.Background(), time.Now().Add(-time.Hour))
	require.NoError(t, err)
	assert.Empty(t, result)
}

// CountSecretReadsBySecretIDs — empty ids.
func TestCountSecretReadsBySecretIDs_Empty(t *testing.T) {
	ls := newAuditStoreMax(t)
	result, err := ls.CountSecretReadsBySecretIDs(context.Background(), nil, time.Now().Add(-time.Hour))
	require.NoError(t, err)
	assert.Empty(t, result)
}

// CountUnusedSecretsByProject — zero result.
func TestCountUnusedSecretsByProject_Zero(t *testing.T) {
	ls := newAuditStoreMax(t)
	counts, err := ls.CountUnusedSecretsByProject(context.Background(), []uint{1}, time.Now())
	require.NoError(t, err)
	assert.Empty(t, counts)
}

// GetAuditLogs — descending mode (non-cursor).
func TestGetAuditLogs_DescendingMode(t *testing.T) {
	ls := newAuditStoreMax(t)
	f := &storage.AuditFilter{ProjectID: nil, Page: 1, PageSize: 10}
	logs, total, err := ls.GetAuditLogs(context.Background(), f)
	require.NoError(t, err)
	assert.Zero(t, total)
	assert.Empty(t, logs)
}

// ---------------------------------------------------------------------------
// local_audit_checkpoint — uncovered paths
// ---------------------------------------------------------------------------

func newCheckpointStoreMax(t *testing.T) *LocalStorage {
	t.Helper()
	return newMaxStore(t, "ckpt_"+t.Name(), &models.AuditCheckpoint{}, &models.AuditEvent{})
}

// LatestAuditCheckpoint — not-found returns nil.
func TestLatestAuditCheckpoint_None(t *testing.T) {
	ls := newCheckpointStoreMax(t)
	got, err := ls.LatestAuditCheckpoint(context.Background())
	require.NoError(t, err)
	assert.Nil(t, got)
}

// AuditEntryHashByID — not-found path.
func TestAuditEntryHashByID_NotFound(t *testing.T) {
	ls := newCheckpointStoreMax(t)
	_, found, err := ls.AuditEntryHashByID(context.Background(), 9999)
	require.NoError(t, err)
	assert.False(t, found)
}

// ---------------------------------------------------------------------------
// local_audit_checkpoint_lock — extra coverage (fn error)
// ---------------------------------------------------------------------------

func TestWithAuditCheckpointLock_FnError(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	ls := NewLocalStorage(db)

	sentinel := fmt.Errorf("lock-fn-error")
	err = ls.WithAuditCheckpointLock(context.Background(), func(context.Context) error { return sentinel })
	require.ErrorIs(t, err, sentinel)
}

// ---------------------------------------------------------------------------
// local_audit_chain — LogAuditEvent error (table missing)
// ---------------------------------------------------------------------------

func TestLogAuditEvent_MissingTable(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	ls := NewLocalStorage(db)

	// No migration → AuditEvent table absent → should return an error.
	err = ls.LogAuditEvent(context.Background(), &models.AuditEvent{EventType: "test"})
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_purge — uncovered paths
// ---------------------------------------------------------------------------

func newPurgeStore(t *testing.T) *LocalStorage {
	t.Helper()
	return newMaxStore(t, "purge_"+t.Name(), append([]any{
		&models.User{}, &models.UserRole{}, &models.UserGroup{},
		&models.ShareRecord{}, &models.SecretACL{}, &models.AccessRequest{}, &models.PersonalAccessToken{}, &models.Session{},
		&models.Project{}, &models.Environment{},
		&models.SecretNode{}, &models.SecretVersion{}, &models.SecretDependency{},
		&models.GroupRole{}, &models.Group{}, &models.MachineIdentityRole{},
		&models.AnomalyAlert{},
		&models.AccessReviewCampaign{}, &models.AccessReviewItem{},
		&models.BreakGlassActivation{},
		&models.AccessRequest{}, &models.AccessRequestApproval{},
		&models.DynamicSecretConfig{},
	}, secretPurgeCascadeModels()...)...)
}

// PurgeDeletedUsersBefore — nothing to purge.
func TestPurgeDeletedUsersBefore_NothingToPurgeMax(t *testing.T) {
	ls := newPurgeStore(t)
	n, err := ls.PurgeDeletedUsersBefore(context.Background(), time.Now())
	require.NoError(t, err)
	assert.Zero(t, n)
}

// PurgeDeletedUsersBefore — deletes eligible users and cascades.
func TestPurgeDeletedUsersBefore_DeletesUsers(t *testing.T) {
	ls := newPurgeStore(t)
	ctx := context.Background()

	u, err := ls.CreateUser(ctx, &models.User{Email: "purge@test.com", EmailFolded: "purge@test.com", Username: "purgeMe", UsernameFolded: "purgeme"})
	require.NoError(t, err)
	require.NoError(t, ls.DeleteUser(ctx, u.ID))

	n, err := ls.PurgeDeletedUsersBefore(ctx, time.Now().Add(time.Hour))
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)
}

// PurgeDeletedProjectsBefore — nothing to purge.
func TestPurgeDeletedProjectsBefore_NothingToPurge(t *testing.T) {
	ls := newPurgeStore(t)
	n, err := ls.PurgeDeletedProjectsBefore(context.Background(), time.Now())
	require.NoError(t, err)
	assert.Zero(t, n)
}

// PurgeDeletedProjectsBefore — deletes eligible projects and cascades role grants.
func TestPurgeDeletedProjectsBefore_DeletesProjects(t *testing.T) {
	ls := newPurgeStore(t)
	ctx := context.Background()

	p, err := ls.CreateProject(ctx, &models.Project{Name: "purge-me-proj"})
	require.NoError(t, err)
	require.NoError(t, ls.DeleteProject(ctx, p.ID))

	n, err := ls.PurgeDeletedProjectsBefore(ctx, time.Now().Add(time.Hour))
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)
}

// PurgeDeletedSecretsBefore — nothing to purge.
func TestPurgeDeletedSecretsBefore_NothingToPurge(t *testing.T) {
	ls := newPurgeStore(t)
	n, err := ls.PurgeDeletedSecretsBefore(context.Background(), time.Now())
	require.NoError(t, err)
	assert.Zero(t, n)
}

// PurgeDeletedSecretsBefore — deletes eligible secrets, versions, and dependency edges.
func TestPurgeDeletedSecretsBefore_DeletesSecrets(t *testing.T) {
	ls := newPurgeStore(t)
	ctx := context.Background()

	p, _ := ls.CreateProject(ctx, &models.Project{Name: "proj-psb"})
	e, _ := ls.CreateEnvironment(ctx, &models.Environment{ProjectID: p.ID, Name: "env"})
	s, _ := ls.CreateSecret(ctx, &models.SecretNode{ProjectID: p.ID, EnvironmentID: e.ID, Name: "TO_PURGE", IsSecret: true})
	_, _ = ls.CreateSecretVersion(ctx, &models.SecretVersion{SecretNodeID: s.ID, VersionNumber: 1, EncryptedValue: []byte("enc")})
	require.NoError(t, ls.DeleteSecret(ctx, s.ID))

	n, err := ls.PurgeDeletedSecretsBefore(ctx, time.Now().Add(time.Hour))
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)
}

// DeleteAnomalyAlertsBefore — zero rows.
func TestDeleteAnomalyAlertsBefore_NoAlerts(t *testing.T) {
	ls := newPurgeStore(t)
	n, err := ls.DeleteAnomalyAlertsBefore(context.Background(), time.Now(), time.Now())
	require.NoError(t, err)
	assert.Zero(t, n)
}

// DeleteClosedAccessReviewsBefore — zero rows.
func TestDeleteClosedAccessReviewsBefore_NoRows(t *testing.T) {
	ls := newPurgeStore(t)
	n1, n2, err := ls.DeleteClosedAccessReviewsBefore(context.Background(), time.Now())
	require.NoError(t, err)
	assert.Zero(t, n1)
	assert.Zero(t, n2)
}

// DeleteExpiredBreakGlassBefore — zero rows.
func TestDeleteExpiredBreakGlassBefore_NoRows(t *testing.T) {
	ls := newPurgeStore(t)
	n, err := ls.DeleteExpiredBreakGlassBefore(context.Background(), time.Now())
	require.NoError(t, err)
	assert.Zero(t, n)
}

// DeleteResolvedAccessRequestsBefore — zero rows.
func TestDeleteResolvedAccessRequestsBefore_NoRows(t *testing.T) {
	ls := newPurgeStore(t)
	n1, n2, err := ls.DeleteResolvedAccessRequestsBefore(context.Background(), time.Now())
	require.NoError(t, err)
	assert.Zero(t, n1)
	assert.Zero(t, n2)
}

// ---------------------------------------------------------------------------
// local_rbac — uncovered paths
// ---------------------------------------------------------------------------

func newRBACStoreMax(t *testing.T) *LocalStorage {
	t.Helper()
	return newMaxStore(t, "rbac_"+t.Name(),
		&models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.GroupRole{}, &models.User{}, &models.Group{}, &models.UserGroup{},
		&models.Project{}, &models.Environment{},
		// SystemMetadata: AssignPermissionToRole/RemovePermissionFromRole/
		// DeleteRole bump the PERF-3 PR-2 role_permissions cache generation
		// (a system_metadata row) in the same transaction as the real write.
		&models.SystemMetadata{},
	)
}

// CreatePermission — success.
func TestCreatePermission(t *testing.T) {
	ls := newRBACStoreMax(t)
	p, err := ls.CreatePermission(context.Background(), &models.Permission{Name: "test.perm", Description: "desc"})
	require.NoError(t, err)
	require.NotZero(t, p.ID)
}

// CreateRole — success and GetRole not-found.
func TestCreateRoleAndGetNotFound(t *testing.T) {
	ls := newRBACStoreMax(t)
	ctx := context.Background()

	testerName, err := identity.NewFoldedName("tester")
	require.NoError(t, err)
	role, err := ls.CreateRole(ctx, testerName, "d")
	require.NoError(t, err)
	require.NotZero(t, role.ID)

	_, err = ls.GetRole(ctx, 9999)
	require.Error(t, err)
}

// GetRoleByName — not-found.
func TestGetRoleByName_NotFound(t *testing.T) {
	ls := newRBACStoreMax(t)
	_, err := ls.GetRoleByName(context.Background(), "no-such-role")
	require.Error(t, err)
}

// UpdateRole — success.
func TestUpdateRole(t *testing.T) {
	ls := newRBACStoreMax(t)
	ctx := context.Background()
	updRoleName, err := identity.NewFoldedName("upd-role")
	require.NoError(t, err)
	role, _ := ls.CreateRole(ctx, updRoleName, "")
	role.Description = "updated"
	got, err := ls.UpdateRole(ctx, role)
	require.NoError(t, err)
	assert.Equal(t, "updated", got.Description)
}

// DeleteRole — not-found.
func TestDeleteRole_NotFound(t *testing.T) {
	ls := newRBACStoreMax(t)
	_, err := ls.DeleteRole(context.Background(), 9999)
	require.Error(t, err)
}

// ListRoles — empty.
func TestListRoles_Empty(t *testing.T) {
	ls := newRBACStoreMax(t)
	roles, err := ls.ListRoles(context.Background())
	require.NoError(t, err)
	assert.Empty(t, roles)
}

// AssignPermissionToRole — success.
func TestAssignPermissionToRole(t *testing.T) {
	ls := newRBACStoreMax(t)
	ctx := context.Background()

	r1Name, err := identity.NewFoldedName("r1")
	require.NoError(t, err)
	role, _ := ls.CreateRole(ctx, r1Name, "")
	perm, _ := ls.CreatePermission(ctx, &models.Permission{Name: "do.thing"})
	require.NoError(t, ls.AssignPermissionToRole(ctx, role.ID, perm.ID))
}

// RemoveAllProjectRoleGrants — success (no rows = no error).
func TestRemoveAllProjectRoleGrants(t *testing.T) {
	ls := newRBACStoreMax(t)
	require.NoError(t, ls.RemoveAllProjectRoleGrants(context.Background(), 1, 1))
}

// GetUserRoles — empty.
func TestGetUserRoles_Empty(t *testing.T) {
	ls := newRBACStoreMax(t)
	roles, err := ls.GetUserRoles(context.Background(), 999)
	require.NoError(t, err)
	assert.Empty(t, roles)
}

// assignUserRole — already-assigned live grant → error.
func TestAssignRole_AlreadyAssigned(t *testing.T) {
	ls := newRBACStoreMax(t)
	ctx := context.Background()
	dupRoleName, err := identity.NewFoldedName("dup-role")
	require.NoError(t, err)
	role, _ := ls.CreateRole(ctx, dupRoleName, "")
	scope := storage.Scope{ProjectID: 1}

	require.NoError(t, ls.AssignRole(ctx, 2, role.ID, scope))
	err = ls.AssignRole(ctx, 2, role.ID, scope)
	require.Error(t, err) // already assigned
}

// assignUserRole — expired grant is replaced.
func TestAssignRole_ExpiredGrantIsReplaced(t *testing.T) {
	ls := newRBACStoreMax(t)
	ctx := context.Background()
	expRoleName, err := identity.NewFoldedName("exp-role")
	require.NoError(t, err)
	role, _ := ls.CreateRole(ctx, expRoleName, "")
	scope := storage.Scope{ProjectID: 5}

	past := time.Now().Add(-time.Hour)
	require.NoError(t, ls.AssignRoleWithExpiry(ctx, 3, role.ID, scope, past))
	// Re-assigning over an already-expired grant should succeed.
	require.NoError(t, ls.AssignRole(ctx, 3, role.ID, scope))
}

// RemoveRole — not-assigned error.
func TestRemoveRole_NotAssigned(t *testing.T) {
	ls := newRBACStoreMax(t)
	err := ls.RemoveRole(context.Background(), 1, 1, storage.Scope{})
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrRoleNotAssigned)
}

// GetUserRoleIDsAt — empty.
func TestGetUserRoleIDsAt_Empty(t *testing.T) {
	ls := newRBACStoreMax(t)
	ids, err := ls.GetUserRoleIDsAt(context.Background(), 999, storage.Scope{})
	require.NoError(t, err)
	assert.Empty(t, ids)
}

// ListPermissions — empty.
func TestListPermissions_Empty(t *testing.T) {
	ls := newRBACStoreMax(t)
	perms, err := ls.ListPermissions(context.Background())
	require.NoError(t, err)
	assert.Empty(t, perms)
}

// GetPermission — not-found.
func TestGetPermission_NotFound(t *testing.T) {
	ls := newRBACStoreMax(t)
	_, err := ls.GetPermission(context.Background(), 9999)
	require.Error(t, err)
}

// GetRolePermissions — empty result.
func TestGetRolePermissions_Empty(t *testing.T) {
	ls := newRBACStoreMax(t)
	perms, err := ls.GetRolePermissions(context.Background(), 9999)
	require.NoError(t, err)
	assert.Empty(t, perms)
}

// RemovePermissionFromRole — not-found path.
func TestRemovePermissionFromRole_NotFound(t *testing.T) {
	ls := newRBACStoreMax(t)
	err := ls.RemovePermissionFromRole(context.Background(), 9999, 9999)
	require.Error(t, err)
}

// GetGroupRoles — empty.
func TestGetGroupRoles_Empty(t *testing.T) {
	ls := newRBACStoreMax(t)
	roles, err := ls.GetGroupRoles(context.Background(), 999)
	require.NoError(t, err)
	assert.Empty(t, roles)
}

// GetGroupRoleGrants — empty.
func TestGetGroupRoleGrants_Empty(t *testing.T) {
	ls := newRBACStoreMax(t)
	grants, err := ls.GetGroupRoleGrants(context.Background(), 999)
	require.NoError(t, err)
	assert.Empty(t, grants)
}

// ListGroupRoleAssignments — empty.
func TestListGroupRoleAssignments_Empty(t *testing.T) {
	ls := newRBACStoreMax(t)
	assignments, err := ls.ListGroupRoleAssignments(context.Background(), 999)
	require.NoError(t, err)
	assert.Empty(t, assignments)
}

// assignGroupRole — already-assigned live grant → error.
func TestAssignRoleToGroup_AlreadyAssigned(t *testing.T) {
	ls := newRBACStoreMax(t)
	ctx := context.Background()
	groleName, err := identity.NewFoldedName("grole")
	require.NoError(t, err)
	role, _ := ls.CreateRole(ctx, groleName, "")
	scope := storage.Scope{ProjectID: 7}

	require.NoError(t, ls.AssignRoleToGroup(ctx, 4, role.ID, scope))
	err = ls.AssignRoleToGroup(ctx, 4, role.ID, scope)
	require.Error(t, err)
}

// RemoveRoleFromGroup — not-assigned.
func TestRemoveRoleFromGroup_NotAssigned(t *testing.T) {
	ls := newRBACStoreMax(t)
	err := ls.RemoveRoleFromGroup(context.Background(), 1, 1, storage.Scope{})
	require.Error(t, err)
}

// GetUserPermissions — empty.
func TestGetUserPermissions_Empty(t *testing.T) {
	ls := newRBACStoreMax(t)
	perms, err := ls.GetUserPermissions(context.Background(), 999)
	require.NoError(t, err)
	assert.Empty(t, perms)
}

// GetUserGroupPermissions — empty.
func TestGetUserGroupPermissions_Empty(t *testing.T) {
	ls := newRBACStoreMax(t)
	perms, err := ls.GetUserGroupPermissions(context.Background(), 999)
	require.NoError(t, err)
	assert.Empty(t, perms)
}

// ListProjectMembers — empty.
func TestListProjectMembers_Empty(t *testing.T) {
	ls := newRBACStoreMax(t)
	members, err := ls.ListProjectMembers(context.Background(), 999)
	require.NoError(t, err)
	assert.Empty(t, members)
}

// GetUserGroupRoleIDsAt — empty.
func TestGetUserGroupRoleIDsAt_Empty(t *testing.T) {
	ls := newRBACStoreMax(t)
	ids, err := ls.GetUserGroupRoleIDsAt(context.Background(), 999, storage.Scope{})
	require.NoError(t, err)
	assert.Empty(t, ids)
}

// GetUserRoleIDsExact — empty.
func TestGetUserRoleIDsExact_Empty(t *testing.T) {
	ls := newRBACStoreMax(t)
	ids, err := ls.GetUserRoleIDsExact(context.Background(), 999, storage.Scope{})
	require.NoError(t, err)
	assert.Empty(t, ids)
}

// DeleteExpiredRoleGrants — no grants → empty slice.
func TestDeleteExpiredRoleGrants_None(t *testing.T) {
	ls := newRBACStoreMax(t)
	grants, err := ls.DeleteExpiredRoleGrants(context.Background(), time.Now())
	require.NoError(t, err)
	assert.Empty(t, grants)
}

// ListGlobalAdminAssignmentsForUpdate — empty.
func TestListGlobalAdminAssignmentsForUpdate_Empty(t *testing.T) {
	ls := newRBACStoreMax(t)
	assignments, err := ls.ListGlobalAdminAssignmentsForUpdate(context.Background(), nil)
	require.NoError(t, err)
	assert.Empty(t, assignments)
}

// ---------------------------------------------------------------------------
// local_sharing — uncovered paths
// ---------------------------------------------------------------------------

func newSharingStoreMax(t *testing.T) *LocalStorage {
	t.Helper()
	return newMaxStore(t, "shr_"+t.Name(),
		&models.ShareRecord{}, &models.SecretNode{}, &models.Project{},
		&models.Environment{}, &models.User{}, &models.Group{},
	)
}

// GetShareRecord — not-found.
func TestGetShareRecord_NotFound(t *testing.T) {
	ls := newSharingStoreMax(t)
	_, err := ls.GetShareRecord(context.Background(), 9999)
	require.Error(t, err)
}

// DeleteShareRecord — not-found.
func TestDeleteShareRecord_NotFound(t *testing.T) {
	ls := newSharingStoreMax(t)
	err := ls.DeleteShareRecord(context.Background(), 9999)
	require.Error(t, err)
}

// ListSharesBySecretIDs — empty ids.
func TestListSharesBySecretIDs_Empty(t *testing.T) {
	ls := newSharingStoreMax(t)
	shares, err := ls.ListSharesBySecretIDs(context.Background(), nil, time.Now())
	require.NoError(t, err)
	assert.Empty(t, shares)
}

// ListSharesByUser — empty.
func TestListSharesByUser_Empty(t *testing.T) {
	ls := newSharingStoreMax(t)
	shares, err := ls.ListSharesByUser(context.Background(), 999, time.Now())
	require.NoError(t, err)
	assert.Empty(t, shares)
}

// ListSharesByOwner — empty.
func TestListSharesByOwner_Empty(t *testing.T) {
	ls := newSharingStoreMax(t)
	shares, err := ls.ListSharesByOwner(context.Background(), 999, time.Now())
	require.NoError(t, err)
	assert.Empty(t, shares)
}

// ListSharesByGroup — empty.
func TestListSharesByGroup_Empty(t *testing.T) {
	ls := newSharingStoreMax(t)
	shares, err := ls.ListSharesByGroup(context.Background(), 999, time.Now())
	require.NoError(t, err)
	assert.Empty(t, shares)
}

// ---------------------------------------------------------------------------
// local_invitations — uncovered paths
// ---------------------------------------------------------------------------

func newInvStore(t *testing.T) *LocalStorage {
	t.Helper()
	return newMaxStore(t, "inv_"+t.Name(),
		&models.ProjectInvitation{}, &models.AccessRequest{}, &models.AccessRequestApproval{},
	)
}

// CreateProjectInvitation — error path (table absent).
func TestCreateProjectInvitation_Error(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	ls := NewLocalStorage(db)
	_, err = ls.CreateProjectInvitation(context.Background(), &models.ProjectInvitation{})
	require.Error(t, err)
}

// GetProjectInvitation — not-found.
func TestGetProjectInvitation_NotFound(t *testing.T) {
	ls := newInvStore(t)
	_, err := ls.GetProjectInvitation(context.Background(), 9999)
	require.Error(t, err)
}

// UpdateProjectInvitation — success.
func TestUpdateProjectInvitation_Success(t *testing.T) {
	ls := newInvStore(t)
	ctx := context.Background()

	inv, err := ls.CreateProjectInvitation(ctx, &models.ProjectInvitation{
		ProjectID: 1, Email: "inv@test.com", State: "pending",
	})
	require.NoError(t, err)
	inv.State = "accepted"
	_, err = ls.UpdateProjectInvitation(ctx, inv)
	require.NoError(t, err)
}

// ListProjectInvitations — empty.
func TestListProjectInvitations_Empty(t *testing.T) {
	ls := newInvStore(t)
	invs, err := ls.ListProjectInvitations(context.Background(), 999)
	require.NoError(t, err)
	assert.Empty(t, invs)
}

// CreateAccessRequest — error path (table absent).
func TestCreateAccessRequest_Error(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	ls := NewLocalStorage(db)
	_, err = ls.CreateAccessRequest(context.Background(), &models.AccessRequest{})
	require.Error(t, err)
}

// GetAccessRequest — not-found.
func TestGetAccessRequest_NotFound(t *testing.T) {
	ls := newInvStore(t)
	_, err := ls.GetAccessRequest(context.Background(), 9999)
	require.Error(t, err)
}

// UpdateAccessRequest — success.
func TestUpdateAccessRequest_Success(t *testing.T) {
	ls := newInvStore(t)
	ctx := context.Background()

	req, err := ls.CreateAccessRequest(ctx, &models.AccessRequest{
		ProjectID: 1, UserID: 2, State: "pending",
	})
	require.NoError(t, err)
	req.State = "approved"
	_, err = ls.UpdateAccessRequest(ctx, req)
	require.NoError(t, err)
}

// ListAccessRequests — empty.
func TestListAccessRequests_Empty(t *testing.T) {
	ls := newInvStore(t)
	reqs, err := ls.ListAccessRequests(context.Background(), 999)
	require.NoError(t, err)
	assert.Empty(t, reqs)
}

// CreateAccessRequestApproval — error path.
func TestCreateAccessRequestApproval_Error(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	ls := NewLocalStorage(db)
	err = ls.CreateAccessRequestApproval(context.Background(), &models.AccessRequestApproval{})
	require.Error(t, err)
}

// ListAccessRequestApprovals — empty.
func TestListAccessRequestApprovals_Empty(t *testing.T) {
	ls := newInvStore(t)
	approvals, err := ls.ListAccessRequestApprovals(context.Background(), 999)
	require.NoError(t, err)
	assert.Empty(t, approvals)
}

// ---------------------------------------------------------------------------
// local_risk_exceptions — uncovered paths
// ---------------------------------------------------------------------------

func newRiskExcStore(t *testing.T) *LocalStorage {
	t.Helper()
	return newMaxStore(t, "riskexc_"+t.Name(), &models.RiskException{})
}

// CreateRiskException — error path.
func TestCreateRiskException_Error(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	ls := NewLocalStorage(db)
	_, err = ls.CreateRiskException(context.Background(), &models.RiskException{})
	require.Error(t, err)
}

// ListRiskExceptions — empty.
func TestListRiskExceptions_Empty(t *testing.T) {
	ls := newRiskExcStore(t)
	excs, err := ls.ListRiskExceptions(context.Background(), false)
	require.NoError(t, err)
	assert.Empty(t, excs)
}

// GetRiskException — not-found.
func TestGetRiskException_NotFound(t *testing.T) {
	ls := newRiskExcStore(t)
	_, err := ls.GetRiskException(context.Background(), 9999)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_rotation_policies — uncovered paths
// ---------------------------------------------------------------------------

func newRotPolStore(t *testing.T) *LocalStorage {
	t.Helper()
	return newMaxStore(t, "rotpol_"+t.Name(), &models.RotationPolicy{})
}

// GetRotationPolicy — not-found.
func TestGetRotationPolicy_NotFound(t *testing.T) {
	ls := newRotPolStore(t)
	_, err := ls.GetRotationPolicy(context.Background(), 9999)
	require.Error(t, err)
}

// ListRotationPolicies — empty result.
func TestListRotationPolicies_Empty(t *testing.T) {
	ls := newRotPolStore(t)
	policies, err := ls.ListRotationPolicies(context.Background(), nil, nil)
	require.NoError(t, err)
	assert.Empty(t, policies)
}

// ---------------------------------------------------------------------------
// local_sod — uncovered paths
// ---------------------------------------------------------------------------

func newSoDStoreMax(t *testing.T) *LocalStorage {
	t.Helper()
	return newMaxStore(t, "sod_"+t.Name(), &models.SoDPolicy{})
}

// CreateSoDPolicy — error path (table absent).
func TestCreateSoDPolicy_Error(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	ls := NewLocalStorage(db)
	_, err = ls.CreateSoDPolicy(context.Background(), &models.SoDPolicy{})
	require.Error(t, err)
}

// ListSoDPolicies — empty.
func TestListSoDPolicies_Empty(t *testing.T) {
	ls := newSoDStoreMax(t)
	policies, err := ls.ListSoDPolicies(context.Background())
	require.NoError(t, err)
	assert.Empty(t, policies)
}

// DeleteSoDPolicy — not-found.
func TestDeleteSoDPolicy_NotFoundMax(t *testing.T) {
	ls := newSoDStoreMax(t)
	err := ls.DeleteSoDPolicy(context.Background(), 9999)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_sso — uncovered paths
// ---------------------------------------------------------------------------

func newSSOStoreMax(t *testing.T) *LocalStorage {
	t.Helper()
	return newMaxStore(t, "sso_"+t.Name(), &models.SSOLoginState{})
}

// CreateSSOLoginState — error path.
func TestCreateSSOLoginState_Error(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	ls := NewLocalStorage(db)
	err = ls.CreateSSOLoginState(context.Background(), &models.SSOLoginState{})
	require.Error(t, err)
}

// ConsumeSSOLoginState — not-found.
func TestConsumeSSOLoginState_NotFoundMax(t *testing.T) {
	ls := newSSOStoreMax(t)
	_, err := ls.ConsumeSSOLoginState(context.Background(), "no-such-nonce")
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_system_metadata — not-found path
// ---------------------------------------------------------------------------

func TestGetSystemMetadata_NotFound(t *testing.T) {
	ls := newMaxStore(t, "sysmeta_nf", &models.SystemMetadata{})
	got, found, err := ls.GetSystemMetadata(context.Background(), "missing-key")
	require.NoError(t, err) // returns empty string, not error, when absent
	assert.False(t, found)
	assert.Equal(t, "", got)
}

// ---------------------------------------------------------------------------
// local_secret_dependencies — uncovered paths
// ---------------------------------------------------------------------------

func newSecDepStore(t *testing.T) *LocalStorage {
	t.Helper()
	return newMaxStore(t, "secdep_"+t.Name(),
		&models.SecretDependency{}, &models.SecretNode{},
		&models.Project{}, &models.Environment{},
	)
}

// CreateSecretDependency — error path.
func TestCreateSecretDependency_Error(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	ls := NewLocalStorage(db)
	_, err = ls.CreateSecretDependency(context.Background(), &models.SecretDependency{})
	require.Error(t, err)
}

// ListSecretDependenciesForProject — empty.
func TestListSecretDependenciesForProject_Empty(t *testing.T) {
	ls := newSecDepStore(t)
	deps, err := ls.ListSecretDependenciesForProject(context.Background(), 999)
	require.NoError(t, err)
	assert.Empty(t, deps)
}

// ListSecretDependenciesForProjectForUpdate — empty.
func TestListSecretDependenciesForProjectForUpdate_Empty(t *testing.T) {
	ls := newSecDepStore(t)
	deps, err := ls.ListSecretDependenciesForProjectForUpdate(context.Background(), 999)
	require.NoError(t, err)
	assert.Empty(t, deps)
}

// DeleteSecretDependency — not-found.
func TestDeleteSecretDependency_NotFound(t *testing.T) {
	ls := newSecDepStore(t)
	err := ls.DeleteSecretDependency(context.Background(), 9999)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_machine_identities — uncovered paths
// ---------------------------------------------------------------------------

func newMachIDStore(t *testing.T) *LocalStorage {
	t.Helper()
	return newMaxStore(t, "machid_"+t.Name(),
		&models.MachineIdentity{}, &models.Project{},
	)
}

// CreateMachineIdentity — error path.
func TestCreateMachineIdentity_Error(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	ls := NewLocalStorage(db)
	_, err = ls.CreateMachineIdentity(context.Background(), &models.MachineIdentity{})
	require.Error(t, err)
}

// LockMachineIdentityForUpdate — not-found.
func TestLockMachineIdentityForUpdate_NotFound(t *testing.T) {
	ls := newMachIDStore(t)
	_, err := ls.LockMachineIdentityForUpdate(context.Background(), 9999)
	require.Error(t, err)
}

// TransitionMachineIdentityState — not-found (zero rows → ok=false, no error).
func TestTransitionMachineIdentityState_NotFound(t *testing.T) {
	ls := newMachIDStore(t)
	ok, err := ls.TransitionMachineIdentityState(context.Background(), &models.MachineIdentity{ID: 9999}, "active")
	require.NoError(t, err)
	assert.False(t, ok)
}

// ListMachineIdentities — empty.
func TestListMachineIdentities_Empty(t *testing.T) {
	ls := newMachIDStore(t)
	identities, err := ls.ListMachineIdentities(context.Background(), 999)
	require.NoError(t, err)
	assert.Empty(t, identities)
}

// ListAllMachineIdentities — empty.
func TestListAllMachineIdentities_Empty(t *testing.T) {
	ls := newMachIDStore(t)
	identities, err := ls.ListAllMachineIdentities(context.Background())
	require.NoError(t, err)
	assert.Empty(t, identities)
}

// ---------------------------------------------------------------------------
// local_machine_credentials — uncovered paths
// ---------------------------------------------------------------------------

func newMachCredStoreMax(t *testing.T) *LocalStorage {
	t.Helper()
	return newMaxStore(t, "machcred_"+t.Name(),
		&models.MachineIdentityCredential{}, &models.MachineIdentity{},
		&models.MachineIdentityRole{}, &models.MachineIdentityOIDCBinding{}, &models.Role{},
		&models.Project{}, &models.Environment{},
	)
}

// CreateMachineIdentityCredential — error path.
func TestCreateMachineIdentityCredential_Error(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	ls := NewLocalStorage(db)
	_, err = ls.CreateMachineIdentityCredential(context.Background(), &models.MachineIdentityCredential{})
	require.Error(t, err)
}

// SetMachineIdentityCredentialClassification — error path.
func TestSetMachineIdentityCredentialClassification_Error(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	ls := NewLocalStorage(db)
	// No migrated table: the UPDATE errors, and the method must surface that
	// rather than reporting a clean no-match (#2696 — a no-match means "the row
	// moved", which a caller is allowed to treat as a benign concurrent write;
	// a storage error must never be collapsed into it).
	matched, err := ls.SetMachineIdentityCredentialClassification(context.Background(), 1, "", "internal")
	require.Error(t, err)
	require.False(t, matched)
}

// ListMachineIdentityCredentials — empty.
func TestListMachineIdentityCredentials_Empty(t *testing.T) {
	ls := newMachCredStoreMax(t)
	creds, err := ls.ListMachineIdentityCredentials(context.Background(), 999)
	require.NoError(t, err)
	assert.Empty(t, creds)
}

// ListActiveMachineIdentityCredentials — empty.
func TestListActiveMachineIdentityCredentials_Empty(t *testing.T) {
	ls := newMachCredStoreMax(t)
	creds, err := ls.ListActiveMachineIdentityCredentials(context.Background())
	require.NoError(t, err)
	assert.Empty(t, creds)
}

// GetMachineRoleIDsAt — empty.
func TestGetMachineRoleIDsAt_Empty(t *testing.T) {
	ls := newMachCredStoreMax(t)
	ids, err := ls.GetMachineRoleIDsAt(context.Background(), 999, storage.Scope{})
	require.NoError(t, err)
	assert.Empty(t, ids)
}

// GetMachineRoles — empty.
func TestGetMachineRoles_Empty(t *testing.T) {
	ls := newMachCredStoreMax(t)
	roles, err := ls.GetMachineRoles(context.Background(), 999)
	require.NoError(t, err)
	assert.Empty(t, roles)
}

// ListOIDCBindings — empty.
func TestListOIDCBindings_Empty(t *testing.T) {
	ls := newMachCredStoreMax(t)
	bindings, err := ls.ListOIDCBindings(context.Background(), 999)
	require.NoError(t, err)
	assert.Empty(t, bindings)
}

// DeleteOIDCBinding — not-found.
func TestDeleteOIDCBinding_NotFound(t *testing.T) {
	ls := newMachCredStoreMax(t)
	err := ls.DeleteOIDCBinding(context.Background(), 9999)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_mfa — uncovered paths
// ---------------------------------------------------------------------------

func newMFAStoreMax(t *testing.T) *LocalStorage {
	t.Helper()
	return newMaxStore(t, "mfa_"+t.Name(),
		&models.MFASecret{}, &models.User{},
		&models.MFARecoveryCode{}, &models.MFAChallenge{},
	)
}

// MarkTOTPStepUsed — user has no MFA secret → returns (false, no error).
func TestMarkTOTPStepUsed_NoSecret(t *testing.T) {
	ls := newMFAStoreMax(t)
	ok, err := ls.MarkTOTPStepUsed(context.Background(), 9999, 100)
	require.NoError(t, err)
	assert.False(t, ok) // no MFA secret row → step not marked
}

// DeleteMFAForUser — no rows (no error).
func TestDeleteMFAForUser_NoRows(t *testing.T) {
	ls := newMFAStoreMax(t)
	require.NoError(t, ls.DeleteMFAForUser(context.Background(), 9999))
}

// ConsumeMFARecoveryCode — not-found.
func TestConsumeMFARecoveryCode_NotFound(t *testing.T) {
	ls := newMFAStoreMax(t)
	ok, err := ls.ConsumeMFARecoveryCode(context.Background(), 9999, "code-hash", time.Now())
	require.NoError(t, err)
	assert.False(t, ok)
}

// ConsumeMFAChallenge — not-found.
func TestConsumeMFAChallenge_NotFound(t *testing.T) {
	ls := newMFAStoreMax(t)
	_, err := ls.ConsumeMFAChallenge(context.Background(), "no-such-token", time.Now())
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_webauthn — uncovered paths
// ---------------------------------------------------------------------------

func newWebAuthnStoreMax(t *testing.T) *LocalStorage {
	t.Helper()
	return newMaxStore(t, "wan_"+t.Name(),
		&models.WebAuthnCredential{}, &models.WebAuthnSession{}, &models.User{},
	)
}

// ListWebAuthnCredentials — empty.
func TestListWebAuthnCredentials_Empty(t *testing.T) {
	ls := newWebAuthnStoreMax(t)
	creds, err := ls.ListWebAuthnCredentials(context.Background(), 999)
	require.NoError(t, err)
	assert.Empty(t, creds)
}

// CountWebAuthnCredentials — zero.
func TestCountWebAuthnCredentials_Zero(t *testing.T) {
	ls := newWebAuthnStoreMax(t)
	n, err := ls.CountWebAuthnCredentials(context.Background(), 999)
	require.NoError(t, err)
	assert.Zero(t, n)
}

// DeleteWebAuthnCredential — not-found.
func TestDeleteWebAuthnCredential_NotFound(t *testing.T) {
	ls := newWebAuthnStoreMax(t)
	err := ls.DeleteWebAuthnCredential(context.Background(), 9999, 1)
	require.Error(t, err)
}

// LockWebAuthnCredentialForUpdate — not-found (credentialID []byte, userID uint).
func TestLockWebAuthnCredentialForUpdate_NotFound(t *testing.T) {
	ls := newWebAuthnStoreMax(t)
	_, err := ls.LockWebAuthnCredentialForUpdate(context.Background(), []byte("no-cred"), 9999)
	require.Error(t, err)
}

// AdvanceWebAuthnCredentialCounter — not-found (LockWebAuthnCredentialForUpdate errors).
func TestAdvanceWebAuthnCredentialCounter_NotFound(t *testing.T) {
	ls := newWebAuthnStoreMax(t)
	_, err := ls.AdvanceWebAuthnCredentialCounter(context.Background(), []byte("no-cred"), 9999, []byte("blob"), 1, time.Now())
	require.Error(t, err)
}

// ConsumeWebAuthnSession — not-found.
func TestConsumeWebAuthnSession_NotFound(t *testing.T) {
	ls := newWebAuthnStoreMax(t)
	_, err := ls.ConsumeWebAuthnSession(context.Background(), "no-such-id", time.Now())
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_dynamic — uncovered paths
// ---------------------------------------------------------------------------

func newDynStore(t *testing.T) *LocalStorage {
	t.Helper()
	return newMaxStore(t, "dyn_"+t.Name(),
		&models.DynamicSecretConfig{}, &models.DynamicSecretLease{},
	)
}

// CreateDynamicSecretConfig — error path.
func TestCreateDynamicSecretConfig_Error(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	ls := NewLocalStorage(db)
	_, err = ls.CreateDynamicSecretConfig(context.Background(), &models.DynamicSecretConfig{})
	require.Error(t, err)
}

// ListDynamicSecretConfigs — empty (no project).
func TestListDynamicSecretConfigs_Empty(t *testing.T) {
	ls := newDynStore(t)
	configs, err := ls.ListDynamicSecretConfigs(context.Background(), 999, 1)
	require.NoError(t, err)
	assert.Empty(t, configs)
}

// CreateDynamicSecretLease — error path.
func TestCreateDynamicSecretLease_Error(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	ls := NewLocalStorage(db)
	_, err = ls.CreateDynamicSecretLease(context.Background(), &models.DynamicSecretLease{})
	require.Error(t, err)
}

// ListDynamicSecretLeases — empty.
func TestListDynamicSecretLeases_Empty(t *testing.T) {
	ls := newDynStore(t)
	leases, err := ls.ListDynamicSecretLeases(context.Background(), 999)
	require.NoError(t, err)
	assert.Empty(t, leases)
}

// ---------------------------------------------------------------------------
// local_legal_hold — uncovered paths
// ---------------------------------------------------------------------------

func newLegalHoldStoreMax(t *testing.T) *LocalStorage {
	t.Helper()
	return newMaxStore(t, "lhold_"+t.Name(), &models.LegalHold{})
}

// UpdateLegalHold — upserts (Save never returns not-found; just covers the branch).
func TestUpdateLegalHold_UpsertPath(t *testing.T) {
	ls := newLegalHoldStoreMax(t)
	err := ls.UpdateLegalHold(context.Background(), &models.LegalHold{ID: 9999})
	require.NoError(t, err)
}

// CreateLegalHold — error path.
func TestCreateLegalHold_Error(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	ls := NewLocalStorage(db)
	_, err = ls.CreateLegalHold(context.Background(), &models.LegalHold{})
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_break_glass — uncovered paths
// ---------------------------------------------------------------------------

func newBGStoreMax(t *testing.T) *LocalStorage {
	t.Helper()
	return newMaxStore(t, "bg_"+t.Name(), &models.BreakGlassActivation{})
}

// CreateBreakGlassActivation — error path.
func TestCreateBreakGlassActivation_Error(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	ls := NewLocalStorage(db)
	_, err = ls.CreateBreakGlassActivation(context.Background(), &models.BreakGlassActivation{})
	require.Error(t, err)
}

// ListBreakGlassActivations — empty.
func TestListBreakGlassActivations_Empty(t *testing.T) {
	ls := newBGStoreMax(t)
	acts, err := ls.ListBreakGlassActivations(context.Background(), 999)
	require.NoError(t, err)
	assert.Empty(t, acts)
}

// UpdateBreakGlassActivation — upserts via Save (covers the success branch).
func TestUpdateBreakGlassActivation_UpsertPath(t *testing.T) {
	ls := newBGStoreMax(t)
	err := ls.UpdateBreakGlassActivation(context.Background(), &models.BreakGlassActivation{ID: 9999})
	require.NoError(t, err)
}

// RevokeBreakGlassActivation — not-found.
func TestRevokeBreakGlassActivation_NotFound(t *testing.T) {
	ls := newBGStoreMax(t)
	err := ls.RevokeBreakGlassActivation(context.Background(), 9999, 1, 0, time.Now())
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_connect_ref_grants — uncovered paths
// ---------------------------------------------------------------------------

func newConnRefStore(t *testing.T) *LocalStorage {
	t.Helper()
	return newMaxStore(t, "cref_"+t.Name(), &models.ConnectRefGrant{})
}

// ListConnectRefGrantsByConnector — empty.
func TestListConnectRefGrantsByConnector_Empty(t *testing.T) {
	ls := newConnRefStore(t)
	grants, err := ls.ListConnectRefGrantsByConnector(context.Background(), "no-connector")
	require.NoError(t, err)
	assert.Empty(t, grants)
}

// ListConnectRefGrants — empty.
func TestListConnectRefGrants_Empty(t *testing.T) {
	ls := newConnRefStore(t)
	grants, err := ls.ListConnectRefGrants(context.Background())
	require.NoError(t, err)
	assert.Empty(t, grants)
}

// ---------------------------------------------------------------------------
// local_drift — uncovered path
// ---------------------------------------------------------------------------

func newDriftStore(t *testing.T) *LocalStorage {
	t.Helper()
	return newMaxStore(t, "drift_"+t.Name(),
		&models.SecretNode{}, &models.SecretVersion{}, &models.Project{}, &models.Environment{},
	)
}

// ListProjectSecretsForDrift — empty.
func TestListProjectSecretsForDrift_Empty(t *testing.T) {
	ls := newDriftStore(t)
	secrets, err := ls.ListProjectSecretsForDrift(context.Background(), 999)
	require.NoError(t, err)
	assert.Empty(t, secrets)
}

// ---------------------------------------------------------------------------
// classification_count — error path (countByClassification with bad table)
// ---------------------------------------------------------------------------

func TestCountByClassification_BadTable(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	ls := NewLocalStorage(db)
	// No tables migrated → countByClassification should return an error.
	_, err = countByClassification(context.Background(), ls.db, &models.SecretNode{})
	require.Error(t, err)
}
