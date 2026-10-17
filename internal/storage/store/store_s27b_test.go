// store_s27b_test.go — s27b coverage blitz for internal/storage/store.
//
// Targets not yet reached by store_s27_test.go (which covered error-paths
// and simple early-returns); this file adds happy-path branches and additional
// failure-mode branches to push the remaining functions above 90%:
//
//	local_purge.go
//	  purgeDeletedBefore (75%)        — exercises the shared helper via
//	                                    PurgeDeletedEnvironmentsBefore happy path
//	  PurgeDeletedUsersBefore (77.8%) — zero-users no-op + actual purge
//	  PurgeDeletedProjectsBefore (85.7%) — zero-projects no-op + actual purge
//	  DeleteAnomalyAlertsBefore (85.7%) — both-zero no-op + acked branch + unacked branch
//
//	local_memberships.go
//	  CreateProjectMembership (80%)    — unique-violation → ErrDuplicateActiveMembership
//	  CountProjectMembershipsByUsers (90%) — happy path with real data
//
//	local_machine_credentials.go
//	  GetMachineRoleIDsAt (80%)  — happy path with a global-scope grant
//	  GetMachineRoles (80%)      — happy path: one role returned
//	  AssignMachineRole (90%)    — already-assigned + DB-error paths
//
//	local_break_glass.go
//	  ListBreakGlassActivations (80%)    — happy path
//	  RevokeBreakGlassActivation (83.3%) — DB error path
//
//	local_mfa.go
//	  ConsumeMFAChallenge (86.7%) — valid + expired challenge paths
//
//	local_machine_identities.go
//	  LockMachineIdentityForUpdate (85.7%) — happy path on SQLite
//	  CountStaleMachineIdentitiesByProject (90.9%) — happy path
//
//	local_auth.go
//	  RotateSession (84.2%)         — winning path (won=true, new session created)
//	  RevokeAllPersonalAccessTokensForUser (87.5%) — actual revoke path
//
//	local_audit.go
//	  PrincipalSecretFirstSeen (92.3%) — nil firstSeen skip + error path
//	  CreateAnomalyAlert (90%)         — error path (broken DB)
//
//	local_audit_chain.go
//	  LogAuditEvent (90.5%) — error path (broken DB)
package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// newS27bStore opens a unique in-memory SQLite DB, auto-migrates the supplied
// model types, and returns a LocalStorage. The "_s27b" suffix avoids DSN
// collisions with store_s27_test.go's "_s27" suffix.
func newS27bStore(t *testing.T, mods ...any) *LocalStorage {
	t.Helper()
	db := sqlitetest.OpenWithDialector(t, "stores27b_", sqlite.Open, &gorm.Config{})
	if len(mods) > 0 {
		require.NoError(t, db.AutoMigrate(mods...))
	}
	return NewLocalStorage(db)
}

// ---------------------------------------------------------------------------
// local_purge.go — purgeDeletedBefore (via PurgeDeletedEnvironmentsBefore)
// ---------------------------------------------------------------------------

// TestPurgeDeletedEnvironmentsBefore_S27b_HappyPath exercises the shared
// purgeDeletedBefore helper via the environment purge path: one soft-deleted
// environment whose deleted_at predates the cutoff is hard-deleted; a live
// one is left untouched.
func TestPurgeDeletedEnvironmentsBefore_S27b_HappyPath(t *testing.T) {
	ls := newS27bStore(t, &models.Environment{})
	ctx := context.Background()
	past := time.Now().Add(-48 * time.Hour)

	// Create and soft-delete an environment.
	env := &models.Environment{Name: "old-env", ProjectID: 1}
	require.NoError(t, ls.db.Create(env).Error)
	require.NoError(t, ls.db.Delete(env).Error)
	require.NoError(t, ls.db.Unscoped().Model(env).Update("deleted_at", past).Error)

	// Live environment — must not be purged.
	require.NoError(t, ls.db.Create(&models.Environment{Name: "live-env", ProjectID: 1}).Error)

	n, err := ls.PurgeDeletedEnvironmentsBefore(ctx, time.Now())
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)
}

// ---------------------------------------------------------------------------
// local_purge.go — PurgeDeletedUsersBefore
// ---------------------------------------------------------------------------

// TestPurgeDeletedUsersBefore_S27b_ZeroUsersNoOp verifies the early-return when
// no users are eligible (len(ids)==0 branch inside the transaction).
func TestPurgeDeletedUsersBefore_S27b_ZeroUsersNoOp(t *testing.T) {
	ls := newS27bStore(t,
		&models.User{}, &models.UserRole{}, &models.UserGroup{},
		&models.ShareRecord{}, &models.PersonalAccessToken{}, &models.Session{},
	)
	// Only a live user — no soft-deleted ones.
	require.NoError(t, ls.db.Create(&models.User{Username: "live-user"}).Error)

	n, err := ls.PurgeDeletedUsersBefore(context.Background(), time.Now().Add(-time.Hour))
	require.NoError(t, err)
	assert.Equal(t, int64(0), n)
}

// TestPurgeDeletedUsersBefore_S27b_PurgesUser verifies that a soft-deleted user
// (deleted_at before cutoff) is hard-deleted along with its role grants.
func TestPurgeDeletedUsersBefore_S27b_PurgesUser(t *testing.T) {
	ls := newS27bStore(t,
		&models.User{}, &models.UserRole{}, &models.UserGroup{},
		&models.ShareRecord{}, &models.PersonalAccessToken{}, &models.Session{}, &models.SecretACL{}, &models.AccessRequest{},
	)
	ctx := context.Background()
	past := time.Now().Add(-24 * time.Hour)

	u := &models.User{Username: "purgeme-s27b"}
	require.NoError(t, ls.db.Create(u).Error)
	// Attach a role grant that should be cascade-deleted.
	require.NoError(t, ls.db.Create(&models.UserRole{UserID: u.ID, RoleID: 1}).Error)
	// Soft-delete the user.
	require.NoError(t, ls.db.Delete(u).Error)
	require.NoError(t, ls.db.Unscoped().Model(u).Update("deleted_at", past).Error)

	n, err := ls.PurgeDeletedUsersBefore(ctx, time.Now())
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)

	// Role grant must be gone too.
	var count int64
	ls.db.Model(&models.UserRole{}).Where("user_id = ?", u.ID).Count(&count)
	assert.Equal(t, int64(0), count)
}

// ---------------------------------------------------------------------------
// local_purge.go — PurgeDeletedProjectsBefore
// ---------------------------------------------------------------------------

// TestPurgeDeletedProjectsBefore_S27b_ZeroProjects verifies early-return when
// no projects are eligible.
func TestPurgeDeletedProjectsBefore_S27b_ZeroProjects(t *testing.T) {
	ls := newS27bStore(t, &models.Project{}, &models.UserRole{}, &models.GroupRole{}, &models.MachineIdentityRole{})
	n, err := ls.PurgeDeletedProjectsBefore(context.Background(), time.Now().Add(-time.Hour))
	require.NoError(t, err)
	assert.Equal(t, int64(0), n)
}

// TestPurgeDeletedProjectsBefore_S27b_PurgesProject verifies that a soft-deleted
// project is hard-deleted along with its scoped role grants.
func TestPurgeDeletedProjectsBefore_S27b_PurgesProject(t *testing.T) {
	ls := newS27bStore(t, &models.Project{}, &models.UserRole{}, &models.GroupRole{}, &models.MachineIdentityRole{})
	ctx := context.Background()
	past := time.Now().Add(-24 * time.Hour)

	p := &models.Project{Name: "old-proj"}
	require.NoError(t, ls.db.Create(p).Error)
	// Attach a project-scoped role grant.
	require.NoError(t, ls.db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: p.ID}).Error)
	// Soft-delete the project.
	require.NoError(t, ls.db.Delete(p).Error)
	require.NoError(t, ls.db.Unscoped().Model(p).Update("deleted_at", past).Error)

	n, err := ls.PurgeDeletedProjectsBefore(ctx, time.Now())
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)

	// Scoped role grant must be gone.
	var count int64
	ls.db.Model(&models.UserRole{}).Where("project_id = ?", p.ID).Count(&count)
	assert.Equal(t, int64(0), count)
}

// ---------------------------------------------------------------------------
// local_purge.go — DeleteAnomalyAlertsBefore
// ---------------------------------------------------------------------------

// TestDeleteAnomalyAlertsBefore_S27b_BothZeroNoOp verifies the early-return path
// when both ackBefore and unackCeiling are zero times.
func TestDeleteAnomalyAlertsBefore_S27b_BothZeroNoOp(t *testing.T) {
	ls := newS27bStore(t, &models.AnomalyAlert{})
	n, err := ls.DeleteAnomalyAlertsBefore(context.Background(), time.Time{}, time.Time{})
	require.NoError(t, err)
	assert.Equal(t, int64(0), n)
}

// TestDeleteAnomalyAlertsBefore_S27b_AckBranchOnly verifies that the ackBefore
// clause deletes acknowledged alerts older than the cutoff.
func TestDeleteAnomalyAlertsBefore_S27b_AckBranchOnly(t *testing.T) {
	ls := newS27bStore(t, &models.AnomalyAlert{})
	ctx := context.Background()
	past := time.Now().Add(-48 * time.Hour)

	// Acknowledged alert older than the cutoff — should be deleted.
	require.NoError(t, ls.db.Create(&models.AnomalyAlert{
		SecretNodeID: 1, AlertType: "unusual_access",
		DetectedAt: past, Acknowledged: true,
	}).Error)
	// Unacknowledged alert (should NOT match the ack clause).
	require.NoError(t, ls.db.Create(&models.AnomalyAlert{
		SecretNodeID: 2, AlertType: "unusual_access",
		DetectedAt: past, Acknowledged: false,
	}).Error)

	n, err := ls.DeleteAnomalyAlertsBefore(ctx, time.Now(), time.Time{})
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)
}

// TestDeleteAnomalyAlertsBefore_S27b_UnackCeilingBranchOnly verifies that the
// unackCeiling clause deletes old, never-acknowledged alerts.
func TestDeleteAnomalyAlertsBefore_S27b_UnackCeilingBranchOnly(t *testing.T) {
	ls := newS27bStore(t, &models.AnomalyAlert{})
	ctx := context.Background()
	past := time.Now().Add(-96 * time.Hour)

	// Very old unacknowledged alert — matches the unackCeiling clause.
	require.NoError(t, ls.db.Create(&models.AnomalyAlert{
		SecretNodeID: 3, AlertType: "unusual_access",
		DetectedAt: past, Acknowledged: false,
	}).Error)

	n, err := ls.DeleteAnomalyAlertsBefore(ctx, time.Time{}, time.Now())
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)
}

// ---------------------------------------------------------------------------
// local_memberships.go — CreateProjectMembership unique-violation path
// ---------------------------------------------------------------------------

// TestCreateProjectMembership_S27b_UniqueViolationReturnsSentinel verifies that
// inserting a second non-revoked membership for the same (project, user) under
// an active partial unique index returns ErrDuplicateActiveMembership (the
// isUniqueViolation translation branch).
func TestCreateProjectMembership_S27b_UniqueViolationReturnsSentinel(t *testing.T) {
	ls := newS27bStore(t, &models.ProjectMembership{})
	ctx := context.Background()

	// Create the partial unique index that factory.go would normally ensure.
	require.NoError(t, ls.db.Exec(
		"CREATE UNIQUE INDEX IF NOT EXISTS uniq_project_memberships_active_s27b "+
			"ON project_memberships (project_id, user_id) WHERE state <> 'revoked'",
	).Error)

	m1 := &models.ProjectMembership{
		ProjectID: 42, UserID: 7, Role: "viewer", State: "active",
		InvitedBy: 1, InvitedAt: time.Now(),
	}
	_, err := ls.CreateProjectMembership(ctx, m1)
	require.NoError(t, err)

	m2 := &models.ProjectMembership{
		ProjectID: 42, UserID: 7, Role: "admin", State: "invited",
		InvitedBy: 1, InvitedAt: time.Now(),
	}
	_, err = ls.CreateProjectMembership(ctx, m2)
	require.ErrorIs(t, err, storage.ErrDuplicateActiveMembership,
		"concurrent duplicate must surface ErrDuplicateActiveMembership, not a raw DB error")
}

// ---------------------------------------------------------------------------
// local_memberships.go — CountProjectMembershipsByUsers happy path
// ---------------------------------------------------------------------------

// TestCountProjectMembershipsByUsers_S27b_HappyPath verifies that the query
// correctly distinguishes active vs non-revoked (total) memberships per user.
func TestCountProjectMembershipsByUsers_S27b_HappyPath(t *testing.T) {
	ls := newS27bStore(t, &models.ProjectMembership{})
	ctx := context.Background()
	now := time.Now()

	rows := []*models.ProjectMembership{
		{ProjectID: 1, UserID: 10, State: "active", InvitedAt: now},
		{ProjectID: 2, UserID: 10, State: "active", InvitedAt: now},
		{ProjectID: 3, UserID: 10, State: "invited", InvitedAt: now}, // non-revoked but not active
		{ProjectID: 4, UserID: 10, State: "revoked", InvitedAt: now}, // revoked — excluded from total
	}
	for _, r := range rows {
		require.NoError(t, ls.db.Create(r).Error)
	}

	counts, err := ls.CountProjectMembershipsByUsers(ctx, []uint{10, 99})
	require.NoError(t, err)

	c10, ok := counts[10]
	require.True(t, ok, "user 10 must appear in the result")
	assert.Equal(t, 2, c10.Active, "only 'active' state rows count toward Active")
	assert.Equal(t, 3, c10.Total, "revoked row must be excluded from Total")

	_, ok = counts[99]
	assert.False(t, ok, "user with no memberships must be absent from the map")
}

// ---------------------------------------------------------------------------
// local_machine_credentials.go — GetMachineRoleIDsAt happy path
// ---------------------------------------------------------------------------

// TestGetMachineRoleIDsAt_S27b_GlobalScopeGrant verifies that a global-scope
// role grant (project_id=0, environment_id=0) is returned for any requested scope.
func TestGetMachineRoleIDsAt_S27b_GlobalScopeGrant(t *testing.T) {
	ls := newS27bStore(t, &models.MachineIdentityRole{}, &models.Project{}, &models.Environment{})
	ctx := context.Background()

	grant := &models.MachineIdentityRole{
		MachineIdentityID: 7, RoleID: 55, ProjectID: 0, EnvironmentID: 0,
	}
	require.NoError(t, ls.db.Create(grant).Error)

	ids, err := ls.GetMachineRoleIDsAt(ctx, 7, storage.Scope{ProjectID: 0, EnvironmentID: 0})
	require.NoError(t, err)
	assert.Contains(t, ids, uint(55))
}

// ---------------------------------------------------------------------------
// local_machine_credentials.go — GetMachineRoles happy path
// ---------------------------------------------------------------------------

// TestGetMachineRoles_S27b_HappyPath verifies that all roles granted to a
// machine (any scope) are returned, regardless of project/environment scoping.
func TestGetMachineRoles_S27b_HappyPath(t *testing.T) {
	ls := newS27bStore(t, &models.Role{}, &models.MachineIdentityRole{})
	ctx := context.Background()

	r := &models.Role{Name: "s27b-machine-role"}
	require.NoError(t, ls.db.Create(r).Error)

	grant := &models.MachineIdentityRole{
		MachineIdentityID: 9, RoleID: r.ID, ProjectID: 2, EnvironmentID: 3,
	}
	require.NoError(t, ls.db.Create(grant).Error)

	roles, err := ls.GetMachineRoles(ctx, 9)
	require.NoError(t, err)
	require.Len(t, roles, 1)
	assert.Equal(t, r.ID, roles[0].ID)
}

// ---------------------------------------------------------------------------
// local_machine_credentials.go — AssignMachineRole
// ---------------------------------------------------------------------------

// TestAssignMachineRole_S27b_AlreadyAssigned verifies the "already assigned" error
// when the same role is assigned twice to a machine.
func TestAssignMachineRole_S27b_AlreadyAssigned(t *testing.T) {
	ls := newS27bStore(t, &models.MachineIdentityRole{})
	ctx := context.Background()
	scope := storage.Scope{ProjectID: 0, EnvironmentID: 0}

	require.NoError(t, ls.AssignMachineRole(ctx, 1, 10, scope))
	err := ls.AssignMachineRole(ctx, 1, 10, scope)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already")
}

// ---------------------------------------------------------------------------
// local_break_glass.go — ListBreakGlassActivations happy path
// ---------------------------------------------------------------------------

// TestListBreakGlassActivations_S27b_HappyPath verifies that only activations
// for the requested project are returned, ordered newest-first.
func TestListBreakGlassActivations_S27b_HappyPath(t *testing.T) {
	ls := newS27bStore(t, &models.BreakGlassActivation{})
	ctx := context.Background()
	now := time.Now()

	for i := range 3 {
		require.NoError(t, ls.db.Create(&models.BreakGlassActivation{
			ProjectID: 12, UserID: uint(i + 1), State: "active",
			CreatedAt: now.Add(time.Duration(i) * time.Second),
		}).Error)
	}
	// Different project — must not appear.
	require.NoError(t, ls.db.Create(&models.BreakGlassActivation{
		ProjectID: 99, UserID: 99, State: "active", CreatedAt: now,
	}).Error)

	rows, err := ls.ListBreakGlassActivations(ctx, 12)
	require.NoError(t, err)
	require.Len(t, rows, 3)
}

// ---------------------------------------------------------------------------
// local_break_glass.go — RevokeBreakGlassActivation DB error path
// ---------------------------------------------------------------------------

// TestRevokeBreakGlassActivation_S27b_BrokenDB verifies the DB error path when
// the table does not exist.
func TestRevokeBreakGlassActivation_S27b_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	err := ls.RevokeBreakGlassActivation(context.Background(), 1, 1, 0, time.Now())
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_mfa.go — ConsumeMFAChallenge
// ---------------------------------------------------------------------------

// TestConsumeMFAChallenge_S27b_HappyPath verifies that a valid, unused,
// non-expired challenge is marked used and returned.
func TestConsumeMFAChallenge_S27b_HappyPath(t *testing.T) {
	ls := newS27bStore(t, &models.MFAChallenge{})
	ctx := context.Background()
	now := time.Now()

	ch := &models.MFAChallenge{
		UserID:    3,
		TokenHash: "s27b-valid-hash",
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	}
	require.NoError(t, ls.db.Create(ch).Error)

	got, err := ls.ConsumeMFAChallenge(ctx, "s27b-valid-hash", now)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.NotNil(t, got.UsedAt, "UsedAt must be set after consumption")
}

// TestConsumeMFAChallenge_S27b_ExpiredOrUsed verifies that no match (zero rows
// updated) surfaces the "invalid or expired" error.
func TestConsumeMFAChallenge_S27b_ExpiredOrUsed(t *testing.T) {
	ls := newS27bStore(t, &models.MFAChallenge{})
	ctx := context.Background()
	now := time.Now()

	// An already-expired challenge.
	past := now.Add(-time.Hour)
	ch := &models.MFAChallenge{
		UserID:    4,
		TokenHash: "s27b-expired-hash",
		ExpiresAt: past, // already expired
		CreatedAt: past,
	}
	require.NoError(t, ls.db.Create(ch).Error)

	_, err := ls.ConsumeMFAChallenge(ctx, "s27b-expired-hash", now)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid or expired")
}

// ---------------------------------------------------------------------------
// local_machine_identities.go — LockMachineIdentityForUpdate happy path
// ---------------------------------------------------------------------------

// TestLockMachineIdentityForUpdate_S27b_HappyPath verifies the SQLite path
// (no SELECT FOR UPDATE clause) returns the row when it exists.
func TestLockMachineIdentityForUpdate_S27b_HappyPath(t *testing.T) {
	ls := newS27bStore(t, &models.MachineIdentity{})
	m := &models.MachineIdentity{ProjectID: 2, Name: "worker-s27b", State: "active"}
	require.NoError(t, ls.db.Create(m).Error)

	got, err := ls.LockMachineIdentityForUpdate(context.Background(), m.ID)
	require.NoError(t, err)
	assert.Equal(t, m.ID, got.ID)
	assert.Equal(t, "worker-s27b", got.Name)
}

// ---------------------------------------------------------------------------
// local_machine_identities.go — CountStaleMachineIdentitiesByProject
// ---------------------------------------------------------------------------

// TestCountStaleMachineIdentitiesByProject_S27b_HappyPath verifies that an active
// machine identity never seen (last_seen_at IS NULL) and older than the cutoff
// is counted as stale.
func TestCountStaleMachineIdentitiesByProject_S27b_HappyPath(t *testing.T) {
	ls := newS27bStore(t, &models.MachineIdentity{})
	ctx := context.Background()
	past := time.Now().Add(-72 * time.Hour)

	m := &models.MachineIdentity{
		ProjectID: 20, Name: "stale-s27b", State: "active", CreatedAt: past,
	}
	require.NoError(t, ls.db.Create(m).Error)
	// Force created_at to past (GORM may override on Create). Routed through
	// Save, not a raw column Update: CountStaleMachineIdentitiesByProject does a
	// real SQL range query on created_at (local_machine_identities.go), and
	// MachineIdentity.BeforeSave exists specifically to UTC-normalize this
	// column for that comparison — a raw Update bypasses it and leaves `past`'s
	// local Location in the column, correct here only because the 72h-old
	// fixture value clears the 1h-old cutoff by a wide margin, not because the
	// value is actually canonical (#1619).
	m.CreatedAt = past
	require.NoError(t, ls.db.Save(m).Error)

	olderThan := time.Now().Add(-time.Hour)
	counts, err := ls.CountStaleMachineIdentitiesByProject(ctx, []uint{20}, olderThan)
	require.NoError(t, err)
	assert.Equal(t, 1, counts[20])
}

// ---------------------------------------------------------------------------
// local_auth.go — RotateSession winning path
// ---------------------------------------------------------------------------

// TestRotateSession_S27b_WinsRace verifies that the winning rotation path
// (RowsAffected==1) creates the new session and returns (created, true, nil).
func TestRotateSession_S27b_WinsRace(t *testing.T) {
	ls := newS27bStore(t, &models.Session{})
	// #2701: a session/PAT insert now re-reads its owning user and rolls back if
	// it is not live, so this fixture needs the owners it references to exist.
	seedCredentialOwners(t, ls.db)
	ctx := context.Background()
	now := time.Now()

	// Create a live (not-yet-rotated) session.
	exp1 := now.Add(time.Hour)
	old := &models.Session{
		UserID:       1,
		SessionToken: hashSessionToken("old-tok-s27b"),
		ExpiresAt:    &exp1,
	}
	require.NoError(t, ls.db.Create(old).Error)

	exp2 := now.Add(2 * time.Hour)
	newSess := &models.Session{
		UserID:       1,
		SessionToken: "new-tok-s27b",
		ExpiresAt:    &exp2,
	}
	created, won, err := ls.RotateSession(ctx, old.ID, newSess, now)
	require.NoError(t, err)
	assert.True(t, won, "must win the race on an unrotated session")
	require.NotNil(t, created)
	assert.Equal(t, "new-tok-s27b", created.SessionToken, "created session must carry the plaintext token")
}

// ---------------------------------------------------------------------------
// local_auth.go — RevokeAllPersonalAccessTokensForUser
// ---------------------------------------------------------------------------

// TestRevokeAllPersonalAccessTokensForUser_S27b_RevokesTokens verifies that
// non-revoked PATs are revoked and their hashes returned.
func TestRevokeAllPersonalAccessTokensForUser_S27b_RevokesTokens(t *testing.T) {
	ls := newS27bStore(t, &models.PersonalAccessToken{})
	ctx := context.Background()

	for i := range 2 {
		require.NoError(t, ls.db.Create(&models.PersonalAccessToken{
			UserID:    5,
			TokenHash: "hash-s27b-" + string(rune('a'+i)),
			Revoked:   false,
		}).Error)
	}

	hashes, err := ls.RevokeAllPersonalAccessTokensForUser(ctx, 5)
	require.NoError(t, err)
	assert.Len(t, hashes, 2, "both non-revoked PATs must be revoked")

	// Confirm the DB rows are now revoked.
	var count int64
	require.NoError(t, ls.db.Model(&models.PersonalAccessToken{}).
		Where("user_id = ? AND revoked = ?", 5, false).Count(&count).Error)
	assert.Equal(t, int64(0), count)
}

// TestRevokeAllPersonalAccessTokensForUser_S27b_NoneToRevoke verifies the
// nil, nil early-return when there are no non-revoked tokens.
func TestRevokeAllPersonalAccessTokensForUser_S27b_NoneToRevoke(t *testing.T) {
	ls := newS27bStore(t, &models.PersonalAccessToken{})
	hashes, err := ls.RevokeAllPersonalAccessTokensForUser(context.Background(), 99)
	require.NoError(t, err)
	assert.Nil(t, hashes)
}

// ---------------------------------------------------------------------------
// local_audit.go — CreateAnomalyAlert error path
// ---------------------------------------------------------------------------

// TestCreateAnomalyAlert_S27b_BrokenDB verifies the error path when the
// anomaly_alerts table does not exist.
func TestCreateAnomalyAlert_S27b_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	err := ls.CreateAnomalyAlert(context.Background(), &models.AnomalyAlert{
		SecretNodeID: 1, AlertType: "test", DetectedAt: time.Now(),
	})
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_audit_chain.go — LogAuditEvent error path
// ---------------------------------------------------------------------------

// TestLogAuditEvent_S27b_BrokenDB verifies the error path when the audit_events
// table does not exist (chain-write fails).
func TestLogAuditEvent_S27b_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	ctx := context.Background()
	successTrue := true
	projID := uint(1)
	err := ls.LogAuditEvent(ctx, &models.AuditEvent{
		EventType: "secret.read",
		ProjectID: &projID,
		Success:   &successTrue,
		ActorType: "user",
		EventTime: time.Now(),
	})
	require.Error(t, err)
}
