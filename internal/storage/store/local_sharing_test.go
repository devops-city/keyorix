package store

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// sharingConcurrentDB opens a temp FILE-backed SQLite (not :memory:) with a busy
// timeout and WAL, so multiple connections genuinely contend — the only way to test
// that the create-race fix holds under real concurrency (mirrors concurrentDB in
// concurrency_max_reads_test.go). It also installs the same partial unique index the
// real migration does (ensureShareRecordUniqueIndex, internal/storage/factory.go —
// not importable here without a cycle, so the DDL is mirrored).
func sharingConcurrentDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "sharing.db") + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Group{}, &models.UserGroup{}, &models.SecretNode{}, &models.ShareRecord{},
		&models.SecretACL{}, &models.AccessRequest{},
	))
	require.NoError(t, db.Exec(
		"CREATE UNIQUE INDEX IF NOT EXISTS uniq_share_records_active ON share_records (secret_id, recipient_id, is_group) WHERE deleted_at IS NULL",
	).Error)
	return db
}

// #136: two concurrent CreateShareRecord calls for the same (secret, recipient) must
// not both succeed as separate rows — the partial unique index rejects the loser's
// INSERT, and CreateShareRecord must turn that into an upsert onto the winner's row
// rather than surfacing a raw constraint error to the caller.
func TestCreateShareRecord_ConcurrentGrantsNoDuplicateRow(t *testing.T) {
	db := sharingConcurrentDB(t)
	ls := NewLocalStorage(db)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "o@x.io"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "grantee", Email: "g@x.io"}).Error)
	require.NoError(t, db.Create(&models.SecretNode{
		ID: 100, Name: "s", ProjectID: 1, EnvironmentID: 1, OwnerID: 1, Status: "active", Type: "password",
	}).Error)

	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	var start sync.WaitGroup
	start.Add(1)
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			start.Wait()
			_, err := ls.CreateShareRecord(ctx, &models.ShareRecord{
				SecretID: 100, RecipientID: 2, IsGroup: false, OwnerID: 1, Permission: "read",
			})
			errs[i] = err
		}(i)
	}
	start.Done() // release all goroutines at once to maximize the race window
	wg.Wait()

	for i, err := range errs {
		assert.NoError(t, err, "goroutine %d", i)
	}

	var count int64
	require.NoError(t, db.Model(&models.ShareRecord{}).
		Where("secret_id = ? AND recipient_id = ? AND is_group = ? AND deleted_at IS NULL", 100, 2, false).
		Count(&count).Error)
	assert.Equal(t, int64(1), count, "concurrent grants for the same (secret, recipient) must collapse to exactly one active row")
}

// #136: DeleteShareRecord must remove every active row for the target's
// (secret, recipient, is_group), not just the row named by shareID — so a
// pre-existing duplicate (e.g. from before the unique index shipped) doesn't survive
// a revoke and leave access live.
func TestDeleteShareRecord_RemovesAllDuplicatesForSameTuple(t *testing.T) {
	db := sharingConcurrentDB(t)
	ls := NewLocalStorage(db)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "o@x.io"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "grantee", Email: "g@x.io"}).Error)
	require.NoError(t, db.Create(&models.SecretNode{
		ID: 100, Name: "s", ProjectID: 1, EnvironmentID: 1, OwnerID: 1, Status: "active", Type: "password",
	}).Error)

	// Simulate a pre-existing duplicate from before the unique index existed: insert
	// directly, bypassing CreateShareRecord (which would now reject/upsert it).
	share1 := &models.ShareRecord{SecretID: 100, RecipientID: 2, IsGroup: false, OwnerID: 1, Permission: "read"}
	require.NoError(t, db.Exec("DROP INDEX IF EXISTS uniq_share_records_active").Error)
	require.NoError(t, db.Create(share1).Error)
	share2 := &models.ShareRecord{SecretID: 100, RecipientID: 2, IsGroup: false, OwnerID: 1, Permission: "read"}
	require.NoError(t, db.Create(share2).Error)

	var preCount int64
	require.NoError(t, db.Model(&models.ShareRecord{}).
		Where("secret_id = ? AND recipient_id = ? AND is_group = ? AND deleted_at IS NULL", 100, 2, false).
		Count(&preCount).Error)
	require.Equal(t, int64(2), preCount, "test setup: two duplicate active rows must exist")

	// Revoke by share1's ID only.
	require.NoError(t, ls.DeleteShareRecord(ctx, share1.ID))

	perm, err := ls.CheckSharePermission(ctx, 100, 2, time.Now())
	require.Error(t, err, "revoking one of the duplicate rows must remove access entirely")
	assert.Equal(t, "", perm)

	var postCount int64
	require.NoError(t, db.Model(&models.ShareRecord{}).
		Where("secret_id = ? AND recipient_id = ? AND is_group = ? AND deleted_at IS NULL", 100, 2, false).
		Count(&postCount).Error)
	assert.Equal(t, int64(0), postCount, "both duplicate rows must be removed by a single revoke")
}

// #370: DeleteSecret must revoke every active ShareRecord for that secret, not just
// soft-delete the secret itself — otherwise a share grant silently resurrects with zero
// re-authorization when the secret is later restored from the recycle bin, even when the
// secret was deleted specifically to sever a former grantee's access.
func TestDeleteSecret_RevokesActiveShares(t *testing.T) {
	db := sharingConcurrentDB(t)
	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.Environment{}))
	ls := NewLocalStorage(db)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "o@x.io"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "grantee", Email: "g@x.io"}).Error)
	proj, err := ls.CreateProject(ctx, &models.Project{Name: "app"})
	require.NoError(t, err)
	env, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: proj.ID})
	require.NoError(t, err)
	sec, err := ls.CreateSecret(ctx, &models.SecretNode{
		ProjectID: proj.ID, EnvironmentID: env.ID, Name: "db-pw", IsSecret: true, Type: "text",
		Status: "active", OwnerID: 1,
	})
	require.NoError(t, err)

	share, err := ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: sec.ID, RecipientID: 2, IsGroup: false, OwnerID: 1, Permission: "read",
	})
	require.NoError(t, err)

	// Sanity: the grantee has access before the delete.
	perm, err := ls.CheckSharePermission(ctx, sec.ID, 2, time.Now())
	require.NoError(t, err)
	assert.Equal(t, "read", perm)

	// Delete the secret specifically to sever the grantee's access.
	require.NoError(t, ls.DeleteSecret(ctx, sec.ID))

	var deletedShare models.ShareRecord
	require.NoError(t, db.Unscoped().First(&deletedShare, share.ID).Error)
	assert.True(t, deletedShare.DeletedAt.Valid, "the share record must be revoked (soft-deleted) alongside the secret")

	// Restore the secret (via project restore, the only supported path once the parent
	// project stays live — RestoreSecret alone also works when the project is live).
	require.NoError(t, ls.RestoreSecret(ctx, sec.ID))

	// The previously-revoked share must NOT silently reactivate: CheckSharePermission
	// must deny the former grantee post-restore with zero new authorization step.
	perm, err = ls.CheckSharePermission(ctx, sec.ID, 2, time.Now())
	require.Error(t, err, "a share revoked by secret delete must not resurrect when the secret is restored")
	assert.Equal(t, "", perm)
}

// #119 residual: DeleteProject's secret cascade is a raw bulk UPDATE on secret_nodes,
// unlike DeleteSecret's per-secret path — before the fix it never revoked each
// project secret's ShareRecord rows, leaving them live even though the project (and its
// secrets) had just been deleted. Mirrors TestDeleteSecret_RevokesActiveShares, but
// through the project-delete cascade instead of a single secret delete, and additionally
// confirms RestoreProject does not silently reinstate the revoked share — "delete means
// gone" for sharing, whether the secret went via a direct delete or a project cascade.
func TestDeleteProject_RevokesActiveSharesForProjectSecrets(t *testing.T) {
	db := sharingConcurrentDB(t)
	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.Environment{}, &models.DynamicSecretConfig{}))
	ls := NewLocalStorage(db)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "o@x.io"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "grantee", Email: "g@x.io"}).Error)
	proj, err := ls.CreateProject(ctx, &models.Project{Name: "app"})
	require.NoError(t, err)
	env, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: proj.ID})
	require.NoError(t, err)
	sec, err := ls.CreateSecret(ctx, &models.SecretNode{
		ProjectID: proj.ID, EnvironmentID: env.ID, Name: "db-pw", IsSecret: true, Type: "text",
		Status: "active", OwnerID: 1,
	})
	require.NoError(t, err)

	share, err := ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: sec.ID, RecipientID: 2, IsGroup: false, OwnerID: 1, Permission: "read",
	})
	require.NoError(t, err)

	// Sanity: the grantee has access before the project delete.
	perm, err := ls.CheckSharePermission(ctx, sec.ID, 2, time.Now())
	require.NoError(t, err)
	assert.Equal(t, "read", perm)

	// Delete the whole project (not the secret directly) — the cascade path this test
	// pins, as distinct from TestDeleteSecret_RevokesActiveShares above.
	require.NoError(t, ls.DeleteProject(ctx, proj.ID))

	var deletedShare models.ShareRecord
	require.NoError(t, db.Unscoped().First(&deletedShare, share.ID).Error)
	assert.True(t, deletedShare.DeletedAt.Valid,
		"the share must be revoked (soft-deleted) when the project holding its secret is deleted")

	// Restoring the project brings the secret back, but must NOT resurrect the share
	// that the project's delete cascade already revoked.
	_, restoredSecrets, err := ls.RestoreProject(ctx, proj.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, restoredSecrets, "the project restore must bring the secret back")

	perm, err = ls.CheckSharePermission(ctx, sec.ID, 2, time.Now())
	require.Error(t, err, "a share revoked by project delete must not resurrect when the project is restored")
	assert.Equal(t, "", perm)
}

// TestDeleteProject_LeavesRoleGrantsUntouched pins the DeleteProject side of the #119
// residual: UserRole/GroupRole (unlike ShareRecord) have no DeletedAt column of their
// own and cannot be soft-deleted without a schema change to their composite primary
// key, and RestoreProject's existing role-reinstatement design (#161,
// requireAuthorityToReinstateProjectRoles) depends on these rows surviving the
// soft-delete window unchanged. They are cleaned up permanently, instead, once the
// project passes its retention window and is no longer restorable
// (PurgeDeletedProjectsBefore, see TestPurgeDeletedProjectsBefore_CascadesRoleGrants).
func TestDeleteProject_LeavesRoleGrantsUntouched(t *testing.T) {
	db := sharingConcurrentDB(t)
	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.Environment{}, &models.UserRole{}, &models.Group{}, &models.GroupRole{}, &models.DynamicSecretConfig{}))
	ls := NewLocalStorage(db)
	ctx := context.Background()

	proj, err := ls.CreateProject(ctx, &models.Project{Name: "app"})
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: proj.ID}).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 1, RoleID: 1, ProjectID: proj.ID}).Error)

	require.NoError(t, ls.DeleteProject(ctx, proj.ID))

	var userRoleCount, groupRoleCount int64
	require.NoError(t, db.Model(&models.UserRole{}).Where("project_id = ?", proj.ID).Count(&userRoleCount).Error)
	assert.Equal(t, int64(1), userRoleCount, "UserRole grants must survive a project soft-delete so restore can reinstate them")
	require.NoError(t, db.Model(&models.GroupRole{}).Where("project_id = ?", proj.ID).Count(&groupRoleCount).Error)
	assert.Equal(t, int64(1), groupRoleCount, "GroupRole grants must survive a project soft-delete so restore can reinstate them")
}

// #136: CheckSharePermission's OwnerID==userID check must not match when both are the
// zero value. A machine actor's ID is also 0, so an unguarded equality would grant it
// owner-level "write" on every ownerless (machine-created) secret.
func TestCheckSharePermission_OwnerZeroGuard(t *testing.T) {
	db := sharingConcurrentDB(t)
	ls := NewLocalStorage(db)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.SecretNode{
		ID: 100, Name: "s", ProjectID: 1, EnvironmentID: 1, OwnerID: 0, Status: "active", Type: "password",
	}).Error)

	perm, err := ls.CheckSharePermission(ctx, 100, 0, time.Now())
	require.Error(t, err, "userID=0 must not match an ownerless secret's OwnerID=0")
	assert.Equal(t, "", perm)
}

// #402: ListSharesBySecret/ListSharesByUser/ListSharesByGroup/ListSharesByOwner used
// to return already-EXPIRED (but not-yet-swept) shares alongside genuinely active
// ones — reporting/compliance-review/risk-scoring callers built on them therefore
// over-counted access that no longer authorizes anything, even though the real
// permission-check path (CheckSharePermission) already excluded expired shares.
// Every listing function must apply the identical expiry filter.
func TestListShares_ExcludeExpiredIncludeActive(t *testing.T) {
	db := sharingConcurrentDB(t)
	ls := NewLocalStorage(db)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "o@x.io"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "grantee-active", Email: "ga@x.io"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 3, Username: "grantee-time-bound-active", Email: "ge@x.io"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 4, Username: "grantee-only-expired", Email: "goe@x.io"}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 1, Name: "g-active"}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 2, Name: "g-expired"}).Error)
	require.NoError(t, db.Create(&models.SecretNode{
		ID: 100, Name: "s", ProjectID: 1, EnvironmentID: 1, OwnerID: 1, Status: "active", Type: "password",
	}).Error)

	// past is UTC explicitly, not just time.Now().Add(...): the two db.Model(...).
	// Update("expires_at", past) calls below write this raw value straight to the
	// column, bypassing ShareRecord.BeforeSave's UTC normalization (BeforeSave only
	// fires on a full-struct Save/Create — a raw column Update never touches the
	// hook receiver's own field, so there's nothing for it to normalize). Without
	// .UTC() here, "past" carries this machine's local offset while every listing
	// query's bound (time.Now().UTC() in local_sharing.go) does not, and SQLite's
	// plain string comparison between two differently-offset RFC3339 timestamps is
	// not reliably chronological -- exactly the class of bug G81 fixed for
	// production write paths (which all go through the hook-covered Save/Create,
	// unlike this test's deliberately-raw "simulate a not-yet-swept expiry" update).
	past := time.Now().UTC().Add(-1 * time.Hour)
	future := time.Now().Add(1 * time.Hour)

	// Active direct share (permanent, no expiry).
	activeDirect, err := ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: 100, RecipientID: 2, IsGroup: false, OwnerID: 1, Permission: "read",
	})
	require.NoError(t, err)

	// Active, time-bound direct share that hasn't expired yet.
	activeTimeBound, err := ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: 100, RecipientID: 3, IsGroup: false, OwnerID: 1, Permission: "read", ExpiresAt: &future,
	})
	require.NoError(t, err)

	// Direct share to a distinct recipient (4), created permanent then back-dated
	// directly to simulate a time-bound share whose expiry has already passed but
	// which hasn't been swept yet (DeleteExpiredShareRecords runs on its own tick).
	expiredDirect, err := ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: 100, RecipientID: 4, IsGroup: false, OwnerID: 1, Permission: "write",
	})
	require.NoError(t, err)
	require.NoError(t, db.Model(&models.ShareRecord{}).Where("id = ?", expiredDirect.ID).
		Update("expires_at", past).Error)

	// Active group share.
	activeGroup, err := ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: 100, RecipientID: 1, IsGroup: true, OwnerID: 1, Permission: "read",
	})
	require.NoError(t, err)

	// Expired group share (distinct recipient group so it doesn't collide with the
	// active group share above).
	expiredGroup, err := ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: 100, RecipientID: 2, IsGroup: true, OwnerID: 1, Permission: "write",
	})
	require.NoError(t, err)
	require.NoError(t, db.Model(&models.ShareRecord{}).Where("id = ?", expiredGroup.ID).
		Update("expires_at", past).Error)

	// --- ListSharesBySecret ---
	bySecret, err := ls.ListSharesBySecret(ctx, 100, time.Now())
	require.NoError(t, err)
	gotIDs := shareIDSet(bySecret)
	assert.Contains(t, gotIDs, activeDirect.ID, "permanent active share must be listed")
	assert.Contains(t, gotIDs, activeTimeBound.ID, "not-yet-expired time-bound share must be listed")
	assert.Contains(t, gotIDs, activeGroup.ID, "active group share must be listed")
	assert.NotContains(t, gotIDs, expiredDirect.ID, "expired direct share must be excluded")
	assert.NotContains(t, gotIDs, expiredGroup.ID, "expired group share must be excluded")

	// --- ListSharesByUser (recipient 3: one active time-bound, none expired left there) ---
	byUser3, err := ls.ListSharesByUser(ctx, 3, time.Now())
	require.NoError(t, err)
	got3 := shareIDSet(byUser3)
	assert.Contains(t, got3, activeTimeBound.ID, "active time-bound share must be listed for its recipient")

	// --- ListSharesByUser (recipient 4: only an expired share) ---
	byUser4, err := ls.ListSharesByUser(ctx, 4, time.Now())
	require.NoError(t, err)
	assert.Empty(t, byUser4, "a recipient whose only share is expired must see no active shares")

	// --- ListSharesByGroup ---
	byGroup1, err := ls.ListSharesByGroup(ctx, 1, time.Now())
	require.NoError(t, err)
	got1 := shareIDSet(byGroup1)
	assert.Contains(t, got1, activeGroup.ID, "active group share must be listed for its group")

	byGroup2, err := ls.ListSharesByGroup(ctx, 2, time.Now())
	require.NoError(t, err)
	assert.Empty(t, byGroup2, "a group whose only share is expired must see no active shares")

	// --- ListSharesByOwner ---
	byOwner, err := ls.ListSharesByOwner(ctx, 1, time.Now())
	require.NoError(t, err)
	gotOwner := shareIDSet(byOwner)
	assert.Contains(t, gotOwner, activeDirect.ID)
	assert.Contains(t, gotOwner, activeTimeBound.ID)
	assert.Contains(t, gotOwner, activeGroup.ID)
	assert.NotContains(t, gotOwner, expiredDirect.ID, "expired share must be excluded from the owner's outgoing list")
	assert.NotContains(t, gotOwner, expiredGroup.ID, "expired group share must be excluded from the owner's outgoing list")
}

func shareIDSet(shares []*models.ShareRecord) map[uint]bool {
	out := make(map[uint]bool, len(shares))
	for _, s := range shares {
		out[s.ID] = true
	}
	return out
}

// #252: CheckSharePermission used to resolve a direct-vs-group conflict by returning
// whichever it happened to check first (the direct share, unconditionally) — so a
// weaker direct grant could silently override a stronger group grant. It must instead
// return the STRONGER of the two, mirroring the "strongest grant wins" rank convention
// in internal/core/secret_access_list.go (read < write < owner). Tested both
// directions so a naive fix that just flips the bug (always preferring the group
// share) would also fail.
func TestCheckSharePermission_DirectVsGroupConflict_StrongestWins(t *testing.T) {
	db := sharingConcurrentDB(t)
	ls := NewLocalStorage(db)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "o@x.io"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "member", Email: "m@x.io"}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 10, Name: "team"}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 2, GroupID: 10}).Error)

	t.Run("direct weaker than group", func(t *testing.T) {
		require.NoError(t, db.Create(&models.SecretNode{
			ID: 100, Name: "s1", ProjectID: 1, EnvironmentID: 1, OwnerID: 1, Status: "active", Type: "password",
		}).Error)
		_, err := ls.CreateShareRecord(ctx, &models.ShareRecord{
			SecretID: 100, RecipientID: 2, IsGroup: false, OwnerID: 1, Permission: "read",
		})
		require.NoError(t, err)
		_, err = ls.CreateShareRecord(ctx, &models.ShareRecord{
			SecretID: 100, RecipientID: 10, IsGroup: true, OwnerID: 1, Permission: "write",
		})
		require.NoError(t, err)

		perm, err := ls.CheckSharePermission(ctx, 100, 2, time.Now())
		require.NoError(t, err)
		assert.Equal(t, "write", perm, "a stronger group grant must not be shadowed by a weaker direct grant")
	})

	t.Run("direct stronger than group", func(t *testing.T) {
		require.NoError(t, db.Create(&models.SecretNode{
			ID: 101, Name: "s2", ProjectID: 1, EnvironmentID: 1, OwnerID: 1, Status: "active", Type: "password",
		}).Error)
		_, err := ls.CreateShareRecord(ctx, &models.ShareRecord{
			SecretID: 101, RecipientID: 2, IsGroup: false, OwnerID: 1, Permission: "write",
		})
		require.NoError(t, err)
		_, err = ls.CreateShareRecord(ctx, &models.ShareRecord{
			SecretID: 101, RecipientID: 10, IsGroup: true, OwnerID: 1, Permission: "read",
		})
		require.NoError(t, err)

		perm, err := ls.CheckSharePermission(ctx, 101, 2, time.Now())
		require.NoError(t, err)
		assert.Equal(t, "write", perm, "a stronger direct grant must win over a weaker group grant")
	})
}

// TestCheckSharePermission_ProjectScopedMembershipDoesNotCrossProjects is the
// #G01 regression: a group MEMBERSHIP scoped to one project must not confer
// that group's share permission on a secret in a DIFFERENT project.
func TestCheckSharePermission_ProjectScopedMembershipDoesNotCrossProjects(t *testing.T) {
	db := sharingConcurrentDB(t)
	ls := NewLocalStorage(db)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner2", Email: "o2@x.io"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 3, Username: "member2", Email: "m2@x.io"}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 11, Name: "team2"}).Error)
	// member2's membership in group 11 is scoped ONLY to project 7.
	require.NoError(t, db.Create(&models.UserGroup{UserID: 3, GroupID: 11, ProjectID: 7}).Error)

	// The secret is in project 9 — a DIFFERENT project than the membership.
	require.NoError(t, db.Create(&models.SecretNode{
		ID: 200, Name: "s3", ProjectID: 9, EnvironmentID: 1, OwnerID: 1, Status: "active", Type: "password",
	}).Error)
	_, err := ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: 200, RecipientID: 11, IsGroup: true, OwnerID: 1, Permission: "write",
	})
	require.NoError(t, err)

	perm, err := ls.CheckSharePermission(ctx, 200, 3, time.Now())
	require.Error(t, err, "a membership scoped to project 7 must not grant access to a secret in project 9")
	assert.Empty(t, perm)

	secrets, err := ls.ListSharedSecrets(ctx, 3, time.Now())
	require.NoError(t, err)
	for _, s := range secrets {
		assert.NotEqual(t, uint(200), s.ID, "ListSharedSecrets must not surface a secret reached only via a cross-project membership")
	}
}

// store-secret-acl-002: CheckSharePermission's owner-equality branch used to grant
// owner-level "write" purely on secret.OwnerID == userID, with no check that the
// owner account itself was still live — unlike the group-share branch, which already
// JOINs users ... deleted_at IS NULL and denies a soft-deleted group member. A
// deprovisioned owner's account row stays live for audit/restore (SCIM/DeleteUser
// soft-delete), and DeleteUser's session/cache invalidation runs on a separate code
// path whose propagation isn't instantaneous across instances, so this branch must
// independently verify owner liveness — the same guard the group branch already has.
func TestCheckSharePermission_SoftDeletedOwnerDeniesAccess(t *testing.T) {
	db := sharingConcurrentDB(t)
	ls := NewLocalStorage(db)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "o@x.io"}).Error)
	require.NoError(t, db.Create(&models.SecretNode{
		ID: 300, Name: "s4", ProjectID: 1, EnvironmentID: 1, OwnerID: 1, Status: "active", Type: "password",
	}).Error)

	// While the owner is live, owner-equality grants "write".
	perm, err := ls.CheckSharePermission(ctx, 300, 1, time.Now())
	require.NoError(t, err)
	assert.Equal(t, "write", perm, "a live owner must still get owner-level access")

	// Soft-delete the owner's account (mirrors DeleteUser's user-row soft delete).
	require.NoError(t, db.Delete(&models.User{}, 1).Error)

	perm, err = ls.CheckSharePermission(ctx, 300, 1, time.Now())
	require.Error(t, err, "a soft-deleted owner must not retain owner-level access via OwnerID equality")
	assert.Empty(t, perm)
}

// store-secret-acl-002: CheckSharePermission's direct-share query used to have no
// user-liveness guard at all, unlike the group-share query's JOIN users ...
// deleted_at IS NULL. A soft-deleted direct recipient's ShareRecord row stays live
// for audit/restore, so without this guard a deleted user's direct share kept
// granting access even though the equivalent group-share path already denied it for
// a deleted group member (see TestGroupShare_SoftDeletedMemberExcluded). Also checks
// ListSharedSecrets's identical direct-query gap, fixed for the same consistency
// reason.
func TestCheckSharePermission_SoftDeletedDirectRecipientDeniesAccess(t *testing.T) {
	db := sharingConcurrentDB(t)
	ls := NewLocalStorage(db)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner3", Email: "o3@x.io"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "grantee3", Email: "g3@x.io"}).Error)
	require.NoError(t, db.Create(&models.SecretNode{
		ID: 301, Name: "s5", ProjectID: 1, EnvironmentID: 1, OwnerID: 1, Status: "active", Type: "password",
	}).Error)
	_, err := ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: 301, RecipientID: 2, IsGroup: false, OwnerID: 1, Permission: "write",
	})
	require.NoError(t, err)

	// While the recipient is live, the direct share grants access.
	perm, err := ls.CheckSharePermission(ctx, 301, 2, time.Now())
	require.NoError(t, err)
	assert.Equal(t, "write", perm, "a live direct recipient must still get the shared permission")
	secrets, err := ls.ListSharedSecrets(ctx, 2, time.Now())
	require.NoError(t, err)
	assert.Len(t, secrets, 1, "a live direct recipient must see the secret in their shared list")

	// Soft-delete the recipient's account.
	require.NoError(t, db.Delete(&models.User{}, 2).Error)

	perm, err = ls.CheckSharePermission(ctx, 301, 2, time.Now())
	require.Error(t, err, "a soft-deleted direct recipient must not retain access via their ShareRecord")
	assert.Empty(t, perm)
	secrets, err = ls.ListSharedSecrets(ctx, 2, time.Now())
	require.NoError(t, err)
	assert.Empty(t, secrets, "a soft-deleted direct recipient must not see the secret in their shared list")
}

// CWE-284 / sibling of #370: DeleteSecret must also delete SecretACL rows in the
// same transaction so that ACL-based access cannot silently reactivate when the
// secret is later restored from the recycle bin (the same class of bug fixed for
// ShareRecord in #370).
func TestDeleteSecret_RevokesSecretACLs(t *testing.T) {
	db := sharingConcurrentDB(t)
	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.Environment{}, &models.SecretACL{}, &models.AccessRequest{}))
	ls := NewLocalStorage(db)
	ctx := context.Background()

	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "o@x.io"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "grantee", Email: "g@x.io"}).Error)
	proj, err := ls.CreateProject(ctx, &models.Project{Name: "acl-app"})
	require.NoError(t, err)
	env, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: proj.ID})
	require.NoError(t, err)
	sec, err := ls.CreateSecret(ctx, &models.SecretNode{
		ProjectID: proj.ID, EnvironmentID: env.ID, Name: "acl-secret", IsSecret: true, Type: "text",
		Status: "active", OwnerID: 1,
	})
	require.NoError(t, err)

	// Grant user 2 an ACL on the secret.
	acl := &models.SecretACL{SecretID: sec.ID, UserID: 2, Permissions: `["secrets.read"]`, GrantedBy: 1}
	require.NoError(t, db.Create(acl).Error)
	aclID := acl.ID

	// Delete the secret — both the soft-delete and the ACL row must be transacted together.
	require.NoError(t, ls.DeleteSecret(ctx, sec.ID))

	// The ACL row must be gone (hard-deleted by the Where+Delete call).
	var count int64
	require.NoError(t, db.Model(&models.SecretACL{}).Where("id = ?", aclID).Count(&count).Error)
	assert.Equal(t, int64(0), count, "SecretACL row must be deleted alongside the secret")
}
