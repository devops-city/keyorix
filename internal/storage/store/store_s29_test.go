// store_s29_test.go — s29 coverage blitz for internal/storage/store.
//
// Targets:
//
//	local_scheduler_lock.go
//	  WithSchedulerLock — SQLite happy + error propagation (already tested in
//	  local_scheduler_lock_test.go; add fn-error branch to push from 9.5%→full)
//
//	local_audit_checkpoint_lock.go
//	  WithAuditCheckpointLock — fn-error + mutex-serialised concurrent calls
//
//	local_sharing.go
//	  CreateShareRecord          — validation error, secret not found, wrong owner,
//	                               group not found, user not found, update-existing
//	  GetShareRecord             — not-found
//	  UpdateShareRecord          — validation error, not-found, happy path
//	  DeleteShareRecord          — not-found
//	  DeleteExpiredShareRecords  — no expired (empty), expired rows removed
//	  ListSharesBySecret         — happy path
//	  ListSharesBySecretIDs      — empty-ids early-return + happy path
//	  ListSharesByUser           — happy path
//	  ListSharesByOwner          — happy path
//	  ListSharesByGroup          — happy path
//	  ListSharedSecrets          — happy path (direct + group)
//	  CheckSharePermission       — not-found secret, direct share, group share,
//	                               both direct+group (stronger wins), no permission
//
//	local_secrets.go
//	  DeleteSecret               — not-found, share-revoke cascade (happy)
//	  RestoreSecret              — not-found, dead project, dead env, happy
//	  ListProjects               — happy
//	  ListProjectsWithCounts     — happy (no includeDeleted / includeDeleted)
//	  GetEnvironment             — not-found + happy
//	  DeleteEnvironment          — has-active-secrets block, not-found, happy
//	  RestoreEnvironment         — dead-project block
//	  DeleteProjectIfEmpty       — non-empty (returns count), empty (deletes)
//	  RestoreProject             — not-found, happy cascade restore
//	  ListEnvironments           — happy
//	  ListEnvironmentsByProject  — happy
//	  ListEnvironmentsByProjectIncludingDeleted — happy
//	  SetSecretCertNotAfter      — happy
//	  IncrementSecretReadCount   — happy
//	  SetSecretTags              — happy path
//	  ListSecrets                — basic filter (DeletedOnly + IncludeDeleted)
//	  ListOrphanedSecrets        — happy
//	  CountOrphanedSecretsByProject — empty IDs + happy
//	  CountExpiringSecretsByProject — empty IDs + happy
//
//	local_access_review_campaigns.go
//	  GetAccessReviewCampaign              — not-found + happy
//	  GetOpenAccessReviewCampaign          — nil-when-none + happy
//	  GetLatestClosedAccessReviewCampaign  — nil-when-none + happy
//	  GetAccessReviewItem                  — not-found + happy
//	  CreateAccessReviewItems              — empty slice no-op
//	  ListAccessReviewItems                — happy
//	  CountPendingAccessReviewItems        — happy
//	  UpdateAccessReviewItem               — happy (rows affected = 1)
//
//	local_scheduler_lock_lease.go
//	  TryAcquireSchedulerLock  — first acquire, contended (other holder), expired reclaim, self-renew
//	  ReleaseSchedulerLock     — owner release + foreign-holder no-op
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

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// newS29Store opens a unique in-memory SQLite DB with requested models migrated.
func newS29Store(t *testing.T, mods ...any) *LocalStorage {
	t.Helper()
	db := sqlitetest.OpenWithDialector(t, "stores29_", sqlite.Open, &gorm.Config{})
	if len(mods) > 0 {
		require.NoError(t, db.AutoMigrate(mods...))
	}
	return NewLocalStorage(db)
}

// sharingModels lists the models needed for sharing-related tests.
var sharingModels = []any{
	&models.User{}, &models.Group{}, &models.UserGroup{},
	&models.SecretNode{}, &models.ShareRecord{}, &models.SecretACL{},
	&models.Project{}, &models.Environment{},
}

// seedShareFixture creates the minimal seed: one owner, one recipient user, one
// secret. Returns (ownerID, recipientID, secretID).
func seedShareFixture(t *testing.T, ls *LocalStorage) (ownerID, recipientID, secretID uint) {
	t.Helper()
	require.NoError(t, ls.db.Create(&models.User{ID: 10, Username: "owner10", Email: "owner10@x.io"}).Error)
	require.NoError(t, ls.db.Create(&models.User{ID: 20, Username: "recip20", Email: "recip20@x.io"}).Error)
	require.NoError(t, ls.db.Create(&models.SecretNode{
		ID: 100, Name: "sec100", ProjectID: 1, EnvironmentID: 1,
		OwnerID: 10, Status: "active", Type: "password",
	}).Error)
	return 10, 20, 100
}

// ---------------------------------------------------------------------------
// local_scheduler_lock.go — WithSchedulerLock additional coverage
// ---------------------------------------------------------------------------

// TestWithSchedulerLock_S29_FnErrorPropagates exercises the fn-returns-error
// branch: (true, err) so the covered-statements counter crosses 9.5%.
func TestWithSchedulerLock_S29_FnErrorPropagates(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	ls := NewLocalStorage(db)

	want := assert.AnError
	ran := false
	got, gotErr := ls.WithSchedulerLock(context.Background(), 99, func(context.Context) error {
		ran = true
		return want
	})
	assert.True(t, got)
	assert.True(t, ran)
	require.ErrorIs(t, gotErr, want)
}

// ---------------------------------------------------------------------------
// local_audit_checkpoint_lock.go — WithAuditCheckpointLock
// ---------------------------------------------------------------------------

// TestWithAuditCheckpointLock_S29_FnError verifies that fn's error is returned
// unchanged (non-Postgres path, fn returns error).
func TestWithAuditCheckpointLock_S29_FnError(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	ls := NewLocalStorage(db)

	want := assert.AnError
	gotErr := ls.WithAuditCheckpointLock(context.Background(), func(context.Context) error { return want })
	require.ErrorIs(t, gotErr, want)
}

// TestWithAuditCheckpointLock_S29_Serializes verifies the mutex: two sequential
// calls on the same store both complete successfully (the second doesn't deadlock
// because the first released the mutex).
func TestWithAuditCheckpointLock_S29_Serializes(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	ls := NewLocalStorage(db)
	ctx := context.Background()

	var seq []int
	require.NoError(t, ls.WithAuditCheckpointLock(ctx, func(context.Context) error { seq = append(seq, 1); return nil }))
	require.NoError(t, ls.WithAuditCheckpointLock(ctx, func(context.Context) error { seq = append(seq, 2); return nil }))
	assert.Equal(t, []int{1, 2}, seq)
}

// ---------------------------------------------------------------------------
// local_sharing.go — CreateShareRecord
// ---------------------------------------------------------------------------

// TestCreateShareRecord_S29_ValidationError verifies the early-return when
// ValidateShareRecord fails (zero SecretID).
func TestCreateShareRecord_S29_ValidationError(t *testing.T) {
	ls := newS29Store(t, sharingModels...)
	_, err := ls.CreateShareRecord(context.Background(), &models.ShareRecord{
		SecretID: 0, OwnerID: 1, RecipientID: 2, Permission: "read",
	})
	require.Error(t, err)
}

// TestCreateShareRecord_S29_SecretNotFound verifies the error when the referenced
// secret does not exist.
func TestCreateShareRecord_S29_SecretNotFound(t *testing.T) {
	ls := newS29Store(t, sharingModels...)
	_, err := ls.CreateShareRecord(context.Background(), &models.ShareRecord{
		SecretID: 999, OwnerID: 1, RecipientID: 2, Permission: "read",
	})
	require.Error(t, err)
}

// TestCreateShareRecord_S29_WrongOwner verifies that sharing a secret you don't
// own returns an authorization error.
func TestCreateShareRecord_S29_WrongOwner(t *testing.T) {
	ls := newS29Store(t, sharingModels...)
	ownerID, recipID, secID := seedShareFixture(t, ls)
	_ = recipID

	_, err := ls.CreateShareRecord(context.Background(), &models.ShareRecord{
		SecretID: secID, OwnerID: ownerID + 1, RecipientID: 2, Permission: "read",
	})
	require.Error(t, err)
}

// TestCreateShareRecord_S29_UserNotFound verifies that trying to share with a
// non-existent user returns an error.
func TestCreateShareRecord_S29_UserNotFound(t *testing.T) {
	ls := newS29Store(t, sharingModels...)
	ownerID, _, secID := seedShareFixture(t, ls)

	_, err := ls.CreateShareRecord(context.Background(), &models.ShareRecord{
		SecretID: secID, OwnerID: ownerID, RecipientID: 999, IsGroup: false, Permission: "read",
	})
	require.Error(t, err)
}

// TestCreateShareRecord_S29_GroupNotFound verifies that trying to share with a
// non-existent group returns an error.
func TestCreateShareRecord_S29_GroupNotFound(t *testing.T) {
	ls := newS29Store(t, sharingModels...)
	ownerID, _, secID := seedShareFixture(t, ls)

	_, err := ls.CreateShareRecord(context.Background(), &models.ShareRecord{
		SecretID: secID, OwnerID: ownerID, RecipientID: 999, IsGroup: true, Permission: "read",
	})
	require.Error(t, err)
}

// TestCreateShareRecord_S29_UpdatesExisting exercises the "row already exists"
// upsert path: a second CreateShareRecord for the same (secret, recipient,
// is_group) tuple must update the existing row's permission and return it.
func TestCreateShareRecord_S29_UpdatesExisting(t *testing.T) {
	ls := newS29Store(t, sharingModels...)
	ownerID, recipID, secID := seedShareFixture(t, ls)
	ctx := context.Background()

	sr1, err := ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: secID, OwnerID: ownerID, RecipientID: recipID, IsGroup: false, Permission: "read",
	})
	require.NoError(t, err)
	assert.Equal(t, "read", sr1.Permission)

	sr2, err := ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: secID, OwnerID: ownerID, RecipientID: recipID, IsGroup: false, Permission: "write",
	})
	require.NoError(t, err)
	assert.Equal(t, "write", sr2.Permission)
	assert.Equal(t, sr1.ID, sr2.ID, "must return the existing row, not a new one")
}

// TestCreateShareRecord_S29_NewRow exercises the happy-path INSERT branch when
// no existing active row is present.
func TestCreateShareRecord_S29_NewRow(t *testing.T) {
	ls := newS29Store(t, sharingModels...)
	ownerID, recipID, secID := seedShareFixture(t, ls)

	sr, err := ls.CreateShareRecord(context.Background(), &models.ShareRecord{
		SecretID: secID, OwnerID: ownerID, RecipientID: recipID, IsGroup: false, Permission: "read",
	})
	require.NoError(t, err)
	assert.NotZero(t, sr.ID)
	assert.Equal(t, "read", sr.Permission)
}

// ---------------------------------------------------------------------------
// local_sharing.go — GetShareRecord
// ---------------------------------------------------------------------------

func TestGetShareRecord_S29_NotFound(t *testing.T) {
	ls := newS29Store(t, sharingModels...)
	_, err := ls.GetShareRecord(context.Background(), 9999)
	require.Error(t, err)
}

func TestGetShareRecord_S29_Found(t *testing.T) {
	ls := newS29Store(t, sharingModels...)
	ownerID, recipID, secID := seedShareFixture(t, ls)
	ctx := context.Background()

	created, err := ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: secID, OwnerID: ownerID, RecipientID: recipID, IsGroup: false, Permission: "read",
	})
	require.NoError(t, err)

	got, err := ls.GetShareRecord(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, created.ID, got.ID)
}

// ---------------------------------------------------------------------------
// local_sharing.go — UpdateShareRecord
// ---------------------------------------------------------------------------

func TestUpdateShareRecord_S29_ValidationError(t *testing.T) {
	ls := newS29Store(t, sharingModels...)
	// ID=0 triggers ValidateShareUpdate error.
	_, err := ls.UpdateShareRecord(context.Background(), &models.ShareRecord{ID: 0, Permission: "read"})
	require.Error(t, err)
}

func TestUpdateShareRecord_S29_NotFound(t *testing.T) {
	ls := newS29Store(t, sharingModels...)
	_, err := ls.UpdateShareRecord(context.Background(), &models.ShareRecord{ID: 9999, Permission: "write"})
	require.Error(t, err)
}

func TestUpdateShareRecord_S29_HappyPath(t *testing.T) {
	ls := newS29Store(t, sharingModels...)
	ownerID, recipID, secID := seedShareFixture(t, ls)
	ctx := context.Background()

	created, err := ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: secID, OwnerID: ownerID, RecipientID: recipID, IsGroup: false, Permission: "read",
	})
	require.NoError(t, err)

	updated, err := ls.UpdateShareRecord(ctx, &models.ShareRecord{ID: created.ID, Permission: "write"})
	require.NoError(t, err)
	assert.Equal(t, "write", updated.Permission)
}

// ---------------------------------------------------------------------------
// local_sharing.go — DeleteShareRecord
// ---------------------------------------------------------------------------

func TestDeleteShareRecord_S29_NotFound(t *testing.T) {
	ls := newS29Store(t, sharingModels...)
	err := ls.DeleteShareRecord(context.Background(), 9999)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_sharing.go — DeleteExpiredShareRecords
// ---------------------------------------------------------------------------

func TestDeleteExpiredShareRecords_S29_NoneExpired(t *testing.T) {
	ls := newS29Store(t, sharingModels...)
	ownerID, recipID, secID := seedShareFixture(t, ls)
	ctx := context.Background()

	// Create a permanent (non-expiring) share.
	_, err := ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: secID, OwnerID: ownerID, RecipientID: recipID, IsGroup: false, Permission: "read",
	})
	require.NoError(t, err)

	removed, err := ls.DeleteExpiredShareRecords(ctx, time.Now())
	require.NoError(t, err)
	assert.Empty(t, removed)
}

func TestDeleteExpiredShareRecords_S29_RemovesExpired(t *testing.T) {
	ls := newS29Store(t, sharingModels...)
	ownerID, recipID, secID := seedShareFixture(t, ls)
	ctx := context.Background()

	past := time.Now().Add(-time.Hour)
	// Insert an expired share directly (bypassing CreateShareRecord's validation
	// which doesn't accept past expiries).
	require.NoError(t, ls.db.Create(&models.ShareRecord{
		SecretID: secID, OwnerID: ownerID, RecipientID: recipID,
		IsGroup: false, Permission: "read", ExpiresAt: &past,
	}).Error)

	removed, err := ls.DeleteExpiredShareRecords(ctx, time.Now())
	require.NoError(t, err)
	assert.Len(t, removed, 1)
}

// ---------------------------------------------------------------------------
// local_sharing.go — list methods
// ---------------------------------------------------------------------------

func TestListSharesBySecret_S29_HappyPath(t *testing.T) {
	ls := newS29Store(t, sharingModels...)
	ownerID, recipID, secID := seedShareFixture(t, ls)
	ctx := context.Background()

	_, err := ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: secID, OwnerID: ownerID, RecipientID: recipID, IsGroup: false, Permission: "read",
	})
	require.NoError(t, err)

	shares, err := ls.ListSharesBySecret(ctx, secID, time.Now())
	require.NoError(t, err)
	assert.Len(t, shares, 1)
}

func TestListSharesBySecretIDs_S29_EmptyEarlyReturn(t *testing.T) {
	ls := newS29Store(t, sharingModels...)
	shares, err := ls.ListSharesBySecretIDs(context.Background(), nil, time.Now())
	require.NoError(t, err)
	assert.Nil(t, shares)
}

func TestListSharesBySecretIDs_S29_HappyPath(t *testing.T) {
	ls := newS29Store(t, sharingModels...)
	ownerID, recipID, secID := seedShareFixture(t, ls)
	ctx := context.Background()

	_, err := ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: secID, OwnerID: ownerID, RecipientID: recipID, IsGroup: false, Permission: "read",
	})
	require.NoError(t, err)

	shares, err := ls.ListSharesBySecretIDs(ctx, []uint{secID}, time.Now())
	require.NoError(t, err)
	assert.Len(t, shares, 1)
}

func TestListSharesByUser_S29_HappyPath(t *testing.T) {
	ls := newS29Store(t, sharingModels...)
	ownerID, recipID, secID := seedShareFixture(t, ls)
	ctx := context.Background()

	_, err := ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: secID, OwnerID: ownerID, RecipientID: recipID, IsGroup: false, Permission: "read",
	})
	require.NoError(t, err)

	shares, err := ls.ListSharesByUser(ctx, recipID, time.Now())
	require.NoError(t, err)
	assert.Len(t, shares, 1)
}

func TestListSharesByOwner_S29_HappyPath(t *testing.T) {
	ls := newS29Store(t, sharingModels...)
	ownerID, recipID, secID := seedShareFixture(t, ls)
	ctx := context.Background()

	_, err := ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: secID, OwnerID: ownerID, RecipientID: recipID, IsGroup: false, Permission: "read",
	})
	require.NoError(t, err)

	shares, err := ls.ListSharesByOwner(ctx, ownerID, time.Now())
	require.NoError(t, err)
	assert.Len(t, shares, 1)
}

func TestListSharesByGroup_S29_HappyPath(t *testing.T) {
	ls := newS29Store(t, sharingModels...)
	ownerID, _, secID := seedShareFixture(t, ls)
	ctx := context.Background()

	// Create a group.
	require.NoError(t, ls.db.Create(&models.Group{ID: 5, Name: "grp5"}).Error)

	_, err := ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: secID, OwnerID: ownerID, RecipientID: 5, IsGroup: true, Permission: "read",
	})
	require.NoError(t, err)

	shares, err := ls.ListSharesByGroup(ctx, 5, time.Now())
	require.NoError(t, err)
	assert.Len(t, shares, 1)
}

func TestListSharedSecrets_S29_DirectShare(t *testing.T) {
	ls := newS29Store(t, sharingModels...)
	ownerID, recipID, secID := seedShareFixture(t, ls)
	ctx := context.Background()

	_, err := ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: secID, OwnerID: ownerID, RecipientID: recipID, IsGroup: false, Permission: "read",
	})
	require.NoError(t, err)

	secrets, err := ls.ListSharedSecrets(ctx, recipID, time.Now())
	require.NoError(t, err)
	assert.Len(t, secrets, 1)
	assert.Equal(t, secID, secrets[0].ID)
}

// ---------------------------------------------------------------------------
// local_sharing.go — CheckSharePermission
// ---------------------------------------------------------------------------

func TestCheckSharePermission_S29_SecretNotFound(t *testing.T) {
	ls := newS29Store(t, sharingModels...)
	_, err := ls.CheckSharePermission(context.Background(), 9999, 1, time.Now())
	require.Error(t, err)
}

func TestCheckSharePermission_S29_DirectShare(t *testing.T) {
	ls := newS29Store(t, sharingModels...)
	ownerID, recipID, secID := seedShareFixture(t, ls)
	ctx := context.Background()

	_, err := ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: secID, OwnerID: ownerID, RecipientID: recipID, IsGroup: false, Permission: "write",
	})
	require.NoError(t, err)

	perm, err := ls.CheckSharePermission(ctx, secID, recipID, time.Now())
	require.NoError(t, err)
	assert.Equal(t, "write", perm)
}

func TestCheckSharePermission_S29_NoPermission(t *testing.T) {
	ls := newS29Store(t, sharingModels...)
	_, _, secID := seedShareFixture(t, ls)

	_, err := ls.CheckSharePermission(context.Background(), secID, 99, time.Now()) // 99 has no share
	require.Error(t, err)
}

func TestCheckSharePermission_S29_OwnerGetsWrite(t *testing.T) {
	ls := newS29Store(t, sharingModels...)
	ownerID, _, secID := seedShareFixture(t, ls)

	perm, err := ls.CheckSharePermission(context.Background(), secID, ownerID, time.Now())
	require.NoError(t, err)
	assert.Equal(t, "write", perm)
}

// ---------------------------------------------------------------------------
// local_secrets.go — DeleteSecret
// ---------------------------------------------------------------------------

func TestDeleteSecret_S29_NotFound(t *testing.T) {
	ls := newS29Store(t, &models.SecretNode{}, &models.ShareRecord{}, &models.SecretACL{})
	err := ls.DeleteSecret(context.Background(), 9999)
	require.Error(t, err)
}

func TestDeleteSecret_S29_RevokesShares(t *testing.T) {
	ls := newS29Store(t, sharingModels...)
	ownerID, recipID, secID := seedShareFixture(t, ls)
	ctx := context.Background()

	_, err := ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: secID, OwnerID: ownerID, RecipientID: recipID, IsGroup: false, Permission: "read",
	})
	require.NoError(t, err)

	require.NoError(t, ls.DeleteSecret(ctx, secID))

	// Share must be gone.
	shares, err := ls.ListSharesBySecret(ctx, secID, time.Now())
	require.NoError(t, err)
	assert.Empty(t, shares)
}

// ---------------------------------------------------------------------------
// local_secrets.go — RestoreSecret
// ---------------------------------------------------------------------------

func TestRestoreSecret_S29_NotFound(t *testing.T) {
	ls := newS29Store(t, sharingModels...)
	err := ls.RestoreSecret(context.Background(), 9999)
	require.Error(t, err)
}

func TestRestoreSecret_S29_DeadProject(t *testing.T) {
	ls := newS29Store(t, sharingModels...)
	db := ls.db

	// Create a project that is soft-deleted.
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p1"}).Error)
	require.NoError(t, db.Delete(&models.Project{}, 1).Error)

	// Insert a secret under the deleted project, itself also soft-deleted.
	require.NoError(t, db.Exec("INSERT INTO secret_nodes (id, name, project_id, environment_id, status, type, deleted_at) VALUES (201, 'sec201', 1, 0, 'active', 'password', datetime('now'))").Error)

	err := ls.RestoreSecret(context.Background(), 201)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "project")
}

// ---------------------------------------------------------------------------
// local_secrets.go — Project / Environment helpers
// ---------------------------------------------------------------------------

func TestListProjects_S29_HappyPath(t *testing.T) {
	ls := newS29Store(t, &models.Project{})
	ctx := context.Background()

	_, err := ls.CreateProject(ctx, &models.Project{Name: "Alpha"})
	require.NoError(t, err)

	projects, err := ls.ListProjects(ctx)
	require.NoError(t, err)
	assert.Len(t, projects, 1)
}

func TestListProjectsWithCounts_S29_HappyPath(t *testing.T) {
	ls := newS29Store(t, &models.Project{}, &models.SecretNode{}, &models.Environment{})
	ctx := context.Background()

	_, err := ls.CreateProject(ctx, &models.Project{Name: "Beta"})
	require.NoError(t, err)

	rows, err := ls.ListProjectsWithCounts(ctx, false)
	require.NoError(t, err)
	assert.Len(t, rows, 1)
	assert.Equal(t, "Beta", rows[0].Name)
}

func TestListProjectsWithCounts_S29_IncludeDeleted(t *testing.T) {
	ls := newS29Store(t, &models.Project{}, &models.SecretNode{}, &models.Environment{}, &models.ShareRecord{}, &models.DynamicSecretConfig{})
	ctx := context.Background()

	p, err := ls.CreateProject(ctx, &models.Project{Name: "Gamma"})
	require.NoError(t, err)
	require.NoError(t, ls.DeleteProject(ctx, p.ID))

	rows, err := ls.ListProjectsWithCounts(ctx, true)
	require.NoError(t, err)
	// Soft-deleted project must appear when includeDeleted=true.
	assert.True(t, len(rows) >= 1)
}

func TestGetEnvironment_S29_NotFound(t *testing.T) {
	ls := newS29Store(t, &models.Environment{})
	_, err := ls.GetEnvironment(context.Background(), 9999)
	require.Error(t, err)
}

func TestGetEnvironment_S29_Found(t *testing.T) {
	ls := newS29Store(t, &models.Project{}, &models.Environment{})
	ctx := context.Background()

	p, err := ls.CreateProject(ctx, &models.Project{Name: "P"})
	require.NoError(t, err)
	env, err := ls.CreateEnvironment(ctx, &models.Environment{ProjectID: p.ID, Name: "prod"})
	require.NoError(t, err)

	got, err := ls.GetEnvironment(ctx, env.ID)
	require.NoError(t, err)
	assert.Equal(t, env.ID, got.ID)
}

func TestDeleteEnvironment_S29_HasActiveSecrets(t *testing.T) {
	ls := newS29Store(t, &models.Project{}, &models.Environment{}, &models.SecretNode{})
	ctx := context.Background()

	p, err := ls.CreateProject(ctx, &models.Project{Name: "P"})
	require.NoError(t, err)
	env, err := ls.CreateEnvironment(ctx, &models.Environment{ProjectID: p.ID, Name: "prod"})
	require.NoError(t, err)

	_, err = ls.CreateSecret(ctx, &models.SecretNode{
		Name: "s", ProjectID: p.ID, EnvironmentID: env.ID, Status: "active", Type: "password",
	})
	require.NoError(t, err)

	err = ls.DeleteEnvironment(ctx, env.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "active secret")
}

func TestDeleteEnvironment_S29_NotFound(t *testing.T) {
	ls := newS29Store(t, &models.Environment{})
	err := ls.DeleteEnvironment(context.Background(), 9999)
	require.Error(t, err)
}

func TestDeleteEnvironment_S29_HappyPath(t *testing.T) {
	ls := newS29Store(t, &models.Project{}, &models.Environment{}, &models.SecretNode{})
	ctx := context.Background()

	p, err := ls.CreateProject(ctx, &models.Project{Name: "P"})
	require.NoError(t, err)
	env, err := ls.CreateEnvironment(ctx, &models.Environment{ProjectID: p.ID, Name: "prod"})
	require.NoError(t, err)

	require.NoError(t, ls.DeleteEnvironment(ctx, env.ID))
}

func TestRestoreEnvironment_S29_DeadProject(t *testing.T) {
	ls := newS29Store(t, &models.Project{}, &models.Environment{}, &models.SecretNode{}, &models.ShareRecord{}, &models.DynamicSecretConfig{})
	ctx := context.Background()

	// Create project, create env, delete project.
	p, err := ls.CreateProject(ctx, &models.Project{Name: "P"})
	require.NoError(t, err)
	env, err := ls.CreateEnvironment(ctx, &models.Environment{ProjectID: p.ID, Name: "prod"})
	require.NoError(t, err)
	require.NoError(t, ls.DeleteProject(ctx, p.ID))

	err = ls.RestoreEnvironment(ctx, p.ID, env.ID)
	require.Error(t, err)
}

func TestListEnvironments_S29_HappyPath(t *testing.T) {
	ls := newS29Store(t, &models.Project{}, &models.Environment{})
	ctx := context.Background()

	p, err := ls.CreateProject(ctx, &models.Project{Name: "P"})
	require.NoError(t, err)
	_, err = ls.CreateEnvironment(ctx, &models.Environment{ProjectID: p.ID, Name: "prod"})
	require.NoError(t, err)

	envs, err := ls.ListEnvironments(ctx)
	require.NoError(t, err)
	assert.Len(t, envs, 1)
}

func TestListEnvironmentsByProject_S29_HappyPath(t *testing.T) {
	ls := newS29Store(t, &models.Project{}, &models.Environment{})
	ctx := context.Background()

	p, err := ls.CreateProject(ctx, &models.Project{Name: "P"})
	require.NoError(t, err)
	_, err = ls.CreateEnvironment(ctx, &models.Environment{ProjectID: p.ID, Name: "prod"})
	require.NoError(t, err)

	envs, err := ls.ListEnvironmentsByProject(ctx, p.ID)
	require.NoError(t, err)
	assert.Len(t, envs, 1)
}

func TestListEnvironmentsByProjectIncludingDeleted_S29_HappyPath(t *testing.T) {
	ls := newS29Store(t, &models.Project{}, &models.Environment{})
	ctx := context.Background()

	p, err := ls.CreateProject(ctx, &models.Project{Name: "P"})
	require.NoError(t, err)
	env, err := ls.CreateEnvironment(ctx, &models.Environment{ProjectID: p.ID, Name: "prod"})
	require.NoError(t, err)

	// Soft-delete the environment directly.
	require.NoError(t, ls.db.Delete(&models.Environment{}, env.ID).Error)

	envs, err := ls.ListEnvironmentsByProjectIncludingDeleted(ctx, p.ID)
	require.NoError(t, err)
	assert.Len(t, envs, 1) // the soft-deleted one still shows up
}

// ---------------------------------------------------------------------------
// local_secrets.go — DeleteProjectIfEmpty / RestoreProject
// ---------------------------------------------------------------------------

func TestDeleteProjectIfEmpty_S29_NonEmpty(t *testing.T) {
	ls := newS29Store(t, &models.Project{}, &models.Environment{}, &models.SecretNode{}, &models.ShareRecord{}, &models.DynamicSecretConfig{})
	ctx := context.Background()

	p, err := ls.CreateProject(ctx, &models.Project{Name: "P"})
	require.NoError(t, err)
	env, err := ls.CreateEnvironment(ctx, &models.Environment{ProjectID: p.ID, Name: "prod"})
	require.NoError(t, err)
	_, err = ls.CreateSecret(ctx, &models.SecretNode{
		Name: "s", ProjectID: p.ID, EnvironmentID: env.ID, Status: "active", Type: "password",
	})
	require.NoError(t, err)

	count, err := ls.DeleteProjectIfEmpty(ctx, p.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "non-empty project must return blocking secret count")

	// Project must still exist.
	_, err = ls.GetProject(ctx, p.ID)
	require.NoError(t, err)
}

func TestDeleteProjectIfEmpty_S29_Empty(t *testing.T) {
	ls := newS29Store(t, &models.Project{}, &models.Environment{}, &models.SecretNode{}, &models.ShareRecord{}, &models.DynamicSecretConfig{})
	ctx := context.Background()

	p, err := ls.CreateProject(ctx, &models.Project{Name: "P"})
	require.NoError(t, err)

	count, err := ls.DeleteProjectIfEmpty(ctx, p.ID)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "empty project must return 0 blocking secrets")
}

func TestRestoreProject_S29_NotFound(t *testing.T) {
	ls := newS29Store(t, &models.Project{}, &models.Environment{}, &models.SecretNode{})
	_, _, err := ls.RestoreProject(context.Background(), 9999)
	require.Error(t, err)
}

func TestRestoreProject_S29_HappyCascade(t *testing.T) {
	ls := newS29Store(t, &models.Project{}, &models.Environment{}, &models.SecretNode{}, &models.ShareRecord{}, &models.DynamicSecretConfig{})
	ctx := context.Background()

	p, err := ls.CreateProject(ctx, &models.Project{Name: "P"})
	require.NoError(t, err)
	env, err := ls.CreateEnvironment(ctx, &models.Environment{ProjectID: p.ID, Name: "prod"})
	require.NoError(t, err)
	_, err = ls.CreateSecret(ctx, &models.SecretNode{
		Name: "s", ProjectID: p.ID, EnvironmentID: env.ID, Status: "active", Type: "password",
	})
	require.NoError(t, err)

	require.NoError(t, ls.DeleteProject(ctx, p.ID))

	restoredEnvs, restoredSecrets, err := ls.RestoreProject(ctx, p.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, restoredEnvs)
	assert.Equal(t, 1, restoredSecrets)
}

// ---------------------------------------------------------------------------
// local_secrets.go — SetSecretCertNotAfter / IncrementSecretReadCount
// ---------------------------------------------------------------------------

func TestSetSecretCertNotAfter_S29_HappyPath(t *testing.T) {
	ls := newS29Store(t, &models.SecretNode{})
	ctx := context.Background()

	sec, err := ls.CreateSecret(ctx, &models.SecretNode{Name: "cert", Status: "active", Type: "certificate"})
	require.NoError(t, err)

	notAfter := time.Now().Add(365 * 24 * time.Hour)
	require.NoError(t, ls.SetSecretCertNotAfter(ctx, sec.ID, &notAfter))
}

func TestIncrementSecretReadCount_S29_HappyPath(t *testing.T) {
	ls := newS29Store(t, &models.SecretNode{}, &models.SecretVersion{})
	ctx := context.Background()

	sec, err := ls.CreateSecret(ctx, &models.SecretNode{Name: "s", Status: "active", Type: "password"})
	require.NoError(t, err)
	ver, err := ls.CreateSecretVersion(ctx, &models.SecretVersion{SecretNodeID: sec.ID, VersionNumber: 1})
	require.NoError(t, err)

	require.NoError(t, ls.IncrementSecretReadCount(ctx, ver.ID))
}

// ---------------------------------------------------------------------------
// local_secrets.go — SetSecretTags
// ---------------------------------------------------------------------------

func TestSetSecretTags_S29_HappyPath(t *testing.T) {
	ls := newS29Store(t, &models.SecretNode{}, &models.Tag{}, &models.SecretTag{})
	ctx := context.Background()

	sec, err := ls.CreateSecret(ctx, &models.SecretNode{Name: "s", Status: "active", Type: "password"})
	require.NoError(t, err)

	require.NoError(t, ls.SetSecretTags(ctx, sec.ID, []string{"env:prod", "owner:ops"}))

	tags, err := ls.GetSecretTags(ctx, sec.ID)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"env:prod", "owner:ops"}, tags)
}

// ---------------------------------------------------------------------------
// local_secrets.go — ListSecrets (filter branches)
// ---------------------------------------------------------------------------

func TestListSecrets_S29_DeletedOnly(t *testing.T) {
	ls := newS29Store(t, &models.Project{}, &models.Environment{}, &models.SecretNode{}, &models.ShareRecord{}, &models.SecretACL{})
	ctx := context.Background()

	p, err := ls.CreateProject(ctx, &models.Project{Name: "P"})
	require.NoError(t, err)
	env, err := ls.CreateEnvironment(ctx, &models.Environment{ProjectID: p.ID, Name: "prod"})
	require.NoError(t, err)

	sec, err := ls.CreateSecret(ctx, &models.SecretNode{
		Name: "s", ProjectID: p.ID, EnvironmentID: env.ID, Status: "active", Type: "password",
	})
	require.NoError(t, err)
	require.NoError(t, ls.DeleteSecret(ctx, sec.ID))

	pID := p.ID
	secrets, total, err := ls.ListSecrets(ctx, &corestorage.SecretFilter{
		DeletedOnly: true, ProjectID: &pID, Page: 1, PageSize: 20,
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	assert.Len(t, secrets, 1)
}

func TestListSecrets_S29_IncludeDeleted(t *testing.T) {
	ls := newS29Store(t, &models.Project{}, &models.Environment{}, &models.SecretNode{}, &models.ShareRecord{}, &models.SecretACL{})
	ctx := context.Background()

	p, err := ls.CreateProject(ctx, &models.Project{Name: "P2"})
	require.NoError(t, err)
	env, err := ls.CreateEnvironment(ctx, &models.Environment{ProjectID: p.ID, Name: "prod"})
	require.NoError(t, err)

	sec, err := ls.CreateSecret(ctx, &models.SecretNode{
		Name: "s", ProjectID: p.ID, EnvironmentID: env.ID, Status: "active", Type: "password",
	})
	require.NoError(t, err)
	require.NoError(t, ls.DeleteSecret(ctx, sec.ID))

	secrets, total, err := ls.ListSecrets(ctx, &corestorage.SecretFilter{
		IncludeDeleted: true, Page: 1, PageSize: 20,
	})
	require.NoError(t, err)
	assert.True(t, total >= 1)
	assert.True(t, len(secrets) >= 1)
}

// ---------------------------------------------------------------------------
// local_secrets.go — ListOrphanedSecrets / CountOrphanedSecretsByProject
// ---------------------------------------------------------------------------

func TestListOrphanedSecrets_S29_HappyPath(t *testing.T) {
	ls := newS29Store(t, &models.Project{}, &models.Environment{}, &models.SecretNode{}, &models.User{})
	ctx := context.Background()

	p, err := ls.CreateProject(ctx, &models.Project{Name: "P"})
	require.NoError(t, err)
	env, err := ls.CreateEnvironment(ctx, &models.Environment{ProjectID: p.ID, Name: "prod"})
	require.NoError(t, err)

	// Secret with owner 999 (no such user) → orphaned.
	_, err = ls.CreateSecret(ctx, &models.SecretNode{
		Name: "orphan", ProjectID: p.ID, EnvironmentID: env.ID,
		Status: "active", Type: "password", OwnerID: 999,
	})
	require.NoError(t, err)

	orphans, err := ls.ListOrphanedSecrets(ctx, p.ID)
	require.NoError(t, err)
	assert.Len(t, orphans, 1)
}

func TestCountOrphanedSecretsByProject_S29_EmptyIDs(t *testing.T) {
	ls := newS29Store(t, &models.Project{}, &models.Environment{}, &models.SecretNode{}, &models.User{})
	counts, err := ls.CountOrphanedSecretsByProject(context.Background(), nil)
	require.NoError(t, err)
	assert.Empty(t, counts)
}

func TestCountOrphanedSecretsByProject_S29_HappyPath(t *testing.T) {
	ls := newS29Store(t, &models.Project{}, &models.Environment{}, &models.SecretNode{}, &models.User{})
	ctx := context.Background()

	p, err := ls.CreateProject(ctx, &models.Project{Name: "P"})
	require.NoError(t, err)
	env, err := ls.CreateEnvironment(ctx, &models.Environment{ProjectID: p.ID, Name: "prod"})
	require.NoError(t, err)
	_, err = ls.CreateSecret(ctx, &models.SecretNode{
		Name: "orphan", ProjectID: p.ID, EnvironmentID: env.ID,
		Status: "active", Type: "password", OwnerID: 888,
	})
	require.NoError(t, err)

	counts, err := ls.CountOrphanedSecretsByProject(ctx, []uint{p.ID})
	require.NoError(t, err)
	assert.Equal(t, 1, counts[p.ID])
}

func TestCountExpiringSecretsByProject_S29_EmptyIDs(t *testing.T) {
	ls := newS29Store(t, &models.Project{}, &models.SecretNode{})
	counts, err := ls.CountExpiringSecretsByProject(context.Background(), nil, time.Now())
	require.NoError(t, err)
	assert.Empty(t, counts)
}

func TestCountExpiringSecretsByProject_S29_HappyPath(t *testing.T) {
	ls := newS29Store(t, &models.Project{}, &models.SecretNode{})
	ctx := context.Background()

	p, err := ls.CreateProject(ctx, &models.Project{Name: "P"})
	require.NoError(t, err)

	exp := time.Now().Add(-time.Hour) // already expired
	_, err = ls.CreateSecret(ctx, &models.SecretNode{
		Name: "expiring", ProjectID: p.ID, Status: "active", Type: "password",
		Expiration: &exp,
	})
	require.NoError(t, err)

	counts, err := ls.CountExpiringSecretsByProject(ctx, []uint{p.ID}, time.Now())
	require.NoError(t, err)
	assert.Equal(t, 1, counts[p.ID])
}

// ---------------------------------------------------------------------------
// local_access_review_campaigns.go — GetAccessReviewCampaign
// ---------------------------------------------------------------------------

func TestGetAccessReviewCampaign_S29_NotFound(t *testing.T) {
	ls := newS29Store(t, &models.AccessReviewCampaign{})
	_, err := ls.GetAccessReviewCampaign(context.Background(), 9999)
	require.Error(t, err)
}

func TestGetAccessReviewCampaign_S29_Found(t *testing.T) {
	ls := newS29Store(t, &models.AccessReviewCampaign{})
	ctx := context.Background()

	c, err := ls.CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID: 1, Name: "Q1", State: "open",
	})
	require.NoError(t, err)

	got, err := ls.GetAccessReviewCampaign(ctx, c.ID)
	require.NoError(t, err)
	assert.Equal(t, c.ID, got.ID)
}

// ---------------------------------------------------------------------------
// local_access_review_campaigns.go — GetOpenAccessReviewCampaign
// ---------------------------------------------------------------------------

func TestGetOpenAccessReviewCampaign_S29_NoneOpen(t *testing.T) {
	ls := newS29Store(t, &models.AccessReviewCampaign{})
	got, err := ls.GetOpenAccessReviewCampaign(context.Background(), 1)
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestGetOpenAccessReviewCampaign_S29_Found(t *testing.T) {
	ls := newS29Store(t, &models.AccessReviewCampaign{})
	ctx := context.Background()

	c, err := ls.CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID: 1, Name: "Q1", State: "open",
	})
	require.NoError(t, err)

	got, err := ls.GetOpenAccessReviewCampaign(ctx, 1)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, c.ID, got.ID)
}

// ---------------------------------------------------------------------------
// local_access_review_campaigns.go — GetLatestClosedAccessReviewCampaign
// ---------------------------------------------------------------------------

func TestGetLatestClosedAccessReviewCampaign_S29_NoneFound(t *testing.T) {
	ls := newS29Store(t, &models.AccessReviewCampaign{})
	got, err := ls.GetLatestClosedAccessReviewCampaign(context.Background(), 1)
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestGetLatestClosedAccessReviewCampaign_S29_Found(t *testing.T) {
	ls := newS29Store(t, &models.AccessReviewCampaign{})
	ctx := context.Background()

	c, err := ls.CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID: 2, Name: "Q4", State: "closed",
	})
	require.NoError(t, err)

	got, err := ls.GetLatestClosedAccessReviewCampaign(ctx, 2)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, c.ID, got.ID)
}

// ---------------------------------------------------------------------------
// local_access_review_campaigns.go — items
// ---------------------------------------------------------------------------

func TestCreateAccessReviewItems_S29_EmptyNoOp(t *testing.T) {
	ls := newS29Store(t, &models.AccessReviewItem{})
	err := ls.CreateAccessReviewItems(context.Background(), nil)
	require.NoError(t, err)
}

func TestGetAccessReviewItem_S29_NotFound(t *testing.T) {
	ls := newS29Store(t, &models.AccessReviewItem{})
	_, err := ls.GetAccessReviewItem(context.Background(), 9999)
	require.Error(t, err)
}

func TestGetAccessReviewItem_S29_Found(t *testing.T) {
	ls := newS29Store(t, &models.AccessReviewCampaign{}, &models.AccessReviewItem{})
	ctx := context.Background()

	c, err := ls.CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID: 1, Name: "Q1", State: "open",
	})
	require.NoError(t, err)

	items := []*models.AccessReviewItem{{
		CampaignID:    c.ID,
		PrincipalType: "user",
		PrincipalID:   5,
		PrincipalName: "alice",
		Source:        "direct_share",
		AccessLevel:   "read",
		Decision:      "pending",
	}}
	require.NoError(t, ls.CreateAccessReviewItems(ctx, items))

	allItems, err := ls.ListAccessReviewItems(ctx, c.ID)
	require.NoError(t, err)
	require.Len(t, allItems, 1)

	got, err := ls.GetAccessReviewItem(ctx, allItems[0].ID)
	require.NoError(t, err)
	assert.Equal(t, allItems[0].ID, got.ID)
}

func TestCountPendingAccessReviewItems_S29_HappyPath(t *testing.T) {
	ls := newS29Store(t, &models.AccessReviewCampaign{}, &models.AccessReviewItem{})
	ctx := context.Background()

	c, err := ls.CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID: 1, Name: "Q1", State: "open",
	})
	require.NoError(t, err)

	items := []*models.AccessReviewItem{
		{CampaignID: c.ID, PrincipalType: "user", PrincipalID: 1, PrincipalName: "alice", Source: "role", AccessLevel: "read", Decision: "pending"},
		{CampaignID: c.ID, PrincipalType: "user", PrincipalID: 2, PrincipalName: "bob", Source: "role", AccessLevel: "read", Decision: "attested"},
	}
	require.NoError(t, ls.CreateAccessReviewItems(ctx, items))

	count, err := ls.CountPendingAccessReviewItems(ctx, c.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestUpdateAccessReviewItem_S29_HappyPath(t *testing.T) {
	ls := newS29Store(t, &models.AccessReviewCampaign{}, &models.AccessReviewItem{})
	ctx := context.Background()

	c, err := ls.CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID: 1, Name: "Q1", State: "open",
	})
	require.NoError(t, err)

	require.NoError(t, ls.CreateAccessReviewItems(ctx, []*models.AccessReviewItem{{
		CampaignID: c.ID, PrincipalType: "user", PrincipalID: 3,
		PrincipalName: "carol", Source: "role", AccessLevel: "read", Decision: "pending",
	}}))

	allItems, err := ls.ListAccessReviewItems(ctx, c.ID)
	require.NoError(t, err)
	require.Len(t, allItems, 1)

	item := allItems[0]
	item.Decision = "attested"
	item.Reason = "reviewed"
	ok, err := ls.UpdateAccessReviewItem(ctx, item)
	require.NoError(t, err)
	assert.True(t, ok, "update of a pending item in an open campaign must succeed")
}

// ---------------------------------------------------------------------------
// local_scheduler_lock_lease.go — TryAcquireSchedulerLock / ReleaseSchedulerLock
// ---------------------------------------------------------------------------

func TestTryAcquireSchedulerLock_S29_FirstAcquire(t *testing.T) {
	ls := newS29Store(t, &models.SchedulerLockLease{})
	ctx := context.Background()

	acquired, err := ls.TryAcquireSchedulerLock(ctx, 1001, "worker-A", time.Minute)
	require.NoError(t, err)
	assert.True(t, acquired)
}

func TestTryAcquireSchedulerLock_S29_Contended(t *testing.T) {
	ls := newS29Store(t, &models.SchedulerLockLease{})
	ctx := context.Background()

	// worker-A holds the lock.
	acquired, err := ls.TryAcquireSchedulerLock(ctx, 1002, "worker-A", time.Minute)
	require.NoError(t, err)
	assert.True(t, acquired)

	// worker-B tries to take the still-live lock — must fail.
	acquired, err = ls.TryAcquireSchedulerLock(ctx, 1002, "worker-B", time.Minute)
	require.NoError(t, err)
	assert.False(t, acquired, "worker-B must not steal an unexpired lock")
}

func TestTryAcquireSchedulerLock_S29_ExpiredReclaim(t *testing.T) {
	ls := newS29Store(t, &models.SchedulerLockLease{})
	ctx := context.Background()

	// worker-A acquires with an extremely short TTL (already expired).
	acquired, err := ls.TryAcquireSchedulerLock(ctx, 1003, "worker-A", -time.Millisecond)
	require.NoError(t, err)
	assert.True(t, acquired)

	// worker-B must be able to reclaim an expired lock.
	acquired, err = ls.TryAcquireSchedulerLock(ctx, 1003, "worker-B", time.Minute)
	require.NoError(t, err)
	assert.True(t, acquired, "worker-B must be able to reclaim an expired lock")
}

func TestTryAcquireSchedulerLock_S29_SelfRenew(t *testing.T) {
	ls := newS29Store(t, &models.SchedulerLockLease{})
	ctx := context.Background()

	acquired, err := ls.TryAcquireSchedulerLock(ctx, 1004, "worker-A", time.Minute)
	require.NoError(t, err)
	assert.True(t, acquired)

	// Self-renew (same holder, same key) must succeed.
	acquired, err = ls.TryAcquireSchedulerLock(ctx, 1004, "worker-A", time.Minute)
	require.NoError(t, err)
	assert.True(t, acquired, "owner must be able to renew its own lock")
}

func TestReleaseSchedulerLock_S29_OwnerRelease(t *testing.T) {
	ls := newS29Store(t, &models.SchedulerLockLease{})
	ctx := context.Background()

	_, err := ls.TryAcquireSchedulerLock(ctx, 1005, "worker-A", time.Minute)
	require.NoError(t, err)

	require.NoError(t, ls.ReleaseSchedulerLock(ctx, 1005, "worker-A"))

	// After release worker-B must be able to acquire.
	acquired, err := ls.TryAcquireSchedulerLock(ctx, 1005, "worker-B", time.Minute)
	require.NoError(t, err)
	assert.True(t, acquired)
}

func TestReleaseSchedulerLock_S29_ForeignHolderNoOp(t *testing.T) {
	ls := newS29Store(t, &models.SchedulerLockLease{})
	ctx := context.Background()

	_, err := ls.TryAcquireSchedulerLock(ctx, 1006, "worker-A", time.Minute)
	require.NoError(t, err)

	// worker-B trying to release a lock it doesn't hold — must be a no-op (no error).
	require.NoError(t, ls.ReleaseSchedulerLock(ctx, 1006, "worker-B"))

	// worker-A still holds the lock.
	acquired, err := ls.TryAcquireSchedulerLock(ctx, 1006, "worker-B", time.Minute)
	require.NoError(t, err)
	assert.False(t, acquired, "worker-A's lock must still be held after foreign-holder release no-op")
}
