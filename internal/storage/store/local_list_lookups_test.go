// local_list_lookups_test.go — the batch name lookups list views use
// (local_list_lookups.go): live rows only, ids de-duplicated, name-only columns.
package store_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

func newListLookupsDB(t *testing.T) *gorm.DB {
	t.Helper()
	db := sqlitetest.OpenWithDialector(t, "listlookups_", sqlite.Open, &gorm.Config{})
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.Group{}, &models.MachineIdentity{}, &models.Tag{}, &models.SecretTag{}))
	return db
}

func TestLocalStorage_NameLookupsByIDs(t *testing.T) {
	db := newListLookupsDB(t)
	ls := store.NewLocalStorage(db)
	ctx := context.Background()

	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", UsernameFolded: "alice"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "bob", UsernameFolded: "bob"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 3, Username: "carol", UsernameFolded: "carol"}).Error)
	require.NoError(t, db.Delete(&models.User{}, 3).Error) // soft-deleted
	require.NoError(t, db.Create(&models.Group{ID: 1, Name: "ops", NameFolded: "ops"}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 2, Name: "gone", NameFolded: "gone"}).Error)
	require.NoError(t, db.Delete(&models.Group{}, 2).Error)
	require.NoError(t, db.Create(&models.MachineIdentity{ID: 7, Name: "ci-app", ProjectID: 1}).Error)

	users, err := ls.GetUsernamesByIDs(ctx, []uint{1, 2, 3, 99, 1})
	require.NoError(t, err)
	assert.Equal(t, map[uint]string{1: "alice", 2: "bob"}, users, "soft-deleted and unknown ids are absent")

	groups, err := ls.GetGroupNamesByIDs(ctx, []uint{1, 2})
	require.NoError(t, err)
	assert.Equal(t, map[uint]string{1: "ops"}, groups)

	machines, err := ls.GetMachineIdentityNamesByIDs(ctx, []uint{7, 8})
	require.NoError(t, err)
	assert.Equal(t, map[uint]string{7: "ci-app"}, machines)

	none, err := ls.GetUsernamesByIDs(ctx, nil)
	require.NoError(t, err)
	assert.Empty(t, none)
}

func TestLocalStorage_GetUsernamesByIDs_MoreIDsThanOneChunk(t *testing.T) {
	db := newListLookupsDB(t)
	ls := store.NewLocalStorage(db)
	const n = 4500 // spans three internal chunks
	users := make([]models.User, 0, n)
	ids := make([]uint, 0, n)
	for i := 1; i <= n; i++ {
		name := fmt.Sprintf("u%05d", i)
		users = append(users, models.User{ID: uint(i), Username: name, UsernameFolded: name})
		ids = append(ids, uint(i))
	}
	require.NoError(t, db.CreateInBatches(&users, 500).Error)

	got, err := ls.GetUsernamesByIDs(context.Background(), ids)
	require.NoError(t, err)
	require.Len(t, got, n)
	assert.Equal(t, "u04500", got[4500])
}

func TestLocalStorage_GetSecretTagsBySecretIDs_MatchesGetSecretTags(t *testing.T) {
	db := newListLookupsDB(t)
	ls := store.NewLocalStorage(db)
	ctx := context.Background()

	require.NoError(t, db.Create(&[]models.Tag{{ID: 1, Name: "prod"}, {ID: 2, Name: "db"}, {ID: 3, Name: "ci"}}).Error)
	require.NoError(t, db.Create(&[]models.SecretTag{
		{SecretNodeID: 10, TagID: 1}, {SecretNodeID: 10, TagID: 2}, {SecretNodeID: 11, TagID: 3},
	}).Error)

	batch, err := ls.GetSecretTagsBySecretIDs(ctx, []uint{10, 11, 12})
	require.NoError(t, err)
	assert.Equal(t, map[uint][]string{10: {"db", "prod"}, 11: {"ci"}}, batch, "name-ordered; untagged secret absent")
	for _, id := range []uint{10, 11, 12} {
		single, serr := ls.GetSecretTags(ctx, id)
		require.NoError(t, serr)
		assert.ElementsMatch(t, single, batch[id], "secret %d", id)
	}
}

func newBatchReadsDB(t *testing.T) *gorm.DB {
	t.Helper()
	db := sqlitetest.OpenWithDialector(t, "batchreads_", sqlite.Open, &gorm.Config{})
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.Group{}, &models.UserGroup{}, &models.UserRole{},
		&models.GroupRole{}, &models.ProjectMembership{}, &models.MachineIdentityCredential{}))
	return db
}

func TestLocalStorage_GetUserBriefsByIDs_OnlyIdentityColumns(t *testing.T) {
	db := newBatchReadsDB(t)
	ls := store.NewLocalStorage(db)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", UsernameFolded: "alice", Email: "a@x.io", PasswordHash: "secret-hash"}).Error)
	got, err := ls.GetUserBriefsByIDs(context.Background(), []uint{1, 2})
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "alice", got[1].Username)
	assert.Equal(t, "a@x.io", got[1].Email)
}

// The batch read must equal the per-user read for every user, including a user whose
// only role comes through a group, one whose group is deleted, one with an expired
// role, and one with no role at all.
func TestLocalStorage_GetUserRoleScopesByUserIDs_MatchesPerUserRead(t *testing.T) {
	db := newBatchReadsDB(t)
	ls := store.NewLocalStorage(db)
	ctx := context.Background()
	past := time.Now().Add(-time.Hour)

	require.NoError(t, db.Create(&models.Group{ID: 1, Name: "live", NameFolded: "live"}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 2, Name: "dead", NameFolded: "dead"}).Error)
	require.NoError(t, db.Delete(&models.Group{}, 2).Error)
	require.NoError(t, db.Create(&[]models.UserRole{
		{UserID: 1, RoleID: 1, ProjectID: 10, EnvironmentID: 0},
		{UserID: 1, RoleID: 2, ProjectID: 10, EnvironmentID: 5},
		{UserID: 1, RoleID: 3, ProjectID: 11, EnvironmentID: 0, ExpiresAt: &past}, // expired: absent
		{UserID: 2, RoleID: 1, ProjectID: 0, EnvironmentID: 0},
	}).Error)
	require.NoError(t, db.Create(&[]models.UserGroup{{UserID: 3, GroupID: 1}, {UserID: 4, GroupID: 2}}).Error)
	require.NoError(t, db.Create(&[]models.GroupRole{
		{GroupID: 1, RoleID: 1, ProjectID: 12, EnvironmentID: 0},
		{GroupID: 2, RoleID: 1, ProjectID: 13, EnvironmentID: 0}, // deleted group: absent
	}).Error)

	ids := []uint{1, 2, 3, 4, 5}
	batch, err := ls.GetUserRoleScopesByUserIDs(ctx, ids)
	require.NoError(t, err)
	for _, id := range ids {
		single, serr := ls.GetUserRoleScopes(ctx, id)
		require.NoError(t, serr)
		assert.ElementsMatch(t, single, batch[id], "user %d", id)
	}
}

func TestLocalStorage_ListUserProjectMembershipsByUserIDs_MatchesPerUserRead(t *testing.T) {
	db := newBatchReadsDB(t)
	ls := store.NewLocalStorage(db)
	ctx := context.Background()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	require.NoError(t, db.Create(&[]models.ProjectMembership{
		{ProjectID: 1, UserID: 1, State: "revoked", InvitedAt: base},
		{ProjectID: 1, UserID: 1, State: "active", InvitedAt: base.Add(time.Hour)},
		{ProjectID: 2, UserID: 1, State: "invited", InvitedAt: base.Add(2 * time.Hour)},
		{ProjectID: 3, UserID: 2, State: "active", InvitedAt: base},
	}).Error)

	batch, err := ls.ListUserProjectMembershipsByUserIDs(ctx, []uint{1, 2, 3})
	require.NoError(t, err)
	for _, id := range []uint{1, 2, 3} {
		single, serr := ls.ListUserProjectMemberships(ctx, id)
		require.NoError(t, serr)
		require.Len(t, batch[id], len(single), "user %d", id)
		for i := range single {
			assert.Equal(t, single[i].ID, batch[id][i].ID, "user %d keeps the single-user order (invited_at DESC)", id)
		}
	}
}

func TestLocalStorage_ListMachineCredentialUsageByMachineIDs_OnlyUsageColumns(t *testing.T) {
	db := newBatchReadsDB(t)
	ls := store.NewLocalStorage(db)
	used := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	require.NoError(t, db.Create(&[]models.MachineIdentityCredential{
		{ID: 1, MachineIdentityID: 7, Name: "a", TokenHash: "hash-a", TokenPrefix: "kx_a", LastUsedAt: &used},
		{ID: 2, MachineIdentityID: 7, Name: "b", TokenHash: "hash-b", Revoked: true},
		{ID: 3, MachineIdentityID: 8, Name: "c", TokenHash: "hash-c"},
	}).Error)

	got, err := ls.ListMachineCredentialUsageByMachineIDs(context.Background(), []uint{7, 9})
	require.NoError(t, err)
	require.Len(t, got[7], 2, "revoked credentials count too, like ListMachineIdentityCredentials")
	assert.Empty(t, got[9])
	for _, c := range got[7] {
		assert.Empty(t, c.TokenHash, "no token hash is loaded")
		assert.Empty(t, c.TokenPrefix)
	}
	var withUse int
	for _, c := range got[7] {
		if c.LastUsedAt != nil && c.LastUsedAt.Equal(used) {
			withUse++
		}
	}
	assert.Equal(t, 1, withUse)
}
