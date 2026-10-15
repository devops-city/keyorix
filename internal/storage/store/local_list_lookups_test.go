// local_list_lookups_test.go — the batch name lookups list views use
// (local_list_lookups.go): live rows only, ids de-duplicated, name-only columns.
package store_test

import (
	"context"
	"fmt"
	"testing"

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
