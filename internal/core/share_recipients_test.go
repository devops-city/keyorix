package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// failingUserLookup makes GetUser(failID) fail with a transient (non-not-found)
// error, as a momentary backend failure would.
type failingUserLookup struct {
	*store.LocalStorage
	failID uint
}

func (f *failingUserLookup) GetUser(ctx context.Context, id uint) (*models.User, error) {
	if id == f.failID {
		return nil, errors.New("db timeout") // NOT storage.ErrUserNotFound
	}
	return f.LocalStorage.GetUser(ctx, id)
}

// A candidate whose account lookup fails for a reason other than "gone" must fail the
// whole search (fail closed, as the file header promises), never silently drop the
// member from the list.
func TestSearchShareRecipients_UserLookupErrorFailsTheSearch(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{}, &models.UserRole{}, &models.Role{},
		&models.Permission{}, &models.RolePermission{}, &models.User{}, &models.Project{}, &models.Environment{},
	))
	for _, u := range []models.User{
		{ID: 1, Username: "sharer", Email: "s@t", IsActive: true},
		{ID: 2, Username: "alice", Email: "a@t", IsActive: true},
		{ID: 3, Username: "bob", Email: "b@t", IsActive: true},
	} {
		require.NoError(t, db.Create(&u).Error)
	}
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "secrets.write", Resource: "secrets", Action: "write"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "writer"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 1, PermissionID: 1}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "member-no-perms"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 2, ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 3, RoleID: 2, ProjectID: 1}).Error)

	ctx := context.Background()
	st := store.NewLocalStorage(db)
	c := &KeyorixCore{storage: st, now: time.Now}
	req := ShareRecipientSearchRequest{ActorType: ActorTypeUser, ActorID: 1, ProjectID: 1}

	page, err := c.SearchShareRecipients(ctx, req)
	require.NoError(t, err)
	require.Equal(t, 3, page.Total, "baseline: sharer, alice and bob are listed")

	c = &KeyorixCore{storage: &failingUserLookup{LocalStorage: st, failID: 3}, now: time.Now}
	page, err = c.SearchShareRecipients(ctx, req)
	assert.Error(t, err, "a transient GetUser failure must not produce a silently partial list")
	assert.Nil(t, page)
}
