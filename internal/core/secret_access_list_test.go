package core

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// grantSecretsManage gives userID an extra project role holding secrets.manage, the
// gate of GET /secrets/{id}/acl, so the report it asks for includes the ACL holders.
func grantSecretsManage(t *testing.T, db *gorm.DB, userID uint) {
	t.Helper()
	p := &models.Permission{Name: "secrets.manage"}
	require.NoError(t, db.Create(p).Error)
	require.NoError(t, db.Create(&models.Role{ID: 99, Name: "acl_manager", NameFolded: "acl_manager"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 99, PermissionID: p.ID}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: userID, RoleID: 99, ProjectID: 1}).Error)
}

func TestListSecretAccessors(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		// AuditEvent: a share commits with its audit row (AUDIT-TX-2).
		&models.AuditEvent{},
		&models.SecretNode{}, &models.SecretVersion{}, &models.User{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{},
		&models.Group{}, &models.UserGroup{}, &models.UserRole{}, &models.GroupRole{},
		// The role and ACL terms of the effective level (ListSecretAccessors) read these.
		&models.Project{}, &models.Environment{}, &models.Role{}, &models.Permission{},
		&models.RolePermission{}, &models.SecretACL{},
	))
	// Role 1 grants membership and no secret permission, so shares decide each level
	// below. Like the built-in project roles it lets its holder read the project's
	// members, which the report needs to list role-holders.
	usersPerm := &models.Permission{Name: "users.read"}
	require.NoError(t, db.Create(usersPerm).Error)
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "member", NameFolded: "member"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 1, PermissionID: usersPerm.ID}).Error)
	// Users: 1 owner, 2 direct recipient, 3 & 4 group members, 5 expired-share recipient.
	for _, u := range []models.User{
		{ID: 1, Username: "owner", Email: "o@t.com"},
		{ID: 2, Username: "alice", Email: "a@t.com"},
		{ID: 3, Username: "bob", Email: "b@t.com"},
		{ID: 4, Username: "carol", Email: "c@t.com"},
		{ID: 5, Username: "dave", Email: "d@t.com"},
	} {
		require.NoError(t, db.Create(&u).Error)
	}
	// IsProjectMember gates CheckSecretPermission (RBAC-001) and ShareSecret recipient check.
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 1, ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 10, Name: "platform"}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 3, GroupID: 10}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 4, GroupID: 10}).Error)
	// ShareSecretWithGroup verifies the group is scoped to the secret's project (1).
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 10, RoleID: 1, ProjectID: 1}).Error)
	grantSecretsManage(t, db, 1)

	now := time.Now()
	st := store.NewLocalStorage(db)
	c := &KeyorixCore{storage: st, now: func() time.Time { return now }}
	ctx := context.Background()

	secret, err := st.CreateSecret(ctx, &models.SecretNode{
		Name: "db", ProjectID: 1, EnvironmentID: 1, Type: "password", OwnerID: 1, IsSecret: true,
		CreatedAt: now, UpdatedAt: now,
	})
	require.NoError(t, err)
	// Direct share to alice (write); group share to platform (read); expired share to dave.
	_, err = c.ShareSecret(ctx, &ShareSecretRequest{SecretID: secret.ID, RecipientID: 2, Permission: "write", SharedBy: 1})
	require.NoError(t, err)
	_, err = c.ShareSecretWithGroup(ctx, &GroupShareSecretRequest{SecretID: secret.ID, GroupID: 10, Permission: "read", SharedBy: 1})
	require.NoError(t, err)
	past := now.Add(-time.Hour)
	require.NoError(t, db.Create(&models.ShareRecord{SecretID: secret.ID, OwnerID: 1, RecipientID: 5, Permission: "read", ExpiresAt: &past}).Error)

	result, err := c.ListSecretAccessors(ctx, secret.ID, 1)
	require.NoError(t, err)
	require.False(t, result.Degraded)
	accessors := result.Accessors

	byName := map[string]SecretAccessor{}
	for _, a := range accessors {
		byName[a.Username] = a
	}
	// owner, alice (direct), bob + carol (group). dave is excluded (expired share).
	assert.Len(t, accessors, 4)
	assert.Equal(t, "owner", byName["owner"].Permission)
	assert.Equal(t, "direct_share", byName["alice"].Source)
	assert.Equal(t, "write", byName["alice"].Permission)
	assert.Equal(t, "read", byName["bob"].Permission)
	assert.Contains(t, byName["bob"].Source, "group_share:platform")
	assert.Contains(t, byName, "carol")
	assert.NotContains(t, byName, "dave", "an expired share must not grant access")

	// Sorted by username.
	for i := 1; i < len(accessors); i++ {
		assert.LessOrEqual(t, accessors[i-1].Username, accessors[i].Username)
	}
}

func TestListSecretAccessors_StrongestGrantWins(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		// AuditEvent: a share commits with its audit row (AUDIT-TX-2).
		&models.AuditEvent{},
		&models.SecretNode{}, &models.SecretVersion{}, &models.User{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{},
		&models.Group{}, &models.UserGroup{}, &models.UserRole{}, &models.GroupRole{},
		// The role and ACL terms of the effective level (ListSecretAccessors) read these.
		&models.Project{}, &models.Environment{}, &models.Role{}, &models.Permission{},
		&models.RolePermission{}, &models.SecretACL{},
	))
	// Role 1 grants membership and no secret permission, so shares decide each level
	// below. Like the built-in project roles it lets its holder read the project's
	// members, which the report needs to list role-holders.
	usersPerm := &models.Permission{Name: "users.read"}
	require.NoError(t, db.Create(usersPerm).Error)
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "member", NameFolded: "member"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 1, PermissionID: usersPerm.ID}).Error)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "o@t.com"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "alice", Email: "a@t.com"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 1, ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 10, Name: "g"}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 2, GroupID: 10}).Error)
	// ShareSecretWithGroup verifies the group is scoped to the secret's project (1).
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 10, RoleID: 1, ProjectID: 1}).Error)
	grantSecretsManage(t, db, 1)

	now := time.Now()
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }}
	ctx := context.Background()
	secret, err := c.storage.CreateSecret(ctx, &models.SecretNode{Name: "s", ProjectID: 1, EnvironmentID: 1, Type: "password", OwnerID: 1, IsSecret: true, CreatedAt: now, UpdatedAt: now})
	require.NoError(t, err)
	// alice gets a group read share AND a direct write share — write should win.
	_, err = c.ShareSecretWithGroup(ctx, &GroupShareSecretRequest{SecretID: secret.ID, GroupID: 10, Permission: "read", SharedBy: 1})
	require.NoError(t, err)
	_, err = c.ShareSecret(ctx, &ShareSecretRequest{SecretID: secret.ID, RecipientID: 2, Permission: "write", SharedBy: 1})
	require.NoError(t, err)

	result, err := c.ListSecretAccessors(ctx, secret.ID, 1)
	require.NoError(t, err)
	require.False(t, result.Degraded)
	for _, a := range result.Accessors {
		if a.Username == "alice" {
			assert.Equal(t, "write", a.Permission, "the stronger (write) grant wins over the group read")
		}
	}
}

// failingGroupMembersStore wraps LocalStorage and fails every ListGroupMembers
// call, simulating storage.type: remote where ListGroupMembers is
// unconditionally unimplemented (#417).
func failingGroupMembersStore(inner storage.Storage) storage.Storage {
	return hooked(inner, &storeHooks{
		ListGroupMembers: func(_ storage.Storage, _ context.Context, _ uint) ([]*models.User, error) {
			return nil, errors.New("simulated: ListGroupMembers unimplemented on this backend")
		},
	})
}

// TestListSecretAccessors_DegradedOnGroupMembersError proves that a failing
// ListGroupMembers call now surfaces as Degraded instead of silently omitting
// the entire group's accessors from an incident-response-critical report (#417).
func TestListSecretAccessors_DegradedOnGroupMembersError(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		// AuditEvent: a share commits with its audit row (AUDIT-TX-2).
		&models.AuditEvent{},
		&models.SecretNode{}, &models.SecretVersion{}, &models.User{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{},
		&models.Group{}, &models.UserGroup{}, &models.UserRole{}, &models.GroupRole{},
		// The role and ACL terms of the effective level (ListSecretAccessors) read these.
		&models.Project{}, &models.Environment{}, &models.Role{}, &models.Permission{},
		&models.RolePermission{}, &models.SecretACL{},
	))
	// Role 1 grants membership and no secret permission, so shares decide each level
	// below. Like the built-in project roles it lets its holder read the project's
	// members, which the report needs to list role-holders.
	usersPerm := &models.Permission{Name: "users.read"}
	require.NoError(t, db.Create(usersPerm).Error)
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "member", NameFolded: "member"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 1, PermissionID: usersPerm.ID}).Error)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "o@t.com"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "bob", Email: "b@t.com"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 10, Name: "platform"}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 2, GroupID: 10}).Error)
	// ShareSecretWithGroup verifies the group is scoped to the secret's project (1).
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 10, RoleID: 1, ProjectID: 1}).Error)

	now := time.Now()
	base := store.NewLocalStorage(db)
	failing := failingGroupMembersStore(base)
	c := &KeyorixCore{storage: failing, now: func() time.Time { return now }}
	ctx := context.Background()

	secret, err := base.CreateSecret(ctx, &models.SecretNode{
		Name: "db", ProjectID: 1, EnvironmentID: 1, Type: "password", OwnerID: 1, IsSecret: true,
		CreatedAt: now, UpdatedAt: now,
	})
	require.NoError(t, err)
	_, err = c.ShareSecretWithGroup(ctx, &GroupShareSecretRequest{SecretID: secret.ID, GroupID: 10, Permission: "read", SharedBy: 1})
	require.NoError(t, err)

	result, err := c.ListSecretAccessors(ctx, secret.ID, 1)
	require.NoError(t, err)
	assert.True(t, result.Degraded, "a failed ListGroupMembers call must flip Degraded")
	require.NotEmpty(t, result.DegradedReasons)
	assert.Contains(t, result.DegradedReasons[0], "group_members:group=10")
	byName := map[string]SecretAccessor{}
	for _, a := range result.Accessors {
		byName[a.Username] = a
	}
	// The group's expansion failed and is flagged above. bob is a project member through
	// the group's role grant, which the report resolves separately from the failed
	// expansion, and the group read share (the term AuthorizeSecret decides with) gives
	// him read. He must be listed, unconditionally and at exactly that level: leaving
	// him out would present a real accessor as verified-absent.
	bob, ok := byName["bob"]
	require.True(t, ok, "bob has real read access through the group share and must be listed")
	assert.Equal(t, "read", bob.Permission)
	assert.Equal(t, "group_share:platform", bob.Source)
	assert.Contains(t, byName, "owner")
}

// TestListSecretAccessors_EffectiveIsMaxOfRoleAndShare: the report shows the EFFECTIVE
// level, max(role, share) (#2941), and every grant behind it; a share to a user who
// is not a project member grants nothing and is not listed.
func TestListSecretAccessors_EffectiveIsMaxOfRoleAndShare(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		// AuditEvent: a share commits with its audit row (AUDIT-TX-2).
		&models.AuditEvent{},
		&models.SecretNode{}, &models.SecretVersion{}, &models.User{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{},
		&models.Group{}, &models.UserGroup{}, &models.UserRole{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.Role{}, &models.Permission{},
		&models.RolePermission{}, &models.SecretACL{},
	))
	readPerm := &models.Permission{Name: "secrets.read"}
	require.NoError(t, db.Create(readPerm).Error)
	// Like the built-in project roles, the viewer can read the project's members.
	usersPerm := &models.Permission{Name: "users.read"}
	require.NoError(t, db.Create(usersPerm).Error)
	viewer := &models.Role{ID: 1, Name: "project_viewer", NameFolded: "project_viewer"}
	require.NoError(t, db.Create(viewer).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: viewer.ID, PermissionID: readPerm.ID}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: viewer.ID, PermissionID: usersPerm.ID}).Error)
	for _, u := range []models.User{
		{ID: 1, Username: "owner", Email: "o@t.com"},
		{ID: 2, Username: "alice", Email: "a@t.com"}, // viewer + write share -> write
		{ID: 3, Username: "bob", Email: "b@t.com"},   // viewer, no share -> read
		{ID: 4, Username: "eve", Email: "e@t.com"},   // share row, not a member -> nothing
	} {
		require.NoError(t, db.Create(&u).Error)
	}
	for _, uid := range []uint{1, 2, 3} {
		require.NoError(t, db.Create(&models.UserRole{UserID: uid, RoleID: viewer.ID, ProjectID: 1}).Error)
	}
	grantSecretsManage(t, db, 1)

	now := time.Now()
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }}
	ctx := context.Background()
	secret, err := c.storage.CreateSecret(ctx, &models.SecretNode{Name: "s", ProjectID: 1, EnvironmentID: 1, Type: "password", OwnerID: 1, IsSecret: true, CreatedAt: now, UpdatedAt: now})
	require.NoError(t, err)
	_, err = c.ShareSecret(ctx, &ShareSecretRequest{SecretID: secret.ID, RecipientID: 2, Permission: "write", SharedBy: 1})
	require.NoError(t, err)
	// A leftover share to a non-member (e.g. removed from the project after the share).
	require.NoError(t, db.Create(&models.ShareRecord{SecretID: secret.ID, OwnerID: 1, RecipientID: 4, Permission: "write"}).Error)

	result, err := c.ListSecretAccessors(ctx, secret.ID, 1)
	require.NoError(t, err)
	require.False(t, result.Degraded, result.DegradedReasons)
	byName := map[string]SecretAccessor{}
	for _, a := range result.Accessors {
		byName[a.Username] = a
	}
	assert.Equal(t, "write", byName["alice"].Permission, "a write share elevates the viewer role")
	assert.Equal(t, "direct_share", byName["alice"].Source)
	assert.ElementsMatch(t, []string{"role:read", "direct_share:write"}, byName["alice"].Grants)
	assert.Equal(t, "read", byName["bob"].Permission, "a role alone is listed too")
	assert.Equal(t, "role", byName["bob"].Source)
	assert.Equal(t, "owner", byName["owner"].Permission)
	assert.NotContains(t, byName, "eve", "a share to a non-member grants nothing")
}

// TestListSecretAccessors_RosterNeedsUsersRead: the report adds role-only members of
// the project, which is the project's member roster. A caller who can read the secret
// but cannot read the project's members (no users.read at the project) must not get
// that roster through this report: the roster is withheld and the report is flagged
// Degraded (an under-count), while owner, shares and ACL holders are still listed.
func TestListSecretAccessors_RosterNeedsUsersRead(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		// AuditEvent: a share commits with its audit row (AUDIT-TX-2).
		&models.AuditEvent{},
		&models.SecretNode{}, &models.SecretVersion{}, &models.User{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{},
		&models.Group{}, &models.UserGroup{}, &models.UserRole{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.Role{}, &models.Permission{},
		&models.RolePermission{}, &models.SecretACL{},
	))
	readPerm := &models.Permission{Name: "secrets.read"}
	usersPerm := &models.Permission{Name: "users.read"}
	require.NoError(t, db.Create(readPerm).Error)
	require.NoError(t, db.Create(usersPerm).Error)
	// Role 1: secrets.read only (a custom role). Role 2: secrets.read + users.read.
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "reader_only", NameFolded: "reader_only"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "reader_dir", NameFolded: "reader_dir"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 1, PermissionID: readPerm.ID}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 2, PermissionID: readPerm.ID}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 2, PermissionID: usersPerm.ID}).Error)
	for _, u := range []models.User{
		{ID: 1, Username: "owner", Email: "o@t.com"},
		{ID: 2, Username: "narrow", Email: "n@t.com"}, // secrets.read only: the caller
		{ID: 3, Username: "bob", Email: "b@t.com"},    // role-only member
		{ID: 4, Username: "wide", Email: "w@t.com"},   // secrets.read + users.read
	} {
		require.NoError(t, db.Create(&u).Error)
	}
	for _, ur := range []models.UserRole{
		{UserID: 1, RoleID: 1, ProjectID: 1}, {UserID: 2, RoleID: 1, ProjectID: 1},
		{UserID: 3, RoleID: 1, ProjectID: 1}, {UserID: 4, RoleID: 2, ProjectID: 1},
	} {
		require.NoError(t, db.Create(&ur).Error)
	}
	// wide may also read the ACL holders, so its report is complete.
	grantSecretsManage(t, db, 4)

	now := time.Now()
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }}
	ctx := context.Background()
	secret, err := c.storage.CreateSecret(ctx, &models.SecretNode{Name: "s", ProjectID: 1, EnvironmentID: 1, Type: "password", OwnerID: 1, IsSecret: true, CreatedAt: now, UpdatedAt: now})
	require.NoError(t, err)

	names := func(r *SecretAccessorsResult) map[string]bool {
		m := map[string]bool{}
		for _, a := range r.Accessors {
			m[a.Username] = true
		}
		return m
	}

	narrow, err := c.ListSecretAccessors(ctx, secret.ID, 2)
	require.NoError(t, err)
	assert.Equal(t, map[string]bool{"owner": true}, names(narrow), "a caller without users.read gets no member roster")
	assert.True(t, narrow.Degraded, "the withheld roster must be flagged, not look complete")
	require.NotEmpty(t, narrow.DegradedReasons)
	assert.Contains(t, narrow.DegradedReasons[0], "project_members")

	wide, err := c.ListSecretAccessors(ctx, secret.ID, 4)
	require.NoError(t, err)
	assert.False(t, wide.Degraded, wide.DegradedReasons)
	assert.Equal(t, map[string]bool{"owner": true, "narrow": true, "bob": true, "wide": true}, names(wide))
}

// accessListFixture is the shared schema and roles of the review-gate tests below:
// role 1 secrets.read only, role 2 secrets.read + users.read, role 3 secrets.read +
// users.read + secrets.manage (the gate of GET /secrets/{id}/acl), role 4 membership
// with no permission.
func accessListFixture(t *testing.T) (*gorm.DB, *KeyorixCore, time.Time) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		// AuditEvent: a share commits with its audit row (AUDIT-TX-2).
		&models.AuditEvent{},
		&models.SecretNode{}, &models.SecretVersion{}, &models.User{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{},
		&models.Group{}, &models.UserGroup{}, &models.UserRole{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.Role{}, &models.Permission{},
		&models.RolePermission{}, &models.SecretACL{},
	))
	perms := map[string]uint{}
	for _, name := range []string{"secrets.read", "users.read", "secrets.manage"} {
		p := &models.Permission{Name: name}
		require.NoError(t, db.Create(p).Error)
		perms[name] = p.ID
	}
	for id, granted := range map[uint][]string{
		1: {"secrets.read"},
		2: {"secrets.read", "users.read"},
		3: {"secrets.read", "users.read", "secrets.manage"},
		4: nil,
	} {
		name := fmt.Sprintf("role%d", id)
		require.NoError(t, db.Create(&models.Role{ID: id, Name: name, NameFolded: name}).Error)
		for _, p := range granted {
			require.NoError(t, db.Create(&models.RolePermission{RoleID: id, PermissionID: perms[p]}).Error)
		}
	}
	now := time.Now()
	return db, &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }}, now
}

func hasGrantPrefix(grants []string, prefix string) bool {
	for _, g := range grants {
		if strings.HasPrefix(g, prefix) {
			return true
		}
	}
	return false
}

// TestListSecretAccessors_ACLHoldersNeedSecretsManage: per-secret ACL holders and their
// acl: grants are the content of GET /secrets/{id}/acl, which requires secrets.manage.
// A caller with secrets.read (and even users.read) but not secrets.manage must not get
// them through this report: the ACL holder is not listed, no grant names an acl source,
// and the report is flagged Degraded with a secret_acls reason. A secrets.manage caller
// gets the holder with acl:read.
func TestListSecretAccessors_ACLHoldersNeedSecretsManage(t *testing.T) {
	t.Parallel()
	db, c, now := accessListFixture(t)
	for _, u := range []models.User{
		{ID: 1, Username: "owner", Email: "o@t.com"},
		{ID: 2, Username: "reader", Email: "r@t.com"},    // secrets.read + users.read: the caller
		{ID: 3, Username: "manager", Email: "m@t.com"},   // + secrets.manage
		{ID: 4, Username: "aclholder", Email: "a@t.com"}, // member without a secret role; ACL read
	} {
		require.NoError(t, db.Create(&u).Error)
	}
	for _, ur := range []models.UserRole{
		{UserID: 1, RoleID: 1, ProjectID: 1}, {UserID: 2, RoleID: 2, ProjectID: 1},
		{UserID: 3, RoleID: 3, ProjectID: 1}, {UserID: 4, RoleID: 4, ProjectID: 1},
	} {
		require.NoError(t, db.Create(&ur).Error)
	}
	ctx := context.Background()
	secret, err := c.storage.CreateSecret(ctx, &models.SecretNode{Name: "s", ProjectID: 1, EnvironmentID: 1, Type: "password", OwnerID: 1, IsSecret: true, CreatedAt: now, UpdatedAt: now})
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.SecretACL{SecretID: secret.ID, UserID: 4, Permissions: `["secrets.read"]`, GrantedBy: 3}).Error)

	reader, err := c.ListSecretAccessors(ctx, secret.ID, 2)
	require.NoError(t, err)
	for _, a := range reader.Accessors {
		assert.NotEqual(t, "aclholder", a.Username, "an ACL holder must not be listed to a caller without secrets.manage")
		assert.False(t, hasGrantPrefix(a.Grants, "acl:"), "no acl grant for a caller without secrets.manage: %s %v", a.Username, a.Grants)
		assert.NotEqual(t, "acl", a.Source)
	}
	assert.True(t, reader.Degraded, "the withheld ACL listing must be flagged, not look complete")
	assert.True(t, hasGrantPrefix(reader.DegradedReasons, "secret_acls"), reader.DegradedReasons)

	manager, err := c.ListSecretAccessors(ctx, secret.ID, 3)
	require.NoError(t, err)
	assert.False(t, manager.Degraded, manager.DegradedReasons)
	var holder *SecretAccessor
	for i := range manager.Accessors {
		if manager.Accessors[i].Username == "aclholder" {
			holder = &manager.Accessors[i]
		}
	}
	require.NotNil(t, holder, "a secrets.manage caller sees the ACL holder")
	assert.Equal(t, "read", holder.Permission)
	assert.Equal(t, "acl", holder.Source)
	assert.Contains(t, holder.Grants, "acl:read")
}

// TestListSecretAccessors_NoRoleGrantsWithoutRoster: a caller without users.read at the
// project is not given the member roster, so it must not learn members' project role
// levels either. The owner and share recipients are still listed, but no grant names a
// role source and no level comes from a role.
func TestListSecretAccessors_NoRoleGrantsWithoutRoster(t *testing.T) {
	t.Parallel()
	db, c, now := accessListFixture(t)
	for _, u := range []models.User{
		{ID: 1, Username: "owner", Email: "o@t.com"},  // role1 (secrets.read)
		{ID: 2, Username: "narrow", Email: "n@t.com"}, // role1: the caller
		{ID: 3, Username: "alice", Email: "a@t.com"},  // role1 + a read share
	} {
		require.NoError(t, db.Create(&u).Error)
	}
	for _, uid := range []uint{1, 2, 3} {
		require.NoError(t, db.Create(&models.UserRole{UserID: uid, RoleID: 1, ProjectID: 1}).Error)
	}
	ctx := context.Background()
	secret, err := c.storage.CreateSecret(ctx, &models.SecretNode{Name: "s", ProjectID: 1, EnvironmentID: 1, Type: "password", OwnerID: 1, IsSecret: true, CreatedAt: now, UpdatedAt: now})
	require.NoError(t, err)
	_, err = c.ShareSecret(ctx, &ShareSecretRequest{SecretID: secret.ID, RecipientID: 3, Permission: "read", SharedBy: 1})
	require.NoError(t, err)

	result, err := c.ListSecretAccessors(ctx, secret.ID, 2)
	require.NoError(t, err)
	assert.True(t, result.Degraded)
	byName := map[string]SecretAccessor{}
	for _, a := range result.Accessors {
		byName[a.Username] = a
		assert.False(t, hasGrantPrefix(a.Grants, "role:"), "no role grant without users.read: %s %v", a.Username, a.Grants)
		assert.NotEqual(t, "role", a.Source)
	}
	require.Contains(t, byName, "alice", "a share recipient is still listed")
	assert.Equal(t, []string{"direct_share:read"}, byName["alice"].Grants)
	require.Contains(t, byName, "owner")
	assert.Equal(t, []string{"owner:owner"}, byName["owner"].Grants)
}

// TestListSecretAccessors_OwnerNeedsLiveMembership: owner-level authority needs the
// owner to still be a member of the secret's project (requireLiveOwnerAuthority,
// RBAC-001), so a departed owner whose OwnerID tag remains is not reported as owner.
// A live owner's grant is in the documented source:level form, owner:owner.
func TestListSecretAccessors_OwnerNeedsLiveMembership(t *testing.T) {
	t.Parallel()
	db, c, now := accessListFixture(t)
	for _, u := range []models.User{
		{ID: 1, Username: "gone", Email: "g@t.com"},    // owner of s1, no longer a member
		{ID: 2, Username: "manager", Email: "m@t.com"}, // role3: the caller
		{ID: 3, Username: "live", Email: "l@t.com"},    // owner of s2, role4 member
	} {
		require.NoError(t, db.Create(&u).Error)
	}
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 3, ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 3, RoleID: 4, ProjectID: 1}).Error)
	ctx := context.Background()
	s1, err := c.storage.CreateSecret(ctx, &models.SecretNode{Name: "s1", ProjectID: 1, EnvironmentID: 1, Type: "password", OwnerID: 1, IsSecret: true, CreatedAt: now, UpdatedAt: now})
	require.NoError(t, err)
	s2, err := c.storage.CreateSecret(ctx, &models.SecretNode{Name: "s2", ProjectID: 1, EnvironmentID: 1, Type: "password", OwnerID: 3, IsSecret: true, CreatedAt: now, UpdatedAt: now})
	require.NoError(t, err)

	r1, err := c.ListSecretAccessors(ctx, s1.ID, 2)
	require.NoError(t, err)
	for _, a := range r1.Accessors {
		assert.NotEqual(t, "gone", a.Username, "a departed owner holds no owner authority")
	}

	r2, err := c.ListSecretAccessors(ctx, s2.ID, 2)
	require.NoError(t, err)
	byName := map[string]SecretAccessor{}
	for _, a := range r2.Accessors {
		byName[a.Username] = a
	}
	require.Contains(t, byName, "live")
	assert.Equal(t, "owner", byName["live"].Permission)
	assert.Equal(t, "owner", byName["live"].Source)
	assert.Equal(t, []string{"owner:owner"}, byName["live"].Grants)
}

// TestListSecretAccessors_ListsEveryShareGrant: Grants is documented as every grant the
// user holds, so a user with a direct read share AND a group write share shows both,
// not only the strongest share.
func TestListSecretAccessors_ListsEveryShareGrant(t *testing.T) {
	t.Parallel()
	db, c, now := accessListFixture(t)
	for _, u := range []models.User{
		{ID: 1, Username: "owner", Email: "o@t.com"}, // role3: the caller, full view
		{ID: 2, Username: "alice", Email: "a@t.com"}, // role4 member, in group platform
	} {
		require.NoError(t, db.Create(&u).Error)
	}
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 3, ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 4, ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 10, Name: "platform"}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 2, GroupID: 10}).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 10, RoleID: 4, ProjectID: 1}).Error)
	ctx := context.Background()
	secret, err := c.storage.CreateSecret(ctx, &models.SecretNode{Name: "s", ProjectID: 1, EnvironmentID: 1, Type: "password", OwnerID: 1, IsSecret: true, CreatedAt: now, UpdatedAt: now})
	require.NoError(t, err)
	_, err = c.ShareSecret(ctx, &ShareSecretRequest{SecretID: secret.ID, RecipientID: 2, Permission: "read", SharedBy: 1})
	require.NoError(t, err)
	_, err = c.ShareSecretWithGroup(ctx, &GroupShareSecretRequest{SecretID: secret.ID, GroupID: 10, Permission: "write", SharedBy: 1})
	require.NoError(t, err)

	result, err := c.ListSecretAccessors(ctx, secret.ID, 1)
	require.NoError(t, err)
	require.False(t, result.Degraded, result.DegradedReasons)
	var alice *SecretAccessor
	for i := range result.Accessors {
		if result.Accessors[i].Username == "alice" {
			alice = &result.Accessors[i]
		}
	}
	require.NotNil(t, alice)
	assert.Equal(t, "write", alice.Permission)
	assert.Equal(t, "group_share:platform", alice.Source)
	assert.ElementsMatch(t, []string{"direct_share:read", "group_share:platform:write"}, alice.Grants,
		"every applying share is listed, not only the strongest")
}

// countingSharesStore counts ListSharesBySecret calls and fails GetUserGroupsAt for one
// user (failGroupsFor; 0 = never).
type countingSharesStore struct {
	shareLists    int
	failGroupsFor uint
}

func newCountingSharesStore(inner storage.Storage, failGroupsFor uint) (storage.Storage, *countingSharesStore) {
	s := &countingSharesStore{failGroupsFor: failGroupsFor}
	return hooked(inner, &storeHooks{
		ListSharesBySecret: func(next storage.Storage, ctx context.Context, secretID uint, now time.Time) ([]*models.ShareRecord, error) {
			s.shareLists++
			return next.ListSharesBySecret(ctx, secretID, now)
		},
		GetUserGroupsAt: func(next storage.Storage, ctx context.Context, userID uint, scope Scope) ([]*models.Group, error) {
			if s.failGroupsFor != 0 && userID == s.failGroupsFor {
				return nil, errors.New("simulated: group lookup failed")
			}
			return next.GetUserGroupsAt(ctx, userID, scope)
		},
	}), s
}

// shareReportFixture: owner (1, role3, the caller), members 2..n+1 (role4) all in group
// 10 (role4 in the project), a group read share and a direct write share to user 2.
func shareReportFixture(t *testing.T, n int, wrap func(*store.LocalStorage) (storage.Storage, *countingSharesStore)) (*KeyorixCore, *countingSharesStore, uint) {
	t.Helper()
	db, base, now := accessListFixture(t)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "o@t.com"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 3, ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 10, Name: "platform"}).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 10, RoleID: 4, ProjectID: 1}).Error)
	for i := range n {
		id := uint(2 + i)
		require.NoError(t, db.Create(&models.User{ID: id, Username: fmt.Sprintf("u%02d", id), Email: fmt.Sprintf("u%d@t.com", id)}).Error)
		require.NoError(t, db.Create(&models.UserRole{UserID: id, RoleID: 4, ProjectID: 1}).Error)
		require.NoError(t, db.Create(&models.UserGroup{UserID: id, GroupID: 10}).Error)
	}
	ctx := context.Background()
	secret, err := base.storage.CreateSecret(ctx, &models.SecretNode{Name: "s", ProjectID: 1, EnvironmentID: 1, Type: "password", OwnerID: 1, IsSecret: true, CreatedAt: now, UpdatedAt: now})
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.ShareRecord{SecretID: secret.ID, OwnerID: 1, RecipientID: 10, IsGroup: true, Permission: "read"}).Error)
	require.NoError(t, db.Create(&models.ShareRecord{SecretID: secret.ID, OwnerID: 1, RecipientID: 2, Permission: "write"}).Error)
	wrapped, st := wrap(base.storage.(*store.LocalStorage))
	return &KeyorixCore{storage: wrapped, now: base.now}, st, secret.ID
}

// TestListSecretAccessors_LoadsSharesOnce: the report reads the secret's shares once,
// not once (or twice) per listed user, so its cost no longer multiplies the share
// lookups by the project size.
func TestListSecretAccessors_LoadsSharesOnce(t *testing.T) {
	t.Parallel()
	c, st, secretID := shareReportFixture(t, 8, func(l *store.LocalStorage) (storage.Storage, *countingSharesStore) {
		return newCountingSharesStore(l, 0)
	})
	result, err := c.ListSecretAccessors(context.Background(), secretID, 1)
	require.NoError(t, err)
	require.False(t, result.Degraded, result.DegradedReasons)
	require.Len(t, result.Accessors, 9)
	assert.Equal(t, 1, st.shareLists, "ListSharesBySecret must be called once for the whole report")
}

// TestListSecretAccessors_DegradedOnGroupShareLookupError: enforcement treats a failed
// group lookup as "no group share" (the share term only adds access), but the report
// must not then look complete: the user is under-counted, so the report is degraded.
func TestListSecretAccessors_DegradedOnGroupShareLookupError(t *testing.T) {
	t.Parallel()
	c, _, secretID := shareReportFixture(t, 2, func(l *store.LocalStorage) (storage.Storage, *countingSharesStore) {
		return newCountingSharesStore(l, 3)
	})
	result, err := c.ListSecretAccessors(context.Background(), secretID, 1)
	require.NoError(t, err)
	assert.True(t, result.Degraded, "a failed group-share lookup must flip Degraded")
	assert.True(t, hasGrantPrefix(result.DegradedReasons, "group_share:user=3"), result.DegradedReasons)
}

// TestListSecretAccessors_ShareGrantsMatchDecisionTerm is the guard that the report's
// share evaluation (reportShareGrants, computed from shares loaded once) cannot drift
// from the share term enforcement uses: for every user, the strongest share grant
// listed equals what sharePermissionFor grants (write for the allowlisted
// SecretActionUpdate, else read, else nothing). Cases: direct read/write, group share
// through a global and a project-scoped membership, a membership scoped to ANOTHER
// project, a share to a non-member, an expired share and a corrupt stored level.
func TestListSecretAccessors_ShareGrantsMatchDecisionTerm(t *testing.T) {
	t.Parallel()
	db, c, now := accessListFixture(t)
	users := []models.User{
		{ID: 1, Username: "owner", Email: "o@t.com"},    // role3: the caller
		{ID: 2, Username: "dread", Email: "2@t.com"},    // direct read
		{ID: 3, Username: "dwrite", Email: "3@t.com"},   // direct write
		{ID: 4, Username: "gglobal", Email: "4@t.com"},  // group A (write share), global membership
		{ID: 5, Username: "gscoped", Email: "5@t.com"},  // group B (read share), membership scoped to project 1
		{ID: 6, Username: "gother", Email: "6@t.com"},   // group A, membership scoped to project 2
		{ID: 7, Username: "outsider", Email: "7@t.com"}, // direct write share, not a member
		{ID: 8, Username: "expired", Email: "8@t.com"},  // expired direct write share
		{ID: 9, Username: "corrupt", Email: "9@t.com"},  // direct share with stored level "owner"
		{ID: 10, Username: "both", Email: "10@t.com"},   // direct read + group A write
		{ID: 11, Username: "plain", Email: "11@t.com"},  // member, no share
	}
	for _, u := range users {
		require.NoError(t, db.Create(&u).Error)
	}
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 3, ProjectID: 1}).Error)
	for _, uid := range []uint{2, 3, 4, 5, 6, 8, 9, 10, 11} {
		require.NoError(t, db.Create(&models.UserRole{UserID: uid, RoleID: 4, ProjectID: 1}).Error)
	}
	require.NoError(t, db.Create(&models.Group{ID: 20, Name: "ga"}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 21, Name: "gb"}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 4, GroupID: 20}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 5, GroupID: 21, ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 6, GroupID: 20, ProjectID: 2}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 10, GroupID: 20}).Error)

	ctx := context.Background()
	secret, err := c.storage.CreateSecret(ctx, &models.SecretNode{Name: "s", ProjectID: 1, EnvironmentID: 1, Type: "password", OwnerID: 1, IsSecret: true, CreatedAt: now, UpdatedAt: now})
	require.NoError(t, err)
	past := now.Add(-time.Hour)
	for _, sh := range []models.ShareRecord{
		{RecipientID: 2, Permission: "read"},
		{RecipientID: 3, Permission: "write"},
		{RecipientID: 20, IsGroup: true, Permission: "write"},
		{RecipientID: 21, IsGroup: true, Permission: "read"},
		{RecipientID: 7, Permission: "write"},
		{RecipientID: 8, Permission: "write", ExpiresAt: &past},
		{RecipientID: 9, Permission: "owner"},
		{RecipientID: 10, Permission: "read"},
	} {
		sh.SecretID, sh.OwnerID = secret.ID, 1
		require.NoError(t, db.Create(&sh).Error)
	}

	result, err := c.ListSecretAccessors(ctx, secret.ID, 1)
	require.NoError(t, err)
	require.False(t, result.Degraded, result.DegradedReasons)
	reported := map[uint]string{}
	for _, a := range result.Accessors {
		best := ""
		for _, g := range a.Grants {
			if !strings.HasPrefix(g, "direct_share") && !strings.HasPrefix(g, "group_share") {
				continue
			}
			lvl := g[strings.LastIndex(g, ":")+1:]
			if permissionRank[lvl] > permissionRank[best] {
				best = lvl
			}
		}
		reported[a.UserID] = best
	}
	for _, u := range users {
		want := ""
		for _, need := range []PermissionLevel{PermissionWrite, PermissionRead} {
			g, err := c.sharePermissionFor(ctx, u.ID, secret.ID, secret.ProjectID, need, SecretActionUpdate)
			require.NoError(t, err)
			if g.Level != PermissionNone {
				want = string(g.Level)
				break
			}
		}
		assert.Equal(t, want, reported[u.ID], "user %s: report's share level vs sharePermissionFor", u.Username)
	}
	// The fixture must exercise every outcome, or the comparison above proves little.
	assert.Equal(t, map[uint]string{2: "read", 3: "write", 4: "write", 5: "read", 10: "write"},
		func() map[uint]string {
			m := map[uint]string{}
			for id, l := range reported {
				if l != "" {
					m[id] = l
				}
			}
			return m
		}())
}
