// secret_listing_acl_test.go — integration tests for the ACL-granted secret discovery
// path in ListSecretsWithSharingInfo.
//
// A user who holds a SecretACL grant on a secret (or a folder) but neither owns
// the secret nor has a legacy ShareRecord for it must see it in the list. These
// tests exercise that gap against a real LocalStorage/SQLite backend to confirm
// the full stack behaves correctly.
package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

// newACLListCore returns a KeyorixCore on a fresh in-memory SQLite DB with all
// tables required for the listing-with-ACL tests already migrated.
func newACLListCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.OpenWithDialector(t, "kxacl_list_", sqlite.Open, &gorm.Config{})
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{},
		&models.SecretACL{},
		&models.AuditEvent{},
		&models.Project{},
		&models.Environment{},
		&models.ShareRecord{},
		&models.User{},
		&models.Role{},
		&models.UserRole{},
		&models.Permission{},
		&models.RolePermission{},
		&models.Group{},
		&models.UserGroup{},
		&models.GroupRole{},
	))
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p1"}).Error)
	require.NoError(t, db.Create(&models.Project{ID: 2, Name: "p2"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "env1"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 2, ProjectID: 2, Name: "env2"}).Error)
	// owner = userID 1, grantee = userID 2
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "owner@t.com"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "grantee", Email: "grantee@t.com"}).Error)
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }}
	return c, db
}

// mkACLListSecret inserts a leaf secret (IsSecret=true) in project 1 / env 1 owned by user 1.
func mkACLListSecret(t *testing.T, db *gorm.DB, name string) *models.SecretNode {
	t.Helper()
	s := &models.SecretNode{
		ProjectID: 1, EnvironmentID: 1, Name: name,
		IsSecret: true, Status: "active", OwnerID: 1,
	}
	require.NoError(t, db.Create(s).Error)
	return s
}

// mkACLListFolder inserts a folder node (IsSecret=false) in project 1 / env 1.
func mkACLListFolder(t *testing.T, db *gorm.DB, name string, parentID *uint) *models.SecretNode {
	t.Helper()
	f := &models.SecretNode{
		ProjectID: 1, EnvironmentID: 1, Name: name,
		IsSecret: false, Status: "active", OwnerID: 1, ParentID: parentID,
	}
	require.NoError(t, db.Create(f).Error)
	return f
}

// mkACLListChildSecret inserts a leaf secret as a child of parentID.
func mkACLListChildSecret(t *testing.T, db *gorm.DB, name string, parentID uint) *models.SecretNode {
	t.Helper()
	s := &models.SecretNode{
		ProjectID: 1, EnvironmentID: 1, Name: name,
		IsSecret: true, Status: "active", OwnerID: 1, ParentID: &parentID,
	}
	require.NoError(t, db.Create(s).Error)
	return s
}

// grantACL inserts a SecretACL row granting userID access to nodeID with the given perm.
func grantACL(t *testing.T, db *gorm.DB, nodeID, userID uint, perm string) {
	t.Helper()
	permsJSON := `["` + perm + `"]`
	require.NoError(t, db.Create(&models.SecretACL{
		SecretID:    nodeID,
		UserID:      userID,
		Permissions: permsJSON,
		GrantedBy:   1,
	}).Error)
}

// TestListSecretsWithSharingInfo_ACLGrantedDirectSecret verifies that a user who
// holds a SecretACL grant on a secret (and neither owns it nor has a ShareRecord
// for it) sees the secret in the listing result.
func TestListSecretsWithSharingInfo_ACLGrantedDirectSecret(t *testing.T) {
	t.Parallel()
	c, db := newACLListCore(t)
	ctx := context.Background()

	s := mkACLListSecret(t, db, "stripe-key")
	grantACL(t, db, s.ID, 2, "secrets.read") // grant user 2 read on the secret

	filter := &models.SecretListFilter{Page: 1, PageSize: 20}
	result, err := c.ListSecretsWithSharingInfo(ctx, 2, filter)
	require.NoError(t, err)

	require.Equal(t, int64(1), result.Total)
	assert.Equal(t, 0, result.OwnedCount)
	assert.Equal(t, 0, result.SharedCount)
	assert.Equal(t, 1, result.ACLGrantedCount)

	got := result.Secrets[0]
	assert.Equal(t, s.ID, got.ID)
	assert.Equal(t, "stripe-key", got.Name)
	assert.False(t, got.IsOwnedByUser)
	assert.False(t, got.IsShared)
	assert.Equal(t, "read", got.UserPermission) // ACL "secrets.read" → normalised "read"
	assert.NotNil(t, got.SharingIndicators)
	assert.True(t, got.SharingIndicators.CanRead)
	assert.False(t, got.SharingIndicators.CanWrite)
	assert.False(t, got.SharingIndicators.CanShare)
}

// TestListSecretsWithSharingInfo_ACLGrantedFolderSecret verifies that a user
// who holds a SecretACL grant on a folder sees every direct-child leaf secret
// in the listing (folder-level inheritance).
func TestListSecretsWithSharingInfo_ACLGrantedFolderSecret(t *testing.T) {
	t.Parallel()
	c, db := newACLListCore(t)
	ctx := context.Background()

	folder := mkACLListFolder(t, db, "infra-creds", nil)
	child1 := mkACLListChildSecret(t, db, "db-password", folder.ID)
	child2 := mkACLListChildSecret(t, db, "api-key", folder.ID)
	mkACLListChildSecret(t, db, "unrelated", folder.ID) // user 2 will get this too — all children inherit

	grantACL(t, db, folder.ID, 2, "secrets.read")

	filter := &models.SecretListFilter{Page: 1, PageSize: 20}
	result, err := c.ListSecretsWithSharingInfo(ctx, 2, filter)
	require.NoError(t, err)

	assert.Equal(t, int64(3), result.Total)
	assert.Equal(t, 0, result.OwnedCount)
	assert.Equal(t, 0, result.SharedCount)
	assert.Equal(t, 3, result.ACLGrantedCount)

	ids := make(map[uint]bool)
	for _, s := range result.Secrets {
		ids[s.ID] = true
		assert.Equal(t, "read", s.UserPermission) // ACL "secrets.read" → normalised "read"
	}
	assert.True(t, ids[child1.ID])
	assert.True(t, ids[child2.ID])
}

// TestListSecretsWithSharingInfo_ACLGrantedNestedFolder verifies two-level
// folder nesting: a grant on the grandparent folder propagates to all descendants.
func TestListSecretsWithSharingInfo_ACLGrantedNestedFolder(t *testing.T) {
	t.Parallel()
	c, db := newACLListCore(t)
	ctx := context.Background()

	root := mkACLListFolder(t, db, "root", nil)
	sub := mkACLListFolder(t, db, "sub", &root.ID)
	leaf := mkACLListChildSecret(t, db, "deep-secret", sub.ID)

	grantACL(t, db, root.ID, 2, "secrets.write")

	filter := &models.SecretListFilter{Page: 1, PageSize: 20}
	result, err := c.ListSecretsWithSharingInfo(ctx, 2, filter)
	require.NoError(t, err)

	require.Equal(t, int64(1), result.Total)
	assert.Equal(t, leaf.ID, result.Secrets[0].ID)
	assert.Equal(t, "write", result.Secrets[0].UserPermission) // ACL "secrets.write" → normalised "write"
	assert.True(t, result.Secrets[0].SharingIndicators.CanWrite)
}

// TestListSecretsWithSharingInfo_ACLDeduplicatedFromOwned verifies that a secret
// the user owns AND has an ACL grant for appears exactly once (as owned).
func TestListSecretsWithSharingInfo_ACLDeduplicatedFromOwned(t *testing.T) {
	t.Parallel()
	c, db := newACLListCore(t)
	ctx := context.Background()

	// Create secret owned by user 2 (not the usual owner=1).
	s := &models.SecretNode{
		ProjectID: 1, EnvironmentID: 1, Name: "my-secret",
		IsSecret: true, Status: "active", OwnerID: 2,
	}
	require.NoError(t, db.Create(s).Error)
	grantACL(t, db, s.ID, 2, "secrets.read") // also has explicit ACL

	filter := &models.SecretListFilter{Page: 1, PageSize: 20}
	result, err := c.ListSecretsWithSharingInfo(ctx, 2, filter)
	require.NoError(t, err)

	// Secret must appear exactly once — as owned, not as ACL-granted.
	require.Equal(t, int64(1), result.Total, "deduplicated: secret appears once")
	assert.Equal(t, 1, result.OwnedCount)
	assert.Equal(t, 0, result.ACLGrantedCount)
	assert.True(t, result.Secrets[0].IsOwnedByUser)
}

// TestListSecretsWithSharingInfo_ACLDeduplicatedFromShared verifies that a secret
// the user already has a ShareRecord for does not appear a second time as ACL-granted.
func TestListSecretsWithSharingInfo_ACLDeduplicatedFromShared(t *testing.T) {
	t.Parallel()
	c, db := newACLListCore(t)
	ctx := context.Background()

	s := mkACLListSecret(t, db, "shared-and-acl")
	// Legacy ShareRecord: user 2 has a share.
	require.NoError(t, db.Create(&models.ShareRecord{
		SecretID: s.ID, OwnerID: 1, RecipientID: 2, Permission: "read",
	}).Error)
	// Also has an ACL grant.
	grantACL(t, db, s.ID, 2, "secrets.read")

	filter := &models.SecretListFilter{Page: 1, PageSize: 20}
	result, err := c.ListSecretsWithSharingInfo(ctx, 2, filter)
	require.NoError(t, err)

	require.Equal(t, int64(1), result.Total, "deduplicated: appears once (via ShareRecord)")
	// The share is discovered first; the ACL path skips the already-seen ID.
	assert.Equal(t, 0, result.ACLGrantedCount)
}

// TestListSecretsWithSharingInfo_ShowOwnedOnly_SkipsACL verifies that
// ShowOwnedOnly=true suppresses the ACL-granted path entirely.
func TestListSecretsWithSharingInfo_ShowOwnedOnly_SkipsACL(t *testing.T) {
	t.Parallel()
	c, db := newACLListCore(t)
	ctx := context.Background()

	s := mkACLListSecret(t, db, "owner-only-view")
	grantACL(t, db, s.ID, 2, "secrets.read")

	filter := &models.SecretListFilter{ShowOwnedOnly: true, Page: 1, PageSize: 20}
	result, err := c.ListSecretsWithSharingInfo(ctx, 2, filter)
	require.NoError(t, err)

	// User 2 owns nothing and ShowOwnedOnly skips ACL grants.
	assert.Equal(t, int64(0), result.Total)
	assert.Equal(t, 0, result.ACLGrantedCount)
}

// TestListSecretsWithSharingInfo_ProjectFilter_HonoursACL verifies that an ACL
// grant on a secret in project 2 is NOT included when the caller filters by project 1.
func TestListSecretsWithSharingInfo_ProjectFilter_HonoursACL(t *testing.T) {
	t.Parallel()
	c, db := newACLListCore(t)
	ctx := context.Background()

	// Secret in project 2 (not project 1).
	sP2 := &models.SecretNode{
		ProjectID: 2, EnvironmentID: 2, Name: "p2-secret",
		IsSecret: true, Status: "active", OwnerID: 1,
	}
	require.NoError(t, db.Create(sP2).Error)
	grantACL(t, db, sP2.ID, 2, "secrets.read")

	// Also a secret in project 1 that user 2 owns.
	sP1 := &models.SecretNode{
		ProjectID: 1, EnvironmentID: 1, Name: "p1-owned",
		IsSecret: true, Status: "active", OwnerID: 2,
	}
	require.NoError(t, db.Create(sP1).Error)

	p1 := uint(1)
	filter := &models.SecretListFilter{ProjectID: &p1, Page: 1, PageSize: 20}
	result, err := c.ListSecretsWithSharingInfo(ctx, 2, filter)
	require.NoError(t, err)

	// Only the p1 owned secret; the p2 ACL grant must not cross the project boundary.
	require.Equal(t, int64(1), result.Total)
	assert.Equal(t, sP1.ID, result.Secrets[0].ID)
	assert.Equal(t, 0, result.ACLGrantedCount)
}

// TestListSecretsWithSharingInfo_NoACLGrants_NoExtraSecrets is a regression test
// ensuring that a user with no ACL grants at all gets exactly the same secrets
// as before the patch (owned + shared only, no extras).
func TestListSecretsWithSharingInfo_NoACLGrants_NoExtraSecrets(t *testing.T) {
	t.Parallel()
	c, db := newACLListCore(t)
	ctx := context.Background()

	// User 2 owns one secret.
	sOwned := &models.SecretNode{
		ProjectID: 1, EnvironmentID: 1, Name: "owned",
		IsSecret: true, Status: "active", OwnerID: 2,
	}
	require.NoError(t, db.Create(sOwned).Error)

	// Another secret (owned by user 1) that user 2 has NO access to.
	mkACLListSecret(t, db, "unrelated")

	filter := &models.SecretListFilter{Page: 1, PageSize: 20}
	result, err := c.ListSecretsWithSharingInfo(ctx, 2, filter)
	require.NoError(t, err)

	require.Equal(t, int64(1), result.Total)
	assert.Equal(t, 1, result.OwnedCount)
	assert.Equal(t, 0, result.SharedCount)
	assert.Equal(t, 0, result.ACLGrantedCount)
	assert.Equal(t, sOwned.ID, result.Secrets[0].ID)
}
