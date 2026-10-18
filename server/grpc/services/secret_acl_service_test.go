// secret_acl_service_test.go — gRPC tests for the three SecretService ACL RPCs.
package services

import (
	"context"
	"fmt"
	"net/url"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// aclTestRig is a test rig for the per-secret ACL gRPC endpoints.
// It seeds:
//   - Project 1, Environment 1
//   - User 1 ("admin") with a role that holds secrets.read, secrets.write,
//     secrets.delete, AND secrets.manage — so they can both own secrets and
//     manage ACLs on them.
//   - User 2 ("guest") with no role (no RBAC grants).
type aclTestRig struct {
	svc      *SecretGRPCService
	db       *gorm.DB
	secretID uint64
}

const (
	aclAdminRoleID  = 10
	aclMemberRoleID = 11 // no permissions — makes a user a project member without any manage access
	aclAdminUserID  = 1
	aclGuestUserID  = 2
)

func newACLTestRig(t *testing.T) *aclTestRig {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))

	// Use a unique per-test in-memory DB name to prevent cross-test DB sharing.
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=private", url.PathEscape(t.Name()))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	// Keep a single connection: audit goroutines fire in background; without this
	// constraint SQLite in-memory DBs can race on separate connections.
	sqlDB.SetMaxOpenConns(1)

	require.NoError(t, db.AutoMigrate(
		&models.Project{}, &models.Environment{}, &models.SecretNode{},
		&models.SecretVersion{}, &models.User{}, &models.Role{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{},
		&models.Permission{}, &models.RolePermission{}, &models.UserRole{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.DynamicSecretConfig{}, &models.SecretACL{}, &models.SecretAccessLog{},
		&models.AuditEvent{},
	))

	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "default"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "development"}).Error)
	require.NoError(t, db.Create(&models.User{ID: aclAdminUserID, Username: "admin", Email: "admin@example.com"}).Error)
	require.NoError(t, db.Create(&models.User{ID: aclGuestUserID, Username: "guest", Email: "guest@example.com"}).Error)

	// Seed the "admin" role with secrets.read/write/delete/manage.
	require.NoError(t, db.Create(&models.Role{ID: aclAdminRoleID, Name: "acl-admin"}).Error)
	perms := []models.Permission{
		{ID: 101, Name: "secrets.read", Resource: "secrets", Action: "read"},
		{ID: 102, Name: "secrets.write", Resource: "secrets", Action: "write"},
		{ID: 103, Name: "secrets.delete", Resource: "secrets", Action: "delete"},
		{ID: 104, Name: "secrets.manage", Resource: "secrets", Action: "manage"},
	}
	for _, p := range perms {
		require.NoError(t, db.Create(&p).Error)
	}
	for _, p := range perms {
		require.NoError(t, db.Create(&models.RolePermission{RoleID: aclAdminRoleID, PermissionID: p.ID}).Error)
	}
	// Seed a no-permission "member" role for the guest user: gives project membership
	// without any manage grants, so PermissionDenied tests still pass.
	require.NoError(t, db.Create(&models.Role{ID: aclMemberRoleID, Name: "acl-member"}).Error)
	// Assign the admin role globally (project 0, env 0) to the admin user.
	require.NoError(t, db.Create(&models.UserRole{UserID: aclAdminUserID, RoleID: aclAdminRoleID}).Error)
	// Also assign at project 1 so IsProjectMember returns true.
	// GrantSecretACL verifies the grant target is a project member (IsProjectMember checks project_id).
	require.NoError(t, db.Create(&models.UserRole{UserID: aclAdminUserID, RoleID: aclAdminRoleID, ProjectID: 1}).Error)
	// Guest gets the no-permission member role at project 1: a project member but cannot manage ACLs.
	require.NoError(t, db.Create(&models.UserRole{UserID: aclGuestUserID, RoleID: aclMemberRoleID, ProjectID: 1}).Error)

	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	svc := NewSecretService(coreService)
	rig := &aclTestRig{svc: svc, db: db}

	// Pre-create a secret owned by the admin user for ACL tests to use.
	adminCtx := aclAdminCtx()
	sec, err := svc.CreateSecret(adminCtx, &pb.CreateSecretRequest{
		Name: "acl-target", Value: "s3cr3t", ProjectId: 1, EnvironmentId: 1, Type: "password",
	})
	require.NoError(t, err)
	rig.secretID = uint64(sec.GetId())
	return rig
}

// aclAdminCtx returns a context authenticated as the admin (user 1).
func aclAdminCtx() context.Context {
	return authCtx(aclAdminUserID, "admin",
		"secrets.read", "secrets.write", "secrets.delete", "secrets.manage")
}

// TestGrantSecretACL_HappyPath verifies that the admin can grant an ACL and
// the returned entry matches the request.
func TestGrantSecretACL_HappyPath(t *testing.T) {
	r := newACLTestRig(t)
	ctx := aclAdminCtx()

	resp, err := r.svc.GrantSecretACL(ctx, &pb.GrantSecretACLRequest{
		SecretId:    r.secretID,
		UserId:      aclGuestUserID,
		Permissions: []string{"secrets.read"},
	})
	require.NoError(t, err)
	assert.NotZero(t, resp.GetId())
	assert.Equal(t, r.secretID, resp.GetSecretId())
	assert.Equal(t, uint64(aclGuestUserID), resp.GetUserId())
	assert.Equal(t, []string{"secrets.read"}, resp.GetPermissions())
	assert.Equal(t, uint64(aclAdminUserID), resp.GetGrantedBy())
	assert.NotEmpty(t, resp.GetCreatedAt())
}

// TestGrantSecretACL_Unauthenticated checks that an unauthenticated caller is rejected.
func TestGrantSecretACL_Unauthenticated(t *testing.T) {
	r := newACLTestRig(t)
	_, err := r.svc.GrantSecretACL(context.Background(), &pb.GrantSecretACLRequest{
		SecretId:    r.secretID,
		UserId:      aclGuestUserID,
		Permissions: []string{"secrets.read"},
	})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

// TestGrantSecretACL_PermissionDenied checks that a user without secrets.manage is denied.
func TestGrantSecretACL_PermissionDenied(t *testing.T) {
	r := newACLTestRig(t)
	// Guest (user 2) has no RBAC role, so AuthorizePrincipal will deny.
	ctx := authCtx(aclGuestUserID, "guest", "secrets.read")
	// ADR-096: authorizeSecretScoped denies as PermissionDenied by default —
	// the guest holds no RBAC role anywhere (not even globally), so this is
	// not the narrow real-404 exception.
	_, err := r.svc.GrantSecretACL(ctx, &pb.GrantSecretACLRequest{
		SecretId:    r.secretID,
		UserId:      aclAdminUserID,
		Permissions: []string{"secrets.read"},
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestGrantSecretACL_MissingSecretID validates that a zero secret_id is rejected.
func TestGrantSecretACL_MissingSecretID(t *testing.T) {
	r := newACLTestRig(t)
	_, err := r.svc.GrantSecretACL(aclAdminCtx(), &pb.GrantSecretACLRequest{
		SecretId:    0,
		UserId:      aclGuestUserID,
		Permissions: []string{"secrets.read"},
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// TestGrantSecretACL_MissingUserID validates that a zero user_id is rejected.
func TestGrantSecretACL_MissingUserID(t *testing.T) {
	r := newACLTestRig(t)
	_, err := r.svc.GrantSecretACL(aclAdminCtx(), &pb.GrantSecretACLRequest{
		SecretId:    r.secretID,
		UserId:      0,
		Permissions: []string{"secrets.read"},
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// TestGrantSecretACL_EmptyPermissions validates that an empty permissions list is rejected.
func TestGrantSecretACL_EmptyPermissions(t *testing.T) {
	r := newACLTestRig(t)
	_, err := r.svc.GrantSecretACL(aclAdminCtx(), &pb.GrantSecretACLRequest{
		SecretId:    r.secretID,
		UserId:      aclGuestUserID,
		Permissions: []string{},
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// TestListSecretACLs_HappyPath verifies that after granting, ListSecretACLs
// returns the entry.
func TestListSecretACLs_HappyPath(t *testing.T) {
	r := newACLTestRig(t)
	ctx := aclAdminCtx()

	// No ACLs initially.
	listResp, err := r.svc.ListSecretACLs(ctx, &pb.ListSecretACLsRequest{SecretId: r.secretID})
	require.NoError(t, err)
	assert.Empty(t, listResp.GetAcls())

	// Grant one.
	_, err = r.svc.GrantSecretACL(ctx, &pb.GrantSecretACLRequest{
		SecretId:    r.secretID,
		UserId:      aclGuestUserID,
		Permissions: []string{"secrets.read", "secrets.write"},
	})
	require.NoError(t, err)

	// Now it should appear.
	listResp, err = r.svc.ListSecretACLs(ctx, &pb.ListSecretACLsRequest{SecretId: r.secretID})
	require.NoError(t, err)
	require.Len(t, listResp.GetAcls(), 1)
	entry := listResp.GetAcls()[0]
	assert.Equal(t, uint64(aclGuestUserID), entry.GetUserId())
	assert.ElementsMatch(t, []string{"secrets.read", "secrets.write"}, entry.GetPermissions())
}

// TestListSecretACLs_Unauthenticated verifies unauthenticated callers are rejected.
func TestListSecretACLs_Unauthenticated(t *testing.T) {
	r := newACLTestRig(t)
	_, err := r.svc.ListSecretACLs(context.Background(), &pb.ListSecretACLsRequest{SecretId: r.secretID})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

// TestListSecretACLs_PermissionDenied verifies a user without secrets.manage is denied.
func TestListSecretACLs_PermissionDenied(t *testing.T) {
	r := newACLTestRig(t)
	ctx := authCtx(aclGuestUserID, "guest", "secrets.read")
	// ADR-096: authorizeSecretScoped denies as PermissionDenied by default —
	// the guest holds no RBAC role anywhere (not even globally), so this is
	// not the narrow real-404 exception.
	_, err := r.svc.ListSecretACLs(ctx, &pb.ListSecretACLsRequest{SecretId: r.secretID})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestListSecretACLs_MissingSecretID validates that a zero secret_id is rejected.
func TestListSecretACLs_MissingSecretID(t *testing.T) {
	r := newACLTestRig(t)
	_, err := r.svc.ListSecretACLs(aclAdminCtx(), &pb.ListSecretACLsRequest{SecretId: 0})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// TestRevokeSecretACL_HappyPath grants then revokes an ACL and verifies it is gone.
func TestRevokeSecretACL_HappyPath(t *testing.T) {
	r := newACLTestRig(t)
	ctx := aclAdminCtx()

	// Grant first.
	grantResp, err := r.svc.GrantSecretACL(ctx, &pb.GrantSecretACLRequest{
		SecretId:    r.secretID,
		UserId:      aclGuestUserID,
		Permissions: []string{"secrets.read"},
	})
	require.NoError(t, err)
	aclID := grantResp.GetId()

	// Now revoke.
	_, err = r.svc.RevokeSecretACL(ctx, &pb.RevokeSecretACLRequest{
		SecretId: r.secretID,
		AclId:    aclID,
	})
	require.NoError(t, err)

	// Verify it's gone.
	listResp, err := r.svc.ListSecretACLs(ctx, &pb.ListSecretACLsRequest{SecretId: r.secretID})
	require.NoError(t, err)
	assert.Empty(t, listResp.GetAcls())
}

// TestRevokeSecretACL_Unauthenticated verifies unauthenticated callers are rejected.
func TestRevokeSecretACL_Unauthenticated(t *testing.T) {
	r := newACLTestRig(t)
	_, err := r.svc.RevokeSecretACL(context.Background(), &pb.RevokeSecretACLRequest{
		SecretId: r.secretID,
		AclId:    1,
	})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

// TestRevokeSecretACL_PermissionDenied verifies a user without secrets.manage is denied.
func TestRevokeSecretACL_PermissionDenied(t *testing.T) {
	r := newACLTestRig(t)
	ctx := authCtx(aclGuestUserID, "guest", "secrets.read")
	// ADR-096: authorizeSecretScoped denies as PermissionDenied by default —
	// the guest holds no RBAC role anywhere (not even globally), so this is
	// not the narrow real-404 exception.
	_, err := r.svc.RevokeSecretACL(ctx, &pb.RevokeSecretACLRequest{
		SecretId: r.secretID,
		AclId:    1,
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestRevokeSecretACL_MissingSecretID validates that a zero secret_id is rejected.
func TestRevokeSecretACL_MissingSecretID(t *testing.T) {
	r := newACLTestRig(t)
	_, err := r.svc.RevokeSecretACL(aclAdminCtx(), &pb.RevokeSecretACLRequest{
		SecretId: 0,
		AclId:    1,
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// TestRevokeSecretACL_MissingACLID validates that a zero acl_id is rejected.
func TestRevokeSecretACL_MissingACLID(t *testing.T) {
	r := newACLTestRig(t)
	_, err := r.svc.RevokeSecretACL(aclAdminCtx(), &pb.RevokeSecretACLRequest{
		SecretId: r.secretID,
		AclId:    0,
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// TestRevokeSecretACL_NotFound verifies that revoking a non-existent ACL ID returns NotFound.
func TestRevokeSecretACL_NotFound(t *testing.T) {
	r := newACLTestRig(t)
	_, err := r.svc.RevokeSecretACL(aclAdminCtx(), &pb.RevokeSecretACLRequest{
		SecretId: r.secretID,
		AclId:    9999,
	})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}
