package services

import (
	"context"
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

type shareTestRig struct {
	svc      *ShareGRPCService
	core     *core.KeyorixCore
	db       *gorm.DB
	secretID uint32
}

// newShareTestRig builds a real core with a seeded secret (owned by user 1) and
// a recipient user (id 2), plus the gRPC ShareService under test.
func newShareTestRig(t *testing.T) *shareTestRig {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	// modernc.org/sqlite gives each pooled connection to ":memory:" its own
	// fresh, unmigrated database unless pinned to a single connection --
	// without this, concurrent queries can intermittently hit a connection
	// that never saw AutoMigrate ("no such table") (ADR-048).
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&models.Project{}, &models.Environment{}, &models.SecretNode{},
		&models.SecretVersion{}, &models.User{}, &models.Role{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{},
		&models.Permission{}, &models.RolePermission{}, &models.UserRole{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{}, &models.ProjectMembership{},
	))
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "default"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "development"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "owner@example.com"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "recipient", Email: "rcpt@example.com"}).Error)

	// Share ops now scope-check via the RBAC graph (like HTTP), so seed real
	// grants: a writer role (secrets.read/write/delete) assigned to the owner
	// globally. Mirrors newSecretTestRig.
	require.NoError(t, db.Create(&models.Role{ID: writerRoleID, Name: "writer"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "secrets.read", Resource: "secrets", Action: "read"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 2, Name: "secrets.write", Resource: "secrets", Action: "write"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 3, Name: "secrets.delete", Resource: "secrets", Action: "delete"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: writerRoleID, PermissionID: 1}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: writerRoleID, PermissionID: 2}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: writerRoleID, PermissionID: 3}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: writerRoleID}).Error)               // global
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: writerRoleID, ProjectID: 1}).Error) // owner must also be a live project member (RBAC-001, requireLiveOwnerAuthority)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: writerRoleID, ProjectID: 1}).Error) // project member for recipient

	// Give recipient (user 2) a project-scoped role with NO permissions so that
	// IsProjectMember(2, 1) passes but authorizeSecretScoped still denies user 2
	// as a sharer (preserving the PermissionDenied and FlatPermissionDenied tests).
	const recipientMemberRoleID = 99
	require.NoError(t, db.Create(&models.Role{ID: recipientMemberRoleID, Name: "project-member"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: recipientMemberRoleID, ProjectID: 1}).Error)

	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	secret, err := coreService.CreateSecret(context.Background(), &core.CreateSecretRequest{
		Name: "shared-secret", Value: []byte("v"), ProjectID: 1, EnvironmentID: 1,
		Type: "password", CreatedBy: "owner", OwnerID: 1,
	})
	require.NoError(t, err)

	return &shareTestRig{
		svc:      NewShareService(coreService),
		core:     coreService,
		db:       db,
		secretID: intToU32(int(secret.ID)),
	}
}

// Regression (gRPC scoped-authz hardening): share ops must authorize at the
// SECRET'S project, not the flat global permission set. A user scoped to project
// 1 who even OWNS a secret in project 2 is denied sharing it / listing its shares
// over gRPC — matching the HTTP scoped gate.
func TestShareService_ShareSecret_ScopedToOtherProjectDenied(t *testing.T) {
	r := newShareTestRig(t)
	require.NoError(t, r.db.Create(&models.Project{ID: 2, Name: "other"}).Error)
	require.NoError(t, r.db.Create(&models.Environment{ID: 2, ProjectID: 2, Name: "development"}).Error)
	require.NoError(t, r.db.Create(&models.User{ID: 3, Username: "scoped", Email: "scoped@example.com"}).Error)
	require.NoError(t, r.db.Create(&models.UserRole{UserID: 3, RoleID: writerRoleID, ProjectID: 1}).Error) // project 1 only
	// A secret in project 2 owned by user 3 (owner check alone would pass).
	require.NoError(t, r.db.Create(&models.SecretNode{
		ID: 90, Name: "p2", ProjectID: 2, EnvironmentID: 2, OwnerID: 3, Status: "active", Type: "password",
	}).Error)

	ctx := authCtx(3, "scoped", "secrets.read", "secrets.write")

	// ADR-096: authorizeSecretScoped denies as PermissionDenied by default —
	// user 3 holds secrets.* only scoped to project 1, not globally, so this
	// is not the narrow real-404 exception.
	_, err := r.svc.ShareSecret(ctx, &pb.ShareSecretRequest{SecretId: 90, RecipientId: 2, Permission: "read"})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "ShareSecret cross-project")

	_, err = r.svc.ListSecretShares(ctx, &pb.ListSecretSharesRequest{SecretId: 90})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "ListSecretShares cross-project")
}

func ownerCtx() context.Context {
	return authCtx(1, "owner", "secrets.write", "secrets.read")
}

func (r *shareTestRig) share(t *testing.T, perm string) *pb.ShareRecord {
	t.Helper()
	rec, err := r.svc.ShareSecret(ownerCtx(), &pb.ShareSecretRequest{
		SecretId: r.secretID, RecipientId: 2, Permission: perm,
	})
	require.NoError(t, err)
	return rec
}

func TestShareService_ShareSecret(t *testing.T) {
	r := newShareTestRig(t)
	rec := r.share(t, "read")
	assert.NotZero(t, rec.GetId())
	assert.Equal(t, r.secretID, rec.GetSecretId())
	assert.Equal(t, uint32(2), rec.GetRecipientId())
	assert.Equal(t, "read", rec.GetPermission())
}

func TestShareService_ShareSecret_Unauthenticated(t *testing.T) {
	r := newShareTestRig(t)
	_, err := r.svc.ShareSecret(context.Background(), &pb.ShareSecretRequest{
		SecretId: r.secretID, RecipientId: 2, Permission: "read",
	})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestShareService_ShareSecret_PermissionDenied(t *testing.T) {
	r := newShareTestRig(t)
	// User 2 holds no RBAC role in the secret's scope, so the scoped check denies
	// regardless of any flat permission advertised in the context.
	ctx := authCtx(2, "recipient", "secrets.write", "secrets.read")
	_, err := r.svc.ShareSecret(ctx, &pb.ShareSecretRequest{
		SecretId: r.secretID, RecipientId: 3, Permission: "read",
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestShareService_ShareSecret_InvalidPermission(t *testing.T) {
	r := newShareTestRig(t)
	_, err := r.svc.ShareSecret(ownerCtx(), &pb.ShareSecretRequest{
		SecretId: r.secretID, RecipientId: 2, Permission: "admin",
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestShareService_ListSecretShares(t *testing.T) {
	r := newShareTestRig(t)
	r.share(t, "read")

	resp, err := r.svc.ListSecretShares(ownerCtx(), &pb.ListSecretSharesRequest{SecretId: r.secretID})
	require.NoError(t, err)
	require.Len(t, resp.GetShares(), 1)
	assert.Equal(t, uint32(2), resp.GetShares()[0].GetRecipientId())
}

func TestShareService_UpdateSharePermission(t *testing.T) {
	r := newShareTestRig(t)
	rec := r.share(t, "read")

	updated, err := r.svc.UpdateSharePermission(ownerCtx(), &pb.UpdateSharePermissionRequest{
		ShareId: rec.GetId(), Permission: "write",
	})
	require.NoError(t, err)
	assert.Equal(t, "write", updated.GetPermission())
}

func TestShareService_RevokeShare(t *testing.T) {
	r := newShareTestRig(t)
	rec := r.share(t, "read")

	_, err := r.svc.RevokeShare(ownerCtx(), &pb.RevokeShareRequest{ShareId: rec.GetId()})
	require.NoError(t, err)

	resp, err := r.svc.ListSecretShares(ownerCtx(), &pb.ListSecretSharesRequest{SecretId: r.secretID})
	require.NoError(t, err)
	assert.Empty(t, resp.GetShares())
}

func TestShareService_ListUserShares(t *testing.T) {
	r := newShareTestRig(t)
	r.share(t, "read")

	resp, err := r.svc.ListUserShares(ownerCtx(), &pb.ListUserSharesRequest{})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(resp.GetShares()), 1)
}

func TestShareService_ListSharedSecrets(t *testing.T) {
	r := newShareTestRig(t)
	r.share(t, "read")

	// The recipient needs a REAL global secrets.read grant (parity with the HTTP
	// GET /shared-secrets gate), not just a flat permission string in the token.
	require.NoError(t, r.db.Create(&models.UserRole{UserID: 2, RoleID: writerRoleID}).Error)

	// Listed from the recipient's perspective (user 2).
	ctx := authCtx(2, "recipient", "secrets.read")
	resp, err := r.svc.ListSharedSecrets(ctx, &pb.ListSharedSecretsRequest{})
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(resp.GetSecrets()), 1)
	assert.Equal(t, "shared-secret", resp.GetSecrets()[0].GetName())
}

// Regression (security review): ListUserShares / ListSharedSecrets must authorize
// through the scope/actor-aware path, not a flat permission check — otherwise a PAT
// restricted below global secrets.read could list shares over gRPC while HTTP denies
// it. A caller whose token carries the "secrets.read" string but who holds no real
// global grant must be denied.
func TestShareService_ListShares_FlatPermissionDenied(t *testing.T) {
	r := newShareTestRig(t)
	r.share(t, "read")
	// User 2 has NO role grant; the flat permission string must no longer be enough.
	ctx := authCtx(2, "recipient", "secrets.read")

	_, err := r.svc.ListSharedSecrets(ctx, &pb.ListSharedSecretsRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "ListSharedSecrets flat-perm")

	_, err = r.svc.ListUserShares(ctx, &pb.ListUserSharesRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "ListUserShares flat-perm")
}

// Regression (security review): listing a secret's shares is owner-only on the
// gRPC surface (flat permissions, no scope middleware) — a non-owner with
// secrets.read must be denied, not shown the recipient list.
func TestShareService_ListSecretShares_NonOwnerDenied(t *testing.T) {
	r := newShareTestRig(t) // secret owned by user 1
	ctx := authCtx(2, "intruder", "secrets.read", "secrets.write")
	_, err := r.svc.ListSecretShares(ctx, &pb.ListSecretSharesRequest{SecretId: r.secretID})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}
