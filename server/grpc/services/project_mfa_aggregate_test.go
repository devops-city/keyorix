// project_mfa_aggregate_test.go — #G17 regression tests: enforceProjectMFA
// fails closed on a lookup error, and authorizeGlobal-gated aggregate RPCs
// (GetDeploymentRotationPlan, ListSharedSecrets, ListUserShares) apply the
// per-project MFA policy across every project their response discloses,
// instead of skipping it entirely because the caller authorized at global
// scope (project 0).
package services

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/server/grpc/interceptors"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// mfaAggregateTestRig seeds two projects — "guarded" (RequireMFA) and "open" —
// each with an overdue secret (so both appear in GetDeploymentRotationPlan) and
// a share owned by the actor (so both appear in ListSharedSecrets/ListUserShares).
// The actor (user 1) holds secrets.read at GLOBAL scope, matching the
// authorizeGlobal gate every RPC under test uses.
type mfaAggregateTestRig struct {
	db       *gorm.DB
	projSvc  *ProjectGRPCService
	shareSvc *ShareGRPCService
}

func newMFAAggregateTestRig(t *testing.T) *mfaAggregateTestRig {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Project{}, &models.Environment{}, &models.SecretNode{}, &models.RotationPolicy{},
		&models.SecretDependency{}, &models.ShareRecord{}, &models.User{}, &models.Role{},
		&models.Permission{}, &models.RolePermission{}, &models.UserRole{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{}, &models.SecretACL{},
	))

	require.NoError(t, db.Create(&models.Role{ID: writerRoleID, Name: "reader"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "secrets.read", Resource: "secrets", Action: "read"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: writerRoleID, PermissionID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: writerRoleID}).Error) // global

	require.NoError(t, db.Create(&models.User{ID: 1, Username: "auditor", Email: "auditor@example.com"}).Error)

	now := time.Now()
	daysAgo := func(d int) *time.Time { tt := now.Add(-time.Duration(d) * 24 * time.Hour); return &tt }

	// Project 1 ("guarded") requires MFA; project 2 ("open") does not. Both have
	// an overdue secret so both surface in the deployment-wide rotation plan.
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "guarded", RequireMFA: true}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "env1"}).Error)
	require.NoError(t, db.Create(&models.RotationPolicy{
		Name: "guarded-90d", Scope: "project", ProjectID: uintPtr(1), IntervalDays: 90, AlertDaysBefore: 14, IsActive: true,
	}).Error)
	require.NoError(t, db.Create(&models.SecretNode{
		ID: 1, Name: "guarded-secret", ProjectID: 1, EnvironmentID: 1, IsSecret: true, Status: "active",
		OwnerID: 1, LastRotatedAt: daysAgo(200),
	}).Error)

	require.NoError(t, db.Create(&models.Project{ID: 2, Name: "open"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 2, ProjectID: 2, Name: "env2"}).Error)
	require.NoError(t, db.Create(&models.RotationPolicy{
		Name: "open-90d", Scope: "project", ProjectID: uintPtr(2), IntervalDays: 90, AlertDaysBefore: 14, IsActive: true,
	}).Error)
	require.NoError(t, db.Create(&models.SecretNode{
		ID: 2, Name: "open-secret", ProjectID: 2, EnvironmentID: 2, IsSecret: true, Status: "active",
		OwnerID: 1, LastRotatedAt: daysAgo(200),
	}).Error)

	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	return &mfaAggregateTestRig{db: db, projSvc: NewProjectService(coreService), shareSvc: NewShareService(coreService)}
}

func uintPtr(v uint) *uint { return &v }

// erroringProjectStorage wraps a real Storage but makes GetProject fail with a
// non-"not found" error (a transient storage failure), to exercise
// enforceProjectMFA's genuine fail-closed path without a nonexistent-project
// "not found" (a different, deliberately non-blocking case — see
// TestEnforceProjectMFA_NotFoundDoesNotBlock).
type erroringProjectStorage struct {
	corestorage.Storage
}

func (erroringProjectStorage) GetProject(context.Context, uint) (*models.Project, error) {
	return nil, fmt.Errorf("connection reset by peer")
}

// TestEnforceProjectMFA_FailsClosedOnLookupError is #G17: a genuine
// ProjectRequiresMFA lookup error (a transient storage failure, distinct from
// "project not found") used to fall through to `return nil`, silently
// treating the caller as MFA-compliant. It must now deny.
func TestEnforceProjectMFA_FailsClosedOnLookupError(t *testing.T) {
	r := newMFAAggregateTestRig(t)
	coreService := core.NewKeyorixCore(erroringProjectStorage{store.NewLocalStorage(r.db)})
	actor := &interceptors.UserContext{UserID: 1, SessionAuth: true, MFAEnabled: false}

	err := enforceProjectMFA(context.Background(), coreService, actor, 1)
	require.Error(t, err, "a genuine ProjectRequiresMFA lookup error must deny, not silently allow")
	assert.Equal(t, codes.Internal, status.Code(err))
}

// TestEnforceProjectMFA_NotFoundDoesNotBlock is #G17's necessary carve-out:
// enforceProjectMFA only runs after the caller's scope was already
// permission-checked (authorizeScoped), so a nonexistent project is not an
// MFA-policy question — it must fall through so the RPC's own not-found
// handling produces the real NotFound, not a misleading "MFA required".
func TestEnforceProjectMFA_NotFoundDoesNotBlock(t *testing.T) {
	r := newMFAAggregateTestRig(t)
	coreService := core.NewKeyorixCore(store.NewLocalStorage(r.db))
	actor := &interceptors.UserContext{UserID: 1, SessionAuth: true, MFAEnabled: false}

	err := enforceProjectMFA(context.Background(), coreService, actor, 999)
	require.NoError(t, err, "a nonexistent project must not be blocked by the MFA gate")
}

// TestProjectService_GetDeploymentRotationPlan_DeniesGlobalScopeMFABypass is #G17:
// authorizeGlobal never runs enforceProjectMFA (scope.ProjectID is always 0), so a
// session without MFA that holds secrets.read at global scope could read an
// MFA-required project's rotation data back out of the deployment-wide roll-up,
// even though that same session is correctly denied GetProjectRotationPlan(1)
// directly.
func TestProjectService_GetDeploymentRotationPlan_DeniesGlobalScopeMFABypass(t *testing.T) {
	r := newMFAAggregateTestRig(t)

	_, err := r.projSvc.GetDeploymentRotationPlan(sessionCtx(1, "auditor", false, "secrets.read"), &emptypb.Empty{})
	require.Error(t, err, "an MFA-required project's data must not leak through the deployment-wide roll-up")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	_, err = r.projSvc.GetDeploymentRotationPlan(sessionCtx(1, "auditor", true, "secrets.read"), &emptypb.Empty{})
	require.NoError(t, err, "a session with MFA is allowed")

	_, err = r.projSvc.GetDeploymentRotationPlan(authCtx(1, "auditor", "secrets.read"), &emptypb.Empty{})
	require.NoError(t, err, "a PAT (non-interactive) is exempt from the per-project MFA gate")
}

// TestShareService_ListSharedSecrets_DeniesGlobalScopeMFABypass is #G17's
// ListSharedSecrets member: each returned SecretNode already carries its own
// ProjectID, so the aggregate check needs no extra lookup.
func TestShareService_ListSharedSecrets_DeniesGlobalScopeMFABypass(t *testing.T) {
	r := newMFAAggregateTestRig(t)
	// User 2 receives shares on both the guarded and open secrets.
	require.NoError(t, r.db.Create(&models.User{ID: 2, Username: "recipient", Email: "recipient@example.com"}).Error)
	require.NoError(t, r.db.Create(&models.UserRole{UserID: 2, RoleID: writerRoleID}).Error)
	require.NoError(t, r.db.Create(&models.ShareRecord{SecretID: 1, OwnerID: 1, RecipientID: 2, IsGroup: false, Permission: "read"}).Error)
	require.NoError(t, r.db.Create(&models.ShareRecord{SecretID: 2, OwnerID: 1, RecipientID: 2, IsGroup: false, Permission: "read"}).Error)

	_, err := r.shareSvc.ListSharedSecrets(sessionCtx(2, "recipient", false, "secrets.read"), &pb.ListSharedSecretsRequest{})
	require.Error(t, err, "a shared secret from an MFA-required project must not leak through this global-scope list")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	_, err = r.shareSvc.ListSharedSecrets(sessionCtx(2, "recipient", true, "secrets.read"), &pb.ListSharedSecretsRequest{})
	require.NoError(t, err, "a session with MFA is allowed")
}

// TestShareService_ListUserShares_DeniesGlobalScopeMFABypass is #G17's
// ListUserShares member: ShareRecord only carries SecretID, so the fix must
// resolve each share's owning project via a batched lookup before the check.
func TestShareService_ListUserShares_DeniesGlobalScopeMFABypass(t *testing.T) {
	r := newMFAAggregateTestRig(t)
	// User 1 (the fixture's global reader) owns shares on both secrets.
	require.NoError(t, r.db.Create(&models.User{ID: 3, Username: "other", Email: "other@example.com"}).Error)
	require.NoError(t, r.db.Create(&models.ShareRecord{SecretID: 1, OwnerID: 1, RecipientID: 3, IsGroup: false, Permission: "read"}).Error)
	require.NoError(t, r.db.Create(&models.ShareRecord{SecretID: 2, OwnerID: 1, RecipientID: 3, IsGroup: false, Permission: "read"}).Error)

	_, err := r.shareSvc.ListUserShares(sessionCtx(1, "auditor", false, "secrets.read"), &pb.ListUserSharesRequest{})
	require.Error(t, err, "a share on an MFA-required project's secret must not leak through this global-scope list")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	_, err = r.shareSvc.ListUserShares(sessionCtx(1, "auditor", true, "secrets.read"), &pb.ListUserSharesRequest{})
	require.NoError(t, err, "a session with MFA is allowed")
}

// erroringSecretsByIDsStorage makes the batched secret lookup fail (a transient
// storage error), which is the only source of the project ids ListUserShares'
// aggregate MFA check sees.
type erroringSecretsByIDsStorage struct {
	corestorage.Storage
}

func (erroringSecretsByIDsStorage) GetSecretsByIDs(context.Context, []uint) ([]*models.SecretNode, error) {
	return nil, fmt.Errorf("connection reset by peer")
}

// TestShareService_ListUserShares_MFACheckFailsClosedOnLookupError: shareProjectIDs
// used to log a failed project lookup and return no project ids, so the aggregate
// MFA check had nothing to check and a no-MFA session got the shares on an
// MFA-required project back (review of #3018, note 3). A lookup error must deny.
func TestShareService_ListUserShares_MFACheckFailsClosedOnLookupError(t *testing.T) {
	r := newMFAAggregateTestRig(t)
	require.NoError(t, r.db.Create(&models.User{ID: 3, Username: "other", Email: "other@example.com"}).Error)
	require.NoError(t, r.db.Create(&models.ShareRecord{SecretID: 1, OwnerID: 1, RecipientID: 3, IsGroup: false, Permission: "read"}).Error)
	svc := NewShareService(core.NewKeyorixCore(erroringSecretsByIDsStorage{store.NewLocalStorage(r.db)}))

	resp, err := svc.ListUserShares(sessionCtx(1, "auditor", false, "secrets.read"), &pb.ListUserSharesRequest{})
	require.Error(t, err, "an unverifiable MFA policy must not let the shares through: %v", resp)
	assert.Equal(t, codes.Internal, status.Code(err))
}
