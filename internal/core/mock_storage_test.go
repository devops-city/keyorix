package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/mock"
)

// MockStorage is a complete mock implementation of the Storage interface for testing
type MockStorage struct {
	mock.Mock

	// GetDynamicSecretConfigFunc/TransitionDynamicSecretConfigDisabledFunc, when
	// set, override the fixed-stub return values GetDynamicSecretConfig/
	// TransitionDynamicSecretConfigDisabled otherwise give (see those methods'
	// doc comments for why they use this settable-func escape hatch instead of
	// the usual testify .On()/m.Called() pattern). nil by default; a test that
	// specifically needs to control the return value (e.g. simulating a lost
	// dynamic-secret-config CAS race deterministically) sets the field directly.
	GetDynamicSecretConfigFunc                func(ctx context.Context, id uint) (*models.DynamicSecretConfig, error)
	TransitionDynamicSecretConfigDisabledFunc func(ctx context.Context, c *models.DynamicSecretConfig, fromDisabled bool) (bool, error)
}

// WithSchedulerLock runs fn directly in tests (single instance, no DB lock).
func (m *MockStorage) WithSchedulerLock(_ context.Context, _ int64, fn func() error) (bool, error) {
	return true, fn()
}

// TryAcquireSchedulerLock/ReleaseSchedulerLock are no-ops in tests (single
// instance, nothing to contend with) — mirrors WithSchedulerLock above.
func (m *MockStorage) TryAcquireSchedulerLock(_ context.Context, _ int64, _ string, _ time.Duration) (bool, error) {
	return true, nil
}
func (m *MockStorage) ReleaseSchedulerLock(_ context.Context, _ int64, _ string) error {
	return nil
}

// WithAuditCheckpointLock runs fn directly in tests (single instance, no DB lock).
func (m *MockStorage) WithAuditCheckpointLock(_ context.Context, fn func() error) error {
	return fn()
}

// WithBootstrapLock runs fn directly in tests (single instance, no DB lock).
func (m *MockStorage) WithBootstrapLock(_ context.Context, fn func() error) error {
	return fn()
}

// WithNamedLock runs fn directly in tests (single instance, no DB lock).
func (m *MockStorage) WithNamedLock(ctx context.Context, _ string, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

// WithTransaction runs fn directly against the mock (no real transaction in tests).
func (m *MockStorage) WithTransaction(_ context.Context, fn func(storage.Storage) error) error {
	return fn(m)
}

// LockLiveProject answers "live" (#2702/#2710/#2711/#2712). This mock has no
// projects at all, and every test using it exercises a path where the project's
// existence is not the subject — answering false would make the create paths
// that now re-check it fail for a reason none of those tests is about.
//
// Note what this costs: a mock-backed test can never observe the deleted-parent
// rollback. That is deliberate, and it is why the proof for this fix is the four
// cross-replica Postgres tests in
// concurrency_child_under_deleted_project_postgres_test.go against real storage
// and a real row lock, not anything here — a mock cannot model a row lock, and a
// mock that returned a canned false would test the error message, not the race.
func (m *MockStorage) LockLiveProject(_ context.Context, _ uint) (bool, error) { return true, nil }

// Login rate-limiting stubs (core rate-limit logic is tested against real SQLite).
func (m *MockStorage) RecordLoginAttempt(_ context.Context, _ string, _ time.Time) error { return nil }
func (m *MockStorage) CountRecentLoginAttempts(_ context.Context, _ string, _ time.Time) (int64, error) {
	return 0, nil
}
func (m *MockStorage) ReserveLoginAttempt(_ context.Context, _ string, _ time.Time, _ string) (uint, error) {
	return 0, nil
}
func (m *MockStorage) ReleaseLoginAttempt(_ context.Context, _ uint) error { return nil }
func (m *MockStorage) PruneLoginAttempts(ctx context.Context, before time.Time) (int64, error) {
	a := m.Called(ctx, before)
	return a.Get(0).(int64), a.Error(1)
}

func (m *MockStorage) PruneMFAStepUpGrants(ctx context.Context, before time.Time) (int64, error) {
	a := m.Called(ctx, before)
	return a.Get(0).(int64), a.Error(1)
}

// Permission Management

func (m *MockStorage) CreatePermission(_ context.Context, permission *models.Permission) (*models.Permission, error) {
	return permission, nil
}

func (m *MockStorage) AssignPermissionToRole(_ context.Context, _, _ uint) error {
	return nil
}

// Project / Environment

func (m *MockStorage) CreateProject(_ context.Context, project *models.Project) (*models.Project, error) {
	return project, nil
}

func (m *MockStorage) CreateEnvironment(_ context.Context, env *models.Environment) (*models.Environment, error) {
	return env, nil
}

func (m *MockStorage) ListProjects(_ context.Context) ([]*models.Project, error) {
	return nil, nil
}

func (m *MockStorage) ListProjectsWithCounts(_ context.Context, _ bool) ([]storage.ProjectWithCounts, error) {
	return nil, nil
}

func (m *MockStorage) GetProject(ctx context.Context, id uint) (*models.Project, error) {
	for _, c := range m.ExpectedCalls {
		if c.Method == "GetProject" {
			args := m.Called(ctx, id)
			if args.Get(0) == nil {
				return nil, args.Error(1)
			}
			return args.Get(0).(*models.Project), args.Error(1)
		}
	}
	return &models.Project{}, nil
}

func (m *MockStorage) UpdateProjectFields(_ context.Context, _ uint, _, _ string, _ *bool, _ time.Time) (bool, error) {
	return true, nil
}

func (m *MockStorage) DeleteProject(_ context.Context, _ uint) error {
	return nil
}

// DeleteProjectIfEmpty defaults to "empty, delete succeeded" (0 blocking secrets) —
// the same trivial-success default DeleteProject above uses. Tests exercising the
// #528 guard behavior use catalog_delete_project_test.go's dedicated spies instead.
func (m *MockStorage) DeleteProjectIfEmpty(_ context.Context, _ uint) (int, error) {
	return 0, nil
}

func (m *MockStorage) RestoreProject(_ context.Context, _ uint) (int, int, error) {
	return 0, 0, nil
}

func (m *MockStorage) ListEnvironments(_ context.Context) ([]*models.Environment, error) {
	return nil, nil
}

func (m *MockStorage) ListEnvironmentsByProject(ctx context.Context, projectID uint) ([]*models.Environment, error) {
	if len(m.ExpectedCalls) == 0 {
		return nil, nil
	}
	for _, c := range m.ExpectedCalls {
		if c.Method == "ListEnvironmentsByProject" {
			args := m.Called(ctx, projectID)
			if args.Get(0) == nil {
				return nil, args.Error(1)
			}
			return args.Get(0).([]*models.Environment), args.Error(1)
		}
	}
	return nil, nil
}

func (m *MockStorage) ListEnvironmentsByProjectIncludingDeleted(_ context.Context, _ uint) ([]*models.Environment, error) {
	return nil, nil
}

func (m *MockStorage) ListProjectMembers(_ context.Context, _ uint) ([]storage.ProjectMember, error) {
	return nil, nil
}

func (m *MockStorage) ListProjectRoleAssignments(ctx context.Context, projectID uint) ([]storage.RoleAssignment, error) {
	args := m.Called(ctx, projectID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]storage.RoleAssignment), args.Error(1)
}

func (m *MockStorage) ListProjectMachineRoleAssignments(ctx context.Context, projectID uint) ([]storage.RoleAssignment, error) {
	a := m.Called(ctx, projectID)
	v, _ := a.Get(0).([]storage.RoleAssignment)
	return v, a.Error(1)
}

// ListGlobalAdminAssignmentsForUpdate is unused by the tests that construct a
// MockStorage directly (they don't exercise RemoveUserRole's last-admin guard);
// returns empty so the guard treats "no other admin" as the default in the rare
// case something reaches it.
func (m *MockStorage) ListGlobalAdminAssignmentsForUpdate(_ context.Context, _ []uint) ([]storage.RoleAssignment, error) {
	return nil, nil
}

// ListAdminBypassRoleIDs (#2496) is the structural replacement for
// installAdminRoleIDSet's name lookups. MockStorage-driven tests never seed a
// bypass-flagged role, so the honest answer here is "this install has none" —
// returned directly rather than via m.Called so no existing test needs a stub,
// which is exactly the position those tests were already in when every
// install-admin name resolved as absent via GetRoleByName. Real last-admin
// coverage lives against store.LocalStorage (last_admin_guard_external_test.go,
// concurrency_last_admin_removal_test.go, admin_role_structural_source_test.go).
//
// The empty answer makes the last-admin guards no-op, never fail-open on a
// masked error: an error return here would be indistinguishable from a real
// storage failure and would turn every MockStorage test that touches a role
// removal into a refusal.
func (m *MockStorage) ListAdminBypassRoleIDs(_ context.Context) ([]uint, error) {
	return nil, nil
}

// RemoveGlobalAdminRoleGuarded (#525) is likewise unused by MockStorage-driven
// tests — none of them seeds a bypass-flagged role, so RemoveUserRole's
// adminBypassRoleIDSlice is always empty and this is never reached
// (real-storage RemoveUserRole/last-admin coverage lives in
// last_admin_guard_external_test.go and concurrency_last_admin_removal_test.go,
// both against a real store.LocalStorage). If a future test DOES reach this
// unmocked, m.Called panics loudly rather than silently allowing the removal.
func (m *MockStorage) RemoveGlobalAdminRoleGuarded(ctx context.Context, userID, roleID uint, adminRoleIDs []uint) error {
	args := m.Called(ctx, userID, roleID, adminRoleIDs)
	return args.Error(0)
}

func (m *MockStorage) ListGroupRoleAssignments(ctx context.Context, groupID uint) ([]storage.RoleAssignment, error) {
	args := m.Called(ctx, groupID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]storage.RoleAssignment), args.Error(1)
}

func (m *MockStorage) CreateProjectInvitation(ctx context.Context, inv *models.ProjectInvitation) (*models.ProjectInvitation, error) {
	args := m.Called(ctx, inv)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ProjectInvitation), args.Error(1)
}

func (m *MockStorage) GetProjectInvitation(ctx context.Context, id uint) (*models.ProjectInvitation, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ProjectInvitation), args.Error(1)
}

func (m *MockStorage) UpdateProjectInvitation(ctx context.Context, inv *models.ProjectInvitation) (bool, error) {
	args := m.Called(ctx, inv)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) ListProjectInvitations(ctx context.Context, projectID uint) ([]*models.ProjectInvitation, error) {
	args := m.Called(ctx, projectID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.ProjectInvitation), args.Error(1)
}

func (m *MockStorage) CreateAccessRequest(ctx context.Context, req *models.AccessRequest) (*models.AccessRequest, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AccessRequest), args.Error(1)
}

func (m *MockStorage) GetAccessRequest(ctx context.Context, id uint) (*models.AccessRequest, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AccessRequest), args.Error(1)
}

func (m *MockStorage) UpdateAccessRequest(ctx context.Context, req *models.AccessRequest) (bool, error) {
	args := m.Called(ctx, req)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) ListAccessRequests(ctx context.Context, projectID uint) ([]*models.AccessRequest, error) {
	args := m.Called(ctx, projectID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.AccessRequest), args.Error(1)
}

func (m *MockStorage) CreateAccessRequestApproval(ctx context.Context, a *models.AccessRequestApproval) error {
	args := m.Called(ctx, a)
	return args.Error(0)
}

func (m *MockStorage) ListAccessRequestApprovals(ctx context.Context, requestID uint) ([]*models.AccessRequestApproval, error) {
	args := m.Called(ctx, requestID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.AccessRequestApproval), args.Error(1)
}

func (m *MockStorage) CreateAccessReviewCampaign(ctx context.Context, c *models.AccessReviewCampaign) (*models.AccessReviewCampaign, error) {
	args := m.Called(ctx, c)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AccessReviewCampaign), args.Error(1)
}

func (m *MockStorage) GetAccessReviewCampaign(ctx context.Context, id uint) (*models.AccessReviewCampaign, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AccessReviewCampaign), args.Error(1)
}

func (m *MockStorage) ListAccessReviewCampaigns(ctx context.Context, projectID uint) ([]*models.AccessReviewCampaign, error) {
	args := m.Called(ctx, projectID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.AccessReviewCampaign), args.Error(1)
}

func (m *MockStorage) GetOpenAccessReviewCampaign(ctx context.Context, projectID uint) (*models.AccessReviewCampaign, error) {
	args := m.Called(ctx, projectID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AccessReviewCampaign), args.Error(1)
}

func (m *MockStorage) GetLatestClosedAccessReviewCampaign(ctx context.Context, projectID uint) (*models.AccessReviewCampaign, error) {
	a := m.Called(ctx, projectID)
	v, _ := a.Get(0).(*models.AccessReviewCampaign)
	return v, a.Error(1)
}

func (m *MockStorage) UpdateAccessReviewCampaign(ctx context.Context, c *models.AccessReviewCampaign) (bool, error) {
	args := m.Called(ctx, c)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) CreateAccessReviewItems(ctx context.Context, items []*models.AccessReviewItem) error {
	args := m.Called(ctx, items)
	return args.Error(0)
}

func (m *MockStorage) ListAccessReviewItems(ctx context.Context, campaignID uint) ([]*models.AccessReviewItem, error) {
	args := m.Called(ctx, campaignID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.AccessReviewItem), args.Error(1)
}

func (m *MockStorage) CountPendingAccessReviewItems(ctx context.Context, campaignID uint) (int, error) {
	args := m.Called(ctx, campaignID)
	return args.Int(0), args.Error(1)
}

func (m *MockStorage) GetAccessReviewItem(ctx context.Context, id uint) (*models.AccessReviewItem, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AccessReviewItem), args.Error(1)
}

func (m *MockStorage) UpdateAccessReviewItem(ctx context.Context, item *models.AccessReviewItem) (bool, error) {
	args := m.Called(ctx, item)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) RevertAccessReviewItemClaim(ctx context.Context, itemID uint, fromDecision string, actorID uint) (bool, error) {
	args := m.Called(ctx, itemID, fromDecision, actorID)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) LastUserSecretActivity(ctx context.Context, projectID uint) (map[uint]time.Time, error) {
	args := m.Called(ctx, projectID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[uint]time.Time), args.Error(1)
}

func (m *MockStorage) LastUserRoleManagementActivity(ctx context.Context, projectID uint) (map[uint]time.Time, error) {
	a := m.Called(ctx, projectID)
	v, _ := a.Get(0).(map[uint]time.Time)
	return v, a.Error(1)
}

func (m *MockStorage) LastUserSecretDeletionActivity(ctx context.Context, projectID uint) (map[uint]time.Time, error) {
	a := m.Called(ctx, projectID)
	v, _ := a.Get(0).(map[uint]time.Time)
	return v, a.Error(1)
}

func (m *MockStorage) LastUserSecretReadActivity(ctx context.Context, projectID uint) (map[uint]time.Time, error) {
	a := m.Called(ctx, projectID)
	v, _ := a.Get(0).(map[uint]time.Time)
	return v, a.Error(1)
}

func (m *MockStorage) LastUserSecretWriteActivity(ctx context.Context, projectID uint) (map[uint]time.Time, error) {
	a := m.Called(ctx, projectID)
	v, _ := a.Get(0).(map[uint]time.Time)
	return v, a.Error(1)
}

func (m *MockStorage) CreateSoDPolicy(ctx context.Context, p *models.SoDPolicy) (*models.SoDPolicy, error) {
	args := m.Called(ctx, p)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SoDPolicy), args.Error(1)
}

func (m *MockStorage) GetSoDPolicy(ctx context.Context, id uint) (*models.SoDPolicy, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SoDPolicy), args.Error(1)
}

// ListSoDPolicies defaults to "no policies configured" when a test hasn't set up
// an expectation for it (mirrors GetProject/ListEnvironmentsByProject above) —
// #419 wired a ListSoDPolicies call into every role-grant choke point
// (requireNoSoDViolation and friends, sod.go), so any grant-path test that
// doesn't care about SoD would otherwise need to stub this out too.
func (m *MockStorage) ListSoDPolicies(ctx context.Context) ([]*models.SoDPolicy, error) {
	for _, c := range m.ExpectedCalls {
		if c.Method == "ListSoDPolicies" {
			args := m.Called(ctx)
			if args.Get(0) == nil {
				return nil, args.Error(1)
			}
			return args.Get(0).([]*models.SoDPolicy), args.Error(1)
		}
	}
	return nil, nil
}

func (m *MockStorage) DeleteSoDPolicy(ctx context.Context, id uint) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockStorage) CreateSecretDependency(ctx context.Context, d *models.SecretDependency) (*models.SecretDependency, error) {
	args := m.Called(ctx, d)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SecretDependency), args.Error(1)
}

func (m *MockStorage) GetSecretDependency(ctx context.Context, id uint) (*models.SecretDependency, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SecretDependency), args.Error(1)
}

func (m *MockStorage) ListSecretDependenciesForProject(ctx context.Context, projectID uint) ([]*models.SecretDependency, error) {
	args := m.Called(ctx, projectID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.SecretDependency), args.Error(1)
}

// ListSecretDependenciesForProjectForUpdate has no row lock in the mock; it
// reuses the ListSecretDependenciesForProject expectation, mirroring
// LockUserForUpdate above.
func (m *MockStorage) ListSecretDependenciesForProjectForUpdate(ctx context.Context, projectID uint) ([]*models.SecretDependency, error) {
	return m.ListSecretDependenciesForProject(ctx, projectID)
}

func (m *MockStorage) DeleteSecretDependency(ctx context.Context, id uint) error {
	return m.Called(ctx, id).Error(0)
}

func (m *MockStorage) CreateSecretDependencyExclusive(ctx context.Context, d *models.SecretDependency) (*models.SecretDependency, error) {
	a := m.Called(ctx, d)
	v, _ := a.Get(0).(*models.SecretDependency)
	return v, a.Error(1)
}

func (m *MockStorage) CreateLegalHold(ctx context.Context, h *models.LegalHold) (*models.LegalHold, error) {
	args := m.Called(ctx, h)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.LegalHold), args.Error(1)
}

func (m *MockStorage) GetActiveLegalHold(ctx context.Context) (*models.LegalHold, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.LegalHold), args.Error(1)
}

func (m *MockStorage) UpdateLegalHold(ctx context.Context, h *models.LegalHold) error {
	args := m.Called(ctx, h)
	return args.Error(0)
}

func (m *MockStorage) CreateRiskException(ctx context.Context, e *models.RiskException) (*models.RiskException, error) {
	args := m.Called(ctx, e)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.RiskException), args.Error(1)
}

func (m *MockStorage) ListRiskExceptions(ctx context.Context, activeOnly bool) ([]*models.RiskException, error) {
	args := m.Called(ctx, activeOnly)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.RiskException), args.Error(1)
}

func (m *MockStorage) GetRiskException(ctx context.Context, id uint) (*models.RiskException, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.RiskException), args.Error(1)
}

func (m *MockStorage) RevokeRiskExceptionIfNotRevoked(ctx context.Context, e *models.RiskException) (bool, error) {
	args := m.Called(ctx, e)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) ApproveRiskExceptionIfPending(ctx context.Context, e *models.RiskException) (bool, error) {
	args := m.Called(ctx, e)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) CreateSSOLoginState(ctx context.Context, s *models.SSOLoginState) error {
	args := m.Called(ctx, s)
	return args.Error(0)
}

func (m *MockStorage) ConsumeSSOLoginState(ctx context.Context, state string) (*models.SSOLoginState, error) {
	args := m.Called(ctx, state)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SSOLoginState), args.Error(1)
}

func (m *MockStorage) CreateBreakGlassActivation(ctx context.Context, a *models.BreakGlassActivation) (*models.BreakGlassActivation, error) {
	args := m.Called(ctx, a)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.BreakGlassActivation), args.Error(1)
}

func (m *MockStorage) GetBreakGlassActivation(ctx context.Context, id uint) (*models.BreakGlassActivation, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.BreakGlassActivation), args.Error(1)
}

func (m *MockStorage) ListBreakGlassActivations(ctx context.Context, projectID uint) ([]*models.BreakGlassActivation, error) {
	args := m.Called(ctx, projectID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.BreakGlassActivation), args.Error(1)
}

func (m *MockStorage) UpdateBreakGlassActivation(ctx context.Context, a *models.BreakGlassActivation) error {
	args := m.Called(ctx, a)
	return args.Error(0)
}

func (m *MockStorage) ReconcileExpiredBreakGlassActivation(ctx context.Context, projectID, userID uint) error {
	args := m.Called(ctx, projectID, userID)
	return args.Error(0)
}

func (m *MockStorage) RevokeBreakGlassActivation(ctx context.Context, id, revokedBy, revokedByMachineID uint, revokedAt time.Time) error {
	args := m.Called(ctx, id, revokedBy, revokedByMachineID, revokedAt)
	return args.Error(0)
}

func (m *MockStorage) ReviewBreakGlassActivation(ctx context.Context, id, reviewerID uint, note string, reviewedAt time.Time) error {
	args := m.Called(ctx, id, reviewerID, note, reviewedAt)
	return args.Error(0)
}

func (m *MockStorage) ListUnreviewedBreakGlassActivationsBefore(ctx context.Context, cutoff time.Time) ([]*models.BreakGlassActivation, error) {
	args := m.Called(ctx, cutoff)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.BreakGlassActivation), args.Error(1)
}

func (m *MockStorage) GetEnvironment(_ context.Context, id uint) (*models.Environment, error) {
	return &models.Environment{ID: id, ProjectID: 1, Name: "test"}, nil
}

func (m *MockStorage) DeleteEnvironment(_ context.Context, _ uint) error {
	return nil
}

func (m *MockStorage) RestoreEnvironment(_ context.Context, _, _ uint) error {
	return nil
}

// Secret Management

// CreateSecret ignores the optional plaintextValue variadic (#499) — it is not
// forwarded to m.Called, so existing `.On("CreateSecret", ctx, secret)`
// expectations (2 args) keep matching regardless of what core passes.
func (m *MockStorage) CreateSecret(ctx context.Context, secret *models.SecretNode, _ ...string) (*models.SecretNode, error) {
	args := m.Called(ctx, secret)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SecretNode), args.Error(1)
}

func (m *MockStorage) GetSecret(ctx context.Context, id uint) (*models.SecretNode, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SecretNode), args.Error(1)
}

func (m *MockStorage) GetSecretsByIDs(ctx context.Context, ids []uint) ([]*models.SecretNode, error) {
	args := m.Called(ctx, ids)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.SecretNode), args.Error(1)
}

func (m *MockStorage) mockNameMap(method string, ctx context.Context, ids []uint) (map[uint]string, error) {
	args := m.MethodCalled(method, ctx, ids)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[uint]string), args.Error(1)
}

func (m *MockStorage) GetUsernamesByIDs(ctx context.Context, ids []uint) (map[uint]string, error) {
	return m.mockNameMap("GetUsernamesByIDs", ctx, ids)
}

func (m *MockStorage) GetUserBriefsByIDs(ctx context.Context, ids []uint) (map[uint]storage.UserBrief, error) {
	args := m.Called(ctx, ids)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[uint]storage.UserBrief), args.Error(1)
}

func (m *MockStorage) GetUserRoleScopesByUserIDs(ctx context.Context, ids []uint) (map[uint][]storage.Scope, error) {
	args := m.Called(ctx, ids)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[uint][]storage.Scope), args.Error(1)
}

func (m *MockStorage) ListUserProjectMembershipsByUserIDs(ctx context.Context, ids []uint) (map[uint][]*models.ProjectMembership, error) {
	args := m.Called(ctx, ids)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[uint][]*models.ProjectMembership), args.Error(1)
}

func (m *MockStorage) ListMachineCredentialUsageByMachineIDs(ctx context.Context, ids []uint) (map[uint][]*models.MachineIdentityCredential, error) {
	args := m.Called(ctx, ids)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[uint][]*models.MachineIdentityCredential), args.Error(1)
}

func (m *MockStorage) GetGroupNamesByIDs(ctx context.Context, ids []uint) (map[uint]string, error) {
	return m.mockNameMap("GetGroupNamesByIDs", ctx, ids)
}

func (m *MockStorage) GetMachineIdentityNamesByIDs(ctx context.Context, ids []uint) (map[uint]string, error) {
	return m.mockNameMap("GetMachineIdentityNamesByIDs", ctx, ids)
}

func (m *MockStorage) GetSecretTagsBySecretIDs(ctx context.Context, ids []uint) (map[uint][]string, error) {
	args := m.Called(ctx, ids)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[uint][]string), args.Error(1)
}

func (m *MockStorage) GetSecretByName(ctx context.Context, name string, projectID, environmentID uint) (*models.SecretNode, error) {
	args := m.Called(ctx, name, projectID, environmentID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SecretNode), args.Error(1)
}

func (m *MockStorage) UpdateSecret(ctx context.Context, secret *models.SecretNode) (*models.SecretNode, error) {
	args := m.Called(ctx, secret)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SecretNode), args.Error(1)
}

func (m *MockStorage) UpdateSecretFields(ctx context.Context, id uint, f storage.SecretFieldUpdate) (bool, error) {
	args := m.Called(ctx, id, f)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) TransitionSecretStatus(ctx context.Context, secret *models.SecretNode, fromStatus string) (bool, error) {
	args := m.Called(ctx, secret, fromStatus)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) UpdateSecretRotationConfig(ctx context.Context, secret *models.SecretNode, fromBackend string) (bool, error) {
	args := m.Called(ctx, secret, fromBackend)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) DeleteSecret(ctx context.Context, id uint) error {
	return m.Called(ctx, id).Error(0)
}

func (m *MockStorage) RestoreSecret(ctx context.Context, id uint) error {
	return m.Called(ctx, id).Error(0)
}

// mockHasExpectation reports whether a test stubbed method. The audit-description
// name lookups (audit_refs.go) are best-effort reads on code paths that predate them,
// so for an unstubbed method the lookup-only getters below answer "not found" instead
// of failing the mock's unexpected-call panic; a test that stubs the method still gets
// exactly what it stubbed.
func (m *MockStorage) mockHasExpectation(method string) bool {
	for _, c := range m.ExpectedCalls {
		if c.Method == method {
			return true
		}
	}
	return false
}

var errMockLookupNotStubbed = fmt.Errorf("mock: lookup not stubbed")

func (m *MockStorage) GetSecretIncludingDeleted(ctx context.Context, id uint) (*models.SecretNode, error) {
	if !m.mockHasExpectation("GetSecretIncludingDeleted") {
		return nil, errMockLookupNotStubbed
	}
	a := m.Called(ctx, id)
	v, _ := a.Get(0).(*models.SecretNode)
	return v, a.Error(1)
}

func (m *MockStorage) PurgeDeletedSecretsBefore(ctx context.Context, before time.Time) (int64, error) {
	args := m.Called(ctx, before)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockStorage) DeleteAnomalyAlertsBefore(ctx context.Context, ackBefore, unackCeiling time.Time) (int64, error) {
	args := m.Called(ctx, ackBefore, unackCeiling)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockStorage) DeleteClosedAccessReviewsBefore(ctx context.Context, before time.Time) (int64, int64, error) {
	args := m.Called(ctx, before)
	return args.Get(0).(int64), args.Get(1).(int64), args.Error(2)
}

func (m *MockStorage) DeleteExpiredBreakGlassBefore(ctx context.Context, before time.Time) (int64, error) {
	a := m.Called(ctx, before)
	return a.Get(0).(int64), a.Error(1)
}

func (m *MockStorage) DeleteResolvedAccessRequestsBefore(ctx context.Context, before time.Time) (int64, int64, error) {
	a := m.Called(ctx, before)
	return a.Get(0).(int64), a.Get(1).(int64), a.Error(2)
}

func (m *MockStorage) ListSecrets(ctx context.Context, filter *storage.SecretFilter) ([]*models.SecretNode, int64, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]*models.SecretNode), args.Get(1).(int64), args.Error(2)
}

func (m *MockStorage) ListOrphanedSecrets(ctx context.Context, projectID uint) ([]*models.SecretNode, error) {
	args := m.Called(ctx, projectID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.SecretNode), args.Error(1)
}

func (m *MockStorage) CountOrphanedSecretsByProject(ctx context.Context, projectIDs []uint) (map[uint]int, error) {
	args := m.Called(ctx, projectIDs)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[uint]int), args.Error(1)
}

func (m *MockStorage) CountExpiringSecretsByProject(ctx context.Context, projectIDs []uint, expiresBefore time.Time) (map[uint]int, error) {
	args := m.Called(ctx, projectIDs, expiresBefore)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[uint]int), args.Error(1)
}

func (m *MockStorage) ListLiveSecretNamesByProject(ctx context.Context, projectIDs []uint, limit int) ([]storage.SecretNameRow, bool, error) {
	args := m.Called(ctx, projectIDs, limit)
	if args.Get(0) == nil {
		return nil, args.Bool(1), args.Error(2)
	}
	return args.Get(0).([]storage.SecretNameRow), args.Bool(1), args.Error(2)
}

func (m *MockStorage) ListProjectSecretsForDrift(ctx context.Context, projectID uint) ([]storage.DriftSecretRow, error) {
	args := m.Called(ctx, projectID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]storage.DriftSecretRow), args.Error(1)
}

func (m *MockStorage) GetSecretTags(ctx context.Context, secretID uint) ([]string, error) {
	args := m.Called(ctx, secretID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockStorage) SetSecretTags(ctx context.Context, secretID uint, tagNames []string) error {
	args := m.Called(ctx, secretID, tagNames)
	return args.Error(0)
}

func (m *MockStorage) GetSecretVersions(ctx context.Context, secretID uint) ([]*models.SecretVersion, error) {
	args := m.Called(ctx, secretID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.SecretVersion), args.Error(1)
}

func (m *MockStorage) CreateSecretVersion(ctx context.Context, version *models.SecretVersion) (*models.SecretVersion, error) {
	args := m.Called(ctx, version)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SecretVersion), args.Error(1)
}

func (m *MockStorage) GetLatestSecretVersion(ctx context.Context, secretID uint) (*models.SecretVersion, error) {
	args := m.Called(ctx, secretID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SecretVersion), args.Error(1)
}

func (m *MockStorage) SetSecretCertNotAfter(ctx context.Context, secretID uint, notAfter *time.Time) error {
	return m.Called(ctx, secretID, notAfter).Error(0)
}

func (m *MockStorage) SetRetentionOverride(ctx context.Context, secretID uint, days int) error {
	return m.Called(ctx, secretID, days).Error(0)
}

func (m *MockStorage) IncrementSecretReadCount(ctx context.Context, versionID uint) error {
	args := m.Called(ctx, versionID)
	return args.Error(0)
}

func (m *MockStorage) TryIncrementSecretReadCount(ctx context.Context, versionID uint, maxReads int) (bool, error) {
	args := m.Called(ctx, versionID, maxReads)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) TryIncrementSecretNodeReadCount(ctx context.Context, secretID uint, maxReads int) (bool, error) {
	args := m.Called(ctx, secretID, maxReads)
	return args.Bool(0), args.Error(1)
}

// Secret Sharing Management

func (m *MockStorage) CreateShareRecord(ctx context.Context, share *models.ShareRecord) (*models.ShareRecord, error) {
	args := m.Called(ctx, share)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ShareRecord), args.Error(1)
}

func (m *MockStorage) GetShareRecord(ctx context.Context, shareID uint) (*models.ShareRecord, error) {
	args := m.Called(ctx, shareID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ShareRecord), args.Error(1)
}

func (m *MockStorage) UpdateShareRecord(ctx context.Context, share *models.ShareRecord) (*models.ShareRecord, error) {
	a := m.Called(ctx, share)
	v, _ := a.Get(0).(*models.ShareRecord)
	return v, a.Error(1)
}

func (m *MockStorage) DeleteShareRecord(ctx context.Context, shareID uint) error {
	args := m.Called(ctx, shareID)
	return args.Error(0)
}

// now (all seven methods below) is accepted for storage.Storage conformance
// but deliberately NOT forwarded to m.Called() -- these are mocking DB
// behavior, and the injected clock a caller passes is not something the
// existing ~90 .On(...) expectation setups across this test suite assert on
// (unlike DeleteExpiredShareRecords' `before`, which genuinely varies
// meaningfully between its own test cases below). Forwarding it would force
// every one of those setups to add a matching arg for no test-behavior gain.
func (m *MockStorage) ListSharesBySecret(ctx context.Context, secretID uint, now time.Time) ([]*models.ShareRecord, error) {
	args := m.Called(ctx, secretID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.ShareRecord), args.Error(1)
}

func (m *MockStorage) ListSharesBySecretIDs(ctx context.Context, secretIDs []uint, now time.Time) ([]*models.ShareRecord, error) {
	args := m.Called(ctx, secretIDs)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.ShareRecord), args.Error(1)
}

func (m *MockStorage) ListSharesByUser(ctx context.Context, userID uint, now time.Time) ([]*models.ShareRecord, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.ShareRecord), args.Error(1)
}

func (m *MockStorage) ListSharesByOwner(ctx context.Context, ownerID uint, now time.Time) ([]*models.ShareRecord, error) {
	args := m.Called(ctx, ownerID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.ShareRecord), args.Error(1)
}

func (m *MockStorage) ListSharesByGroup(ctx context.Context, groupID uint, now time.Time) ([]*models.ShareRecord, error) {
	args := m.Called(ctx, groupID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.ShareRecord), args.Error(1)
}

func (m *MockStorage) ListSharedSecrets(ctx context.Context, userID uint, now time.Time) ([]*models.SecretNode, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.SecretNode), args.Error(1)
}

func (m *MockStorage) CheckSharePermission(ctx context.Context, secretID, userID uint, now time.Time) (string, error) {
	args := m.Called(ctx, secretID, userID)
	return args.String(0), args.Error(1)
}

func (m *MockStorage) ReassignSecretShareOwner(ctx context.Context, secretID, newOwnerID uint) (int64, error) {
	args := m.Called(ctx, secretID, newOwnerID)
	return int64(args.Int(0)), args.Error(1)
}

func (m *MockStorage) DeleteExpiredShareRecords(ctx context.Context, before time.Time) ([]*models.ShareRecord, error) {
	args := m.Called(ctx, before)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.ShareRecord), args.Error(1)
}

// User Management

// CreateUser ignores the optional plaintextPassword variadic (#499) — it is not
// forwarded to m.Called, so existing `.On("CreateUser", ctx, user)`
// expectations (2 args) keep matching regardless of what core passes.
func (m *MockStorage) CreateUser(ctx context.Context, user *models.User, _ ...string) (*models.User, error) {
	args := m.Called(ctx, user)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockStorage) GetUser(ctx context.Context, id uint) (*models.User, error) {
	if !m.mockHasExpectation("GetUser") {
		return nil, errMockLookupNotStubbed
	}
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

// LockUserForUpdate has no row lock in the mock; it reuses the GetUser expectation.
func (m *MockStorage) LockUserForUpdate(ctx context.Context, id uint) (*models.User, error) {
	return m.GetUser(ctx, id)
}

func (m *MockStorage) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockStorage) UpdateUser(ctx context.Context, user *models.User) (*models.User, error) {
	args := m.Called(ctx, user)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockStorage) UpdateUserIfActiveStateMatches(ctx context.Context, user *models.User, fromActive bool) (bool, error) {
	args := m.Called(ctx, user, fromActive)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) UpdateLastLogin(ctx context.Context, userID uint, loginAt time.Time) error {
	args := m.Called(ctx, userID, loginAt)
	return args.Error(0)
}

func (m *MockStorage) SetAccountState(ctx context.Context, id uint, state string, updatedAt time.Time) error {
	args := m.Called(ctx, id, state, updatedAt)
	return args.Error(0)
}

func (m *MockStorage) SetAccountStateIfMatches(ctx context.Context, id uint, fromState, toState string, updatedAt time.Time) (bool, error) {
	args := m.Called(ctx, id, fromState, toState, updatedAt)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) ClaimUserExternalIDIfUnset(ctx context.Context, id uint, externalID string, updatedAt time.Time) (bool, error) {
	args := m.Called(ctx, id, externalID, updatedAt)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) SetPasswordHash(ctx context.Context, id uint, hash string, changedAt time.Time) error {
	args := m.Called(ctx, id, hash, changedAt)
	return args.Error(0)
}

func (m *MockStorage) SetOneTimePasswordExpiry(ctx context.Context, id uint, expiresAt *time.Time, updatedAt time.Time) error {
	args := m.Called(ctx, id, expiresAt, updatedAt)
	return args.Error(0)
}

func (m *MockStorage) UpdateLoginLockoutState(ctx context.Context, id uint, attempts int, lastFailedAt, lockedUntil *time.Time, lockoutCount int) error {
	args := m.Called(ctx, id, attempts, lastFailedAt, lockedUntil, lockoutCount)
	return args.Error(0)
}

func (m *MockStorage) DeleteUser(ctx context.Context, id uint) error {
	return m.Called(ctx, id).Error(0)
}

func (m *MockStorage) RestoreUser(ctx context.Context, id uint) error {
	return m.Called(ctx, id).Error(0)
}

func (m *MockStorage) PurgeDeletedUsersBefore(ctx context.Context, before time.Time) (int64, error) {
	a := m.Called(ctx, before)
	return a.Get(0).(int64), a.Error(1)
}

func (m *MockStorage) PurgeDeletedProjectsBefore(ctx context.Context, before time.Time) (int64, error) {
	a := m.Called(ctx, before)
	return a.Get(0).(int64), a.Error(1)
}

func (m *MockStorage) PurgeDeletedEnvironmentsBefore(ctx context.Context, before time.Time) (int64, error) {
	a := m.Called(ctx, before)
	return a.Get(0).(int64), a.Error(1)
}

func (m *MockStorage) ListUsers(ctx context.Context, filter *storage.UserFilter) ([]*models.User, int64, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]*models.User), args.Get(1).(int64), args.Error(2)
}

func (m *MockStorage) ListUsersInStateBefore(ctx context.Context, state string, before time.Time) ([]*models.User, error) {
	args := m.Called(ctx, state, before)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.User), args.Error(1)
}

func (m *MockStorage) ListInactiveUsers(ctx context.Context, threshold time.Time) ([]*models.User, error) {
	args := m.Called(ctx, threshold)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.User), args.Error(1)
}

func (m *MockStorage) CreateUserWithRoleGrants(ctx context.Context, user *models.User, grants []storage.RoleGrant) (*models.User, error) {
	args := m.Called(ctx, user, grants)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockStorage) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	args := m.Called(ctx, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockStorage) GetUserByExternalID(ctx context.Context, externalID string) (*models.User, error) {
	args := m.Called(ctx, externalID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockStorage) GetUserGroups(ctx context.Context, userID uint) ([]*models.Group, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Group), args.Error(1)
}

func (m *MockStorage) ListAllUserGroupMemberships(ctx context.Context) ([]storage.UserGroupMembership, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]storage.UserGroupMembership), args.Error(1)
}

func (m *MockStorage) GetUserGroupsAt(ctx context.Context, userID uint, scope storage.Scope) ([]*models.Group, error) {
	args := m.Called(ctx, userID, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Group), args.Error(1)
}

func (m *MockStorage) AddPasswordHistory(ctx context.Context, userID uint, hash string, at time.Time) error {
	args := m.Called(ctx, userID, hash, at)
	return args.Error(0)
}

func (m *MockStorage) RecentPasswordHashes(ctx context.Context, userID uint, limit int) ([]string, error) {
	args := m.Called(ctx, userID, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockStorage) PrunePasswordHistory(ctx context.Context, userID uint, keep int) error {
	args := m.Called(ctx, userID, keep)
	return args.Error(0)
}

func (m *MockStorage) CreateGroup(ctx context.Context, group *models.Group) (*models.Group, error) {
	args := m.Called(ctx, group)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Group), args.Error(1)
}

func (m *MockStorage) GetGroup(ctx context.Context, id uint) (*models.Group, error) {
	if !m.mockHasExpectation("GetGroup") {
		return nil, errMockLookupNotStubbed
	}
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Group), args.Error(1)
}

func (m *MockStorage) UpdateGroupFields(ctx context.Context, id uint, name, nameFolded, description *string, updatedAt time.Time) (bool, error) {
	a := m.Called(ctx, id, name, nameFolded, description, updatedAt)
	return a.Bool(0), a.Error(1)
}

func (m *MockStorage) DeleteGroup(ctx context.Context, id uint) error {
	return m.Called(ctx, id).Error(0)
}

func (m *MockStorage) RestoreGroup(ctx context.Context, id uint) error {
	return m.Called(ctx, id).Error(0)
}

func (m *MockStorage) ListGroups(ctx context.Context) ([]*models.Group, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Group), args.Error(1)
}

func (m *MockStorage) ListGroupsPage(ctx context.Context, offset, pageSize int) ([]*models.Group, int64, error) {
	args := m.Called(ctx, offset, pageSize)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]*models.Group), args.Get(1).(int64), args.Error(2)
}

func (m *MockStorage) AddUserToGroup(ctx context.Context, userID, groupID, projectID uint) error {
	args := m.Called(ctx, userID, groupID, projectID)
	return args.Error(0)
}

func (m *MockStorage) RemoveUserFromGroup(ctx context.Context, userID, groupID, projectID uint) error {
	return m.Called(ctx, userID, groupID, projectID).Error(0)
}

func (m *MockStorage) ListGroupMembers(ctx context.Context, groupID uint) ([]*models.User, error) {
	args := m.Called(ctx, groupID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.User), args.Error(1)
}

func (m *MockStorage) ListGroupMembersAt(ctx context.Context, groupID uint, scope storage.Scope) ([]*models.User, error) {
	args := m.Called(ctx, groupID, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.User), args.Error(1)
}

func (m *MockStorage) ListGroupMembersByGroupIDs(ctx context.Context, groupIDs []uint) (map[uint][]*models.User, error) {
	args := m.Called(ctx, groupIDs)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[uint][]*models.User), args.Error(1)
}

// Role Management

func (m *MockStorage) CreateRole(ctx context.Context, name identity.FoldedName, description string) (*models.Role, error) {
	args := m.Called(ctx, name, description)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Role), args.Error(1)
}

func (m *MockStorage) SetRoleBypassesPermissionChecks(ctx context.Context, roleID uint, value bool) error {
	args := m.Called(ctx, roleID, value)
	return args.Error(0)
}

func (m *MockStorage) GetRole(ctx context.Context, id uint) (*models.Role, error) {
	if !m.mockHasExpectation("GetRole") {
		return nil, errMockLookupNotStubbed
	}
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Role), args.Error(1)
}

func (m *MockStorage) GetRoleByName(ctx context.Context, name string) (*models.Role, error) {
	args := m.Called(ctx, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Role), args.Error(1)
}

func (m *MockStorage) UpdateRole(ctx context.Context, role *models.Role) (*models.Role, error) {
	a := m.Called(ctx, role)
	v, _ := a.Get(0).(*models.Role)
	return v, a.Error(1)
}

func (m *MockStorage) DeleteRole(ctx context.Context, id uint) (storage.RoleDeleteCascadeCounts, error) {
	a := m.Called(ctx, id)
	v, _ := a.Get(0).(storage.RoleDeleteCascadeCounts)
	return v, a.Error(1)
}

func (m *MockStorage) ListRoles(ctx context.Context) ([]*models.Role, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Role), args.Error(1)
}

// RBAC Operations

func (m *MockStorage) AssignRole(ctx context.Context, userID, roleID uint, scope storage.Scope) error {
	args := m.Called(ctx, userID, roleID, scope)
	return args.Error(0)
}

func (m *MockStorage) AssignRoleWithExpiry(ctx context.Context, userID, roleID uint, scope storage.Scope, expiresAt time.Time) error {
	args := m.Called(ctx, userID, roleID, scope, expiresAt)
	return args.Error(0)
}

func (m *MockStorage) RemoveRole(ctx context.Context, userID, roleID uint, scope storage.Scope) error {
	return m.Called(ctx, userID, roleID, scope).Error(0)
}

func (m *MockStorage) RemoveAllProjectRoleGrants(ctx context.Context, userID, projectID uint) error {
	args := m.Called(ctx, userID, projectID)
	return args.Error(0)
}

func (m *MockStorage) ClearProjectSecretOwnership(ctx context.Context, userID, projectID uint) error {
	args := m.Called(ctx, userID, projectID)
	return args.Error(0)
}

func (m *MockStorage) AssignRoleToGroupWithExpiry(ctx context.Context, groupID, roleID uint, scope storage.Scope, expiresAt time.Time) error {
	args := m.Called(ctx, groupID, roleID, scope, expiresAt)
	return args.Error(0)
}

func (m *MockStorage) DeleteExpiredRoleGrants(ctx context.Context, before time.Time) ([]storage.RoleAssignment, error) {
	args := m.Called(ctx, before)
	if v := args.Get(0); v != nil {
		return v.([]storage.RoleAssignment), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockStorage) GetUserRoles(ctx context.Context, userID uint) ([]*models.Role, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Role), args.Error(1)
}

func (m *MockStorage) GetUserRoleIDsAt(ctx context.Context, userID uint, scope storage.Scope) ([]uint, error) {
	args := m.Called(ctx, userID, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]uint), args.Error(1)
}

func (m *MockStorage) GetUserRoleIDsExact(ctx context.Context, userID uint, scope storage.Scope) ([]uint, error) {
	a := m.Called(ctx, userID, scope)
	v, _ := a.Get(0).([]uint)
	return v, a.Error(1)
}

func (m *MockStorage) IsProjectMember(ctx context.Context, userID, projectID uint) (bool, error) {
	args := m.Called(ctx, userID, projectID)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) ProjectMembershipsAmong(ctx context.Context, userID uint, projectIDs []uint) (map[uint]bool, error) {
	args := m.Called(ctx, userID, projectIDs)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[uint]bool), args.Error(1)
}

func (m *MockStorage) ListUserRoleGrants(ctx context.Context, userID uint) ([]storage.UserRoleGrant, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]storage.UserRoleGrant), args.Error(1)
}

func (m *MockStorage) ListUserLiveGroupMemberships(ctx context.Context, userID uint) ([]storage.UserGroupMembershipAt, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]storage.UserGroupMembershipAt), args.Error(1)
}

func (m *MockStorage) IsGroupProjectScoped(ctx context.Context, groupID, projectID uint) (bool, error) {
	args := m.Called(ctx, groupID, projectID)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) GetUserGroupRoleIDsAt(ctx context.Context, userID uint, scope storage.Scope) ([]uint, error) {
	a := m.Called(ctx, userID, scope)
	v, _ := a.Get(0).([]uint)
	return v, a.Error(1)
}

func (m *MockStorage) GetUserRoleScopes(ctx context.Context, userID uint) ([]storage.Scope, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]storage.Scope), args.Error(1)
}

func (m *MockStorage) RoleSetHasPermission(ctx context.Context, roleIDs []uint, permission string) (bool, error) {
	args := m.Called(ctx, roleIDs, permission)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) RoleSetBypassesPermissionChecks(ctx context.Context, roleIDs []uint) (bool, error) {
	args := m.Called(ctx, roleIDs)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) GetUserPermissions(ctx context.Context, userID uint) ([]*storage.Permission, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*storage.Permission), args.Error(1)
}

func (m *MockStorage) GetUserGroupPermissions(ctx context.Context, userID uint) ([]*storage.Permission, error) {
	a := m.Called(ctx, userID)
	v, _ := a.Get(0).([]*storage.Permission)
	return v, a.Error(1)
}

// Audit Logging

func (m *MockStorage) LogAuditEvent(ctx context.Context, event *models.AuditEvent) error {
	args := m.Called(ctx, event)
	return args.Error(0)
}

func (m *MockStorage) LogAuditEventWithAccessLog(ctx context.Context, event *models.AuditEvent, accessLog *models.SecretAccessLog) error {
	args := m.Called(ctx, event, accessLog)
	return args.Error(0)
}

func (m *MockStorage) CreateSecretAccessLog(ctx context.Context, log *models.SecretAccessLog) error {
	args := m.Called(ctx, log)
	return args.Error(0)
}

func (m *MockStorage) ListSecretAccessLogs(ctx context.Context, secretID uint, since time.Time) ([]models.SecretAccessLog, error) {
	args := m.Called(ctx, secretID, since)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.SecretAccessLog), args.Error(1)
}

func (m *MockStorage) CountSecretReadsBySecretIDs(ctx context.Context, secretIDs []uint, since time.Time) (map[uint]int, error) {
	args := m.Called(ctx, secretIDs, since)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[uint]int), args.Error(1)
}

func (m *MockStorage) ListSecretIDsAccessedSince(ctx context.Context, since time.Time) ([]uint, error) {
	args := m.Called(ctx, since)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]uint), args.Error(1)
}

func (m *MockStorage) PrincipalSecretFirstSeen(ctx context.Context, since time.Time) (map[string]map[uint]time.Time, error) {
	args := m.Called(ctx, since)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]map[uint]time.Time), args.Error(1)
}

func (m *MockStorage) MostAccessedSecrets(ctx context.Context, projectID, environmentID *uint, since time.Time, limit int) ([]storage.SecretUsageStat, error) {
	args := m.Called(ctx, projectID, environmentID, since, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]storage.SecretUsageStat), args.Error(1)
}

func (m *MockStorage) AuditRetentionStats(ctx context.Context) (*storage.AuditRetentionStats, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.AuditRetentionStats), args.Error(1)
}

func (m *MockStorage) DeleteAuditLogsBefore(ctx context.Context, cutoff time.Time) (int64, *storage.AuditChainAnchor, error) {
	args := m.Called(ctx, cutoff)
	var anchor *storage.AuditChainAnchor
	if args.Get(1) != nil {
		anchor = args.Get(1).(*storage.AuditChainAnchor)
	}
	return args.Get(0).(int64), anchor, args.Error(2)
}

func (m *MockStorage) VerifyAuditChain(ctx context.Context, anchor *storage.AuditChainAnchor) (*storage.AuditChainVerification, error) {
	args := m.Called(ctx, anchor)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.AuditChainVerification), args.Error(1)
}

func (m *MockStorage) VerifyAuditChainSegment(ctx context.Context, seg storage.AuditChainSegment) (*storage.AuditChainVerification, error) {
	args := m.Called(ctx, seg)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.AuditChainVerification), args.Error(1)
}

func (m *MockStorage) MigrateAuditChainEncoding(ctx context.Context, dryRun bool, anchor *storage.AuditChainAnchor) (*storage.AuditChainMigrationResult, error) {
	args := m.Called(ctx, dryRun, anchor)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.AuditChainMigrationResult), args.Error(1)
}

func (m *MockStorage) CreateAuditCheckpoint(ctx context.Context, cp *models.AuditCheckpoint) error {
	args := m.Called(ctx, cp)
	return args.Error(0)
}

func (m *MockStorage) LatestAuditCheckpoint(ctx context.Context) (*models.AuditCheckpoint, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AuditCheckpoint), args.Error(1)
}

func (m *MockStorage) UpdateAuditCheckpointAnchor(ctx context.Context, id uint, token []byte, anchoredAt time.Time, provider string) error {
	args := m.Called(ctx, id, token, anchoredAt, provider)
	return args.Error(0)
}

func (m *MockStorage) AuditEntryHashByID(ctx context.Context, id uint) (string, bool, error) {
	args := m.Called(ctx, id)
	return args.String(0), args.Bool(1), args.Error(2)
}

func (m *MockStorage) GetSystemMetadata(ctx context.Context, key string) (string, bool, error) {
	args := m.Called(ctx, key)
	return args.String(0), args.Bool(1), args.Error(2)
}

func (m *MockStorage) SetSystemMetadata(ctx context.Context, key, value string) error {
	args := m.Called(ctx, key, value)
	return args.Error(0)
}

func (m *MockStorage) GetRecoveryKeyRecord(ctx context.Context) (*models.RecoveryKeyRecord, bool, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Bool(1), args.Error(2)
	}
	return args.Get(0).(*models.RecoveryKeyRecord), args.Bool(1), args.Error(2)
}

func (m *MockStorage) SetRecoveryKeyRecord(ctx context.Context, record *models.RecoveryKeyRecord) error {
	args := m.Called(ctx, record)
	return args.Error(0)
}

func (m *MockStorage) UnusedSecrets(ctx context.Context, projectID, environmentID *uint, notReadSince time.Time) ([]storage.UnusedSecretStat, error) {
	args := m.Called(ctx, projectID, environmentID, notReadSince)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]storage.UnusedSecretStat), args.Error(1)
}

func (m *MockStorage) CountUnusedSecretsByProject(ctx context.Context, projectIDs []uint, notReadSince time.Time) (map[uint]int, error) {
	args := m.Called(ctx, projectIDs, notReadSince)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[uint]int), args.Error(1)
}

func (m *MockStorage) CreateAnomalyAlert(ctx context.Context, alert *models.AnomalyAlert) error {
	args := m.Called(ctx, alert)
	return args.Error(0)
}

func (m *MockStorage) ListAnomalyAlerts(ctx context.Context, acknowledged *bool) ([]models.AnomalyAlert, error) {
	args := m.Called(ctx, acknowledged)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.AnomalyAlert), args.Error(1)
}

func (m *MockStorage) AcknowledgeAnomalyAlert(ctx context.Context, id, actorID uint, at time.Time) error {
	args := m.Called(ctx, id, actorID, at)
	return args.Error(0)
}

func (m *MockStorage) ListUnalertedAnomalyAlerts(ctx context.Context) ([]models.AnomalyAlert, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.AnomalyAlert), args.Error(1)
}

func (m *MockStorage) MarkAnomalyAlertAlerted(ctx context.Context, id uint) error {
	return m.Called(ctx, id).Error(0)
}

func (m *MockStorage) GetAnomalyConfig(ctx context.Context) (*models.AnomalyConfigRecord, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AnomalyConfigRecord), args.Error(1)
}

func (m *MockStorage) SaveAnomalyConfig(ctx context.Context, cfg *models.AnomalyConfigRecord) error {
	return m.Called(ctx, cfg).Error(0)
}

func (m *MockStorage) GetAuditLogs(ctx context.Context, filter *storage.AuditFilter) ([]*models.AuditEvent, int64, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]*models.AuditEvent), args.Get(1).(int64), args.Error(2)
}

// Session Management

func (m *MockStorage) CreateSession(ctx context.Context, session *models.Session) (*models.Session, error) {
	args := m.Called(ctx, session)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Session), args.Error(1)
}

func (m *MockStorage) GetSession(ctx context.Context, token string) (*models.Session, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Session), args.Error(1)
}

func (m *MockStorage) GetSessionAny(ctx context.Context, token string) (*models.Session, error) {
	a := m.Called(ctx, token)
	v, _ := a.Get(0).(*models.Session)
	return v, a.Error(1)
}

func (m *MockStorage) RotateSession(ctx context.Context, oldID uint, newSession *models.Session, now time.Time) (*models.Session, bool, error) {
	args := m.Called(ctx, oldID, newSession, now)
	if args.Get(0) == nil {
		return nil, args.Bool(1), args.Error(2)
	}
	return args.Get(0).(*models.Session), args.Bool(1), args.Error(2)
}

func (m *MockStorage) ListSessionTokenHashesByFamily(ctx context.Context, familyID string) ([]string, error) {
	args := m.Called(ctx, familyID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockStorage) DeleteSessionsByFamily(ctx context.Context, familyID string) error {
	args := m.Called(ctx, familyID)
	return args.Error(0)
}

func (m *MockStorage) DeleteSession(ctx context.Context, id uint) error {
	return m.Called(ctx, id).Error(0)
}

func (m *MockStorage) CleanupExpiredSessions(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockStorage) GetSessionByID(ctx context.Context, id uint) (*models.Session, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Session), args.Error(1)
}

func (m *MockStorage) ListSessionsByUser(ctx context.Context, userID uint) ([]*models.Session, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Session), args.Error(1)
}

func (m *MockStorage) EnforceSessionLimit(_ context.Context, _ uint, _ int) error { return nil }

func (m *MockStorage) DeleteSessionsForUserExcept(ctx context.Context, userID, exceptID uint) error {
	args := m.Called(ctx, userID, exceptID)
	return args.Error(0)
}

func (m *MockStorage) ListSessionTokenHashesForUser(ctx context.Context, userID uint) ([]string, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockStorage) TouchSession(ctx context.Context, id uint, seenAt time.Time, staleness time.Duration) error {
	args := m.Called(ctx, id, seenAt, staleness)
	return args.Error(0)
}

// Personal Access Token Management

func (m *MockStorage) CreatePersonalAccessToken(ctx context.Context, t *models.PersonalAccessToken) (*models.PersonalAccessToken, error) {
	args := m.Called(ctx, t)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.PersonalAccessToken), args.Error(1)
}

func (m *MockStorage) ListPersonalAccessTokensByUser(ctx context.Context, userID uint) ([]*models.PersonalAccessToken, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.PersonalAccessToken), args.Error(1)
}

func (m *MockStorage) ListActivePersonalAccessTokens(ctx context.Context) ([]*models.PersonalAccessToken, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.PersonalAccessToken), args.Error(1)
}

func (m *MockStorage) GetPersonalAccessTokenByID(ctx context.Context, id uint) (*models.PersonalAccessToken, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.PersonalAccessToken), args.Error(1)
}

func (m *MockStorage) GetPersonalAccessTokenByHash(ctx context.Context, hash string) (*models.PersonalAccessToken, error) {
	args := m.Called(ctx, hash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.PersonalAccessToken), args.Error(1)
}

func (m *MockStorage) RevokePersonalAccessToken(ctx context.Context, id uint) error {
	return m.Called(ctx, id).Error(0)
}

func (m *MockStorage) RevokeAllPersonalAccessTokensForUser(ctx context.Context, userID uint) ([]string, error) {
	a := m.Called(ctx, userID)
	v, _ := a.Get(0).([]string)
	return v, a.Error(1)
}

func (m *MockStorage) TouchPersonalAccessToken(ctx context.Context, id uint, usedAt time.Time, staleness time.Duration) error {
	args := m.Called(ctx, id, usedAt, staleness)
	return args.Error(0)
}

func (m *MockStorage) ListExpiredPATsByUser(ctx context.Context, userID uint, now time.Time) ([]*models.PersonalAccessToken, error) {
	args := m.Called(ctx, userID, now)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.PersonalAccessToken), args.Error(1)
}

func (m *MockStorage) BulkRevokeExpiredPATsByUser(ctx context.Context, userID uint, now time.Time) ([]string, error) {
	args := m.Called(ctx, userID, now)
	v, _ := args.Get(0).([]string)
	return v, args.Error(1)
}

// Setup Token Management (ADR-028)

func (m *MockStorage) CreateSetupToken(ctx context.Context, t *models.SetupToken) (*models.SetupToken, error) {
	args := m.Called(ctx, t)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SetupToken), args.Error(1)
}

func (m *MockStorage) GetSetupTokenByHash(ctx context.Context, hash string) (*models.SetupToken, error) {
	args := m.Called(ctx, hash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SetupToken), args.Error(1)
}

func (m *MockStorage) GetSetupTokenByID(ctx context.Context, id uint) (*models.SetupToken, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SetupToken), args.Error(1)
}

func (m *MockStorage) SupersedeActiveSetupTokens(ctx context.Context, purpose, email string, projectID *uint) error {
	args := m.Called(ctx, purpose, email, projectID)
	return args.Error(0)
}

func (m *MockStorage) MarkSetupTokenConsumed(ctx context.Context, id uint, consumedAt time.Time) (bool, error) {
	args := m.Called(ctx, id, consumedAt)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) MarkSetupTokenExpired(ctx context.Context, id uint) error {
	return m.Called(ctx, id).Error(0)
}

func (m *MockStorage) CountSetupTokensSince(ctx context.Context, purpose, email string, since time.Time) (int64, error) {
	args := m.Called(ctx, purpose, email, since)
	return args.Get(0).(int64), args.Error(1)
}

// Health and Maintenance

func (m *MockStorage) HealthCheck(ctx context.Context) error {
	return m.Called(ctx).Error(0)
}

func (m *MockStorage) GetStats(ctx context.Context) (*storage.StorageStats, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.StorageStats), args.Error(1)
}

func (m *MockStorage) GetProjectUsageStats(ctx context.Context, projectIDs []uint, windowDays int) ([]storage.ProjectUsageStat, error) {
	args := m.Called(ctx, projectIDs, windowDays)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]storage.ProjectUsageStat), args.Error(1)
}

func (m *MockStorage) GetBillingReport(ctx context.Context, from, to time.Time, projectIDs []uint) (*storage.BillingReport, error) {
	args := m.Called(ctx, from, to, projectIDs)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.BillingReport), args.Error(1)
}

func (m *MockStorage) SaveStatsSnapshot(ctx context.Context, snapshot *models.StatsSnapshot) error {
	args := m.Called(ctx, snapshot)
	return args.Error(0)
}

func (m *MockStorage) GetPreviousStatsSnapshot(ctx context.Context, userID uint) (*models.StatsSnapshot, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.StatsSnapshot), args.Error(1)
}

func (m *MockStorage) SaveDeploymentStatsSnapshot(_ context.Context, _ *models.DeploymentStatsSnapshot) error {
	return nil
}

func (m *MockStorage) GetPreviousDeploymentStatsSnapshot(_ context.Context) (*models.DeploymentStatsSnapshot, error) {
	return nil, nil
}

func (m *MockStorage) GetDistinctActiveUserIDs(_ context.Context, _ time.Time) ([]uint, error) {
	return nil, nil
}

func (m *MockStorage) CountImpersonatedActions(_ context.Context, actingAs, impersonator uint, since time.Time) (int64, error) {
	args := m.Called(actingAs, impersonator, since)
	return args.Get(0).(int64), args.Error(1)
}

// Permission queries

func (m *MockStorage) ListPermissions(_ context.Context) ([]*models.Permission, error) {
	return nil, nil
}

func (m *MockStorage) GetPermission(_ context.Context, id uint) (*models.Permission, error) {
	return &models.Permission{ID: id}, nil
}

func (m *MockStorage) GetRolePermissions(ctx context.Context, roleID uint) ([]*models.Permission, error) {
	for _, c := range m.ExpectedCalls {
		if c.Method == "GetRolePermissions" {
			args := m.Called(ctx, roleID)
			if args.Get(0) == nil {
				return nil, args.Error(1)
			}
			return args.Get(0).([]*models.Permission), args.Error(1)
		}
	}
	return nil, nil
}

func (m *MockStorage) RemovePermissionFromRole(_ context.Context, _, _ uint) error {
	return nil
}

// Keyorix Connect per-reference grants (ADR-045) — core enforcement is tested against
// real SQLite, so these mock stubs just satisfy the interface.
func (m *MockStorage) ListConnectRefGrantsByConnector(ctx context.Context, connector string) ([]*models.ConnectRefGrant, error) {
	for _, c := range m.ExpectedCalls {
		if c.Method == "ListConnectRefGrantsByConnector" {
			args := m.Called(ctx, connector)
			if args.Get(0) == nil {
				return nil, args.Error(1)
			}
			return args.Get(0).([]*models.ConnectRefGrant), args.Error(1)
		}
	}
	return nil, nil
}
func (m *MockStorage) ListConnectRefGrants(_ context.Context) ([]*models.ConnectRefGrant, error) {
	return nil, nil
}
func (m *MockStorage) CreateConnectRefGrant(_ context.Context, grant *models.ConnectRefGrant) (*models.ConnectRefGrant, error) {
	return grant, nil
}
func (m *MockStorage) DeleteConnectRefGrant(_ context.Context, _ uint) error {
	return nil
}

// ADR-082 branch 2: connector project-binding storage — core enforcement is tested
// against real SQLite (connect_rbac_test.go, connect_ownership_test.go), so these
// mock stubs just satisfy the interface. GetProjectByName/GetConnectorProjectBinding
// default to "not found" (the substring convention every caller of these checks
// against) rather than a zero value, since a zero-value *models.Project/
// *models.ConnectorProjectBinding would misrepresent a real, resolvable result.
func (m *MockStorage) GetProjectByName(_ context.Context, _ string) (*models.Project, error) {
	return nil, fmt.Errorf("project not found")
}
func (m *MockStorage) GetConnectorProjectBinding(_ context.Context, _ string) (*models.ConnectorProjectBinding, error) {
	return nil, fmt.Errorf("connector project binding not found")
}
func (m *MockStorage) CreateConnectorProjectBinding(_ context.Context, binding *models.ConnectorProjectBinding) (*models.ConnectorProjectBinding, error) {
	return binding, nil
}
func (m *MockStorage) ListConnectorProjectBindings(_ context.Context) ([]*models.ConnectorProjectBinding, error) {
	return nil, nil
}

// Group-Role assignments

func (m *MockStorage) GetGroupRoles(ctx context.Context, groupID uint) ([]*models.Role, error) {
	for _, c := range m.ExpectedCalls {
		if c.Method == "GetGroupRoles" {
			args := m.Called(ctx, groupID)
			if args.Get(0) == nil {
				return nil, args.Error(1)
			}
			return args.Get(0).([]*models.Role), args.Error(1)
		}
	}
	return nil, nil
}

func (m *MockStorage) GetGroupRoleGrants(_ context.Context, _ uint) ([]*storage.GroupRoleGrant, error) {
	return nil, nil
}

func (m *MockStorage) AssignRoleToGroup(_ context.Context, _, _ uint, _ storage.Scope) error {
	return nil
}

func (m *MockStorage) RemoveRoleFromGroup(_ context.Context, _, _ uint, _ storage.Scope) error {
	return nil
}

// Rotation Policy Management

func (m *MockStorage) CreateRotationPolicy(_ context.Context, _ *models.RotationPolicy) error {
	return nil
}

func (m *MockStorage) GetRotationPolicy(_ context.Context, id uint) (*models.RotationPolicy, error) {
	return &models.RotationPolicy{ID: id}, nil
}

func (m *MockStorage) ListRotationPolicies(ctx context.Context, projectID *uint, environmentID *uint) ([]*models.RotationPolicy, error) {
	args := m.Called(ctx, projectID, environmentID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.RotationPolicy), args.Error(1)
}

func (m *MockStorage) UpdateRotationPolicyFields(_ context.Context, _ uint, _ storage.RotationPolicyFieldUpdate, _ time.Time) (bool, error) {
	return true, nil
}

func (m *MockStorage) DeleteRotationPolicy(_ context.Context, _ uint) error {
	return nil
}

func (m *MockStorage) GetRotationPolicyBySecret(ctx context.Context, secretID uint) (*models.RotationPolicy, error) {
	args := m.Called(ctx, secretID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.RotationPolicy), args.Error(1)
}

func (m *MockStorage) UpdateRotationState(ctx context.Context, policyID uint, state, errMsg string) error {
	args := m.Called(ctx, policyID, state, errMsg)
	return args.Error(0)
}

// Machine identities (ADR-023).
func (m *MockStorage) CreateMachineIdentity(ctx context.Context, mi *models.MachineIdentity) (*models.MachineIdentity, error) {
	args := m.Called(ctx, mi)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.MachineIdentity), args.Error(1)
}

func (m *MockStorage) GetMachineIdentity(ctx context.Context, id uint) (*models.MachineIdentity, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.MachineIdentity), args.Error(1)
}

func (m *MockStorage) LockMachineIdentityForUpdate(ctx context.Context, id uint) (*models.MachineIdentity, error) {
	a := m.Called(ctx, id)
	v, _ := a.Get(0).(*models.MachineIdentity)
	return v, a.Error(1)
}

func (m *MockStorage) TransitionMachineIdentityState(ctx context.Context, mi *models.MachineIdentity, fromState string) (bool, error) {
	args := m.Called(ctx, mi, fromState)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) ListMachineIdentities(ctx context.Context, projectID uint) ([]*models.MachineIdentity, error) {
	args := m.Called(ctx, projectID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.MachineIdentity), args.Error(1)
}

func (m *MockStorage) ListAllMachineIdentities(ctx context.Context) ([]*models.MachineIdentity, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.MachineIdentity), args.Error(1)
}

func (m *MockStorage) CountMachineIdentitiesByClassification(ctx context.Context) (map[string]int, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]int), args.Error(1)
}

func (m *MockStorage) CountStaleMachineIdentitiesByProject(ctx context.Context, projectIDs []uint, olderThan time.Time) (map[uint]int, error) {
	args := m.Called(ctx, projectIDs, olderThan)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[uint]int), args.Error(1)
}

func (m *MockStorage) CreateMachineIdentityCredential(ctx context.Context, c *models.MachineIdentityCredential) (*models.MachineIdentityCredential, error) {
	args := m.Called(ctx, c)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.MachineIdentityCredential), args.Error(1)
}

func (m *MockStorage) GetMachineIdentityCredentialByHash(ctx context.Context, hash string) (*models.MachineIdentityCredential, error) {
	args := m.Called(ctx, hash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.MachineIdentityCredential), args.Error(1)
}

func (m *MockStorage) GetMachineIdentityCredentialWithIdentityStateByHash(ctx context.Context, hash string) (*models.MachineIdentityCredential, string, error) {
	args := m.Called(ctx, hash)
	if args.Get(0) == nil {
		return nil, args.String(1), args.Error(2)
	}
	return args.Get(0).(*models.MachineIdentityCredential), args.String(1), args.Error(2)
}

func (m *MockStorage) GetMachineIdentityCredentialByID(ctx context.Context, id uint) (*models.MachineIdentityCredential, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.MachineIdentityCredential), args.Error(1)
}

func (m *MockStorage) ListMachineIdentityCredentials(ctx context.Context, machineID uint) ([]*models.MachineIdentityCredential, error) {
	args := m.Called(ctx, machineID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.MachineIdentityCredential), args.Error(1)
}

func (m *MockStorage) ListActiveMachineIdentityCredentials(ctx context.Context) ([]*models.MachineIdentityCredential, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.MachineIdentityCredential), args.Error(1)
}

func (m *MockStorage) SetMachineIdentityCredentialClassification(ctx context.Context, credentialID uint, fromClassification, toClassification string) (bool, error) {
	args := m.Called(ctx, credentialID, fromClassification, toClassification)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) CountMachineIdentityCredentialsByClassification(ctx context.Context) (map[string]int, error) {
	a := m.Called(ctx)
	v, _ := a.Get(0).(map[string]int)
	return v, a.Error(1)
}

func (m *MockStorage) RevokeMachineIdentityCredential(ctx context.Context, projectID, id uint) error {
	return m.Called(ctx, projectID, id).Error(0)
}

func (m *MockStorage) TouchMachineIdentityCredential(ctx context.Context, id uint, usedAt time.Time, staleness time.Duration) error {
	// Best-effort on the auth hot path — tolerate tests that don't set an expectation.
	for _, c := range m.ExpectedCalls {
		if c.Method == "TouchMachineIdentityCredential" {
			return m.Called(ctx, id, usedAt, staleness).Error(0)
		}
	}
	return nil
}

func (m *MockStorage) AssignMachineRole(ctx context.Context, machineID, roleID uint, scope storage.Scope) error {
	args := m.Called(ctx, machineID, roleID, scope)
	return args.Error(0)
}

func (m *MockStorage) RemoveMachineRole(ctx context.Context, machineID, roleID uint, scope storage.Scope) error {
	return m.Called(ctx, machineID, roleID, scope).Error(0)
}

func (m *MockStorage) GetMachineRoleIDsAt(ctx context.Context, machineID uint, scope storage.Scope) ([]uint, error) {
	args := m.Called(ctx, machineID, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]uint), args.Error(1)
}

func (m *MockStorage) GetMachineRoles(ctx context.Context, machineID uint) ([]*models.Role, error) {
	args := m.Called(ctx, machineID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Role), args.Error(1)
}

func (m *MockStorage) GetMachineRoleScopes(ctx context.Context, machineID uint) ([]storage.Scope, error) {
	args := m.Called(ctx, machineID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]storage.Scope), args.Error(1)
}

func (m *MockStorage) CreateOIDCBinding(ctx context.Context, b *models.MachineIdentityOIDCBinding) (*models.MachineIdentityOIDCBinding, error) {
	args := m.Called(ctx, b)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.MachineIdentityOIDCBinding), args.Error(1)
}

func (m *MockStorage) GetMachineByOIDCSubject(ctx context.Context, issuer, subject string) (*models.MachineIdentity, error) {
	args := m.Called(ctx, issuer, subject)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.MachineIdentity), args.Error(1)
}

func (m *MockStorage) ListOIDCBindings(ctx context.Context, machineID uint) ([]*models.MachineIdentityOIDCBinding, error) {
	args := m.Called(ctx, machineID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.MachineIdentityOIDCBinding), args.Error(1)
}

func (m *MockStorage) GetOIDCBindingByID(ctx context.Context, id uint) (*models.MachineIdentityOIDCBinding, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.MachineIdentityOIDCBinding), args.Error(1)
}

func (m *MockStorage) DeleteOIDCBinding(ctx context.Context, id uint) error {
	return m.Called(ctx, id).Error(0)
}

// Project membership lifecycle (ADR-022).
func (m *MockStorage) CreateProjectMembership(ctx context.Context, pm *models.ProjectMembership) (*models.ProjectMembership, error) {
	args := m.Called(ctx, pm)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ProjectMembership), args.Error(1)
}

func (m *MockStorage) GetProjectMembership(ctx context.Context, id uint) (*models.ProjectMembership, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ProjectMembership), args.Error(1)
}

func (m *MockStorage) TransitionProjectMembershipState(ctx context.Context, pm *models.ProjectMembership, fromState string) (bool, error) {
	args := m.Called(ctx, pm, fromState)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) ListProjectMemberships(ctx context.Context, projectID uint) ([]*models.ProjectMembership, error) {
	args := m.Called(ctx, projectID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.ProjectMembership), args.Error(1)
}

func (m *MockStorage) GetActiveProjectMembership(ctx context.Context, projectID, userID uint) (*models.ProjectMembership, error) {
	args := m.Called(ctx, projectID, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ProjectMembership), args.Error(1)
}

func (m *MockStorage) ListStaleInvitedMemberships(ctx context.Context, before time.Time) ([]*models.ProjectMembership, error) {
	args := m.Called(ctx, before)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.ProjectMembership), args.Error(1)
}

func (m *MockStorage) ListUserProjectMemberships(ctx context.Context, userID uint) ([]*models.ProjectMembership, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.ProjectMembership), args.Error(1)
}

func (m *MockStorage) CountProjectMembershipsByUsers(ctx context.Context, userIDs []uint) (map[uint]storage.MembershipCounts, error) {
	args := m.Called(ctx, userIDs)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[uint]storage.MembershipCounts), args.Error(1)
}

func (m *MockStorage) CreateNotification(ctx context.Context, n *models.Notification) (*models.Notification, error) {
	args := m.Called(ctx, n)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Notification), args.Error(1)
}

func (m *MockStorage) ListNotifications(ctx context.Context, userID uint, unreadOnly bool, limit int) ([]*models.Notification, error) {
	args := m.Called(ctx, userID, unreadOnly, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Notification), args.Error(1)
}

func (m *MockStorage) ListScopedNotifications(ctx context.Context, userID uint, scope storage.NotificationScope, unreadOnly bool, limit int) ([]*models.Notification, error) {
	args := m.Called(ctx, userID, scope, unreadOnly, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Notification), args.Error(1)
}

func (m *MockStorage) CountUnreadScopedNotifications(ctx context.Context, userID uint, scope storage.NotificationScope) (int64, error) {
	args := m.Called(ctx, userID, scope)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockStorage) MarkScopedNotificationRead(ctx context.Context, id, userID uint, scope storage.NotificationScope) error {
	return m.Called(ctx, id, userID, scope).Error(0)
}

func (m *MockStorage) MarkAllScopedNotificationsRead(ctx context.Context, userID uint, scope storage.NotificationScope) error {
	return m.Called(ctx, userID, scope).Error(0)
}

func (m *MockStorage) CountUnreadNotifications(ctx context.Context, userID uint) (int64, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockStorage) HasUnreadNotification(ctx context.Context, userID uint, nType string, projectID uint) (bool, error) {
	args := m.Called(ctx, userID, nType, projectID)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) GetUnreadNotification(ctx context.Context, userID uint, nType string, projectID uint) (*models.Notification, error) {
	args := m.Called(ctx, userID, nType, projectID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Notification), args.Error(1)
}

func (m *MockStorage) UpdateNotification(ctx context.Context, n *models.Notification) error {
	return m.Called(ctx, n).Error(0)
}

func (m *MockStorage) MarkNotificationRead(ctx context.Context, id, userID uint) error {
	return m.Called(ctx, id, userID).Error(0)
}

func (m *MockStorage) MarkAllNotificationsRead(ctx context.Context, userID uint) error {
	return m.Called(ctx, userID).Error(0)
}

// MFA stubs (MFA core logic is tested against real SQLite, not this mock).
func (m *MockStorage) UpsertMFASecret(_ context.Context, _ *models.MFASecret) error { return nil }
func (m *MockStorage) GetMFASecret(_ context.Context, _ uint) (*models.MFASecret, error) {
	return nil, nil
}
func (m *MockStorage) ActivateMFASecret(_ context.Context, _ uint, _ []byte) (bool, error) {
	return true, nil
}
func (m *MockStorage) MarkTOTPStepUsed(_ context.Context, _ uint, _ int64) (bool, error) {
	return true, nil
}
func (m *MockStorage) ReleaseTOTPStepIfUnchanged(_ context.Context, _ uint, _ int64) (bool, error) {
	return true, nil
}
func (m *MockStorage) DeleteMFAForUser(_ context.Context, _ uint) error          { return nil }
func (m *MockStorage) SetUserMFAEnabled(_ context.Context, _ uint, _ bool) error { return nil }
func (m *MockStorage) CreateMFARecoveryCodes(_ context.Context, _ uint, _ []string) error {
	return nil
}
func (m *MockStorage) ConsumeMFARecoveryCode(_ context.Context, _ uint, _ string, _ time.Time) (bool, error) {
	return false, nil
}
func (m *MockStorage) CountUnusedMFARecoveryCodes(_ context.Context, _ uint) (int, error) {
	return 0, nil
}
func (m *MockStorage) DeleteMFARecoveryCodes(_ context.Context, _ uint) error             { return nil }
func (m *MockStorage) CreateMFAChallenge(_ context.Context, _ *models.MFAChallenge) error { return nil }
func (m *MockStorage) ConsumeMFAChallenge(_ context.Context, _ string, _ time.Time) (*models.MFAChallenge, error) {
	return nil, nil
}

// Dynamic-secrets stubs (the dynamic-secrets core logic is tested against real
// SQLite + a fake engine, not this mock). GetDynamicSecretConfig/
// TransitionDynamicSecretConfigDisabled below are FIXED stubs by default (see
// the GetDynamicSecretConfigFunc/TransitionDynamicSecretConfigDisabledFunc
// doc on the struct above for why they use a settable-func escape hatch
// instead of the usual testify .On()/m.Called() pattern).
func (m *MockStorage) CreateDynamicSecretConfig(_ context.Context, c *models.DynamicSecretConfig) (*models.DynamicSecretConfig, error) {
	return c, nil
}
func (m *MockStorage) GetDynamicSecretConfig(ctx context.Context, id uint) (*models.DynamicSecretConfig, error) {
	if m.GetDynamicSecretConfigFunc != nil {
		return m.GetDynamicSecretConfigFunc(ctx, id)
	}
	return nil, nil
}
func (m *MockStorage) ListDynamicSecretConfigs(_ context.Context, _, _ uint) ([]*models.DynamicSecretConfig, error) {
	return nil, nil
}
func (m *MockStorage) UpdateDynamicSecretConfig(_ context.Context, _ *models.DynamicSecretConfig) error {
	return nil
}
func (m *MockStorage) SetDynamicSecretConfigAdminDSN(_ context.Context, _ uint, _, _ []byte) error {
	return nil
}
func (m *MockStorage) SetDynamicSecretConfigClassification(_ context.Context, _ uint, _, _ string, _ time.Time) (bool, error) {
	return true, nil
}
func (m *MockStorage) TransitionDynamicSecretConfigDisabled(ctx context.Context, c *models.DynamicSecretConfig, fromDisabled bool) (bool, error) {
	if m.TransitionDynamicSecretConfigDisabledFunc != nil {
		return m.TransitionDynamicSecretConfigDisabledFunc(ctx, c, fromDisabled)
	}
	return true, nil
}
func (m *MockStorage) CountDynamicSecretConfigsByClassification(_ context.Context) (map[string]int, error) {
	return nil, nil
}
func (m *MockStorage) CreateDynamicSecretLease(_ context.Context, l *models.DynamicSecretLease) (*models.DynamicSecretLease, error) {
	return l, nil
}
func (m *MockStorage) GetDynamicSecretLease(_ context.Context, _ string) (*models.DynamicSecretLease, error) {
	return nil, nil
}
func (m *MockStorage) ListDynamicSecretLeases(_ context.Context, _ uint) ([]*models.DynamicSecretLease, error) {
	return nil, nil
}
func (m *MockStorage) CountActiveLeases(_ context.Context, _ uint) (int64, error) {
	return 0, nil
}
func (m *MockStorage) UpdateDynamicSecretLease(_ context.Context, _ *models.DynamicSecretLease) error {
	return nil
}
func (m *MockStorage) ExtendDynamicSecretLeaseExpiry(_ context.Context, _ string, _ time.Time) (bool, error) {
	return true, nil
}
func (m *MockStorage) RecordDynamicSecretLeaseRevocation(_ context.Context, _, _, _, _ string, _ *time.Time) (bool, error) {
	return true, nil
}
func (m *MockStorage) ListExpiredActiveLeases(_ context.Context, _ time.Time) ([]*models.DynamicSecretLease, error) {
	return nil, nil
}

// WebAuthn stubs (the WebAuthn core logic is tested against real SQLite, not this mock).
func (m *MockStorage) GetActiveMFAChallenge(_ context.Context, _ string, _ time.Time) (*models.MFAChallenge, error) {
	return nil, nil
}
func (m *MockStorage) CreateWebAuthnCredential(_ context.Context, _ *models.WebAuthnCredential) error {
	return nil
}
func (m *MockStorage) ListWebAuthnCredentials(_ context.Context, _ uint) ([]*models.WebAuthnCredential, error) {
	return nil, nil
}
func (m *MockStorage) GetWebAuthnCredentialByCredID(_ context.Context, _ []byte, _ uint) (*models.WebAuthnCredential, error) {
	return nil, nil
}
func (m *MockStorage) LockWebAuthnCredentialForUpdate(_ context.Context, _ []byte, _ uint) (*models.WebAuthnCredential, error) {
	return nil, nil
}
func (m *MockStorage) DisableWebAuthnCredential(_ context.Context, _ uint) (bool, error) {
	return true, nil
}
func (m *MockStorage) SetWebAuthnCredentialCounterState(_ context.Context, _ uint, _ []byte, _ time.Time) (bool, error) {
	return true, nil
}
func (m *MockStorage) AdvanceWebAuthnCredentialCounter(_ context.Context, _ []byte, _ uint, _ []byte, _ uint32, _ time.Time) (bool, error) {
	return false, nil
}
func (m *MockStorage) DeleteWebAuthnCredential(_ context.Context, _, _ uint) error { return nil }
func (m *MockStorage) CountWebAuthnCredentials(_ context.Context, _ uint) (int64, error) {
	return 0, nil
}
func (m *MockStorage) SetUserWebAuthnEnabled(_ context.Context, _ uint, _ bool) error { return nil }
func (m *MockStorage) CreateWebAuthnSession(_ context.Context, _ *models.WebAuthnSession) error {
	return nil
}
func (m *MockStorage) ConsumeWebAuthnSession(_ context.Context, _ string, _ time.Time) (*models.WebAuthnSession, error) {
	return nil, nil
}

func (m *MockStorage) ListAllUserRoleGrants(ctx context.Context) ([]*models.UserRole, error) {
	for _, c := range m.ExpectedCalls {
		if c.Method == "ListAllUserRoleGrants" {
			args := m.Called(ctx)
			if args.Get(0) == nil {
				return nil, args.Error(1)
			}
			return args.Get(0).([]*models.UserRole), args.Error(1)
		}
	}
	return nil, nil
}

func (m *MockStorage) ListAllGroupRoleGrants(ctx context.Context) ([]*models.GroupRole, error) {
	for _, c := range m.ExpectedCalls {
		if c.Method == "ListAllGroupRoleGrants" {
			args := m.Called(ctx)
			if args.Get(0) == nil {
				return nil, args.Error(1)
			}
			return args.Get(0).([]*models.GroupRole), args.Error(1)
		}
	}
	return nil, nil
}

func (m *MockStorage) ListExpiringUserRoles(ctx context.Context, cutoff time.Time) ([]models.UserRole, error) {
	args := m.Called(ctx, cutoff)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.UserRole), args.Error(1)
}

func (m *MockStorage) ListSecretsWithQuota(ctx context.Context) ([]models.SecretNode, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.SecretNode), args.Error(1)
}

// Per-secret / per-folder ACL stubs (ADR-058).
func (m *MockStorage) CreateOrUpdateSecretACL(_ context.Context, _ *models.SecretACL) error {
	return nil
}

func (m *MockStorage) GetSecretACL(ctx context.Context, secretID, userID uint) (*models.SecretACL, error) {
	args := m.Called(ctx, secretID, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SecretACL), args.Error(1)
}

func (m *MockStorage) ListSecretACLs(_ context.Context, _ uint) ([]*models.SecretACL, error) {
	return nil, nil
}

func (m *MockStorage) ListSecretACLsByUser(ctx context.Context, userID uint) ([]*models.SecretACL, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.SecretACL), args.Error(1)
}

func (m *MockStorage) DeleteSecretACL(_ context.Context, _ uint) error {
	return nil
}

func (m *MockStorage) DeleteSecretACLsByUserAndProject(_ context.Context, _, _ uint) error {
	return nil
}

func (m *MockStorage) GetSecretAncestors(ctx context.Context, nodeID uint) ([]uint, error) {
	args := m.Called(ctx, nodeID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]uint), args.Error(1)
}

// Compliance posture snapshot stubs — best-effort server-side writes; MockStorage
// tests that construct a core without a real DB can tolerate a no-op save and a
// nil prior snapshot (both represent "no history yet", which is the correct
// initial state for any fresh deployment).
func (m *MockStorage) SaveCompliancePostureSnapshot(_ context.Context, _ *models.CompliancePostureSnapshot) error {
	return nil
}

func (m *MockStorage) GetPreviousCompliancePostureSnapshot(_ context.Context, _ time.Time) (*models.CompliancePostureSnapshot, error) {
	return nil, nil
}

func (m *MockStorage) ListCompliancePostureSnapshots(ctx context.Context, limit int) ([]*models.CompliancePostureSnapshot, error) {
	args := m.Called(ctx, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.CompliancePostureSnapshot), args.Error(1)
}

// Temporal access schedule — stubs return no schedule (nil, nil) by default,
// which enforces no restriction (fail-open on the check side).
func (m *MockStorage) GetSecretAccessSchedule(_ context.Context, _ uint) (*models.SecretAccessSchedule, error) {
	return nil, nil
}
func (m *MockStorage) SetSecretAccessSchedule(_ context.Context, _ *models.SecretAccessSchedule) error {
	return nil
}
func (m *MockStorage) DeleteSecretAccessSchedule(_ context.Context, _ uint) error {
	return nil
}

// NEW STORAGE METHODS — do NOT append here.
//
// This file is frozen so that parallel feature branches never conflict on it.
// When your PR adds new Storage interface methods to mock, create a NEW file:
//
//	internal/core/mock_storage_<feature>_test.go
//
// Declare the methods there (same package "core", no struct redeclaration).
// Go allows a struct's method set to span multiple files in the same package,
// so the compiler enforces interface completeness across all of them.
