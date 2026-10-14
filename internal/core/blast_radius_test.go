package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// ── blastRiskLevel unit tests ──────────────────────────────────────────────────

func TestBlastRiskLevel_AllBranches(t *testing.T) {
	t.Parallel()
	cases := []struct {
		depth    int
		srcClass string
		depClass string
		wantRisk string
	}{
		// critical: depth=1 AND source is restricted
		{1, "restricted", "", "critical"},
		// critical: depth=1 AND dependent is restricted
		{1, "", "restricted", "critical"},
		// critical: depth=1 AND both restricted
		{1, "restricted", "restricted", "critical"},
		// high: depth=1, no restricted labels
		{1, "confidential", "internal", "high"},
		// high: depth=1, no labels at all
		{1, "", "", "high"},
		// high: depth=2 but source is confidential
		{2, "confidential", "", "high"},
		// high: depth=3 but dependent is restricted
		{3, "", "restricted", "high"},
		// high: depth=3 but source is confidential
		{3, "confidential", "", "high"},
		// medium: depth=2 and no high-sensitivity labels
		{2, "internal", "internal", "medium"},
		// medium: depth=2, no labels
		{2, "", "", "medium"},
		// low: depth=3, no labels
		{3, "", "", "low"},
		// low: depth=10, no labels
		{10, "", "", "low"},
	}

	for _, tc := range cases {
		got := blastRiskLevel(tc.depth, tc.srcClass, tc.depClass)
		assert.Equal(t, tc.wantRisk, got,
			"depth=%d src=%q dep=%q", tc.depth, tc.srcClass, tc.depClass)
	}
}

// ── GetBlastRadius integration tests using real SQLite ────────────────────────

// blastRadiusTestActor is the caller identity used by every real-SQLite test in this
// file (see newBlastRadiusCore's grantGlobalAdmin call). #G32: GetBlastRadius now
// independently authorizes each peer secret it discloses, so a caller with no RBAC
// grant at all would see every Dependents entry filtered out — these tests are about
// the BFS/risk-level shape, not authorization, so the fixture actor is granted global
// admin to keep that orthogonal (peer-authorization-gap regression tests live in
// TestGetBlastRadius_DoesNotDiscloseUnauthorizedPeer below, with a deliberately
// unprivileged actor).
const blastRadiusTestActor = uint(999)

// newBlastRadiusCore creates an isolated in-memory core for blast-radius tests.
func newBlastRadiusCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{},
		&models.SecretDependency{},
		&models.SecretACL{},
		&models.AuditEvent{},
		&models.Project{},
		&models.Environment{},
		&models.ShareRecord{},
		&models.User{}, &models.Role{}, &models.UserRole{},
		&models.Permission{}, &models.RolePermission{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.MachineIdentityRole{},
	))
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p1"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "env1"}).Error)
	// Global admin bypass for blastRadiusTestActor (see its doc comment above).
	// ADR-084: the bypass is now the structural BypassesPermissionChecks flag,
	// not the "admin" name — a role built via a raw Create like this one, as a
	// real bootstrap-seeded role would be, must set it explicitly.
	role := &models.Role{Name: "admin", BypassesPermissionChecks: true}
	require.NoError(t, db.Create(role).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: blastRadiusTestActor, RoleID: role.ID, ProjectID: 0, EnvironmentID: 0}).Error)
	now := time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC)
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }}
	return c, db
}

// mkBlastSecret inserts a secret into environment 1, project 1.
func mkBlastSecret(t *testing.T, db *gorm.DB, name string, opts ...func(*models.SecretNode)) uint {
	t.Helper()
	s := &models.SecretNode{
		ProjectID:     1,
		EnvironmentID: 1,
		Name:          name,
		IsSecret:      true,
		Status:        "active",
	}
	for _, o := range opts {
		o(s)
	}
	require.NoError(t, db.Create(s).Error)
	return s.ID
}

func withOwner(ownerID uint) func(*models.SecretNode) {
	return func(s *models.SecretNode) { s.OwnerID = ownerID }
}

func withClassification(c string) func(*models.SecretNode) {
	return func(s *models.SecretNode) { s.Classification = c }
}

// mkBlastDep adds a dependency edge: dependent depends on dependsOn.
func mkBlastDep(t *testing.T, db *gorm.DB, dependent, dependsOn uint) {
	t.Helper()
	require.NoError(t, db.Create(&models.SecretDependency{
		ProjectID:         1,
		DependentSecretID: dependent,
		DependsOnSecretID: dependsOn,
	}).Error)
}

func TestGetBlastRadius_SourceNotFound(t *testing.T) {
	t.Parallel()
	c, _ := newBlastRadiusCore(t)
	_, err := c.GetBlastRadius(context.Background(), ActorTypeUser, blastRadiusTestActor, 99999)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestGetBlastRadius_NoDependents(t *testing.T) {
	t.Parallel()
	c, db := newBlastRadiusCore(t)
	srcID := mkBlastSecret(t, db, "standalone")
	report, err := c.GetBlastRadius(context.Background(), ActorTypeUser, blastRadiusTestActor, srcID)
	require.NoError(t, err)
	assert.Equal(t, srcID, report.SourceSecretID)
	assert.Equal(t, "standalone", report.SourceSecretName)
	assert.Empty(t, report.Dependents)
	assert.Equal(t, 0, report.TotalImpact)
	assert.Equal(t, 0, report.MaxDepth)
}

func TestGetBlastRadius_OneDirectDependent(t *testing.T) {
	t.Parallel()
	c, db := newBlastRadiusCore(t)
	srcID := mkBlastSecret(t, db, "db-password", withOwner(10))
	depID := mkBlastSecret(t, db, "app-token", withOwner(20))
	mkBlastDep(t, db, depID, srcID) // app-token depends on db-password

	report, err := c.GetBlastRadius(context.Background(), ActorTypeUser, blastRadiusTestActor, srcID)
	require.NoError(t, err)
	assert.Equal(t, 1, report.TotalImpact)
	assert.Equal(t, 1, report.MaxDepth)
	require.Len(t, report.Dependents, 1)
	assert.Equal(t, depID, report.Dependents[0].SecretID)
	assert.Equal(t, "app-token", report.Dependents[0].SecretName)
	assert.Equal(t, uint(20), report.Dependents[0].OwnerID)
	assert.Equal(t, uint(1), report.Dependents[0].ProjectID)
	assert.Equal(t, 1, report.Dependents[0].Depth)
	assert.Equal(t, "high", report.Dependents[0].RiskLevel) // depth=1, no restricted labels
}

func TestGetBlastRadius_TransitiveDependents(t *testing.T) {
	t.Parallel()
	// A→B→C: rotating A affects B (depth=1) and C (depth=2).
	c, db := newBlastRadiusCore(t)
	a := mkBlastSecret(t, db, "A")
	b := mkBlastSecret(t, db, "B")
	cc := mkBlastSecret(t, db, "C")
	mkBlastDep(t, db, b, a)  // B depends on A
	mkBlastDep(t, db, cc, b) // C depends on B

	report, err := c.GetBlastRadius(context.Background(), ActorTypeUser, blastRadiusTestActor, a)
	require.NoError(t, err)
	assert.Equal(t, 2, report.TotalImpact)
	assert.Equal(t, 2, report.MaxDepth)
	require.Len(t, report.Dependents, 2)
	// First node is B (depth=1), second is C (depth=2).
	assert.Equal(t, b, report.Dependents[0].SecretID)
	assert.Equal(t, 1, report.Dependents[0].Depth)
	assert.Equal(t, "high", report.Dependents[0].RiskLevel) // depth=1

	assert.Equal(t, cc, report.Dependents[1].SecretID)
	assert.Equal(t, 2, report.Dependents[1].Depth)
	assert.Equal(t, "medium", report.Dependents[1].RiskLevel) // depth=2, no labels
}

func TestGetBlastRadius_CycleDetection(t *testing.T) {
	t.Parallel()
	// Hand-forge a cycle A→B, B→A in storage (bypassing the add-time guard).
	// GetBlastRadius must terminate and visit each node only once.
	c, db := newBlastRadiusCore(t)
	a := mkBlastSecret(t, db, "A")
	b := mkBlastSecret(t, db, "B")
	require.NoError(t, db.Create(&models.SecretDependency{
		ProjectID: 1, DependentSecretID: b, DependsOnSecretID: a,
	}).Error)
	require.NoError(t, db.Create(&models.SecretDependency{
		ProjectID: 1, DependentSecretID: a, DependsOnSecretID: b,
	}).Error)

	// Starting from A: B is a direct dependent (depth=1).
	// From B, A is a dependent, but A is already visited → stop.
	report, err := c.GetBlastRadius(context.Background(), ActorTypeUser, blastRadiusTestActor, a)
	require.NoError(t, err)
	assert.Equal(t, 1, report.TotalImpact) // only B, not A again
	assert.Equal(t, b, report.Dependents[0].SecretID)
}

func TestGetBlastRadius_MaxDepthRespected(t *testing.T) {
	t.Parallel()
	// Build a chain of 12 nodes; the BFS must stop at depth=10.
	c, db := newBlastRadiusCore(t)
	prev := mkBlastSecret(t, db, "root")
	for range 12 {
		next := mkBlastSecret(t, db, "link")
		mkBlastDep(t, db, next, prev)
		prev = next
	}

	report, err := c.GetBlastRadius(context.Background(), ActorTypeUser, blastRadiusTestActor, 1)
	require.NoError(t, err)
	assert.LessOrEqual(t, report.MaxDepth, 10,
		"BFS must not exceed maxDepth=10, got %d", report.MaxDepth)
	// #G24: hitting the depth ceiling with dependents still beyond it must be
	// flagged — a capped result must never be silently reported as complete.
	assert.True(t, report.Truncated, "depth-capped report must set Truncated")
}

// TestGetBlastRadius_NotTruncatedWhenWithinDepth is the #G24 counterpart: a
// chain shorter than maxDepth must NOT be flagged as truncated.
func TestGetBlastRadius_NotTruncatedWhenWithinDepth(t *testing.T) {
	t.Parallel()
	c, db := newBlastRadiusCore(t)
	prev := mkBlastSecret(t, db, "root")
	for range 3 {
		next := mkBlastSecret(t, db, "link")
		mkBlastDep(t, db, next, prev)
		prev = next
	}

	report, err := c.GetBlastRadius(context.Background(), ActorTypeUser, blastRadiusTestActor, 1)
	require.NoError(t, err)
	assert.False(t, report.Truncated)
}

func TestGetBlastRadius_RiskLevelCritical(t *testing.T) {
	t.Parallel()
	// Source is "restricted": a direct dependent must be "critical".
	c, db := newBlastRadiusCore(t)
	srcID := mkBlastSecret(t, db, "restricted-secret", withClassification("restricted"))
	depID := mkBlastSecret(t, db, "dep-secret")
	mkBlastDep(t, db, depID, srcID)

	report, err := c.GetBlastRadius(context.Background(), ActorTypeUser, blastRadiusTestActor, srcID)
	require.NoError(t, err)
	require.Len(t, report.Dependents, 1)
	assert.Equal(t, "critical", report.Dependents[0].RiskLevel)
}

func TestGetBlastRadius_RiskLevelDepClassification(t *testing.T) {
	t.Parallel()
	// Dependent is "restricted": even at depth=1 it must be "critical".
	c, db := newBlastRadiusCore(t)
	srcID := mkBlastSecret(t, db, "plain-secret")
	depID := mkBlastSecret(t, db, "restricted-dep", withClassification("restricted"))
	mkBlastDep(t, db, depID, srcID)

	report, err := c.GetBlastRadius(context.Background(), ActorTypeUser, blastRadiusTestActor, srcID)
	require.NoError(t, err)
	require.Len(t, report.Dependents, 1)
	assert.Equal(t, "critical", report.Dependents[0].RiskLevel)
}

func TestGetBlastRadius_RiskLevelHighFromDeepConfidential(t *testing.T) {
	t.Parallel()
	// Source is "confidential" but dependent is at depth=2 → "high"
	// (because isHighSensitivity(sourceClass) is true).
	c, db := newBlastRadiusCore(t)
	srcID := mkBlastSecret(t, db, "confidential-src", withClassification("confidential"))
	midID := mkBlastSecret(t, db, "mid")
	leafID := mkBlastSecret(t, db, "leaf")
	mkBlastDep(t, db, midID, srcID)  // depth=1
	mkBlastDep(t, db, leafID, midID) // depth=2

	report, err := c.GetBlastRadius(context.Background(), ActorTypeUser, blastRadiusTestActor, srcID)
	require.NoError(t, err)
	require.Len(t, report.Dependents, 2)
	// depth=1 node → high (from depth=1 rule, not critical since src is confidential not restricted)
	assert.Equal(t, "high", report.Dependents[0].RiskLevel)
	// depth=2 node → high (because source is confidential)
	assert.Equal(t, "high", report.Dependents[1].RiskLevel)
}

func TestGetBlastRadius_RiskLevelLow(t *testing.T) {
	t.Parallel()
	// A chain of 3 hops with no labels: the third node is "low".
	c, db := newBlastRadiusCore(t)
	a := mkBlastSecret(t, db, "A")
	b := mkBlastSecret(t, db, "B")
	cc := mkBlastSecret(t, db, "C")
	d := mkBlastSecret(t, db, "D")
	mkBlastDep(t, db, b, a)
	mkBlastDep(t, db, cc, b)
	mkBlastDep(t, db, d, cc)

	report, err := c.GetBlastRadius(context.Background(), ActorTypeUser, blastRadiusTestActor, a)
	require.NoError(t, err)
	require.Len(t, report.Dependents, 3)
	assert.Equal(t, "low", report.Dependents[2].RiskLevel) // depth=3
}

func TestGetBlastRadius_SameDeptSortedByID(t *testing.T) {
	t.Parallel()
	// A has two direct dependents B and C (both at depth=1).
	// They must be sorted by ID when depths are equal, exercising the
	// ID-fallback branch in the sort.Slice comparator.
	c, db := newBlastRadiusCore(t)
	aID := mkBlastSecret(t, db, "A")
	bID := mkBlastSecret(t, db, "B")
	cID := mkBlastSecret(t, db, "C")
	mkBlastDep(t, db, bID, aID) // B depends on A (depth=1)
	mkBlastDep(t, db, cID, aID) // C depends on A (depth=1)

	report, err := c.GetBlastRadius(context.Background(), ActorTypeUser, blastRadiusTestActor, aID)
	require.NoError(t, err)
	assert.Equal(t, 2, report.TotalImpact)
	assert.Equal(t, 1, report.MaxDepth)
	// Both at depth=1; sorted by ID ascending means B before C.
	assert.Equal(t, bID, report.Dependents[0].SecretID)
	assert.Equal(t, cID, report.Dependents[1].SecretID)
}

// ── mock-storage tests for error propagation ──────────────────────────────────

func newMockBlastCore(t *testing.T) (*KeyorixCore, *MockStorage) {
	t.Helper()
	ms := new(MockStorage)
	c := &KeyorixCore{storage: ms, now: func() time.Time { return time.Now() }}
	return c, ms
}

func TestGetBlastRadius_StorageErrorOnListDependencies(t *testing.T) {
	t.Parallel()
	c, ms := newMockBlastCore(t)
	src := &models.SecretNode{ID: 1, ProjectID: 1, EnvironmentID: 1, Name: "src", IsSecret: true}
	ms.On("GetSecret", mock.Anything, uint(1)).Return(src, nil)
	ms.On("ListSecretDependenciesForProject", mock.Anything, uint(1)).
		Return(nil, errors.New("db error"))

	_, err := c.GetBlastRadius(context.Background(), ActorTypeUser, blastRadiusTestActor, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "db error")
}

func TestGetBlastRadius_SourceIsFolder_Rejected(t *testing.T) {
	t.Parallel()
	c, ms := newMockBlastCore(t)
	folder := &models.SecretNode{ID: 5, ProjectID: 1, EnvironmentID: 1, Name: "folder", IsSecret: false}
	ms.On("GetSecret", mock.Anything, uint(5)).Return(folder, nil)

	_, err := c.GetBlastRadius(context.Background(), ActorTypeUser, blastRadiusTestActor, 5)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a secret")
}

func TestGetBlastRadius_SkipsSoftDeletedDependent(t *testing.T) {
	t.Parallel()
	// The BFS finds a dependent in the edge list but GetSecret returns an error
	// (simulating a soft-deleted dependent). The node should be silently skipped
	// and not appear in the report.
	c, ms := newMockBlastCore(t)
	src := &models.SecretNode{ID: 1, ProjectID: 1, EnvironmentID: 1, Name: "src", IsSecret: true}
	dep := &models.SecretNode{ID: 2, ProjectID: 1, EnvironmentID: 1, Name: "dep", IsSecret: true}

	edges := []*models.SecretDependency{
		{DependentSecretID: 2, DependsOnSecretID: 1, ProjectID: 1},
	}

	ms.On("GetSecret", mock.Anything, uint(1)).Return(src, nil)
	ms.On("ListSecretDependenciesForProject", mock.Anything, uint(1)).Return(edges, nil)
	// resolveSecretInfo calls GetSecret for each endpoint
	ms.On("GetSecret", mock.Anything, uint(2)).Return(dep, nil).Once()
	// Then during the BFS result phase, GetSecret is called again and returns not-found
	ms.On("GetSecret", mock.Anything, uint(2)).Return(nil, errors.New("not found"))

	report, err := c.GetBlastRadius(context.Background(), ActorTypeUser, blastRadiusTestActor, 1)
	require.NoError(t, err)
	assert.Empty(t, report.Dependents)
	assert.Equal(t, 0, report.TotalImpact)
}
