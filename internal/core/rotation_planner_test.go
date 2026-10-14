package core

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// --- pure helpers ---

func TestRotationUrgency(t *testing.T) {
	t.Parallel()
	// Overdue always outranks due-soon, regardless of risk.
	overdue := rotationUrgency(RotationStatusOverdue, 0, 0)
	dueSoon := rotationUrgency(RotationStatusDueSoon, -1, 100)
	assert.Greater(t, overdue, dueSoon, "any overdue beats any due-soon")

	// Within overdue, more days past due and higher risk raise the score.
	assert.Greater(t, rotationUrgency(RotationStatusOverdue, 30, 50), rotationUrgency(RotationStatusOverdue, 5, 50))
	assert.Greater(t, rotationUrgency(RotationStatusOverdue, 10, 80), rotationUrgency(RotationStatusOverdue, 10, 10))

	// Within due-soon, closer to due (less negative) ranks higher.
	assert.Greater(t, rotationUrgency(RotationStatusDueSoon, -2, 0), rotationUrgency(RotationStatusDueSoon, -10, 0))

	// The overdue cap prevents one ancient secret from dwarfing everything.
	assert.Equal(t, rotationUrgency(RotationStatusOverdue, 9999, 0), rotationUrgency(RotationStatusOverdue, 365, 0))
}

func TestMoreUrgentEntry(t *testing.T) {
	t.Parallel()
	od := &RotationStatusEntry{Status: RotationStatusOverdue, DaysOverdue: 5}
	ds := &RotationStatusEntry{Status: RotationStatusDueSoon, DaysOverdue: -2}
	assert.True(t, moreUrgentEntry(od, ds))
	assert.False(t, moreUrgentEntry(ds, od))
	assert.True(t, moreUrgentEntry(
		&RotationStatusEntry{Status: RotationStatusOverdue, DaysOverdue: 40},
		&RotationStatusEntry{Status: RotationStatusOverdue, DaysOverdue: 10},
	))
}

func TestRotationWaves(t *testing.T) {
	t.Parallel()
	// 1 depends on 2; 3 stands alone. Wave 0 = {2,3}, wave 1 = {1}.
	edges := []*models.SecretDependency{edge(1, 2)}
	candidates := map[uint]bool{1: true, 2: true, 3: true}
	waves, ok := rotationWaves(edges, candidates)
	require.True(t, ok)
	require.Len(t, waves, 2)
	assert.Equal(t, []uint{2, 3}, waves[0], "no-dependency candidates rotate first")
	assert.Equal(t, []uint{1}, waves[1], "the dependent rotates after its dependency")
}

func TestRotationWavesIgnoresNonCandidateEdges(t *testing.T) {
	t.Parallel()
	// 1 depends on 2, but 2 is not in the plan → 1 has no in-plan dependency.
	edges := []*models.SecretDependency{edge(1, 2)}
	candidates := map[uint]bool{1: true}
	waves, ok := rotationWaves(edges, candidates)
	require.True(t, ok)
	require.Len(t, waves, 1)
	assert.Equal(t, []uint{1}, waves[0])
}

func TestRotationWavesDetectsCycle(t *testing.T) {
	t.Parallel()
	edges := []*models.SecretDependency{edge(1, 2), edge(2, 1)}
	_, ok := rotationWaves(edges, map[uint]bool{1: true, 2: true})
	assert.False(t, ok)
}

// --- integration against a real in-memory store ---

// plannerTestActor is granted global admin below so #G32's independent peer-secret
// authorization check doesn't interfere with these tests, which are about rotation-plan
// waving/ordering, not authorization.
const plannerTestActor = uint(1)

func newPlannerCore(t *testing.T, now time.Time) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Project{}, &models.Environment{}, &models.SecretNode{}, &models.RotationPolicy{},
		&models.SecretDependency{}, &models.ShareRecord{}, &models.SecretAccessLog{}, &models.AuditEvent{},
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Permission{}, &models.RolePermission{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{}, &models.MachineIdentityRole{}, &models.SecretACL{},
	))
	role := &models.Role{Name: "admin", BypassesPermissionChecks: true}
	require.NoError(t, db.Create(role).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: plannerTestActor, RoleID: role.ID, ProjectID: 0, EnvironmentID: 0}).Error)
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }}
	return c, db
}

func TestGenerateRotationPlan(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	c, db := newPlannerCore(t, now)
	projectID := uint(1)
	daysAgo := func(d int) *time.Time { tt := now.Add(-time.Duration(d) * 24 * time.Hour); return &tt }

	require.NoError(t, db.Create(&models.Project{ID: projectID, Name: "prod"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: projectID, Name: "production"}).Error)
	require.NoError(t, db.Create(&models.RotationPolicy{
		Name: "90-day", Scope: "project", ProjectID: &projectID, IntervalDays: 90, AlertDaysBefore: 14, IsActive: true,
	}).Error)

	mk := func(id uint, name string, last *time.Time) {
		require.NoError(t, db.Create(&models.SecretNode{
			ID: id, Name: name, ProjectID: projectID, EnvironmentID: 1, IsSecret: true, Status: "active",
			OwnerID: 1, LastRotatedAt: last,
		}).Error)
	}
	mk(1, "overdue-app", daysAgo(120)) // 30 days overdue
	mk(2, "overdue-db", daysAgo(200))  // 110 days overdue (more urgent)
	mk(3, "due-soon-key", daysAgo(80)) // 10 days remaining → due_soon
	mk(4, "healthy-key", daysAgo(5))   // ok → excluded from the plan

	// overdue-app depends on overdue-db → it must rotate in a later wave.
	_, err := c.AddSecretDependency(ctx, ActorTypeUser, plannerTestActor, 1, 2, "app token derives from db password", 0)
	require.NoError(t, err)

	plan, err := c.GenerateRotationPlan(ctx, projectID)
	require.NoError(t, err)

	assert.Equal(t, 3, plan.TotalSecrets)
	assert.Equal(t, 2, plan.OverdueCount)
	assert.Equal(t, 1, plan.DueSoonCount)
	require.Len(t, plan.Waves, 2, "the dependency forces a second wave")

	// Wave 0: overdue-db (dependency, most urgent) before due-soon-key; overdue-app is NOT here.
	w0 := plan.Waves[0].Secrets
	require.Len(t, w0, 2)
	assert.Equal(t, "overdue-db", w0[0].SecretName)
	assert.Equal(t, "due-soon-key", w0[1].SecretName)
	assert.Greater(t, w0[0].Urgency, w0[1].Urgency)

	// Wave 1: overdue-app, which must follow overdue-db.
	w1 := plan.Waves[1].Secrets
	require.Len(t, w1, 1)
	assert.Equal(t, "overdue-app", w1[0].SecretName)
	assert.Equal(t, []uint{2}, w1[0].AfterSecretIDs)

	// Rationale is present and specific.
	assert.Contains(t, joinReasons(w1[0].Reasons), "30 days overdue")
	assert.Contains(t, joinReasons(w1[0].Reasons), "rotate after overdue-db")
	assert.Contains(t, joinReasons(w0[1].Reasons), "due in 10 days")
}

func TestGenerateRotationPlanEmptyWhenNothingDue(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	c, db := newPlannerCore(t, now)
	projectID := uint(1)
	require.NoError(t, db.Create(&models.RotationPolicy{
		Name: "90-day", Scope: "project", ProjectID: &projectID, IntervalDays: 90, AlertDaysBefore: 14, IsActive: true,
	}).Error)
	tt := now.Add(-5 * 24 * time.Hour)
	require.NoError(t, db.Create(&models.SecretNode{ID: 1, Name: "healthy", ProjectID: projectID, EnvironmentID: 1, IsSecret: true, Status: "active", OwnerID: 1, LastRotatedAt: &tt}).Error)

	plan, err := c.GenerateRotationPlan(ctx, projectID)
	require.NoError(t, err)
	assert.Equal(t, 0, plan.TotalSecrets)
	assert.Empty(t, plan.Waves)
}

// #486: a genuine failure to compute the risk score (ComputeSecretRiskScore
// returning an error, not just a Degraded=true result) must not silently read
// as a fully-resolved zero-risk secret — that would under-rank an actually
// risky overdue secret in rotationUrgency's intra-wave ordering, and the API
// response's RiskDegraded:false would give callers no hint anything failed.
func TestPlanSecretRiskScoreErrorDegrades(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	c, _ := newPlannerCore(t, now)

	// This secret ID has no entry in the batch risk-score result (e.g. its
	// underlying secret row is gone by the time ComputeSecretRiskScoresBatch ran).
	e := &RotationStatusEntry{
		SecretID:    999,
		SecretName:  "ghost-secret",
		Status:      RotationStatusOverdue,
		DaysOverdue: 10,
	}

	pr := c.planSecret(e, nil, map[uint]*RotationStatusEntry{}, map[uint]*SecretRiskScore{}, nil)

	assert.True(t, pr.RiskDegraded, "a risk-score computation error must degrade the plan entry, not silently zero it")
	assert.Equal(t, 0, pr.RiskScore, "an errored risk score is a floor of 0, not an inflated guess")
	assert.Empty(t, pr.RiskBand)
	assert.Contains(t, joinReasons(pr.Reasons), "risk score", "the reason must surface that the risk score itself could not be computed")
}

// A genuine batch-wide risk-score computation failure (riskErr != nil, e.g. the
// batched secret lookup itself errored) must degrade the entry the same way a
// missing-from-result secret does (#486, #409).
func TestPlanSecretRiskScoreBatchErrorDegrades(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	c, _ := newPlannerCore(t, now)

	e := &RotationStatusEntry{
		SecretID:    1,
		SecretName:  "some-secret",
		Status:      RotationStatusOverdue,
		DaysOverdue: 10,
	}

	pr := c.planSecret(e, nil, map[uint]*RotationStatusEntry{}, nil, errors.New("batch lookup failed"))

	assert.True(t, pr.RiskDegraded)
	assert.Equal(t, 0, pr.RiskScore)
	assert.Empty(t, pr.RiskBand)
	assert.Contains(t, joinReasons(pr.Reasons), "risk score")
}

func joinReasons(rs []string) string {
	out := ""
	for _, r := range rs {
		out += r + " | "
	}
	return out
}

func TestGenerateDeploymentRotationPlan(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	c, db := newPlannerCore(t, now)
	daysAgo := func(d int) *time.Time { tt := now.Add(-time.Duration(d) * 24 * time.Hour); return &tt }

	mkProject := func(id uint, name string) {
		require.NoError(t, db.Create(&models.Project{ID: id, Name: name}).Error)
		require.NoError(t, db.Create(&models.Environment{ID: id, ProjectID: id, Name: name + "-env"}).Error)
		pid := id
		require.NoError(t, db.Create(&models.RotationPolicy{
			Name: name + "-90d", Scope: "project", ProjectID: &pid, IntervalDays: 90, AlertDaysBefore: 14, IsActive: true,
		}).Error)
	}
	mkSecret := func(id, projID, envID uint, name string, last *time.Time) {
		require.NoError(t, db.Create(&models.SecretNode{
			ID: id, Name: name, ProjectID: projID, EnvironmentID: envID, IsSecret: true, Status: "active",
			OwnerID: 1, LastRotatedAt: last,
		}).Error)
	}

	mkProject(1, "prod")
	mkSecret(1, 1, 1, "prod-db", daysAgo(200))  // 110 days overdue
	mkSecret(2, 1, 1, "prod-app", daysAgo(120)) // 30 days overdue

	mkProject(2, "staging")
	mkSecret(3, 2, 2, "stg-key", daysAgo(80)) // 10 days remaining → due_soon

	mkProject(3, "sandbox")
	mkSecret(4, 3, 3, "sbx-healthy", daysAgo(5)) // ok → no work

	dp, err := c.GenerateDeploymentRotationPlan(ctx)
	require.NoError(t, err)

	assert.Equal(t, 3, dp.ProjectsScanned)
	assert.Equal(t, 2, dp.ProjectsWithWork, "sandbox has nothing due → excluded from the list")
	assert.Equal(t, 3, dp.TotalSecrets, "2 in prod + 1 in staging")
	assert.Equal(t, 2, dp.OverdueCount)
	assert.Equal(t, 1, dp.DueSoonCount)

	// Only projects with work are listed, most-overdue first: prod (2 overdue) before staging (0).
	require.Len(t, dp.Projects, 2)
	assert.Equal(t, uint(1), dp.Projects[0].ProjectID)
	assert.Equal(t, 2, dp.Projects[0].OverdueCount)
	assert.Equal(t, uint(2), dp.Projects[1].ProjectID)
	assert.Equal(t, 0, dp.Projects[1].OverdueCount)
	assert.Equal(t, 1, dp.Projects[1].DueSoonCount)
}

// A cyclic dependency graph in ONE project (which the add path normally rejects,
// ADR-052, but can slip past a racing AddSecretDependency call, #260) must not 500
// the whole deployment-wide roll-up for every other project's viewers: it is
// skipped and flagged in BrokenProjects, while every other project's plan still
// comes back normally.
func TestGenerateDeploymentRotationPlan_CyclicProjectIsSkippedNotFatal(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	c, db := newPlannerCore(t, now)
	daysAgo := func(d int) *time.Time { tt := now.Add(-time.Duration(d) * 24 * time.Hour); return &tt }

	mkProject := func(id uint, name string) {
		require.NoError(t, db.Create(&models.Project{ID: id, Name: name}).Error)
		require.NoError(t, db.Create(&models.Environment{ID: id, ProjectID: id, Name: name + "-env"}).Error)
		pid := id
		require.NoError(t, db.Create(&models.RotationPolicy{
			Name: name + "-90d", Scope: "project", ProjectID: &pid, IntervalDays: 90, AlertDaysBefore: 14, IsActive: true,
		}).Error)
	}
	mkSecret := func(id, projID, envID uint, name string, last *time.Time) {
		require.NoError(t, db.Create(&models.SecretNode{
			ID: id, Name: name, ProjectID: projID, EnvironmentID: envID, IsSecret: true, Status: "active",
			OwnerID: 1, LastRotatedAt: last,
		}).Error)
	}

	// Project 1 (broken): two overdue secrets with a cyclic edge inserted directly,
	// bypassing AddSecretDependency's normal cycle guard — simulating #260's raced
	// cycle.
	mkProject(1, "broken")
	mkSecret(1, 1, 1, "broken-a", daysAgo(120))
	mkSecret(2, 1, 1, "broken-b", daysAgo(200))
	require.NoError(t, db.Create(&models.SecretDependency{ProjectID: 1, DependentSecretID: 1, DependsOnSecretID: 2}).Error)
	require.NoError(t, db.Create(&models.SecretDependency{ProjectID: 1, DependentSecretID: 2, DependsOnSecretID: 1}).Error)

	// Project 2 (healthy): one overdue secret, no dependency graph issues.
	mkProject(2, "healthy")
	mkSecret(3, 2, 2, "healthy-overdue", daysAgo(150))

	dp, err := c.GenerateDeploymentRotationPlan(ctx)
	require.NoError(t, err, "one project's cycle must not fail the whole deployment-wide roll-up")

	assert.Equal(t, 2, dp.ProjectsScanned)
	require.Len(t, dp.BrokenProjects, 1, "the cyclic project is flagged, not silently dropped")
	assert.Equal(t, uint(1), dp.BrokenProjects[0].ProjectID)
	assert.Contains(t, dp.BrokenProjects[0].Error, "cycle")

	// The healthy project's plan is still present and correct — the deployment view
	// is not entirely blank just because one project is broken.
	assert.Equal(t, 1, dp.ProjectsWithWork)
	assert.Equal(t, 1, dp.TotalSecrets)
	assert.Equal(t, 1, dp.OverdueCount)
	require.Len(t, dp.Projects, 1)
	assert.Equal(t, uint(2), dp.Projects[0].ProjectID)
}

// #409: GenerateDeploymentRotationPlan (via GenerateRotationPlan → planSecret) used
// to call ComputeSecretRiskScore fresh — with its own several queries — once per
// candidate secret, per project: an O(projects × candidates × groups-per-secret)
// unbounded fan-out on a single request. ComputeSecretRiskScoresBatch now fetches
// every input (secrets, read counts, shares, group memberships) once PER PROJECT
// via batched (GROUP BY / IN) queries, so a project's risk-scoring query count no
// longer grows with its candidate-secret count. This proves the total query count
// issued by a single GenerateDeploymentRotationPlan call is the SAME whether each of
// a fixed number of projects has 5 or 50 always-overdue candidate secrets — mixing
// direct-user and group shares, so both ListSharesBySecretIDs and
// ListGroupMembersByGroupIDs are actually exercised — a query COUNT assertion, not a
// timing one, so it can't flake under load.
func TestGenerateDeploymentRotationPlan_RiskScoringQueryCostDoesNotScaleWithCandidateCount(t *testing.T) {
	t.Parallel()
	const numProjects = 3

	runWithCandidatesPerProject := func(perProject int) int {
		now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
		db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
		require.NoError(t, err)
		sqlDB, _ := db.DB()
		sqlDB.SetMaxOpenConns(1)
		require.NoError(t, db.AutoMigrate(
			&models.Project{}, &models.Environment{}, &models.SecretNode{}, &models.RotationPolicy{},
			&models.SecretDependency{}, &models.ShareRecord{}, &models.SecretAccessLog{}, &models.AuditEvent{},
			&models.User{}, &models.Group{}, &models.UserGroup{},
		))
		c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }}
		ctx := context.Background()

		require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "owner@t.com"}).Error)
		require.NoError(t, db.Create(&models.User{ID: 2, Username: "direct-recipient", Email: "d@t.com"}).Error)
		require.NoError(t, db.Create(&models.User{ID: 3, Username: "group-member", Email: "g@t.com"}).Error)
		require.NoError(t, db.Create(&models.Group{ID: 1, Name: "team-a"}).Error)
		require.NoError(t, db.Create(&models.UserGroup{UserID: 3, GroupID: 1}).Error)

		overdue := now.Add(-200 * 24 * time.Hour) // well past a 90-day cadence
		secretID := uint(1)
		for p := uint(1); p <= numProjects; p++ {
			require.NoError(t, db.Create(&models.Project{ID: p, Name: fmt.Sprintf("proj-%d", p)}).Error)
			require.NoError(t, db.Create(&models.Environment{ID: p, ProjectID: p, Name: "env"}).Error)
			require.NoError(t, db.Create(&models.RotationPolicy{
				Name: fmt.Sprintf("90d-%d", p), Scope: "project", ProjectID: &p, IntervalDays: 90, AlertDaysBefore: 14, IsActive: true,
			}).Error)
			for i := range perProject {
				require.NoError(t, db.Create(&models.SecretNode{
					ID: secretID, Name: fmt.Sprintf("s-%d", secretID), ProjectID: p, EnvironmentID: p,
					IsSecret: true, Status: "active", OwnerID: 1, LastRotatedAt: &overdue,
				}).Error)
				// Alternate direct-user and group shares so both ListSharesBySecretIDs
				// and ListGroupMembersByGroupIDs are actually exercised, not just the
				// no-shares-at-all path.
				if i%2 == 0 {
					require.NoError(t, db.Create(&models.ShareRecord{SecretID: secretID, OwnerID: 1, RecipientID: 2, IsGroup: false}).Error)
				} else {
					require.NoError(t, db.Create(&models.ShareRecord{SecretID: secretID, OwnerID: 1, RecipientID: 1, IsGroup: true}).Error)
				}
				secretID++
			}
		}

		qc := attachTotalQueryCounter(t, db)
		dp, err := c.GenerateDeploymentRotationPlan(ctx)
		require.NoError(t, err)
		require.Equal(t, numProjects*perProject, dp.TotalSecrets)
		return qc.total
	}

	small := runWithCandidatesPerProject(5)
	large := runWithCandidatesPerProject(50)

	assert.Equal(t, small, large,
		"query count must not scale with the number of candidate secrets per project")
	assert.Less(t, small, 40,
		"expected a small constant number of batched queries per project, not one set of queries per candidate secret")
}

func TestGenerateDeploymentRotationPlan_NothingDueAnywhere(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	c, db := newPlannerCore(t, now)
	healthy := now.Add(-5 * 24 * time.Hour)

	for _, p := range []struct {
		id   uint
		name string
	}{{1, "alpha"}, {2, "beta"}} {
		require.NoError(t, db.Create(&models.Project{ID: p.id, Name: p.name}).Error)
		require.NoError(t, db.Create(&models.Environment{ID: p.id, ProjectID: p.id, Name: p.name + "-env"}).Error)
		pid := p.id
		require.NoError(t, db.Create(&models.RotationPolicy{
			Name: "90d-" + p.name, Scope: "project", ProjectID: &pid, IntervalDays: 90, AlertDaysBefore: 14, IsActive: true,
		}).Error)
		require.NoError(t, db.Create(&models.SecretNode{
			ID: p.id, Name: "healthy-" + p.name, ProjectID: p.id, EnvironmentID: p.id, IsSecret: true, Status: "active", OwnerID: 1, LastRotatedAt: &healthy,
		}).Error)
	}

	dp, err := c.GenerateDeploymentRotationPlan(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, dp.ProjectsScanned)
	assert.Equal(t, 0, dp.ProjectsWithWork)
	assert.Equal(t, 0, dp.TotalSecrets)
	assert.Empty(t, dp.Projects)
}
