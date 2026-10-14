package core

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func TestDeploymentSecretNameConformance(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.SecretVersion{}, &models.Project{}, &models.Environment{},
	))

	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	ctx := context.Background()
	now := time.Now()

	// Two projects; each gets one conforming and one non-conforming name, created
	// directly via storage (i.e. before any policy existed).
	mkProject := func(name string, secretNames ...string) {
		p, err := c.storage.CreateProject(ctx, &models.Project{Name: name})
		require.NoError(t, err)
		e, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p.ID})
		require.NoError(t, err)
		for _, sn := range secretNames {
			_, err = c.storage.CreateSecret(ctx, &models.SecretNode{
				Name: sn, ProjectID: p.ID, EnvironmentID: e.ID, Type: "password", OwnerID: 1,
				IsSecret: true, CreatedAt: now, UpdatedAt: now,
			})
			require.NoError(t, err)
		}
	}
	mkProject("alpha", "DB_PASSWORD", "alpha-key") // alpha-key violates
	mkProject("beta", "API_TOKEN", "beta key")     // "beta key" violates (space)

	t.Run("no policy → enabled false, scan skipped, no violations", func(t *testing.T) {
		require.NoError(t, c.SetSecretNamePolicy(SecretNamePolicy{}))
		rep, err := c.DeploymentSecretNameConformance(ctx)
		require.NoError(t, err)
		assert.False(t, rep.PolicyEnabled)
		assert.Empty(t, rep.Violations)
		assert.Zero(t, rep.TotalSecrets)
	})

	t.Run("aggregates violations across all projects, each tagged with its project", func(t *testing.T) {
		require.NoError(t, c.SetSecretNamePolicy(SecretNamePolicy{Enabled: true, Pattern: "^[A-Z][A-Z0-9_]*$"}))
		rep, err := c.DeploymentSecretNameConformance(ctx)
		require.NoError(t, err)
		assert.True(t, rep.PolicyEnabled)
		assert.Equal(t, 4, rep.TotalSecrets, "two projects × two secrets")
		require.Len(t, rep.Violations, 2)

		byName := map[string]DeploymentSecretNameViolation{}
		for _, v := range rep.Violations {
			byName[v.Name] = v
		}
		require.Contains(t, byName, "alpha-key")
		assert.Equal(t, "alpha", byName["alpha-key"].ProjectName)
		require.Contains(t, byName, "beta key")
		assert.Equal(t, "beta", byName["beta key"].ProjectName)
		assert.Contains(t, byName["beta key"].Reason, "pattern")
	})

	t.Run("when every name conforms, no violations but total counted", func(t *testing.T) {
		require.NoError(t, c.SetSecretNamePolicy(SecretNamePolicy{Enabled: true, Pattern: "^[A-Za-z0-9_ -]+$"}))
		rep, err := c.DeploymentSecretNameConformance(ctx)
		require.NoError(t, err)
		assert.Equal(t, 4, rep.TotalSecrets)
		assert.Empty(t, rep.Violations)
	})
}

// #416: DeploymentSecretNameConformance used to call SecretNameConformance once PER
// PROJECT — a full ListSecrets query per project, repeated for every project in the
// deployment, with no bound on project count. That made the endpoint's query count
// (and so its latency/DB load) grow linearly, unboundedly, with the number of
// projects in the deployment — reachable well below system_admin, the same
// N+1/unbounded fan-out family as #238/#393. Every project's live secret names are
// now fetched in a single bounded query (ListLiveSecretNamesByProject) and checked
// against the naming policy in memory. This proves the query count issued by a
// single call is the SAME whether the deployment has 5 or 50 projects — a query
// COUNT assertion (attachTotalQueryCounter, defined in deployment_hygiene_test.go),
// not a timing one, so it can't flake under load.
func TestDeploymentSecretNameConformance_QueryCostDoesNotScaleWithProjectCount(t *testing.T) {
	t.Parallel()
	runWithNProjects := func(n int) int {
		require.NoError(t, i18n.InitializeForTesting())
		db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
		require.NoError(t, err)
		sqlDB, _ := db.DB()
		sqlDB.SetMaxOpenConns(1)
		require.NoError(t, db.AutoMigrate(
			&models.SecretNode{}, &models.SecretVersion{}, &models.Project{}, &models.Environment{},
		))

		c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
		ctx := context.Background()
		now := time.Now()
		require.NoError(t, c.SetSecretNamePolicy(SecretNamePolicy{Enabled: true, Pattern: "^[A-Z][A-Z0-9_]*$"}))

		for i := range n {
			p, err := c.storage.CreateProject(ctx, &models.Project{Name: fmt.Sprintf("p%d", i)})
			require.NoError(t, err)
			e, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p.ID})
			require.NoError(t, err)
			// One conforming and one violating name per project, so the breakdown is
			// non-trivial — the QUERY COUNT must stay flat regardless of how many
			// projects (or how many carry violations) exist.
			_, err = c.storage.CreateSecret(ctx, &models.SecretNode{
				Name: "DB_PASSWORD", ProjectID: p.ID, EnvironmentID: e.ID, Type: "password", OwnerID: 1,
				IsSecret: true, CreatedAt: now, UpdatedAt: now,
			})
			require.NoError(t, err)
			_, err = c.storage.CreateSecret(ctx, &models.SecretNode{
				Name: fmt.Sprintf("bad-key-%d", i), ProjectID: p.ID, EnvironmentID: e.ID, Type: "password", OwnerID: 1,
				IsSecret: true, CreatedAt: now, UpdatedAt: now,
			})
			require.NoError(t, err)
		}

		qc := attachTotalQueryCounter(t, db)
		rep, err := c.DeploymentSecretNameConformance(ctx)
		require.NoError(t, err)
		assert.Equal(t, 2*n, rep.TotalSecrets)
		assert.Len(t, rep.Violations, n)
		assert.False(t, rep.Truncated)
		return qc.total
	}

	small := runWithNProjects(5)
	large := runWithNProjects(50)

	assert.Equal(t, small, large,
		"DeploymentSecretNameConformance's query count must not scale with the number of projects in the deployment")
	assert.Less(t, small, 10,
		"expected a small constant number of queries (list projects + one bounded secret-name scan), not one set of queries per project")
}
