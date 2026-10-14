package core

import (
	"context"
	"fmt"
	"sync"
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

func TestDeploymentHygieneSummary(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.SecretVersion{}, &models.User{}, &models.Project{},
		&models.Environment{}, &models.SecretAccessLog{}, &models.MachineIdentity{}, &models.AuditEvent{},
		&models.RotationPolicy{},
	))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "o@t.com"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "leaver", Email: "l@t.com"}).Error)

	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	ctx := context.Background()
	now := time.Now()

	// p1 carries debt: one orphaned secret (owner 2 departs) + one expiring secret.
	p1, err := c.storage.CreateProject(ctx, &models.Project{Name: "p1"})
	require.NoError(t, err)
	e1, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p1.ID})
	require.NoError(t, err)
	soon := now.Add(10 * 24 * time.Hour)
	_, err = c.storage.CreateSecret(ctx, &models.SecretNode{
		Name: "orphan", ProjectID: p1.ID, EnvironmentID: e1.ID, Type: "password", OwnerID: 2,
		IsSecret: true, CreatedAt: now, UpdatedAt: now,
	})
	require.NoError(t, err)
	_, err = c.storage.CreateSecret(ctx, &models.SecretNode{
		Name: "expiring", ProjectID: p1.ID, EnvironmentID: e1.ID, Type: "password", OwnerID: 1,
		IsSecret: true, Expiration: &soon, CreatedAt: now, UpdatedAt: now,
	})
	require.NoError(t, err)
	require.NoError(t, c.storage.DeleteUser(ctx, 2)) // offboard → "orphan" is orphaned

	// p2 is clean: a single secret with a recent read (not unused), live owner, no expiry.
	p2, err := c.storage.CreateProject(ctx, &models.Project{Name: "p2"})
	require.NoError(t, err)
	e2, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p2.ID})
	require.NoError(t, err)
	clean, err := c.storage.CreateSecret(ctx, &models.SecretNode{
		Name: "ok", ProjectID: p2.ID, EnvironmentID: e2.ID, Type: "password", OwnerID: 1,
		IsSecret: true, CreatedAt: now, UpdatedAt: now,
	})
	require.NoError(t, err)
	require.NoError(t, c.storage.CreateSecretAccessLog(ctx, &models.SecretAccessLog{
		SecretNodeID: clean.ID, AccessedBy: "owner", Action: "read", AccessTime: now,
	}))

	t.Run("totals sum across projects; breakdown lists only projects with debt", func(t *testing.T) {
		h, err := c.DeploymentHygieneSummary(ctx, 90, 30, 90)
		require.NoError(t, err)
		assert.Equal(t, 1, h.Totals.OrphanedSecrets)
		assert.Equal(t, 1, h.Totals.ExpiringSecrets)
		assert.Equal(t, 2, h.Totals.UnusedSecrets, "both p1 secrets are unused; p2's was read")

		require.Len(t, h.Projects, 1, "only p1 has outstanding signals")
		assert.Equal(t, p1.ID, h.Projects[0].ProjectID)
		assert.Equal(t, "p1", h.Projects[0].ProjectName)
		assert.Equal(t, 1, h.Projects[0].OrphanedSecrets)
	})

	t.Run("windows default when non-positive", func(t *testing.T) {
		h, err := c.DeploymentHygieneSummary(ctx, 0, 0, 0)
		require.NoError(t, err)
		assert.Equal(t, 1, h.Totals.OrphanedSecrets)
	})
}

// totalQueryCounter tallies every SELECT GORM executes, via the same "gorm:query"
// callback hook GORM itself uses to run queries — a precise, non-flaky substitute
// for a timing-based assertion (mirrors the #238 fix's queryCounter).
type totalQueryCounter struct {
	mu    sync.Mutex
	total int
}

func attachTotalQueryCounter(t *testing.T, db *gorm.DB) *totalQueryCounter {
	qc := &totalQueryCounter{}
	err := db.Callback().Query().After("gorm:query").Register("test:count_total_queries", func(_ *gorm.DB) {
		qc.mu.Lock()
		defer qc.mu.Unlock()
		qc.total++
	})
	require.NoError(t, err)
	return qc
}

// #393: DeploymentHygieneSummary used to call ProjectHygieneSummary once PER
// PROJECT — five separate DB round trips (orphaned/unused/expiring/stale-MI/
// rotation-overdue), repeated for every project in the deployment, with no bound.
// That made the endpoint's query count (and so its latency/DB load) grow linearly,
// unboundedly, with the number of projects in the deployment — reachable well below
// system_admin. Each signal is now computed once, deployment-wide, via a grouped
// query. This proves the query count issued by a single call is the SAME whether
// the deployment has 5 or 60 projects — a query COUNT assertion, not a timing one,
// so it can't flake under load.
func TestDeploymentHygieneSummary_QueryCostDoesNotScaleWithProjectCount(t *testing.T) {
	t.Parallel()
	runWithNProjects := func(n int) int {
		require.NoError(t, i18n.InitializeForTesting())
		db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
		require.NoError(t, err)
		sqlDB, _ := db.DB()
		sqlDB.SetMaxOpenConns(1)
		require.NoError(t, db.AutoMigrate(
			&models.SecretNode{}, &models.SecretVersion{}, &models.User{}, &models.Project{},
			&models.Environment{}, &models.SecretAccessLog{}, &models.MachineIdentity{}, &models.AuditEvent{},
			&models.RotationPolicy{},
		))
		require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "o@t.com"}).Error)
		require.NoError(t, db.Create(&models.User{ID: 2, Username: "leaver", Email: "l@t.com"}).Error)

		c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
		ctx := context.Background()
		now := time.Now()

		for i := range n {
			p, err := c.storage.CreateProject(ctx, &models.Project{Name: fmt.Sprintf("p%d", i)})
			require.NoError(t, err)
			e, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p.ID})
			require.NoError(t, err)
			// Every third project carries debt (orphaned secret + stale machine
			// identity), so the breakdown is non-trivial — the QUERY COUNT must stay
			// flat regardless of how many projects (or how many carry debt) exist.
			ownerID := uint(1)
			if i%3 == 0 {
				ownerID = 2
			}
			_, err = c.storage.CreateSecret(ctx, &models.SecretNode{
				Name: "s", ProjectID: p.ID, EnvironmentID: e.ID, Type: "password", OwnerID: ownerID,
				IsSecret: true, CreatedAt: now, UpdatedAt: now,
			})
			require.NoError(t, err)
			_, err = c.storage.CreateMachineIdentity(ctx, &models.MachineIdentity{
				ProjectID: p.ID, Name: "svc", IdentityType: "service", State: MachineActive,
				CreatedAt: now.Add(-200 * 24 * time.Hour),
			})
			require.NoError(t, err)
		}
		require.NoError(t, c.storage.DeleteUser(ctx, 2)) // offboard → every "%3==0" secret is orphaned

		qc := attachTotalQueryCounter(t, db)
		_, err = c.DeploymentHygieneSummary(ctx, 90, 30, 90)
		require.NoError(t, err)
		return qc.total
	}

	small := runWithNProjects(5)
	large := runWithNProjects(60)

	assert.Equal(t, small, large,
		"DeploymentHygieneSummary's query count must not scale with the number of projects in the deployment")
	assert.Less(t, small, 20,
		"expected a small constant number of grouped/deployment-wide queries, not one set of queries per project")
}
