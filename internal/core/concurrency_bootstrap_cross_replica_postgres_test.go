package core

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConcurrency_BootstrapSystem_CrossReplicaPostgres_ExactlyOneAdmin is the
// genuine multi-replica counterpart to
// TestConcurrency_BootstrapSystem_CrossReplicaExactlyOneAdmin
// (concurrency_bootstrap_cross_replica_test.go). That test's "replicas" all
// share ONE storage.Storage instance and therefore one process-local
// bootstrapMu — it would pass identically even if WithBootstrapLock's
// pg_advisory_lock call were deleted, because the shared mutex alone already
// serializes every goroutine in the test. It also never runs on Postgres at
// all (in-memory SQLite), so the advisory-lock branch in
// local_bootstrap_lock.go never even executes.
//
// This test instead gives each simulated replica its OWN *gorm.DB connection
// (own LocalStorage, own bootstrapMu) into the SAME real Postgres schema —
// the only thing left that can serialize BootstrapSystem's check-then-create
// sequence across them is pg_advisory_lock. If it's missing or broken, two
// replicas can both observe "not yet initialised" and each seed a first
// admin (#core-auth-03) — a duplicate-admin race that silently corrupts the
// RBAC seed until someone notices two admins exist.
func TestConcurrency_BootstrapSystem_CrossReplicaPostgres_ExactlyOneAdmin(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	base := pgTestDSN(t)
	dsn := pgIsolatedSchemaDSN(t, base)

	const token = "correct-token"
	const replicas = 5
	const callsPerReplica = 4

	cores := make([]*KeyorixCore, replicas)
	for i := range replicas {
		db := pgOpen(t, dsn)
		require.NoError(t, db.AutoMigrate(
			&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
			&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
			&models.Project{}, &models.Environment{}, &models.SystemMetadata{},
		))
		ls := localstore.NewLocalStorage(db)
		c := NewKeyorixCore(ls)
		c.SetBootstrapToken(token)
		cores[i] = c
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	type outcome struct {
		created bool
		err     error
	}
	results := make(chan outcome, replicas*callsPerReplica)
	n := 0
	for r := range replicas {
		for range callsPerReplica {
			n++
			wg.Add(1)
			go func(c *KeyorixCore, idx int) {
				defer wg.Done()
				<-start
				req := &BootstrapRequest{
					Username:    fmt.Sprintf("admin-%d", idx),
					Email:       fmt.Sprintf("admin-%d@example.com", idx),
					Password:    "BootstrapPass123!",
					DisplayName: "Admin",
					Token:       token,
				}
				res, err := c.BootstrapSystem(context.Background(), req)
				if err != nil {
					results <- outcome{err: err}
					return
				}
				results <- outcome{created: !res.AlreadyInitialized}
			}(cores[r], n)
		}
	}
	close(start) // release every call, across every independent replica, at once
	wg.Wait()
	close(results)

	created := 0
	for res := range results {
		assert.NoError(t, res.err, "no concurrent bootstrap call holding the valid token should error")
		if res.created {
			created++
		}
	}
	assert.Equal(t, 1, created, "exactly one call across every independent replica may create the first admin")

	// Verify from a fresh connection into the same schema, independent of any
	// replica's own connection.
	verifierDB := pgOpen(t, dsn)
	verifier := localstore.NewLocalStorage(verifierDB)

	_, total, err := verifier.ListUsers(context.Background(), &storage.UserFilter{Page: 1, PageSize: 100})
	require.NoError(t, err)
	assert.Equal(t, int64(1), total, "exactly one admin user must exist, not one per racing replica")

	roles, err := verifier.ListRoles(context.Background())
	require.NoError(t, err)
	assert.Len(t, roles, len(defaultRoles), "roles must be seeded exactly once across every replica")

	perms, err := verifier.ListPermissions(context.Background())
	require.NoError(t, err)
	assert.Len(t, perms, len(defaultPermissions), "permissions must be seeded exactly once across every replica")

	projects, err := verifier.ListProjects(context.Background())
	require.NoError(t, err)
	assert.Len(t, projects, 1, "the default project must be created exactly once across every replica")
}
