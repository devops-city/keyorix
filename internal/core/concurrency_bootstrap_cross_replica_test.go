// concurrency_bootstrap_cross_replica_test.go — regression coverage for
// #core-auth-03: BootstrapSystem's check-then-create sequence must serialize
// across HA replicas (ADR-039), not just within one process. A plain
// KeyorixCore-level sync.Mutex only ever guards goroutines inside the SAME
// KeyorixCore instance; two different replica processes — each with their own
// KeyorixCore, both talking to the same shared database — have no coordination
// through it at all, so both could observe "not yet initialised" and each
// independently seed a "first admin".
//
// This test simulates that topology at the Go level: multiple independent
// KeyorixCore instances (standing in for separate replica processes) all backed
// by ONE shared storage.Storage. Pre-fix, each instance's own bootstrapMu cannot
// see the others, so the race reproduces even though they share a database.
// Post-fix, BootstrapSystem serializes through storage.WithBootstrapLock, which
// lives on the shared storage instance (not on any one replica's KeyorixCore) —
// exactly mirroring how a real PostgreSQL advisory lock is scoped to the shared
// database, not to any one replica's process.
package core

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// sharedBootstrapStorage returns a single storage.Storage instance backed by a
// fresh in-memory DB, standing in for the ONE database every replica in an HA
// deployment shares.
func sharedBootstrapStorage(t *testing.T) storage.Storage {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.SystemMetadata{},
	))
	return store.NewLocalStorage(db)
}

// replicaBootstrapCore returns a KeyorixCore standing in for one replica's
// process: its own instance (own Go-level state, own bootstrapToken copy — same
// as every replica gets the same KEYORIX_BOOTSTRAP_TOKEN from shared config) but
// wired to the shared storage every replica in the deployment talks to.
func replicaBootstrapCore(shared storage.Storage, token string) *KeyorixCore {
	c := NewKeyorixCore(shared)
	c.SetBootstrapToken(token)
	return c
}

// TestConcurrency_BootstrapSystem_CrossReplicaExactlyOneAdmin drives many
// concurrent BootstrapSystem calls spread across SEVERAL independent KeyorixCore
// instances (simulating several HA replicas), all racing against ONE shared
// database with the same valid bootstrap token but different usernames — the
// exact #core-auth-03 exploit scenario. Only one call across the whole fleet may
// actually seed the first admin; every other call must observe
// AlreadyInitialized, and the store must end up in a fully consistent state: one
// user, and none of the seeded RBAC data duplicated.
func TestConcurrency_BootstrapSystem_CrossReplicaExactlyOneAdmin(t *testing.T) {
	t.Parallel()
	shared := sharedBootstrapStorage(t)
	const token = "correct-token"

	const replicas = 5
	const callsPerReplica = 4
	cores := make([]*KeyorixCore, replicas)
	for i := range cores {
		cores[i] = replicaBootstrapCore(shared, token)
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
	close(start)
	wg.Wait()
	close(results)

	created := 0
	for res := range results {
		assert.NoError(t, res.err, "no concurrent bootstrap call holding the valid token should error")
		if res.created {
			created++
		}
	}
	assert.Equal(t, 1, created, "exactly one call across every replica may create the first admin")

	// The store must end up fully consistent: exactly one user, and the RBAC seed
	// (permissions/roles) ran exactly once — not once per racing replica.
	_, total, err := shared.ListUsers(context.Background(), &storage.UserFilter{Page: 1, PageSize: 100})
	require.NoError(t, err)
	assert.Equal(t, int64(1), total, "exactly one admin user must exist, not one per racing replica")

	roles, err := shared.ListRoles(context.Background())
	require.NoError(t, err)
	assert.Len(t, roles, len(defaultRoles), "roles must be seeded exactly once across every replica")

	perms, err := shared.ListPermissions(context.Background())
	require.NoError(t, err)
	assert.Len(t, perms, len(defaultPermissions), "permissions must be seeded exactly once across every replica")

	projects, err := shared.ListProjects(context.Background())
	require.NoError(t, err)
	assert.Len(t, projects, 1, "the default project must be created exactly once across every replica")
}
