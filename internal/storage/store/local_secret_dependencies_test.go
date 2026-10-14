package store

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSecretDependencyReachable is the same truth table
// internal/core/secret_dependencies_test.go's TestDependencyReachable exercises against
// core's own dependencyReachable — this package cannot import core (core imports this
// package), so secretDependencyReachable is a deliberate duplicate that must produce
// identical answers; this test is what keeps the two in sync.
func TestSecretDependencyReachable(t *testing.T) {
	edge := func(dependent, dependsOn uint) *models.SecretDependency {
		return &models.SecretDependency{DependentSecretID: dependent, DependsOnSecretID: dependsOn}
	}
	// 1→2→3 (1 depends on 2 depends on 3), plus 4→2.
	edges := []*models.SecretDependency{edge(1, 2), edge(2, 3), edge(4, 2)}
	assert.True(t, secretDependencyReachable(edges, 1, 3), "1 transitively depends on 3")
	assert.True(t, secretDependencyReachable(edges, 1, 2))
	assert.False(t, secretDependencyReachable(edges, 3, 1), "3 does not depend on 1")
	assert.True(t, secretDependencyReachable(edges, 4, 3), "4→2→3 reachable")
	assert.False(t, secretDependencyReachable(edges, 2, 4), "2 does not reach 4")
}

func newSecretDependencyTestStorage(t *testing.T) *LocalStorage {
	t.Helper()
	db := concurrentDB(t)
	require.NoError(t, db.AutoMigrate(&models.SecretDependency{}))
	return NewLocalStorage(db)
}

// TestCreateSecretDependencyExclusive_HappyPath proves the ordinary case: a fresh edge
// with no existing rows in the project is created and returned with a real ID.
func TestCreateSecretDependencyExclusive_HappyPath(t *testing.T) {
	ls := newSecretDependencyTestStorage(t)
	ctx := context.Background()

	created, err := ls.CreateSecretDependencyExclusive(ctx, &models.SecretDependency{
		ProjectID: 1, DependentSecretID: 10, DependsOnSecretID: 20, Note: "app depends on db",
	})
	require.NoError(t, err)
	assert.NotZero(t, created.ID)
	assert.Equal(t, uint(10), created.DependentSecretID)
	assert.Equal(t, uint(20), created.DependsOnSecretID)

	fetched, err := ls.GetSecretDependency(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, "app depends on db", fetched.Note)
}

// TestCreateSecretDependencyExclusive_DuplicateRejected proves the exact
// (dependent, depends_on) pair is rejected with the ErrDuplicateSecretDependency
// sentinel, not a raw constraint-violation error.
func TestCreateSecretDependencyExclusive_DuplicateRejected(t *testing.T) {
	ls := newSecretDependencyTestStorage(t)
	ctx := context.Background()

	_, err := ls.CreateSecretDependencyExclusive(ctx, &models.SecretDependency{
		ProjectID: 1, DependentSecretID: 10, DependsOnSecretID: 20,
	})
	require.NoError(t, err)

	_, err = ls.CreateSecretDependencyExclusive(ctx, &models.SecretDependency{
		ProjectID: 1, DependentSecretID: 10, DependsOnSecretID: 20,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, storage.ErrDuplicateSecretDependency))
}

// TestCreateSecretDependencyExclusive_CycleRejected proves adding the reverse edge of an
// existing dependency (which would close a 2-node cycle) is rejected with the
// ErrSecretDependencyCycle sentinel.
func TestCreateSecretDependencyExclusive_CycleRejected(t *testing.T) {
	ls := newSecretDependencyTestStorage(t)
	ctx := context.Background()

	// 10 depends on 20.
	_, err := ls.CreateSecretDependencyExclusive(ctx, &models.SecretDependency{
		ProjectID: 1, DependentSecretID: 10, DependsOnSecretID: 20,
	})
	require.NoError(t, err)

	// 20 depends on 10 would close the loop.
	_, err = ls.CreateSecretDependencyExclusive(ctx, &models.SecretDependency{
		ProjectID: 1, DependentSecretID: 20, DependsOnSecretID: 10,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, storage.ErrSecretDependencyCycle))

	// A longer cycle (30 depends on 10, which would close 10→20(nonexistent)... use a
	// 3-node chain instead: 20 depends on 30, then 30 depends on 10 would close
	// 10→20→30→10).
	_, err = ls.CreateSecretDependencyExclusive(ctx, &models.SecretDependency{
		ProjectID: 1, DependentSecretID: 20, DependsOnSecretID: 30,
	})
	require.NoError(t, err)
	_, err = ls.CreateSecretDependencyExclusive(ctx, &models.SecretDependency{
		ProjectID: 1, DependentSecretID: 30, DependsOnSecretID: 10,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, storage.ErrSecretDependencyCycle), "a longer cycle (10→20→30→10) must also be rejected")
}

// TestConcurrency_CreateSecretDependencyExclusive_NoCycleUnderRealContention is the
// storage-layer analogue of internal/core's
// TestAddSecretDependency_ConcurrentRaceCannotPersistACycle (#260), but exercised
// directly against CreateSecretDependencyExclusive over a REAL multi-connection SQLite
// database (concurrentDB, BEGIN IMMEDIATE) with NO process-level mutex held around the
// call — proving the atomicity guarantee now lives in the storage primitive itself,
// not only in the caller's secretDependencyMu. This is exactly the property
// RemoteStorage's implementation depends on: a downstream server's mutex only
// serializes its OWN goroutines, so multiple downstream replicas (or, here, multiple
// bare goroutines with no shared mutex at all) must still be unable to both persist
// reciprocal edges for the same pair.
func TestConcurrency_CreateSecretDependencyExclusive_NoCycleUnderRealContention(t *testing.T) {
	ls := newSecretDependencyTestStorage(t)
	ctx := context.Background()

	const iterations = 20
	for i := range iterations {
		a := uint(1000 + i*2)
		b := uint(1000 + i*2 + 1)

		var wg sync.WaitGroup
		start := make(chan struct{})
		results := make([]error, 2)
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_, results[0] = ls.CreateSecretDependencyExclusive(ctx, &models.SecretDependency{
				ProjectID: 1, DependentSecretID: a, DependsOnSecretID: b,
			})
		}()
		go func() {
			defer wg.Done()
			<-start
			_, results[1] = ls.CreateSecretDependencyExclusive(ctx, &models.SecretDependency{
				ProjectID: 1, DependentSecretID: b, DependsOnSecretID: a,
			})
		}()
		close(start)
		wg.Wait()

		successes := 0
		for _, e := range results {
			if e == nil {
				successes++
			}
		}
		require.Equal(t, 1, successes,
			"iteration %d: exactly one of A→B / B→A must win the race under real multi-connection contention", i)
	}
}
