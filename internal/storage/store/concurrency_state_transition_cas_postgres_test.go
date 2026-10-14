package store

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// raceTransitions runs n goroutines, each on its OWN Postgres connection, all
// released at once, each calling attempt(i, store) — a bare conditional write
// with no surrounding lock — and returns how many reported matched=true.
func raceTransitions(t *testing.T, dsn string, n int, attempt func(i int, ls *LocalStorage) (bool, error)) int32 {
	t.Helper()
	stores := make([]*LocalStorage, n)
	for i := range stores {
		stores[i] = NewLocalStorage(pgOpen(t, dsn))
	}
	var won int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			matched, err := attempt(i, stores[i])
			assert.NoError(t, err)
			if matched {
				atomic.AddInt32(&won, 1)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	return won
}

// TestConcurrency_StateTransitionCAS_MultiInstancePostgres_ExactlyOneWinner
// proves INV-STORE-14 on real Postgres: TransitionMachineIdentityState and
// TransitionSecretStatus are a conditional UPDATE (`WHERE id = ? AND
// state/status = ?`), so N independent connections all racing off the SAME
// observed fromState — with no row lock and no transaction, just the bare
// statement — produce exactly one matched=true, and the row ends on that
// winner's value. The CAS alone has to carry this; the row lock in
// transitionMachineInTx is a separate, additional layer (see
// concurrency_machine_identity_lock_postgres_test.go).
func TestConcurrency_StateTransitionCAS_MultiInstancePostgres_ExactlyOneWinner(t *testing.T) {
	dsn := pgIsolatedSchemaDSN(t, pgTestDSN(t))
	setup := pgOpen(t, dsn)
	require.NoError(t, setup.AutoMigrate(&models.MachineIdentity{}, &models.SecretNode{}))
	ctx := context.Background()
	const racers = 8

	t.Run("machine identity", func(t *testing.T) {
		now := time.Now().UTC()
		base := &models.MachineIdentity{ProjectID: 1, Name: "ci", IdentityType: "ci", State: "active", CreatedAt: now, UpdatedAt: now}
		require.NoError(t, setup.Create(base).Error)

		won := raceTransitions(t, dsn, racers, func(i int, ls *LocalStorage) (bool, error) {
			m := *base
			m.State = fmt.Sprintf("racer-%d", i)
			return ls.TransitionMachineIdentityState(ctx, &m, "active")
		})
		assert.Equal(t, int32(1), won, "exactly one racer may move the row off 'active'")

		var final models.MachineIdentity
		require.NoError(t, setup.First(&final, base.ID).Error)
		assert.Contains(t, final.State, "racer-", "the row must hold some racer's value, not the seed")
	})

	t.Run("secret status", func(t *testing.T) {
		base := &models.SecretNode{Name: "db-password", ProjectID: 1, EnvironmentID: 1, IsSecret: true, Status: "active"}
		require.NoError(t, setup.Create(base).Error)

		won := raceTransitions(t, dsn, racers, func(i int, ls *LocalStorage) (bool, error) {
			s := *base
			s.Status = fmt.Sprintf("racer-%d", i)
			return ls.TransitionSecretStatus(ctx, &s, "active")
		})
		assert.Equal(t, int32(1), won, "exactly one racer may move the secret off 'active'")

		var final models.SecretNode
		require.NoError(t, setup.First(&final, base.ID).Error)
		assert.Contains(t, final.Status, "racer-")
	})
}
