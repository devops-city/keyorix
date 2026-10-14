package store

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func seedPGMachineIdentity(t *testing.T, dsn string) uint {
	t.Helper()
	setup := pgOpen(t, dsn)
	require.NoError(t, setup.AutoMigrate(&models.MachineIdentity{}))
	now := time.Now().UTC()
	m := &models.MachineIdentity{ProjectID: 1, Name: "ci", IdentityType: "ci", State: "active", CreatedAt: now, UpdatedAt: now}
	require.NoError(t, setup.Create(m).Error)
	return m.ID
}

// TestConcurrency_LockMachineIdentityForUpdate_MultiInstancePostgres covers
// INV-STORE-15 on real Postgres, across independent connections:
//
//  1. Inside a transaction, the lock actually blocks a second connection's
//     lock-and-read of the same row until the first commits (SELECT … FOR UPDATE).
//  2. Outside a transaction it blocks nobody — a standalone FOR UPDATE is an
//     autocommit statement whose lock is released as it completes. This is the
//     documented no-op that makes "always take it inside the same
//     WithTransaction as the write" a rule rather than a style choice.
func TestConcurrency_LockMachineIdentityForUpdate_MultiInstancePostgres(t *testing.T) {
	dsn := pgIsolatedSchemaDSN(t, pgTestDSN(t))
	id := seedPGMachineIdentity(t, dsn)
	holder := NewLocalStorage(pgOpen(t, dsn))
	contender := NewLocalStorage(pgOpen(t, dsn))
	ctx := context.Background()

	// contend runs a lock-in-transaction on the contender connection and reports
	// when it completes.
	contend := func() <-chan error {
		done := make(chan error, 1)
		go func() {
			done <- contender.WithTransaction(ctx, func(tx storage.Storage) error {
				_, err := tx.LockMachineIdentityForUpdate(ctx, id)
				return err
			})
		}()
		return done
	}

	t.Run("in a transaction the lock blocks a second connection", func(t *testing.T) {
		release := make(chan struct{})
		var releaseOnce sync.Once
		unblock := func() { releaseOnce.Do(func() { close(release) }) }
		// A failing assertion below must still end the holder's transaction, or
		// the schema cleanup would wait on it forever.
		t.Cleanup(unblock)
		held := make(chan struct{})
		holderDone := make(chan error, 1)
		go func() {
			holderDone <- holder.WithTransaction(ctx, func(tx storage.Storage) error {
				if _, err := tx.LockMachineIdentityForUpdate(ctx, id); err != nil {
					return err
				}
				close(held)
				<-release
				return nil
			})
		}()
		<-held

		done := contend()
		select {
		case err := <-done:
			t.Fatalf("second connection's lock returned (err=%v) while the first still held it: FOR UPDATE is not blocking", err)
		case <-time.After(500 * time.Millisecond):
		}

		unblock()
		require.NoError(t, <-holderDone)
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(10 * time.Second):
			t.Fatal("second connection's lock never returned after the first committed")
		}
	})

	t.Run("outside a transaction the lock is a no-op", func(t *testing.T) {
		_, err := holder.LockMachineIdentityForUpdate(ctx, id) // autocommit: lock gone on return
		require.NoError(t, err)
		select {
		case err := <-contend():
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("a standalone (unwrapped) FOR UPDATE must not hold a lock past its own statement")
		}
	})
}

// TestConcurrency_MachineIdentityTransition_MultiInstancePostgres_RevokedAlwaysWins
// reproduces transitionMachineInTx's production shape (lock + read + legality
// check + conditional write, all in ONE WithTransaction) with two replicas
// racing active→suspended against active→revoked, and asserts the invariant that
// holds under EVERY legal interleaving: the row's FINAL state is 'revoked' and
// the revoke never fails. (suspended→revoked is legal, so "revoke goes second"
// succeeds; revoked→suspended is not, so "suspend goes second" is refused. An
// assertion that exactly one of the two wins would be false.)
//
// The harness pauses between the read and the write, widening the window the
// row lock exists to close. Without FOR UPDATE both replicas read 'active', the
// suspend's write lands, and the revoke's conditional UPDATE then loses
// (matched=false) — revoke fails and the final state is 'suspended'.
func TestConcurrency_MachineIdentityTransition_MultiInstancePostgres_RevokedAlwaysWins(t *testing.T) {
	dsn := pgIsolatedSchemaDSN(t, pgTestDSN(t))
	setup := pgOpen(t, dsn)
	require.NoError(t, setup.AutoMigrate(&models.MachineIdentity{}))
	ctx := context.Background()

	errIllegal := errors.New("illegal transition")
	// Mirrors core.machineTransitions for the states used here (the store package
	// cannot import core): only revoked is terminal.
	legal := func(from, to string) bool { return from != "revoked" && from != to }

	// transition is transitionMachineInTx's body, with a pause after the read.
	transition := func(ls *LocalStorage, id uint, to string) error {
		return ls.WithTransaction(ctx, func(tx storage.Storage) error {
			m, err := tx.LockMachineIdentityForUpdate(ctx, id)
			if err != nil {
				return err
			}
			from := m.State
			if !legal(from, to) {
				return errIllegal
			}
			time.Sleep(50 * time.Millisecond)
			m.State = to
			m.UpdatedAt = time.Now().UTC()
			matched, err := tx.TransitionMachineIdentityState(ctx, m, from)
			if err != nil {
				return err
			}
			if !matched {
				return errIllegal
			}
			return nil
		})
	}

	const rounds = 8
	for i := range rounds {
		now := time.Now().UTC()
		m := &models.MachineIdentity{ProjectID: 1, Name: "ci", IdentityType: "ci", State: "active", CreatedAt: now, UpdatedAt: now}
		require.NoError(t, setup.Create(m).Error)
		suspender := NewLocalStorage(pgOpen(t, dsn))
		revoker := NewLocalStorage(pgOpen(t, dsn))

		var wg sync.WaitGroup
		start := make(chan struct{})
		var revokeErr error
		wg.Add(2)
		go func() { defer wg.Done(); <-start; _ = transition(suspender, m.ID, "suspended") }()
		go func() { defer wg.Done(); <-start; revokeErr = transition(revoker, m.ID, "revoked") }()
		close(start)
		wg.Wait()

		var final models.MachineIdentity
		require.NoError(t, setup.First(&final, m.ID).Error)
		assert.Equal(t, "revoked", final.State, "round %d: revoked must always win the row's final value", i)
		assert.NoError(t, revokeErr, "round %d: a revoke is legal from active and from suspended, so it must never fail", i)
	}
}
