package store

// concurrency_row_lock_sites_postgres_test.go — the webauthn half of the
// row-lock-site contention coverage. The users and machine-identity halves
// moved to internal/core/concurrency_row_lock_sites_postgres_test.go so each
// calls its REAL production entry point (recordFailedLogin,
// TransitionMachineIdentity) instead of reconstructing the lock-then-write
// sequence here — see that file's header for why. webauthn stays here: its
// production caller, persistUpdatedCredential (internal/core/webauthn.go),
// calls storage.AdvanceWebAuthnCredentialCounter directly with no logic in
// between — that storage-layer call already IS the production entry point,
// not a reconstruction of one, so there was nothing to move.
//
// webauthn: a high-watermark counter (AdvanceWebAuthnCredentialCounter only
// persists a newSignCount that exceeds what's currently stored, via
// UpdateWebAuthnCredential — a plain Save, no CAS guard). The row lock is what
// stops a smaller, stale value from clobbering an already-committed larger one
// under a race. Verified by disabling the lock and re-running: goes red
// deterministically without it.

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// raceIndependentInstances spins up n independent LocalStorage instances
// (own connection each) into dsn, and runs race(ls, idx) on all of them
// concurrently, released by a single start barrier. Any error race returns
// fails the test immediately (via require, in the calling goroutine's
// deferred check) — every case here expects every racer to return cleanly,
// win or lose; a non-nil error is itself the bug this file exists to catch
// (see the scheduler-lease finding this campaign fixed).
func raceIndependentInstances(t *testing.T, dsn string, n int, race func(ls *LocalStorage, idx int) error) {
	t.Helper()
	stores := make([]*LocalStorage, n)
	for i := range n {
		stores[i] = NewLocalStorage(pgOpen(t, dsn))
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, n)
	for i := range n {
		wg.Add(1)
		go func(idx int, ls *LocalStorage) {
			defer wg.Done()
			<-start
			if err := race(ls, idx); err != nil {
				errs <- err
			}
		}(i, stores[i])
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
}

func TestConcurrency_RowLockSites_MultiInstancePostgres(t *testing.T) {
	base := pgTestDSN(t)

	t.Run("webauthn_signCount_never_regresses", func(t *testing.T) {
		dsn := pgIsolatedSchemaDSN(t, base)
		setupDB := pgOpen(t, dsn)
		require.NoError(t, setupDB.AutoMigrate(&models.WebAuthnCredential{}))
		credID := []byte("cred-race")
		initialBlob, err := json.Marshal(map[string]any{"authenticator": map[string]any{"signCount": 0}})
		require.NoError(t, err)
		require.NoError(t, setupDB.Create(&models.WebAuthnCredential{
			ID: 1, UserID: 1, CredentialID: credID, CredentialBlob: initialBlob,
		}).Error)

		const n = 8
		raceIndependentInstances(t, dsn, n, func(ls *LocalStorage, idx int) error {
			// Racer idx presents signCount = idx+1 (values 1..n) — the max, n,
			// must win regardless of goroutine scheduling order.
			blob, err := json.Marshal(map[string]any{"authenticator": map[string]any{"signCount": idx + 1}})
			if err != nil {
				return err
			}
			_, err = ls.AdvanceWebAuthnCredentialCounter(context.Background(), credID, 1, blob, uint32(idx+1), time.Now().UTC())
			return err
		})

		verifier := pgOpen(t, dsn)
		var final models.WebAuthnCredential
		require.NoError(t, verifier.Where("credential_id = ?", credID).First(&final).Error)
		var stored webauthnStoredCounter
		require.NoError(t, json.Unmarshal(final.CredentialBlob, &stored))
		assert.Equal(t, uint32(n), stored.Authenticator.SignCount,
			"the stored counter must end at the maximum presented value — a smaller concurrent value must never clobber a larger already-committed one")
	})
}
