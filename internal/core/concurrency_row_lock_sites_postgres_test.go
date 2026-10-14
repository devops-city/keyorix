package core

// concurrency_row_lock_sites_postgres_test.go — the users and machine-identity
// halves of the row-lock-site contention coverage, moved here from
// internal/storage/store's TestConcurrency_RowLockSites_MultiInstancePostgres so
// each one calls its REAL production entry point (recordFailedLogin,
// TransitionMachineIdentity) instead of reconstructing the lock-then-write
// sequence inside the test harness.
//
// Why this matters: a harness that hand-assembles
// `WithTransaction(func(tx) { tx.LockXForUpdate(...); tx.WriteX(...) })` only
// proves that SEQUENCE is safe — it says nothing about whether the real
// production caller actually uses that sequence, and a future refactor that
// moves the lock or the write out of its transaction (in production code)
// would not be caught by a test that never calls the production code path at
// all. Calling the real entry point means a transaction-boundary regression
// breaks an actual test, not just an AST/line-number check. This is the
// guard from the Postgres contention audit — see that report for the earlier,
// reconstructed version of the machine-identity case and why its assertion
// was also wrong (active->revoked being itself a legal transition).
//
// The webauthn subtest stayed in internal/storage/store: its production
// caller, persistUpdatedCredential (webauthn.go), calls
// storage.AdvanceWebAuthnCredentialCounter directly with no logic in
// between — that storage-layer call already IS the production entry point,
// not a reconstruction of one, so there was nothing to move.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConcurrency_RecordFailedLogin_MultiInstancePostgres_NoLostUpdates calls
// the real c.recordFailedLogin (login_lockout.go) — same package, so the
// unexported method is directly callable — across N independent KeyorixCore
// instances (own LocalStorage, own *gorm.DB connection, own process-local
// loginFailureLock shard) racing the SAME user row. LockUserForUpdate's row
// lock is the only thing serializing the read-modify-write across them: the
// write (UpdateLoginLockoutState) is a plain, unconditional `WHERE id = ?`
// update with no compare-and-swap guard.
func TestConcurrency_RecordFailedLogin_MultiInstancePostgres_NoLostUpdates(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	base := pgTestDSN(t)
	dsn := pgIsolatedSchemaDSN(t, base)

	setupDB := pgOpen(t, dsn)
	require.NoError(t, setupDB.AutoMigrate(&models.User{}))
	require.NoError(t, setupDB.Create(&models.User{ID: 1, Username: "racer", Email: "racer@example.com"}).Error)

	const n = 8
	cores := make([]*KeyorixCore, n)
	for i := range n {
		db := pgOpen(t, dsn)
		c := NewKeyorixCore(localstore.NewLocalStorage(db))
		c.SetLoginLockoutPolicy(LoginLockoutPolicy{
			Enabled:      true,
			MaxAttempts:  1000, // high enough that no racer trips a lockout mid-test
			Window:       time.Hour,
			BaseCooldown: time.Minute,
			MaxCooldown:  time.Hour,
		})
		cores[i] = c
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func(c *KeyorixCore) {
			defer wg.Done()
			<-start
			c.recordFailedLogin(context.Background(), &models.User{ID: 1})
		}(cores[i])
	}
	close(start)
	wg.Wait()

	verifier := pgOpen(t, dsn)
	var final models.User
	require.NoError(t, verifier.First(&final, 1).Error)
	assert.Equal(t, n, final.FailedLoginAttempts, "every racer's recordFailedLogin call must be reflected — a lost update means LockUserForUpdate isn't serializing the read-modify-write in production")
}

// TestConcurrency_TransitionMachineIdentity_MultiInstancePostgres_RevokedIsTerminal
// calls the real c.TransitionMachineIdentity (exported, machine_identities.go)
// across two independent KeyorixCore instances racing suspended->revoked
// against suspended->active off the same row (#388's own example). Unlike a
// flat "exactly one write succeeds" assertion (wrong here — active->revoked is
// itself a legal transition, so if active wins the race to go first, revoked
// legitimately gets a second, later, ALSO-successful write), the invariant
// that holds under every legal interleaving is narrower: the racer targeting
// revoked must always win, and the row must end revoked, never active. This
// also removes the earlier reconstructed test's hand-rolled "revoked is
// terminal" gate (a stand-in for canTransitionMachine that internal/storage/
// store couldn't import due to the core->store dependency direction) — calling
// production directly means the REAL canTransitionMachine gate runs.
func TestConcurrency_TransitionMachineIdentity_MultiInstancePostgres_RevokedIsTerminal(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	base := pgTestDSN(t)
	dsn := pgIsolatedSchemaDSN(t, base)

	setupDB := pgOpen(t, dsn)
	require.NoError(t, setupDB.AutoMigrate(&models.MachineIdentity{}))
	require.NoError(t, setupDB.Create(&models.MachineIdentity{
		ID: 1, ProjectID: 1, Name: "ci-runner", State: MachineSuspended,
	}).Error)

	coreRevoke := NewKeyorixCore(localstore.NewLocalStorage(pgOpen(t, dsn)))
	coreActivate := NewKeyorixCore(localstore.NewLocalStorage(pgOpen(t, dsn)))

	type outcome struct {
		target string
		err    error
	}
	results := make(chan outcome, 2)
	var wg sync.WaitGroup
	start := make(chan struct{})
	race := func(c *KeyorixCore, target string) {
		defer wg.Done()
		<-start
		_, err := c.TransitionMachineIdentity(context.Background(), 1, 1, target, 1)
		results <- outcome{target: target, err: err}
	}
	wg.Add(2)
	go race(coreRevoke, MachineRevoked)
	go race(coreActivate, MachineActive)
	close(start)
	wg.Wait()
	close(results)

	var revokedErr, activeErr error
	for o := range results {
		switch o.target {
		case MachineRevoked:
			revokedErr = o.err
		case MachineActive:
			activeErr = o.err
		}
	}
	assert.NoError(t, revokedErr, "the transition targeting revoked must always succeed — either first (suspended->revoked) or second (active->revoked), never refused")
	if activeErr == nil {
		t.Log("active won the race to go first (suspended->active), then revoked legitimately followed (active->revoked) — both succeeding here is correct, not a fork")
	}

	verifier := localstore.NewLocalStorage(pgOpen(t, dsn))
	final, err := verifier.GetMachineIdentity(context.Background(), 1)
	require.NoError(t, err)
	assert.Equal(t, MachineRevoked, final.State, "the row must end revoked regardless of race ordering — never left at active")
}
