// concurrency_credential_under_suspend_sqlite_test.go — #2701 on SQLite.
//
// The SQLite counterpart of concurrency_credential_under_suspend_postgres_test.go:
// the same two-replica ctaReview fixture, built on ONE SQLite file opened by
// three independent *gorm.DB pools with the PRODUCTION pragmas (see
// sqliteProdPragmas), so it runs in default CI rather than only where a
// Postgres DSN exists.
//
// What differs from Postgres, and why the hook below is not beforeA: production
// SQLite opens every transaction with BEGIN IMMEDIATE (_txlock=immediate), which
// takes the database's single write lock at BEGIN. Before the fix, the
// credential INSERT ran in autocommit with no lock held, so replica B's whole
// sweep could run and commit in the window before it — exactly the interleaving
// #2701 describes, and the one this test forces. After the fix the INSERT runs
// inside a transaction that already holds the write lock, so on SQLite B
// physically cannot run in that window: the earliest point it can run is after
// A commits. Running B synchronously there (as beforeA does) would not choose an
// interleaving, it would deadlock B against A for the busy timeout. So the hook
// runs B at the earliest point the engine permits — in the window when A holds
// no transaction, otherwise straight after A returns — and the assertion is the
// one that must hold in EVERY legal interleaving: no live credential survives a
// sweep that reported success.
//
// The opposite ordering — B's sweep committed entirely before A's insert
// transaction even begins, which is what the owner re-check
// (requireLiveCredentialOwner) exists for — is pinned deterministically, with no
// concurrency at all, by TestCredentialInsertRefusedForUnusableOwner
// (internal/storage/store).
package core

import (
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// sqliteProdPragmas mirrors internal/storage/factory.go's sqliteDSN (unexported
// there). _txlock=immediate is the one that matters to these tests: see the file
// header.
const sqliteProdPragmas = "?_foreign_keys=1&_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate&_synchronous=FULL"

func newCTAReviewSQLite(t *testing.T) *ctaReview {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cta-review.db")
	return newCTAReviewOn(t, func() *gorm.DB {
		db, err := gorm.Open(sqlite.Open("file:"+path+sqliteProdPragmas), &gorm.Config{Logger: logger.Discard})
		require.NoError(t, err)
		t.Cleanup(func() {
			if sqlDB, err := db.DB(); err == nil {
				_ = sqlDB.Close()
			}
		})
		return db
	})
}

// sweepInInsertWindow registers a one-shot hook on replica A's own *gorm.DB,
// immediately before A's first INSERT into table. If A holds no transaction
// there, sweep (replica B's real operation, on B's own connection) runs to
// completion right then, before the INSERT. If A is already inside a
// transaction, SQLite's write lock is held and sweep cannot run until A
// commits, so it is started on its own goroutine and the returned wait blocks
// until it has finished. Call wait after A's operation returns, then assert.
func (f *ctaReview) sweepInInsertWindow(table string, sweep func()) (wait func() (fired, ranInWindow bool)) {
	f.t.Helper()
	var once sync.Once
	var wg sync.WaitGroup
	fired, inWindow := false, false
	fn := func(tx *gorm.DB) {
		if tx.Statement.Table != table {
			return
		}
		once.Do(func() {
			fired = true
			if _, inTx := tx.Statement.ConnPool.(gorm.TxCommitter); !inTx {
				inWindow = true
				sweep()
				return
			}
			wg.Go(func() {
				sweep()
			})
		})
	}
	require.NoError(f.t, f.dbA.Callback().Create().Before("gorm:begin_transaction").Register("cred-2701:before-create-"+table, fn))
	return func() (bool, bool) {
		wg.Wait()
		return fired, inWindow
	}
}

func TestCredentialUnderSuspend_CreatePAT_vs_SuspendUser_CrossReplicaSQLite(t *testing.T) {
	f := newCTAReviewSQLite(t)
	u := f.user("pat2701", "")

	var suspendErr error
	wait := f.sweepInInsertWindow("personal_access_tokens", func() {
		suspendErr = f.coreB.SuspendUser(f.ctx, f.adminID, u.ID)
	})

	_, patErr := f.coreA.CreateOwnPAT(f.ctx, u.ID, "ci", nil, nil, 0, 0, nil)
	fired, inWindow := wait()

	require.True(t, fired, "replica A never reached its PAT INSERT — the interleaving under test never happened")
	require.NoError(t, suspendErr, "replica B's suspend must report success; the whole point is that it did")
	assert.Zero(t, f.countLive(&models.PersonalAccessToken{}, "user_id = ? AND revoked = ?", u.ID, false),
		"a suspend that revoked all PATs and returned success must leave none unrevoked — otherwise "+
			"suspend → investigate → reactivate restores a credential the revoke-all was audited as having "+
			"removed (create err: %v, sweep ran in A's insert window: %v)", patErr, inWindow)
}

func TestCredentialUnderSuspend_CreateSession_vs_SuspendUser_CrossReplicaSQLite(t *testing.T) {
	f := newCTAReviewSQLite(t)
	u := f.user("sess2701", "")

	var suspendErr error
	wait := f.sweepInInsertWindow("sessions", func() {
		suspendErr = f.coreB.SuspendUser(f.ctx, f.adminID, u.ID)
	})

	_, _, loginErr := f.coreA.Login(f.ctx, &LoginRequest{Username: "sess2701", Password: "UserPass123!xyz-long-enough"})
	fired, inWindow := wait()

	require.True(t, fired, "replica A never reached its session INSERT — the interleaving under test never happened")
	require.NoError(t, suspendErr, "replica B's suspend must report success; the whole point is that it did")
	assert.Zero(t, f.countLive(&models.Session{}, "user_id = ? AND rotated_at IS NULL", u.ID),
		"a suspend that terminated every session and returned success must leave none live — otherwise the "+
			"session becomes usable again the moment the account is reactivated, up to its own expiry "+
			"(login err: %v, sweep ran in A's insert window: %v)", loginErr, inWindow)
}

// DeleteUser is the sweep the PR's design note singles out: a soft-deleted user
// reads as absent under GORM's default scoping, so this is the case a weaker
// "fail only if the owner exists and is blocked" re-check would silently stop
// covering. delete → restore → reactivate is the revival path here.
func TestCredentialUnderSuspend_CreatePAT_vs_DeleteUser_CrossReplicaSQLite(t *testing.T) {
	f := newCTAReviewSQLite(t)
	u := f.user("patdel2701", "")

	var deleteErr error
	wait := f.sweepInInsertWindow("personal_access_tokens", func() {
		deleteErr = f.coreB.DeleteUser(f.ctx, f.adminID, u.ID)
	})

	_, patErr := f.coreA.CreateOwnPAT(f.ctx, u.ID, "ci", nil, nil, 0, 0, nil)
	fired, inWindow := wait()

	require.True(t, fired, "replica A never reached its PAT INSERT — the interleaving under test never happened")
	require.NoError(t, deleteErr, "replica B's delete must report success; the whole point is that it did")
	assert.Zero(t, f.countLive(&models.PersonalAccessToken{}, "user_id = ? AND revoked = ?", u.ID, false),
		"a delete that revoked all PATs and returned success must leave none unrevoked — otherwise "+
			"delete → restore → reactivate restores a credential the sweep was audited as having removed "+
			"(create err: %v, sweep ran in A's insert window: %v)", patErr, inWindow)
}
