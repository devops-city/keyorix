package core

// SHARE-CAS-1 (REVIEW-2 residual on #3367): UpdateSharePermission classifies its
// change (widens, narrows, or both: two commits) against the share as read
// inside its transaction, then writes the row. On PostgreSQL READ COMMITTED a
// plain read locks nothing, so a narrowing on another replica could commit
// between the read and the UPDATE: an update classified neutral then landed
// write over read (or a stale expiry over a shortened one), a real widening
// with only a best-effort audit row, or none during an audit outage.
//
// The interleaving is forced with GORM callbacks on replica A's own *gorm.DB
// (beforeAShareUpdate, beforeAInTxShareRead): replica B's real
// UpdateSharePermission (its own connection, its own transaction, the same
// code path as A) starts right before A's share UPDATE, after A's
// in-transaction read, or right before that read. Unfixed, B commits inside
// A's window. Fixed (LockShareRecordForUpdate), B waits on A's row lock and
// applies after A commits.
//
// PostgreSQL only (newCTAReview skips without KEYORIX_TEST_PG_DSN, and the test
// asserts the dialect): SQLite write transactions are BEGIN IMMEDIATE, so no
// second writer can commit between the read and the UPDATE; there is no window
// to force there.

import (
	"fmt"
	"regexp"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
)

// shareUpdateRace is one forced interleaving: A's update on replica A (audit
// outage optional) with B's update on replica B started before A's UPDATE.
type shareUpdateRace struct {
	f       *ctaReview
	shareID uint
	errA    error
	errB    error
}

// Where B starts, relative to A.
const (
	bBeforeAUpdate   = "before A's share UPDATE"                     // after A's in-transaction read
	bBeforeAInTxRead = "before A's in-transaction read of the share" // after A's pre-transaction read
)

// beforeAInTxShareRead runs concurrent to completion right before A's first
// read of share_records inside a transaction. A holds no lock on the row yet
// (this statement takes it), so B never waits here; it commits between A's
// pre-transaction read and its in-transaction one.
func (f *ctaReview) beforeAInTxShareRead(concurrent func()) (fired func() bool) {
	f.t.Helper()
	var once sync.Once
	hit := false
	require.NoError(f.t, f.dbA.Callback().Query().Before("gorm:query").Register("share-cas-1:before-tx-read", func(tx *gorm.DB) {
		if tx.Statement.Table != "share_records" {
			return
		}
		if _, inTx := tx.Statement.ConnPool.(gorm.TxCommitter); !inTx {
			return
		}
		once.Do(func() {
			hit = true
			concurrent()
		})
	}))
	return func() bool { return hit }
}

// beforeAShareUpdate starts concurrent in a goroutine right before A's first
// share_records UPDATE and holds A there until concurrent has finished (it
// committed inside A's window: the unfixed interleaving) or Postgres reports a
// backend blocked by A's OWN backend (pg_blocking_pids: B waits on A's row
// lock and runs after A commits). Unlike beforeAMayBlock's database-wide
// lock-wait count, a waiter of a parallel test cannot release A early, so an
// unfixed run cannot turn green by chance. Call waitB after A returns.
func (f *ctaReview) beforeAShareUpdate(concurrent func()) (fired func() bool, waitB func()) {
	f.t.Helper()
	var once sync.Once
	hit := false
	done := make(chan struct{})
	require.NoError(f.t, f.dbA.Callback().Update().Before("gorm:update").Register("share-cas-1:before-update", func(tx *gorm.DB) {
		if tx.Statement.Table != "share_records" {
			return
		}
		once.Do(func() {
			hit = true
			var pidA int64
			require.NoError(f.t, tx.Statement.ConnPool.QueryRowContext(tx.Statement.Context, "SELECT pg_backend_pid()").Scan(&pidA))
			go func() {
				defer close(done)
				concurrent()
			}()
			for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
				select {
				case <-done:
					return
				default:
				}
				var blocked int64
				require.NoError(f.t, f.setupDB.Raw("SELECT count(*) FROM pg_stat_activity WHERE ? = ANY(pg_blocking_pids(pid))", pidA).
					Scan(&blocked).Error)
				if blocked > 0 {
					return
				}
			}
			f.t.Errorf("B neither finished nor blocked on A within 10s")
		})
	}))
	return func() bool { return hit }, func() {
		if hit {
			<-done
		}
	}
}

func runShareUpdateRace(t *testing.T, when string, auditDown bool, initial ShareSecretRequest, reqA, reqB UpdateShareRequest) *shareUpdateRace {
	t.Helper()
	f := newCTAReview(t)
	require.Equal(t, "postgres", f.dbA.Dialector.Name(), "this race exists only on PostgreSQL")
	down := &atomic.Bool{}
	coreA := NewKeyorixCore((&auditOutageStorage{inner: localstore.NewLocalStorage(f.dbA), down: down}).store())
	coreA.SetAuthEncryptor(f.enc)

	owner := f.user("cta-cls-owner", "project_admin")
	recipient := f.user("cta-cls-recipient", "project_viewer")
	s := f.secret("cta-cls-secret", owner.ID)
	initial.SecretID, initial.RecipientID, initial.SharedBy = s.ID, recipient.ID, owner.ID
	share, err := f.setup.ShareSecret(f.ctx, &initial)
	require.NoError(t, err)

	r := &shareUpdateRace{f: f, shareID: share.ID}
	reqA.ShareID, reqA.UpdatedBy = share.ID, owner.ID
	reqB.ShareID, reqB.UpdatedBy = share.ID, owner.ID
	runB := func() { _, r.errB = f.coreB.UpdateSharePermission(f.ctx, &reqB) }
	var fired func() bool
	waitB := func() {}
	switch when {
	case bBeforeAUpdate:
		fired, waitB = f.beforeAShareUpdate(runB)
	case bBeforeAInTxRead:
		fired = f.beforeAInTxShareRead(runB)
	default:
		t.Fatalf("unknown interleaving %q", when)
	}
	down.Store(auditDown)
	_, r.errA = coreA.UpdateSharePermission(f.ctx, &reqA)
	down.Store(false)
	waitB()
	t.Logf("B started %s; A (audit down=%v) err=%v, B err=%v", when, auditDown, r.errA, r.errB)
	require.True(t, fired(), "the hook must have started B's update %s", when)
	return r
}

func (r *shareUpdateRace) final() *models.ShareRecord {
	r.f.t.Helper()
	var s models.ShareRecord
	require.NoError(r.f.t, r.f.setupDB.First(&s, r.shareID).Error)
	return &s
}

var shareUpdatedFromTo = regexp.MustCompile(`\(from (\w+) to (\w+)\)`)

// transitions returns the (from, to) permission of every share_updated row of
// this share, in no particular order: a best-effort row is written after its
// commit, so row order is not commit order.
func (r *shareUpdateRace) transitions() [][2]string {
	r.f.t.Helper()
	var rows []models.AuditEvent
	require.NoError(r.f.t, r.f.setupDB.Where("event_type = ? AND description LIKE ?",
		string(ShareAuditEventUpdated), fmt.Sprintf("%%(share %d)", r.shareID)).Find(&rows).Error)
	out := make([][2]string, 0, len(rows))
	for _, e := range rows {
		m := shareUpdatedFromTo.FindStringSubmatch(e.Description)
		require.Len(r.f.t, m, 3, "unparsable share_updated row: %q", e.Description)
		out = append(out, [2]string{m[1], m[2]})
	}
	return out
}

// auditChainExplains reports whether some order of the rows walks the share's
// permission from initial to final, each row starting from the value the
// previous one left. That holds under every legal interleaving when each row
// records what its update really overwrote; it fails when a committed change of
// the permission has no row, or a row claims a "from" the share did not have.
func auditChainExplains(initial, final string, rows [][2]string) bool {
	if len(rows) == 0 {
		return initial == final
	}
	for i, row := range rows {
		if row[0] != initial {
			continue
		}
		rest := append(append([][2]string{}, rows[:i]...), rows[i+1:]...)
		if auditChainExplains(row[1], final, rest) {
			return true
		}
	}
	return false
}

// TestCTAReview_UpdateSharePermission_NeutralVsConcurrentNarrowing_CrossReplicaPostgres:
// A re-saves write (neutral) while B narrows write→read. Unfixed, B commits in
// A's window and A writes write over read: the narrowing B reported is undone,
// and A's row (if any) says write→write. With the audit log down on A that
// widening commits with no row at all.
//
// The last case is a control: B commits before A's in-transaction read, so A
// sees read, classifies write-over-read as widening and, with the audit log
// down, is refused. It is green with or without the fix and shows the
// invariant is not met by refusing everything.
func TestCTAReview_UpdateSharePermission_NeutralVsConcurrentNarrowing_CrossReplicaPostgres(t *testing.T) {
	for _, tc := range []struct {
		when      string
		auditDown bool
		refused   bool
	}{
		{when: bBeforeAUpdate},
		{when: bBeforeAUpdate, auditDown: true},
		{when: bBeforeAInTxRead, auditDown: true, refused: true},
	} {
		t.Run(fmt.Sprintf("%s/audit-down=%v", tc.when, tc.auditDown), func(t *testing.T) {
			t.Parallel()
			r := runShareUpdateRace(t, tc.when, tc.auditDown,
				ShareSecretRequest{Permission: "write"},
				UpdateShareRequest{Permission: "write"},
				UpdateShareRequest{Permission: "read"})
			require.NoError(t, r.errB, "the narrowing reported success")
			if tc.refused {
				require.ErrorIs(t, r.errA, ErrMutationAuditUnavailable, "write over read widens: it must fail closed with the audit log down")
			} else {
				require.NoError(t, r.errA, "a neutral update must not be blocked")
			}

			final, rows := r.final().Permission, r.transitions()
			t.Logf("final permission %q, share_updated rows %v", final, rows)
			assert.True(t, auditChainExplains("write", final, rows),
				"the audit trail cannot explain the share's permission (write -> %q) from rows %v: an update classified "+
					"from a stale read changed the permission without a true row", final, rows)
		})
	}
}

// TestCTAReview_UpdateSharePermission_PreservedExpiryVsConcurrentShortening_CrossReplicaPostgres:
// A re-saves write and does not touch the expiry while B shortens it. A
// request that does not touch the expiry must never change it, in any order.
// Unfixed, A wrote back the expiry it read before its transaction over B's
// shorter one: classified neutral when B landed after A's in-transaction read
// (no row with the audit log down), widening but audited when B landed before it.
func TestCTAReview_UpdateSharePermission_PreservedExpiryVsConcurrentShortening_CrossReplicaPostgres(t *testing.T) {
	for _, tc := range []struct {
		when      string
		auditDown bool
	}{
		{when: bBeforeAUpdate, auditDown: true},
		{when: bBeforeAInTxRead},
	} {
		t.Run(fmt.Sprintf("%s/audit-down=%v", tc.when, tc.auditDown), func(t *testing.T) {
			t.Parallel()
			long, short := time.Now().Add(48*time.Hour), time.Now().Add(time.Hour)
			r := runShareUpdateRace(t, tc.when, tc.auditDown,
				ShareSecretRequest{Permission: "write", ExpiresAt: &long},
				UpdateShareRequest{Permission: "write"},
				UpdateShareRequest{Permission: "write", ExpiresAt: &short})
			require.NoError(t, r.errA, "an update that changes no access must not be blocked")
			require.NoError(t, r.errB, "the shortening reported success")

			got := r.final()
			require.NotNil(t, got.ExpiresAt)
			assert.WithinDuration(t, short, *got.ExpiresAt, time.Second,
				"the shortened expiry was overwritten by an update that did not ask to change the expiry")
		})
	}
}
