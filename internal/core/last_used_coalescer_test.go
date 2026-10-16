package core

// last_used_coalescer_test.go — OPT-LASTUSED-1: the per-request last_used_at /
// last_seen_at UPDATE is gone from the request path, the coalesced flush keeps
// GREATEST semantics across replicas, and every reader of the three columns
// sees a use within the documented bound (lastUsedFlushInterval).

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

// sqlRecorder is a gorm logger that records every statement's SQL.
type sqlRecorder struct {
	mu    sync.Mutex
	stmts []string
}

func (r *sqlRecorder) LogMode(logger.LogLevel) logger.Interface { return r }
func (r *sqlRecorder) Info(context.Context, string, ...any)     {}
func (r *sqlRecorder) Warn(context.Context, string, ...any)     {}
func (r *sqlRecorder) Error(context.Context, string, ...any)    {}
func (r *sqlRecorder) Trace(_ context.Context, _ time.Time, fc func() (string, int64), _ error) {
	sql, _ := fc()
	r.mu.Lock()
	r.stmts = append(r.stmts, sql)
	r.mu.Unlock()
}

func (r *sqlRecorder) reset() {
	r.mu.Lock()
	r.stmts = nil
	r.mu.Unlock()
}

var lastUsedWriteRE = regexp.MustCompile(`(?is)^\s*UPDATE\b.*\b(last_used_at|last_seen_at)\b`)

// lastUsedWrites returns the recorded statements that write a last-used column.
func (r *sqlRecorder) lastUsedWrites() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, s := range r.stmts {
		if lastUsedWriteRE.MatchString(s) {
			out = append(out, s)
		}
	}
	return out
}

const (
	luPATRaw     = "kx_pat_lastused_coalesce"
	luMachineRaw = "kx_machine_lastused_coalesce"
	luSessionRaw = "lastused-coalesce-session"
)

// lastUsedWorld is one user with a PAT and a session, and one active machine
// identity with a credential, on a real SQLite LocalStorage.
type lastUsedWorld struct {
	db   *gorm.DB
	rec  *sqlRecorder
	core *KeyorixCore
	now  time.Time
	mu   sync.Mutex
}

func (w *lastUsedWorld) clock() time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.now
}

func (w *lastUsedWorld) advance(d time.Duration) {
	w.mu.Lock()
	w.now = w.now.Add(d)
	w.mu.Unlock()
}

func newLastUsedWorld(t *testing.T) *lastUsedWorld {
	t.Helper()
	rec := &sqlRecorder{}
	db := sqlitetest.OpenWithDialector(t, "lastusedcoalesce_", sqlite.Open, &gorm.Config{Logger: rec})
	require.NoError(t, db.AutoMigrate(models.AllTestModels()...))

	start := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	old := start.Add(-40 * 24 * time.Hour)
	far := start.Add(365 * 24 * time.Hour)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "lu", Email: "lu@example.com", IsActive: true, AccountState: AccountActive, CreatedAt: old}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "viewer"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1}).Error)
	require.NoError(t, db.Create(&models.PersonalAccessToken{ID: 1, UserID: 1, Name: "ci", TokenHash: sha256Hex(luPATRaw), CreatedAt: old}).Error)
	require.NoError(t, db.Create(&models.Session{ID: 1, UserID: 1, SessionToken: sha256Hex(luSessionRaw), CreatedAt: old, ExpiresAt: &far}).Error)
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p"}).Error)
	require.NoError(t, db.Create(&models.MachineIdentity{ID: 1, ProjectID: 1, Name: "bot", State: MachineActive, CreatedAt: old}).Error)
	require.NoError(t, db.Create(&models.MachineIdentityCredential{ID: 1, MachineIdentityID: 1, Name: "c", TokenHash: sha256Hex(luMachineRaw), CreatedAt: old}).Error)

	w := &lastUsedWorld{db: db, rec: rec, now: start}
	w.core = NewKeyorixCore(store.NewLocalStorage(db))
	w.core.now = w.clock
	return w
}

// request runs the core half of one authenticated request of each kind,
// exactly as the HTTP middleware / gRPC interceptor call it: validate, then
// (network check passed) touch.
func (w *lastUsedWorld) request(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	_, _, _, patID, err := w.core.ValidatePATToken(ctx, luPATRaw)
	require.NoError(t, err)
	w.core.TouchPATLastUsed(ctx, patID)

	_, _, _, credID, err := w.core.ValidateMachineToken(ctx, luMachineRaw)
	require.NoError(t, err)
	w.core.TouchMachineTokenLastUsed(ctx, credID)

	_, _, err = w.core.ValidateSessionToken(ctx, luSessionRaw)
	require.NoError(t, err)
}

func (w *lastUsedWorld) stored(t *testing.T) (pat, cred, sess *time.Time) {
	t.Helper()
	var p models.PersonalAccessToken
	require.NoError(t, w.db.First(&p, 1).Error)
	var c models.MachineIdentityCredential
	require.NoError(t, w.db.First(&c, 1).Error)
	var s models.Session
	require.NoError(t, w.db.First(&s, 1).Error)
	return p.LastUsedAt, c.LastUsedAt, s.LastSeenAt
}

// TestLastUsed_RequestPathRunsNoLastUsedStatement is the statement-count proof:
// 50 authenticated requests of each kind (PAT, machine token, session), with the
// clock advancing past the old 30 s throttle between them so the old inline
// stamp would really have written every time, run ZERO statements that write a
// last-used column. On main this is 150 UPDATEs. The flush then writes exactly
// one UPDATE per credential, carrying the newest use.
func TestLastUsed_RequestPathRunsNoLastUsedStatement(t *testing.T) {
	w := newLastUsedWorld(t)
	w.rec.reset()
	for range 50 {
		w.request(t)
		w.advance(31 * time.Second)
	}
	if writes := w.rec.lastUsedWrites(); len(writes) != 0 {
		t.Errorf("the request path must not write last_used_at / last_seen_at: %d UPDATE(s), first %q", len(writes), writes[0])
	}

	lastUse := w.clock().Add(-31 * time.Second)
	w.rec.reset()
	w.core.FlushLastUsed(context.Background())
	assert.Len(t, w.rec.lastUsedWrites(), 3, "one UPDATE per credential per flush")

	pat, cred, sess := w.stored(t)
	for name, v := range map[string]*time.Time{"pat": pat, "machine credential": cred, "session": sess} {
		require.NotNil(t, v, name)
		assert.True(t, v.Equal(lastUse), "%s: stored %v, want the newest use %v", name, v, lastUse)
	}

	// Nothing pending: a second flush writes nothing.
	w.rec.reset()
	w.core.FlushLastUsed(context.Background())
	assert.Empty(t, w.rec.lastUsedWrites())
}

// TestLastUsed_RejectedRequestRecordsNothing keeps the touch-after-gate rule:
// a request refused by validation (suspended account) records no use.
func TestLastUsed_RejectedRequestRecordsNothing(t *testing.T) {
	w := newLastUsedWorld(t)
	require.NoError(t, w.db.Model(&models.User{}).Where("id = 1").Update("account_state", AccountSuspended).Error)
	ctx := context.Background()
	_, _, _, patID, err := w.core.ValidatePATToken(ctx, luPATRaw)
	require.Error(t, err)
	w.core.TouchPATLastUsed(ctx, patID) // patID is 0 on failure
	_, _, err = w.core.ValidateSessionToken(ctx, luSessionRaw)
	require.Error(t, err)

	w.core.FlushLastUsed(ctx)
	pat, _, sess := w.stored(t)
	assert.Nil(t, pat)
	assert.Nil(t, sess)
}

// TestLastUsed_FlushIsMonotonicAcrossReplicas: two replicas (two cores, two
// LocalStorage instances over the same database) flush observations in either
// order; the column ends at the newer one and never goes backwards.
func TestLastUsed_FlushIsMonotonicAcrossReplicas(t *testing.T) {
	for _, newerFirst := range []bool{true, false} {
		w := newLastUsedWorld(t)
		t1 := w.clock()
		t2 := t1.Add(10 * time.Second)
		a := NewKeyorixCore(store.NewLocalStorage(w.db))
		b := NewKeyorixCore(store.NewLocalStorage(w.db))
		a.now = func() time.Time { return t2 }
		b.now = func() time.Time { return t1 }
		for _, c := range []*KeyorixCore{a, b} {
			c.TouchPATLastUsed(context.Background(), 1)
			c.TouchMachineTokenLastUsed(context.Background(), 1)
		}
		first, second := a, b
		if !newerFirst {
			first, second = b, a
		}
		first.FlushLastUsed(context.Background())
		second.FlushLastUsed(context.Background())
		pat, cred, _ := w.stored(t)
		require.NotNil(t, pat)
		require.NotNil(t, cred)
		assert.True(t, pat.Equal(t2), "newerFirst=%v: pat %v want %v", newerFirst, pat, t2)
		assert.True(t, cred.Equal(t2), "newerFirst=%v: cred %v want %v", newerFirst, cred, t2)
	}
}

// TestLastUsed_TimerFlushesWithinInterval: with no explicit flush, a recorded use
// reaches the database by itself within the interval, and repeated uses inside
// one interval cost one UPDATE.
func TestLastUsed_TimerFlushesWithinInterval(t *testing.T) {
	w := newLastUsedWorld(t)
	w.core.lastUsedAgg = newLastUsedCoalescer(100*time.Millisecond, lastUsedMaxPending)
	w.rec.reset()
	for range 200 {
		w.core.TouchMachineTokenLastUsed(context.Background(), 1)
	}
	require.Eventually(t, func() bool {
		_, cred, _ := w.stored(t)
		return cred != nil
	}, 5*time.Second, 20*time.Millisecond, "the timer must flush a recorded use without an explicit flush")
	assert.Len(t, w.rec.lastUsedWrites(), 1, "200 uses inside one interval are one UPDATE")
}

// TestLastUsed_FailedWriteIsRetried: a write that fails goes back to pending and
// is written by a later flush instead of being dropped; a newer use recorded in
// between wins.
func TestLastUsed_FailedWriteIsRetried(t *testing.T) {
	a := newLastUsedCoalescer(time.Hour, lastUsedMaxPending)
	var fail atomic.Bool
	fail.Store(true)
	var mu sync.Mutex
	written := map[lastUsedKey]time.Time{}
	a.write = func(_ context.Context, k lastUsedKey, at time.Time) error {
		if fail.Load() {
			return errors.New("db down")
		}
		mu.Lock()
		written[k] = at
		mu.Unlock()
		return nil
	}
	k := lastUsedKey{lastUsedPAT, 9}
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	a.record(k, t0)
	a.flush(context.Background())
	got, ok := a.pendingAt(k)
	require.True(t, ok, "a failed write must stay pending")
	assert.True(t, got.Equal(t0))

	a.record(k, t0.Add(-time.Minute)) // an older observation does not regress it
	fail.Store(false)
	a.flush(context.Background())
	mu.Lock()
	defer mu.Unlock()
	assert.True(t, written[k].Equal(t0))
	_, ok = a.pendingAt(k)
	assert.False(t, ok)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.timer != nil {
		a.timer.Stop()
	}
}

// TestLastUsed_MaxPendingFlushesEarly: reaching the cap starts a flush at once.
func TestLastUsed_MaxPendingFlushesEarly(t *testing.T) {
	a := newLastUsedCoalescer(time.Hour, 3)
	var n atomic.Int32
	a.write = func(context.Context, lastUsedKey, time.Time) error { n.Add(1); return nil }
	now := time.Now()
	for i := range 3 {
		a.record(lastUsedKey{lastUsedSession, uint(i + 1)}, now)
	}
	require.Eventually(t, func() bool { return n.Load() == 3 }, 5*time.Second, 10*time.Millisecond)
}

// TestLastUsed_ReadersSeeUseWithinBound is the freshness proof for every reader
// of the three columns (inventory in the PR body). Before the flush a reader
// may still show the previous value (here: a 40-day-old creation, never used),
// which is the documented staleness of at most lastUsedFlushInterval; after it,
// every reader reports the use and no longer counts the credential as stale.
func TestLastUsed_ReadersSeeUseWithinBound(t *testing.T) {
	w := newLastUsedWorld(t)
	ctx := context.Background()
	w.request(t)
	use := w.clock()
	w.core.FlushLastUsed(ctx)

	staleAfter := 30 * 24 * time.Hour
	thresholdFor := func() time.Time { return w.clock().Add(-staleAfter) }

	t.Run("ListOwnPATs (GET /api/v1/pats, CLI pat list)", func(t *testing.T) {
		pats, err := w.core.ListOwnPATs(ctx, 1)
		require.NoError(t, err)
		require.Len(t, pats, 1)
		require.NotNil(t, pats[0].LastUsedAt)
		assert.True(t, pats[0].LastUsedAt.Equal(use))
	})
	t.Run("ListPATHygiene", func(t *testing.T) {
		entries, err := w.core.ListPATHygiene(ctx, staleAfter)
		require.NoError(t, err)
		for _, e := range entries {
			assert.False(t, e.Stale, "a just-used PAT must not be reported stale")
		}
	})
	t.Run("CountStalePATs (hygiene trends)", func(t *testing.T) {
		n, err := w.core.storage.CountStalePATs(ctx, thresholdFor())
		require.NoError(t, err)
		assert.Zero(t, n)
	})
	t.Run("ListMachineTokens (HTTP + gRPC credential list)", func(t *testing.T) {
		creds, err := w.core.ListMachineTokens(ctx, 1, 1)
		require.NoError(t, err)
		require.Len(t, creds, 1)
		require.NotNil(t, creds[0].LastUsedAt)
		assert.True(t, creds[0].LastUsedAt.Equal(use))
	})
	t.Run("ListMachineTokenHygiene", func(t *testing.T) {
		entries, err := w.core.ListMachineTokenHygiene(ctx, staleAfter)
		require.NoError(t, err)
		for _, e := range entries {
			assert.False(t, e.Stale, "a just-used machine credential must not be reported stale")
		}
	})
	t.Run("CountStaleMachineCredentials (hygiene trends)", func(t *testing.T) {
		n, err := w.core.storage.CountStaleMachineCredentials(ctx, thresholdFor())
		require.NoError(t, err)
		assert.Zero(t, n, "a machine identity whose credential was just used is not stale")
	})
	t.Run("GetMachineAuditReport", func(t *testing.T) {
		rep, err := w.core.GetMachineAuditReport(ctx)
		require.NoError(t, err)
		require.Len(t, rep.Machines, 1)
		require.NotNil(t, rep.Machines[0].LastUsedAt)
		assert.True(t, rep.Machines[0].LastUsedAt.Equal(use))
		assert.False(t, rep.Machines[0].IsStale)
	})
	t.Run("ListOwnSessions (My Account sessions view)", func(t *testing.T) {
		sessions, err := w.core.ListOwnSessions(ctx, 1)
		require.NoError(t, err)
		require.Len(t, sessions, 1)
		require.NotNil(t, sessions[0].LastSeenAt)
		assert.True(t, sessions[0].LastSeenAt.Equal(use))
	})
}

// TestLastUsed_OnlyTheCoalescerCallsTheStoreTouches is the static half of
// INV-CORE-last-used-off-request-path: outside the coalescer's own write, no
// non-test file in internal/core or server calls the store's Touch* methods
// (which is how a per-request UPDATE would come back). It recognises the
// method-call form `.TouchX(`; a call through a method value or reflection is
// not seen.
func TestLastUsed_OnlyTheCoalescerCallsTheStoreTouches(t *testing.T) {
	callRE := regexp.MustCompile(`\.(TouchPersonalAccessToken|TouchMachineIdentityCredential|TouchSession)\(`)
	allowed := map[string]bool{"last_used_coalescer.go": true}
	var offenders []string
	for _, root := range []string{".", "../../server"} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			if root == "." && allowed[path] {
				return nil
			}
			src, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for i, line := range strings.Split(string(src), "\n") {
				if code, _, _ := strings.Cut(line, "//"); callRE.MatchString(code) {
					offenders = append(offenders, fmt.Sprintf("%s:%d", path, i+1))
				}
			}
			return nil
		})
		require.NoError(t, err)
	}
	assert.Empty(t, offenders, "record uses through TouchPATLastUsed / TouchMachineTokenLastUsed / lastUsed().record, not the store directly")
}
