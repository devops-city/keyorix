package core

// break_glass_degraded_test.go — BREAKGLASS-OWED-1: break-glass must work
// during an audit-subsystem incident without ever being unrecorded.
//
// On SQLite and on PostgreSQL (set KEYORIX_TEST_PG_DSN; the Postgres leg skips
// without it):
//
//   - the normal path is unchanged: audit rows in the chain, no owed record,
//     not degraded, normal expiry;
//   - the audit append fails (error, effect-then-error, panic, or a wait that
//     never ends — the chain lock): the activation commits TOGETHER WITH a
//     pending_audit_events record of each of its rows, degraded, with the short
//     expiry on both the record and the role grant, and is counted, logged and
//     listed for mandatory review at once;
//   - the audit append fails AND the owed record cannot be written (error,
//     panic): refused with ErrBreakGlassUnrecordable pointing to recover-admin,
//     and nothing changed;
//   - crash (runtime.Goexit, the in-process stand-in for kill -9) at the audit
//     append, at the owed-record insert, and in the backfill's append: never an
//     activation without its rows or its owed records;
//   - the backfill writes the owed rows into the chain in id order with their
//     original event times, settles the activation in the same transaction, is
//     idempotent, and the chain verifies.
//
// Red on main: the activation failed closed (ErrMutationAuditUnavailable) on
// every audit failure — break-glass did not work during an audit incident.

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/auditverify"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
)

type bgdFault int32

const (
	bgdOK bgdFault = iota
	bgdError
	bgdEffectThenError
	bgdPanic
	bgdHang
	bgdCrash
)

func (f bgdFault) String() string {
	return [...]string{"ok", "error", "effect-then-error", "panic", "hang", "crash"}[f]
}

// bgdStore injects faults into the audit append and the owed-record insert,
// inside and outside transactions (WrapTx). A crash fault ends the calling goroutine
// (deferred rollbacks run, nothing after them does) and disarms itself.
func bgdStore(inner storage.Storage, audit, pending *atomic.Int32) storage.Storage {
	return hooked(inner, &storeHooks{
		WrapTx: true,
		LogAuditEvent: func(next storage.Storage, ctx context.Context, e *models.AuditEvent) error {
			return bgdInject(ctx, audit, "audit append", func() error { return next.LogAuditEvent(ctx, e) })
		},
		CreatePendingAuditEvent: func(next storage.Storage, ctx context.Context, p *models.PendingAuditEvent) error {
			return bgdInject(ctx, pending, "owed-audit record", func() error { return next.CreatePendingAuditEvent(ctx, p) })
		},
	})
}

func bgdInject(ctx context.Context, slot *atomic.Int32, what string, real func() error) error {
	switch bgdFault(slot.Load()) {
	case bgdError:
		return fmt.Errorf("injected: %s refused", what)
	case bgdEffectThenError:
		_ = real()
		return fmt.Errorf("injected: %s wrote, then reported an error", what)
	case bgdPanic:
		panic("injected: " + what + " panicked")
	case bgdHang:
		// The chain lock that does not come: the real store gives up after its own
		// auditWriteTimeout (10 s, a detached context) and reports the deadline;
		// this stands in for that with a short wait. The real lock is
		// TestBreakGlass_AuditChainLockHeldGoesDegraded_Postgres.
		time.Sleep(200 * time.Millisecond)
		return fmt.Errorf("injected: %s waited for the chain lock: %w", what, context.DeadlineExceeded)
	case bgdCrash:
		slot.Store(int32(bgdOK))
		runtime.Goexit()
	}
	return real()
}

type bgdWorld struct {
	t              *testing.T
	f              *ctaReview
	db             *gorm.DB
	audit, pending *atomic.Int32
	c              *KeyorixCore
	seq            int
}

func newBGDWorld(t *testing.T, f *ctaReview) *bgdWorld {
	t.Helper()
	w := &bgdWorld{t: t, f: f, db: f.dbA, audit: &atomic.Int32{}, pending: &atomic.Int32{}}
	w.c = NewKeyorixCore(bgdStore(localstore.NewLocalStorage(f.dbA), w.audit, w.pending))
	w.c.SetBreakGlassPolicy(BreakGlassPolicy{Enabled: true, EmergencyRole: "project_developer", DefaultTTL: time.Hour, MaxTTL: 4 * time.Hour})
	return w
}

func bgdBackends(t *testing.T, fn func(t *testing.T, w *bgdWorld)) {
	t.Run("sqlite", func(t *testing.T) { fn(t, newBGDWorld(t, newCTAReviewSQLite(t))) })
	t.Run("postgres", func(t *testing.T) { fn(t, newBGDWorld(t, newCTAReview(t))) })
}

func (w *bgdWorld) member() *models.User {
	w.seq++
	return w.f.user(fmt.Sprintf("bgd-u%d", w.seq), "project_viewer")
}

func (w *bgdWorld) activate(u *models.User, ttl string) (*models.BreakGlassActivation, error) {
	return w.c.ActivateBreakGlass(context.Background(), w.f.projectID, u.ID, "production outage, paging incident commander now", ttl)
}

// state is everything an activation of u may write: its activation rows, its
// role grants, owed records, and its audit rows.
func (w *bgdWorld) state(u *models.User) string {
	w.t.Helper()
	count := func(model any, where string, args ...any) int64 {
		var n int64
		require.NoError(w.t, w.db.Model(model).Where(where, args...).Count(&n).Error)
		return n
	}
	return fmt.Sprintf("activations=%d grants=%d pending=%d audit=%d",
		count(&models.BreakGlassActivation{}, "user_id = ?", u.ID),
		count(&models.UserRole{}, "user_id = ?", u.ID),
		count(&models.PendingAuditEvent{}, "1 = 1"),
		count(&models.AuditEvent{}, "user_id = ? AND event_type IN ?", u.ID, []string{EventRoleAssigned, EventBreakGlassActivated}))
}

func (w *bgdWorld) auditRows(u *models.User, eventType string) []models.AuditEvent {
	w.t.Helper()
	var rows []models.AuditEvent
	require.NoError(w.t, w.db.Where("user_id = ? AND event_type = ?", u.ID, eventType).Order("id").Find(&rows).Error)
	return rows
}

func (w *bgdWorld) owed(activationID uint) []models.PendingAuditEvent {
	w.t.Helper()
	var rows []models.PendingAuditEvent
	require.NoError(w.t, w.db.Where("break_glass_activation_id = ?", activationID).Order("id").Find(&rows).Error)
	return rows
}

func (w *bgdWorld) reload(id uint) *models.BreakGlassActivation {
	w.t.Helper()
	var a models.BreakGlassActivation
	require.NoError(w.t, w.db.First(&a, id).Error)
	return &a
}

func (w *bgdWorld) grantExpiry(u *models.User) time.Time {
	w.t.Helper()
	var ur models.UserRole
	require.NoError(w.t, w.db.Where("user_id = ? AND expires_at IS NOT NULL", u.ID).First(&ur).Error)
	require.NotNil(w.t, ur.ExpiresAt)
	return *ur.ExpiresAt
}

// offlineVerify runs the offline verifier (verify-audit's engine) against the
// SQLite file, so its owed-break-glass query is checked against the real migrated
// schema. nil on Postgres (the query is the same; the isolated-schema DSN is not
// at hand here).
func (w *bgdWorld) offlineVerify() *auditverify.Result {
	w.t.Helper()
	if w.db.Dialector.Name() == "postgres" {
		return nil
	}
	var rows []struct {
		Seq  int
		Name string
		File string
	}
	require.NoError(w.t, w.db.Raw("PRAGMA database_list").Scan(&rows).Error)
	require.NotEmpty(w.t, rows)
	vdb, err := auditverify.OpenSQLiteReadOnly(rows[0].File)
	require.NoError(w.t, err)
	defer func() { _ = vdb.Close() }()
	r, err := auditverify.Verify(context.Background(), vdb, auditverify.Options{})
	require.NoError(w.t, err)
	return r
}

func (w *bgdWorld) requireChainValid() {
	w.t.Helper()
	v, err := w.c.Storage().VerifyAuditChain(context.Background(), nil)
	require.NoError(w.t, err)
	require.True(w.t, v.Valid, "the audit chain must verify: %s", v.Reason)
}

// requireDegraded asserts a committed degraded activation: owed records of both
// rows linked to it, none of its rows in the chain yet, the short expiry on the
// record and on the grant, listed for review at once.
func (w *bgdWorld) requireDegraded(u *models.User, a *models.BreakGlassActivation, normalTTL time.Duration) {
	w.t.Helper()
	require.True(w.t, a.Degraded, "an activation the audit log refused must be marked degraded")
	stored := w.reload(a.ID)
	require.True(w.t, stored.Degraded)
	require.Nil(w.t, stored.AuditSettledAt, "nothing is in the chain yet, so it is not settled")
	require.NotNil(w.t, stored.ExpiresAt)
	life := stored.ExpiresAt.Sub(stored.CreatedAt)
	require.LessOrEqual(w.t, life, defaultBreakGlassDegradedTTL+time.Second, "a degraded activation is short-lived (15 min default)")
	require.LessOrEqual(w.t, life, normalTTL+time.Second, "a degraded activation never lives longer than a normal one would")
	require.WithinDuration(w.t, *stored.ExpiresAt, w.grantExpiry(u), time.Second, "the role grant expires with the record")

	owed := w.owed(a.ID)
	require.Len(w.t, owed, 2, "both rows (role.assigned, break_glass.activated) must be owed")
	require.Equal(w.t, EventRoleAssigned, owed[0].EventType)
	require.Equal(w.t, EventBreakGlassActivated, owed[1].EventType)
	var ev models.AuditEvent
	require.NoError(w.t, json.Unmarshal([]byte(owed[1].Event), &ev))
	require.Contains(w.t, ev.Description, "DEGRADED")
	require.Contains(w.t, ev.Description, fmt.Sprintf("activation %d", a.ID))
	require.Empty(w.t, w.auditRows(u, EventBreakGlassActivated), "a refused row must not be in the chain")

	unreviewed, err := w.c.ListUnreviewedBreakGlassActivations(context.Background(), 72*time.Hour)
	require.NoError(w.t, err)
	found := false
	for _, r := range unreviewed {
		found = found || r.ID == a.ID
	}
	require.True(w.t, found, "a degraded activation's review is mandatory at once, with no grace window")
}

// requireBackfilled heals nothing itself: the caller has already let the audit
// log accept writes. It runs the backfill and asserts the rows landed with their
// original times, the activation settled with them, and a rerun writes nothing.
func (w *bgdWorld) requireBackfilled(u *models.User, a *models.BreakGlassActivation) {
	w.t.Helper()
	owed := w.owed(a.ID)
	require.Len(w.t, owed, 2)
	var original models.AuditEvent
	require.NoError(w.t, json.Unmarshal([]byte(owed[1].Event), &original))
	time.Sleep(20 * time.Millisecond) // a backfill "now" distinguishable from the original time
	start := time.Now()

	_, err := w.c.BackfillPendingAuditEvents(context.Background())
	require.NoError(w.t, err)
	require.Empty(w.t, w.owed(a.ID))
	rows := w.auditRows(u, EventBreakGlassActivated)
	require.Len(w.t, rows, 1, "the owed break_glass.activated row must be in the chain exactly once")
	require.Len(w.t, w.auditRows(u, EventRoleAssigned), 1, "the owed role.assigned row must be in the chain exactly once")
	require.WithinDuration(w.t, original.EventTime, rows[0].EventTime, time.Millisecond,
		"a backfilled break-glass row keeps its ORIGINAL event time")
	require.True(w.t, rows[0].EventTime.Before(start), "the event time is the activation's, not the backfill's")
	require.Contains(w.t, rows[0].Description, "recorded late")
	roleRows := w.auditRows(u, EventRoleAssigned)
	require.Less(w.t, roleRows[0].ID, rows[0].ID, "owed rows land in the chain in the order they were owed")

	stored := w.reload(a.ID)
	require.NotNil(w.t, stored.AuditSettledAt, "the activation is settled with its last owed row")

	again, err := w.c.BackfillPendingAuditEvents(context.Background())
	require.NoError(w.t, err)
	require.Zero(w.t, again, "the backfill is idempotent")
	require.Len(w.t, w.auditRows(u, EventBreakGlassActivated), 1)
	w.requireChainValid()
}

func TestBreakGlass_NormalPathUnchanged(t *testing.T) {
	bgdBackends(t, func(t *testing.T, w *bgdWorld) {
		u := w.member()
		before := testutil.ToFloat64(breakGlassDegradedActivationsTotal)
		a, err := w.activate(u, "")
		require.NoError(t, err)
		require.False(t, a.Degraded)
		stored := w.reload(a.ID)
		require.False(t, stored.Degraded)
		require.Nil(t, stored.AuditSettledAt, "a normal activation was never owed anything")
		require.WithinDuration(t, stored.CreatedAt.Add(time.Hour), *stored.ExpiresAt, time.Second, "normal expiry (default_ttl)")
		require.Empty(t, w.owed(a.ID))
		require.Len(t, w.auditRows(u, EventBreakGlassActivated), 1)
		require.Len(t, w.auditRows(u, EventRoleAssigned), 1)
		require.NotContains(t, w.auditRows(u, EventBreakGlassActivated)[0].Description, "DEGRADED")
		require.Equal(t, before, testutil.ToFloat64(breakGlassDegradedActivationsTotal))
		st := w.c.BreakGlassDegradedStatus(context.Background())
		require.Zero(t, st.Unsettled)
		require.Zero(t, st.Unreviewed)
		w.requireChainValid()
	})
}

func TestBreakGlass_AuditRefusedCommitsDegradedWithOwedRecord(t *testing.T) {
	bgdBackends(t, func(t *testing.T, w *bgdWorld) {
		for _, fk := range []bgdFault{bgdError, bgdEffectThenError, bgdPanic, bgdHang} {
			t.Run("audit-"+fk.String(), func(t *testing.T) {
				u := w.member()
				before := testutil.ToFloat64(breakGlassDegradedActivationsTotal)
				w.audit.Store(int32(fk))
				a, err := w.activate(u, "")
				w.audit.Store(int32(bgdOK))
				require.NoError(t, err, "break-glass must work while the audit log refuses writes")
				w.requireDegraded(u, a, time.Hour)
				require.Equal(t, before+1, testutil.ToFloat64(breakGlassDegradedActivationsTotal), "keyorix_breakglass_degraded_activations_total")
				st := w.c.BreakGlassDegradedStatus(context.Background())
				require.Contains(t, st.ActivationIDs, a.ID, "the admin banner lists it")
				require.Positive(t, st.Unsettled)

				w.requireBackfilled(u, a)
				require.NotContains(t, w.c.BreakGlassDegradedStatus(context.Background()).ActivationIDs, uint(0))
			})
		}
	})
}

func TestBreakGlass_AuditAndOwedRecordRefusedIsRefused(t *testing.T) {
	bgdBackends(t, func(t *testing.T, w *bgdWorld) {
		for _, pk := range []bgdFault{bgdError, bgdEffectThenError, bgdPanic} {
			t.Run("owed-"+pk.String(), func(t *testing.T) {
				u := w.member()
				before := w.state(u)
				w.audit.Store(int32(bgdError))
				w.pending.Store(int32(pk))
				var a *models.BreakGlassActivation
				err := func() (err error) {
					defer func() {
						if r := recover(); r != nil {
							err = fmt.Errorf("panic escaped the activation: %v", r)
						}
					}()
					a, err = w.activate(u, "")
					return err
				}()
				w.audit.Store(int32(bgdOK))
				w.pending.Store(int32(bgdOK))
				require.Nil(t, a)
				require.ErrorIs(t, err, ErrBreakGlassUnrecordable, "neither the rows nor a record of them: refuse")
				require.Contains(t, err.Error(), "recover-admin", "the refusal must point to the offline recover-admin procedure")
				require.Equal(t, before, w.state(u), "a refused activation must change nothing")
			})
		}
		w.requireChainValid()
	})
}

func TestBreakGlass_CrashNeverLeavesAnUnrecordedActivation(t *testing.T) {
	bgdBackends(t, func(t *testing.T, w *bgdWorld) {
		t.Run("crash-at-audit-append", func(t *testing.T) {
			u := w.member()
			before := w.state(u)
			w.audit.Store(int32(bgdCrash))
			returned, err := runCrashing(func() error { _, err := w.activate(u, ""); return err })
			require.False(t, returned, "precondition: the goroutine must die at the append (err=%v)", err)
			require.Equal(t, bgdOK, bgdFault(w.audit.Load()), "precondition: the crash fired")
			require.Equal(t, before, w.state(u), "a crash at the audit append commits nothing")
		})
		t.Run("crash-at-owed-record", func(t *testing.T) {
			u := w.member()
			before := w.state(u)
			w.audit.Store(int32(bgdError))
			w.pending.Store(int32(bgdCrash))
			returned, err := runCrashing(func() error { _, err := w.activate(u, ""); return err })
			w.audit.Store(int32(bgdOK))
			require.False(t, returned, "precondition: the goroutine must die at the owed-record insert (err=%v)", err)
			require.Equal(t, bgdOK, bgdFault(w.pending.Load()), "precondition: the crash fired")
			require.Equal(t, before, w.state(u), "a crash between the degraded commit's writes commits nothing")
		})
		t.Run("crash-after-degraded-commit-then-restart", func(t *testing.T) {
			u := w.member()
			w.audit.Store(int32(bgdError))
			a, err := w.activate(u, "")
			w.audit.Store(int32(bgdOK))
			require.NoError(t, err)
			w.requireDegraded(u, a, time.Hour)
			// The process dies before any backfill; a NEW process (fresh core,
			// fresh connection pool on the same database) drains the owed rows.
			restarted := NewKeyorixCore(localstore.NewLocalStorage(w.f.dbB))
			_, err = restarted.BackfillPendingAuditEvents(context.Background())
			require.NoError(t, err)
			require.NotNil(t, w.reload(a.ID).AuditSettledAt)
			require.Len(t, w.auditRows(u, EventBreakGlassActivated), 1)
		})
		t.Run("crash-in-backfill-append", func(t *testing.T) {
			u := w.member()
			w.audit.Store(int32(bgdError))
			a, err := w.activate(u, "")
			require.NoError(t, err)
			w.audit.Store(int32(bgdCrash))
			returned, _ := runCrashing(func() error { _, err := w.c.BackfillPendingAuditEvents(context.Background()); return err })
			require.False(t, returned, "precondition: the backfill died at its append")
			require.Len(t, w.owed(a.ID), 2, "the claim rolled back with the append: still owed")
			require.Nil(t, w.reload(a.ID).AuditSettledAt, "not settled without its rows in the chain")
			w.requireBackfilled(u, a)
		})
	})
}

// TestBreakGlass_DegradedTTLNeverLongerThanNormal: a requested or configured
// lifetime cannot stretch a degraded activation.
func TestBreakGlass_DegradedTTLNeverLongerThanNormal(t *testing.T) {
	w := newBGDWorld(t, newCTAReviewSQLite(t))
	for _, tc := range []struct {
		name        string
		degradedTTL time.Duration
		requested   string
		want        time.Duration
	}{
		{"default 15m, long request capped", 0, "4h", 15 * time.Minute},
		{"short request beats the degraded ttl", 0, "5m", 5 * time.Minute},
		{"configured longer than normal is capped at normal", 3 * time.Hour, "", time.Hour},
		{"configured shorter", 2 * time.Minute, "", 2 * time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w.c.SetBreakGlassPolicy(BreakGlassPolicy{Enabled: true, EmergencyRole: "project_developer", DefaultTTL: time.Hour, MaxTTL: 4 * time.Hour,
				DegradedTTL: tc.degradedTTL})
			u := w.member()
			w.audit.Store(int32(bgdError))
			a, err := w.activate(u, tc.requested)
			w.audit.Store(int32(bgdOK))
			require.NoError(t, err)
			require.True(t, a.Degraded)
			require.WithinDuration(t, a.CreatedAt.Add(tc.want), *a.ExpiresAt, time.Second)
			require.WithinDuration(t, *a.ExpiresAt, w.grantExpiry(u), time.Second)
		})
	}
}

// TestBreakGlass_AttackerMakesAuditUnwritable: someone with database access makes
// the audit log refuse every write ON PURPOSE (a trigger), hoping to self-elevate
// without a record. The activation still works — the incident case must — but it
// is recorded (owed, durably, with the elevation), short-lived, cannot be renewed
// while active, alerted (metric, admin notification, status, mandatory review),
// and lands in the chain the moment the audit log is writable again. Making the
// owed-record table unwritable too gets the activation refused outright.
func TestBreakGlass_AttackerMakesAuditUnwritable(t *testing.T) {
	bgdBackends(t, func(t *testing.T, w *bgdWorld) {
		ctx := context.Background()
		block := func(table string) func() {
			name := "bgd_refuse_" + table
			if w.db.Dialector.Name() == "postgres" {
				require.NoError(t, w.db.Exec(`CREATE OR REPLACE FUNCTION bgd_refuse() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'unwritable on purpose'; END $$ LANGUAGE plpgsql`).Error)
				require.NoError(t, w.db.Exec(fmt.Sprintf(`CREATE TRIGGER %s BEFORE INSERT ON %s FOR EACH ROW EXECUTE FUNCTION bgd_refuse()`, name, table)).Error)
				return func() { require.NoError(t, w.db.Exec(fmt.Sprintf(`DROP TRIGGER %s ON %s`, name, table)).Error) }
			}
			require.NoError(t, w.db.Exec(fmt.Sprintf(`CREATE TRIGGER %s BEFORE INSERT ON %s BEGIN SELECT RAISE(ABORT, 'unwritable on purpose'); END`, name, table)).Error)
			return func() { require.NoError(t, w.db.Exec(fmt.Sprintf(`DROP TRIGGER %s`, name)).Error) }
		}

		// The attacker's own account: a plain project member.
		attacker := w.member()
		metric := testutil.ToFloat64(breakGlassDegradedActivationsTotal)
		unblockAudit := block("audit_events")

		a, err := w.activate(attacker, "24h")
		require.NoError(t, err)
		w.requireDegraded(attacker, a, 4*time.Hour)
		require.WithinDuration(t, a.CreatedAt.Add(defaultBreakGlassDegradedTTL), *a.ExpiresAt, time.Second,
			"a 24h request is cut to the 15-minute degraded lifetime")
		require.Equal(t, metric+1, testutil.ToFloat64(breakGlassDegradedActivationsTotal))

		// Not renewable while active, even with the audit log still down.
		_, err = w.activate(attacker, "")
		require.Error(t, err, "a second activation while the first is active must be refused")
		require.Len(t, w.owed(a.ID), 2)

		// Alerted to the project's admins, in words that say what happened.
		var notes []models.Notification
		require.NoError(t, w.db.Where("title LIKE ?", "%DEGRADED%").Find(&notes).Error)
		require.NotEmpty(t, notes, "the project's admins must be notified of a degraded activation")
		st := w.c.BreakGlassDegradedStatus(ctx)
		require.Equal(t, int64(1), st.Unsettled)
		require.Equal(t, int64(1), st.Unreviewed)
		require.Equal(t, []uint{a.ID}, st.ActivationIDs)

		// verify-audit (offline, independent of this code) reports it as owed.
		if r := w.offlineVerify(); r != nil {
			require.Equal(t, []uint64{uint64(a.ID)}, r.OwedBreakGlass.ActivationIDs)
			require.Equal(t, auditverify.VerdictIndeterminate, r.Verdict, "the chain is known to be missing the elevation's rows")
		}

		// The backfill cannot write while the audit log refuses; nothing is lost.
		_, err = w.c.BackfillPendingAuditEvents(ctx)
		require.Error(t, err)
		require.Len(t, w.owed(a.ID), 2)

		// Making the owed-record table unwritable too gets the next attempt
		// (another member) refused outright: never unrecorded.
		other := w.member()
		beforeOther := w.state(other)
		unblockPending := block("pending_audit_events")
		_, err = w.activate(other, "")
		require.ErrorIs(t, err, ErrBreakGlassUnrecordable)
		require.True(t, strings.Contains(err.Error(), "recover-admin"))
		require.Equal(t, beforeOther, w.state(other))
		unblockPending()

		// The audit log comes back: the elevation is in the chain, with its time.
		unblockAudit()
		w.requireBackfilled(attacker, a)
		st = w.c.BreakGlassDegradedStatus(ctx)
		require.Zero(t, st.Unsettled)
		require.Equal(t, int64(1), st.Unreviewed, "settling the audit rows does not replace the mandatory review")
		if r := w.offlineVerify(); r != nil {
			require.True(t, r.OwedBreakGlass.Checked)
			require.Zero(t, r.OwedBreakGlass.Unsettled)
			require.Equal(t, auditverify.VerdictValid, r.Verdict, r.Reason)
		}
	})
}

// TestBreakGlassDegradedTTLDefaultMatchesConfig keeps core's duplicated 15m
// default honest against internal/config's (same reasoning as
// TestBreakGlassReviewWindowDefaultMatchesConfig).
func TestBreakGlassDegradedTTLDefaultMatchesConfig(t *testing.T) {
	require.Equal(t, config.BreakGlassConfig{}.GetDegradedTTL(), defaultBreakGlassDegradedTTL)
}

// TestBreakGlass_AuditChainLockHeldGoesDegraded_Postgres: the "lock" case for
// real. Another session holds the audit chain's advisory lock (the one every
// append takes, local_audit_chain.go), so the activation's append cannot get it.
// After the audit write path's own bound (auditWriteTimeout, 10 s, a detached
// context in internal/storage/store) the activation commits degraded instead of
// failing; once the lock is released the backfill writes its rows.
func TestBreakGlass_AuditChainLockHeldGoesDegraded_Postgres(t *testing.T) {
	w := newBGDWorld(t, newCTAReview(t))
	ctx := context.Background()
	sqlDB, err := w.f.dbB.DB()
	require.NoError(t, err)
	conn, err := sqlDB.Conn(ctx)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	const auditAdvisoryLockKey = 0x4B455941_55444954 // local_audit_chain.go ("KEYAUDIT")
	_, err = conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", int64(auditAdvisoryLockKey))
	require.NoError(t, err)
	locked := true
	defer func() {
		if locked {
			_, _ = conn.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", int64(auditAdvisoryLockKey))
		}
	}()

	u := w.member()
	start := time.Now()
	a, err := w.activate(u, "")
	require.NoError(t, err, "a held chain lock must not block emergency access")
	require.Less(t, time.Since(start), 20*time.Second, "bounded by the audit write path's 10 s, not by the lock holder")
	w.requireDegraded(u, a, time.Hour)

	_, err = conn.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", int64(auditAdvisoryLockKey))
	require.NoError(t, err)
	locked = false
	w.requireBackfilled(u, a)
}
