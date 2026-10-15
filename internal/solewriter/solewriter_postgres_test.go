package solewriter

// solewriter_postgres_test.go — the holder lock, the write fence, the epoch,
// the lease and the emergency two-step against a real PostgreSQL schema
// migrated by the production storage factory. pg-gated (KEYORIX_TEST_PG_DSN).
//
// The tests do not run in parallel: the session tag is process-wide
// (config.SetSoleWriterSessionTag), exactly as in a server. A "foreign"
// session (an operator's psql, a second process) is a plain gorm.Open of the
// DSN, which never carries the tag.

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
)

var swSchemaSeq atomic.Int64

// swWorld is one migrated schema: its DSN, a config pointing at it, a foreign
// session and one machine credential.
type swWorld struct {
	t       *testing.T
	dsn     string
	schema  string
	cfg     *config.Config
	foreign *gorm.DB
	credID  uint
}

func newSWWorld(t *testing.T) *swWorld {
	t.Helper()
	base := os.Getenv("KEYORIX_TEST_PG_DSN")
	if base == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set — single_writer needs PostgreSQL")
	}
	t.Cleanup(config.ClearSoleWriterSessionTagForTest)
	schema := fmt.Sprintf("sw_%d_%d", os.Getpid(), swSchemaSeq.Add(1))
	admin, err := gorm.Open(postgres.Open(base), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, admin.Exec("DROP SCHEMA IF EXISTS "+schema+" CASCADE").Error)
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() {
		_ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error
		if d, err := admin.DB(); err == nil {
			_ = d.Close()
		}
	})
	dsn := pgdsn.PGSearchPathDSN(base, schema)
	cfg := &config.Config{Storage: config.StorageConfig{Type: "postgres", Database: config.DatabaseConfig{DSN: dsn}}}
	st, err := storage.NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	// Close the migration pool: left open, every world keeps its connections
	// until the process ends and a full run exhausts max_connections.
	if c, ok := st.(interface{ Close() error }); ok {
		t.Cleanup(func() { _ = c.Close() })
	}
	w := &swWorld{t: t, dsn: dsn, schema: schema, cfg: cfg, foreign: w0open(t, dsn)}
	p := models.Project{Name: "sw-project"}
	require.NoError(t, w.foreign.Create(&p).Error)
	m := models.MachineIdentity{ProjectID: p.ID, Name: "sw-machine", State: "active"}
	require.NoError(t, w.foreign.Create(&m).Error)
	c := models.MachineIdentityCredential{MachineIdentityID: m.ID, Name: "sw", TokenHash: "h-" + schema, TokenPrefix: "kx"}
	require.NoError(t, w.foreign.Create(&c).Error)
	w.credID = c.ID
	return w
}

func w0open(t *testing.T, dsn string) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	t.Cleanup(func() {
		if d, err := db.DB(); err == nil {
			_ = d.Close()
		}
	})
	return db
}

// start runs the server's boot sequence: Start, InstallFence, Settle, Run.
func (w *swWorld) start(opts Options) *Guard {
	w.t.Helper()
	opts.SkipPresenceCensus = true // other packages' servers share this database in CI
	if opts.LockWait == 0 {
		opts.LockWait = 500 * time.Millisecond
	}
	g, err := Start(context.Background(), w.cfg, opts)
	require.NoError(w.t, err)
	w.t.Cleanup(g.Close)
	require.NoError(w.t, g.InstallFence(context.Background()))
	require.NoError(w.t, g.Settle(context.Background()))
	g.Run(context.Background())
	return g
}

// own opens a session the way the server's pools do (tagged).
func (w *swWorld) own() *gorm.DB {
	w.t.Helper()
	cc, err := config.ResolvePostgresConnConfig(&w.cfg.Storage.Database)
	require.NoError(w.t, err)
	db, err := gorm.Open(postgres.New(postgres.Config{Conn: stdlibOpen(cc)}), &gorm.Config{Logger: logger.Discard})
	require.NoError(w.t, err)
	w.t.Cleanup(func() {
		if d, err := db.DB(); err == nil {
			_ = d.Close()
		}
	})
	return db
}

func (w *swWorld) revoked() bool {
	w.t.Helper()
	var c models.MachineIdentityCredential
	require.NoError(w.t, w.foreign.First(&c, w.credID).Error)
	return c.Revoked
}

func (w *swWorld) epoch(db *gorm.DB) int64 {
	w.t.Helper()
	var n int64
	require.NoError(w.t, db.Raw("SELECT n FROM "+EpochTable+" WHERE id = 1").Scan(&n).Error)
	return n
}

func requireFenced(t *testing.T, err error, what string) {
	t.Helper()
	require.Error(t, err, "%s: the fence let a foreign write through while the holder runs", what)
	require.Contains(t, err.Error(), "keyorix single_writer", "%s: refused, but not by the fence", what)
}

func waitFor(t *testing.T, within time.Duration, cond func() bool) time.Duration {
	t.Helper()
	start := time.Now()
	for time.Since(start) < within {
		if cond() {
			return time.Since(start)
		}
		time.Sleep(20 * time.Millisecond)
	}
	return -1
}

func TestStart_SecondHolderRefused(t *testing.T) {
	w := newSWWorld(t)
	w.start(Options{})
	_, err := Start(context.Background(), w.cfg, Options{LockWait: 300 * time.Millisecond, SkipPresenceCensus: true})
	require.ErrorIs(t, err, ErrLockHeld)
}

func TestStart_RefusedWhileAnotherServerIsAttached(t *testing.T) {
	w := newSWWorld(t)
	other := w0open(t, w.dsn)
	sqlDB, err := other.DB()
	require.NoError(t, err)
	conn, err := sqlDB.Conn(context.Background())
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck
	_, err = conn.ExecContext(context.Background(), "SELECT pg_advisory_lock_shared($1)", serverPresenceLockKey)
	require.NoError(t, err)
	_, err = Start(context.Background(), w.cfg, Options{LockWait: 300 * time.Millisecond, ExpectOwnPresence: false})
	require.Error(t, err)
	require.Contains(t, err.Error(), "other Keyorix server(s) are attached")
}

// TestFence_RefusesEveryForeignWriteWhileHolderLives: every fenced table,
// every statement kind, also under session_replication_role = replica (what
// pg_restore and logical replication run with). The holder's own sessions
// write and move the epoch; the bookkeeping-only column does neither.
func TestFence_RefusesEveryForeignWriteWhileHolderLives(t *testing.T) {
	w := newSWWorld(t)
	g := w.start(Options{})
	ctx := context.Background()

	err := w.foreign.Exec("UPDATE machine_identity_credentials SET revoked = true WHERE id = ?", w.credID).Error
	requireFenced(t, err, "UPDATE revoked")
	require.False(t, w.revoked(), "the refused revocation must not have been applied")

	for _, tbl := range FencedTableNames() {
		err := w.foreign.Transaction(func(tx *gorm.DB) error {
			return tx.Exec("TRUNCATE " + tbl + " CASCADE").Error
		})
		requireFenced(t, err, "TRUNCATE "+tbl)
		// The guards are per row (a statement-level one is skipped by a write
		// through a parent), so a DELETE is refused when it reaches a row; a
		// zero-row statement changes nothing and fires nothing.
		var rows int64
		require.NoError(t, w.foreign.Raw("SELECT count(*) FROM "+tbl).Scan(&rows).Error)
		if rows > 0 && tbl != "system_metadata" {
			requireFenced(t, w.foreign.Exec("DELETE FROM "+tbl).Error, "DELETE "+tbl)
		}
	}
	requireFenced(t, w.foreign.Exec("INSERT INTO machine_identities (project_id, name, state, created_at, updated_at) SELECT project_id, name || '2', state, now(), now() FROM machine_identities").Error, "INSERT ... SELECT")
	requireFenced(t, w.foreign.Exec("UPDATE projects SET name = name || '2'").Error, "UPDATE projects")
	err = w.foreign.Exec("INSERT INTO system_metadata (key, value, updated_at) VALUES ('role_permissions_generation', '7', now()) ON CONFLICT (key) DO UPDATE SET value = '7'").Error
	requireFenced(t, err, "system_metadata generation row")
	require.NoError(t, w.foreign.Exec("INSERT INTO system_metadata (key, value, updated_at) VALUES ('sw-unrelated', 'x', now())").Error,
		"system_metadata rows other than the generation are not fenced")

	err = w.foreign.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("SET LOCAL session_replication_role = replica").Error; err != nil {
			return err
		}
		return tx.Exec("UPDATE machine_identity_credentials SET revoked = true WHERE id = ?", w.credID).Error
	})
	requireFenced(t, err, "replica-role session")

	// A session on another search_path writing schema-qualified names meets
	// the same fence (the holder is looked up for the TABLE's schema).
	other := w0open(t, os.Getenv("KEYORIX_TEST_PG_DSN"))
	requireFenced(t, other.Exec("UPDATE "+w.schema+".machine_identity_credentials SET revoked = true WHERE id = ?", w.credID).Error, "schema-qualified write from another search_path")

	for _, own := range []string{HolderTable, EpochTable} {
		requireFenced(t, w.foreign.Exec("UPDATE "+own+" SET id = id").Error, "UPDATE "+own)
	}

	// last_used_at alone: neither fenced nor counted.
	e0 := w.epoch(w.foreign)
	require.NoError(t, w.foreign.Exec("UPDATE machine_identity_credentials SET last_used_at = now() WHERE id = ?", w.credID).Error)
	require.Equal(t, e0, w.epoch(w.foreign), "a last_used_at-only update must not move the epoch")

	// The holder's own session writes, and the epoch moves in the same commit.
	own := w.own()
	require.NoError(t, own.Exec("UPDATE machine_identity_credentials SET revoked = true WHERE id = ?", w.credID).Error)
	require.True(t, w.revoked())
	require.Greater(t, w.epoch(w.foreign), e0)
	require.Eventually(t, func() bool { return g.Epoch() > e0 }, 2*time.Second, 20*time.Millisecond, "the poller must see the new epoch")
	_ = ctx
}

// TestFence_OpenWithoutALiveHolder: a stopped (or crashed) server never
// blocks a write, so recovery never needs the server.
func TestFence_OpenWithoutALiveHolder(t *testing.T) {
	w := newSWWorld(t)
	g := w.start(Options{})
	requireFenced(t, w.foreign.Exec("UPDATE machine_identity_credentials SET revoked = true WHERE id = ?", w.credID).Error, "while live")
	g.Close()
	require.Eventually(t, func() bool {
		return w.foreign.Exec("UPDATE machine_identity_credentials SET revoked = true WHERE id = ?", w.credID).Error == nil
	}, 5*time.Second, 50*time.Millisecond, "after the holder is gone the fence must let writes through")
	require.True(t, w.revoked())
}

// TestEmergencyTwoStep is the documented emergency path (Andrei 2026-10-15,
// decision 3): a direct revocation is refused while the server runs;
// terminating the holder's lock session opens the fence at once, the
// revocation commits, and the server leaves the authoritative state within
// the lease and does not return to it.
func TestEmergencyTwoStep(t *testing.T) {
	w := newSWWorld(t)
	g := w.start(Options{})
	require.Eventually(t, g.Authoritative, 2*time.Second, 20*time.Millisecond)

	requireFenced(t, w.foreign.Exec("UPDATE machine_identity_credentials SET revoked = true WHERE id = ?", w.credID).Error, "step 0")

	var terminated bool
	require.NoError(t, w.foreign.Raw("SELECT pg_terminate_backend(holder_pid) FROM "+HolderTable).Scan(&terminated).Error)
	require.True(t, terminated)
	start := time.Now()
	require.Eventually(t, func() bool {
		return w.foreign.Exec("UPDATE machine_identity_credentials SET revoked = true WHERE id = ?", w.credID).Error == nil
	}, 5*time.Second, 20*time.Millisecond, "step 2: the revocation must commit once the holder's lock session is gone")
	require.True(t, w.revoked())

	d := waitFor(t, 3*time.Second, func() bool { return !g.Authoritative() })
	require.GreaterOrEqual(t, d, time.Duration(0), "the server must stop trusting its caches")
	require.LessOrEqual(t, time.Since(start), LeaseDuration+PollInterval+200*time.Millisecond,
		"the server must stop trusting its caches within the lease of the terminate")
	time.Sleep(3 * PollInterval)
	require.False(t, g.Authoritative(), "a lost holder lock must not be re-entered without a restart")
	st := g.Status()
	require.Equal(t, StateConfirming, st.State)
	t.Logf("emergency: stopped trusting caches %s after the terminate; status: %s (%s)", time.Since(start).Round(time.Millisecond), st.State, st.Reason)
}

// TestPoll_FenceTamperingLeavesAuthoritativeForGood: a table owner or
// superuser disabling, replacing or working around a fence trigger is seen on
// the next poll. Each case is a list of transactions, each a list of
// statements. The restore-the-same-state cases (toggle inside one
// transaction, toggle split over two, drop and re-create the identical
// trigger, re-create the identical function) leave every definition and
// enabled flag as it was, so only the catalog rows' xmin tells them apart
// (REVIEW-SINGLE-WRITER-1 F1).
func TestPoll_FenceTamperingLeavesAuthoritativeForGood(t *testing.T) {
	const updTrigger = TriggerPrefix + "guard_upd"
	revoke := "UPDATE machine_identity_credentials SET revoked = true WHERE id = %d"
	cases := []struct {
		name string
		txs  [][]string
	}{
		{"disable", [][]string{{"ALTER TABLE machine_identity_credentials DISABLE TRIGGER " + updTrigger}}},
		{"enable-not-always", [][]string{{"ALTER TABLE roles ENABLE TRIGGER " + TriggerPrefix + "guard"}}},
		{"drop", [][]string{{"DROP TRIGGER " + TriggerPrefix + "guard ON secret_nodes"}}},
		{"replace-function", [][]string{{"CREATE OR REPLACE FUNCTION " + checkFunc + "(sch text) RETURNS void LANGUAGE plpgsql AS $$ BEGIN RETURN; END; $$"}}},
		{"toggle-in-one-tx", [][]string{{
			"ALTER TABLE machine_identity_credentials DISABLE TRIGGER " + updTrigger,
			revoke,
			"ALTER TABLE machine_identity_credentials ENABLE ALWAYS TRIGGER " + updTrigger,
		}}},
		{"toggle-over-two-tx", [][]string{
			{"ALTER TABLE machine_identity_credentials DISABLE TRIGGER " + updTrigger, revoke},
			{"ALTER TABLE machine_identity_credentials ENABLE ALWAYS TRIGGER " + updTrigger},
		}},
		{"drop-and-recreate-identical", [][]string{{
			"DROP TRIGGER " + updTrigger + " ON machine_identity_credentials",
			revoke,
			"CREATE TRIGGER " + updTrigger + " AFTER UPDATE ON machine_identity_credentials FOR EACH ROW WHEN ((to_jsonb(OLD) - 'last_used_at') IS DISTINCT FROM (to_jsonb(NEW) - 'last_used_at')) EXECUTE PROCEDURE " + guardFunc + "()",
			"ALTER TABLE machine_identity_credentials ENABLE ALWAYS TRIGGER " + updTrigger,
		}}},
		{"recreate-identical-function", [][]string{{
			"CREATE OR REPLACE FUNCTION " + checkFunc + "(sch text) RETURNS void LANGUAGE plpgsql AS $keyorix$" + checkFuncBody() + "$keyorix$",
		}}},
		// A child table's rows are read through the parent, but the parent's
		// triggers do not fire for writes to the child.
		{"inheriting-child", [][]string{{"CREATE TABLE sw_child_roles () INHERITS (roles)"}}},
		// Rules and row-level security act on rows with no trigger firing:
		// DO INSTEAD NOTHING drops the server's own writes, a policy hides
		// rows from its reads.
		{"rule", [][]string{{"CREATE RULE sw_drop AS ON UPDATE TO machine_identity_credentials DO INSTEAD NOTHING"}}},
		{"rule-disabled", [][]string{
			{"CREATE RULE sw_drop AS ON UPDATE TO machine_identity_credentials DO INSTEAD NOTHING", "ALTER TABLE machine_identity_credentials DISABLE RULE sw_drop"},
		}},
		{"policy", [][]string{{"CREATE POLICY sw_hide ON roles USING (false)"}}},
		{"row-level-security", [][]string{{"ALTER TABLE roles ENABLE ROW LEVEL SECURITY"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newSWWorld(t)
			g := w.start(Options{})
			require.Eventually(t, g.Authoritative, 2*time.Second, 20*time.Millisecond)
			for _, stmts := range tc.txs {
				require.NoError(t, w.foreign.Transaction(func(tx *gorm.DB) error {
					for _, s := range stmts {
						if strings.Contains(s, "%d") {
							s = fmt.Sprintf(s, w.credID)
						}
						if err := tx.Exec(s).Error; err != nil {
							return err
						}
					}
					return nil
				}))
			}
			start := time.Now()
			d := waitFor(t, 2*time.Second, func() bool { return !g.Authoritative() })
			require.GreaterOrEqual(t, d, time.Duration(0))
			require.LessOrEqual(t, time.Since(start), PollInterval+pollTimeout)
			require.Equal(t, StateConfirming, g.Status().State)
			require.Contains(t, g.Status().Reason, "write fence changed")
		})
	}
}

// TestLease_ExpiresOnAStalledPollerAndAClockJump: no authoritative answer on
// a lease older than LeaseDuration by either clock.
func TestLease_ExpiresOnAStalledPollerAndAClockJump(t *testing.T) {
	w := newSWWorld(t)
	// Only the wall source is skewed: time.Now().Add would move the
	// monotonic reading too, and the jump would then be caught by the
	// monotonic check alone.
	var skew atomic.Int64
	g := w.start(Options{Wall: func() time.Time { return time.Now().Round(0).Add(time.Duration(skew.Load())) }})
	require.Eventually(t, g.Authoritative, 2*time.Second, 20*time.Millisecond)

	// A stalled poller: stop it; the lease runs out.
	g.stopOnce.Do(func() { close(g.stop) })
	<-g.done
	require.Eventually(t, func() bool { return !g.Authoritative() }, LeaseDuration+500*time.Millisecond, 20*time.Millisecond)

	// A fresh poll restores it; a wall-clock jump (monotonic unchanged in
	// this process, so only the wall reading moves) expires it again.
	g.pollOnce(context.Background())
	require.True(t, g.Authoritative())
	skew.Store(int64(2 * LeaseDuration))
	require.False(t, g.Authoritative(), "a wall clock 2 leases ahead must expire the lease")
	skew.Store(int64(-2 * LeaseDuration))
	require.False(t, g.Authoritative(), "a wall clock 2 leases behind must expire the lease")
	skew.Store(0)
	require.True(t, g.Authoritative(), "the monotonic lease alone is still fresh")
}

// TestSettle_WaitsForATransactionOlderThanTheBoot: a write that passed the
// fence before this boot became the holder and commits only afterwards.
func TestSettle_WaitsForATransactionOlderThanTheBoot(t *testing.T) {
	w := newSWWorld(t)
	g0 := w.start(Options{}) // install the triggers once
	g0.Close()
	require.Eventually(t, func() bool {
		return w.foreign.Exec("UPDATE machine_identity_credentials SET name = name WHERE id = ?", w.credID).Error == nil
	}, 5*time.Second, 50*time.Millisecond)

	tx := w.foreign.Begin()
	require.NoError(t, tx.Exec("UPDATE machine_identity_credentials SET revoked = true WHERE id = ?", w.credID).Error)
	commitAt := 600 * time.Millisecond
	go func() {
		time.Sleep(commitAt)
		_ = tx.Commit().Error
	}()

	start := time.Now()
	g, err := Start(context.Background(), w.cfg, Options{LockWait: 500 * time.Millisecond, SkipPresenceCensus: true})
	require.NoError(t, err)
	t.Cleanup(g.Close)
	require.NoError(t, g.InstallFence(context.Background()))
	require.NoError(t, g.Settle(context.Background()))
	require.GreaterOrEqual(t, time.Since(start), commitAt-50*time.Millisecond, "settle returned before the older transaction finished")
	require.True(t, w.revoked())
	require.True(t, g.Authoritative())
}

func TestSettle_TimeoutLeavesAuthoritativeForGood(t *testing.T) {
	w := newSWWorld(t)
	g0 := w.start(Options{})
	g0.Close()
	require.Eventually(t, func() bool {
		return w.foreign.Exec("UPDATE machine_identity_credentials SET name = name WHERE id = ?", w.credID).Error == nil
	}, 5*time.Second, 50*time.Millisecond)
	tx := w.foreign.Begin()
	require.NoError(t, tx.Exec("UPDATE machine_identity_credentials SET name = name WHERE id = ?", w.credID).Error)
	defer tx.Rollback()

	g, err := Start(context.Background(), w.cfg, Options{LockWait: 500 * time.Millisecond, SkipPresenceCensus: true, SettleTimeout: 300 * time.Millisecond})
	require.NoError(t, err)
	t.Cleanup(g.Close)
	require.NoError(t, g.InstallFence(context.Background()))
	require.NoError(t, g.Settle(context.Background()))
	require.False(t, g.Authoritative())
	require.Contains(t, g.Status().Reason, "settle timed out")
}

// TestCheckOff: a server without the setting refuses next to a live holder,
// and removes a fence an earlier single-writer boot left.
func TestCheckOff(t *testing.T) {
	w := newSWWorld(t)
	g := w.start(Options{})
	err := CheckOff(context.Background(), w.cfg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "single_writer holds this database")
	live, pid, err := HolderLive(context.Background(), w.cfg)
	require.NoError(t, err)
	require.True(t, live)
	require.Equal(t, g.PID(), pid)

	g.Close()
	require.Eventually(t, func() bool { l, _, _ := HolderLive(context.Background(), w.cfg); return !l }, 5*time.Second, 50*time.Millisecond)
	require.NoError(t, CheckOff(context.Background(), w.cfg))
	var n int
	require.NoError(t, w.foreign.Raw("SELECT count(*) FROM pg_trigger WHERE tgname LIKE 'trg\\_ksw\\_%' AND tgrelid IN (SELECT oid FROM pg_class WHERE relnamespace = to_regnamespace(current_schema()))").Scan(&n).Error)
	require.Zero(t, n, "CheckOff must remove the fence triggers")
	require.NoError(t, CheckOff(context.Background(), w.cfg), "idempotent")
}

// TestInstallFence_RefusesWhenATableIsMissing: no fence, no start (decision 2).
func TestInstallFence_RefusesWhenATableIsMissing(t *testing.T) {
	w := newSWWorld(t)
	require.NoError(t, w.foreign.Exec("DROP TABLE secret_access_schedules").Error)
	g, err := Start(context.Background(), w.cfg, Options{LockWait: 500 * time.Millisecond, SkipPresenceCensus: true})
	require.NoError(t, err)
	t.Cleanup(g.Close)
	err = g.InstallFence(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "secret_access_schedules does not exist")
}

// TestInstallFence_RefusesAFencedTableWithAChild: rows written to a child
// table are read through the fenced parent without firing its triggers, so a
// boot that finds one does not start (the fingerprint only notices a child
// added later).
func TestInstallFence_RefusesAFencedTableWithAChild(t *testing.T) {
	w := newSWWorld(t)
	require.NoError(t, w.foreign.Exec("CREATE TABLE sw_child_creds () INHERITS (machine_identity_credentials)").Error)
	g, err := Start(context.Background(), w.cfg, Options{LockWait: 500 * time.Millisecond, SkipPresenceCensus: true})
	require.NoError(t, err)
	t.Cleanup(g.Close)
	err = g.InstallFence(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "sw_child_creds INHERITS machine_identity_credentials")
}

// TestSessionTag_NotInStatementText: a freshly tagged server session carries
// the nonce, but the statement that set it (still that backend's
// pg_stat_activity.query, since nothing else ran yet) does not contain it.
// Anyone who can read pg_stat_activity could otherwise copy it
// (REVIEW-SINGLE-WRITER-1 F2).
func TestSessionTag_NotInStatementText(t *testing.T) {
	w := newSWWorld(t)
	g := w.start(Options{})
	ctx := context.Background()
	cc, err := config.ResolvePostgresConnConfig(&w.cfg.Storage.Database)
	require.NoError(t, err)
	conn, err := pgx.ConnectConfig(ctx, cc)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close(ctx) })
	var query string
	require.NoError(t, w.foreign.Raw("SELECT coalesce(query, '') FROM pg_stat_activity WHERE pid = ?", conn.PgConn().PID()).Scan(&query).Error)
	t.Logf("the tagged session's last statement: %q", query)
	require.NotEmpty(t, query, "the test must see the set-up statement")
	require.NotContains(t, query, g.nonce, "the nonce is visible in pg_stat_activity")
	var got string
	require.NoError(t, conn.QueryRow(ctx, "SELECT current_setting('"+config.SoleWriterSessionSetting+"')").Scan(&got))
	require.Equal(t, g.nonce, got, "the session must still carry the tag")
}

// TestPoll_CatalogMaintenanceKeepsAuthoritative is the other direction of the
// tampering test: routine maintenance that freezes the catalog rows the
// fingerprint reads (xmin included) must not be taken for tampering. VACUUM
// FULL of pg_trigger / pg_proc keeps xmin too (checked by hand, FIX-SINGLE-
// WRITER-1), but it is not run here: it locks the catalog for every session
// of the shared test database.
func TestPoll_CatalogMaintenanceKeepsAuthoritative(t *testing.T) {
	w := newSWWorld(t)
	g := w.start(Options{})
	require.Eventually(t, g.Authoritative, 2*time.Second, 20*time.Millisecond)
	for _, s := range []string{
		"VACUUM FREEZE pg_catalog.pg_trigger", "VACUUM FREEZE pg_catalog.pg_proc",
		"VACUUM FREEZE pg_catalog.pg_attribute", "VACUUM FREEZE pg_catalog.pg_inherits",
		"ANALYZE machine_identity_credentials", "CREATE INDEX sw_maint_idx ON machine_identity_credentials (name)",
		"VACUUM FULL machine_identity_credentials", "CLUSTER machine_identity_credentials USING sw_maint_idx",
		"VACUUM FREEZE " + EpochTable, "ANALYZE " + EpochTable,
	} {
		require.NoError(t, w.foreign.Exec(s).Error, s)
	}
	time.Sleep(3 * PollInterval)
	require.True(t, g.Authoritative(), "maintenance was taken for tampering: %s", g.Status().Reason)
}

// TestInspectFence_ReportsARoleThatReachesBelowSQL: the posture deviation for
// the one bypass neither the fence nor the fingerprint can see (a superuser,
// or a role that may run server programs or write server files). A plain
// table-owning role is not reported.
func TestInspectFence_ReportsARoleThatReachesBelowSQL(t *testing.T) {
	w := newSWWorld(t)
	var super bool
	require.NoError(t, w.foreign.Raw("SELECT rolsuper FROM pg_roles WHERE rolname = current_user").Scan(&super).Error)
	if !super {
		t.Skip("the test role is not a superuser; the reported case cannot be shown")
	}
	rep, err := InspectFence(context.Background(), w.cfg)
	require.NoError(t, err)
	require.True(t, rep.BelowSQL, "a superuser connection must be reported")

	role := "sw_plain_" + w.schema
	require.NoError(t, w.foreign.Exec("CREATE ROLE "+role+" NOLOGIN").Error)
	t.Cleanup(func() { _ = w.foreign.Exec("DROP ROLE IF EXISTS " + role).Error })
	for _, tc := range []struct {
		grant string
		want  bool
	}{{"", false}, {"pg_execute_server_program", true}, {"pg_write_server_files", true}} {
		if tc.grant != "" {
			require.NoError(t, w.foreign.Exec("GRANT "+tc.grant+" TO "+role).Error)
		}
		var got bool
		require.NoError(t, w.foreign.Transaction(func(tx *gorm.DB) error {
			if err := tx.Exec("SET LOCAL ROLE " + role).Error; err != nil {
				return err
			}
			return tx.Raw(belowSQLQuery).Scan(&got).Error
		}))
		require.Equal(t, tc.want, got, "role with %q", tc.grant)
		if tc.grant != "" {
			require.NoError(t, w.foreign.Exec("REVOKE "+tc.grant+" FROM "+role).Error)
		}
	}
}
