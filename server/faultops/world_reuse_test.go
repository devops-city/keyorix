// world_reuse_test.go — per-worker world reuse for FuzzStorageFaultOperations
// ONLY (Session M item M5). newFaultWorld (world_test.go) stays completely
// untouched: it is shared by audit_completeness_fuzz_test.go,
// fuzz_shared_secrets_view_test.go, mixed_principal_authority_fuzz_test.go,
// and several smoke/profile/fixture tests, none of which this item is
// scoped to touch (see the session's own "apply to other world-based
// fuzzers only if their world code is shared; otherwise list them" —
// listed, not applied, in the M5 report).
//
// The shape: build the expensive, content-independent infrastructure (DB
// connection, migrated schema + indexes, testCore wiring, REST router,
// gRPC server/bufconn/client) ONCE per fuzz worker process (i.e. once per
// testing.F -- see buildReusableFaultWorld), then before every iteration
// restore the world to EXACTLY the same starting content a fresh
// newFaultWorld call would produce (see resetForReuse) instead of rebuilding
// the infrastructure from scratch. Go's native fuzzer runs each worker as a
// separate OS process (test binary re-exec'd with -test.fuzzworker), so a
// world built once in the function passed to f.Fuzz's enclosing scope is
// already naturally one-per-worker with no cross-worker sharing to guard.
package faultops

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/delivery"
	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
	grpcserver "github.com/keyorixhq/keyorix/server/grpc"
	httpserver "github.com/keyorixhq/keyorix/server/http"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// tbLite is the minimal subset of testing.TB that both *testing.T and
// *testing.F implement (both embed the same unexported *testing.common,
// except Helper which *testing.F overrides itself -- confirmed by reading
// GOROOT src/testing/{testing,fuzz}.go, not assumed): Helper/Fatal/Fatalf/
// Cleanup/Logf. Lets buildReusableFaultWorld run at per-worker setup time
// (called with an f) and resetForReuse run at per-iteration reset time
// (called with a t) via the same signatures where they overlap.
type tbLite interface {
	Helper()
	Fatal(args ...any)
	Fatalf(format string, args ...any)
	Cleanup(func())
	Logf(format string, args ...any)
}

func mustExecTB(tb tbLite, db *gorm.DB, sql string) {
	tb.Helper()
	if err := db.Exec(sql).Error; err != nil {
		tb.Fatalf("exec %q: %v", sql, err)
	}
}

// buildReusableFaultWorld builds everything newFaultWorld builds EXCEPT the
// bootstrap admin + login: DB connection (SQLite always; PostgreSQL too when
// KEYORIX_TEST_PG_DSN is set, reusing openWorldDB unchanged), migrated
// schema + indexes, testCore wiring (delivery/WebAuthn/break-glass/dynamic
// engine factory -- all content-independent settings, safe to set once),
// REST router + httptest.Server, gRPC server + bufconn + client. spec is the
// fault armed on construction; resetForReuse re-arms it (or a different one)
// on every subsequent call.
//
// Takes a tbLite so it can be called with the *testing.F Session M's reuse
// wants this built against (once, before f.Fuzz), not a *testing.T (which
// doesn't exist yet at that point) -- Cleanup registered here therefore runs
// at the END OF THE WHOLE FUZZ RUN (f's Cleanup), not per-iteration, which is
// the whole point: httpSrv.Close/grpcSrv.Stop/conn.Close must NOT fire until
// every iteration this worker process ever runs is done, unlike a t.Cleanup
// registered inside f.Fuzz's closure, which fires at the end of the CURRENT
// input alone (confirmed by reading GOROOT src/testing/fuzz.go's F.Fuzz
// before relying on it -- this is the exact trap a naive
// "just call newFaultWorld once outside f.Fuzz" attempt would fall into).
func buildReusableFaultWorld(tb tbLite, spec *faultstorage.FaultSpec) *faultWorld {
	tb.Helper()

	if err := i18n.InitializeForTesting(); err != nil {
		tb.Fatalf("i18n.InitializeForTesting: %v", err)
	}

	db, backend := openWorldDBTB(tb)
	if err := db.AutoMigrate(models.AllTestModels()...); err != nil {
		tb.Fatal(err)
	}
	if err := db.AutoMigrate(&models.AuditCheckpoint{}); err != nil {
		tb.Fatal(err)
	}
	mustExecTB(tb, db, "CREATE UNIQUE INDEX IF NOT EXISTS uniq_project_memberships_active "+
		"ON project_memberships (project_id, user_id) WHERE state <> 'revoked'")
	mustExecTB(tb, db, "CREATE UNIQUE INDEX IF NOT EXISTS uniq_legal_holds_active "+
		"ON legal_holds (released) WHERE released = false")
	mustExecTB(tb, db, "CREATE UNIQUE INDEX IF NOT EXISTS uniq_break_glass_active_project_user "+
		"ON break_glass_activations (project_id, user_id) WHERE state = 'active'")
	mustExecTB(tb, db, "CREATE UNIQUE INDEX IF NOT EXISTS uniq_users_email_active "+
		"ON users (LOWER(email)) WHERE deleted_at IS NULL AND email <> ''")

	real := store.NewLocalStorage(db)
	faulty := faultstorage.NewFaultyStorage(real, spec)
	testCore := newWorldCore(tb, faulty)

	w := &faultWorld{
		db: db, backend: backend, core: testCore, faulty: faulty,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
	w.rebuildTransport(tb)
	tb.Cleanup(func() {
		if w.httpServer != nil {
			w.httpServer.Close()
		}
		if w.grpcConn != nil {
			_ = w.grpcConn.Close()
		}
		if w.grpcSrv != nil {
			w.grpcSrv.Stop()
		}
	})
	return w
}

// newWorldCore builds a fresh KeyorixCore over faulty with every
// content-independent setting buildReusableFaultWorld used to apply once.
// resetForReuse calls it on EVERY reset: KeyorixCore carries in-memory state
// (permission/RBAC caches keyed by user ID, login-throttle and MFA-lockout
// counters, audit-chain head, bootstrap token, encryption wiring) that
// resetWorldTables can't see, and IDs restart at 1 each iteration, so a
// surviving core would hand one iteration's cached state to the next.
// Rebuilding it is cheap (no I/O); only the DB, schema and servers are reused.
func newWorldCore(tb tbLite, faulty *faultstorage.FaultyStorage) *core.KeyorixCore {
	tb.Helper()
	testCore := core.NewKeyorixCore(faulty)

	deliverer, err := delivery.New(delivery.Config{})
	if err != nil {
		tb.Fatalf("delivery.New: %v", err)
	}
	testCore.SetCredentialDelivery(deliverer, "https://fuzz-world.invalid")

	// Session FI2: RPID/RPOrigins match newFaultWorld's identical change in
	// world_test.go (see that comment for why "example.org" / "https://example.org",
	// the W3C spec test vectors' own baked-in RP identity, replaced "localhost").
	rp, err := webauthn.New(&webauthn.Config{
		RPID: "example.org", RPDisplayName: "Keyorix", RPOrigins: []string{"https://example.org"},
	})
	if err != nil {
		tb.Fatalf("webauthn.New: %v", err)
	}
	testCore.SetWebAuthn(rp)

	if err := wireSSOProviders(testCore); err != nil {
		tb.Fatalf("wireSSOProviders: %v", err)
	}

	testCore.SetBootstrapToken("fault-fuzz-bootstrap")

	testCore.SetBreakGlassPolicy(core.BreakGlassPolicy{
		Enabled: true, EmergencyRole: "project_developer",
		DefaultTTL: 4 * time.Hour, MaxTTL: 24 * time.Hour,
	})

	testCore.SetDynamicEngineFactory(func(backendType string) (dynamic.CredentialEngine, error) {
		return dynamic.New(backendType, false, false)
	})
	return testCore
}

// rebuildTransport (re)builds w's REST router + httptest.Server + gRPC
// server + bufconn + client, closing/stopping whatever it previously held
// first. Called once from buildReusableFaultWorld and again on EVERY
// resetForReuse -- NOT because the router/server themselves hold DB content
// that needs wiping (they don't; resetWorldTables already handles that), but
// because handlers.InitCoreHandlers has a documented package-level side
// effect (server/http/router.go's own comment: "InitCoreHandlers' side
// effect of setting the package-level defaultUserHandler is still required
// by users_handler.go's live wrapper functions") -- a GLOBAL, not scoped to
// one router instance. With two long-lived reused worlds (ref and w) built
// ONCE and BOTH alive for the rest of the run, building w's router SECOND
// permanently overwrites that global to point at w's coreService -- every
// LATER request against ref's OWN httpServer would silently be serviced by
// w's handler/core/DB instead of ref's own, since the wrapper function reads
// the global, not a per-request-scoped value. The single-shot (pre-reuse)
// design never hits this: ref is built, used, and fully snapshotted before w
// is even constructed, so the global is never read by ref again after being
// overwritten. Found empirically by TestWorldReuseSoundness itself (see the
// M5 PR body for the full diagnostic trail) -- not by reading this comment
// first. Rebuilding the router+servers (not the DB/schema) on every reset
// "reclaims" the global right before that world's requests are issued, at a
// cost of ~0.4ms (REST) + ~0.03ms (gRPC) per Finding 2's own profiling table
// — negligible next to the ~5-8ms DB open+migrate+bootstrap this reuse
// design still avoids paying twice.
func (w *faultWorld) rebuildTransport(tb tbLite) {
	tb.Helper()
	if w.httpServer != nil {
		w.httpServer.Close()
	}
	if w.grpcConn != nil {
		_ = w.grpcConn.Close()
	}
	if w.grpcSrv != nil {
		w.grpcSrv.Stop()
	}

	cfg := &config.Config{Server: config.ServerConfig{HTTP: config.ServerInstanceConfig{Enabled: true, Port: "8080"}}}
	handler, err := httpserver.NewRouter(cfg, w.core)
	if err != nil {
		tb.Fatal(err)
	}
	w.httpServer = httptest.NewServer(handler)

	grpcSrv, err := grpcserver.NewServer(&config.Config{}, w.core)
	if err != nil {
		tb.Fatal(err)
	}
	w.grpcSrv = grpcSrv
	lis := bufconn.Listen(1024 * 1024)
	go func() { _ = grpcSrv.Serve(lis) }()

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		tb.Fatal(err)
	}
	w.grpcConn = conn
}

// openWorldDBTB opens the backend for one world (SQLite always; PostgreSQL
// when KEYORIX_TEST_PG_DSN is set: a fresh uniquely-named schema, dropped on
// Cleanup). Takes tbLite so buildReusableFaultWorld can call it with a
// *testing.F; openWorldDB (world_test.go) delegates here. Schema-management
// calls use a short-lived admin connection, closed immediately, so -parallel
// runs don't exhaust Postgres's max_connections.
func openWorldDBTB(tb tbLite) (*gorm.DB, string) {
	tb.Helper()
	dsn := os.Getenv(pgDSNEnv)
	if dsn == "" {
		db, err := gorm.Open(sqlite.Open(uniqueMemDSN()), &gorm.Config{})
		if err != nil {
			tb.Fatal(err)
		}
		sqlDB, err := db.DB()
		if err != nil {
			tb.Fatal(err)
		}
		sqlDB.SetMaxOpenConns(1)
		tb.Cleanup(func() { _ = sqlDB.Close() })
		return db, "sqlite"
	}

	n := pgSchemaSeq.Add(1)
	schema := fmt.Sprintf("faultops_reuse_%d_%d", os.Getpid(), n)

	pgAdminExec := func(sql string) error {
		admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
		if err != nil {
			return err
		}
		defer func() {
			if sqlDB, e := admin.DB(); e == nil {
				_ = sqlDB.Close()
			}
		}()
		return admin.Exec(sql).Error
	}
	if err := pgAdminExec("DROP SCHEMA IF EXISTS " + schema + " CASCADE"); err != nil {
		tb.Fatalf("drop schema %s: %v", schema, err)
	}
	if err := pgAdminExec("CREATE SCHEMA " + schema); err != nil {
		tb.Fatalf("create schema %s: %v", schema, err)
	}
	tb.Cleanup(func() {
		_ = pgAdminExec("DROP SCHEMA IF EXISTS " + schema + " CASCADE")
	})

	db, err := gorm.Open(postgres.Open(pgdsn.PGSearchPathDSN(dsn, schema)), &gorm.Config{})
	if err != nil {
		tb.Fatalf("open postgres: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		tb.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(2)
	tb.Cleanup(func() { _ = sqlDB.Close() })
	return db, "postgres"
}

// resetWorldTables restores db to an empty-but-migrated state: every user
// table (SQLite: everything in sqlite_master except sqlite's own bookkeeping
// tables; PostgreSQL: everything pg_tables reports in the current schema) is
// emptied and its autoincrement/serial sequence reset to its start value.
//
// The sequence reset is not cosmetic: snapshot_test.go's canonicalRow does
// NOT exclude ID or foreign-key fields from the oracle's state-comparison
// hash (only timestamps, hash-chain links, and a short explicit
// presence-only list are excluded) -- so a row ID that merely keeps counting
// up across reused iterations, rather than restarting at the same baseline
// every time, would make the reference world and the faulted world
// incomparable for reasons that have nothing to do with the fault under
// test. Confirmed empirically before relying on it: GORM's SQLite dialect
// migrates a primaryKey uint field as `INTEGER PRIMARY KEY AUTOINCREMENT`,
// which persists its counter in sqlite_sequence across a bare DELETE FROM
// (a fresh row after delete+reinsert got id=3, not id=1, without also
// clearing sqlite_sequence) -- see the M5 PR body for the exact probe.
// leakTableForTest, when non-empty, makes resetWorldTables silently skip
// wiping the named table -- ONLY used by
// TestWorldReuseSoundness_CatchesPlantedStateLeak (world_reuse_soundness_test.go)
// to plant a deliberate state-leak bug and prove the soundness gate actually
// fails on it. Always "" outside that one test.
var leakTableForTest string

func resetWorldTables(db *gorm.DB, backend string) error {
	if backend == "postgres" {
		var tables []string
		if err := db.Raw("SELECT tablename FROM pg_tables WHERE schemaname = current_schema()").Scan(&tables).Error; err != nil {
			return fmt.Errorf("list postgres tables: %w", err)
		}
		tables = withoutLeakedTable(tables)
		if len(tables) == 0 {
			return nil
		}
		stmt := "TRUNCATE TABLE " + strings.Join(tables, ", ") + " RESTART IDENTITY CASCADE" // nosemgrep: go.lang.security.audit.database.string-formatted-query.string-formatted-query -- tables comes from pg_tables (this connection's own migrated schema), never fuzzer/external input
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("truncate postgres tables: %w", err)
		}
		return nil
	}

	var tables []string
	if err := db.Raw("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'").Scan(&tables).Error; err != nil {
		return fmt.Errorf("list sqlite tables: %w", err)
	}
	tables = withoutLeakedTable(tables)
	if err := db.Exec("PRAGMA foreign_keys = OFF").Error; err != nil {
		return fmt.Errorf("disable foreign_keys: %w", err)
	}
	defer func() { _ = db.Exec("PRAGMA foreign_keys = ON").Error }()
	for _, tbl := range tables {
		if err := db.Exec("DELETE FROM " + tbl).Error; err != nil { // nosemgrep: go.lang.security.audit.database.string-formatted-query.string-formatted-query -- tbl comes from sqlite_master (this connection's own migrated schema), never fuzzer/external input
			return fmt.Errorf("delete from %s: %w", tbl, err)
		}
	}
	if err := db.Exec("DELETE FROM sqlite_sequence").Error; err != nil &&
		!strings.Contains(err.Error(), "no such table") {
		return fmt.Errorf("reset sqlite_sequence: %w", err)
	}
	return nil
}

func withoutLeakedTable(tables []string) []string {
	if leakTableForTest == "" {
		return tables
	}
	out := tables[:0:0]
	for _, tbl := range tables {
		if tbl == leakTableForTest {
			continue
		}
		out = append(out, tbl)
	}
	return out
}

// resetForReuse restores w to the exact same logical starting state a fresh
// newFaultWorld(t, spec) call would produce, WITHOUT rebuilding the DB
// connection, schema, REST router, or gRPC server: wipe every table +
// sequence (resetWorldTables), re-run BootstrapSystem + Login (both write DB
// rows that resetWorldTables just cleared, so this is not optional), rebind
// w.t to the current iteration's real *testing.T (every opCatalog Setup/
// Execute function, and ensureEncryption, use w.t -- see world_test.go's own
// doc comment on ensureEncryption for why it reads w.t rather than taking a
// parameter), and re-arm the fault wrapper via Arm (which itself resets
// per-method call counters and the fired latch -- faultstorage.go's own doc
// comment on Arm).
//
// The KeyorixCore is rebuilt (newWorldCore) and encryptOnce/encryptErr are
// reset, so every iteration starts from the same in-memory state a fresh
// newFaultWorld has, including lazy (not pre-wired) encryption. An iteration
// whose op needs encryption pays PBKDF2 (~125ms) once, as it did before world
// reuse; iterations that don't, don't. Background goroutines from the previous
// iteration are drained first so none can write into the freshly wiped tables.
func (w *faultWorld) resetForReuse(t *testing.T, spec *faultstorage.FaultSpec) {
	t.Helper()
	w.t = t

	// A detached audit write from the previous iteration must not land in the
	// tables we're about to wipe (or after the wipe, in this iteration's state).
	drainAllBackgroundGoroutines()

	// Disarm/re-arm BEFORE BootstrapSystem/Login below, not after: a fault
	// left armed from a PRIOR iteration (this same faulty wrapper, and its
	// spec, persist across reuse) would otherwise still be live while
	// BootstrapSystem/Login run, injecting a stale failure into calls that
	// have nothing to do with the current iteration's input. Found by
	// TestWorldReuseSoundness itself: BootstrapSystem's CreateEnvironment
	// call failed with a PRIOR iteration's injected fault before this fix
	// (see the M5 PR body).
	w.faulty.Arm(spec)

	// Fresh core, fresh lazy encryption (see this function's doc comment).
	w.core = newWorldCore(t, w.faulty)
	w.encryptOnce = sync.Once{}
	w.encryptErr = nil

	// Reclaim handlers' package-level defaultUserHandler global before
	// issuing any request against w's own httpServer -- see
	// rebuildTransport's own doc comment for why this is required, not
	// optional, the moment a second reused world exists.
	w.rebuildTransport(t)

	if err := resetWorldTables(w.db, w.backend); err != nil {
		t.Fatalf("reset world tables: %v", err)
	}

	// BootstrapSystem's token is single-use, in-memory state (KeyorixCore.bootstrapToken,
	// internal/core/auth_bootstrap.go:352 clears it after the first successful call --
	// a genuine first-boot-admin security property, not something resetWorldTables'
	// DB-only wipe touches or should touch). Must be re-armed before every reset's
	// BootstrapSystem call, not just the first -- found by TestWorldReuseSoundness
	// itself: the 2nd reused iteration failed BootstrapSystem with "invalid bootstrap
	// token" before this fix (see the M5 PR body).
	w.core.SetBootstrapToken("fault-fuzz-bootstrap")

	ctx := context.Background()
	if _, err := w.core.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "faultadmin", Email: "faultadmin@example.com",
		Password: "FaultFuzzAdmin123!", Token: "fault-fuzz-bootstrap",
	}); err != nil {
		t.Fatalf("BootstrapSystem: %v", err)
	}
	session, _, err := w.core.Login(ctx, &core.LoginRequest{
		Username: "faultadmin", Password: "FaultFuzzAdmin123!",
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	w.adminToken = session.SessionToken
	w.grpcCtx = metadata.NewOutgoingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer "+session.SessionToken))
}
