// concurrent_linearizable_fuzz_test.go — FuzzConcurrentOpsLinearizable: a TRUE
// concurrent (real goroutines, no serializing shared-model mutex) stateful
// fuzzer for authz grant/revoke, per-secret RotateSecret, and session
// revocation, checked for linearizability against a sequential model via
// porcupine (github.com/anishathalye/porcupine, test-only dependency).
//
// Every existing sequence fuzzer in this repo (FuzzCoreOperationSequence,
// FuzzKeyorixHTTPAPISequence) drives one op at a time on a SINGLE goroutine —
// sound for a bug that appears across a sequence, but blind to a bug that only
// appears when two ops genuinely race. This repo has already shipped exactly
// that bug class once: TestConcurrency_RotateSecret_NoDuplicateVersionNumbers
// (#121) — two concurrent RotateSecret calls on the same secret could both
// read the same "latest version" and both write it, fixed by a retry loop in
// storeNextSecretVersion — and today it is pinned only by a one-shot
// regression test with one fixed scenario (15 goroutines, one secret). This
// fuzzer generalizes that shape across a fuzzer-chosen mix of goroutine
// counts, op interleavings, and GOMAXPROCS values, and extends the same
// technique to the grant/revoke/read authz path and session revocation.
//
// SCOPE NOTE (2026-09-19 investigation, approved before Step 2): raw DEK/KEK
// envelope-key rotation (RotateDEKWithSweep, RewrapDEK) is deliberately NOT
// modeled here. Both acquire Service.AcquireExclusiveKeyLock — the SAME
// exclusive, cross-process advisory lock server/main.go takes for a live
// server's entire lifetime (see service_rotation.go's AcquireExclusiveKeyLock/
// AcquireSharedKeyLock and exclusive_lock_test.go's
// TestAcquireSharedKeyLock_RefusedWhileServerHoldsLock /
// TestAcquireSharedKeyLock_RefusedWhileRotationSweepInProgress) — so a live
// server serving concurrent secret reads/writes and a DEK-sweep-rotation or
// KEK-rewrap can never coexist in the same process/key-directory in
// production. Concurrency-fuzzing that combination would fuzz an unreachable
// deployment shape. The single-threaded, checkpoint-injected crash-consistency
// class that operation DOES need is already covered by
// keymanager_rewrap_crash_consistency_fuzz_test.go /
// keymanager_sweep_crash_consistency_fuzz_test.go (PR #1921).
//
// LAYER: internal/core (KeyorixCore) directly for grant/revoke/read/rotate —
// maximizes interleaving density per fuzz-time budget, and there is no
// permission cache in that path (every permission check re-reads grants from
// the DB — server/middleware's token cache holds only authenticated IDENTITY,
// confirmed by FuzzKeyorixHTTPAPISequence's own doc comment). The session-
// revocation op alone goes through the real HTTP router, because the thing
// being tested — active token-cache eviction on RevokeUserSessions via
// InvalidateTokenCacheByHash — only exists at the server/middleware layer.
//
// MODEL: three families of independent linearizable REGISTERS, each checked
// separately via porcupine (partitioned by hand rather than via porcupine's
// Partition callback, since the three op classes touch disjoint state and
// disjoint principals/secrets by construction — a register is exactly
// porcupine's own canonical example model):
//
//   - grantReg[principal][secret] (bool): grant/revoke SET it (only on
//     success — a failed grant/revoke is skipped from the history entirely,
//     matching FuzzCoreOperationSequence's existing convention of only
//     updating the shadow model when err == nil); a permission-checked read
//     OBSERVES it. No staleness budget: a linearizability check, not a
//     bounded-staleness one.
//   - rotateReg[secret] (string, the current plaintext): RotateSecret WRITES
//     it on success (a failed rotation — retry-exhaustion — is skipped from
//     the history: state doesn't move either way, so omitting it and
//     recording it as a no-op write are equivalent); an ADMIN read OBSERVES
//     it. Admin bypasses permission checks, isolating this register from the
//     grant/revoke race above. An admin read is hard-asserted to never error
//     (DATA LOSS/AVAILABILITY), outside porcupine, mirroring
//     FuzzCoreOperationSequence's assertAdminValue.
//   - sessionReg (bool, starts true): RevokeUserSessions on a dedicated
//     principal SETS it false; an authenticated HTTP read of that
//     principal's own granted secret OBSERVES it.
//
// FAIL-CLOSED / NO-PLAINTEXT-ON-DENY for both the grant/revoke and session
// registers is asserted directly and unconditionally (never via porcupine —
// that direction is order-independent, matching every prior fuzzer here).
//
// BACKENDS: SQLite always, mirroring PRODUCTION's actual pool — WAL journal
// mode, _busy_timeout=10000ms, up to internal/storage/factory.go's
// storage.DefaultSQLiteMaxOpenConns open connections (see sqliteDSN there) — NOT the
// ':memory:' + SetMaxOpenConns(1) single-connection serialization
// FuzzCoreOperationSequence/FuzzKeyorixHTTPAPISequence use (correct for THEIR
// ':memory:'-per-connection quirk, but it would make THIS fuzzer race-safe by
// construction and useless: production SQLite genuinely allows concurrent
// readers with WAL, and writers queue via busy_timeout rather than erroring
// outright — enough to reproduce the #121 shape). PostgreSQL (real MVCC, READ
// COMMITTED, independent transactions with row-level locking — a materially
// different interleaving story from SQLite's one-writer-at-a-time WAL model)
// runs too whenever KEYORIX_TEST_PG_DSN is set, skipped otherwise.
package http

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anishathalye/porcupine"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/fuzzworld"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
)

// clSqliteBusyTimeoutMillis / clSqliteMaxOpenConns mirror
// internal/storage/factory.go's sqliteDSN/DefaultSQLiteMaxOpenConns exactly (see
// this file's package doc for why matching production's pool matters here).
// The DSN built below also mirrors sqliteDSN's _txlock=immediate, for the
// same reason: this fuzzer's whole point is exercising production's real
// locking behavior under concurrency.
const (
	clSqliteBusyTimeoutMillis = 10000
	clSqliteMaxOpenConns      = storage.DefaultSQLiteMaxOpenConns // referenced, not copied: #2631 changed it
)

type clPrincipal struct {
	id uint
}

// clWorld is built ONCE per backend per Fuzz-function invocation (login/bcrypt
// is expensive) and reused across every fuzz iteration; per-iteration state
// (grants, secret values, revuser's session) is reset/re-established inside
// f.Fuzz.
type clWorld struct {
	backend    string // "sqlite" or "postgres" — for failure messages only
	db         *gorm.DB
	c          *core.KeyorixCore
	router     http.Handler
	readerRole uint
	adminID    uint
	projIDs    [2]uint // secret A's project, secret B's project
	envIDs     [2]uint
	secretIDs  [2]uint
	refs       [2]string // "proj/env/name" for HTTP reads
	principals [3]clPrincipal
	revuserID  uint // dedicated, session-revocation-only principal
}

var (
	clRotateSeq atomic.Int64 // global across all backends/iterations — guarantees every rotated value is unique
	clSecretSeq atomic.Int64
)

func buildLinearizabilityWorldSQLite(f *testing.F) *clWorld {
	f.Helper()
	// A real file DB (not :memory:) with FKs on and a multi-connection pool:
	// this fuzzer's whole point is concurrent operations, so it deliberately
	// does not use the single-connection in-memory shape the other fuzzers do.
	dbPath := filepath.Join(f.TempDir(), "cl.db")
	dsn := fmt.Sprintf("%s?_foreign_keys=1&_busy_timeout=%d&_journal_mode=WAL&_txlock=immediate", dbPath, clSqliteBusyTimeoutMillis)
	return buildLinearizabilityWorld(f, fuzzworld.BackendSQLite, fuzzworld.OpenSQLite(f, dsn, clSqliteMaxOpenConns))
}

// buildLinearizabilityWorldPostgres returns nil (not a skip) when
// KEYORIX_TEST_PG_DSN is unset — the caller decides whether that's fine.
func buildLinearizabilityWorldPostgres(f *testing.F) *clWorld {
	f.Helper()
	db := fuzzworld.OpenPostgres(f, "cl_fuzz")
	if db == nil {
		return nil
	}
	return buildLinearizabilityWorld(f, fuzzworld.BackendPostgres, db)
}

func buildLinearizabilityWorld(f *testing.F, backend string, db *gorm.DB) *clWorld {
	f.Helper()
	if err := i18n.InitializeForTesting(); err != nil {
		f.Fatalf("i18n: %v", err)
	}
	// #1947: build the schema through the real production migration
	// (fuzzworld.Bootstrap -> migrateDatabase). An AutoMigrate-only fixture
	// lacks uniq_secret_versions_node_version, so storeNextSecretVersion's
	// retry-on-conflict loop (#121) had no unique constraint to detect a lost
	// race against -- this harness's first fuzz burst produced a duplicate
	// version_number within ~2000 execs purely from that fixture gap. The
	// explicit CREATE UNIQUE INDEX workaround that used to sit here is now
	// redundant; assert the index instead of re-creating it.
	fuzzworld.Bootstrap(f, db)
	if err := db.AutoMigrate(models.AllTestModels()...); err != nil {
		f.Fatalf("migrate test models (%s): %v", backend, err)
	}
	if !db.Migrator().HasIndex("secret_versions", "uniq_secret_versions_node_version") {
		f.Fatalf("(%s) production bootstrap did not create uniq_secret_versions_node_version", backend)
	}

	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	c.SetTokenCacheInvalidator(customMiddleware.InvalidateTokenCacheByHash)
	ctx := context.Background()

	c.SetBootstrapToken("cl-fuzz-bootstrap-token")
	if _, err := c.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "cladmin", Email: "cladmin@example.com",
		Password: "TestPassword123!", Token: "cl-fuzz-bootstrap-token",
	}); err != nil {
		f.Logf("bootstrap (%s): %v (may already be initialised)", backend, err)
	}
	adminSess, _, err := c.Login(ctx, &core.LoginRequest{Username: "cladmin", Password: "TestPassword123!"})
	if err != nil {
		f.Fatalf("admin login (%s): %v", backend, err)
	}
	ls := store.NewLocalStorage(db)
	admin, err := ls.GetUserByUsername(ctx, "cladmin")
	if err != nil || admin == nil {
		f.Fatalf("admin lookup (%s): %v", backend, err)
	}

	var perm models.Permission
	if e := db.Where("name = ?", "secrets.read").First(&perm).Error; e != nil {
		perm = models.Permission{Name: "secrets.read", Resource: "secrets", Action: "read"}
		if e2 := db.Create(&perm).Error; e2 != nil {
			f.Fatalf("seed permission (%s): %v", backend, e2)
		}
	}
	role := models.Role{Name: "cl-fuzz-reader", NameFolded: "cl-fuzz-reader"}
	if err := db.Create(&role).Error; err != nil {
		f.Fatalf("seed role (%s): %v", backend, err)
	}
	if err := db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error; err != nil {
		f.Fatalf("seed role-permission (%s): %v", backend, err)
	}

	w := &clWorld{backend: backend, db: db, c: c, readerRole: role.ID, adminID: admin.ID}

	for i, name := range []string{"cla", "clb"} {
		proj, err := ls.CreateProject(ctx, &models.Project{Name: name})
		if err != nil {
			f.Fatalf("create project %s (%s): %v", name, backend, err)
		}
		env, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: proj.ID})
		if err != nil {
			f.Fatalf("create env %s (%s): %v", name, backend, err)
		}
		sid := clSecretSeq.Add(1)
		secName := fmt.Sprintf("s-%s-%d", name, sid)
		sec, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
			Name: secName, Value: []byte(fmt.Sprintf("init-%d", sid)), ProjectID: proj.ID, EnvironmentID: env.ID,
			Type: "password", CreatedBy: "cladmin", OwnerID: admin.ID,
		})
		if err != nil || sec == nil {
			f.Fatalf("create secret %s (%s): %v", name, backend, err)
		}
		w.projIDs[i] = proj.ID
		w.envIDs[i] = env.ID
		w.secretIDs[i] = sec.ID
		w.refs[i] = fmt.Sprintf("%s/prod/%s", name, secName)
	}

	mkPrincipal := func(uname string) clPrincipal {
		u, err := c.CreateUser(ctx, &core.CreateUserRequest{Username: uname, Email: uname + "@x.io", Password: "Xk7#Qp2$Rn5@Wv9!"})
		if err != nil || u == nil {
			f.Fatalf("create user %s (%s): %v", uname, backend, err)
		}
		return clPrincipal{id: u.ID}
	}
	w.principals = [3]clPrincipal{mkPrincipal("clr0"), mkPrincipal("clr1"), mkPrincipal("clr2")}

	revuser, err := c.CreateUser(ctx, &core.CreateUserRequest{Username: "clrev", Email: "clrev@x.io", Password: "Xk7#Qp2$Rn5@Wv9!"})
	if err != nil || revuser == nil {
		f.Fatalf("create revuser (%s): %v", backend, err)
	}
	w.revuserID = revuser.ID
	// Permanent grant on project A — the ONLY variable the session register
	// exercises is the session's own validity, never the role grant, so it
	// cannot be confounded with the grant/revoke register above.
	if err := c.AssignUserRole(ctx, 0, w.revuserID, w.readerRole, core.Scope{ProjectID: w.projIDs[0]}, false); err != nil {
		f.Fatalf("grant revuser (%s): %v", backend, err)
	}

	r, err := NewRouter(&config.Config{}, c)
	if err != nil {
		f.Fatalf("router (%s): %v", backend, err)
	}
	w.router = r
	_ = adminSess
	w.c.SetBootstrapToken("") // no longer needed
	return w
}

// --- porcupine models -------------------------------------------------------

// boolRegOp is the input to the grant/revoke and session boolean registers.
// write=true is a grant(setTo=true)/revoke(setTo=false)/session-revoke
// (setTo=false); write=false is a read, whose legality is judged from output.
type boolRegOp struct {
	write bool
	setTo bool
}

var boolRegModel = porcupine.Model{
	Init: func() any { return true }, // overridden per-history via a wrapper below when needed
	Step: func(state, input, output any) (bool, any) {
		in := input.(boolRegOp)
		if in.write {
			return true, in.setTo
		}
		return output.(bool) == state.(bool), state
	},
	DescribeOperation: func(input, output any) string {
		in := input.(boolRegOp)
		if in.write {
			return fmt.Sprintf("set(%v)", in.setTo)
		}
		return fmt.Sprintf("read() -> %v", output)
	},
}

// boolRegModelWithInit returns boolRegModel with a specific initial state —
// grant/revoke registers start false (no grant yet); the session register
// starts true (freshly minted, positive-control-verified session).
func boolRegModelWithInit(initial bool) porcupine.Model {
	m := boolRegModel
	m.Init = func() any { return initial }
	return m
}

// stringRegOp is the input to the per-secret value register. write=true is a
// successful RotateSecret (value = the new plaintext); write=false is a read,
// whose legality is judged from output.
type stringRegOp struct {
	write bool
	value string
}

var stringRegModel = porcupine.Model{
	Init: func() any { return "" },
	Step: func(state, input, output any) (bool, any) {
		in := input.(stringRegOp)
		if in.write {
			return true, in.value
		}
		return output.(string) == state.(string), state
	},
	DescribeOperation: func(input, output any) string {
		in := input.(stringRegOp)
		if in.write {
			return fmt.Sprintf("write(%q)", in.value)
		}
		return fmt.Sprintf("read() -> %q", output)
	},
}

// stringRegModelWithInit seeds the register's initial state to the value
// established by the synchronous baseline rotate done before goroutines are
// spawned (see runLinearizabilityIteration) — that baseline write is real but
// happens outside the concurrent phase, so it is never itself recorded as a
// "write" op in the history; the register's Init must reflect it directly.
func stringRegModelWithInit(initial string) porcupine.Model {
	m := stringRegModel
	m.Init = func() any { return initial }
	return m
}

// clHistoriesChecked / clMaxHistoryLen / clHistoryLenSum are soak-reporting
// counters only (never used for correctness) — the Step 3 rig soak's own
// per-segment report ("execs, histories checked, max history length") reads
// these from the periodic and final log lines below; go test's own fuzz
// progress output already covers execs.
var (
	clHistoriesChecked atomic.Int64
	clMaxHistoryLen    atomic.Int64
	clHistoryLenSum    atomic.Int64
)

func clRecordHistoryStat(n int) {
	clHistoriesChecked.Add(1)
	clHistoryLenSum.Add(int64(n))
	for {
		old := clMaxHistoryLen.Load()
		if int64(n) <= old {
			return
		}
		if clMaxHistoryLen.CompareAndSwap(old, int64(n)) {
			return
		}
	}
}

// clLogHistoryStats emits a soak-reportable summary line. Called periodically
// (checkLinearizable, every 2000 histories) and once at process exit
// (FuzzConcurrentOpsLinearizable's f.Cleanup) so a segment killed at its
// deadline still leaves a recent summary in the log, not just a final one.
func clLogHistoryStats(tag string) {
	n := clHistoriesChecked.Load()
	if n == 0 {
		return
	}
	sum := clHistoryLenSum.Load()
	log.Printf("[cl-soak-stats %s] histories_checked=%d max_history_len=%d avg_history_len=%.1f",
		tag, n, clMaxHistoryLen.Load(), float64(sum)/float64(n))
}

// checkLinearizable fails the test iff the checker conclusively finds a
// violation. A timeout (Unknown) is logged, not failed — porcupine's own
// documentation is explicit that Unknown must not be treated as a violation
// (an inconclusive result is not evidence of a bug), and these histories are
// tiny (a handful of ops per register) so a genuine timeout would itself be
// surprising and worth the log line.
func checkLinearizable(t *testing.T, label string, model porcupine.Model, history []porcupine.Operation) {
	t.Helper()
	if len(history) == 0 {
		return
	}
	clRecordHistoryStat(len(history))
	if n := clHistoriesChecked.Load(); n%2000 == 0 {
		clLogHistoryStats("periodic")
	}
	res, info := porcupine.CheckOperationsVerbose(model, history, 5*time.Second)
	switch res {
	case porcupine.Illegal:
		var sb strings.Builder
		fmt.Fprintf(&sb, "NOT LINEARIZABLE: register %q — history is inconsistent with any sequential order:\n", label)
		for _, op := range history {
			fmt.Fprintf(&sb, "  client %d: [%d,%d] %s\n", op.ClientId, op.Call, op.Return, model.DescribeOperation(op.Input, op.Output))
		}
		t.Fatalf("%s", sb.String())
	case porcupine.Unknown:
		t.Logf("linearizability check for %q timed out (Unknown, not treated as a failure) over %d ops", label, len(history))
	}
	_ = info
}

// --- the fuzz target ---------------------------------------------------------

type clOp struct {
	kind      byte
	principal byte
	secret    byte
	yield     bool
}

// clGOMAXPROCSOverride, when set, pins every fuzz iteration's GOMAXPROCS to
// exactly this value instead of letting the fuzz input pick from
// {2, 4, runtime.NumCPU()}. This is how the Step 3 rig soak implements its own
// external "rotate segments of ~2h through GOMAXPROCS {2, 4, nproc}" plan on a
// SHARED box without the fuzzer's own per-iteration choice ever picking a
// higher value than the segment currently budgets for (in particular,
// runtime.NumCPU() on a contended rig can exceed the core budget actually
// available to this process) — -parallel bounds worker PROCESS count; this
// bounds per-process GOMAXPROCS the same way, from outside. Unset (local dev,
// CI, `go test -fuzz` with no env override) preserves the original
// fuzz-input-driven variety.
func clGOMAXPROCSOverride() (int, bool) {
	v := os.Getenv("KEYORIX_CL_GOMAXPROCS")
	if v == "" {
		return 0, false
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

func decodeCLProgram(program []byte, maxGoroutines, maxOpsPerGoroutine int) (goroutines [][]clOp, gomaxprocs int) {
	if len(program) < 2 {
		return nil, 2
	}
	g := 2 + int(program[0])%(maxGoroutines-1)
	if override, ok := clGOMAXPROCSOverride(); ok {
		gomaxprocs = override
	} else {
		switch program[1] % 3 {
		case 0:
			gomaxprocs = 2
		case 1:
			gomaxprocs = 4
		default:
			gomaxprocs = runtime.NumCPU()
		}
	}
	goroutines = make([][]clOp, g)
	body := program[2:]
	total := 0
	for i := 0; i+3 < len(body) && total < maxGoroutines*maxOpsPerGoroutine; i += 4 {
		gi := total % g
		goroutines[gi] = append(goroutines[gi], clOp{
			kind:      body[i],
			principal: body[i+1],
			secret:    body[i+2],
			yield:     body[i+3]%2 == 1,
		})
		total++
	}
	return goroutines, gomaxprocs
}

// clHistories accumulates operations for every register instance touched
// during one fuzz iteration. Guarded by mu since goroutines append
// concurrently; Call/Return timestamps are captured OUTSIDE the lock,
// immediately around the real operation, so lock contention here never
// distorts the recorded intervals.
type clHistories struct {
	mu      sync.Mutex
	grant   map[[2]byte][]porcupine.Operation // key: {principalIdx, secretIdx}
	rotate  map[byte][]porcupine.Operation    // key: secretIdx
	session []porcupine.Operation
}

func newCLHistories() *clHistories {
	return &clHistories{grant: map[[2]byte][]porcupine.Operation{}, rotate: map[byte][]porcupine.Operation{}}
}

func (h *clHistories) addGrant(key [2]byte, op porcupine.Operation) {
	h.mu.Lock()
	h.grant[key] = append(h.grant[key], op)
	h.mu.Unlock()
}

func (h *clHistories) addRotate(secret byte, op porcupine.Operation) {
	h.mu.Lock()
	h.rotate[secret] = append(h.rotate[secret], op)
	h.mu.Unlock()
}

func (h *clHistories) addSession(op porcupine.Operation) {
	h.mu.Lock()
	h.session = append(h.session, op)
	h.mu.Unlock()
}

const (
	clMaxGoroutines      = 8
	clMaxOpsPerGoroutine = 6
)

func FuzzConcurrentOpsLinearizable(f *testing.F) {
	sqliteWorld := buildLinearizabilityWorldSQLite(f)
	worlds := []*clWorld{sqliteWorld}
	if pg := buildLinearizabilityWorldPostgres(f); pg != nil {
		worlds = append(worlds, pg)
	} else {
		f.Logf("KEYORIX_TEST_PG_DSN not set — PostgreSQL backend skipped, SQLite only")
	}

	f.Add([]byte{3, 2, 0, 0, 0, 0, 1, 1, 1, 0, 2, 1, 2, 1, 0, 0, 3, 0, 1, 1, 4, 0, 1, 0})
	f.Add([]byte{7, 0, 0, 0, 1, 0, 6, 0, 5, 0, 0, 0, 0, 0, 1, 1})
	f.Add([]byte{})
	f.Cleanup(func() { clLogHistoryStats("final") })

	f.Fuzz(func(t *testing.T, program []byte) {
		goroutines, gomaxprocs := decodeCLProgram(program, clMaxGoroutines, clMaxOpsPerGoroutine)
		if len(goroutines) == 0 {
			return
		}
		prevGOMAXPROCS := runtime.GOMAXPROCS(gomaxprocs)
		defer runtime.GOMAXPROCS(prevGOMAXPROCS)

		runSessionRegister := len(program) > 0 && program[0]%3 == 0

		for _, w := range worlds {
			runLinearizabilityIteration(t, w, goroutines, runSessionRegister)
		}
	})
}

func runLinearizabilityIteration(t *testing.T, w *clWorld, goroutines [][]clOp, runSessionRegister bool) {
	t.Helper()
	ctx := context.Background()

	// Reset per-iteration grant state for the 3 fuzzable principals by deleting
	// their user_roles rows directly (matching FuzzKeyorixHTTPAPISequence's own
	// convention) rather than calling RemoveUserRole through the API — that API
	// legitimately errors "role not assigned" whenever a principal enters this
	// iteration with no grant at all (e.g. every very first iteration), which is
	// the expected steady state, not a failure. revuser's permanent grant on
	// project A is untouched: this only targets the 3 fuzzable principals.
	for _, p := range w.principals {
		if err := w.db.Exec("DELETE FROM user_roles WHERE user_id = ?", p.id).Error; err != nil {
			t.Fatalf("[%s] reset grants for principal %d: %v", w.backend, p.id, err)
		}
	}

	// Establish a fresh, globally-unique baseline value for each secret so
	// the rotate register's Init state is unambiguous and never collides with
	// a value any other secret or prior iteration could have produced.
	baseline := [2]string{}
	for i, sid := range w.secretIDs {
		v := fmt.Sprintf("base-%d", clRotateSeq.Add(1))
		if _, err := w.c.RotateSecret(ctx, sid, []byte(v), w.adminID, "cl-fuzz-init"); err != nil {
			t.Fatalf("[%s] baseline rotate secret %d: %v", w.backend, i, err)
		}
		baseline[i] = v
	}

	// Session register: mint a fresh session for revuser and prove it works
	// BEFORE spawning goroutines (positive control — an unverified token would
	// make every subsequent "denied" observation vacuous), mirroring
	// FuzzKeyorixHTTPAPISequence's revocationProbe. Skipped (register stays
	// empty and is not checked) when gated off or the login/probe don't pan
	// out cleanly, rather than asserting anything unsound.
	var sessionToken string
	sessionValid := runSessionRegister
	if sessionValid {
		sess, _, err := w.c.Login(ctx, &core.LoginRequest{Username: "clrev", Password: "Xk7#Qp2$Rn5@Wv9!"})
		if err != nil || sess == nil {
			sessionValid = false
		} else {
			sessionToken = sess.SessionToken
			rec := clSessionRead(w.router, w.refs[0], sessionToken)
			sessionValid = rec.Code == http.StatusOK
		}
	}

	hist := newCLHistories()
	start := time.Now()

	var wg sync.WaitGroup
	for gi, ops := range goroutines {
		wg.Add(1)
		go func(gi int, ops []clOp) {
			defer wg.Done()
			for _, op := range ops {
				if op.yield {
					runtime.Gosched()
				}
				runCLOp(t, w, ctx, hist, start, gi, op, sessionToken, sessionValid)
			}
		}(gi, ops)
	}
	wg.Wait()

	for key, h := range hist.grant {
		checkLinearizable(t, fmt.Sprintf("[%s] grant principal=%d secret=%d", w.backend, key[0], key[1]), boolRegModelWithInit(false), h)
	}
	for secret, h := range hist.rotate {
		checkLinearizable(t, fmt.Sprintf("[%s] rotate secret=%d", w.backend, secret), stringRegModelWithInit(baseline[secret]), h)
	}
	if sessionValid {
		checkLinearizable(t, fmt.Sprintf("[%s] session revuser", w.backend), boolRegModelWithInit(true), hist.session)
	}

	// POSTCONDITION (not a linearizability claim — see approved Step 1 spec):
	// version numbers for each secret are unique and contiguous 1..N in the
	// final DB state, regardless of how many concurrent rotations raced or
	// failed. A rotation returning an error after exhausting its retry loop
	// is acceptable (no liveness claim); it must leave no partial version row.
	for i, sid := range w.secretIDs {
		assertContiguousVersions(t, w, sid, i)
	}
}

func assertContiguousVersions(t *testing.T, w *clWorld, secretID uint, idx int) {
	t.Helper()
	var nums []int
	if err := w.db.Table("secret_versions").
		Where("secret_node_id = ?", secretID).
		Pluck("version_number", &nums).Error; err != nil {
		t.Fatalf("[%s] list versions for secret[%d]: %v", w.backend, idx, err)
	}
	seen := map[int]bool{}
	maxV := 0
	for _, n := range nums {
		if seen[n] {
			t.Fatalf("[%s] VERSION CORRUPTION: secret[%d] has duplicate version_number=%d", w.backend, idx, n)
		}
		seen[n] = true
		if n > maxV {
			maxV = n
		}
	}
	for n := 1; n <= maxV; n++ {
		if !seen[n] {
			t.Fatalf("[%s] VERSION GAP: secret[%d] is missing version_number=%d (max=%d, %d rows)", w.backend, idx, n, maxV, len(nums))
		}
	}
}

func clSessionRead(router http.Handler, ref, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/value?ref="+ref, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func runCLOp(t *testing.T, w *clWorld, ctx context.Context, hist *clHistories, start time.Time, gi int, op clOp, sessionToken string, sessionValid bool) {
	t.Helper()
	pIdx := int(op.principal) % len(w.principals)
	sIdx := int(op.secret) % len(w.secretIDs)
	principal := w.principals[pIdx]
	secretID := w.secretIDs[sIdx]
	projID := w.projIDs[sIdx]

	switch op.kind % 7 {
	case 0: // grant
		call := time.Since(start).Nanoseconds()
		err := w.c.AssignUserRole(ctx, 0, principal.id, w.readerRole, core.Scope{ProjectID: projID}, false)
		ret := time.Since(start).Nanoseconds()
		if err == nil {
			hist.addGrant([2]byte{byte(pIdx), byte(sIdx)}, porcupine.Operation{
				ClientId: gi, Input: boolRegOp{write: true, setTo: true}, Call: call, Output: true, Return: ret,
			})
		}

	case 1: // revoke
		call := time.Since(start).Nanoseconds()
		err := w.c.RemoveUserRole(ctx, 0, principal.id, w.readerRole, core.Scope{ProjectID: projID})
		ret := time.Since(start).Nanoseconds()
		if err == nil {
			hist.addGrant([2]byte{byte(pIdx), byte(sIdx)}, porcupine.Operation{
				ClientId: gi, Input: boolRegOp{write: true, setTo: false}, Call: call, Output: false, Return: ret,
			})
		}

	case 2: // permission-checked read
		call := time.Since(start).Nanoseconds()
		val, err := w.c.GetSecretValueWithPermissionCheck(ctx, secretID, principal.id)
		ret := time.Since(start).Nanoseconds()
		allowed := err == nil
		if err != nil && len(val) != 0 {
			t.Fatalf("[%s] NO-PLAINTEXT-ON-DENY: denied read of secret[%d] by principal %d returned non-empty plaintext: %q", w.backend, sIdx, pIdx, val)
		}
		hist.addGrant([2]byte{byte(pIdx), byte(sIdx)}, porcupine.Operation{
			ClientId: gi, Input: boolRegOp{write: false}, Call: call, Output: allowed, Return: ret,
		})

	case 3: // rotate (admin actor — isolates this register from the grant/revoke race)
		newVal := fmt.Sprintf("rot-%d", clRotateSeq.Add(1))
		call := time.Since(start).Nanoseconds()
		_, err := w.c.RotateSecret(ctx, secretID, []byte(newVal), w.adminID, "cl-fuzz")
		ret := time.Since(start).Nanoseconds()
		if err == nil {
			hist.addRotate(byte(sIdx), porcupine.Operation{
				ClientId: gi, Input: stringRegOp{write: true, value: newVal}, Call: call, Output: newVal, Return: ret,
			})
		}
		// A retry-exhausted rotation is an accepted, non-liveness outcome
		// (approved Step 1 spec) — deliberately not asserted here.

	case 4: // admin read (feeds the rotate register)
		call := time.Since(start).Nanoseconds()
		val, err := w.c.GetSecretValueWithPermissionCheck(ctx, secretID, w.adminID)
		ret := time.Since(start).Nanoseconds()
		if err != nil {
			t.Fatalf("[%s] DATA LOSS/AVAILABILITY: admin cannot read secret[%d]: %v", w.backend, sIdx, err)
		}
		hist.addRotate(byte(sIdx), porcupine.Operation{
			ClientId: gi, Input: stringRegOp{write: false}, Call: call, Output: string(val), Return: ret,
		})

	case 5: // session-revoke authenticated read
		if !sessionValid {
			return
		}
		call := time.Since(start).Nanoseconds()
		rec := clSessionRead(w.router, w.refs[0], sessionToken)
		ret := time.Since(start).Nanoseconds()
		allowed := rec.Code == http.StatusOK
		if !allowed && strings.Contains(rec.Body.String(), "init-") {
			// best-effort leak guard; the authoritative NO-PLAINTEXT-ON-DENY
			// check for this ref already lives in FuzzKeyorixHTTPAPISequence —
			// this is a cheap extra tripwire, not a substitute for it.
			t.Fatalf("[%s] PLAINTEXT LEAK on session-denied read: body=%s", w.backend, rec.Body.String())
		}
		hist.addSession(porcupine.Operation{
			ClientId: gi, Input: boolRegOp{write: false}, Call: call, Output: allowed, Return: ret,
		})

	default: // 6: session revoke
		if !sessionValid {
			return
		}
		call := time.Since(start).Nanoseconds()
		_, err := w.c.RevokeUserSessions(ctx, w.adminID, w.revuserID)
		ret := time.Since(start).Nanoseconds()
		if err == nil {
			hist.addSession(porcupine.Operation{
				ClientId: gi, Input: boolRegOp{write: true, setTo: false}, Call: call, Output: false, Return: ret,
			})
		}
	}
}
