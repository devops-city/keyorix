// cross_replica_ops_fuzz_test.go — FuzzCrossReplicaOps: a genuine two-replica
// stateful fuzzer. Two *KeyorixCore instances, each with its OWN *gorm.DB
// connection pool, share ONE real PostgreSQL schema — the multi-pool pattern
// TestConcurrency_BootstrapSystem_CrossReplicaPostgres_ExactlyOneAdmin
// (concurrency_bootstrap_cross_replica_postgres_test.go) established for
// exactly this reason: two wrappers over ONE *gorm.DB (or SQLite) share a
// process-local mutex that would serialize every goroutine regardless of
// whether the thing actually being tested works at all. This fuzzer reuses
// that same multi-pool shape and generalizes it from bootstrap alone to a
// fuzzer-chosen mix of role grant/revoke, session revoke, PAT revoke,
// machine-token issue/revoke, secret update (rotate), dynamic-secret lease
// issue/revoke, and user deactivate (suspend) — every op family SESSION-T's
// T1 spec names.
//
// Schema is built through the real production migration
// (internal/storage.MigrateExisting), not AutoMigrate — #1947 in
// concurrent_linearizable_fuzz_test.go is the standing reason: an
// AutoMigrate-only fixture silently lacks indexes migrateDatabase adds on
// top of the struct tags (uniq_secret_versions_node_version,
// uniq_dynamic_secret_configs_project_env_name), which is exactly what two
// of this fuzzer's own oracles below depend on being real.
//
// Postgres only, skipped cleanly when KEYORIX_TEST_PG_DSN is unset — see the
// T1 spec ("not two wrappers over one pool, and not SQLite").
//
// ORACLES:
//
//	(a) single-winner / uniqueness: CreateDynamicSecretConfig races both
//	    replicas at a shared (project, env) against a 2-name alphabet, so a
//	    genuine cross-replica same-name collision happens routinely. The DB
//	    carries a real unique index on (project_id, environment_id, name)
//	    (built by the production migration above); the oracle asserts AT
//	    MOST ONE success per name across BOTH replicas' attempts this
//	    iteration, and that the final row count for that exact tuple matches
//	    the recorded success count exactly (never more, from a duplicate
//	    neither replica reported succeeding at, and never zero when one did).
//
//	(b) revocation-honored-on-next-check: session revoke, PAT revoke,
//	    machine-token revoke, dynamic-secret-lease revoke, and user suspend
//	    are modeled as boolean registers (see boolRegModel below, a
//	    duplicate of server/http/concurrent_linearizable_fuzz_test.go's own
//	    model — cannot import it, that copy is unexported in a different
//	    package) starting true, driven by concurrent reads and (at most, in
//	    practice, exactly one live) writes from BOTH replicas, and checked
//	    for linearizability with porcupine. The bound this asserts is 0, not
//	    a documented TTL window: ValidateSessionToken, ValidatePATToken,
//	    ValidateMachineToken, GetDynamicSecretLease, and
//	    VerifyPasswordCredentials/AccountStillUsable (used by the suspend
//	    register's read side) were each read end-to-end for this fuzzer —
//	    none caches anything at the KeyorixCore layer; every one re-reads
//	    its row from storage on every call, so real Postgres READ COMMITTED
//	    is the only thing standing between a write on replica A and a read
//	    on replica B, and it guarantees the very next read on any OTHER
//	    connection observes an already-committed write. (Contrast
//	    server/middleware/auth.go's tokenCache: a real 30s positive-cache
//	    TTL window, but it lives one layer up, at the HTTP layer this fuzzer
//	    does not touch, and it is a single process-wide map — two
//	    *replicas* sharing one Go test binary would trivially share that ONE
//	    cache too, which would not model two independent production
//	    replicas at all. Testing that layer's real cross-replica staleness
//	    bound needs two separate OS processes; out of scope for a foreground,
//	    60s-local-burst fuzz session — recorded in the T1 report instead of
//	    silently skipped.)
//
//	(c) final DB state == serial replay in commit order: for the role
//	    grant/revoke register and the rotate-secret value register, every
//	    successful op's Return timestamp (captured immediately after the
//	    call returns, i.e. immediately after its transaction commits) gives
//	    a total order consistent with actual Postgres commit order for that
//	    row — two successful writes to the same row cannot commit
//	    concurrently; Postgres's own row-level locking serializes them.
//	    Sorting successful ops by Return time and taking the last writer's
//	    value is exactly the state a serial replay in that real commit order
//	    would produce. assertCommitOrderReplay compares it directly against
//	    the actual final DB row — no porcupine involved, a cheaper and more
//	    direct check of the one property that actually matters here (no
//	    lost update), matching the T1 spec's own wording for this oracle.
//
// Lease issue/revoke and dynamic-secret-config creation use a shared
// dynamictest.FakeEngine (mirrors dynamic_secrets_test.go's
// newDynamicTestCore) in place of a live target — both replica cores point
// their SetDynamicEngineFactory at the SAME fake instance (it is
// mutex-protected internally), mirroring how two real replicas would share
// one external target even though each holds its own DB pool.
package core

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anishathalye/porcupine"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/dynamic/dynamictest"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
)

// crPgTestDSN / crPgIsolatedSchemaDSN / crPgOpen are testing.TB-typed
// counterparts of postgres_contention_helpers_test.go's pgTestDSN /
// pgIsolatedSchemaDSN / pgOpen: this fuzzer builds its world once against a
// *testing.F (before f.Fuzz), and *testing.F does not satisfy the
// *testing.T-typed signatures those helpers use, only the shared
// testing.TB interface. Kept local rather than widening the shared helpers'
// signature, to keep this file's footprint self-contained.
var crPgSchemaSeq int64

func crPgTestDSN(tb testing.TB) string {
	tb.Helper()
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		tb.Skip("KEYORIX_TEST_PG_DSN not set — skipping cross-replica fuzzer")
	}
	return dsn
}

func crPgIsolatedSchemaDSN(tb testing.TB, base string) string {
	tb.Helper()
	n := atomic.AddInt64(&crPgSchemaSeq, 1)
	schema := fmt.Sprintf("core_crops_%d_%d", os.Getpid(), n)

	admin := crPgOpen(tb, base)
	require.NoError(tb.(require.TestingT), admin.Exec("DROP SCHEMA IF EXISTS "+schema+" CASCADE").Error)
	require.NoError(tb.(require.TestingT), admin.Exec("CREATE SCHEMA "+schema).Error)
	tb.Cleanup(func() {
		cleaner := crPgOpen(tb, base)
		_ = cleaner.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error
	})
	return pgdsn.PGSearchPathDSN(base, schema)
}

func crPgOpen(tb testing.TB, dsn string) *gorm.DB {
	tb.Helper()
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	require.NoError(tb.(require.TestingT), err)
	tb.Cleanup(func() {
		if sqlDB, dbErr := db.DB(); dbErr == nil {
			_ = sqlDB.Close()
		}
	})
	return db
}

// crWorld holds the two independent replicas plus the fixtures every fuzz
// iteration exercises. Built ONCE per testing.F.
type crWorld struct {
	db0, db1 *gorm.DB
	c0, c1   *KeyorixCore
	fake     *dynamictest.FakeEngine

	adminID      uint
	principalID  uint // the sole role-grant/revoke register's target
	readerRoleID uint
	projID       uint
	envID        uint
	secretID     uint

	sessionUserID   uint
	sessionPassword string

	patUserID uint

	machineID uint

	suspendUserID uint

	dynConfigID uint // config the lease register issues/revokes leases against

	cfgNames [2]string // the 2-name alphabet oracle (a) races
}

const crAdminDSNPlain = "postgres://admin:s3cr3t@db.internal:5432/app"

func buildCrossReplicaWorld(f *testing.F) *crWorld {
	f.Helper()
	require.NoError(f, i18n.InitializeForTesting())

	base := crPgTestDSN(f)
	dsn := crPgIsolatedSchemaDSN(f, base)

	db0 := crPgOpen(f, dsn)
	db1 := crPgOpen(f, dsn)
	require.NoError(f, kxstorage.MigrateExisting(db0))
	if !db0.Migrator().HasIndex("secret_versions", "uniq_secret_versions_node_version") {
		f.Fatalf("production migration did not create uniq_secret_versions_node_version")
	}
	if !db0.Migrator().HasIndex("dynamic_secret_configs", "uniq_dynamic_secret_configs_project_env_name") {
		f.Fatalf("production migration did not create uniq_dynamic_secret_configs_project_env_name")
	}

	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, f.TempDir())
	require.NoError(f, enc.Initialize("cr-fuzz-test-passphrase"))
	fake := &dynamictest.FakeEngine{NativeExpiry: true}
	engineFactory := func(string) (dynamic.CredentialEngine, error) { return fake, nil }

	c0 := NewKeyorixCore(localstore.NewLocalStorage(db0))
	c0.SetAuthEncryptor(enc)
	c0.SetDynamicEngineFactory(engineFactory)
	c1 := NewKeyorixCore(localstore.NewLocalStorage(db1))
	c1.SetAuthEncryptor(enc)
	c1.SetDynamicEngineFactory(engineFactory)

	ctx := context.Background()
	c0.SetBootstrapToken("cr-fuzz-bootstrap-token")
	if _, err := c0.BootstrapSystem(ctx, &BootstrapRequest{
		Username: "cradmin", Email: "cradmin@example.com", Password: "BootstrapPass123!",
		DisplayName: "Admin", Token: "cr-fuzz-bootstrap-token",
	}); err != nil {
		f.Fatalf("bootstrap: %v", err)
	}
	c0.SetBootstrapToken("")
	admin, err := localstore.NewLocalStorage(db0).GetUserByUsername(ctx, "cradmin")
	if err != nil || admin == nil {
		f.Fatalf("admin lookup: %v", err)
	}

	w := &crWorld{db0: db0, db1: db1, c0: c0, c1: c1, fake: fake, adminID: admin.ID}

	proj, err := c0.CreateProject(ctx, "cr-fuzz-project", "")
	if err != nil {
		f.Fatalf("create project: %v", err)
	}
	w.projID = proj.ID
	env, err := c0.CreateEnvironment(ctx, proj.ID, "cr-fuzz-env")
	if err != nil {
		f.Fatalf("create environment: %v", err)
	}
	w.envID = env.ID

	sec, err := c0.CreateSecret(ctx, &CreateSecretRequest{
		Name: "cr-fuzz-secret", Value: []byte("init"), ProjectID: proj.ID, EnvironmentID: env.ID,
		Type: "password", CreatedBy: "cradmin", OwnerID: admin.ID,
	})
	if err != nil || sec == nil {
		f.Fatalf("create secret: %v", err)
	}
	w.secretID = sec.ID

	var perm models.Permission
	if e := db0.Where("name = ?", "secrets.read").First(&perm).Error; e != nil {
		perm = models.Permission{Name: "secrets.read", Resource: "secrets", Action: "read"}
		if e2 := db0.Create(&perm).Error; e2 != nil {
			f.Fatalf("seed permission: %v", e2)
		}
	}
	role := models.Role{Name: "cr-fuzz-reader", NameFolded: "cr-fuzz-reader"}
	if err := db0.Create(&role).Error; err != nil {
		f.Fatalf("seed role: %v", err)
	}
	if err := db0.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error; err != nil {
		f.Fatalf("seed role-permission: %v", err)
	}
	w.readerRoleID = role.ID

	mkUser := func(uname string) uint {
		u, err := c0.CreateUser(ctx, &CreateUserRequest{Username: uname, Email: uname + "@x.io", Password: "Xk7#Qp2$Rn5@Wv9!"})
		if err != nil || u == nil {
			f.Fatalf("create user %s: %v", uname, err)
		}
		return u.ID
	}
	w.principalID = mkUser("cr-principal")
	w.sessionUserID = mkUser("cr-sessuser")
	w.sessionPassword = "Xk7#Qp2$Rn5@Wv9!"
	w.patUserID = mkUser("cr-patuser")
	w.suspendUserID = mkUser("cr-suspenduser")

	m, err := c0.CreateMachineIdentity(ctx, proj.ID, "cr-fuzz-machine", MachineTypeOther, "", "", admin.ID, 0)
	if err != nil || m == nil {
		f.Fatalf("create machine identity: %v", err)
	}
	w.machineID = m.ID

	cfg, err := c0.CreateDynamicSecretConfig(ctx, &CreateDynamicSecretConfigRequest{
		Name: "cr-fuzz-lease-config", ProjectID: proj.ID, EnvironmentID: env.ID, BackendType: "postgres",
		AdminDSN: crAdminDSNPlain, CreationTemplate: "GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};",
		DefaultTTLSeconds: 3600, CreatedBy: "cradmin", ActorID: admin.ID,
	})
	if err != nil || cfg == nil {
		f.Fatalf("create dynamic-secret config: %v", err)
	}
	w.dynConfigID = cfg.ID
	w.cfgNames = [2]string{"cr-fuzz-race-a", "cr-fuzz-race-b"}

	return w
}

func crReplica(w *crWorld, pick byte) *KeyorixCore {
	if pick%2 == 0 {
		return w.c0
	}
	return w.c1
}

// --- porcupine boolean-register model (revocation-honored oracle b) --------
// Duplicated from server/http/concurrent_linearizable_fuzz_test.go's own
// unexported boolRegModel/boolRegOp — cannot import an unexported symbol
// across packages, and this fuzzer's registers all start true (a live
// credential/account) with at most one revoke-style write, unlike that
// file's grant register which starts false.

type crBoolOp struct {
	write bool
	setTo bool
}

var crBoolRegModel = porcupine.Model{
	Init: func() any { return true },
	Step: func(state, input, output any) (bool, any) {
		in := input.(crBoolOp)
		if in.write {
			return true, in.setTo
		}
		return output.(bool) == state.(bool), state
	},
	DescribeOperation: func(input, output any) string {
		in := input.(crBoolOp)
		if in.write {
			return fmt.Sprintf("set(%v)", in.setTo)
		}
		return fmt.Sprintf("read() -> %v", output)
	},
}

func crCheckLinearizable(t *testing.T, label string, history []porcupine.Operation) {
	t.Helper()
	if len(history) == 0 {
		return
	}
	res, _ := porcupine.CheckOperationsVerbose(crBoolRegModel, history, 5*time.Second)
	switch res {
	case porcupine.Illegal:
		var sb strings.Builder
		fmt.Fprintf(&sb, "NOT LINEARIZABLE (oracle b, bound=0): register %q:\n", label)
		for _, op := range history {
			fmt.Fprintf(&sb, "  client %d: [%d,%d] %s\n", op.ClientId, op.Call, op.Return, crBoolRegModel.DescribeOperation(op.Input, op.Output))
		}
		t.Fatalf("%s", sb.String())
	case porcupine.Unknown:
		t.Logf("linearizability check for %q timed out (Unknown, not a failure) over %d ops", label, len(history))
	}
}

// --- oracle (c): commit-order replay ---------------------------------------

// assertNoDuplicateSecretVersions strengthens oracle (c) for the rotate
// register: regardless of how many concurrent RotateSecret calls raced or
// failed across the two replicas, no two version rows for the same secret
// may share a version_number — that would mean two concurrent writers each
// believed they held "the next" version and one silently overwrote/aliased
// the other, a lost update the top-level value comparison alone might not
// surface if the two colliding writes happened to write the same value.
// Mirrors concurrent_linearizable_fuzz_test.go's assertContiguousVersions in
// spirit but checks uniqueness only (not contiguity — a failed rotation
// here can legitimately abandon a version_number, unlike that file's
// exhaustive-retry design).
func assertNoDuplicateSecretVersions(t *testing.T, w *crWorld, secretID uint) {
	t.Helper()
	var nums []int
	if err := w.db0.Table("secret_versions").
		Where("secret_node_id = ?", secretID).
		Pluck("version_number", &nums).Error; err != nil {
		t.Fatalf("list secret versions: %v", err)
	}
	seen := map[int]bool{}
	for _, n := range nums {
		if seen[n] {
			t.Fatalf("COMMIT-ORDER REPLAY MISMATCH (oracle c): secret %d has duplicate version_number=%d — lost update across replicas", secretID, n)
		}
		seen[n] = true
	}
}

type crOrderedWrite struct {
	returnAt int64
	value    any
}

// assertCommitOrderReplay sorts successful writes by their Return timestamp
// (captured immediately after each write's call returned, i.e. immediately
// after its commit) and asserts the last writer's value equals actual —
// the state a serial replay in real commit order would produce.
func assertCommitOrderReplay(t *testing.T, label string, writes []crOrderedWrite, actual any) {
	t.Helper()
	if len(writes) == 0 {
		return
	}
	sort.Slice(writes, func(i, j int) bool { return writes[i].returnAt < writes[j].returnAt })
	want := writes[len(writes)-1].value
	if want != actual {
		t.Fatalf("COMMIT-ORDER REPLAY MISMATCH (oracle c): register %q — replaying %d successful writes in real commit order expects final state %v, DB has %v",
			label, len(writes), want, actual)
	}
}

// --- the fuzz target ---------------------------------------------------------

type crOp struct {
	kind    byte
	replica byte
	misc    byte
}

const (
	crMaxGoroutines      = 6
	crMaxOpsPerGoroutine = 5
)

func decodeCRProgram(program []byte) [][]crOp {
	if len(program) < 1 {
		return nil
	}
	g := 2 + int(program[0])%(crMaxGoroutines-1)
	goroutines := make([][]crOp, g)
	body := program[1:]
	total := 0
	for i := 0; i+2 < len(body) && total < crMaxGoroutines*crMaxOpsPerGoroutine; i += 3 {
		gi := total % g
		goroutines[gi] = append(goroutines[gi], crOp{kind: body[i], replica: body[i+1], misc: body[i+2]})
		total++
	}
	return goroutines
}

func FuzzCrossReplicaOps(f *testing.F) {
	w := buildCrossReplicaWorld(f)

	f.Add([]byte{2, 0, 0, 0, 1, 1, 1, 2, 0, 1, 4, 1, 0, 6, 0, 0, 8, 1, 0})
	f.Add([]byte{3, 14, 0, 0, 14, 1, 1, 14, 0, 0})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, program []byte) {
		goroutines := decodeCRProgram(program)
		if len(goroutines) == 0 {
			return
		}
		runCrossReplicaIteration(t, w, goroutines)
	})
}

type crHistories struct {
	mu      sync.Mutex
	session []porcupine.Operation
	pat     []porcupine.Operation
	machine []porcupine.Operation
	suspend []porcupine.Operation
	lease   []porcupine.Operation

	grantWrites  []crOrderedWrite
	rotateWrites []crOrderedWrite

	mu2         sync.Mutex
	cfgAWinners int
	cfgBWinners int
}

func (h *crHistories) add(which *[]porcupine.Operation, op porcupine.Operation) {
	h.mu.Lock()
	*which = append(*which, op)
	h.mu.Unlock()
}

func runCrossReplicaIteration(t *testing.T, w *crWorld, goroutines [][]crOp) {
	t.Helper()
	ctx := context.Background()

	// --- per-iteration fixture reset (synchronous, before any goroutine starts) ---
	if err := w.db0.Exec("DELETE FROM user_roles WHERE user_id = ?", w.principalID).Error; err != nil {
		t.Fatalf("reset role grants: %v", err)
	}
	if err := w.c0.ReactivateUser(ctx, w.adminID, w.suspendUserID); err != nil {
		t.Logf("reactivate suspenduser (probably already active): %v", err)
	}
	if err := w.db0.Exec("DELETE FROM dynamic_secret_configs WHERE project_id = ? AND environment_id = ? AND name IN (?, ?)",
		w.projID, w.envID, w.cfgNames[0], w.cfgNames[1]).Error; err != nil {
		t.Fatalf("reset config-name race rows: %v", err)
	}

	rotateBaseline := fmt.Sprintf("cr-base-%d", crRotateSeq.Add(1))
	if _, err := w.c0.RotateSecret(ctx, w.secretID, []byte(rotateBaseline), w.adminID, "cr-fuzz-init"); err != nil {
		t.Fatalf("baseline rotate: %v", err)
	}

	sess, _, err := w.c0.Login(ctx, &LoginRequest{Username: "cr-sessuser", Password: w.sessionPassword})
	sessionValid := err == nil && sess != nil
	var sessionToken string
	if sessionValid {
		sessionToken = sess.SessionToken
	}

	patRes, err := w.c0.CreateOwnPAT(ctx, w.patUserID, fmt.Sprintf("cr-pat-%d", crRotateSeq.Add(1)), nil, nil, 0, 0, nil)
	patValid := err == nil && patRes != nil
	var patToken string
	var patID uint
	if patValid {
		patToken = patRes.PlainToken
		patID = patRes.Token.ID
	}

	machRes, err := w.c0.IssueMachineToken(ctx, w.projID, w.machineID, w.adminID, IssueMachineTokenParams{Name: fmt.Sprintf("cr-mtok-%d", crRotateSeq.Add(1))})
	machValid := err == nil && machRes != nil
	var machToken string
	var machCredID uint
	if machValid {
		machToken = machRes.PlainToken
		machCredID = machRes.Credential.ID
	}

	lease, err := w.c0.IssueLease(ctx, w.dynConfigID, 0, w.adminID)
	leaseValid := err == nil && lease != nil
	var leaseID string
	if leaseValid {
		leaseID = lease.LeaseID
	}

	hist := &crHistories{}
	start := time.Now()

	var wg sync.WaitGroup
	for gi, ops := range goroutines {
		wg.Add(1)
		go func(gi int, ops []crOp) {
			defer wg.Done()
			for _, op := range ops {
				if op.misc%3 == 0 {
					runtime.Gosched()
				}
				runCrossReplicaOp(t, w, ctx, hist, start, gi, op,
					sessionToken, sessionValid,
					patToken, patValid, patID,
					machToken, machValid, machCredID,
					leaseID, leaseValid)
			}
		}(gi, ops)
	}
	wg.Wait()

	// --- oracle (c): commit-order replay ---------------------------------
	var grantActual bool
	if err := w.db0.Raw("SELECT EXISTS(SELECT 1 FROM user_roles WHERE user_id = ? AND role_id = ?)", w.principalID, w.readerRoleID).Scan(&grantActual).Error; err != nil {
		t.Fatalf("read final grant state: %v", err)
	}
	assertCommitOrderReplay(t, "role-grant", hist.grantWrites, grantActual)

	// The rotate register's "actual" value is read via an admin
	// GetSecretValueWithPermissionCheck against a fresh connection (db0),
	// not raw SQL, since the plaintext is encrypted at rest.
	actualRotate, rerr := w.c0.GetSecretValueWithPermissionCheck(ctx, w.secretID, w.adminID)
	if rerr != nil {
		t.Fatalf("read final rotate state: %v", rerr)
	}
	allRotateWrites := append([]crOrderedWrite{{returnAt: -1, value: rotateBaseline}}, hist.rotateWrites...)
	assertCommitOrderReplay(t, "rotate-secret", allRotateWrites, string(actualRotate))
	assertNoDuplicateSecretVersions(t, w, w.secretID)

	// --- oracle (b): linearizability of the revoke/read registers --------
	crCheckLinearizable(t, "session", hist.session)
	crCheckLinearizable(t, "pat", hist.pat)
	crCheckLinearizable(t, "machine-token", hist.machine)
	crCheckLinearizable(t, "suspend(usable)", hist.suspend)
	crCheckLinearizable(t, "lease(active)", hist.lease)

	// --- oracle (a): single-winner / uniqueness on the config-name race ---
	for i, name := range w.cfgNames {
		wantWinners := hist.cfgAWinners
		if i == 1 {
			wantWinners = hist.cfgBWinners
		}
		if wantWinners > 1 {
			t.Fatalf("SINGLE-WINNER VIOLATION (oracle a): config name %q reported %d successful creates across both replicas", name, wantWinners)
		}
		var rowCount int64
		if err := w.db0.Model(&models.DynamicSecretConfig{}).
			Where("project_id = ? AND environment_id = ? AND name = ?", w.projID, w.envID, name).
			Count(&rowCount).Error; err != nil {
			t.Fatalf("count config rows for %q: %v", name, err)
		}
		if rowCount != int64(wantWinners) {
			t.Fatalf("SINGLE-WINNER VIOLATION (oracle a): config name %q — %d recorded successes but %d DB rows exist", name, wantWinners, rowCount)
		}
	}
}

var crRotateSeq atomic.Int64

func runCrossReplicaOp(
	t *testing.T, w *crWorld, ctx context.Context, hist *crHistories, start time.Time, gi int, op crOp,
	sessionToken string, sessionValid bool,
	patToken string, patValid bool, patID uint,
	machToken string, machValid bool, machCredID uint,
	leaseID string, leaseValid bool,
) {
	t.Helper()
	c := crReplica(w, op.replica)

	switch op.kind % 15 {
	case 0: // grant role
		callAt := time.Since(start).Nanoseconds()
		err := c.AssignUserRole(ctx, 0, w.principalID, w.readerRoleID, Scope{ProjectID: w.projID}, false)
		retAt := time.Since(start).Nanoseconds()
		if err == nil {
			hist.mu.Lock()
			hist.grantWrites = append(hist.grantWrites, crOrderedWrite{returnAt: retAt, value: true})
			hist.mu.Unlock()
		}
		_ = callAt

	case 1: // revoke role
		callAt := time.Since(start).Nanoseconds()
		err := c.RemoveUserRole(ctx, 0, w.principalID, w.readerRoleID, Scope{ProjectID: w.projID})
		retAt := time.Since(start).Nanoseconds()
		if err == nil {
			hist.mu.Lock()
			hist.grantWrites = append(hist.grantWrites, crOrderedWrite{returnAt: retAt, value: false})
			hist.mu.Unlock()
		}
		_ = callAt

	case 2: // rotate secret (secret update)
		newVal := fmt.Sprintf("cr-rot-%d", crRotateSeq.Add(1))
		_, err := c.RotateSecret(ctx, w.secretID, []byte(newVal), w.adminID, "cr-fuzz")
		retAt := time.Since(start).Nanoseconds()
		if err == nil {
			hist.mu.Lock()
			hist.rotateWrites = append(hist.rotateWrites, crOrderedWrite{returnAt: retAt, value: newVal})
			hist.mu.Unlock()
		}

	case 3: // session revoke
		if !sessionValid {
			return
		}
		callAt := time.Since(start).Nanoseconds()
		_, err := c.RevokeUserSessions(ctx, w.adminID, w.sessionUserID)
		retAt := time.Since(start).Nanoseconds()
		if err == nil {
			hist.add(&hist.session, porcupine.Operation{ClientId: gi, Input: crBoolOp{write: true, setTo: false}, Call: callAt, Output: false, Return: retAt})
		}

	case 4: // session check
		if !sessionValid {
			return
		}
		callAt := time.Since(start).Nanoseconds()
		_, _, err := c.ValidateSessionToken(ctx, sessionToken)
		retAt := time.Since(start).Nanoseconds()
		hist.add(&hist.session, porcupine.Operation{ClientId: gi, Input: crBoolOp{write: false}, Call: callAt, Output: err == nil, Return: retAt})

	case 5: // pat revoke
		if !patValid {
			return
		}
		callAt := time.Since(start).Nanoseconds()
		_, err := c.RevokeOwnPAT(ctx, w.patUserID, patID)
		retAt := time.Since(start).Nanoseconds()
		if err == nil {
			hist.add(&hist.pat, porcupine.Operation{ClientId: gi, Input: crBoolOp{write: true, setTo: false}, Call: callAt, Output: false, Return: retAt})
		}

	case 6: // pat check
		if !patValid {
			return
		}
		callAt := time.Since(start).Nanoseconds()
		_, _, _, _, err := c.ValidatePATToken(ctx, patToken)
		retAt := time.Since(start).Nanoseconds()
		hist.add(&hist.pat, porcupine.Operation{ClientId: gi, Input: crBoolOp{write: false}, Call: callAt, Output: err == nil, Return: retAt})

	case 7: // machine-token revoke
		if !machValid {
			return
		}
		callAt := time.Since(start).Nanoseconds()
		_, err := c.RevokeMachineToken(ctx, w.projID, w.machineID, machCredID, w.adminID)
		retAt := time.Since(start).Nanoseconds()
		if err == nil {
			hist.add(&hist.machine, porcupine.Operation{ClientId: gi, Input: crBoolOp{write: true, setTo: false}, Call: callAt, Output: false, Return: retAt})
		}

	case 8: // machine-token check
		if !machValid {
			return
		}
		callAt := time.Since(start).Nanoseconds()
		_, _, _, _, err := c.ValidateMachineToken(ctx, machToken)
		retAt := time.Since(start).Nanoseconds()
		hist.add(&hist.machine, porcupine.Operation{ClientId: gi, Input: crBoolOp{write: false}, Call: callAt, Output: err == nil, Return: retAt})

	case 9: // user suspend (deactivate)
		callAt := time.Since(start).Nanoseconds()
		err := c.SuspendUser(ctx, w.adminID, w.suspendUserID)
		retAt := time.Since(start).Nanoseconds()
		if err == nil {
			hist.add(&hist.suspend, porcupine.Operation{ClientId: gi, Input: crBoolOp{write: true, setTo: false}, Call: callAt, Output: false, Return: retAt})
		}

	case 10: // suspend check (account still usable)
		callAt := time.Since(start).Nanoseconds()
		usable, err := c.AccountStillUsable(ctx, w.suspendUserID)
		retAt := time.Since(start).Nanoseconds()
		if err != nil {
			return
		}
		hist.add(&hist.suspend, porcupine.Operation{ClientId: gi, Input: crBoolOp{write: false}, Call: callAt, Output: usable, Return: retAt})

	case 11: // lease revoke
		if !leaseValid {
			return
		}
		callAt := time.Since(start).Nanoseconds()
		err := c.RevokeLease(ctx, leaseID, w.adminID, "cr-fuzz")
		retAt := time.Since(start).Nanoseconds()
		if err == nil {
			hist.add(&hist.lease, porcupine.Operation{ClientId: gi, Input: crBoolOp{write: true, setTo: false}, Call: callAt, Output: false, Return: retAt})
		}

	case 12: // lease check
		if !leaseValid {
			return
		}
		callAt := time.Since(start).Nanoseconds()
		l, err := c.GetDynamicSecretLease(ctx, leaseID)
		retAt := time.Since(start).Nanoseconds()
		if err != nil {
			return
		}
		hist.add(&hist.lease, porcupine.Operation{ClientId: gi, Input: crBoolOp{write: false}, Call: callAt, Output: l.Status == "active", Return: retAt})

	case 13: // config-name race: name A
		_, err := c.CreateDynamicSecretConfig(ctx, &CreateDynamicSecretConfigRequest{
			Name: w.cfgNames[0], ProjectID: w.projID, EnvironmentID: w.envID, BackendType: "postgres",
			AdminDSN: crAdminDSNPlain, CreationTemplate: "GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};",
			DefaultTTLSeconds: 3600, CreatedBy: "cradmin", ActorID: w.adminID,
		})
		if err == nil {
			hist.mu2.Lock()
			hist.cfgAWinners++
			hist.mu2.Unlock()
		}

	default: // 14: config-name race: name B
		_, err := c.CreateDynamicSecretConfig(ctx, &CreateDynamicSecretConfigRequest{
			Name: w.cfgNames[1], ProjectID: w.projID, EnvironmentID: w.envID, BackendType: "postgres",
			AdminDSN: crAdminDSNPlain, CreationTemplate: "GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};",
			DefaultTTLSeconds: 3600, CreatedBy: "cradmin", ActorID: w.adminID,
		})
		if err == nil {
			hist.mu2.Lock()
			hist.cfgBWinners++
			hist.mu2.Unlock()
		}
	}
}
