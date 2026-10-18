// fast_audit_mode_test.go — ADR-112 Amendment 1 / FASTAUDIT-1
// (docs/specs/fast-audit-mode.md): the store-layer guards for the opt-in
// fast audit mode.
//
// What these tests DO cover: the default is durable; the Postgres mechanism
// is exactly `SET LOCAL synchronous_commit = off` and only on the audit
// transaction; that setting does not leak to the next transaction borrowing
// the same pooled connection; fail-closed-on-write-failure survives the mode;
// a transaction-scoped clone never inherits it.
//
// What they do NOT cover, stated per this repo's own standing lesson ("name
// mechanisms for what they verify, and state in the doc comment what they do
// not"): they do not prove anything about what survives an OS crash or power
// loss. No Go test can — losing the OS page cache is outside the process's
// control. The crash-resistance claim is tested, as far as it can be, by
// fast_audit_mode_crash_test.go (a real kill -9 loop, plus a mechanical
// SQLite WAL-tail truncation that models the lost-tail case directly).
package store

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// TestApplyAuditCommitDurability_OffIssuesNoStatementAtAll pins the thing a
// "the default still waits for the sync" test actually has to establish: that
// with the setting off, the audit transaction issues NO durability statement,
// so the commit inherits whatever the cluster/role is configured with (on, by
// ADR-112 §3) rather than anything this code chose.
//
// The two directions are observed through a SQLite handle on purpose, and this
// is the whole trick that makes the assertion sharp rather than vacuous:
// `SET LOCAL synchronous_commit = off` is not valid SQLite, so SQLite itself
// is the oracle for "was a statement issued?" — off must return nil (nothing
// ran, nothing to reject), and on must return a non-nil error (the statement
// ran and SQLite rejected it). A mutation that made the function a no-op in
// both directions, or issued its statement in both, fails one half or the
// other. Production only ever calls this with a postgres dialect; see its
// callers in local_audit_chain.go.
func TestApplyAuditCommitDurability_OffIssuesNoStatementAtAll(t *testing.T) {
	ls := newAuditChainTestStore(t)

	require.NoError(t, applyAuditCommitDurability(ls.db, false),
		"with the fast audit mode OFF this must issue no statement whatsoever, so the audit commit "+
			"keeps whatever synchronous_commit the cluster is configured with -- a no-op is the secure default")

	err := applyAuditCommitDurability(ls.db, true)
	require.Error(t, err,
		"with the fast audit mode ON this must actually issue `SET LOCAL synchronous_commit = off`; "+
			"observed here through a SQLite handle, which rejects that statement -- an error is the proof "+
			"the statement was issued at all. If this ever returns nil, the mechanism has become a no-op "+
			"and every fast-mode measurement downstream of it is measuring nothing.")
}

// TestFastAuditMode_DefaultIsDurableSync is the cheap, direct statement of
// S4: a LocalStorage built the normal way has the weak mode OFF, because the
// field's zero value is the secure one. A construction site that forgets to
// call SetAuditSkipDurableSync gets durable commits.
func TestFastAuditMode_DefaultIsDurableSync(t *testing.T) {
	ls := newAuditChainTestStore(t)
	require.False(t, ls.auditSkipDurableSync,
		"NewLocalStorage must leave the fast audit mode off -- the zero value has to be the secure one, "+
			"so forgetting to configure it can never be the weakening")

	ls.SetAuditSkipDurableSync(true)
	require.True(t, ls.auditSkipDurableSync)
	ls.SetAuditSkipDurableSync(false)
	require.False(t, ls.auditSkipDurableSync)
}

// TestWithTransaction_CloneNeverInheritsAuditSkipDurableSync guards the
// local_transaction.go omission that is a correctness requirement, not a
// style choice: a transaction-scoped clone's audit append runs
// logAuditEventDirect inside the CALLER's transaction (GORM nests it as a
// SAVEPOINT), so a `SET LOCAL synchronous_commit = off` issued there would
// relax the commit durability of the caller's whole transaction -- the secret
// mutation included -- not just the audit row.
//
// Behavioural half: exercises the real WithTransaction and reads the field off
// the clone it actually hands out. The structural half, which covers every
// clone site including ones this test never calls, is
// TestEveryLocalStorageCloneOmitsAuditSkipDurableSync below.
func TestWithTransaction_CloneNeverInheritsAuditSkipDurableSync(t *testing.T) {
	ls := newAuditChainTestStore(t)
	ls.SetAuditSkipDurableSync(true)

	var sawSkip bool
	var sawClone bool
	require.NoError(t, ls.WithTransaction(context.Background(), func(s storage.Storage) error {
		clone, ok := s.(*LocalStorage)
		require.True(t, ok, "WithTransaction must hand fn a *LocalStorage")
		sawClone = true
		sawSkip = clone.auditSkipDurableSync
		return nil
	}))

	require.True(t, sawClone, "the transaction body never ran -- this test would pass vacuously")
	require.False(t, sawSkip,
		"a transaction-scoped clone must NOT inherit auditSkipDurableSync: its audit append runs inside "+
			"the caller's own transaction, so relaxing durability there would weaken the caller's mutation, "+
			"not just the audit row (see local_transaction.go's comment)")
}

// TestEveryLocalStorageCloneOmitsAuditSkipDurableSync is the structural half,
// added after coordinator review of #2828 pointed out that
// RemoveGlobalAdminRoleGuarded (local_rbac.go) builds a SECOND
// transaction-scoped clone which the behavioural test above never touches --
// correct today, but untested, and a third clone site would be invisible to a
// hand-written list.
//
// AST-DERIVED, not grep-derived, and not file-listed. It parses every non-test
// file in this package and finds every composite literal of type LocalStorage,
// so a clone added tomorrow in a file nobody thought about is covered the
// moment it is written. Then it asserts that none of them -- except the root
// constructor NewLocalStorage, which is the one place that legitimately
// populates the struct -- sets auditSkipDurableSync.
//
// WHAT IT DOES NOT CATCH, stated so the gap reads as considered: a clone built
// by whole-struct copy (`clone := *ls`) rather than a composite literal, or by
// reflection, carries every field including this one and is NOT a composite
// literal, so this walk would not see it. The behavioural test above is what
// catches that shape for WithTransaction specifically. The two together cover
// "every literal clone site, known or future" plus "the one clone path a
// caller actually receives"; neither alone covers both.
func TestEveryLocalStorageCloneOmitsAuditSkipDurableSync(t *testing.T) {
	const fieldName = "auditSkipDurableSync"
	const rootConstructor = "NewLocalStorage"

	thisFile := filepath.Join(srcpath.PkgDir(), "fast_audit_mode_test.go")
	pkgDir := filepath.Dir(thisFile)

	entries, err := os.ReadDir(pkgDir)
	require.NoError(t, err)

	fset := token.NewFileSet()
	type site struct {
		fn       string
		pos      string
		setsSkip bool
	}
	var sites []site

	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(pkgDir, name), nil, parser.ParseComments)
		require.NoErrorf(t, perr, "parse %s", name)

		for _, decl := range f.Decls {
			fn, isFunc := decl.(*ast.FuncDecl)
			if !isFunc || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				lit, isLit := n.(*ast.CompositeLit)
				if !isLit {
					return true
				}
				// Matches both `LocalStorage{...}` and `&LocalStorage{...}`
				// (the & is a UnaryExpr wrapping this same literal, so the
				// literal's own Type is the bare Ident either way).
				ident, isIdent := lit.Type.(*ast.Ident)
				if !isIdent || ident.Name != "LocalStorage" {
					return true
				}
				s := site{fn: fn.Name.Name, pos: fset.Position(lit.Pos()).String()}
				for _, elt := range lit.Elts {
					kv, isKV := elt.(*ast.KeyValueExpr)
					if !isKV {
						continue
					}
					if key, kok := kv.Key.(*ast.Ident); kok && key.Name == fieldName {
						s.setsSkip = true
					}
				}
				sites = append(sites, s)
				return true
			})
		}
	}

	// Positive controls. If the walk finds nothing, or finds only the
	// constructor, it has stopped looking at what it claims to look at and
	// every assertion below would hold vacuously.
	require.NotEmpty(t, sites,
		"the AST walk found NO LocalStorage composite literals in this package. Either the type was renamed "+
			"or this walk is broken -- either way it is no longer guarding anything")
	var sawConstructor, cloneCount int
	for _, s := range sites {
		if s.fn == rootConstructor {
			sawConstructor++
			continue
		}
		cloneCount++
	}
	require.Equal(t, 1, sawConstructor,
		"expected exactly one LocalStorage literal inside %s (the root constructor). Found %d. Sites: %+v",
		rootConstructor, sawConstructor, sites)
	require.GreaterOrEqualf(t, cloneCount, 2,
		"expected at least 2 clone sites outside %s (WithTransaction in local_transaction.go and "+
			"RemoveGlobalAdminRoleGuarded in local_rbac.go). Found %d: %+v. If a clone site was legitimately "+
			"removed, lower this number deliberately -- do not let the guard silently stop covering anything.",
		rootConstructor, cloneCount, sites)

	for _, s := range sites {
		if s.fn == rootConstructor {
			continue
		}
		require.Falsef(t, s.setsSkip,
			"%s (%s) sets %s on a transaction-scoped LocalStorage clone. It must NOT: a clone's audit append "+
				"runs logAuditEventDirect inside the CALLER's transaction, so `SET LOCAL synchronous_commit = "+
				"off` issued there would relax the commit durability of the caller's whole transaction -- the "+
				"secret mutation included -- rather than just the audit row. Leave the field at its zero "+
				"value (false, durable). See local_transaction.go's comment.",
			s.fn, s.pos, fieldName)
	}

	t.Logf("checked %d LocalStorage literal(s): 1 constructor + %d clone site(s)", len(sites), cloneCount)
}

// TestFastAuditMode_StillFailsClosedOnWriteFailure is S1. The mode removes the
// WAIT for a sync, never the fail-closed behaviour: if the audit row cannot be
// WRITTEN, LogAuditEvent still returns an error and the caller still fails.
//
// POSTGRES-GATED, and that is the point. The first version of this test ran on
// SQLite, where the flag is inert after the Postgres-only decision — so it
// would have passed identically with the mode OFF, which makes it a test of
// LogAuditEvent's ordinary error path rather than of this mode's fail-closed
// behaviour. Coordinator review of #2828 caught that. On Postgres the mode is
// genuinely in effect (`SET LOCAL synchronous_commit = off` really is issued
// inside the transaction that then fails), so the assertion is about the thing
// its name claims.
//
// Asserts the EFFECT, not a return value alone, and drops the table out from
// under the writer to make the write genuinely impossible rather than mocking a
// failure shape the real system may not produce.
func TestFastAuditMode_StillFailsClosedOnWriteFailure(t *testing.T) {
	ls, _ := newPostgresAuditStore(t)
	ls.SetAuditSkipDurableSync(true)

	// Positive control first: the mode is on and an ordinary append works, so
	// the failure below is attributable to the dropped table and not to the
	// mode breaking writes outright.
	appendEvent(t, ls, "fastaudit.control", "before the table is dropped", time.Now().UTC())

	require.NoError(t, ls.db.Exec("DROP TABLE audit_events").Error)

	tr := true
	err := ls.LogAuditEvent(context.Background(), &models.AuditEvent{
		EventType: "fastaudit.should_fail", Description: "no table to write to",
		Success: &tr, EventTime: time.Now().UTC(), ActorType: "system",
	})
	require.Error(t, err,
		"with the fast audit mode on, an audit row that cannot be WRITTEN must still fail the call -- "+
			"only the wait for the disk sync is skipped, never the write and never the fail-closed path")

	// And no row survives: assert the effect, not just the returned error. A
	// mode that had quietly become best-effort could return an error from one
	// layer while still having committed something.
	var n int64
	require.NoError(t, ls.db.Raw(
		"SELECT count(*) FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = 'audit_events'",
	).Scan(&n).Error)
	require.Zero(t, n, "the table really is gone, so the failed write had nowhere to land")
}

// TestFastAuditMode_ChainStaysLinkedWhenEnabled is S2's visibility half: under
// Postgres async commit a committed row is immediately VISIBLE, and only its
// DURABILITY lags. So consecutive appends still link and the chain still
// verifies with the mode on.
//
// POSTGRES-GATED for the same reason as the test above — on SQLite the flag is
// inert, so the chain would link whether or not the mode did anything.
func TestFastAuditMode_ChainStaysLinkedWhenEnabled(t *testing.T) {
	ls, cap := newPostgresAuditStore(t)
	ls.SetAuditSkipDurableSync(true)

	base := time.Now().UTC()
	first := appendEvent(t, ls, "fastaudit.one", "first", base)
	second := appendEvent(t, ls, "fastaudit.two", "second", base.Add(time.Millisecond))

	// Precondition, asserted rather than assumed: the mode really was active
	// for these appends. Without this the linkage assertions below would hold
	// trivially on a durable commit too, which is exactly the flaw the SQLite
	// version of this test had.
	require.True(t, cap.saw("set local synchronous_commit = off"),
		"the fast audit mode was not actually exercised -- no SET LOCAL was issued, so this test would "+
			"pass identically with the mode off. Statements seen: %v", cap.stmts)

	require.Equal(t, auditGenesisHash, first.PrevHash)
	require.Equal(t, first.EntryHash, second.PrevHash,
		"the second append must link onto the first even with the sync wait skipped -- a committed row is "+
			"immediately visible regardless of whether its WAL record has reached the disk yet")

	v, err := ls.VerifyAuditChain(context.Background(), nil)
	require.NoError(t, err)
	require.True(t, v.Valid, "chain must verify with the fast audit mode on: reason=%q", v.Reason)
}

// --- Postgres-only: the mechanism itself, observed on a real cluster ---

// capturingLogger records every SQL statement GORM executes, so the two
// Postgres tests below can assert on what was actually sent to the server
// rather than on a proxy for it. Not used in production: gormConfig()
// deliberately silences GORM's logger (#464, bound parameters would otherwise
// reach the logs).
type capturingLogger struct {
	gormlogger.Interface
	stmts []string
}

func (c *capturingLogger) Trace(_ context.Context, _ time.Time, fc func() (string, int64), _ error) {
	sql, _ := fc()
	c.stmts = append(c.stmts, sql)
}

func (c *capturingLogger) saw(substr string) bool {
	for _, s := range c.stmts {
		if strings.Contains(strings.ToLower(s), strings.ToLower(substr)) {
			return true
		}
	}
	return false
}

// fastAuditSchemaName turns a Go test name into a legal, unquoted Postgres
// identifier. t.Name() for a subtest carries '/' and, worse, whatever
// punctuation the subtest label contains (`SET LOCAL synchronous_commit = off
// is sent` becomes `on:_SET_LOCAL_...`), and interpolating that straight into
// `CREATE SCHEMA` is a syntax error — the first version of this file hit
// exactly that. Collapsing to [a-z0-9_] is also what keeps the interpolation
// safe: the value is a test name, not input, but the sanitiser means it stays
// safe if someone later derives it from something else.
func fastAuditSchemaName(testName string) string {
	var b strings.Builder
	b.WriteString("fastaudit_")
	for _, r := range strings.ToLower(testName) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	// Postgres truncates identifiers at NAMEDATALEN-1 (63) bytes, which would
	// silently collide two long subtest names into one schema — and then one
	// subtest's DROP SCHEMA cleanup would delete the other's table.
	name := b.String()
	if len(name) > 60 {
		name = name[:60]
	}
	return name
}

// newPostgresAuditStore opens the pg-gated test cluster with a
// statement-capturing logger and the minimal schema the audit chain needs.
// Skips (not fails) when KEYORIX_TEST_PG_DSN is unset, per this repo's
// pg-gated convention: a skip is expected in a DSN-less run and is NOT a
// failure, but these are the only tests that can prove the Postgres
// mechanism, so the `core` CI leg is what actually runs them.
// requirePostgresDSN skips the CALLING test unless a real cluster is
// configured, and returns the DSN. Call it from a PARENT test, not only from a
// subtest helper: a parent whose subtests all skip still emits `--- PASS`, and
// scripts/check-adr-conformance.sh treats that line as proof the claim was
// verified — so a DSN-less run would silently certify a Postgres-only property.
// See TestFastAuditMode_PostgresIssuesSetLocalOnlyWhenEnabled's own comment.
func requirePostgresDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set -- this test can only prove the Postgres mechanism on a real cluster")
	}
	return dsn
}

func newPostgresAuditStore(t *testing.T) (*LocalStorage, *capturingLogger) {
	t.Helper()
	dsn := requirePostgresDSN(t)
	cap := &capturingLogger{Interface: gormlogger.Default.LogMode(gormlogger.Silent)}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: cap})
	require.NoError(t, err)
	// Each test gets its own table namespace via a dedicated schema, so a
	// parallel run against the same cluster cannot see another test's chain.
	schema := fastAuditSchemaName(t.Name())
	require.NoError(t, db.Exec("DROP SCHEMA IF EXISTS "+schema+" CASCADE").Error)
	require.NoError(t, db.Exec("CREATE SCHEMA "+schema).Error)
	require.NoError(t, db.Exec("SET search_path TO "+schema).Error)
	t.Cleanup(func() { _ = db.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error })
	sqlDB, err := db.DB()
	require.NoError(t, err)
	// One connection, so `SET search_path` above and the leak check below
	// both observe the same session the audit transaction ran on. That is
	// what makes TestFastAuditMode_PostgresSetLocalDoesNotLeak meaningful:
	// with a multi-connection pool the follow-up query could land on a
	// different, never-touched session and pass for the wrong reason.
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}))
	cap.stmts = nil // drop the setup/migration noise
	return NewLocalStorage(db), cap
}

// TestFastAuditMode_PostgresIssuesSetLocalOnlyWhenEnabled is the Postgres
// half of S4 and the direct proof of the mechanism: with the mode off the
// audit transaction sends no synchronous_commit statement at all (so the
// commit keeps the cluster's durable default -- the sync wait still happens),
// and with it on the transaction sends exactly `SET LOCAL
// synchronous_commit = off`.
func TestFastAuditMode_PostgresIssuesSetLocalOnlyWhenEnabled(t *testing.T) {
	// The gate is checked HERE, in the parent, not only inside
	// newPostgresAuditStore. If only the subtests skipped, this parent would
	// still emit `--- PASS` with no DSN present, and
	// scripts/check-adr-conformance.sh — which looks for exactly that line —
	// would record the claim as VERIFIED in a run that never touched a
	// Postgres cluster. Caught by running that checker: it reported this row
	// `ok (pg-gated)` without a DSN while its sibling correctly reported
	// `gated-skip`. A green check that does not cover what its name implies
	// is worse than no check.
	requirePostgresDSN(t)

	t.Run("off: no durability statement is sent", func(t *testing.T) {
		ls, cap := newPostgresAuditStore(t)

		// Precondition, asserted rather than assumed: "we send nothing" only
		// means "the commit is durable" if the cluster's own default is
		// durable. A cluster running synchronous_commit=off would make the
		// default path non-durable with this code unchanged, and a test that
		// did not check this would certify that as correct.
		var effective string
		require.NoError(t, ls.db.Raw("SHOW synchronous_commit").Scan(&effective).Error)
		require.Equal(t, "on", effective,
			"this test cluster has synchronous_commit=%q, not \"on\" -- the DEFAULT audit path cannot be "+
				"shown durable against it, so the result here would be meaningless rather than green", effective)

		cap.stmts = nil
		appendEvent(t, ls, "fastaudit.pg.off", "default path", time.Now().UTC())

		require.False(t, cap.saw("synchronous_commit"),
			"with the fast audit mode OFF the audit transaction must not touch synchronous_commit at all; "+
				"statements seen: %v", cap.stmts)
	})

	t.Run("on: SET LOCAL synchronous_commit = off is sent", func(t *testing.T) {
		ls, cap := newPostgresAuditStore(t)
		ls.SetAuditSkipDurableSync(true)

		appendEvent(t, ls, "fastaudit.pg.on", "fast path", time.Now().UTC())

		require.True(t, cap.saw("set local synchronous_commit = off"),
			"with the fast audit mode ON the audit transaction must issue `SET LOCAL synchronous_commit = off`; "+
				"statements seen: %v", cap.stmts)

		v, err := ls.VerifyAuditChain(context.Background(), nil)
		require.NoError(t, err)
		require.True(t, v.Valid, "chain must verify under async commit: reason=%q", v.Reason)
	})
}

// TestFastAuditMode_PostgresSetLocalDoesNotLeak is the property that makes
// SET LOCAL the right mechanism rather than a dangerous one: the relaxation
// must be confined to the audit transaction and must NOT follow the pooled
// connection into the next transaction, which is where a secret write would
// run. Asserted on the same single pooled connection the audit transaction
// just used (see newPostgresAuditStore's SetMaxOpenConns(1) comment) -- with
// a larger pool this query could land on an untouched session and pass for
// the wrong reason.
func TestFastAuditMode_PostgresSetLocalDoesNotLeak(t *testing.T) {
	ls, _ := newPostgresAuditStore(t)
	ls.SetAuditSkipDurableSync(true)

	appendEvent(t, ls, "fastaudit.pg.leak", "after this the session must be durable again", time.Now().UTC())

	var effective string
	require.NoError(t, ls.db.Raw("SHOW synchronous_commit").Scan(&effective).Error)
	require.Equal(t, "on", effective,
		"synchronous_commit leaked out of the audit transaction and is now %q on this pooled connection -- "+
			"the next transaction to borrow it (a secret WRITE, say) would commit non-durably without anyone "+
			"asking for that. SET LOCAL is transaction-scoped precisely so this cannot happen; if this fails, "+
			"the statement has been changed to a plain SET or moved outside the transaction.", effective)
}
