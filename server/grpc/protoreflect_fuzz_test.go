package grpc_test

// FuzzGRPCProtoreflectInvariants -- fuzzer inventory item #6: a schema-aware
// gRPC fuzzer. Existing byte-level gRPC fuzzing dies almost entirely in proto
// decoding (malformed wire bytes never reach a handler); this one instead
// builds a WELL-TYPED request for a fuzzer-chosen registered keyorix.v1
// service+method by walking that method's protoreflect descriptor
// (protoreflect_builder_fuzz_test.go), then drives it through the REAL,
// fully-wired in-process gRPC server (bufconn) -- the actual interceptor
// chain, services, core, and a real SQLite world -- as three identities with
// different grants (zero-grant, read-only, admin), and checks four
// invariants that hold for EVERY RPC regardless of which one was picked:
//
//  1. NO LEAK: no panic reaches the client, and no codes.Unknown/Internal
//     status leaks a raw Go error string or stack trace (classifyStatusLeak,
//     red/green-proofed in protoreflect_oracle_mechanism_test.go).
//  2. AUTHZ: the zero-grant identity (a freshly created user with only the
//     universal baseline role, no read/write grant of any kind) must never
//     get an OK response that either changed the database (derived, not
//     hand-classified "mutating" -- see dbSnapshot) or carried the planted
//     canary secret's plaintext (derived "secret-reading", via
//     containsCanary). The read-only identity (system_auditor, global scope --
//     read access to secrets/users/roles/audit/system, no write grant of any
//     kind) gets the same write-side check. This generalizes
//     FuzzGRPCRESTSecretReadAuthzParity's model (REST vs gRPC decision parity
//     for secret reads) to EVERY RPC by deriving "mutating"/"secret-reading"
//     from the call's actual, observed effect instead of a hand-maintained
//     per-method list -- the latter is exactly the enumeration-completeness
//     trap CLAUDE.md warns about (new methods are added to this proto
//     routinely; a hand list would silently stop covering them).
//  3. ERROR-IMPLIES-NO-COMMIT: a non-OK status must leave the database
//     unchanged, except for a documented best-effort async write (see
//     bestEffortSideEffectTables).
//  4. BOUNDED WORK: handling time must not be disproportionate to the
//     request's marshaled size (checkBoundedWork).
//
// Oracles 2 and 3 share one mechanism (dbSnapshot/unexplainedWrites) --
// "did this one call write anything the documented best-effort channel
// doesn't already explain" is the same question whether asked of a call that
// returned OK (2) or one that didn't (3). dbSnapshot tracks a write-count
// trigger on EVERY table in the schema (not just the exempt ones), so a
// violation names exactly which table(s) absorbed the unaccounted write and
// by how many write operations (see unexplainedWrites, tableDelta).
//
// This mechanism caught three REAL gaps in its own exemption list live, not
// product bugs: the GetCompliancePosture snapshot upsert, the
// LogSecretRead*-family secret_access_logs write, and -- initially
// misdiagnosed as fuzz-minimization noise, corrected after PR #2390 review --
// ValidateSessionToken's throttled session.last_seen_at touch
// (internal/core/auth.go), which runs on EVERY successful authentication
// inside authenticateRequest, BEFORE a handler's own validation/authz logic,
// so it can fire on a call that's about to be rejected for an unrelated
// reason. Being wall-clock-throttled (30s) is exactly
// why it fired intermittently across a long -fuzz burst and never on an
// isolated single-input replay seconds later -- looking identical to
// non-reproducible noise until the per-table diagnostics this file now emits
// named "sessions" as the table that kept moving. All three are documented,
// intentional best-effort side effects, now named in
// bestEffortSideEffectTables; see TestUnexplainedWrites_NamesTheDifferingTable
// and TestUnexplainedWrite_RedOnMixedExemptAndNonExemptWrite in
// protoreflect_oracle_mechanism_test.go for direct proof the diagnostics are
// accurate and that exempting one table never masks a write to another.
//
// Session E5 already covers the request-smuggling / double-parse variant for
// gRPC; this target does not re-attempt that. Streaming RPCs are out of scope
// (see discoverUnaryMethods) and reported as a known gap in the coverage
// summary this fuzzer logs on Cleanup.

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"net"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/fuzzworld"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	keyorixgrpc "github.com/keyorixhq/keyorix/server/grpc"
	grpcservices "github.com/keyorixhq/keyorix/server/grpc/services"
)

// --- world ------------------------------------------------------------

// prPrincipalPassword is the shared login password for every non-admin
// principal this world mints.
const prPrincipalPassword = "Xk7#Qp2$Rn5@Wv9!"

// prCanaryValue is the plaintext of the one secret this world seeds. Fixed
// (not per-run random) so a failing corpus entry replays identically --
// Go fuzz targets must not depend on a nondeterministic source.
const prCanaryValue = "KXPROTOREFLECT-CANARY-9f21ab77c6"

type prWorld struct {
	srv  *grpc.Server
	conn *grpc.ClientConn
	db   *sql.DB // raw *sql.DB for the per-table write-count snapshotting -- see dbSnapshot
	c    *core.KeyorixCore

	methods []grpcMethod

	zeroGrantTok  string
	zeroGrantUID  uint
	readOnlyTok   string
	readOnlyUID   uint
	auditorRoleID uint
	adminTok      string

	// reachedMu/reached track, across the whole fuzz run, which methods were
	// actually invoked at least once -- drained in f.Cleanup to log the
	// coverage summary the session's "Done when" asks for.
	reachedMu sync.Mutex
	reached   map[string]bool
}

func (w *prWorld) markReached(key string) {
	w.reachedMu.Lock()
	defer w.reachedMu.Unlock()
	if w.reached == nil {
		w.reached = map[string]bool{}
	}
	w.reached[key] = true
}

func buildPRWorld(f *testing.F) *prWorld {
	f.Helper()
	if err := i18n.InitializeForTesting(); err != nil {
		f.Fatalf("i18n: %v", err)
	}

	// sqlitetest: private DB per world, single-connection pool, closed on cleanup.
	gormDB := sqlitetest.Open(f, "kxprfuzz_")
	fuzzworld.Bootstrap(f, gormDB)
	if err := gormDB.AutoMigrate(models.AllTestModels()...); err != nil {
		f.Fatalf("migrate test models: %v", err)
	}
	sqlDB, err := gormDB.DB()
	if err != nil {
		f.Fatalf("underlying *sql.DB: %v", err)
	}
	installWriteCountTriggers(f, sqlDB, discoverAllTables(f, sqlDB))

	c := core.NewKeyorixCore(store.NewLocalStorage(gormDB))
	ls := store.NewLocalStorage(gormDB)
	ctx := context.Background()

	c.SetBootstrapToken("test-bootstrap-token")
	if _, err := c.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "testadmin", Email: "testadmin@example.com",
		Password: "TestPassword123!", Token: "test-bootstrap-token",
	}); err != nil {
		f.Logf("bootstrap: %v (may already be initialised)", err)
	}
	adminSess, _, err := c.Login(ctx, &core.LoginRequest{Username: "testadmin", Password: "TestPassword123!"})
	if err != nil {
		f.Fatalf("admin login: %v", err)
	}
	admin, err := ls.GetUserByUsername(ctx, "testadmin")
	if err != nil || admin == nil {
		f.Fatalf("admin lookup: %v", err)
	}

	proj, err := ls.CreateProject(ctx, &models.Project{Name: "prfuzz-proj"})
	if err != nil {
		f.Fatalf("project: %v", err)
	}
	env, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: proj.ID})
	if err != nil {
		f.Fatalf("environment: %v", err)
	}
	if _, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "prfuzz-canary", Value: []byte(prCanaryValue), ProjectID: proj.ID, EnvironmentID: env.ID,
		Type: "password", CreatedBy: "testadmin", OwnerID: admin.ID,
	}); err != nil {
		f.Fatalf("seed canary secret: %v", err)
	}

	mint := func(uname string) (string, uint) {
		u, err := c.CreateUser(ctx, &core.CreateUserRequest{Username: uname, Email: uname + "@x.io", Password: prPrincipalPassword})
		if err != nil || u == nil {
			f.Fatalf("create user %s: %v", uname, err)
		}
		sess, _, err := c.Login(ctx, &core.LoginRequest{Username: uname, Password: prPrincipalPassword})
		if err != nil || sess == nil {
			f.Fatalf("login %s: %v", uname, err)
		}
		return sess.SessionToken, u.ID
	}
	zeroGrantTok, zeroGrantUID := mint("prfuzz-zero-grant")
	readOnlyTok, readOnlyUID := mint("prfuzz-read-only")

	// system_auditor (ADR-021 built-in role): install-wide read access to
	// secrets/users/roles/audit/system, no write permission of any kind --
	// reused as-is (not a bespoke role) so this fuzzer's "read-only" identity
	// tracks whatever the product actually ships as its read-only persona.
	auditorRole, err := ls.GetRoleByName(ctx, "system_auditor")
	if err != nil || auditorRole == nil {
		f.Fatalf("system_auditor role lookup: %v", err)
	}
	if err := c.AssignUserRole(ctx, 0, readOnlyUID, auditorRole.ID, core.Scope{}, false); err != nil {
		f.Fatalf("grant system_auditor: %v", err)
	}

	srv, err := keyorixgrpc.NewServer(&config.Config{}, c)
	if err != nil {
		f.Fatalf("grpc server: %v", err)
	}
	lis := bufconn.Listen(1 << 20)
	go func() { _ = srv.Serve(lis) }()

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		f.Fatalf("grpc dial: %v", err)
	}

	methods := discoverUnaryMethods(srv)
	if len(methods) == 0 {
		f.Fatalf("discoverUnaryMethods found zero unary methods -- harness is dry")
	}

	return &prWorld{
		srv: srv, conn: conn, db: sqlDB, c: c, methods: methods,
		zeroGrantTok: zeroGrantTok, zeroGrantUID: zeroGrantUID,
		readOnlyTok: readOnlyTok, readOnlyUID: readOnlyUID, auditorRoleID: auditorRole.ID,
		adminTok: adminSess.SessionToken,
	}
}

// resetPrincipalGrants restores the zero-grant and read-only identities to
// their intended baseline grants before every fuzz iteration -- mirroring
// FuzzGRPCRESTSecretReadAuthzParity's own "Per-iteration reset: drop
// fuzz-principal grants" convention. Required because the fuzzer-generated
// requests for RoleService.AssignRole/RemoveRole carry ARBITRARY user_id/
// role_id fields, and the admin identity legitimately calls them too: across
// enough iterations in one long-lived world, a fuzzed AssignRole request's
// user_id can coincide with w.zeroGrantUID or w.readOnlyUID, LEGITIMATELY
// granting one of them a real role -- after which every later iteration
// would see that identity behave as something other than what its name
// claims, for the rest of the process's life. Found live via PR #2390 review:
// a burst-reported "zero-grant got OK" case for RoleService.RemoveRole did
// not reproduce in isolation, and tracing it showed the request's user_id
// happened to equal w.zeroGrantUID's real ID -- admin's OWN earlier fuzzed
// AssignRole call (same iteration or an earlier one) had actually granted it
// a role, so the later "zero-grant" read was, by then, true to the DB but
// false to this harness's own label. Deleting any user_roles rows for both
// IDs, then re-granting read-only's own baseline system_auditor role, undoes
// that drift before each iteration's assertions run.
func (w *prWorld) resetPrincipalGrants(t *testing.T, ctx context.Context) {
	t.Helper()
	if _, err := w.db.Exec("DELETE FROM user_roles WHERE user_id IN (?, ?)", w.zeroGrantUID, w.readOnlyUID); err != nil {
		t.Fatalf("reset principal grants: %v", err)
	}
	if err := w.c.AssignUserRole(ctx, 0, w.readOnlyUID, w.auditorRoleID, core.Scope{}, false); err != nil {
		t.Fatalf("re-grant read-only baseline system_auditor: %v", err)
	}
}

func (w *prWorld) close() {
	w.srv.Stop()
	_ = w.conn.Close()
}

// --- oracle 2/3 shared mechanism: derived DB-write detection -----------

// bestEffortSideEffectTables are the documented, named exceptions to
// error-implies-no-commit / zero-grant-or-read-only-never-mutates: writes that
// fire as a DOCUMENTED side effect of an otherwise read-only or
// not-independently-authorized call, not as a consequence of the caller's own
// grants. A short, explicit list on purpose -- NOT a broad pattern match -- so
// a future, undocumented best-effort write this fuzzer finds stays a real
// finding instead of being silently swallowed by an over-broad exemption.
//
//   - audit_events: the gRPC services' goSafe-dispatched audit log write (see
//     server/grpc/services/secret_service.go's goSafe calls), fired
//     asynchronously and independently of whether the triggering RPC itself
//     was authorized or succeeded.
//
//   - compliance_posture_snapshots: GetCompliancePosture's own doc comment
//     (internal/core/compliance_posture.go) -- "Persist today's snapshot for
//     trend tracking (best-effort -- a write failure must not abort the
//     posture response an auditor is waiting on)". Found live by this
//     fuzzer's first run: a read-only (system_auditor) call to
//     GetCompliancePosture (and, transitively, GetComplianceControls, which
//     calls it internally) tripped the write-detection oracle before this
//     table was named here -- a real, intentional, documented side effect,
//     not a security bug, which is exactly what this list exists to name
//     explicitly rather than mask with a broader heuristic.
//
//   - secret_access_logs: every LogSecretRead*/LogSecretCreated*/
//     LogSecretUpdated*-family call (internal/core/audit.go's writeAccessLog)
//     writes BOTH audit_events AND this table for the same event -- found
//     live the same way as compliance_posture_snapshots: a read-only
//     (system_auditor) GetSecretVersions call (a metadata-only RPC, and
//     GRPC's own comment on it: "Audit as a secret read... Best-effort
//     metadata fetch") tripped the oracle because only audit_events was
//     named here at the time.
//
//   - sessions, UPDATE of last_seen_at only: internal/core/auth.go's
//     ValidateSessionToken touches session.last_seen_at on EVERY successful
//     authentication, throttled to once per 30s -- that function's own doc
//     comment: "Best-effort last-seen stamp for the My Account sessions
//     view... Never fails the request." (Since OPT-LASTUSED-1 the stamp is
//     recorded in memory and written by the core's last-used coalescer up to
//     30s later, from a timer goroutine -- so it can land during a LATER
//     call's window, which this principal-agnostic, column-scoped exemption
//     already covers.)
//     This runs inside authenticateRequest BEFORE a handler's own
//     validation/authz logic, so it can fire on a call that is about to be
//     rejected for an unrelated reason -- this was the coordinator's
//     diagnosis on PR #2390 of what the earlier "state-dependent,
//     non-reproducible" findings actually were: a real, synchronous,
//     documented best-effort writer this list hadn't named yet, not
//     fuzz-minimization noise. The exemption is scoped to UPDATE only (PR
//     #2390 second review round), AND, within UPDATE, to a change touching
//     ONLY last_seen_at (PR #2390 third review round): an INSERT (minting a
//     session), a DELETE (revoking one), or an UPDATE that ALSO changes any
//     other column (expires_at, revoked_at, user_id, ...) is exactly the
//     authz-bypass shape this oracle exists to catch, and a broader
//     exemption would wave it through. See
//     TestUnexplainedWrite_RedOnSessionsInsert,
//     TestUnexplainedWrite_RedOnSessionsDelete,
//     TestUnexplainedWrite_RedOnSessionsUpdateTouchingOtherColumn, and
//     TestUnexplainedWrite_RedOnSessionsUpdateOfOtherColumnAlone in
//     protoreflect_oracle_mechanism_test.go for the direct red-proofs.
//
//   - secret_nodes / secret_versions, UPDATE of read_count only: found live
//     by THIS round's 10-minute burst (not pre-anticipated -- flagged to the
//     coordinator for review in the PR reply, same as every prior entry).
//     internal/core/versions.go's readVersionValue enforces max_reads by
//     atomically incrementing secret_nodes.read_count
//     (TryIncrementSecretNodeReadCount, "the ACTUAL enforcement mechanism...
//     fail closed") and, best-effort, secret_versions.read_count
//     (TryIncrementSecretReadCount, "CLI/gRPC display only, not the
//     enforcement mechanism... a failure here must not block an
//     already-authorized read") on EVERY value read of a secret that has
//     max_reads set -- regardless of which authorized identity triggered the
//     read. Both storage calls use GORM's UpdateColumn (not Updates/Save),
//     which touches ONLY the named column and nothing else -- confirmed by
//     reading internal/storage/store/local_secrets.go directly, not assumed.
//     This is not best-effort bookkeeping layered on top of the read the way
//     the audit-log writes are -- it IS the read's own defined behavior
//     (burn-after-N-reads), so a read-only principal who legitimately holds
//     secrets.read correctly triggers it; the column scoping (not a blanket
//     table exemption) is what still catches a write to any OTHER column on
//     either table -- the actual secret value, its project/owner, a
//     version's content, etc.
//
//     #2401 follow-up: this entry was originally unscoped by principal --
//     exempt for EVERY identity, including zero-grant. That was harmless at
//     the time because value reads enforce secrets.read before
//     readVersionValue ever increments the counter, so a zero-grant caller
//     never reached it -- but a future regression letting a denied caller
//     reach readVersionValue would have bumped someone else's
//     burn-after-N-reads counter while this oracle silently waved it
//     through. Scoped to principals: read-only and admin (the only
//     identities this harness mints that can legitimately hold secrets.read)
//     so a zero-grant call that increments read_count now fails the oracle
//     instead of being masked by this exemption. See
//     TestUnexplainedWrite_RedOnSecretNodesReadCountUpdateByZeroGrant /
//     ...ByZeroGrant's secret_versions twin in
//     protoreflect_oracle_mechanism_test.go for the direct red-proof.
var bestEffortSideEffectTables = []writeExemption{
	{table: "audit_events"},
	{table: "compliance_posture_snapshots"},
	{table: "secret_access_logs"},
	{table: "sessions", events: []string{"UPDATE"}, onlyColumns: []string{"last_seen_at"}},
	{table: "secret_nodes", events: []string{"UPDATE"}, onlyColumns: []string{"read_count"}, principals: []string{"read-only", "admin"}},
	{table: "secret_versions", events: []string{"UPDATE"}, onlyColumns: []string{"read_count"}, principals: []string{"read-only", "admin"}},
}

// writeExemption names one table (and optionally a specific subset of
// INSERT/UPDATE/DELETE events on it) that unexplainedWrites must not flag.
// events == nil/empty means every event on that table is exempt; a non-empty
// list narrows the exemption to exactly those events -- e.g. {"sessions",
// []string{"UPDATE"}} exempts an UPDATE but still flags an INSERT (a new
// session, i.e. a login or impersonation start) or a DELETE (a session
// revocation) on that same table, both of which are real, security-relevant
// writes a zero-grant/read-only principal must never be able to trigger.
//
// onlyColumns narrows an UPDATE exemption further, to statements that change
// ONLY the listed columns and no others. When set, allows() always returns
// false for this entry (see its own doc comment) -- the real filtering
// happens at the SQL level, in installColumnScopedUpdateTrigger's WHEN
// clause, which only increments the counter unexplainedWrites reads when a
// column OUTSIDE onlyColumns actually changed. A plain events-only exemption
// (no onlyColumns) can't express this: "events" answers "which statement
// kinds", not "which columns within one kind".
//
// principals optionally narrows the exemption to specific runAs labels
// ("zero-grant", "read-only", "admin"). Empty/nil means the exemption
// applies to every principal -- the right default for a side effect that
// fires independently of who's calling (audit_events, the sessions
// last_seen_at touch). A non-empty list means ONLY those principals get the
// exemption; for any other principal, the same write is treated as
// unexplained. Added for #2401: secret_nodes/secret_versions' read_count
// entries are legitimate only for an identity that can actually reach
// readVersionValue's own enforcement path (read-only, admin) -- a zero-grant
// caller incrementing read_count would be the exact authz-bypass shape this
// oracle exists to catch, not a documented side effect.
type writeExemption struct {
	table       string
	events      []string
	onlyColumns []string
	principals  []string
}

// principalAllowed reports whether this entry's exemption covers principal.
// An entry with no principals list applies to every principal.
func (e writeExemption) principalAllowed(principal string) bool {
	if len(e.principals) == 0 {
		return true
	}
	return slices.Contains(e.principals, principal)
}

// allows reports whether this entry exempts event on its own, WITHOUT
// consulting column content -- true for a plain table/event exemption.
// Column-scoped entries (onlyColumns set) always return false here: the
// trigger installed for them (installColumnScopedUpdateTrigger) only
// increments the shared counter for the NON-exempt case (some other column
// changed), so by the time unexplainedWrites sees a nonzero delta for that
// key, it is already known-bad -- a second, blanket exemption at this layer
// would silently re-open exactly the gap onlyColumns exists to close.
func (e writeExemption) allows(event string) bool {
	if len(e.onlyColumns) > 0 {
		return false
	}
	if len(e.events) == 0 {
		return true
	}
	return slices.Contains(e.events, event)
}

// exemptOnlyEvent is a synthetic event name (never a real SQLite statement
// kind) for the companion counter installExemptOnlyUpdateTrigger installs
// alongside a column-scoped UPDATE exemption: "did onlyColumns itself
// change", tracked independently of the ordinary UPDATE counter (which only
// counts a change to some OTHER column). isBestEffortSideEffectWrite treats
// this event specially, below -- it's how a column-scoped exemption's
// principals scoping gets applied to the exempt case itself, not just used
// to decide whether the non-exempt case should be flagged (that part is
// already handled at the SQL level and never depends on principal).
const exemptOnlyEvent = "UPDATE_EXEMPT_ONLY"

func isBestEffortSideEffectWrite(table, event, principal string) bool {
	for _, e := range bestEffortSideEffectTables {
		if e.table != table {
			continue
		}
		if event == exemptOnlyEvent {
			if len(e.onlyColumns) == 0 {
				continue
			}
			if e.principalAllowed(principal) {
				return true
			}
			continue
		}
		if e.allows(event) && e.principalAllowed(principal) {
			return true
		}
	}
	return false
}

// columnScopedUpdateExemption returns the first bestEffortSideEffectTables
// entry naming table with a non-empty onlyColumns, if any -- used by
// installWriteCountTriggers to decide whether table's UPDATE trigger needs
// installColumnScopedUpdateTrigger's WHEN-clause form instead of the plain
// unconditional one.
func columnScopedUpdateExemption(table string) ([]string, bool) {
	for _, e := range bestEffortSideEffectTables {
		if e.table == table && len(e.onlyColumns) > 0 {
			return e.onlyColumns, true
		}
	}
	return nil, false
}

// prFuzzWriteCountsTable backs a per-(table,event) write counter, kept
// current by one AFTER INSERT/AFTER UPDATE/AFTER DELETE trigger per table in
// the schema -- installed once in buildPRWorld via installWriteCountTriggers
// against EVERY table discoverAllTables finds, not only the exempt ones.
// Tracking every table AND every event separately (not just a per-table
// total) is what lets an exemption narrow to one specific event on one
// table (see writeExemption) and lets unexplainedWrites name EXACTLY which
// table(s) absorbed an unaccounted write and by how many write operations
// (PR #2390 review: "make every unexplainedWrite failure name the differing
// tables").
//
// A row-content hash diff was tried first and rejected: GORM's
// FirstOrCreate+Assign (the compliance-snapshot upsert) issues a real UPDATE
// on every call regardless of whether the new values differ from the old
// ones, which a content hash would see as unchanged -- confirmed live (a
// same-day second call with unchanged tallies produced a false mismatch). A
// trigger-based counter tracks "was a write statement executed against this
// table" directly, independent of content, so a same-value UPDATE still
// counts correctly as a write.
const prFuzzWriteCountsTable = "pr_fuzz_write_counts"

// writeCountEvents are the three statement kinds tracked per table. Order is
// insignificant; a fixed list (not derived) because SQLite's own trigger
// vocabulary is exactly these three.
var writeCountEvents = []string{"INSERT", "UPDATE", "DELETE"}

// counterKey is prFuzzWriteCountsTable's primary key for one (table, event)
// pair. table never legitimately contains ':' (SQL identifiers can't), so a
// later split on the last ':' is unambiguous.
func counterKey(table, event string) string { return table + ":" + event }

func splitCounterKey(key string) (table, event string) {
	before, after, ok := strings.CutLast(key, ":")
	if !ok {
		return key, ""
	}
	return before, after
}

// discoverAllTables introspects sqlite_master for every real table the live
// schema declares, excluding SQLite's own internal tables and the tracker
// table itself -- driven by the live schema, not a hand-maintained list, so a
// table the production migration adds later is covered here automatically.
func discoverAllTables(t testing.TB, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name != ?", prFuzzWriteCountsTable)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan table name: %v", err)
		}
		tables = append(tables, name)
	}
	return tables
}

// tableColumns reads PRAGMA table_info(table) to list every column the live
// schema declares for it, in declaration order -- used to derive "every
// OTHER column" for a column-scoped UPDATE exemption, so a column added to
// the table later is covered automatically rather than needing a hand edit
// here.
func tableColumns(t testing.TB, db *sql.DB, table string) []string {
	t.Helper()
	// table always ranges over the live schema's own table names
	// (discoverAllTables) in production use, or a fixed hardcoded literal in
	// the oracle mechanism unit tests -- never fuzz input.
	rows, err := db.Query("PRAGMA table_info(" + table + ")") // nosemgrep: go.lang.security.audit.database.string-formatted-query.string-formatted-query -- table is always one of the hardcoded cases above; PRAGMA statements cannot be parameterized in SQLite
	if err != nil {
		t.Fatalf("pragma table_info(%s): %v", table, err)
	}
	defer func() { _ = rows.Close() }()
	cols, err := rows.Columns()
	if err != nil {
		t.Fatalf("pragma table_info(%s) columns: %v", table, err)
	}
	var out []string
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatalf("scan table_info(%s): %v", table, err)
		}
		// PRAGMA table_info's fixed output schema is (cid, name, type,
		// notnull, dflt_value, pk) -- "name" is always column index 1.
		switch v := vals[1].(type) {
		case string:
			out = append(out, v)
		case []byte:
			out = append(out, string(v))
		}
	}
	return out
}

// installColumnScopedUpdateTrigger installs table's UPDATE trigger for a
// column-scoped best-effort exemption (writeExemption.onlyColumns): it
// increments counterKey(table, "UPDATE") -- the SAME key a plain,
// unconditional UPDATE trigger would -- but ONLY when at least one column
// OTHER than onlyColumns actually changed. An UPDATE that changes only the
// listed columns (ValidateSessionToken's last_seen_at touch) never
// increments it, so it never appears in unexplainedWrites; an UPDATE that
// ALSO touches any other column -- or touches only some other column,
// skipping the listed ones entirely -- does. "Other columns" comes from
// tableColumns (PRAGMA table_info), not a hand-maintained list, so a column
// added to the table later is covered automatically rather than silently
// falling outside the check.
func installColumnScopedUpdateTrigger(t testing.TB, db *sql.DB, table, key string, onlyColumns []string) {
	t.Helper()
	only := make(map[string]bool, len(onlyColumns))
	for _, c := range onlyColumns {
		only[c] = true
	}
	var changedConds []string
	for _, col := range tableColumns(t, db, table) {
		if only[col] {
			continue
		}
		changedConds = append(changedConds, fmt.Sprintf(`(NEW."%s" IS NOT OLD."%s")`, col, col))
	}
	when := "0" // no columns exist outside onlyColumns -- this table's UPDATE can never be the non-exempt case.
	if len(changedConds) > 0 {
		when = strings.Join(changedConds, " OR ")
	}
	stmt := fmt.Sprintf(
		"CREATE TRIGGER IF NOT EXISTS pr_fuzz_count_%s_UPDATE_scoped AFTER UPDATE ON %s WHEN %s BEGIN UPDATE %s SET n = n + 1 WHERE key = '%s'; END",
		table, table, when, prFuzzWriteCountsTable, key,
	) // nosemgrep: go.lang.security.audit.database.string-formatted-query.string-formatted-query -- table/key are schema-derived or fixed test literals; the WHEN clause's column names come from PRAGMA table_info (the live schema itself), never external/fuzz input
	if _, err := db.Exec(stmt); err != nil {
		t.Fatalf("install column-scoped UPDATE trigger on %s: %v", table, err)
	}
}

// installExemptOnlyUpdateTrigger installs table's companion UPDATE trigger
// for exemptOnlyEvent: the inverse condition of installColumnScopedUpdateTrigger.
// It increments counterKey(table, exemptOnlyEvent) when at least one of
// onlyColumns itself changed, regardless of whether some OTHER column also
// did in the same statement (that case is already caught, for every
// principal, by the ordinary column-scoped counter above). Added for #2401:
// without this second counter, a column-scoped exemption's "only these
// columns changed" case is invisible to Go entirely -- the SQL trigger
// filters it out before unexplainedWrites ever sees a nonzero delta -- so
// there was no way to apply writeExemption.principals to it. This trigger
// makes that case observable; isBestEffortSideEffectWrite decides, per
// principal, whether it's still exempt.
func installExemptOnlyUpdateTrigger(t testing.TB, db *sql.DB, table, exemptKey string, onlyColumns []string) {
	t.Helper()
	var changedConds []string
	for _, col := range onlyColumns {
		changedConds = append(changedConds, fmt.Sprintf(`(NEW."%s" IS NOT OLD."%s")`, col, col))
	}
	when := "0" // onlyColumns is always non-empty when this is called (see installWriteCountTriggers); kept for symmetry with installColumnScopedUpdateTrigger.
	if len(changedConds) > 0 {
		when = strings.Join(changedConds, " OR ")
	}
	stmt := fmt.Sprintf(
		"CREATE TRIGGER IF NOT EXISTS pr_fuzz_count_%s_UPDATE_exempt_only AFTER UPDATE ON %s WHEN %s BEGIN UPDATE %s SET n = n + 1 WHERE key = '%s'; END",
		table, table, when, prFuzzWriteCountsTable, exemptKey,
	) // nosemgrep: go.lang.security.audit.database.string-formatted-query.string-formatted-query -- table/exemptKey are schema-derived or fixed test literals; the WHEN clause's column names come from onlyColumns, a fixed hardcoded list, never external/fuzz input
	if _, err := db.Exec(stmt); err != nil {
		t.Fatalf("install exempt-only UPDATE trigger on %s: %v", table, err)
	}
}

func installWriteCountTriggers(t testing.TB, db *sql.DB, tables []string) {
	t.Helper()
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS " + prFuzzWriteCountsTable + " (key TEXT PRIMARY KEY, n INTEGER NOT NULL)"); err != nil {
		t.Fatalf("create %s: %v", prFuzzWriteCountsTable, err)
	}
	for _, tbl := range tables {
		// tbl always ranges over the live schema's own table names
		// (discoverAllTables) in production use, or a fixed hardcoded literal
		// in the oracle mechanism unit tests -- never fuzz input.
		for _, event := range writeCountEvents {
			key := counterKey(tbl, event)
			if _, err := db.Exec("INSERT OR IGNORE INTO "+prFuzzWriteCountsTable+" (key, n) VALUES (?, 0)", key); err != nil {
				t.Fatalf("seed counter row for %s: %v", key, err)
			}
			if event == "UPDATE" {
				if onlyCols, ok := columnScopedUpdateExemption(tbl); ok {
					installColumnScopedUpdateTrigger(t, db, tbl, key, onlyCols)
					exemptKey := counterKey(tbl, exemptOnlyEvent)
					if _, err := db.Exec("INSERT OR IGNORE INTO "+prFuzzWriteCountsTable+" (key, n) VALUES (?, 0)", exemptKey); err != nil {
						t.Fatalf("seed counter row for %s: %v", exemptKey, err)
					}
					installExemptOnlyUpdateTrigger(t, db, tbl, exemptKey, onlyCols)
					continue
				}
			}
			stmt := fmt.Sprintf(
				"CREATE TRIGGER IF NOT EXISTS pr_fuzz_count_%s_%s AFTER %s ON %s BEGIN UPDATE %s SET n = n + 1 WHERE key = '%s'; END",
				tbl, event, event, tbl, prFuzzWriteCountsTable, key,
			) // nosemgrep: go.lang.security.audit.database.string-formatted-query.string-formatted-query -- tbl/event are always drawn from the live schema's own table names or a fixed test literal, never external input
			if _, err := db.Exec(stmt); err != nil {
				t.Fatalf("install %s trigger on %s: %v", event, tbl, err)
			}
		}
	}
}

// dbSnapshot holds the write-trigger counter for EVERY (table, event) pair
// in the schema at one point in time -- not just the exempt ones -- so a
// violation can name exactly which table(s) changed, and an exemption can be
// scoped to one event on one table without masking the other two.
type dbSnapshot struct {
	n map[string]int64 // counterKey(table, event) -> counter at snapshot time
}

func snapshotDB(t testing.TB, db *sql.DB) dbSnapshot {
	t.Helper()
	rows, err := db.Query("SELECT key, n FROM " + prFuzzWriteCountsTable)
	if err != nil {
		t.Fatalf("snapshot write counts: %v", err)
	}
	defer func() { _ = rows.Close() }()
	snap := dbSnapshot{n: map[string]int64{}}
	for rows.Next() {
		var key string
		var n int64
		if err := rows.Scan(&key, &n); err != nil {
			t.Fatalf("scan write count: %v", err)
		}
		snap.n[key] = n
	}
	return snap
}

// tableDelta names one table and how many (non-exempt) write operations it
// absorbed between two snapshots, summed across whichever of
// INSERT/UPDATE/DELETE were not covered by an exemption.
type tableDelta struct {
	table string
	n     int64
}

func (d tableDelta) String() string { return fmt.Sprintf("%s:+%d", d.table, d.n) }

// unexplainedWrites returns every table with a write NOT covered by
// bestEffortSideEffectTables for principal (one of the runAs labels
// "zero-grant", "read-only", "admin"), aggregating across whichever of
// INSERT/UPDATE/DELETE weren't exempt -- empty means no unexplained write
// happened. Checking exemption per (table, event) pair, not per table, is
// what lets a narrow exemption (e.g. sessions:UPDATE only) still catch an
// INSERT or DELETE on that same table. principal narrows this further per
// writeExemption.principals (#2401) -- a write that's exempt for one
// principal can still be unexplained for another.
func (before dbSnapshot) unexplainedWrites(after dbSnapshot, principal string) []tableDelta {
	byTable := map[string]int64{}
	for key, afterN := range after.n {
		table, event := splitCounterKey(key)
		if isBestEffortSideEffectWrite(table, event, principal) {
			continue
		}
		if delta := afterN - before.n[key]; delta > 0 {
			byTable[table] += delta
		}
	}
	out := make([]tableDelta, 0, len(byTable))
	for table, n := range byTable {
		out = append(out, tableDelta{table: table, n: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].table < out[j].table })
	return out
}

func (before dbSnapshot) unexplainedWrite(after dbSnapshot, principal string) bool {
	return len(before.unexplainedWrites(after, principal)) > 0
}

func formatTableDeltas(ds []tableDelta) string {
	parts := make([]string, len(ds))
	for i, d := range ds {
		parts[i] = d.String()
	}
	return strings.Join(parts, ", ")
}

// --- oracle 4: bounded work ---------------------------------------------

// perCallTimeout bounds a single RPC call; anything hitting it is either a
// hung handler or genuinely slow work on a huge input -- disproportionateSizeThreshold
// tells those two apart.
const perCallTimeout = 4 * time.Second

// disproportionateSizeThreshold: this builder caps individual
// string/bytes/repeated/map sizes well below 1 MiB (see fuzzCursor.sizeProbe),
// so a marshaled request below this threshold that still times out cannot be
// explained by "it was just a lot of data" -- it is disproportionate.
const disproportionateSizeThreshold = 1 << 20

// tLogger is the minimal subset of *testing.T checkBoundedWork needs --
// factored out so protoreflect_oracle_mechanism_test.go can red/green-proof
// this function directly with a recorder that observes a Fatalf call instead
// of actually failing the enclosing test (a real *testing.T's Fatalf aborts
// the goroutine and marks every ancestor subtest failed, which would make the
// RED half of that proof itself report as a failing test run).
type tLogger interface {
	Helper()
	Fatalf(format string, args ...any)
	Logf(format string, args ...any)
}

func checkBoundedWork(t tLogger, label string, m grpcMethod, reqSize int, elapsed time.Duration, timedOut bool) {
	t.Helper()
	if !timedOut {
		return
	}
	if reqSize < disproportionateSizeThreshold {
		t.Fatalf("BOUNDED-WORK VIOLATION op=%s principal=%s: a %d-byte request took longer than %s to handle (context deadline exceeded) -- work disproportionate to message size",
			m.key(), label, reqSize, perCallTimeout)
	}
	t.Logf("op=%s principal=%s: %d-byte request hit the %s deadline -- at/above the size-proportional threshold, not flagged", m.key(), label, reqSize, perCallTimeout)
}

// --- oracle 1: no panic / no leaking Unknown/Internal -------------------

// leakIndicatorPatterns are substrings that only ever appear in a RAW,
// unmapped Go/SQL/runtime error -- never in one of this codebase's own
// hand-written client-safe messages (see server/grpc/services/conversions.go's
// clientSafe and every mapXError's documented fallback string). Checking for
// these leak SHAPES, rather than hand-listing every one of the ~25 legitimate
// clientSafe/Internal messages the services package currently uses, is what
// keeps this sound as new Internal call sites are added -- a hand list would
// need updating every time; a leak-shape denylist does not.
var leakIndicatorPatterns = []string{
	"goroutine ", "runtime error", "panic:", "nil pointer dereference",
	".go:", "/users/", "/home/", "/private/",
	"sql:", "gorm:", "pq:", "sqlite:",
	"constraint failed", "constraint violation", "no rows in result set",
	"dial tcp", "connection refused",
}

func leakLooking(msg string) bool {
	lower := strings.ToLower(msg)
	for _, pat := range leakIndicatorPatterns {
		if strings.Contains(lower, pat) {
			return true
		}
	}
	return false
}

// classifyStatusLeak reports whether err's gRPC status is one oracle 1 must
// reject: codes.Unknown (which this codebase's handlers never intentionally
// return -- see the file-header's grep confirming every real call site maps to
// a specific code -- so its mere presence means some error reached the client
// unmapped, raw Go Error() text and all), or codes.Internal carrying a
// leak-shaped message. Red/green-proofed directly (no live server needed) in
// protoreflect_oracle_mechanism_test.go.
func classifyStatusLeak(err error) (bad bool, reason string) {
	if err == nil {
		return false, ""
	}
	st, ok := status.FromError(err)
	if !ok {
		return true, fmt.Sprintf("a non-gRPC-status error reached the client: %v", err)
	}
	switch st.Code() {
	case codes.Unknown:
		return true, fmt.Sprintf("codes.Unknown (an unmapped error reached the client, not a documented status): %q", st.Message())
	case codes.Internal:
		if leakLooking(st.Message()) {
			return true, fmt.Sprintf("codes.Internal message looks like a raw internal error, not a clean client-safe message: %q", st.Message())
		}
	}
	return false, ""
}

func containsCanary(resp *dynamicpb.Message) bool {
	if resp == nil {
		return false
	}
	b, err := proto.Marshal(resp)
	if err != nil {
		return false
	}
	return bytes.Contains(b, []byte(prCanaryValue))
}

func invokeGeneric(ctx context.Context, conn *grpc.ClientConn, m grpcMethod, req *dynamicpb.Message) (*dynamicpb.Message, error) {
	resp := dynamicpb.NewMessage(m.output)
	err := conn.Invoke(ctx, m.fullMethod(), req, resp)
	return resp, err
}

// --- the fuzz target -----------------------------------------------------

func FuzzGRPCProtoreflectInvariants(f *testing.F) {
	w := buildPRWorld(f)
	f.Cleanup(func() {
		w.close()
		i18n.ResetForTesting()
		w.reachedMu.Lock()
		defer w.reachedMu.Unlock()
		var unreached []string
		for _, m := range w.methods {
			if !w.reached[m.key()] {
				unreached = append(unreached, m.key())
			}
		}
		f.Logf("protoreflect fuzzer coverage: %d/%d unary methods reached", len(w.reached), len(w.methods))
		if len(unreached) > 0 {
			f.Logf("unreached methods (%d): %v", len(unreached), unreached)
		}
	})

	// One deterministic seed per discovered method -- every method gets
	// exercised at least once even before any coverage-guided mutation runs,
	// and `go test` (seed-corpus-only, no -fuzz flag) alone proves every RPC
	// is reachable through this harness.
	for i := range w.methods {
		f.Add([]byte{byte(i)})
	}
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, program []byte) {
		w.resetPrincipalGrants(t, context.Background())

		cur := newFuzzCursor(program)
		m := w.methods[int(cur.byte())%len(w.methods)]
		w.markReached(m.key())
		bodyOffset := cur.pos

		// buildReq rebuilds the SAME message from the SAME remaining bytes each
		// time it's called -- a fresh cursor copy starting at bodyOffset -- so all
		// three identities below are compared on an identical request, the same
		// control FuzzGRPCRESTSecretReadAuthzParity's own parity checks rely on.
		buildReq := func() *dynamicpb.Message {
			fresh := &fuzzCursor{data: program, pos: bodyOffset}
			return buildMessage(m.input, fresh, 0)
		}

		drain := func() {
			core.DrainBackgroundGoroutines()
			grpcservices.DrainBackgroundGoroutines()
		}

		runAs := func(label, token string) (resp *dynamicpb.Message, before, after dbSnapshot, err error) {
			req := buildReq()
			reqSize := proto.Size(req)
			ctx := context.Background()
			if token != "" {
				ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+token))
			}
			cctx, cancel := context.WithTimeout(ctx, perCallTimeout)
			defer cancel()

			drain()
			before = snapshotDB(t, w.db)
			start := time.Now()
			resp, err = invokeGeneric(cctx, w.conn, m, req)
			elapsed := time.Since(start)
			drain()
			after = snapshotDB(t, w.db)

			timedOut := status.Code(err) == codes.DeadlineExceeded
			checkBoundedWork(t, label, m, reqSize, elapsed, timedOut)
			if bad, reason := classifyStatusLeak(err); bad {
				t.Fatalf("op=%s principal=%s: %s", m.key(), label, reason)
			}
			return resp, before, after, err
		}

		errorImpliesNoCommit := func(label string, callErr error, before, after dbSnapshot) {
			if callErr == nil {
				return
			}
			if diffs := before.unexplainedWrites(after, label); len(diffs) > 0 {
				t.Fatalf("ERROR-IMPLIES-NO-COMMIT violation op=%s principal=%s: non-OK status (%v) but the DB changed outside the documented best-effort writes -- differing table(s): %s",
					m.key(), label, callErr, formatTableDeltas(diffs))
			}
		}

		zResp, zBefore, zAfter, zErr := runAs("zero-grant", w.zeroGrantTok)
		if zErr == nil {
			if diffs := zBefore.unexplainedWrites(zAfter, "zero-grant"); len(diffs) > 0 {
				t.Fatalf("AUTHZ BYPASS (write) op=%s: zero-grant principal got OK and the DB changed outside the documented best-effort writes -- differing table(s): %s",
					m.key(), formatTableDeltas(diffs))
			}
			if containsCanary(zResp) {
				t.Fatalf("AUTHZ BYPASS (secret read) op=%s: zero-grant principal got OK and the response carried the canary secret's plaintext", m.key())
			}
		}
		errorImpliesNoCommit("zero-grant", zErr, zBefore, zAfter)

		_, roBefore, roAfter, roErr := runAs("read-only", w.readOnlyTok)
		if roErr == nil {
			if diffs := roBefore.unexplainedWrites(roAfter, "read-only"); len(diffs) > 0 {
				t.Fatalf("AUTHZ BYPASS (write) op=%s: read-only principal (system_auditor, no write grant) got OK and the DB changed outside the documented best-effort writes -- differing table(s): %s",
					m.key(), formatTableDeltas(diffs))
			}
		}
		errorImpliesNoCommit("read-only", roErr, roBefore, roAfter)

		// admin: no authz assertion (expected to succeed broadly across a
		// fuzzer-chosen method+request it didn't design for) -- still covered by
		// the leak/bounded-work checks inside runAs, and by error-implies-no-commit
		// on whatever subset of fuzzed requests admin itself can't satisfy
		// (malformed IDs, missing resources, etc).
		_, adBefore, adAfter, adErr := runAs("admin", w.adminTok)
		errorImpliesNoCommit("admin", adErr, adBefore, adAfter)
	})
}
