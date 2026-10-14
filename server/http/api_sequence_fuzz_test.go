package http

// FuzzKeyorixHTTPAPISequence is the "fuzzing x DAST/IAST" tier: it drives a
// fuzzer-chosen sequence of grant/revoke/read operations against a REAL, fully
// wired keyorix stack — the actual chi router + auth middleware + handlers + core
// + crypto + storage — stood up in-process via the real NewRouter, so Go's
// coverage-guided fuzzer sees the whole request path. Reads go over HTTP
// (GET /api/v1/secrets/value?ref=...); mutations go through the core with an
// explicit auth-cache flush so the shadow model never lags the 30s token cache.
//
// Oracle = a tiny shadow authz model + the known secret plaintexts. Invariants are
// asserted only in the direction that cannot false-positive:
//   - AUTH-REQUIRED:   no/garbage token must never return 200 with a value.
//   - FAIL-CLOSED:     a principal the model says may NOT read must be denied.
//   - NO-PLAINTEXT-ON-DENY: a non-200 body must never contain the secret value.
//   - INTEGRITY:       a 200 read must carry EXACTLY the requested secret's value
//                      (we never assert "allowed => must 200").
// Tenant isolation falls out for free: a reader granted on project A reading a
// project-B secret is an ungranted (principal, project) pair, i.e. fail-closed.
//
// Phase 1. SQLite-backed (CI-runnable, fast); the same harness points at the rig
// Postgres by swapping the core's DB (Phase 2). See
// claude/2026-09-16-spec-live-api-invariant-fuzzing.md.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/fuzzworld"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
)

type apiFuzzPrincipal struct {
	id    uint
	token string // "" if this principal could not obtain a session (treated as no-token)
}

// apiFuzzPrincipalPassword is the shared password for the non-admin fuzz principals and
// the dedicated revocation-probe principal.
const apiFuzzPrincipalPassword = "Xk7#Qp2$Rn5@Wv9!"

// apiSeqMutSeq gives each mutation-audit-completeness probe invocation a process-unique
// secret name so a freshly created secret carries a brand-new SecretNodeID with no prior
// audit rows — the audit oracle then filters on (Action, ResourceID) alone, clock-free.
var apiSeqMutSeq atomic.Int64

type apiFuzzWorld struct {
	backend    string // "sqlite" or "postgres" -- failure messages only
	router     http.Handler
	db         *gorm.DB
	c          *core.KeyorixCore
	readerRole uint
	adminTok   string
	adminID    uint // actor for RevokeUserSessions in the revocation probe
	revuserID  uint // dedicated principal for the token-revocation-monotonicity probe
	projAID    uint
	projBID    uint
	envAID     uint // env of projA — target scope for the create/rotate/update/delete audit-completeness probe
	refA, valA string
	refB, valB string
	principals []apiFuzzPrincipal // non-admin, own no secrets, start with no grants
}

// buildAPIFuzzWorldSQLite and buildAPIFuzzWorldPostgres build the full rich
// apiFuzzWorld on top of a bare *gorm.DB from internal/testutil/fuzzworld
// (OpenSQLite/OpenPostgres). The rich-world construction (router, core,
// principals, secrets) is itself the expensive once-per-backend step here,
// so unlike the core/encryption fuzzers this one does not use
// fuzzworld.Worlds/World.Reset. buildAPIFuzzWorlds returns the
// SQLite world (always) plus the PostgreSQL world (when KEYORIX_TEST_PG_DSN
// is set) as a slice callers range over -- one iteration of the fuzz body
// per world.
func buildAPIFuzzWorldSQLite(f *testing.F) *apiFuzzWorld {
	f.Helper()
	return buildAPIFuzzWorld(f, fuzzworld.BackendSQLite, fuzzworld.OpenSQLite(f, sqlitetest.DSN("kxtest_"), 1))
}

func buildAPIFuzzWorldPostgres(f *testing.F, schemaPrefix string) *apiFuzzWorld {
	f.Helper()
	db := fuzzworld.OpenPostgres(f, schemaPrefix)
	if db == nil {
		return nil
	}
	return buildAPIFuzzWorld(f, fuzzworld.BackendPostgres, db)
}

func buildAPIFuzzWorlds(f *testing.F, schemaPrefix string) []*apiFuzzWorld {
	worlds := []*apiFuzzWorld{buildAPIFuzzWorldSQLite(f)}
	if pg := buildAPIFuzzWorldPostgres(f, schemaPrefix); pg != nil {
		worlds = append(worlds, pg)
	} else {
		f.Logf("KEYORIX_TEST_PG_DSN not set (%s) -- PostgreSQL backend skipped, SQLite only", schemaPrefix)
	}
	return worlds
}

func buildAPIFuzzWorld(f *testing.F, backend string, db *gorm.DB) *apiFuzzWorld {
	f.Helper()
	if err := i18n.InitializeForTesting(); err != nil {
		f.Fatalf("i18n: %v", err)
	}
	// #1947: the real production schema (migrateDatabase), not AutoMigrate plus a
	// hand-copied subset of its partial unique indexes -- that copy (four indexes,
	// errors discarded) is exactly the drift the issue describes. AllTestModels is
	// AutoMigrated on top only for any test-only models production doesn't create.
	fuzzworld.Bootstrap(f, db)
	if err := db.AutoMigrate(models.AllTestModels()...); err != nil {
		f.Fatalf("migrate test models (%s): %v", backend, err)
	}

	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	// Wire the core's auth-cache invalidator to the middleware cache, exactly as real
	// server startup does (NewRouter alone does not). Without this, RevokeUserSessions'
	// cache eviction is a no-op in-test and a revoked token lingers in the positive cache
	// for its TTL — so the revocation probe below must exercise the real eviction path.
	c.SetTokenCacheInvalidator(customMiddleware.InvalidateTokenCacheByHash)
	ls := store.NewLocalStorage(db)
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

	pA, err := ls.CreateProject(ctx, &models.Project{Name: "proja"})
	if err != nil {
		f.Fatalf("projA: %v", err)
	}
	eA, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: pA.ID})
	if err != nil {
		f.Fatalf("envA: %v", err)
	}
	pB, err := ls.CreateProject(ctx, &models.Project{Name: "projb"})
	if err != nil {
		f.Fatalf("projB: %v", err)
	}
	eB, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: pB.ID})
	if err != nil {
		f.Fatalf("envB: %v", err)
	}

	// reader role carrying secrets.read (reuse the seeded permission if present)
	var perm models.Permission
	if e := db.Where("name = ?", "secrets.read").First(&perm).Error; e != nil {
		perm = models.Permission{Name: "secrets.read", Resource: "secrets", Action: "read"}
		if e2 := db.Create(&perm).Error; e2 != nil {
			f.Fatalf("seed permission: %v", e2)
		}
	}
	role := models.Role{Name: "api-fuzz-reader", NameFolded: "api-fuzz-reader"}
	if e := db.Create(&role).Error; e != nil {
		f.Fatalf("seed role: %v", e)
	}
	if e := db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error; e != nil {
		f.Fatalf("seed role-permission: %v", e)
	}

	sA, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "sa", Value: []byte("VALUE-A-9f3c1"), ProjectID: pA.ID, EnvironmentID: eA.ID,
		Type: "password", CreatedBy: "testadmin", OwnerID: admin.ID,
	})
	if err != nil || sA == nil {
		f.Fatalf("secretA: %v", err)
	}
	sB, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "sb", Value: []byte("VALUE-B-6b28e"), ProjectID: pB.ID, EnvironmentID: eB.ID,
		Type: "password", CreatedBy: "testadmin", OwnerID: admin.ID,
	})
	if err != nil || sB == nil {
		f.Fatalf("secretB: %v", err)
	}

	mkPrincipal := func(uname, email string) apiFuzzPrincipal {
		u, err := c.CreateUser(ctx, &core.CreateUserRequest{Username: uname, Email: email, Password: "Xk7#Qp2$Rn5@Wv9!"})
		if err != nil || u == nil {
			f.Fatalf("create user %s: %v", uname, err)
		}
		tok := ""
		if sess, _, lerr := c.Login(ctx, &core.LoginRequest{Username: uname, Password: "Xk7#Qp2$Rn5@Wv9!"}); lerr == nil && sess != nil {
			tok = sess.SessionToken
		} else {
			f.Logf("principal %s could not obtain a session (%v) — treated as no-token", uname, lerr)
		}
		return apiFuzzPrincipal{id: u.ID, token: tok}
	}
	principals := []apiFuzzPrincipal{
		mkPrincipal("readera", "readera@x.io"),
		mkPrincipal("readerb", "readerb@x.io"),
		mkPrincipal("outsider", "outsider@x.io"),
	}

	// revuser is a dedicated principal for the token-revocation-monotonicity probe. It is
	// NOT pre-logged-in: the probe mints a fresh session each time, so a revocation in one
	// iteration never leaks a dead token into the next (the shared world is built once).
	// RevokeUserSessions leaves the account active, so re-login always succeeds.
	revuser, err := c.CreateUser(ctx, &core.CreateUserRequest{Username: "revuser", Email: "revuser@x.io", Password: apiFuzzPrincipalPassword})
	if err != nil || revuser == nil {
		f.Fatalf("create revuser: %v", err)
	}

	r, err := NewRouter(&config.Config{}, c)
	if err != nil {
		f.Fatalf("router: %v", err)
	}

	return &apiFuzzWorld{
		backend: backend,
		router:  r, db: db, c: c, readerRole: role.ID, adminTok: adminSess.SessionToken,
		adminID: admin.ID, revuserID: revuser.ID,
		projAID: pA.ID, projBID: pB.ID, envAID: eA.ID,
		refA: "proja/prod/sa", valA: "VALUE-A-9f3c1",
		refB: "projb/prod/sb", valB: "VALUE-B-6b28e",
		principals: principals,
	}
}

func FuzzKeyorixHTTPAPISequence(f *testing.F) {
	worlds := buildAPIFuzzWorlds(f, "apiseqfuzz")
	f.Cleanup(i18n.ResetForTesting)

	// Every existing seed is prefixed with 0xFF (the full-set sentinel — see
	// decodeOpSubsetHTTP), so each one still exercises every operation type
	// exactly as it did before swarm mode, byte-for-byte, from the second
	// byte on; the probe gates below now read body[0] (the first byte AFTER
	// the subset byte), preserving the original program[0]-based gating
	// relationship one byte over.
	f.Add([]byte{0xFF, 0, 0, 0, 2, 0, 3, 2, 2, 3})
	f.Add([]byte{0xFF, 0, 1, 1, 2, 1, 3})
	f.Add([]byte{0xFF, 0}) // body[0]=0 -- triggers the revocation-monotonicity probe (body[0]%4==0)
	f.Add([]byte{0xFF, 1}) // body[0]=1 -- triggers the mutation/audit-completeness probe (body[0]%4==1)
	f.Add([]byte{})
	// Swarm seeds: restrict the active op set (0=grant,1=revoke,2=read) to a
	// single rare-in-practice pair. Bit i (1<<i) enables op i.
	f.Add([]byte{0b011, 0, 0, 0, 2, 0, 1, 0}) // grant(bit0) + revoke(bit1) only, no reads
	f.Add([]byte{0b110, 1, 0, 0, 2, 1, 3, 1}) // revoke(bit1) + read(bit2) only, no grants

	f.Fuzz(func(t *testing.T, program []byte) {
		for _, w := range worlds {
			runAPISeqIteration(t, w, program)
		}
	})
}

// decodeOpSubsetHTTP (swarm mode) reads the FIRST byte of a raw program as an
// enabled-operation bitmask: bit i (1<<i) enables step operation kind i (0
// grant, 1 revoke, 2 read). See core_sequence_fuzz_test.go's decodeOpSubset
// for the full rationale (same mechanism, 3 operation kinds here instead of
// 5). 0xFF and the degenerate all-zero-bits case both mean "every operation
// enabled".
func decodeOpSubsetHTTP(b byte) []int {
	if b == 0xFF {
		return []int{0, 1, 2}
	}
	var subset []int
	for i := range 3 {
		if b&(1<<uint(i)) != 0 {
			subset = append(subset, i)
		}
	}
	if len(subset) == 0 {
		return []int{0, 1, 2} // degenerate: no bit set -> fall back to full set
	}
	return subset
}

func runAPISeqIteration(t *testing.T, w *apiFuzzWorld, program []byte) {
	t.Helper()
	ctx := context.Background()

	// Swarm mode: the first byte of the raw program picks the enabled-operation
	// subset for the rest of this iteration; everything after it is the
	// original 3-bytes-per-step encoding, now read from body rather than program.
	subsetByte := byte(0xFF)
	body := program
	if len(program) > 0 {
		subsetByte = program[0]
		body = program[1:]
	}
	subset := decodeOpSubsetHTTP(subsetByte)

	// per-iteration reset: drop fuzz-principal grants, clear the model. NO token-cache
	// flush. middleware.InvalidateTokenCache writes a negative TOMBSTONE (it is a
	// revocation helper, not a refresh), which denied the token for invalidTokenTTL and
	// so silently masked every AUTHORIZED read in this harness — the positive path was
	// never actually verified (a granted read got 401, and read() only checks integrity
	// on a 200, so the assertion was skipped). The auth cache holds only the
	// authenticated IDENTITY; the per-request permission check re-reads grants from the
	// DB, so a grant/revoke is reflected on the very next read with no flush needed.
	w.db.Exec("DELETE FROM user_roles WHERE user_id IN (?,?,?)",
		w.principals[0].id, w.principals[1].id, w.principals[2].id)
	canRead := map[uint]map[uint]bool{}
	for _, p := range w.principals {
		canRead[p.id] = map[uint]bool{w.projAID: false, w.projBID: false}
	}

	projFor := func(sel int) uint {
		if sel%2 == 1 {
			return w.projBID
		}
		return w.projAID
	}
	grant := func(pi, proj int) {
		p := w.principals[pi%len(w.principals)]
		projID := projFor(proj)
		if err := w.c.AssignUserRole(ctx, 0, p.id, w.readerRole, core.Scope{ProjectID: projID}, false); err == nil {
			canRead[p.id][projID] = true
		}
	}
	revoke := func(pi, proj int) {
		p := w.principals[pi%len(w.principals)]
		projID := projFor(proj)
		if err := w.c.RemoveUserRole(ctx, 0, p.id, w.readerRole, core.Scope{ProjectID: projID}); err == nil {
			canRead[p.id][projID] = false
		}
	}
	read := func(who, which, mode byte) {
		ref, val, projID := w.refA, w.valA, w.projAID
		if which%2 == 1 {
			ref, val, projID = w.refB, w.valB, w.projBID
		}
		var authz string
		allowed := false
		switch mode % 4 {
		case 0: // no token
		case 1: // garbage token
			authz = "Bearer garbage-not-a-real-token"
		case 2: // admin (owns every secret; global admin)
			authz, allowed = "Bearer "+w.adminTok, true
		default: // a fuzz principal's token
			p := w.principals[int(who)%len(w.principals)]
			if p.token != "" {
				authz = "Bearer " + p.token
			}
			allowed = p.token != "" && canRead[p.id][projID]
		}
		req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/value?ref="+ref, nil)
		if authz != "" {
			req.Header.Set("Authorization", authz)
		}
		rec := httptest.NewRecorder()
		w.router.ServeHTTP(rec, req)
		body := rec.Body.String()

		if !allowed {
			if rec.Code == http.StatusOK {
				t.Fatalf("AUTHZ BYPASS: unauthorized read of %q returned 200 (mode=%d who=%d)\nbody=%s", ref, mode%4, who, body)
			}
			if strings.Contains(body, val) {
				t.Fatalf("PLAINTEXT LEAK on deny: response for %q (code=%d) contains the secret value\nbody=%s", ref, rec.Code, body)
			}
			return
		}
		// allowed: a 200 must carry EXACTLY this secret's value (never assert must-200).
		if rec.Code == http.StatusOK {
			var resp struct {
				Data struct {
					Value string `json:"value"`
				} `json:"data"`
			}
			if json.Unmarshal(rec.Body.Bytes(), &resp) == nil && resp.Data.Value != val {
				t.Fatalf("INTEGRITY: authorized read of %q returned wrong value %q (want %q)", ref, resp.Data.Value, val)
			}
		}
	}

	// revocationProbe exercises token-revocation monotonicity end-to-end against the
	// real stack: mint a FRESH session for revuser, grant it read on A, confirm the
	// token actually authorizes the read (positive control — otherwise the deny below
	// is vacuous), then RevokeUserSessions and assert the SAME token is now denied.
	// Sound: only the deny direction is asserted, and only after proving the token
	// worked immediately before. Revocation is driven through the real core path
	// (deletes the session + evicts the auth cache), reads over HTTP — so it verifies
	// the actual cache-eviction, not a directly-written tombstone.
	revocationProbe := func() {
		sess, _, lerr := w.c.Login(ctx, &core.LoginRequest{Username: "revuser", Password: apiFuzzPrincipalPassword})
		if lerr != nil || sess == nil {
			return
		}
		tok := sess.SessionToken
		defer w.db.Exec("DELETE FROM user_roles WHERE user_id = ?", w.revuserID) // keep the shared world clean
		if err := w.c.AssignUserRole(ctx, 0, w.revuserID, w.readerRole, core.Scope{ProjectID: w.projAID}, false); err != nil {
			return
		}
		readA := func() *httptest.ResponseRecorder {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/value?ref="+w.refA, nil)
			req.Header.Set("Authorization", "Bearer "+tok)
			rec := httptest.NewRecorder()
			w.router.ServeHTTP(rec, req)
			return rec
		}
		// Positive control: the granted token must actually read A, else the deny below
		// is vacuous and we skip the assertion (avoids a false positive).
		if readA().Code != http.StatusOK {
			return
		}
		if _, err := w.c.RevokeUserSessions(ctx, w.adminID, w.revuserID); err != nil {
			return
		}
		post := readA()
		if post.Code == http.StatusOK {
			t.Fatalf("REVOCATION INEFFECTIVE: revuser's token still returned 200 for %q after RevokeUserSessions", w.refA)
		}
		if strings.Contains(post.Body.String(), w.valA) {
			t.Fatalf("PLAINTEXT LEAK after revocation: response for %q contains the secret value\nbody=%s", w.refA, post.Body.String())
		}
	}

	// mutationProbe drives the WRITE side of the CRUD lifecycle over HTTP through the
	// real stack — create, rotate, update, delete — as the global admin (authorized at
	// every scope, so each call genuinely succeeds), and asserts AUDIT COMPLETENESS:
	// every successful privileged mutation must leave its attributable audit event.
	//
	// Sound and clock-free. The assertion fires ONLY after the HTTP call returned its
	// documented success code (201/200/200/204); a non-success skips it and never
	// asserts absence — so it can only catch a mutation that SUCCEEDED yet produced NO
	// event, i.e. a real audit-trail gap (the property NIS2/DORA compliance leans on).
	// The secret is created fresh with a process-unique name, so its SecretNodeID is
	// brand new and the oracle matches on (Action, ResourceID) alone — no time window to
	// race, no confounding older events.
	//
	// The audit write is asynchronous: the handlers fire LogSecret*WithProject inside a
	// goSafe goroutine on a detached context, so the row is not guaranteed present the
	// instant ServeHTTP returns. Hence a BOUNDED POLL, not an immediate read — the poll
	// only ever converts a slow write into a short wait, and fails solely when the event
	// never lands within a generous deadline (a genuine drop).
	mutationProbe := func() {
		name := fmt.Sprintf("apiseq-mut-%d", apiSeqMutSeq.Add(1))
		defer w.db.Exec("DELETE FROM secret_nodes WHERE name = ? AND project_id = ?", name, w.projAID)

		adminReq := func(method, target, body string) *httptest.ResponseRecorder {
			var req *http.Request
			if body != "" {
				req = httptest.NewRequest(method, target, strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
			} else {
				req = httptest.NewRequest(method, target, nil)
			}
			req.Header.Set("Authorization", "Bearer "+w.adminTok)
			rec := httptest.NewRecorder()
			w.router.ServeHTTP(rec, req)
			return rec
		}

		// assertAudited: the (kind, sid) event MUST appear within the deadline. The
		// bounded poll absorbs the async detached-context audit write without ever
		// false-positiving on a merely-slow one.
		assertAudited := func(kind string, sid uint) {
			deadline := time.Now().Add(10 * time.Second)
			for {
				res, err := w.c.SearchAuditLogs(ctx, core.AuditSearchRequest{Action: kind, ResourceID: sid, Limit: 5})
				if err == nil && res != nil && (res.Total > 0 || len(res.Events) > 0) {
					return
				}
				if time.Now().After(deadline) {
					t.Fatalf("AUDIT COMPLETENESS: successful HTTP mutation left no %q event for secret %d (id-scoped, 10s deadline)", kind, sid)
				}
				time.Sleep(20 * time.Millisecond)
			}
		}

		// CREATE — POST /api/v1/secrets/ (authz is handler-internal; admin passes).
		createBody := fmt.Sprintf(`{"name":%q,"value":"MUT-CREATE-1","project_id":%d,"environment_id":%d,"type":"password"}`,
			name, w.projAID, w.envAID)
		if rec := adminReq(http.MethodPost, "/api/v1/secrets/", createBody); rec.Code != http.StatusCreated {
			return // create didn't cleanly succeed — nothing to assert soundly
		}
		// Resolve the fresh secret's id by its unique name (clock- and JSON-shape-
		// independent). Absent ⇒ skip rather than assert.
		var node models.SecretNode
		if e := w.db.Where("name = ? AND project_id = ?", name, w.projAID).First(&node).Error; e != nil || node.ID == 0 {
			return
		}
		sid := node.ID
		assertAudited("secret.created", sid)

		// ROTATE — POST /{id}/rotate (secrets.write, route-gated; admin passes).
		if rec := adminReq(http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/rotate", sid), `{"new_value":"MUT-ROTATE-2"}`); rec.Code == http.StatusOK {
			assertAudited("secret.rotated", sid)
		}
		// UPDATE — PUT /{id} (secrets.write, route-gated).
		if rec := adminReq(http.MethodPut, fmt.Sprintf("/api/v1/secrets/%d", sid), `{"value":"MUT-UPDATE-3"}`); rec.Code == http.StatusOK {
			assertAudited("secret.updated", sid)
		}
		// DELETE — DELETE /{id} (secrets.delete, route-gated) → 204.
		if rec := adminReq(http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d", sid), ""); rec.Code == http.StatusNoContent {
			assertAudited("secret.deleted", sid)
		}
	}

	const maxSteps = 60
	for i := 0; i+2 < len(body) && i < maxSteps*3; i += 3 {
		switch subset[int(body[i])%len(subset)] {
		case 0:
			grant(int(body[i+1]), int(body[i+2]))
		case 1:
			revoke(int(body[i+1]), int(body[i+2]))
		default:
			read(body[i+1], body[i+2], body[i+1])
		}
	}
	// always exercise the two anchor paths regardless of input:
	read(0, 0, 2) // admin reads A -> integrity/round-trip
	read(2, 1, 3) // outsider (index 2, ungranted) reads B -> fail-closed

	// Occasionally run the revocation-monotonicity probe. It mints a fresh session
	// (bcrypt), so gate it (~1 in 4 inputs) to keep average throughput high. Gated
	// on body[0] (not subject to the swarm subset — these probes are fixed
	// safety-net checks, not part of the fuzzed op stream), mirroring the
	// original program[0]-based gate one byte over.
	if len(body) >= 1 && body[0]%4 == 0 {
		revocationProbe()
	}

	// Occasionally run the mutation/audit-completeness probe (~1 in 4 inputs, disjoint
	// from the revocation gate above). It creates + rotates + updates + deletes a fresh
	// secret over HTTP and polls the async audit write, so it is heavier — gate it too.
	if len(body) >= 1 && body[0]%4 == 1 {
		mutationProbe()
	}
}
