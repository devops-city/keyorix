// session_revoke_race_test.go — deterministic reproduction of the linearizability
// violation FuzzConcurrentOpsLinearizable found on the session-revocation register
// ("[sqlite] session revuser"): a read that started after a RevokeUserSessions call
// RETURNED still authenticated. See docs/findings/2026-09-20-FINDING-session-revoke-
// cache-race.md for the full write-up.
//
// ROOT CAUSE (confirmed by reading, not just hypothesized): RevokeUserSessions
// (internal/core/account_sessions.go) lists the user's session token hashes, DELETEs
// the session rows, THEN calls invalidateTokenCache(tokens...) to evict the HTTP
// auth cache (server/middleware/auth.go). Between the DELETE committing and the
// invalidate call actually running, the auth cache still holds a POSITIVE entry for
// the deleted session — any request presenting that token in that window hits
// serveAuthCacheHit's session branch, which only re-checks AccountStillUsable (the
// owning ACCOUNT's active/blocked state), never whether the SESSION ROW ITSELF still
// exists. A revoke that leaves the account active (RevokeUserSessions's whole
// purpose, per its own doc comment) has no other live-state check to catch this.
//
// This test forces that exact window deterministically via
// core.SetTestRevokeUserSessionsPreInvalidateHook (a test-only seam, nil in
// production, invoked by RevokeUserSessions right after its DELETE commits and
// right before invalidateTokenCache runs) instead of relying on goroutine
// scheduling luck — the real crashers' natural hit rate is only ~2% per replay
// (3 of 13 archived crashers independently confirmed at 1/50 in isolated
// -count=50 -race replay)
// (see the investigation report).
package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
)

// srrAuthedRead issues an authenticated GET for ref (a permission-checked secret
// read, mirroring the linearizability fuzzer's own clSessionRead) and reports
// whether it authenticated.
func srrAuthedRead(router http.Handler, ref, token string) bool {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/value?ref="+ref, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec.Code == http.StatusOK
}

// TestSessionRevoke_ConcurrentRevokeDoesNotResurrectCachedAuth is the deterministic
// regression test for the session-revocation linearizability bug. RED on
// unfixed main: the read while revoke A is paused (after its DELETE committed, before
// its invalidate) is still authenticated.
func TestSessionRevoke_ConcurrentRevokeDoesNotResurrectCachedAuth(t *testing.T) {
	if err := i18n.InitializeForTesting(); err != nil {
		t.Fatalf("i18n: %v", err)
	}
	t.Cleanup(i18n.ResetForTesting)

	dbPath := filepath.Join(t.TempDir(), "srr.db")
	db, err := gorm.Open(sqlite.Open(dbPath+"?_foreign_keys=1&_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(models.AllTestModels()...); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	c.SetTokenCacheInvalidator(customMiddleware.InvalidateTokenCacheByHash)
	ctx := context.Background()

	c.SetBootstrapToken("srr-bootstrap-token")
	if _, err := c.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "srradmin", Email: "srradmin@example.com",
		Password: "TestPassword123!", Token: "srr-bootstrap-token",
	}); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	ls := store.NewLocalStorage(db)
	admin, err := ls.GetUserByUsername(ctx, "srradmin")
	if err != nil || admin == nil {
		t.Fatalf("admin lookup: %v", err)
	}

	victim, err := c.CreateUser(ctx, &core.CreateUserRequest{
		Username: "srrvictim", Email: "srrvictim@x.io", Password: "Xk7#Qp2$Rn5@Wv9!",
	})
	if err != nil || victim == nil {
		t.Fatalf("create victim: %v", err)
	}

	// Grant the victim a permission-checked secret read (mirrors the linearizability
	// fuzzer's own world setup) so srrAuthedRead exercises a real authenticated,
	// authorized request, not just route-not-found.
	proj, err := ls.CreateProject(ctx, &models.Project{Name: "srr"})
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	env, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: proj.ID})
	if err != nil {
		t.Fatalf("create env: %v", err)
	}
	sec, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "s", Value: []byte("init"), ProjectID: proj.ID, EnvironmentID: env.ID,
		Type: "password", CreatedBy: "srradmin", OwnerID: admin.ID,
	})
	if err != nil || sec == nil {
		t.Fatalf("create secret: %v", err)
	}
	ref := "srr/prod/s"
	var perm models.Permission
	if e := db.Where("name = ?", "secrets.read").First(&perm).Error; e != nil {
		perm = models.Permission{Name: "secrets.read", Resource: "secrets", Action: "read"}
		if e2 := db.Create(&perm).Error; e2 != nil {
			t.Fatalf("seed permission: %v", e2)
		}
	}
	role := models.Role{Name: "srr-reader", NameFolded: "srr-reader"}
	if err := db.Create(&role).Error; err != nil {
		t.Fatalf("seed role: %v", err)
	}
	if err := db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error; err != nil {
		t.Fatalf("seed role-permission: %v", err)
	}
	if err := c.AssignUserRole(ctx, 0, victim.ID, role.ID, core.Scope{ProjectID: proj.ID}, false); err != nil {
		t.Fatalf("grant victim: %v", err)
	}

	sess, _, err := c.Login(ctx, &core.LoginRequest{Username: "srrvictim", Password: "Xk7#Qp2$Rn5@Wv9!"})
	if err != nil || sess == nil {
		t.Fatalf("victim login: %v", err)
	}
	token := sess.SessionToken

	r, err := NewRouter(&config.Config{}, c)
	if err != nil {
		t.Fatalf("router: %v", err)
	}

	// Prime the POSITIVE auth cache entry for token via the real cold path — this
	// mirrors the fuzzer's own "positive control" read (an unverified token would
	// make every subsequent 'still authenticated' observation vacuous).
	if !srrAuthedRead(r, ref, token) {
		t.Fatalf("positive control: victim's own fresh session did not authenticate")
	}

	// --- Force the interleaving ---
	reachedHook := make(chan struct{})
	release := make(chan struct{})
	var hookFired atomic.Bool

	core.SetTestRevokeUserSessionsPreInvalidateHook(func() {
		// Only the FIRST call (revoke A) pauses -- revoke B's own call to
		// RevokeUserSessions also passes through this same hook (it's a package-level
		// seam, not per-call), and B must run to completion, not block. NOT
		// sync.Once: Once.Do blocks EVERY concurrent caller until the first
		// invocation's function returns, which would make B's call also hang on
		// A's <-release below -- a self-inflicted deadlock, not the interleaving
		// under test. CompareAndSwap only gates which goroutine pauses; it does
		// not block the others.
		if hookFired.CompareAndSwap(false, true) {
			close(reachedHook)
			<-release
		}
	})
	t.Cleanup(func() { core.SetTestRevokeUserSessionsPreInvalidateHook(nil) })

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Revoke A: lists [T], DELETEs it (commits), then pauses in the hook above
		// before calling invalidateTokenCache.
		if _, err := c.RevokeUserSessions(ctx, admin.ID, victim.ID); err != nil {
			t.Errorf("revoke A: %v", err)
		}
	}()

	<-reachedHook // A's DELETE has committed; A is now paused before its invalidate.

	// Revoke B: A's DELETE already committed, so B's own list is empty, its DELETE
	// affects zero rows, and its own invalidateTokenCache call is a no-op (nothing to
	// invalidate) -- it returns cleanly while A is still paused. This is exactly the
	// real crashers' shape: a fast concurrent revoke that "sees nothing to do."
	if _, err := c.RevokeUserSessions(ctx, admin.ID, victim.ID); err != nil {
		t.Fatalf("revoke B: %v", err)
	}

	// THE ASSERTION: while A is still paused (its own invalidate has NOT run yet),
	// the session was already deleted from the DB by A's committed transaction. A
	// cache-hit request with T must be denied. On unfixed main, the auth cache still
	// holds the POSITIVE entry primed above (B's invalidate was a no-op, and
	// serveAuthCacheHit's session branch never checks session-row existence), so this
	// currently authenticates -- RED.
	if srrAuthedRead(r, ref, token) {
		t.Error("LINEARIZABILITY VIOLATION: read while revoke A was paused (DELETE committed, invalidate not yet run) still authenticated with the revoked session token")
	}

	close(release) // let A finish (its own invalidateTokenCache(T) now runs)
	wg.Wait()

	// Sanity: once A has fully completed, the token must be denied regardless (this
	// should already hold even on unfixed code -- confirms eventual correctness, not
	// the race itself).
	if srrAuthedRead(r, ref, token) {
		t.Error("token still authenticated even after revoke A fully completed")
	}
}

// srrWorld holds the shared fixture ingredients (one DB, one project/secret/role/
// permission, one admin) that both srrSetupWorld's callers build a core and a
// victim on top of.
type srrWorld struct {
	db    *gorm.DB
	ls    *store.LocalStorage
	admin *models.User
	ref   string
}

// srrSetupWorld bootstraps a fresh SQLite DB with an admin, a project/secret,
// and a "reader" role/permission, ready for a caller to create its own
// *core.KeyorixCore wrapper(s), a victim, and a login on top. Shared by every
// test in this file so each one isn't a ~50-line copy of the others.
func srrSetupWorld(t testing.TB, dbName string) *srrWorld {
	t.Helper()
	if err := i18n.InitializeForTesting(); err != nil {
		t.Fatalf("i18n: %v", err)
	}
	t.Cleanup(i18n.ResetForTesting)

	dbPath := filepath.Join(t.TempDir(), dbName)
	db, err := gorm.Open(sqlite.Open(dbPath+"?_foreign_keys=1&_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(models.AllTestModels()...); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	ls := store.NewLocalStorage(db)

	bootstrapper := core.NewKeyorixCore(ls)
	bootstrapper.SetBootstrapToken("srr-bootstrap-token-" + dbName)
	ctx := context.Background()
	if _, err := bootstrapper.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "srradmin", Email: "srradmin@example.com",
		Password: "TestPassword123!", Token: "srr-bootstrap-token-" + dbName,
	}); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	admin, err := ls.GetUserByUsername(ctx, "srradmin")
	if err != nil || admin == nil {
		t.Fatalf("admin lookup: %v", err)
	}

	proj, err := ls.CreateProject(ctx, &models.Project{Name: "srr"})
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	env, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: proj.ID})
	if err != nil {
		t.Fatalf("create env: %v", err)
	}
	sec, err := bootstrapper.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "s", Value: []byte("init"), ProjectID: proj.ID, EnvironmentID: env.ID,
		Type: "password", CreatedBy: "srradmin", OwnerID: admin.ID,
	})
	if err != nil || sec == nil {
		t.Fatalf("create secret: %v", err)
	}
	ref := "srr/prod/s"
	var perm models.Permission
	if e := db.Where("name = ?", "secrets.read").First(&perm).Error; e != nil {
		perm = models.Permission{Name: "secrets.read", Resource: "secrets", Action: "read"}
		if e2 := db.Create(&perm).Error; e2 != nil {
			t.Fatalf("seed permission: %v", e2)
		}
	}
	role := models.Role{Name: "srr-reader", NameFolded: "srr-reader"}
	if err := db.Create(&role).Error; err != nil {
		t.Fatalf("seed role: %v", err)
	}
	if err := db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error; err != nil {
		t.Fatalf("seed role-permission: %v", err)
	}
	if err := bootstrapper.AssignUserRole(ctx, 0, admin.ID, role.ID, core.Scope{ProjectID: proj.ID}, false); err != nil {
		// admin doesn't need read access itself; ignore -- role exists for the victim.
		_ = err
	}

	return &srrWorld{db: db, ls: ls, admin: admin, ref: ref}
}

// createVictimAndLogin creates a fresh user granted the "srr-reader" role over
// the world's project, logs in via c, and returns the user and their session
// token.
func (w *srrWorld) createVictimAndLogin(t testing.TB, c *core.KeyorixCore, username, password string) (*models.User, string) {
	t.Helper()
	ctx := context.Background()
	victim, err := c.CreateUser(ctx, &core.CreateUserRequest{
		Username: username, Email: username + "@x.io", Password: password,
	})
	if err != nil || victim == nil {
		t.Fatalf("create victim %s: %v", username, err)
	}
	var role models.Role
	if err := w.db.Where("name = ?", "srr-reader").First(&role).Error; err != nil {
		t.Fatalf("lookup role: %v", err)
	}
	var proj models.Project
	if err := w.db.Where("name = ?", "srr").First(&proj).Error; err != nil {
		t.Fatalf("lookup project: %v", err)
	}
	if err := c.AssignUserRole(ctx, 0, victim.ID, role.ID, core.Scope{ProjectID: proj.ID}, false); err != nil {
		t.Fatalf("grant victim %s: %v", username, err)
	}
	sess, _, err := c.Login(ctx, &core.LoginRequest{Username: username, Password: password})
	if err != nil || sess == nil {
		t.Fatalf("login victim %s: %v", username, err)
	}
	return victim, sess.SessionToken
}

// TestSessionRevoke_SecondReplicaNeverInvalidatedCacheHitDenied is requirement
// (b)'s second-node test: cNode2 stands in for a second replica in a
// multi-process deployment that revoked a session but has no way to reach
// cNode1's in-process auth cache (the token cache is a package-level Go map,
// server/middleware/auth.go -- there is no cross-node invalidation mechanism at
// all, see docs/findings/2026-09-20-FINDING-session-revoke-cache-race.md's
// multi-replica section). cNode1 and cNode2 share the SAME underlying DB (this
// process's one *gorm.DB, exactly as two replicas share one Postgres primary in
// production) but NOT the same in-process cache -- only cNode1 ever primes or
// reads it here, so this reproduces "cNode1's cache is stale and nothing ever
// told it" without needing two real processes.
//
// RED on unfixed main: the session row is gone from the shared DB, but
// cNode1's cache was never told (cNode2 has no invalidator wired) and
// serveAuthCacheHit's session branch re-checks only AccountStillUsable, so the
// stale cache hit still authenticates. GREEN after the fix:
// SessionLiveForToken re-reads the session row directly, sees it is gone, and
// denies regardless of which node's cache is stale.
func TestSessionRevoke_SecondReplicaNeverInvalidatedCacheHitDenied(t *testing.T) {
	w := srrSetupWorld(t, "srr-2node.db")

	cNode1 := core.NewKeyorixCore(w.ls)
	cNode1.SetTokenCacheInvalidator(customMiddleware.InvalidateTokenCacheByHash)
	r, err := NewRouter(&config.Config{}, cNode1)
	if err != nil {
		t.Fatalf("router: %v", err)
	}

	victim, token := w.createVictimAndLogin(t, cNode1, "srr2-victim", "Xk7#Qp2$Rn5@Wv9!")

	if !srrAuthedRead(r, w.ref, token) {
		t.Fatalf("positive control: victim's own fresh session did not authenticate")
	}

	// cNode2: the SAME underlying storage, but never wired to evict cNode1's
	// (this process's) auth cache -- exactly what a genuinely separate replica
	// process could never do either.
	cNode2 := core.NewKeyorixCore(store.NewLocalStorage(w.db))
	if _, err := cNode2.RevokeUserSessions(context.Background(), w.admin.ID, victim.ID); err != nil {
		t.Fatalf("revoke via cNode2: %v", err)
	}

	if srrAuthedRead(r, w.ref, token) {
		t.Error("cNode1's cache hit still authenticated a session cNode2 already revoked in the shared DB -- the multi-replica cache-staleness gap is open")
	}
}

// TestSessionRevoke_RotatedTokenCacheHitDenied is requirement 1's rotation
// regression test. RefreshSession/RotateSession (#211, internal/core/auth.go)
// creates a NEW session row with a NEW token hash and marks the OLD row's
// RotatedAt -- it never rewrites session_token in place -- and never calls
// invalidateTokenCache for the OLD token at all, so the old token's positive
// auth-cache entry (if one was already warm) is left untouched by rotation.
//
// RED on unfixed main: the pre-rotation token's warm cache entry keeps
// authenticating (serveAuthCacheHit's session branch never checked session
// identity, only account state, and account state didn't change). GREEN after
// the fix: SessionLiveForToken hashes the presented token and compares it
// against the row it resolves by id; for the OLD token's own SessionID, that
// row now has RotatedAt set, so SessionLiveForToken denies it directly (the
// hash comparison isn't even reached) -- and separately, if sessionID/hash were
// ever mismatched by a wiring bug rather than rotation, the hash comparison
// alone would still catch it.
func TestSessionRevoke_RotatedTokenCacheHitDenied(t *testing.T) {
	w := srrSetupWorld(t, "srr-rotate.db")

	c := core.NewKeyorixCore(w.ls)
	c.SetTokenCacheInvalidator(customMiddleware.InvalidateTokenCacheByHash)
	r, err := NewRouter(&config.Config{}, c)
	if err != nil {
		t.Fatalf("router: %v", err)
	}

	_, oldToken := w.createVictimAndLogin(t, c, "srr-rotate-victim", "Xk7#Qp2$Rn5@Wv9!")

	if !srrAuthedRead(r, w.ref, oldToken) {
		t.Fatalf("positive control: victim's own fresh session did not authenticate")
	}

	newSession, err := c.RefreshSession(context.Background(), oldToken)
	if err != nil || newSession == nil {
		t.Fatalf("refresh session: %v", err)
	}
	if newSession.SessionToken == oldToken {
		t.Fatalf("rotation did not produce a new token")
	}

	if srrAuthedRead(r, w.ref, oldToken) {
		t.Error("the OLD, rotated-out token's warm cache entry still authenticated after rotation")
	}
	// Sanity: the NEW token authenticates fine -- rotation itself is not broken,
	// only the OLD token's stale cache entry was the bug.
	if !srrAuthedRead(r, w.ref, newSession.SessionToken) {
		t.Error("the NEW, post-rotation token failed to authenticate")
	}
}

// TestSessionCacheHit_AccountRestrictionRefreshedOnHit closes the
// AccountRestricted stale-cache gap: EnforceAccountSetup reads
// UserContext.Restricted, which a cache hit previously never refreshed — only
// the outright-deny AccountStillUsable boolean was re-checked on a hit. A
// transition into a restricted-but-not-login-blocked state
// (RequirePasswordReset -> password_reset_required; AccountLoginBlocked is
// false for it, so the account stays "usable") was invisible to a cache hit
// until that transition's OWN cache eviction reached this process — the same
// race SHAPE as the session-liveness bug this PR fixes elsewhere, not just a
// bounded TTL lag. Uses the same two-core pattern as
// TestSessionRevoke_SecondReplicaNeverInvalidatedCacheHitDenied: cNode2 has no
// cache invalidator wired, so its RequirePasswordReset call's own
// invalidateTokenCache is a silent no-op — isolating the cache-hit path's own
// fresh-read refresh (AccountUsabilityAndState / cloneUserContextWithAccountState)
// as what has to do the work, not that call's own eviction.
//
// RED on unfixed code: the cache hit still serves the pre-transition
// Restricted=false, so a non-allowlisted endpoint returns 200. GREEN after
// the fix: the same cache hit re-reads AccountState fresh, and
// EnforceAccountSetup (server/middleware/auth.go, reading
// userCtx.Restricted) returns 403.
func TestSessionCacheHit_AccountRestrictionRefreshedOnHit(t *testing.T) {
	w := srrSetupWorld(t, "srr-restrict.db")

	cNode1 := core.NewKeyorixCore(w.ls)
	cNode1.SetTokenCacheInvalidator(customMiddleware.InvalidateTokenCacheByHash)
	r, err := NewRouter(&config.Config{}, cNode1)
	if err != nil {
		t.Fatalf("router: %v", err)
	}

	victim, token := w.createVictimAndLogin(t, cNode1, "srr-restrict-victim", "Xk7#Qp2$Rn5@Wv9!")

	if !srrAuthedRead(r, w.ref, token) {
		t.Fatalf("positive control: victim's own fresh session did not authenticate")
	}

	// cNode2: same underlying storage, but never wired to evict cNode1's (this
	// process's) auth cache -- see the doc comment above for why this isolates
	// the mechanism under test.
	cNode2 := core.NewKeyorixCore(store.NewLocalStorage(w.db))
	if err := cNode2.RequirePasswordReset(context.Background(), w.admin.ID, victim.ID); err != nil {
		t.Fatalf("RequirePasswordReset: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/value?ref="+w.ref, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 (PasswordChangeRequired) on the next cache-hit request after RequirePasswordReset, got %d", rec.Code)
	}
}

// BenchmarkSessionCacheHit measures the warm-cache-hit path for a session
// token through a REAL *core.KeyorixCore (unlike server/middleware's own
// BenchmarkAuthentication, which passes a nil coreService and so never enters
// serveAuthCacheHit's coreService-gated branch at all -- neither the
// pre-existing AccountStillUsable check nor this fix's SessionLiveForToken
// check would ever run there). b.N-1 of the b.N requests hit the warm cache
// (the first fills it); requirement 8's before/after comparison is this
// benchmark's ns/op with SessionLiveForToken's call site present vs. commented
// out, run manually across the fix commit.
func BenchmarkSessionCacheHit(b *testing.B) {
	w := srrSetupWorld(b, "srr-bench.db")
	c := core.NewKeyorixCore(w.ls)
	c.SetTokenCacheInvalidator(customMiddleware.InvalidateTokenCacheByHash)
	r, err := NewRouter(&config.Config{}, c)
	if err != nil {
		b.Fatalf("router: %v", err)
	}
	_, token := w.createVictimAndLogin(b, c, "srr-bench-victim", "Xk7#Qp2$Rn5@Wv9!")
	if !srrAuthedRead(r, w.ref, token) {
		b.Fatalf("positive control: victim's own fresh session did not authenticate")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/value?ref="+w.ref, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("unexpected status %d", rec.Code)
		}
	}
}
