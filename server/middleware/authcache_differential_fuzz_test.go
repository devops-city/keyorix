// authcache_differential_fuzz_test.go — FuzzAuthCacheDifferential (FUZZ-GAPS G5,
// K9 part 1: single-node auth-cache-vs-DB differential; the two-replica part is
// a separate, later track).
//
// Drives random sequences of login / PAT create / machine-token issue,
// interleaved with revoke / suspend / role-change / password-change /
// session-delete / expiry mutations and authenticated requests, over a REAL
// sqlite-backed *core.KeyorixCore and the REAL Authentication middleware chain
// (this package) — not a reimplementation of the cache.
//
// Oracle: for every "authenticated request" step, the decision the auth-cache
// layer serves (which may be a cache hit) must equal the decision the exact
// same request gets with that token's cache entry forced out first (straight
// to storage). Any divergence is a stale/wrong cached auth decision — a real
// bug by this track's own definition, regardless of which internal mechanism
// was supposed to prevent it.
//
// Regression coverage for the three prior fixes named in the G5 spec, by
// construction of that oracle (not by re-deriving each fix's own internal
// mechanism):
//
//   - #1955 (re-verify on every cache hit): serveAuthCacheHit is supposed to
//     re-check revocation/expiry/suspension on every hit, exactly like a miss
//     would. If that re-check were ever dropped, a normal call serving a stale
//     cache hit would authenticate while the forced-cache-bypass call (always
//     through the real validators) denies — acCheckDifferential's status
//     comparison catches this directly, for session, PAT, and machine tokens
//     alike, whenever a revoke/suspend/role-removal op precedes an
//     authenticated-request op in the fuzzed sequence.
//   - #1878 (session-expiry clamp): acOpExpireSession backdates a session's
//     real ExpiresAt directly in storage (deterministic, no sleep) AFTER its
//     positive cache entry already exists. If a cache entry could ever
//     outlive the session's own expiry, the normal (cache-hit) call would
//     keep authenticating while the forced-fresh call — which re-validates
//     against storage — denies. Same oracle, same catch.
//   - #1985 (role-lookup error fails closed): this one is not a caching
//     question (a storage error looks the same to a cache hit and a miss —
//     both must fail closed), so it needs its own dedicated check rather than
//     the cache-bypass diff: acCheckRoleLookupFault drives the live session
//     token through a validator that reports core.ErrRoleResolutionUnavailable
//     (the exact #1944/#1985 shape) and asserts the request is denied (503),
//     never reaches the handler, and writes no cache entry at all — a
//     regression to "success with an empty role list" would flip every one of
//     those three assertions.
package middleware

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// acdInitialPassword is the victim's password at the start of every fuzz
// iteration (acWorld.resetIteration resets the stored hash back to this
// value's bcrypt hash directly, so a password-change op earlier in the
// program never leaks into the next iteration).
const acdInitialPassword = "Xk7#Qp2$Rn5@Wv9!"

// acWorld holds the one sqlite DB / core.KeyorixCore / handler chain shared
// across every fuzz execution (schema + bcrypt setup cost paid once, not per
// iteration — mirrors FuzzConcurrentOpsLinearizable's clWorld convention in
// server/http). Only the victim's own mutable state (sessions, PATs, machine
// credentials, roles, suspension, password) is reset between iterations.
type acWorld struct {
	db *gorm.DB
	c  *core.KeyorixCore
	// handler is Authentication(c) wrapping a probe that authorizes
	// "secrets.read" in scope — a real, minimal authenticated-request target.
	handler http.Handler

	adminID           uint
	victimID          uint
	victimUser        string
	baselinePwHash    string
	projID            uint
	roleID            uint
	scope             core.Scope
	machineIdentityID uint
}

func acBuildWorld(f *testing.F) *acWorld {
	f.Helper()
	if err := i18n.InitializeForTesting(); err != nil {
		f.Fatalf("i18n: %v", err)
	}

	dbPath := filepath.Join(f.TempDir(), "acd.db")
	db, err := gorm.Open(sqlite.Open(dbPath+"?_foreign_keys=1&_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		f.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(models.AllTestModels()...); err != nil {
		f.Fatalf("migrate: %v", err)
	}
	ls := store.NewLocalStorage(db)
	c := core.NewKeyorixCore(ls)
	c.SetTokenCacheInvalidator(InvalidateTokenCacheByHash)
	c.SetTokenCacheClearer(ClearTokenCacheIfCached)
	ctx := context.Background()

	c.SetBootstrapToken("acd-bootstrap-token")
	if _, err := c.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "acdadmin", Email: "acdadmin@example.com",
		Password: "TestPassword123!", Token: "acd-bootstrap-token",
	}); err != nil {
		f.Fatalf("bootstrap: %v", err)
	}
	admin, err := ls.GetUserByUsername(ctx, "acdadmin")
	if err != nil || admin == nil {
		f.Fatalf("admin lookup: %v", err)
	}

	proj, err := ls.CreateProject(ctx, &models.Project{Name: "acd"})
	if err != nil {
		f.Fatalf("create project: %v", err)
	}
	env, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: proj.ID})
	if err != nil {
		f.Fatalf("create env: %v", err)
	}
	sec, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "s", Value: []byte("init"), ProjectID: proj.ID, EnvironmentID: env.ID,
		Type: "password", CreatedBy: "acdadmin", OwnerID: admin.ID,
	})
	if err != nil || sec == nil {
		f.Fatalf("create secret: %v", err)
	}

	var perm models.Permission
	if e := db.Where("name = ?", "secrets.read").First(&perm).Error; e != nil {
		perm = models.Permission{Name: "secrets.read", Resource: "secrets", Action: "read"}
		if e2 := db.Create(&perm).Error; e2 != nil {
			f.Fatalf("seed permission: %v", e2)
		}
	}
	role := models.Role{Name: "acd-reader", NameFolded: "acd-reader"}
	if err := db.Create(&role).Error; err != nil {
		f.Fatalf("seed role: %v", err)
	}
	if err := db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error; err != nil {
		f.Fatalf("seed role-permission: %v", err)
	}

	victim, err := c.CreateUser(ctx, &core.CreateUserRequest{
		Username: "acdvictim", Email: "acdvictim@x.io", Password: acdInitialPassword,
	})
	if err != nil || victim == nil {
		f.Fatalf("create victim: %v", err)
	}
	freshVictim, err := ls.GetUser(ctx, victim.ID)
	if err != nil || freshVictim == nil {
		f.Fatalf("reload victim: %v", err)
	}

	mid, err := c.CreateMachineIdentity(ctx, proj.ID, "acd-machine", core.MachineTypeCI, "", "", admin.ID, 0)
	if err != nil || mid == nil {
		f.Fatalf("create machine identity: %v", err)
	}

	scope := core.Scope{ProjectID: proj.ID}
	downstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userCtx := GetUserFromContext(r.Context())
		cs := GetCoreServiceFromContext(r.Context())
		if userCtx == nil || cs == nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		allowed, aerr := cs.AuthorizePrincipal(r.Context(), userCtx.ActorKind(), userCtx.PrincipalID(), "secrets.read", scope)
		if aerr != nil || !allowed {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	return &acWorld{
		db:                db,
		c:                 c,
		handler:           Authentication(c)(downstream),
		adminID:           admin.ID,
		victimID:          victim.ID,
		victimUser:        "acdvictim",
		baselinePwHash:    freshVictim.PasswordHash,
		projID:            proj.ID,
		roleID:            role.ID,
		scope:             scope,
		machineIdentityID: mid.ID,
	}
}

// acIterState is the per-fuzz-execution mutable state: which credentials are
// currently live, and the world's current view of the victim's password (so
// the password-change op can keep succeeding across several invocations in
// one program instead of failing "current password incorrect" every time
// after the first).
type acIterState struct {
	sessionToken  string
	patToken      string
	patID         uint
	machineToken  string
	machineCredID uint
	roleGranted   bool
	suspended     bool
	currentPass   string
}

var acIterCounter atomic.Uint64

// resetIteration wipes the victim's mutable per-run state directly via
// storage (matching this repo's existing convention for resetting fuzzed
// principal state between fuzz iterations — see runLinearizabilityIteration's
// own "DELETE FROM user_roles" reset in server/http) instead of unwinding
// every op through its own API, so a fresh iteration always starts from a
// known baseline no matter what the PREVIOUS iteration's program did last.
func (w *acWorld) resetIteration(t *testing.T) *acIterState {
	t.Helper()
	if err := w.db.Where("user_id = ?", w.victimID).Delete(&models.Session{}).Error; err != nil {
		t.Fatalf("reset sessions: %v", err)
	}
	if err := w.db.Where("user_id = ?", w.victimID).Delete(&models.PersonalAccessToken{}).Error; err != nil {
		t.Fatalf("reset PATs: %v", err)
	}
	if err := w.db.Where("machine_identity_id = ?", w.machineIdentityID).Delete(&models.MachineIdentityCredential{}).Error; err != nil {
		t.Fatalf("reset machine credentials: %v", err)
	}
	if err := w.db.Exec("DELETE FROM user_roles WHERE user_id = ?", w.victimID).Error; err != nil {
		t.Fatalf("reset roles: %v", err)
	}
	if err := w.db.Model(&models.User{}).Where("id = ?", w.victimID).
		Updates(map[string]any{
			"password_hash": w.baselinePwHash,
			"is_active":     true,
			"account_state": string(core.AccountActive),
		}).Error; err != nil {
		t.Fatalf("reset user state: %v", err)
	}

	return &acIterState{currentPass: acdInitialPassword}
}

// acNextIP returns a fresh, never-repeated source IP. Each differential check
// gets its OWN ip (not one shared for a whole iteration or the whole run):
// the per-IP invalid-token brute-force budget (tokenAuthFailureBurst) is a
// deliberate product feature (MCP-storm mitigation), not part of the auth-
// cache decision this fuzzer is checking, and a token that is already
// revoked/expired is a genuinely repeated "invalid" slow-path attempt at
// every differential check that touches it for the rest of the iteration —
// sharing one ip across many such checks would eventually cross the burst
// threshold and turn the SECOND (forced-fresh) call of some later check into
// 429 while the first (cache) call of that same check was still 401, purely
// from accumulated call count. That would be harness noise (both denials),
// not a real cache/DB divergence. A fresh ip per check keeps every check's
// own two calls (and only those two) sharing a counter, so the only way they
// can differ is a genuine decision divergence.
func acNextIP() string {
	n := acIterCounter.Add(1)
	return fmt.Sprintf("10.%d.%d.%d", byte(n>>16), byte(n>>8), byte(n))
}

// acRunOp executes one fuzzed op. Every mutation is best-effort (errors are
// ignored, e.g. "revoke a PAT that doesn't exist yet") — the fuzzer explores
// SEQUENCES, and an op that's a no-op in a given state is a legitimate
// sequence, not a harness failure.
func acRunOp(t *testing.T, w *acWorld, st *acIterState, op byte) {
	t.Helper()
	ctx := context.Background()
	switch op % 12 {
	case 0: // login
		sess, _, err := w.c.Login(ctx, &core.LoginRequest{Username: w.victimUser, Password: st.currentPass})
		if err == nil && sess != nil {
			st.sessionToken = sess.SessionToken
		}
	case 1: // create PAT
		res, err := w.c.CreateOwnPAT(ctx, w.victimID, "acd-pat", nil, nil, 0, 0, nil)
		if err == nil && res != nil {
			st.patToken = res.PlainToken
			st.patID = res.Token.ID
		}
	case 2: // issue machine token
		res, err := w.c.IssueMachineToken(ctx, w.projID, w.machineIdentityID, w.adminID, core.IssueMachineTokenParams{Name: "acd-mtoken"})
		if err == nil && res != nil {
			st.machineToken = res.PlainToken
			st.machineCredID = res.Credential.ID
		}
	case 3: // delete/revoke the current session
		if st.sessionToken != "" {
			_ = w.c.Logout(ctx, st.sessionToken)
		}
	case 4: // revoke the current PAT
		if st.patID != 0 {
			_, _ = w.c.RevokeOwnPAT(ctx, w.victimID, st.patID)
		}
	case 5: // revoke the current machine token
		if st.machineCredID != 0 {
			_, _ = w.c.RevokeMachineToken(ctx, w.projID, w.machineIdentityID, st.machineCredID, w.adminID)
		}
	case 6: // suspend / reactivate toggle
		if st.suspended {
			_ = w.c.ReactivateUser(ctx, w.adminID, w.victimID)
		} else {
			_ = w.c.SuspendUser(ctx, w.adminID, w.victimID)
		}
		st.suspended = !st.suspended
	case 7: // role grant / removal toggle ("permission removal")
		if st.roleGranted {
			_ = w.c.RemoveUserRole(ctx, 0, w.victimID, w.roleID, w.scope)
		} else {
			_ = w.c.AssignUserRole(ctx, 0, w.victimID, w.roleID, w.scope, false)
		}
		st.roleGranted = !st.roleGranted
	case 8: // password change
		next := st.currentPass + "x"
		if err := w.c.ChangePassword(ctx, w.victimID, st.currentPass, next, ""); err == nil {
			st.currentPass = next
		}
	case 9: // #1878 shape: backdate the session's REAL expiry after its cache
		// entry may already exist, deterministically (no sleep) — a stale
		// cache would keep authenticating a session whose storage-level
		// ExpiresAt is already in the past.
		if st.sessionToken != "" {
			if sess, err := w.c.Storage().GetSession(ctx, st.sessionToken); err == nil && sess != nil {
				past := time.Now().UTC().Add(-24 * time.Hour) // canonical UTC: see beforeSaveBypassAllowlistG1619
				_ = w.db.Model(&models.Session{}).Where("id = ?", sess.ID).Update("expires_at", past).Error
			}
		}
	case 10: // authenticated request(s): the cache-vs-DB-truth differential
		for _, tok := range []string{st.sessionToken, st.patToken, st.machineToken} {
			if tok != "" {
				acCheckDifferential(t, w, tok)
			}
		}
	case 11: // #1985 shape: a role-lookup storage error must fail closed
		acCheckRoleLookupFault(t, w, st)
	}
}

// acDoRequest issues one authenticated GET with token as a bearer credential
// from remoteAddr, returning the response status.
func acDoRequest(handler http.Handler, token, remoteAddr string) int {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.RemoteAddr = remoteAddr + ":4242"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Code
}

// acForceCacheMiss removes token's entry from the package-level tokenCache
// map directly (white-box: this file is in package middleware) so the NEXT
// request for it is a genuine cache MISS that falls through to the real
// slow-path validators.
//
// Deliberately NOT InvalidateTokenCacheByHash: that function is the product's
// own REVOKE primitive (auth.go's own doc comment: "write a short-lived
// tombstone rather than a plain delete") — it writes a NEGATIVE cache entry
// (userCtx: nil, revokedAt: now) so a revoked token stays denied for
// invalidTokenTTL without a slow-path lookup at all. Using it here to mean
// "bypass the cache" would make every very next request an automatic,
// unconditional 401 straight from that tombstone — never actually reaching
// the validators — which is exactly the bug this harness hit before this
// fix: every "differential" it reported was the harness poisoning its own
// second call, not a real cache/DB divergence. A genuine bypass must leave
// the token with NO cache entry at all, positive or negative.
func acForceCacheMiss(token string) {
	tokenCacheMu.Lock()
	delete(tokenCache, tokenKey(token))
	tokenCacheMu.Unlock()
}

// acCheckDifferential is the core oracle: the same request, same token, must
// get the same status whether or not the auth cache currently holds an entry
// for it. Forcing a cache miss between the two calls sends the second one
// down the real slow path (straight to storage via the real validators) —
// the ground truth. Nothing else about the world changes between the two
// calls, so any difference is the cache disagreeing with the DB, not a
// legitimate state transition.
func acCheckDifferential(t *testing.T, w *acWorld, token string) {
	t.Helper()
	ip := acNextIP()
	cachedStatus := acDoRequest(w.handler, token, ip)
	acForceCacheMiss(token)
	freshStatus := acDoRequest(w.handler, token, ip)
	if cachedStatus != freshStatus {
		t.Fatalf("auth-cache differential: cache-path status=%d, cache-bypassed (DB-truth) status=%d for the same token and request -- the auth cache served a decision storage disagrees with", cachedStatus, freshStatus)
	}
}

// acRoleFaultValidator wraps the real validator but reports
// core.ErrRoleResolutionUnavailable for one specific session token, exactly
// reproducing the #1944/#1985 shape ("the credential checked out but the
// owner's roles could not be read from storage") without needing a live
// storage fault. Every other method — and every other token — passes
// straight through to real.
type acRoleFaultValidator struct {
	real       sessionValidator
	faultToken string
}

func (v acRoleFaultValidator) ValidateSessionToken(ctx context.Context, token string) (*models.User, []string, error) {
	if token == v.faultToken {
		return nil, nil, fmt.Errorf("acd-fault: %w", core.ErrRoleResolutionUnavailable)
	}
	return v.real.ValidateSessionToken(ctx, token)
}

func (v acRoleFaultValidator) ValidatePATToken(ctx context.Context, token string) (*models.User, []string, *core.PATRestriction, uint, error) {
	return v.real.ValidatePATToken(ctx, token)
}

func (v acRoleFaultValidator) ValidateMachineToken(ctx context.Context, token string) (*models.MachineIdentity, []string, *core.MachineTokenRestriction, uint, error) {
	return v.real.ValidateMachineToken(ctx, token)
}

func (v acRoleFaultValidator) ValidateOIDCToken(ctx context.Context, token string) (*models.MachineIdentity, []string, error) {
	return v.real.ValidateOIDCToken(ctx, token)
}

func (v acRoleFaultValidator) OIDCEnabled() bool { return v.real.OIDCEnabled() }

// acCheckRoleLookupFault drives the live session token through
// acRoleFaultValidator and asserts the #1985 invariant directly: a
// role-lookup storage error must be a 503, must never reach the handler, and
// must never be cached (positive OR negative) — a regression to "success
// with an empty role list" (#1944's original bug) would flip every one of
// these.
func acCheckRoleLookupFault(t *testing.T, w *acWorld, st *acIterState) {
	t.Helper()
	if st.sessionToken == "" {
		return
	}
	acForceCacheMiss(st.sessionToken)

	reached := false
	probe := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		reached = true
		rw.WriteHeader(http.StatusOK)
	})
	faulty := authenticationWithValidator(acRoleFaultValidator{real: w.c, faultToken: st.sessionToken}, w.c)(probe)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+st.sessionToken)
	req.RemoteAddr = acNextIP() + ":4242"
	rec := httptest.NewRecorder()
	faulty.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("#1985 regression: a role-resolution storage failure must be a retryable 503, got %d", rec.Code)
	}
	if reached {
		t.Fatalf("#1985 regression: request reached the handler with a half-built (empty-roles) identity")
	}
	if _, found := cacheGet(tokenKey(st.sessionToken)); found {
		t.Fatalf("#1985 regression: a role-resolution failure must not be cached, positive or negative")
	}
}

func FuzzAuthCacheDifferential(f *testing.F) {
	w := acBuildWorld(f)

	// login, authed-request, PAT, authed-request, machine-token, authed-request,
	// revoke-session, authed-request, revoke-pat, authed-request,
	// revoke-machine, authed-request, suspend, authed-request, role-toggle,
	// authed-request, password-change, authed-request, expire-session,
	// authed-request, role-fault-check.
	f.Add([]byte{0, 10, 1, 10, 2, 10, 3, 10, 4, 10, 5, 10, 6, 10, 7, 10, 8, 10, 9, 10, 11})
	f.Add([]byte{})
	f.Add([]byte{0, 10, 9, 10, 3, 10})
	f.Add([]byte{0, 10, 6, 10, 6, 10})
	f.Add([]byte{1, 10, 4, 10})
	f.Add([]byte{2, 10, 5, 10})
	f.Add([]byte{0, 11, 10})

	f.Fuzz(func(t *testing.T, program []byte) {
		if len(program) == 0 {
			return
		}
		st := w.resetIteration(t)
		maxOps := min(len(program), 48)
		for i := range maxOps {
			acRunOp(t, w, st, program[i])
		}
	})
}
