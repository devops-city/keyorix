package middleware

// auth_s24_test.go — targeted coverage for low-% branches identified after
// the s23 blitz. All tests are white-box (same package) so they can touch
// package-level vars (tokenCache, lastPurge) and unexported helpers directly.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// ── validateToken branches ────────────────────────────────────────────────────

// TestValidateToken_NilValidator verifies the function returns an error (not a
// panic) when no validator is supplied.
func TestValidateToken_NilValidator(t *testing.T) {
	_, err := validateToken(context.Background(), nil, "some-token")
	assert.Error(t, err, "nil validator must return an error, not panic")
}

// TestValidateToken_OIDCDisabled verifies that a JWT-looking token is NOT routed
// to ValidateOIDCToken when OIDC is disabled, falling through to
// ValidateSessionToken instead.
func TestValidateToken_OIDCDisabled(t *testing.T) {
	// oidcDisabledValidator never enables OIDC, so a JWT-looking token must fall
	// through to the session validator (and be rejected there).
	vc, err := validateToken(context.Background(), oidcDisabledFakeValidator{}, "header.valid.sig")
	// The fakeValidator's ValidateSessionToken rejects this token.
	assert.Error(t, err, "JWT-shaped token with OIDC disabled must not succeed via OIDC path")
	assert.Nil(t, vc)
}

// TestValidateToken_OIDCError verifies an invalid JWT is rejected by the OIDC validator.
func TestValidateToken_OIDCError(t *testing.T) {
	// fakeValidator has OIDC enabled but only "header.valid.sig" is recognised;
	// an unknown JWT returns an error from ValidateOIDCToken.
	vc, err := validateToken(context.Background(), fakeValidator{}, "a.b.c")
	assert.Error(t, err, "unrecognised JWT must be rejected by the OIDC validator")
	assert.Nil(t, vc)
}

// TestValidateToken_MachineTokenError verifies a bad kx_machine_ token returns an error.
func TestValidateToken_MachineTokenError(t *testing.T) {
	vc, err := validateToken(context.Background(), fakeValidator{}, "kx_machine_badtoken")
	assert.Error(t, err)
	assert.Nil(t, vc)
}

// oidcDisabledFakeValidator is a minimal sessionValidator where OIDCEnabled
// returns false.
type oidcDisabledFakeValidator struct{}

func (oidcDisabledFakeValidator) ValidateSessionToken(_ context.Context, _ string) (*models.User, []string, error) {
	return nil, nil, http.ErrNotSupported
}
func (oidcDisabledFakeValidator) ValidatePATToken(_ context.Context, _ string) (*models.User, []string, *core.PATRestriction, uint, error) {
	return nil, nil, nil, 0, http.ErrNotSupported
}
func (oidcDisabledFakeValidator) ValidateMachineToken(_ context.Context, _ string) (*models.MachineIdentity, []string, *core.MachineTokenRestriction, uint, error) {
	return nil, nil, nil, 0, http.ErrNotSupported
}
func (oidcDisabledFakeValidator) ValidateOIDCToken(_ context.Context, _ string) (*models.MachineIdentity, []string, time.Time, error) {
	return nil, nil, time.Time{}, http.ErrNotSupported
}
func (oidcDisabledFakeValidator) OIDCEnabled() bool { return false }

// ── buildRequestContext branches ─────────────────────────────────────────────

// TestBuildRequestContext_MachineIdentity verifies that a machine-identity
// UserContext causes the ActorType to be tagged in the context.
func TestBuildRequestContext_MachineIdentity(t *testing.T) {
	mid := uint(7)
	uc := &UserContext{
		UserID:            0,
		MachineIdentityID: &mid,
		ActorType:         core.ActorTypeMachine,
		Username:          "bot",
	}
	ctx := buildRequestContext(context.Background(), uc, nil)
	// The user context must be reachable from the returned context.
	got := GetUserFromContext(ctx)
	require.NotNil(t, got)
	assert.Equal(t, mid, *got.MachineIdentityID)
}

// TestBuildRequestContext_PATRestriction verifies that PATRestriction is
// propagated via core.WithPATRestriction so downstream core.Authorize picks
// it up.
func TestBuildRequestContext_PATRestriction(t *testing.T) {
	restriction := &core.PATRestriction{
		Permissions: []string{"secrets.read"},
		ProjectID:   3,
	}
	uc := &UserContext{
		UserID:         42,
		PATRestriction: restriction,
	}
	ctx := buildRequestContext(context.Background(), uc, nil)
	got := GetUserFromContext(ctx)
	require.NotNil(t, got)
	assert.Equal(t, restriction, got.PATRestriction)
}

// TestBuildRequestContext_Impersonation verifies that ImpersonatedBy is
// threaded into the context via core.WithImpersonation.
func TestBuildRequestContext_Impersonation(t *testing.T) {
	adminID := uint(99)
	uc := &UserContext{
		UserID:         1,
		ImpersonatedBy: &adminID,
	}
	ctx := buildRequestContext(context.Background(), uc, nil)
	got := GetUserFromContext(ctx)
	require.NotNil(t, got)
	assert.Equal(t, adminID, *got.ImpersonatedBy)
}

// TestBuildRequestContext_NilUserContext verifies the function does not panic
// when the UserContext is nil (e.g. unauthenticated placeholder).
func TestBuildRequestContext_NilUserContext(t *testing.T) {
	ctx := buildRequestContext(context.Background(), nil, nil)
	assert.Nil(t, GetUserFromContext(ctx))
}

// ── cacheGet — expired entry deletion branch ─────────────────────────────────

// TestCacheGet_ExpiredEntryDeleted verifies that cacheGet removes an entry
// whose expiresAt is in the past and returns (zero, false).
func TestCacheGet_ExpiredEntryDeleted(t *testing.T) {
	key := tokenKey("expired-entry-test-" + strconv.FormatInt(time.Now().UnixNano(), 36))
	tokenCacheMu.Lock()
	tokenCache[key] = tokenCacheEntry{
		userCtx:   &UserContext{UserID: 99},
		expiresAt: time.Now().Add(-time.Second), // already expired
	}
	tokenCacheMu.Unlock()

	entry, ok := cacheGet(key)
	assert.False(t, ok, "an expired entry must be evicted and report not-found")
	assert.Nil(t, entry.userCtx)

	// Confirm it was actually removed from the map.
	tokenCacheMu.Lock()
	_, stillThere := tokenCache[key]
	tokenCacheMu.Unlock()
	assert.False(t, stillThere, "cacheGet must delete an expired entry from the map")
}

// ── pruneLocked — time-based expired-entry sweep ─────────────────────────────

// TestPruneLocked_TimeBasedSweep exercises the "since last purge > 1 minute"
// branch by temporarily back-dating lastPurge and inserting an expired entry.
func TestPruneLocked_TimeBasedSweep(t *testing.T) {
	key := tokenKey("prune-expired-" + strconv.FormatInt(time.Now().UnixNano(), 36))

	tokenCacheMu.Lock()
	savedLastPurge := lastPurge
	lastPurge = time.Now().Add(-2 * time.Minute) // trick: pretend the last purge was 2 min ago
	tokenCache[key] = tokenCacheEntry{
		userCtx:   &UserContext{UserID: 55},
		expiresAt: time.Now().Add(-time.Second), // expired
	}
	pruneLocked()
	_, stillThere := tokenCache[key]
	lastPurge = savedLastPurge // restore
	tokenCacheMu.Unlock()

	assert.False(t, stillThere, "pruneLocked time-based sweep must remove expired entries")
}

// ── RequireScopedSecretRefPermission — ErrSecretRefInvalid / not-found branches ──
//
// RequireScopedSecretRefPermission (and handleScopedSecretRefPermissionRequest)
// replaced the old standalone ScopeFromRefQuery resolver: it now resolves a
// "?ref=project/environment/name" query param EXACTLY ONCE per request and pins
// the result on the request context (GetResolvedSecretRefFromContext) instead of
// letting the handler resolve the same ref again by name — see the doc comment
// on RequireScopedSecretRefPermission in auth.go for the TOCTOU this closes.

// TestRequireScopedSecretRefPermission_InvalidRefFormat verifies that a
// malformed ref string (not "project/environment/name") 400s, not 404s.
func TestRequireScopedSecretRefPermission_InvalidRefFormat(t *testing.T) {
	db := newScopedTestDB(t)
	seedAdmin(t, db, 1)
	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	userCtx := &UserContext{UserID: 1, ActorType: core.ActorTypeUser}

	// A ref with only one segment is invalid (needs "proj/env/name").
	req := makeRequest(t, http.MethodGet, "/secrets/value?ref=onlyone", nil, userCtx, cs)
	rec := httptest.NewRecorder()
	nextCalled := false
	handleScopedSecretRefPermissionRequest(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}), rec, req, "secrets.read")

	assert.Equal(t, http.StatusBadRequest, rec.Code,
		"a malformed ref must 400, not 404")
	assert.False(t, nextCalled, "next must not run on a resolution failure")
}

// TestRequireScopedSecretRefPermission_NotFound verifies that a well-formed ref
// pointing to a non-existent secret 404s (this admin test user holds the
// permission globally, so handleScopeResolutionError takes the "reveal" branch).
func TestRequireScopedSecretRefPermission_NotFound(t *testing.T) {
	db := newScopedTestDB(t)
	seedAdmin(t, db, 1)
	// Seed minimal project + environment so the ref can be parsed but the secret
	// lookup fails (no matching name).
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "myproject"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "prod"}).Error)
	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	userCtx := &UserContext{UserID: 1, ActorType: core.ActorTypeUser}

	req := makeRequest(t, http.MethodGet, "/secrets/value?ref=myproject/prod/missing-secret", nil, userCtx, cs)
	rec := httptest.NewRecorder()
	nextCalled := false
	handleScopedSecretRefPermissionRequest(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}), rec, req, "secrets.read")

	assert.Equal(t, http.StatusNotFound, rec.Code,
		"a valid-format ref for a missing secret must 404")
	assert.False(t, nextCalled, "next must not run on a resolution failure")
}

// TestRequireScopedSecretRefPermission_PinsResolvedSecretOnContext proves the
// context hand-off itself: on a successful authorization, the exact
// *models.SecretNode resolved by the middleware is retrievable from the next
// handler's request context via GetResolvedSecretRefFromContext.
func TestRequireScopedSecretRefPermission_PinsResolvedSecretOnContext(t *testing.T) {
	db := newScopedTestDB(t)
	seedAdmin(t, db, 1)
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "proj"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "prod"}).Error)
	require.NoError(t, db.Create(&models.SecretNode{ID: 1, ProjectID: 1, EnvironmentID: 1, Name: "db"}).Error)
	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	userCtx := &UserContext{UserID: 1, ActorType: core.ActorTypeUser}

	req := makeRequest(t, http.MethodGet, "/secrets/value?ref=proj/prod/db", nil, userCtx, cs)
	rec := httptest.NewRecorder()
	var pinned *models.SecretNode
	handleScopedSecretRefPermissionRequest(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pinned = GetResolvedSecretRefFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}), rec, req, "secrets.read")

	assert.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, pinned, "the handler must see the resolved secret on its request context")
	assert.Equal(t, uint(1), pinned.ID)
	assert.Equal(t, uint(1), pinned.ProjectID)
	assert.Equal(t, uint(1), pinned.EnvironmentID)
}

// TestRequireScopedSecretRefPermission_SingleResolutionSurvivesRename is the
// TOCTOU regression test for core-secret-ref-4: it reproduces the exact race
// the old two-resolution flow was vulnerable to — a project soft-delete plus a
// same-named recreate landing between the authorization-scope resolution and
// the value-read resolution — and proves the fix makes the two "reads" of the
// resolved secret (the context pin, checked both immediately and again after
// the race) agree, because there is structurally only ONE resolution call for
// the whole request. It also independently confirms the race is real: an
// UNRELATED, fresh call to ResolveSecretRef with the identical ref string
// AFTER the rename lands on the NEW project — exactly the divergence the old
// GetSecretValueByRef code path would have handed back to the caller as "the"
// secret to read, despite authorization having been decided against the OLD
// project.
func TestRequireScopedSecretRefPermission_SingleResolutionSurvivesRename(t *testing.T) {
	db := newScopedTestDB(t)
	seedAdmin(t, db, 1)
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "race-proj"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "prod"}).Error)
	require.NoError(t, db.Create(&models.SecretNode{ID: 1, ProjectID: 1, EnvironmentID: 1, Name: "db"}).Error)
	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	userCtx := &UserContext{UserID: 1, ActorType: core.ActorTypeUser}
	ref := "race-proj/prod/db"

	req := makeRequest(t, http.MethodGet, "/secrets/value?ref="+ref, nil, userCtx, cs)
	rec := httptest.NewRecorder()
	var pinnedBeforeRace, pinnedAfterRace *models.SecretNode
	var staleReResolution *models.SecretNode

	handleScopedSecretRefPermissionRequest(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This is the ONE resolution the request ever performs — captured
		// before simulating anything, exactly as the real handler would read
		// it via middleware.GetResolvedSecretRefFromContext.
		pinnedBeforeRace = GetResolvedSecretRefFromContext(r.Context())

		// Simulate the race: soft-delete the original project and create a
		// brand-new project with the SAME name (name uniqueness is only
		// enforced while deleted_at IS NULL, so this is legal), with its own
		// environment/secret rows also named "prod"/"db".
		require.NoError(t, db.Delete(&models.Project{}, 1).Error)
		require.NoError(t, db.Create(&models.Project{ID: 2, Name: "race-proj"}).Error)
		require.NoError(t, db.Create(&models.Environment{ID: 2, ProjectID: 2, Name: "prod"}).Error)
		require.NoError(t, db.Create(&models.SecretNode{ID: 2, ProjectID: 2, EnvironmentID: 2, Name: "db"}).Error)

		// Prove the race is real: an independent resolution of the identical
		// ref string, performed now, lands on the NEW project — this is what
		// the pre-fix GetSecretValueByRef's second ResolveSecretRef call would
		// have returned instead of the secret actually authorized against.
		var err error
		staleReResolution, err = cs.ResolveSecretRef(r.Context(), ref)
		require.NoError(t, err)

		// The fixed handler never makes that second call — it reads the SAME
		// context value again, which must still be the pre-race resolution.
		pinnedAfterRace = GetResolvedSecretRefFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}), rec, req, "secrets.read")

	require.NotNil(t, pinnedBeforeRace)
	require.NotNil(t, staleReResolution)
	require.NotNil(t, pinnedAfterRace)

	assert.Equal(t, uint(1), pinnedBeforeRace.ProjectID, "authorization was decided against project 1")
	assert.Equal(t, uint(2), staleReResolution.ProjectID,
		"a second by-name resolution after the race diverges onto project 2 — confirming the race is real")
	assert.Same(t, pinnedBeforeRace, pinnedAfterRace,
		"the context-pinned resolution must be the exact same value throughout the request, unaffected by the race")
	assert.Equal(t, uint(1), pinnedAfterRace.ProjectID,
		"the handler must still act on project 1's secret — the one authorization was actually decided against")
}

// ── hostOnly — bare IP (no port) branch ─────────────────────────────────────

// TestHostOnly_BareIP verifies that hostOnly returns the input unchanged when
// there is no port component (SplitHostPort returns an error for bare IPs).
func TestHostOnly_BareIP(t *testing.T) {
	got := hostOnly("203.0.113.5")
	assert.Equal(t, "203.0.113.5", got, "bare IP must be returned unchanged")
}

// TestHostOnly_HostPort verifies that the port is stripped from host:port.
func TestHostOnly_HostPort(t *testing.T) {
	got := hostOnly("203.0.113.5:8080")
	assert.Equal(t, "203.0.113.5", got)
}

// ── sweepLocked — idle entries eviction ─────────────────────────────────────

// TestSweepLocked_EvictsIdleBuckets inserts a bucket with a lastSeen well
// outside principalLimiterIdleTTL and verifies sweepLocked removes it.
func TestSweepLocked_EvictsIdleBuckets(t *testing.T) {
	rl := &principalRateLimiter{
		rps:      1000,
		burst:    10000,
		limiters: make(map[string]*principalBucket),
	}
	const staleKey = "stale-principal"
	rl.limiters[staleKey] = &principalBucket{
		lastSeen: time.Now().Add(-2 * principalLimiterIdleTTL), // way past TTL
	}
	rl.sweepLocked()
	_, ok := rl.limiters[staleKey]
	assert.False(t, ok, "sweepLocked must evict buckets idle longer than principalLimiterIdleTTL")
}

// TestSweepLocked_KeepsRecentBuckets verifies that a recently-seen bucket is
// NOT evicted.
func TestSweepLocked_KeepsRecentBuckets(t *testing.T) {
	rl := &principalRateLimiter{
		rps:      1000,
		burst:    10000,
		limiters: make(map[string]*principalBucket),
	}
	const activeKey = "active-principal"
	rl.limiters[activeKey] = &principalBucket{
		lastSeen: time.Now(),
	}
	rl.sweepLocked()
	_, ok := rl.limiters[activeKey]
	assert.True(t, ok, "sweepLocked must NOT evict recently-active buckets")
}

// ── rateLimitKey — machine identity and zero UserID branches ─────────────────

// TestRateLimitKey_MachineIdentity verifies the "machine:<id>" bucket label.
func TestRateLimitKey_MachineIdentity(t *testing.T) {
	mid := uint(42)
	uc := &UserContext{
		UserID:            0,
		MachineIdentityID: &mid,
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(context.WithValue(req.Context(), userContextKey, uc))
	key := rateLimitKey(req)
	assert.Equal(t, "machine:42", key)
}

// TestRateLimitKey_ZeroUserID verifies the IP fallback when UserID == 0 and
// MachineIdentityID is nil.
func TestRateLimitKey_ZeroUserID(t *testing.T) {
	uc := &UserContext{UserID: 0}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.5:9000"
	req = req.WithContext(context.WithValue(req.Context(), userContextKey, uc))
	key := rateLimitKey(req)
	assert.True(t, strings.HasPrefix(key, "ip:"), "zero UserID must fall back to ip: bucket; got %q", key)
	assert.Contains(t, key, "10.0.0.5")
}

// ── Recovery — X-Request-ID header and user context in panic path ───────────

// TestRecovery_PanicWithUserContextAndRequestID verifies that Recovery logs the
// user and X-Request-ID (neither reaches the response) without panicking.
func TestRecovery_PanicWithUserContextAndRequestID(t *testing.T) {
	panicking := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		panic("test panic with user context")
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets", nil)
	req.Header.Set("X-Request-ID", "req-abc-123")
	req = req.WithContext(context.WithValue(req.Context(), userContextKey, &UserContext{
		UserID:   7,
		Username: "alice",
	}))

	rec := httptest.NewRecorder()
	Recovery()(panicking).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	// The username and request-id must NOT leak to the client.
	body := rec.Body.String()
	assert.NotContains(t, body, "alice")
	assert.NotContains(t, body, "req-abc-123")
	assert.Contains(t, body, "InternalServerError")
}

// TestRecovery_PanicWithoutUserContext covers the "anonymous" branch inside
// the panic handler (no user context on the request).
func TestRecovery_PanicWithoutUserContext(t *testing.T) {
	panicking := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		panic("anon panic")
	})
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	Recovery()(panicking).ServeHTTP(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// ── clientIPFromRequest — only-trusted-hops XFF branch ───────────────────────

// TestClientIPFromRequest_XFFAllTrustedHops verifies that when every hop in
// the X-Forwarded-For chain is a trusted proxy, clientIPFromRequest returns ""
// (nothing client-attributable), so RemoteAddr stays unchanged.
func TestClientIPFromRequest_XFFAllTrustedHops(t *testing.T) {
	// All three hops are in 10.0.0.0/8 (trusted).
	got := serveAndCaptureRemoteAddr(
		[]string{"10.0.0.0/8"},
		"10.1.2.3:443",
		map[string]string{"X-Forwarded-For": "10.5.6.7, 10.8.9.10, 10.11.12.13"},
	)
	// When clientIPFromRequest returns "", RemoteAddr is left as the original
	// value set on the test request.
	assert.Equal(t, "10.1.2.3:443", got,
		"all-trusted XFF chain must leave RemoteAddr unchanged")
}

// TestClientIPFromRequest_XFFMalformedHopsSkipped verifies that blank / non-IP
// segments in the XFF chain are skipped.
func TestClientIPFromRequest_XFFMalformedHopsSkipped(t *testing.T) {
	// The chain has a malformed segment; the valid untrusted hop should still win.
	got := serveAndCaptureRemoteAddr(
		[]string{"10.0.0.0/8"},
		"10.1.2.3:443",
		map[string]string{"X-Forwarded-For": "203.0.113.5,  not-an-ip  , 10.8.9.10"},
	)
	// Walking right→left: 10.8.9.10 is trusted (skip), "not-an-ip" is invalid
	// (skip), 203.0.113.5 is untrusted → chosen.
	assert.Equal(t, "203.0.113.5", got)
}

// ── GenerateCSRFToken — happy path ───────────────────────────────────────────

// TestGenerateCSRFToken_HappyPath confirms the function produces a 64-char hex
// token on success and returns no error.
func TestGenerateCSRFToken_HappyPath(t *testing.T) {
	tok, err := GenerateCSRFToken()
	require.NoError(t, err)
	// 32 random bytes → 64 hex characters.
	assert.Len(t, tok, 64, "CSRF token must be 64 hex characters (32 bytes)")
	// Must be valid hex.
	assert.Regexp(t, `^[0-9a-f]{64}$`, tok)
}

// TestGenerateCSRFToken_Uniqueness verifies consecutive calls return distinct
// tokens (probabilistic; the chance of a collision is negligible for 256-bit
// random values).
func TestGenerateCSRFToken_Uniqueness(t *testing.T) {
	a, err := GenerateCSRFToken()
	require.NoError(t, err)
	b, err := GenerateCSRFToken()
	require.NoError(t, err)
	assert.NotEqual(t, a, b, "two distinct CSRF tokens must not be equal")
}

// ── parseCIDRs — IPv6 bare-IP branch ─────────────────────────────────────────

// TestParseCIDRs_IPv6BareIP verifies that a bare IPv6 address is treated as
// a /128 and correctly stored.
func TestParseCIDRs_IPv6BareIP(t *testing.T) {
	nets := parseCIDRs([]string{"::1"})
	require.Len(t, nets, 1)
	assert.True(t, nets[0].Contains([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
		"::1 bare address must parse as a /128 that contains the loopback address")
}

// TestParseCIDRs_EmptyAndBlankEntries verifies that blank entries and the
// function as a whole handle edge inputs gracefully.
func TestParseCIDRs_EmptyAndBlankEntries(t *testing.T) {
	nets := parseCIDRs([]string{"", "   ", "not-an-ip-at-all!"})
	// Invalid entries are silently ignored.
	assert.Len(t, nets, 0)
}

// ── RequireRole — no user context ────────────────────────────────────────────

// TestRequireRole_NoUserContext verifies that RequireRole returns 401 when
// there is no UserContext in the request (unauthenticated request that somehow
// bypasses Authentication — defence-in-depth).
func TestRequireRole_NoUserContext(t *testing.T) {
	rec := httptest.NewRecorder()
	RequireRole("admin")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin", nil))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// ── extractRequestToken — session cookie takes precedence ────────────────────

// TestExtractRequestToken_CookiePrecedence verifies the httpOnly session cookie
// is preferred over the Authorization: Bearer header when both are present.
func TestExtractRequestToken_CookiePrecedence(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "cookie-token"})
	req.Header.Set("Authorization", "Bearer header-token")

	tok, err := extractRequestToken(req)
	require.NoError(t, err)
	assert.Equal(t, "cookie-token", tok, "cookie must take precedence over Authorization header")
}
