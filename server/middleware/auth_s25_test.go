package middleware

// auth_s25_test.go — targeted coverage for the low-% branches left after the
// s23/s24 blitzes (see g80 coverage sweep). All tests are white-box (same
// package) so they can touch unexported helpers and package-level vars
// directly.

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// ── handleAuthRequest — 429 too-many-requests branch ─────────────────────────

// TestHandleAuthRequest_TooManyInvalidAttempts_Returns429 drives the full
// Authentication middleware past tokenAuthFailureBurst invalid-token attempts
// from a single source IP and proves the NEXT attempt is rejected with 429
// (tooManyRequestsResponse), rather than the ordinary 401 — the PAT-003
// brute-force backstop, exercised end to end rather than just at the
// recordTokenAuthFailure unit level.
func TestHandleAuthRequest_TooManyInvalidAttempts_Returns429(t *testing.T) {
	const remoteAddr = "203.0.113.30:5555"

	handler := newTestAuthMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	doRequest := func(token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req.RemoteAddr = remoteAddr
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr
	}

	// Burn through the failure budget with distinct invalid tokens (a repeated
	// token would hit the negative cache instead of re-entering the slow path).
	for i := range tokenAuthFailureBurst {
		rr := doRequest("s25-burst-token-" + string(rune('a'+i)))
		require.Equal(t, http.StatusUnauthorized, rr.Code, "attempt %d should still be an ordinary 401", i)
	}

	// The next distinct invalid token exhausts the budget and must 429.
	rr := doRequest("s25-burst-token-final")
	assert.Equal(t, http.StatusTooManyRequests, rr.Code,
		"the attempt beyond tokenAuthFailureBurst must be rate-limited, not just rejected as invalid")
	assert.Equal(t, "60", rr.Header().Get("Retry-After"))
	assert.Contains(t, rr.Body.String(), "too many invalid token attempts")
}

// ── serveAuthCacheHit — negative-cache fast path ──────────────────────────────

// TestHandleAuthRequest_NegativeCacheHit_Returns401 pre-populates the token
// cache with a negative (known-bad) entry and proves a subsequent request with
// that exact token is rejected via the fast cache-hit path (serveAuthCacheHit's
// entry.userCtx == nil branch) without ever reaching the validator.
func TestHandleAuthRequest_NegativeCacheHit_Returns401(t *testing.T) {
	token := "s25-negative-cache-token"
	key := tokenKey(token)
	cacheSet(key, tokenCacheEntry{userCtx: nil, expiresAt: time.Now().Add(time.Minute)})

	handler := newTestAuthMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("next handler must not run for a negatively-cached token")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid or expired token")
}

// ── RequireScopedSecretRefPermission — middleware constructor ────────────────

// TestRequireScopedSecretRefPermission_WrapsHandler covers the middleware
// constructor itself (RequireScopedSecretRefPermission), proving it builds a
// working http.Handler chain that delegates to
// handleScopedSecretRefPermissionRequest, mirroring
// TestRequireScopedSecretPermission_WrapsHandler for the by-id sibling.
func TestRequireScopedSecretRefPermission_WrapsHandler(t *testing.T) {
	db := newScopedTestDB(t)
	seedAdmin(t, db, 1)
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "proj"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "prod"}).Error)
	require.NoError(t, db.Create(&models.SecretNode{ID: 1, ProjectID: 1, EnvironmentID: 1, Name: "db"}).Error)
	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	userCtx := &UserContext{UserID: 1, ActorType: core.ActorTypeUser}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := RequireScopedSecretRefPermission("secrets.read")(next)
	req := makeRequest(t, http.MethodGet, "/secrets/value?ref=proj/prod/db", nil, userCtx, cs)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.True(t, nextCalled, "next handler must be called for an authorized admin")
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ── handleScopedSecretRefPermissionRequest — requireUserAndCore gate ─────────

// TestHandleScopedSecretRefPermission_NoUserContext covers the requireUserAndCore
// "no user in context" branch as reached through the by-ref handler (mirrors
// TestHandleScopedSecretPermission_NoUserContext for the by-id sibling).
func TestHandleScopedSecretRefPermission_NoUserContext(t *testing.T) {
	req := makeRequest(t, http.MethodGet, "/secrets/value?ref=proj/prod/db", nil, nil, nil)
	rec := httptest.NewRecorder()
	nextCalled := false
	handleScopedSecretRefPermissionRequest(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
	}), rec, req, "secrets.read")

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.False(t, nextCalled)
}

// ── ScopeFromRoleAssignmentBody — body-read error branch ─────────────────────

// errorReadCloser is an io.ReadCloser whose Read always fails, simulating a
// body-read error (e.g. a client disconnecting mid-upload).
type errorReadCloser struct{}

func (errorReadCloser) Read([]byte) (int, error) { return 0, errors.New("simulated body read error") }
func (errorReadCloser) Close() error             { return nil }

// TestScopeFromRoleAssignmentBody_BodyReadError verifies that a request body
// that fails to read is surfaced as errInvalidTarget rather than panicking or
// being silently swallowed.
func TestScopeFromRoleAssignmentBody_BodyReadError(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/user-roles", nil)
	req.Body = errorReadCloser{}

	_, err := ScopeFromRoleAssignmentBody(req, nil)
	assert.ErrorIs(t, err, errInvalidTarget)
}

// ── oidcDiagnosticFields — malformed (non-dotted) token branch ───────────────

// TestOidcDiagnosticFields_TooFewSegments verifies that a token with fewer
// than 2 dot-separated segments yields empty issuer/kid rather than an
// out-of-range slice access.
func TestOidcDiagnosticFields_TooFewSegments(t *testing.T) {
	issuer, kid := oidcDiagnosticFields("not-a-jwt-at-all")
	assert.Empty(t, issuer)
	assert.Empty(t, kid)
}

// ── validateToken — OIDC success branch ───────────────────────────────────────

// TestValidateToken_OIDCSuccess verifies the success return path of the OIDC
// branch: a validator with OIDC enabled that resolves a JWT-shaped token to a
// machine identity produces the machine UserContext.
func TestValidateToken_OIDCSuccess(t *testing.T) {
	uc, err := validateToken(context.Background(), fakeValidator{}, "header.valid.sig")
	require.NoError(t, err)
	require.NotNil(t, uc)
	assert.Equal(t, core.ActorTypeMachine, uc.ActorType)
	assert.NotNil(t, uc.MachineIdentityID)
	assert.Equal(t, uint(11), *uc.MachineIdentityID)
}

// ── ProjectsMFABlocked — duplicate project ID de-dup branch ──────────────────

// TestProjectsMFABlocked_DuplicateIDsDeduped verifies that a duplicate project
// ID in the input slice is skipped on its second occurrence (the `seen[id]`
// branch) rather than being re-checked, while the aggregate result is still
// correct.
func TestProjectsMFABlocked_DuplicateIDsDeduped(t *testing.T) {
	cs := newProjectMFACore(t)
	sessionNoMFA := &UserContext{UserID: 1, ActorType: core.ActorTypeUser, SessionAuth: true, MFAEnabled: false}

	// Project 2 (no MFA requirement) repeated, plus project 0 (must be skipped
	// outright) mixed in — exercises both the `id == 0` and `seen[id]` arms of
	// the same `continue` condition.
	assert.False(t, ProjectsMFABlocked(reqWithUser(sessionNoMFA), cs, []uint{2, 2, 0, 2}),
		"repeated/zero IDs must be deduped, not cause a spurious block")

	// Same duplication pattern but with an MFA-required project included once —
	// still must block.
	assert.True(t, ProjectsMFABlocked(reqWithUser(sessionNoMFA), cs, []uint{1, 1, 2}),
		"a duplicated MFA-required project ID must still block")
}

var _ io.ReadCloser = errorReadCloser{}
