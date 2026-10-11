// g18_cache_hit_revocation_test.go — #G18 regression tests: serveAuthCacheHit
// generalizes #146's "re-fetch on every cache hit" pattern from just the PAT
// CIDR allowlist to every revocation-relevant field (PAT/machine-token
// Revoked+ExpiresAt, machine-token CIDR, session account state). Each test
// caches a valid identity via the slow path (fakeValidator), mutates the
// underlying row directly to simulate a live revocation, then asserts the
// SAME cached token is denied on the very next request — not after
// validTokenTTL — mirroring TestAuthentication_PATNetworkAllowlist_RefreshesOnCacheHit's
// established pattern for the #146 precedent this group generalizes.
package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// resetTokenCacheG18 clears any cache entry raw may already hold from a prior
// test in this package (tokenCache is a package-level global) — several
// fakeValidator-backed tests across this package share the same fixed raw
// token strings, so a leftover positive/negative entry from another test
// would otherwise short-circuit this test's own slow-path/cache-hit sequence.
func resetTokenCacheG18(raw string) {
	tokenCacheMu.Lock()
	delete(tokenCache, tokenKey(raw))
	tokenCacheMu.Unlock()
}

// seedSessionRow stores the session row a validated session token always has
// (session_token holds the token's SHA-256 hex). fakeValidator accepts the raw
// token without one, but the middleware's slow path re-reads the row for the
// per-session facts and refuses the request when it is missing (#3041 review).
func seedSessionRow(t *testing.T, db *gorm.DB, raw string, userID uint) {
	t.Helper()
	sum := sha256.Sum256([]byte(raw))
	exp := time.Now().Add(time.Hour)
	require.NoError(t, db.Create(&models.Session{UserID: userID, SessionToken: hex.EncodeToString(sum[:]), ExpiresAt: &exp}).Error)
}

func serveG18(handler http.Handler, bearer string) int {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.RemoteAddr = "127.0.0.1:5555"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w.Code
}

// TestAuthentication_PATRevokedAfterCache_DeniedOnCacheHit is #G18 member #5's
// consequence: CurrentPATRestriction used to silently discard Revoked/ExpiresAt,
// so a PAT revoked after it was cached kept authenticating for up to
// validTokenTTL. It must now be denied on the very next request.
func TestAuthentication_PATRevokedAfterCache_DeniedOnCacheHit(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.PersonalAccessToken{}))
	require.NoError(t, db.Create(&models.User{ID: 3, Username: "patuser", Email: "pat@example.com", IsActive: true}).Error)

	const raw = "kx_pat_validtoken"
	resetTokenCacheG18(raw)
	sum := sha256.Sum256([]byte(raw))
	hash := hex.EncodeToString(sum[:])
	pat := &models.PersonalAccessToken{ID: 1, UserID: 3, Name: "ci", TokenHash: hash}
	require.NoError(t, db.Create(pat).Error)

	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	mw := authenticationWithValidator(fakeValidator{}, coreService)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	require.Equal(t, http.StatusOK, serveG18(handler, raw), "first request caches via the slow path")

	require.NoError(t, db.Model(pat).Update("revoked", true).Error)

	require.Equal(t, http.StatusUnauthorized, serveG18(handler, raw),
		"a PAT revoked after caching must be denied on the very next request, not after the cache TTL")
}

// TestAuthentication_PATExpiredAfterCache_DeniedOnCacheHit is the ExpiresAt half
// of the same member #5 fix.
func TestAuthentication_PATExpiredAfterCache_DeniedOnCacheHit(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.PersonalAccessToken{}))
	require.NoError(t, db.Create(&models.User{ID: 3, Username: "patuser", Email: "pat@example.com", IsActive: true}).Error)

	const raw = "kx_pat_validtoken"
	resetTokenCacheG18(raw)
	sum := sha256.Sum256([]byte(raw))
	hash := hex.EncodeToString(sum[:])
	pat := &models.PersonalAccessToken{ID: 1, UserID: 3, Name: "ci", TokenHash: hash}
	require.NoError(t, db.Create(pat).Error)

	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	mw := authenticationWithValidator(fakeValidator{}, coreService)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	require.Equal(t, http.StatusOK, serveG18(handler, raw))

	past := time.Now().Add(-time.Hour)
	require.NoError(t, db.Model(pat).Update("expires_at", past).Error)

	require.Equal(t, http.StatusUnauthorized, serveG18(handler, raw),
		"a PAT that expired after caching must be denied on the very next request")
}

// TestAuthentication_MachineTokenCIDR_RefreshesOnCacheHit is #G18 members #2/#4:
// unlike a PAT, a machine token's network restriction was NEVER refreshed on a
// cache hit — mirrors TestAuthentication_PATNetworkAllowlist_RefreshesOnCacheHit.
func TestAuthentication_MachineTokenCIDR_RefreshesOnCacheHit(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.MachineIdentity{}, &models.MachineIdentityCredential{}))
	require.NoError(t, db.Create(&models.MachineIdentity{ID: 9, Name: "ci-bot", State: "active"}).Error)

	const raw = "kx_machine_validtoken"
	resetTokenCacheG18(raw)
	sum := sha256.Sum256([]byte(raw))
	hash := hex.EncodeToString(sum[:])
	cred := &models.MachineIdentityCredential{ID: 1, MachineIdentityID: 9, Name: "ci", TokenHash: hash, AllowedCIDRs: `["10.0.0.0/8"]`}
	require.NoError(t, db.Create(cred).Error)

	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	mw := authenticationWithValidator(fakeValidator{}, coreService)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	serve := func(remoteAddr string) int {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer "+raw)
		req.RemoteAddr = remoteAddr
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w.Code
	}

	require.Equal(t, http.StatusOK, serve("10.1.2.3:5555"), "in-range source IP is allowed, caches the identity")

	cred.AllowedCIDRs = `["192.0.2.0/24"]`
	require.NoError(t, db.Save(cred).Error)

	require.Equal(t, http.StatusForbidden, serve("10.1.2.3:5555"),
		"a narrowed machine-token allowlist must take effect on the very next request, not after the cache TTL")
	require.Equal(t, http.StatusOK, serve("192.0.2.7:5555"), "the newly-allowed network is honored on a cache hit")
}

// TestAuthentication_MachineTokenRevokedAfterCache_DeniedOnCacheHit is #G18
// members #2/#4's revocation half.
func TestAuthentication_MachineTokenRevokedAfterCache_DeniedOnCacheHit(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.MachineIdentity{}, &models.MachineIdentityCredential{}))
	require.NoError(t, db.Create(&models.MachineIdentity{ID: 9, Name: "ci-bot", State: "active"}).Error)

	const raw = "kx_machine_validtoken"
	resetTokenCacheG18(raw)
	sum := sha256.Sum256([]byte(raw))
	hash := hex.EncodeToString(sum[:])
	cred := &models.MachineIdentityCredential{ID: 1, MachineIdentityID: 9, Name: "ci", TokenHash: hash}
	require.NoError(t, db.Create(cred).Error)

	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	mw := authenticationWithValidator(fakeValidator{}, coreService)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	require.Equal(t, http.StatusOK, serveG18(handler, raw))

	require.NoError(t, db.Model(cred).Update("revoked", true).Error)

	require.Equal(t, http.StatusUnauthorized, serveG18(handler, raw),
		"a machine token revoked after caching must be denied on the very next request")
}

// TestAuthentication_SessionAccountSuspendedAfterCache_DeniedOnCacheHit is #G18
// member #1's concretely-fixable form: a session's owning account being
// deactivated/suspended after caching (not role revocation, which every real
// permission check already re-verifies live via core.Authorize on every
// request regardless of the auth cache — see the group's commit message).
func TestAuthentication_SessionAccountSuspendedAfterCache_DeniedOnCacheHit(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	resetTokenCacheG18(validToken)
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.Session{}))
	user := &models.User{ID: 1, Username: "admin", Email: "admin@example.com", IsActive: true}
	require.NoError(t, db.Create(user).Error)
	seedSessionRow(t, db, validToken, 1)

	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	mw := authenticationWithValidator(fakeValidator{}, coreService)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	require.Equal(t, http.StatusOK, serveG18(handler, validToken), "first request caches via the slow path")

	require.NoError(t, db.Model(user).Update("is_active", false).Error)

	require.Equal(t, http.StatusUnauthorized, serveG18(handler, validToken),
		"a session whose account was deactivated after caching must be denied on the very next request")
}
