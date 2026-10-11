// cache_hit_transient_degrade_test.go — INV-MW-05's transient half (#2518).
//
// serveAuthCacheHit re-reads every revocation-relevant field on each cache hit
// (#G18). A DEFINITIVE revocation signal denies and evicts —
// g18_cache_hit_revocation_test.go covers that half. An INDETERMINATE one (the
// re-read itself failed: a storage error, not a verdict on the credential) must
// degrade to the cached snapshot: the request proceeds with the stale cached
// principal, it is neither failed closed (401/500) nor failed open (the stale
// snapshot's own restrictions still apply), and the entry is not evicted.
//
// auth_transient_error_test.go covers only the SLOW path's transient handling
// (a cache MISS whose validateToken fails transiently → 503, no negative
// cache). None of its tests ever reach serveAuthCacheHit.
//
// The storage error is produced by dropping the table the cache-hit re-read
// queries after the entry is cached — a real error out of the real
// LocalStorage → core path, not a mock. What this does NOT cover: a context
// deadline during the re-read (same code path — serveAuthCacheHit does not
// distinguish error kinds beyond the revocation sentinels — so not separately
// exercised), and RemoteStorage (never wired into the server, ADR-083).
package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func serveFrom(handler http.Handler, bearer, remoteAddr string) int {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.RemoteAddr = remoteAddr
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w.Code
}

// requirePositiveCacheEntry asserts raw still holds a positive (non-tombstone)
// cache entry — i.e. the transient error did not evict it.
func requirePositiveCacheEntry(t *testing.T, raw string) {
	t.Helper()
	entry, found := cacheGet(tokenKey(raw))
	require.True(t, found, "a transient re-read error must not evict the cache entry")
	require.NotNil(t, entry.userCtx, "a transient re-read error must not replace the entry with a negative tombstone")
}

// TestCacheHit_PATTransientStorageError_DegradesToStaleSnapshot: the PAT
// table becomes unreadable after the entry is cached. CurrentPATRestriction
// fails with a non-sentinel error, so the request proceeds on the cached
// principal — and the CACHED CIDR restriction (10.0.0.0/8, from the slow path)
// still applies, proving this is degrade-to-stale, not fail-open.
func TestCacheHit_PATTransientStorageError_DegradesToStaleSnapshot(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.PersonalAccessToken{}))
	require.NoError(t, db.Create(&models.User{ID: 3, Username: "patuser", Email: "pat@example.com", IsActive: true}).Error)

	const raw = "kx_pat_cidrtoken"
	resetTokenCacheG18(raw)
	t.Cleanup(func() { resetTokenCacheG18(raw) })
	sum := sha256.Sum256([]byte(raw))
	require.NoError(t, db.Create(&models.PersonalAccessToken{ID: 1, UserID: 3, Name: "ci", TokenHash: hex.EncodeToString(sum[:]), AllowedCIDRs: `["10.0.0.0/8"]`}).Error)

	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	handler := authenticationWithValidator(fakeValidator{}, coreService)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	require.Equal(t, http.StatusOK, serveFrom(handler, raw, "10.1.2.3:5555"), "first request caches via the slow path")

	require.NoError(t, db.Migrator().DropTable(&models.PersonalAccessToken{}))
	_, reErr := coreService.CurrentPATRestriction(t.Context(), raw)
	require.Error(t, reErr, "precondition: the cache-hit re-read must actually fail")
	require.NotErrorIs(t, reErr, core.ErrPATRevoked)
	require.NotErrorIs(t, reErr, core.ErrPATExpired)

	require.Equal(t, http.StatusOK, serveFrom(handler, raw, "10.1.2.3:5555"),
		"a transient storage error on a cache hit must degrade to the cached principal, not 401/500")
	require.Equal(t, http.StatusForbidden, serveFrom(handler, raw, "203.0.113.9:5555"),
		"degrading to the stale snapshot must still enforce the snapshot's own network restriction (not fail open)")
	requirePositiveCacheEntry(t, raw)
}

// TestCacheHit_MachineTokenTransientStorageError_DegradesToStaleSnapshot is the
// machine-token branch (CurrentMachineTokenRestriction).
func TestCacheHit_MachineTokenTransientStorageError_DegradesToStaleSnapshot(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.MachineIdentity{}, &models.MachineIdentityCredential{}))
	require.NoError(t, db.Create(&models.MachineIdentity{ID: 9, Name: "ci-bot", State: "active"}).Error)

	const raw = "kx_machine_validtoken"
	resetTokenCacheG18(raw)
	t.Cleanup(func() { resetTokenCacheG18(raw) })
	sum := sha256.Sum256([]byte(raw))
	require.NoError(t, db.Create(&models.MachineIdentityCredential{ID: 1, MachineIdentityID: 9, Name: "ci", TokenHash: hex.EncodeToString(sum[:])}).Error)

	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	handler := authenticationWithValidator(fakeValidator{}, coreService)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	require.Equal(t, http.StatusOK, serveG18(handler, raw), "first request caches via the slow path")

	require.NoError(t, db.Migrator().DropTable(&models.MachineIdentityCredential{}))
	_, reErr := coreService.CurrentMachineTokenRestriction(t.Context(), raw)
	require.Error(t, reErr, "precondition: the cache-hit re-read must actually fail")
	require.NotErrorIs(t, reErr, core.ErrMachineTokenRevoked)
	require.NotErrorIs(t, reErr, core.ErrMachineTokenExpired)

	require.Equal(t, http.StatusOK, serveG18(handler, raw),
		"a transient storage error on a machine-token cache hit must degrade to the cached principal, not 401/500")
	requirePositiveCacheEntry(t, raw)
}

// TestCacheHit_SessionTransientStorageError_DegradesToStaleSnapshot is the
// interactive-session branch (AccountUsabilityAndState).
func TestCacheHit_SessionTransientStorageError_DegradesToStaleSnapshot(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	resetTokenCacheG18(validToken)
	t.Cleanup(func() { resetTokenCacheG18(validToken) })
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.Session{}))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "admin", Email: "admin@example.com", IsActive: true}).Error)
	seedSessionRow(t, db, validToken, 1)

	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	handler := authenticationWithValidator(fakeValidator{}, coreService)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	require.Equal(t, http.StatusOK, serveG18(handler, validToken), "first request caches via the slow path")

	require.NoError(t, db.Migrator().DropTable(&models.User{}))
	_, _, reErr := coreService.AccountUsabilityAndState(t.Context(), 1)
	require.Error(t, reErr, "precondition: the cache-hit re-read must actually fail")

	require.Equal(t, http.StatusOK, serveG18(handler, validToken),
		"a transient storage error on a session cache hit must degrade to the cached principal, not 401/500")
	requirePositiveCacheEntry(t, validToken)
}

// TestCacheHit_MachineIdentityInactive_IsDefinitiveNotTransient pins the
// boundary between the two halves of INV-MW-05: CurrentMachineTokenRestriction's
// doc comment says a no-longer-active machine identity is one of three signals
// the caller "must treat as deny the request, not a transient lookup failure to
// degrade past" — but it used to be returned as a plain fmt.Errorf, and
// serveAuthCacheHit only denied on the two revoked/expired sentinels, so it fell
// into the degrade-to-stale branch. On the replica that ran the suspension the
// token cache is flushed (SetMachineTokenCacheFlusher), so the stale accept was
// visible on every OTHER replica (and wherever the flusher is not wired) for up
// to validTokenTTL.
//
// Closed 2026-10-05 (#2518): core.ErrMachineIdentityNotActive is now a typed
// sentinel and this branch denies on it, so the doc comment's claim is checkable
// rather than asserted. This test was previously t.Skip'ed with that gap as its
// reason; the skip is removed in the same change that closes it.
func TestCacheHit_MachineIdentityInactive_IsDefinitiveNotTransient(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.MachineIdentity{}, &models.MachineIdentityCredential{}))
	mi := &models.MachineIdentity{ID: 9, Name: "ci-bot", State: "active"}
	require.NoError(t, db.Create(mi).Error)

	const raw = "kx_machine_validtoken"
	resetTokenCacheG18(raw)
	t.Cleanup(func() { resetTokenCacheG18(raw) })
	sum := sha256.Sum256([]byte(raw))
	require.NoError(t, db.Create(&models.MachineIdentityCredential{ID: 1, MachineIdentityID: 9, Name: "ci", TokenHash: hex.EncodeToString(sum[:])}).Error)

	// No SetMachineTokenCacheFlusher: stands in for a replica other than the
	// one that ran the suspension.
	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	handler := authenticationWithValidator(fakeValidator{}, coreService)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	require.Equal(t, http.StatusOK, serveG18(handler, raw), "first request caches via the slow path")

	require.NoError(t, db.Model(mi).Update("state", "suspended").Error)

	require.Equal(t, http.StatusUnauthorized, serveG18(handler, raw),
		"a machine identity suspended after caching must be denied on the very next request, like a revoked credential")
}
