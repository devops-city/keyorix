// cache_hit_fail_closed_test.go — INV-MW-cache-hit-recheck-fails-closed
// (CACHE-FAILCLOSED-1).
//
// On an auth-cache hit, serveAuthCacheHit re-reads the credential's live state
// before serving the cached principal (#G18). When that re-read FAILS (a
// storage error, not a verdict), the request must be refused with 503 +
// Retry-After and no raw error text — never authenticated from the cache, as
// it used to be for up to validTokenTTL (INV-MW-05's former transient half).
//
// The fault is injected with internal/faultstorage on the exact storage method
// each branch's re-check calls, over a real LocalStorage → core path, so the
// error reaches serveAuthCacheHit the way a database outage would. One table
// covers the four cache-hit branches: PAT, opaque machine token, federated
// OIDC machine principal, interactive session.
//
// What this does NOT cover: gRPC (no auth cache; its per-request validation is
// pinned in server/grpc/interceptors/auth_storage_error_fail_closed_test.go),
// a context deadline during the re-read (same code path: serveAuthCacheHit does
// not distinguish error kinds beyond the definitive sentinels), and
// RemoteStorage (never wired into the server, ADR-083).
package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// cfcRawErrorDetail is planted in the injected error so a test can prove the
// response never carries the storage error's text.
const cfcRawErrorDetail = "pq: connection refused to db-internal-7:5432"

// cfcCase is one cache-hit branch: the bearer it authenticates with, the
// storage method its live re-check calls, and how to revoke that credential
// directly in the database (standing in for a revoke on another replica,
// which does not flush this process's cache).
type cfcCase struct {
	name     string
	token    string
	recheck  string
	revokeIn func(t *testing.T, db *gorm.DB)
}

func cfcCases() []cfcCase {
	return []cfcCase{
		{
			name: "pat", token: "kx_pat_validtoken", recheck: "GetPersonalAccessTokenByHash",
			revokeIn: func(t *testing.T, db *gorm.DB) {
				require.NoError(t, db.Model(&models.PersonalAccessToken{}).Where("id = ?", 1).Update("revoked", true).Error)
			},
		},
		{
			name: "machine_token", token: "kx_machine_validtoken", recheck: "GetMachineIdentityCredentialWithIdentityStateByHash",
			revokeIn: func(t *testing.T, db *gorm.DB) {
				require.NoError(t, db.Model(&models.MachineIdentityCredential{}).Where("id = ?", 1).Update("revoked", true).Error)
			},
		},
		{
			name: "oidc_federated_machine", token: "header.valid.sig", recheck: "GetMachineIdentity",
			revokeIn: func(t *testing.T, db *gorm.DB) {
				require.NoError(t, db.Model(&models.MachineIdentity{}).Where("id = ?", 11).Update("state", "suspended").Error)
			},
		},
		{
			name: "session", token: validToken, recheck: "GetSessionAuthLiveness",
			revokeIn: func(t *testing.T, db *gorm.DB) {
				require.NoError(t, db.Where("user_id = ?", 1).Delete(&models.Session{}).Error)
			},
		},
	}
}

// cfcWorld is a real SQLite LocalStorage behind a FaultyStorage, holding a live
// row for every credential fakeValidator accepts in cfcCases, plus the auth
// middleware over a handler that counts how often it was reached.
type cfcWorld struct {
	db      *gorm.DB
	fs      *faultstorage.FaultyStorage
	handler http.Handler
	served  *atomic.Int32
}

func newCFCWorld(t *testing.T, tc cfcCase) *cfcWorld {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	resetTokenCacheG18(tc.token)
	t.Cleanup(func() { resetTokenCacheG18(tc.token) })

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.Session{}, &models.PersonalAccessToken{},
		&models.MachineIdentity{}, &models.MachineIdentityCredential{}))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "admin", Email: "admin@example.com", IsActive: true}).Error)
	require.NoError(t, db.Create(&models.User{ID: 3, Username: "patuser", Email: "pat@example.com", IsActive: true}).Error)
	seedSessionRow(t, db, validToken, 1)
	patSum := sha256.Sum256([]byte("kx_pat_validtoken"))
	require.NoError(t, db.Create(&models.PersonalAccessToken{ID: 1, UserID: 3, Name: "ci", TokenHash: hex.EncodeToString(patSum[:])}).Error)
	require.NoError(t, db.Create(&models.MachineIdentity{ID: 9, Name: "ci-bot", State: "active"}).Error)
	require.NoError(t, db.Create(&models.MachineIdentity{ID: 11, Name: "k8s-sa", State: "active"}).Error)
	machineSum := sha256.Sum256([]byte("kx_machine_validtoken"))
	require.NoError(t, db.Create(&models.MachineIdentityCredential{ID: 1, MachineIdentityID: 9, Name: "ci", TokenHash: hex.EncodeToString(machineSum[:])}).Error)

	fs := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
	served := &atomic.Int32{}
	// No SetMachineTokenCacheFlusher: stands in for a replica other than the
	// one that ran a revocation.
	handler := authenticationWithValidator(fakeValidator{}, core.NewKeyorixCore(fs))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		served.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	return &cfcWorld{db: db, fs: fs, handler: handler, served: served}
}

func (w *cfcWorld) do(token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.RemoteAddr = "127.0.0.1:5555"
	rec := httptest.NewRecorder()
	w.handler.ServeHTTP(rec, req)
	return rec
}

// armRecheckError makes the next call to method fail with an error carrying
// cfcRawErrorDetail.
func (w *cfcWorld) armRecheckError(method string) {
	w.fs.Arm(&faultstorage.FaultSpec{Method: method, NthCall: 1, Kind: faultstorage.KindError, Err: errors.New(cfcRawErrorDetail)})
}

// requireRefusedUnavailable asserts rec is the "temporarily unavailable"
// response class: 503, Retry-After, the fixed message, no storage error text.
func requireRefusedUnavailable(t *testing.T, rec *httptest.ResponseRecorder, msg string) {
	t.Helper()
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, msg)
	require.NotEmpty(t, rec.Header().Get("Retry-After"), "the 503 must carry Retry-After, like the slow path's")
	body := rec.Body.String()
	require.Contains(t, body, "authentication temporarily unavailable")
	require.NotContains(t, body, "connection refused", "the storage error's text must never reach the client")
	require.NotContains(t, body, "db-internal-7")
}

// TestCacheHit_RecheckStorageError_FailsClosed: a credential cached by a
// healthy slow path, then a storage error on the cache-hit re-check. The
// request is refused 503 and never reaches the handler; the entry is kept (the
// credential may be fine) and, once storage recovers, the next request is
// served from the cache again. Red before CACHE-FAILCLOSED-1: every branch
// degraded to the cached principal (200).
func TestCacheHit_RecheckStorageError_FailsClosed(t *testing.T) {
	for _, tc := range cfcCases() {
		t.Run(tc.name, func(t *testing.T) {
			w := newCFCWorld(t, tc)
			require.Equal(t, http.StatusOK, w.do(tc.token).Code, "first request caches via the slow path")
			require.EqualValues(t, 1, w.served.Load())

			w.armRecheckError(tc.recheck)
			rec := w.do(tc.token)
			require.True(t, w.fs.Fired(), "precondition: the fault must fire on the cache-hit re-check (%s)", tc.recheck)
			requireRefusedUnavailable(t, rec, "a failed re-check on a cache hit must refuse the request, not authenticate from the cache")
			require.EqualValues(t, 1, w.served.Load(), "the refused request must never reach the handler")
			requirePositiveCacheEntry(t, tc.token)

			w.fs.Arm(nil)
			require.Equal(t, http.StatusOK, w.do(tc.token).Code, "after storage recovers the cached credential is served again")
			require.EqualValues(t, 2, w.served.Load())
		})
	}
}

// TestCacheHit_RevokedCredentialAndStorageError_NeverAccepted: the credential is
// revoked after it was cached (on another replica: nothing flushes this
// cache), and then every re-check fails. However many requests arrive during
// the outage, none is accepted; the first one after recovery sees the
// revocation, is denied 401 and evicts. Red before CACHE-FAILCLOSED-1: every
// request during the outage was served from the cache.
func TestCacheHit_RevokedCredentialAndStorageError_NeverAccepted(t *testing.T) {
	for _, tc := range cfcCases() {
		t.Run(tc.name, func(t *testing.T) {
			w := newCFCWorld(t, tc)
			require.Equal(t, http.StatusOK, w.do(tc.token).Code, "first request caches via the slow path")
			tc.revokeIn(t, w.db)

			for range 3 {
				w.armRecheckError(tc.recheck)
				rec := w.do(tc.token)
				require.True(t, w.fs.Fired(), "precondition: the fault must fire on the cache-hit re-check (%s)", tc.recheck)
				requireRefusedUnavailable(t, rec, "a revoked credential must never be accepted while its re-check fails")
			}
			require.EqualValues(t, 1, w.served.Load(), "no request after the revocation may reach the handler")

			w.fs.Arm(nil)
			require.Equal(t, http.StatusUnauthorized, w.do(tc.token).Code, "once storage recovers the revocation is seen and denied")
			entry, found := cacheGet(tokenKey(tc.token))
			require.True(t, found)
			require.Nil(t, entry.userCtx, "the definitive deny must evict to a negative entry")
			require.EqualValues(t, 1, w.served.Load())
		})
	}
}

// TestCacheHit_HealthyStorage_OneRecheckRead: with storage healthy a cache hit
// is still served from the cache, with exactly one storage call (the branch's
// own re-check) and no slow-path re-validation: failing closed added no round
// trip. For the OIDC branch the one read changed from the account re-read for
// user id 0 (which never exists, so the hit was always served unchecked) to
// the identity's state — red before CACHE-FAILCLOSED-1 for that row only.
func TestCacheHit_HealthyStorage_OneRecheckRead(t *testing.T) {
	for _, tc := range cfcCases() {
		t.Run(tc.name, func(t *testing.T) {
			w := newCFCWorld(t, tc)
			require.Equal(t, http.StatusOK, w.do(tc.token).Code, "first request caches via the slow path")

			before := len(w.fs.Calls())
			require.Equal(t, http.StatusOK, w.do(tc.token).Code, "a cache hit on healthy storage is served")
			var methods []string
			for _, c := range w.fs.Calls()[before:] {
				methods = append(methods, c.Method)
			}
			require.Equal(t, []string{tc.recheck}, methods, "a cache hit makes exactly its one re-check read")
			require.EqualValues(t, 2, w.served.Load())
		})
	}
}

// TestCacheHit_SessionAccountGone_DeniedNotRefused: the account row behind a
// cached session is gone (hard- or soft-deleted). That is a definitive verdict,
// not a failed read, so it denies 401 and evicts like a revoked credential,
// rather than answering 503 until validTokenTTL runs out. Before
// CACHE-FAILCLOSED-1 a missing account was indistinguishable from a storage
// error and degraded to the cached principal (200).
func TestCacheHit_SessionAccountGone_DeniedNotRefused(t *testing.T) {
	tc := cfcCases()[3]
	require.Equal(t, "session", tc.name)
	w := newCFCWorld(t, tc)
	require.Equal(t, http.StatusOK, w.do(tc.token).Code, "first request caches via the slow path")

	require.NoError(t, w.db.Delete(&models.User{}, 1).Error) // soft delete
	rec := w.do(tc.token)
	require.Equal(t, http.StatusUnauthorized, rec.Code, "a session whose account is gone must be denied on the next cache hit")
	require.False(t, strings.Contains(rec.Body.String(), "temporarily unavailable"))
	entry, found := cacheGet(tokenKey(tc.token))
	require.True(t, found)
	require.Nil(t, entry.userCtx, "the definitive deny must evict to a negative entry")
	require.EqualValues(t, 1, w.served.Load())
}
