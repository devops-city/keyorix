package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func TestReadinessCheck(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)

	// This test exercises a genuine state transition (DB reachable -> severed)
	// across two calls to the SAME handler instance, so it must defeat
	// readiness.go's short-TTL cache (#G82) between subtests — a fake clock
	// that jumps forward stands in for a real sleep.
	fakeNow := time.Now()
	readinessNow = func() time.Time { return fakeNow }
	t.Cleanup(func() { readinessNow = time.Now })

	h := ReadinessCheck(core.NewKeyorixCore(store.NewLocalStorage(db)))

	t.Run("reports ready when the database is reachable", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		w := httptest.NewRecorder()
		h(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), `"status":"ready"`)
	})

	t.Run("reports 503 not_ready when the database is unreachable", func(t *testing.T) {
		require.NoError(t, sqlDB.Close())            // sever the DB connection → SELECT 1 fails
		fakeNow = fakeNow.Add(2 * readinessCacheTTL) // force the cached "ready" result to expire
		req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		w := httptest.NewRecorder()
		h(w, req)

		require.Equal(t, http.StatusServiceUnavailable, w.Code)
		assert.Contains(t, w.Body.String(), `"status":"not_ready"`)
	})
}

// TestReadinessCheck_CachesWithinTTL is #G82: within the cache window, a flood
// of requests must reuse the last real DB check result instead of hitting the
// database on every single call — bounding the DB round trips an unauthenticated
// flood can force, without ever risking a false "too many requests" rejection
// that would make an orchestrator wrongly conclude a healthy replica is unready.
func TestReadinessCheck_CachesWithinTTL(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)

	fakeNow := time.Now()
	readinessNow = func() time.Time { return fakeNow }
	t.Cleanup(func() { readinessNow = time.Now })

	h := ReadinessCheck(core.NewKeyorixCore(store.NewLocalStorage(db)))

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	h(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// Sever the DB connection, but stay WITHIN the cache TTL — a flood of
	// calls here must still return the cached "ready" result, not a fresh
	// (now-failing) check.
	require.NoError(t, sqlDB.Close())
	for range 10 {
		req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		w := httptest.NewRecorder()
		h(w, req)
		require.Equal(t, http.StatusOK, w.Code, "within the cache window every call must reuse the cached result, not hit the DB")
	}
}
