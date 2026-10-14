package store

import (
	"context"
	"fmt"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestClampPageSize pins the defense-in-depth ceiling LocalStorage applies to every
// paginated query, independent of whatever clamp (if any) the caller already applied.
func TestClampPageSize(t *testing.T) {
	cases := []struct {
		name string
		in   int
		want int
	}{
		{"typical page size unaffected", 20, 20},
		{"exactly at the ceiling unaffected", maxStoragePageSize, maxStoragePageSize},
		{"one over the ceiling clamped down", maxStoragePageSize + 1, maxStoragePageSize},
		{"wildly oversized clamped down", 1 << 30, maxStoragePageSize},
		{"zero passed through (caller's own default applies)", 0, 0},
		// #G44: a negative size must NEVER reach GORM's Limit() — Limit(-1) (or any
		// negative) removes the LIMIT clause entirely, turning a caller-controlled
		// negative page size into an unbounded query. Clamped to 0, not passed through.
		{"negative clamped to zero, not passed through", -1, 0},
		{"large negative clamped to zero", -1 << 30, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, clampPageSize(tc.in))
		})
	}
}

// TestClampPageSize_NegativeNeverReachesGORMLimit is the #G44 regression: before the
// fix, a negative pageSize passed straight through clampPageSize into GORM's
// Limit(), which treats any negative value as "no limit" — turning a caller-
// controlled negative page size into an unbounded query. This proves the actual
// query result is bounded, not just the clamp helper's return value.
func TestClampPageSize_NegativeNeverReachesGORMLimit(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.Environment{}))
	ls := NewLocalStorage(db)
	ctx := context.Background()

	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "dev"}).Error)
	for i := range 5 {
		require.NoError(t, db.Create(&models.SecretNode{
			ProjectID: 1, EnvironmentID: 1, Name: fmt.Sprintf("secret-%d", i),
			IsSecret: true, Type: "api_key", Status: "active",
		}).Error)
	}

	secrets, _, err := ls.ListSecrets(ctx, &storage.SecretFilter{
		Page: 1, PageSize: -1, // a caller supplying a hostile negative page size
	})
	require.NoError(t, err)
	assert.Empty(t, secrets, "a negative page size must return zero rows, never every row")
}

// TestClampPage pins the ceiling on caller-supplied page numbers to prevent
// deep-pagination DoS via huge OFFSET values (#r124-M).
func TestClampPage(t *testing.T) {
	cases := []struct {
		name string
		in   int
		want int
	}{
		{"page 1 unchanged", 1, 1},
		{"typical mid-page unchanged", 50, 50},
		{"exactly at ceiling unchanged", maxStoragePage, maxStoragePage},
		{"one over ceiling clamped", maxStoragePage + 1, maxStoragePage},
		{"hostile million-page clamped", 1_000_000, maxStoragePage},
		{"page 0 becomes 1", 0, 1},
		{"negative becomes 1", -5, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, clampPage(tc.in))
		})
	}
}

// TestEscapeLIKE verifies that SQL LIKE wildcard metacharacters are neutralised
// by escapeLIKE so user-supplied search terms cannot expand a match unexpectedly
// (#r124-M LIKE injection).
func TestEscapeLIKE(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"plain string untouched", "admin", "admin"},
		{"percent escaped", "admin%", `admin\%`},
		{"underscore escaped", "a_b", `a\_b`},
		{"both wildcards", "%_foo_%", `\%\_foo\_\%`},
		{"backslash first", `a\b`, `a\\b`},
		{"backslash then percent", `a\%b`, `a\\\%b`},
		{"empty string", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, escapeLIKE(tc.input))
		})
	}
}

// TestListSecrets_PageSizeClampedAtStorage confirms a future caller that forgets to
// clamp PageSize itself (bypassing the ≤100 clamp every current HTTP/gRPC handler
// applies before reaching storage) cannot force an unbounded SQL LIMIT — the storage
// layer's own ceiling still applies, and the call succeeds rather than erroring or
// hanging on a hostile/overflowed value.
func TestListSecrets_PageSizeClampedAtStorage(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.Environment{}))
	ls := NewLocalStorage(db)
	ctx := context.Background()

	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "dev"}).Error)
	for i := range 5 {
		require.NoError(t, db.Create(&models.SecretNode{
			ProjectID: 1, EnvironmentID: 1, Name: fmt.Sprintf("secret-%d", i),
			IsSecret: true, Type: "api_key", Status: "active",
		}).Error)
	}

	secrets, total, err := ls.ListSecrets(ctx, &storage.SecretFilter{
		Page: 1, PageSize: 1 << 30, // a caller that forgot to clamp
	})
	require.NoError(t, err)
	assert.Equal(t, int64(5), total)
	assert.Len(t, secrets, 5)
}
