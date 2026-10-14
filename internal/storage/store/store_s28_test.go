// store_s28_test.go — s28 coverage blitz for internal/storage/store.
//
// Targets (error-path coverage for local_secrets.go):
//
//	local_secrets.go
//	  CreateProject          — DB error (non-duplicate)
//	  GetProject             — not-found + DB error
//	  UpdateProjectFields    — DB error
//	  GetSecretsByIDs        — DB error
//	  GetSecretByName        — DB error
//	  UpdateSecret           — DB error
//	  DeleteSecret           — share-delete DB error path
//	  GetSecretIncludingDeleted — not-found
//	  RequireLiveProject     — DB error
//	  RequireLiveEnvironment — DB error
//	  ListLiveSecretNamesByProject — DB error
//	  GetSecretTags          — DB error
//	  SetSecretTags          — DB error
//	  CreateSecretVersion    — DB error
//	  GetSecretVersions      — DB error
//	  GetLatestSecretVersion — DB error + not-found
//	  TryIncrementSecretReadCount — DB error
//	  TryIncrementSecretNodeReadCount — DB error
//
// Originally also covered remote_rbac.go/remote_machine_identities.go/
// remote_secrets.go error-path coverage; that RemoteStorage portion was
// deleted along with RemoteStorage itself in ADR-108 Phase 6 step 14b-2.
package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// newS28Store opens a unique in-memory SQLite DB with the requested models auto-migrated.
func newS28Store(t *testing.T, mods ...any) *store.LocalStorage {
	t.Helper()
	db := sqlitetest.OpenWithDialector(t, "stores28_", sqlite.Open, &gorm.Config{})
	if len(mods) > 0 {
		require.NoError(t, db.AutoMigrate(mods...))
	}
	return store.NewLocalStorage(db)
}

// brokenS28Store returns a LocalStorage whose underlying DB is already closed.
func brokenS28Store(t *testing.T) *store.LocalStorage {
	t.Helper()
	db := sqlitetest.OpenWithDialector(t, "stores28_", sqlite.Open, &gorm.Config{})
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())
	return store.NewLocalStorage(db)
}

// ---------------------------------------------------------------------------
// local_secrets.go — error branches
// ---------------------------------------------------------------------------

// secretModels lists the models required for local_secrets tests.
var secretModels = []any{
	&models.Project{},
	&models.Environment{},
	&models.SecretNode{},
	&models.ShareRecord{},
	&models.SecretTag{},
	&models.SecretVersion{},
}

func TestLocalStorage_S28_CreateProject_DBError(t *testing.T) {
	ls := brokenS28Store(t)
	_, err := ls.CreateProject(context.Background(), &models.Project{Name: "p"})
	require.Error(t, err)
}

func TestLocalStorage_S28_GetProject_NotFound(t *testing.T) {
	ls := newS28Store(t, &models.Project{})
	_, err := ls.GetProject(context.Background(), 999)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestLocalStorage_S28_GetProject_DBError(t *testing.T) {
	ls := brokenS28Store(t)
	_, err := ls.GetProject(context.Background(), 1)
	require.Error(t, err)
}

func TestLocalStorage_S28_UpdateProjectFields_DBError(t *testing.T) {
	ls := brokenS28Store(t)
	// A storage error must surface as an error, never be collapsed into a clean
	// matched=false (#2697 — a no-match means "the project is gone", which a
	// caller is entitled to report as not-found; a broken DB is not that).
	matched, err := ls.UpdateProjectFields(context.Background(), 1, "x", "", nil, time.Now())
	require.Error(t, err)
	require.False(t, matched)
}

func TestLocalStorage_S28_GetSecretsByIDs_DBError(t *testing.T) {
	ls := brokenS28Store(t)
	_, err := ls.GetSecretsByIDs(context.Background(), []uint{1, 2})
	require.Error(t, err)
}

func TestLocalStorage_S28_GetSecretByName_DBError(t *testing.T) {
	ls := brokenS28Store(t)
	_, err := ls.GetSecretByName(context.Background(), "s", 1, 1)
	require.Error(t, err)
}

func TestLocalStorage_S28_UpdateSecret_DBError(t *testing.T) {
	ls := brokenS28Store(t)
	_, err := ls.UpdateSecret(context.Background(), &models.SecretNode{ID: 1})
	require.Error(t, err)
}

func TestLocalStorage_S28_GetSecretIncludingDeleted_NotFound(t *testing.T) {
	ls := newS28Store(t, secretModels...)
	_, err := ls.GetSecretIncludingDeleted(context.Background(), 999)
	require.Error(t, err)
}

func TestLocalStorage_S28_ListLiveSecretNamesByProject_DBError(t *testing.T) {
	ls := brokenS28Store(t)
	_, _, err := ls.ListLiveSecretNamesByProject(context.Background(), []uint{1}, 10)
	require.Error(t, err)
}

func TestLocalStorage_S28_GetSecretTags_DBError(t *testing.T) {
	ls := brokenS28Store(t)
	_, err := ls.GetSecretTags(context.Background(), 1)
	require.Error(t, err)
}

func TestLocalStorage_S28_SetSecretTags_DBError(t *testing.T) {
	ls := brokenS28Store(t)
	err := ls.SetSecretTags(context.Background(), 1, []string{"tag1"})
	require.Error(t, err)
}

func TestLocalStorage_S28_CreateSecretVersion_DBError(t *testing.T) {
	ls := brokenS28Store(t)
	_, err := ls.CreateSecretVersion(context.Background(), &models.SecretVersion{SecretNodeID: 1, VersionNumber: 1})
	require.Error(t, err)
}

func TestLocalStorage_S28_GetSecretVersions_DBError(t *testing.T) {
	ls := brokenS28Store(t)
	_, err := ls.GetSecretVersions(context.Background(), 1)
	require.Error(t, err)
}

func TestLocalStorage_S28_GetLatestSecretVersion_DBError(t *testing.T) {
	ls := brokenS28Store(t)
	_, err := ls.GetLatestSecretVersion(context.Background(), 1)
	require.Error(t, err)
}

func TestLocalStorage_S28_GetLatestSecretVersion_NotFound(t *testing.T) {
	ls := newS28Store(t, secretModels...)
	// No versions in DB for secret 999.
	_, err := ls.GetLatestSecretVersion(context.Background(), 999)
	require.Error(t, err)
}

func TestLocalStorage_S28_TryIncrementSecretReadCount_DBError(t *testing.T) {
	ls := brokenS28Store(t)
	_, err := ls.TryIncrementSecretReadCount(context.Background(), 1, 5)
	require.Error(t, err)
}

func TestLocalStorage_S28_TryIncrementSecretNodeReadCount_DBError(t *testing.T) {
	ls := brokenS28Store(t)
	_, err := ls.TryIncrementSecretNodeReadCount(context.Background(), 1, 5)
	require.Error(t, err)
}
