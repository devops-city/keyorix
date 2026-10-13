// secret_templates_unit_test.go — unit tests for SecretTemplateHandler that
// exercise branches unreachable through the HTTP router (e.g. nil-user context,
// injected storage errors).
package handlers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"time"
)

// ---------- failing store wrapper ----------

// failingSecretTemplateStore embeds LocalStorage and overrides SecretTemplate
// methods so individual paths can be made to return an injected error,
// reaching the HTTP handler's 500 branches.
type failingSecretTemplateStore struct {
	*store.LocalStorage
	failCreate bool
	failList   bool
	failGet    bool
	failUpdate bool
	failDelete bool
}

func (s *failingSecretTemplateStore) CreateSecretTemplate(_ context.Context, _ *models.SecretTemplate) error {
	if s.failCreate {
		return errors.New("injected create error")
	}
	return s.LocalStorage.CreateSecretTemplate(context.Background(), &models.SecretTemplate{})
}

func (s *failingSecretTemplateStore) ListSecretTemplates(_ context.Context) ([]*models.SecretTemplate, error) {
	if s.failList {
		return nil, errors.New("injected list error")
	}
	return s.LocalStorage.ListSecretTemplates(context.Background())
}

func (s *failingSecretTemplateStore) GetSecretTemplate(_ context.Context, id uint) (*models.SecretTemplate, error) {
	if s.failGet {
		// Return an error that is NOT "not found" — triggers the 500 branch.
		return nil, errors.New("injected db error")
	}
	return s.LocalStorage.GetSecretTemplate(context.Background(), id)
}

func (s *failingSecretTemplateStore) UpdateSecretTemplateFields(_ context.Context, id uint, f coreStorage.SecretTemplateFieldUpdate, updatedAt time.Time) (bool, error) {
	if s.failUpdate {
		return false, errors.New("injected update error")
	}
	return s.LocalStorage.UpdateSecretTemplateFields(context.Background(), id, f, updatedAt)
}

func (s *failingSecretTemplateStore) DeleteSecretTemplate(_ context.Context, id uint) error {
	if s.failDelete {
		return errors.New("injected delete error")
	}
	return s.LocalStorage.DeleteSecretTemplate(context.Background(), id)
}

// newFailingSTHandler opens a migrated SQLite DB, seeds it with one template
// (ID=1), and wraps it with failingSecretTemplateStore for error injection.
var stUnitCounter int

func newFailingSTHandler(t *testing.T, flags failingSecretTemplateStore) *SecretTemplateHandler {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	stUnitCounter++
	// %d, not a rune offset from '0': past 9 (repeated tests or -count>1) that built
	// "file:stunit?" / "file:stunit@" ..., which drops mode=memory and makes SQLite write
	// a real file named stunit into the package directory.
	dsn := fmt.Sprintf("file:stunit%d?mode=memory&cache=private", stUnitCounter)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	// cache=private gives each new physical connection its own empty
	// in-memory database — without this, a pool-rotated connection opened by
	// a later handler call in the same test would see neither the migrated
	// schema nor the seed row below. Matches local_transaction_test.go /
	// local_usage_test.go's identical fix for the same cache=private pattern.
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.SecretTemplate{}))
	t.Cleanup(func() { _ = sqlDB.Close() })

	// Seed a template so GET/UPDATE/DELETE have a valid ID to work with before
	// the injected error fires at the storage layer.
	require.NoError(t, db.Create(&models.SecretTemplate{Name: "seed"}).Error)

	fs := &failingSecretTemplateStore{
		LocalStorage: store.NewLocalStorage(db),
		failCreate:   flags.failCreate,
		failList:     flags.failList,
		failGet:      flags.failGet,
		failUpdate:   flags.failUpdate,
		failDelete:   flags.failDelete,
	}
	return NewSecretTemplateHandler(core.NewKeyorixCore(fs))
}

// TestSecretTemplateCreate_NilUser exercises the nil-user-context guard in
// Create. In production this path is unreachable (RequirePermission middleware
// returns 401 first), but the guard is a defensive in-handler check that
// requires its own test for complete line coverage.
func TestSecretTemplateCreate_NilUser(t *testing.T) {
	// Create the handler with a nil coreService — the nil-user check fires
	// before coreService is ever called, so no panic.
	h := NewSecretTemplateHandler(nil)

	body := bytes.NewBufferString(`{"name":"tpl"}`)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "/", body)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	// Deliberately omit any user in the context — middleware.GetUserFromContext
	// will return nil.

	w := httptest.NewRecorder()
	h.Create(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ---------- storage-error (500) paths ----------

// TestSecretTemplateCreate_StorageError exercises the default branch in
// Create's error switch — triggered when the storage returns an unexpected
// error (not "name is required" / "invalid classification").
func TestSecretTemplateCreate_StorageError(t *testing.T) {
	h := newFailingSTHandler(t, failingSecretTemplateStore{failCreate: true})
	body := bytes.NewBufferString(`{"name":"valid-name"}`)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", body))
	w := httptest.NewRecorder()
	h.Create(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestSecretTemplateList_StorageError exercises the error path in List when
// the storage layer returns an error.
func TestSecretTemplateList_StorageError(t *testing.T) {
	h := newFailingSTHandler(t, failingSecretTemplateStore{failList: true})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.List(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestSecretTemplateGet_StorageError exercises the internal-error branch in
// Get — the storage returns an error that is NOT a "not found" message, so the
// handler must return 500 rather than 404.
func TestSecretTemplateGet_StorageError(t *testing.T) {
	h := newFailingSTHandler(t, failingSecretTemplateStore{failGet: true})
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.Get(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestSecretTemplateUpdate_StorageError exercises the default branch in
// Update's error switch — triggered when UpdateSecretTemplate returns an
// unexpected error (not "not found" / "name is required" / "invalid classification").
func TestSecretTemplateUpdate_StorageError(t *testing.T) {
	h := newFailingSTHandler(t, failingSecretTemplateStore{failUpdate: true})
	body := bytes.NewBufferString(`{"name":"new-name"}`)
	req := withChiParam(withUserCtx(httptest.NewRequest(http.MethodPut, "/", body)), "id", "1")
	w := httptest.NewRecorder()
	h.Update(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestSecretTemplateDelete_StorageError exercises the internal-error branch in
// Delete — DeleteSecretTemplate returns an error that is NOT "not found", so
// the handler must return 500 rather than 404.
func TestSecretTemplateDelete_StorageError(t *testing.T) {
	h := newFailingSTHandler(t, failingSecretTemplateStore{failDelete: true})
	req := withChiParam(withUserCtx(httptest.NewRequest(http.MethodDelete, "/", nil)), "id", "1")
	w := httptest.NewRecorder()
	h.Delete(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestSecretTemplateApply_StorageError exercises the internal-error branch in
// Apply — GetSecretTemplate returns an error that is NOT "not found", so the
// handler must return 500 rather than 404.
func TestSecretTemplateApply_StorageError(t *testing.T) {
	h := newFailingSTHandler(t, failingSecretTemplateStore{failGet: true})
	body := bytes.NewBufferString(`{"classification":"internal"}`)
	req := withChiParam(withUserCtx(httptest.NewRequest(http.MethodPost, "/", body)), "id", "1")
	w := httptest.NewRecorder()
	h.Apply(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
