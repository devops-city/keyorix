// secrets_error_sanitization_test.go — regression guard for backlog #441: five
// SecretHandler methods (ClassifySecret, SetAutoRotate, RestoreSecret in
// secrets_crud.go; CopySecret in secrets_copy.go; CopyEnvironmentSecrets in
// secrets_copy_environment.go) echoed the raw, wrapped internal/storage error
// verbatim at HTTP 500 in their default/fallthrough error-mapping branch —
// the same class of internal-error-disclosure issue #116/#401/#421 fixed
// elsewhere via the clientSafe() helper. Each test below forces a genuine
// storage-layer failure that does NOT match any of the handler's
// deliberately-safe branches (not found / validation / already exists /
// permission / etc.) so it falls through to the default branch, and asserts
// the HTTP response carries the generic clientSafe() message — never the raw
// error text — while the raw error still reaches the server-side log.
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// secretErrSanitizationFixture builds a pinned-connection in-memory sqlite DB
// (so PRAGMA query_only survives across queries and matches the schema
// created below), makes user 1 a global admin (so in-handler authorization
// checks pass), and creates a project/environment/secret to operate on.
func secretErrSanitizationFixture(t *testing.T) (*SecretHandler, *core.KeyorixCore, *models.SecretNode, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"}}))

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.Role{}, &models.UserRole{},
		&models.Permission{}, &models.RolePermission{}, &models.Group{}, &models.GroupRole{},
		&models.UserGroup{}, &models.Project{}, &models.Environment{}, &models.AuditEvent{},
		&models.SecretNode{}, &models.SecretVersion{}, &models.SecretAccessLog{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{},
		&models.SecretACL{}))

	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", AccountState: "active"}).Error)
	adminRole := &models.Role{Name: "admin", BypassesPermissionChecks: true}
	require.NoError(t, db.Create(adminRole).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: adminRole.ID}).Error)

	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "proj"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 10, ProjectID: 1, Name: "prod"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 11, ProjectID: 1, Name: "staging"}).Error)

	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	handler, err := NewSecretHandler(coreService)
	require.NoError(t, err)

	secret, err := coreService.CreateSecret(context.Background(), &core.CreateSecretRequest{
		Name: "target", Value: []byte("v"), ProjectID: 1, EnvironmentID: 10, Type: "static",
		CreatedBy: "alice", OwnerID: 1,
	})
	require.NoError(t, err)

	t.Cleanup(func() {
		// Undo query_only so any deferred cleanup (t.Cleanup ordering, etc.)
		// doesn't itself explode.
		_ = db.Exec("PRAGMA query_only = OFF").Error
	})

	return handler, coreService, secret, db
}

// forceReadOnly makes every subsequent write on the pinned connection fail
// with a genuine sqlite error, while SELECTs keep working — the tool used to
// reach the "not-found"-shaped path's sibling: a real storage failure that
// isn't a deliberately-safe outcome.
func forceReadOnly(t *testing.T, db *gorm.DB) {
	t.Helper()
	require.NoError(t, db.Exec("PRAGMA query_only = ON").Error)
}

// captureLog redirects the shared log.Default() output for the duration of
// the test and returns a function to read what was written.
func captureLog(t *testing.T) func() string {
	t.Helper()
	var buf bytes.Buffer
	origOutput := log.Writer()
	origFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(origOutput)
		log.SetFlags(origFlags)
	})
	return buf.String
}

func assertSanitizedInternalError(t *testing.T, w *httptest.ResponseRecorder, rawErr error, logs func() string) {
	t.Helper()
	require.Equal(t, http.StatusInternalServerError, w.Code, w.Body.String())
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	msg, _ := resp["message"].(string)
	assert.NotEmpty(t, msg)
	assert.NotEqual(t, rawErr.Error(), msg)
	assert.NotContains(t, w.Body.String(), "readonly database")
	assert.Equal(t, clientSafe(rawErr), msg)
	assert.Contains(t, logs(), rawErr.Error(),
		"the raw error must still be logged server-side for operators to debug")
}

func TestClassifySecret_StorageErrorSanitizedInResponseButLogged(t *testing.T) {
	handler, coreService, secret, db := secretErrSanitizationFixture(t)

	_, rawErr := coreService.ClassifySecret(context.Background(), 1, "alice", secret.ID, "confidential")
	require.NoError(t, rawErr, "sanity: classification succeeds before the DB goes read-only")

	forceReadOnly(t, db)
	logs := captureLog(t)

	_, rawErr = coreService.ClassifySecret(context.Background(), 1, "alice", secret.ID, "public")
	require.Error(t, rawErr)
	require.NotContains(t, rawErr.Error(), "not found")
	require.NotContains(t, rawErr.Error(), "classification must be")

	body := `{"classification":"public"}`
	req := withUserCtx(httptest.NewRequest(http.MethodPatch, "/api/v1/secrets/1/classification", bytes.NewBufferString(body)))
	req = withChiParam(req, "id", strconv.FormatUint(uint64(secret.ID), 10))
	w := httptest.NewRecorder()
	handler.ClassifySecret(w, req)

	assertSanitizedInternalError(t, w, rawErr, logs)
}

func TestSetAutoRotate_StorageErrorSanitizedInResponseButLogged(t *testing.T) {
	handler, coreService, secret, db := secretErrSanitizationFixture(t)

	forceReadOnly(t, db)
	logs := captureLog(t)

	rawErr := coreService.SetSecretAutoRotate(context.Background(), secret.ID, core.AutoRotateSpec{Enabled: true}, 1)
	require.Error(t, rawErr)
	require.NotContains(t, rawErr.Error(), "not found")
	require.NotContains(t, rawErr.Error(), "unknown rotation charset")

	body := `{"enabled":true}`
	req := withUserCtx(httptest.NewRequest(http.MethodPatch, "/api/v1/secrets/1/auto-rotate", bytes.NewBufferString(body)))
	req = withChiParam(req, "id", strconv.FormatUint(uint64(secret.ID), 10))
	w := httptest.NewRecorder()
	handler.SetAutoRotate(w, req)

	assertSanitizedInternalError(t, w, rawErr, logs)
}

func TestRestoreSecret_StorageErrorSanitizedInResponseButLogged(t *testing.T) {
	handler, coreService, secret, db := secretErrSanitizationFixture(t)

	// The restore path only ever hits the write it needs to sanitize when the
	// secret is actually soft-deleted (deleted_at IS NOT NULL) — delete it
	// first, before the DB goes read-only.
	require.NoError(t, coreService.DeleteSecret(context.Background(), secret.ID))

	forceReadOnly(t, db)
	logs := captureLog(t)

	rawErr := coreService.RestoreSecret(context.Background(), 1, secret.ID)
	require.Error(t, rawErr)
	require.NotContains(t, rawErr.Error(), "not found")

	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/secrets/1/restore", nil))
	req = withChiParam(req, "id", strconv.FormatUint(uint64(secret.ID), 10))
	w := httptest.NewRecorder()
	handler.RestoreSecret(w, req)

	assertSanitizedInternalError(t, w, rawErr, logs)
}

func TestCopySecret_StorageErrorSanitizedInResponseButLogged(t *testing.T) {
	handler, coreService, secret, db := secretErrSanitizationFixture(t)

	forceReadOnly(t, db)
	logs := captureLog(t)

	_, rawErr := coreService.CopySecret(context.Background(), secret.ID, 11, "", "alice", 1, "", "")
	require.Error(t, rawErr)
	require.NotContains(t, rawErr.Error(), "not found")
	require.NotContains(t, rawErr.Error(), "same project")
	require.NotContains(t, rawErr.Error(), "already exists")
	require.NotContains(t, rawErr.Error(), "validation")
	require.NotContains(t, rawErr.Error(), "required")
	require.NotContains(t, rawErr.Error(), "permission")
	require.NotContains(t, rawErr.Error(), "not authorized")

	body := `{"environment_id":11}`
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/secrets/1/copy", bytes.NewBufferString(body)))
	req = withChiParam(req, "id", strconv.FormatUint(uint64(secret.ID), 10))
	w := httptest.NewRecorder()
	handler.CopySecret(w, req)

	assertSanitizedInternalError(t, w, rawErr, logs)
}

func TestCopyEnvironmentSecrets_StorageErrorSanitizedInResponseButLogged(t *testing.T) {
	handler, coreService, _, _ := secretErrSanitizationFixture(t)

	logs := captureLog(t)

	// A source environment that doesn't exist forces core.CopyEnvironmentSecrets'
	// GetEnvironment lookup to fail. That failure is wrapped as "Validation
	// error: <record not found>" — capital-V "Validation" doesn't match the
	// handler's lowercase "validation" substring check, and there is no
	// "not found" branch in this handler at all, so it falls to the
	// default/else branch that must sanitize.
	_, _, rawErr := coreService.CopyEnvironmentSecrets(context.Background(), 1, 999, 11, "alice", 1, "", "")
	require.Error(t, rawErr)
	require.NotContains(t, rawErr.Error(), "must ")
	require.NotContains(t, rawErr.Error(), "required")
	require.NotContains(t, rawErr.Error(), "belong")
	require.NotContains(t, rawErr.Error(), "validation")

	body := `{"target_environment_id":11}`
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/environments/999/copy-secrets", bytes.NewBufferString(body)))
	req = withChiParams(req, map[string]string{"id": "1", "envId": "999"})
	w := httptest.NewRecorder()
	handler.CopyEnvironmentSecrets(w, req)

	assertSanitizedInternalError(t, w, rawErr, logs)
}
