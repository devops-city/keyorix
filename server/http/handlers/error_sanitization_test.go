// error_sanitization_test.go — proves the backlog #116 fix: a raw internal
// (DB-layer) error is sanitized before it reaches the client but the ORIGINAL
// error still reaches the server-side log for operators to debug.
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// TestClientSafe_NilAndError exercises the helper in isolation: a nil error
// yields an empty string, and a non-nil error yields a fixed, generic message
// that never echoes the error's own text.
func TestClientSafe_NilAndError(t *testing.T) {
	assert.Equal(t, "", clientSafe(nil))

	raw := errorWithMessage("pq: duplicate key value violates unique constraint \"idx_users_email\"")
	safe := clientSafe(raw)
	assert.NotEmpty(t, safe)
	assert.NotContains(t, safe, "idx_users_email")
	assert.NotContains(t, safe, "duplicate key")
	assert.NotEqual(t, raw.Error(), safe)
}

// errorWithMessage is a tiny error implementation so the test doesn't need to
// depend on a real driver error type.
type errorWithMessage string

func (e errorWithMessage) Error() string { return string(e) }

// TestGetProject_DBErrorSanitizedInResponseButLoggedForOperators is the
// end-to-end property test: force a genuine database-layer failure (NOT a
// "project not found", which is a deliberately safe message the handler
// still passes through) and verify BOTH halves of the fix —
//  1. the HTTP response never contains the raw DB error text, and
//  2. the raw error still reaches the server-side log.
func TestGetProject_DBErrorSanitizedInResponseButLoggedForOperators(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Project{}))

	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	h := NewCatalogHandler(coreService)

	// Force a genuine DB-layer error (not "not found") by closing the
	// underlying *sql.DB out from under the handler before it queries.
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	// Capture exactly what core.GetProject raises on a closed connection, so
	// we can assert the log line carries this same text.
	_, rawErr := coreService.GetProject(context.Background(), 1)
	require.Error(t, rawErr)
	require.NotContains(t, rawErr.Error(), "not found",
		"test must exercise the sanitize branch, not the deliberate not-found branch")

	var logBuf bytes.Buffer
	origOutput := log.Writer()
	origFlags := log.Flags()
	log.SetOutput(&logBuf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(origOutput)
		log.SetFlags(origFlags)
	})

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/projects/1", nil))
	req = withChiParam(req, "id", "1")
	w := httptest.NewRecorder()
	h.GetProject(w, req)

	// --- Client-facing half: the raw DB error must NOT reach the response. ---
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	msg, _ := resp["message"].(string)
	assert.NotEmpty(t, msg)
	assert.NotEqual(t, rawErr.Error(), msg)
	assert.NotContains(t, w.Body.String(), "sql:")
	assert.NotContains(t, w.Body.String(), "database is closed")
	assert.Equal(t, clientSafe(rawErr), msg)

	// --- Server-side half: the ORIGINAL error must still reach the operator log. ---
	assert.Contains(t, logBuf.String(), rawErr.Error(),
		"the raw error must still be logged server-side for operators to debug")
}
