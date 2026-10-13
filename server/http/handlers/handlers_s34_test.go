// handlers_s34_test.go — broken-DB error-path sweep for regular (non-proxy)
// handler functions whose storage-error branch was not yet covered: catalog,
// break-glass, access-review, audit, and dashboard.
package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

func freshCoreBrokenS34(t *testing.T) *core.KeyorixCore {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kxhandlers_s34_")
	require.NoError(t, db.AutoMigrate(&models.Project{}))
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())
	return core.NewKeyorixCore(store.NewLocalStorage(db))
}

// ── CatalogHandler / access_review_campaigns.go ───────────────────────────────

func TestListAccessReviewCampaigns_DBError_S34(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS34(t))
	r := withChiParamS7(httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/access-review/campaigns", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListAccessReviewCampaigns(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── CatalogHandler / break_glass.go ───────────────────────────────────────────

// TestListBreakGlassActivations_DBError_S34: with the whole store down, the first
// read is now the handler's own authorization (BREAKGLASS-OWN-1: the route has no
// permission gate), and a failed authorization read fails CLOSED with the 403 the old
// roles.read gate gave, never a downgrade to the caller's own rows. The list-read
// failure's 500 is TestListBreakGlassActivations_ListReadError_S34 below.
func TestListBreakGlassActivations_DBError_S34(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS34(t))
	r := withUserCtxS7(withChiParamS7(httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/break-glass", nil), "id", "1"))
	w := httptest.NewRecorder()
	h.ListBreakGlassActivations(w, r)
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.NotContains(t, w.Body.String(), "activations")
}

// TestListBreakGlassActivations_ListReadError_S34: authorization succeeds (user 1 is
// the fixture's admin) but the activations read fails: a 500 with a client-safe body.
func TestListBreakGlassActivations_ListReadError_S34(t *testing.T) {
	cs, db := freshCoreS24WithAdmin(t)
	require.NoError(t, db.Migrator().DropTable(&models.BreakGlassActivation{}))
	h := NewCatalogHandler(cs)
	r := withUserCtxS7(withChiParamS7(httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/break-glass", nil), "id", "1"))
	w := httptest.NewRecorder()
	h.ListBreakGlassActivations(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NotContains(t, w.Body.String(), "break_glass_activations")
}

// ── CatalogHandler / catalog.go ───────────────────────────────────────────────

func TestGetProjectDrift_DBError_S34(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS34(t))
	r := withChiParamS7(httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/drift", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetProjectDrift(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListProjectEnvironments_DBError_S34(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS34(t))
	r := withChiParamS7(httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/environments", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListProjectEnvironments(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListProjectEnvironments_IncludeDeleted_DBError_S34(t *testing.T) {
	// Exercises the include_deleted=true branch of ListProjectEnvironments.
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS34(t))
	r := withChiParamS7(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/environments?include_deleted=true", nil),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.ListProjectEnvironments(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── AuditHandler / audit.go ───────────────────────────────────────────────────

func TestGetAuditRetention_DBError_S34(t *testing.T) {
	t.Parallel()
	h := NewAuditHandler(freshCoreBrokenS34(t))
	r := withUserCtxS7(httptest.NewRequest(http.MethodGet, "/api/v1/audit/retention", nil))
	w := httptest.NewRecorder()
	h.GetAuditRetention(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestVerifyAuditChain_DBError_S34(t *testing.T) {
	t.Parallel()
	h := NewAuditHandler(freshCoreBrokenS34(t))
	r := withUserCtxS7(httptest.NewRequest(http.MethodGet, "/api/v1/audit/verify", nil))
	w := httptest.NewRecorder()
	h.VerifyAuditChain(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestWriteAuditCheckpoint_DBError_S34(t *testing.T) {
	t.Parallel()
	h := NewAuditHandler(freshCoreBrokenS34(t))
	r := withUserCtxS7(httptest.NewRequest(http.MethodPost, "/api/v1/audit/checkpoint", nil))
	w := httptest.NewRecorder()
	h.WriteAuditCheckpoint(w, r)
	// With no encryption configured, WriteAuditCheckpoint returns (nil, false, nil) →
	// the !written branch fires → 412 PreconditionFailed.
	assert.Equal(t, http.StatusPreconditionFailed, w.Code)
}
