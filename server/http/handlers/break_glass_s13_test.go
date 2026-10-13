// break_glass_s13_test.go — S13 coverage sweep for break_glass.go. Targets
// uncovered branches: bad-param paths, missing user context, bad JSON,
// validation errors. break_glass_proxy.go's tests were removed with the
// ADR-108 Phase 6 /system proxy tier deletion.
package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// newCatalogHandlerBreakGlassS13 returns a CatalogHandler backed by a fresh isolated DB.
func newCatalogHandlerBreakGlassS13(t *testing.T) *CatalogHandler {
	t.Helper()
	cs := freshCoreS12(t)
	return NewCatalogHandler(cs)
}

// ── break_glass.go: ActivateBreakGlass ────────────────────────────────────────

func TestActivateBreakGlass_BadProjectID_S13(t *testing.T) {
	h := newCatalogHandlerBreakGlassS13(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "notanumber")
	w := httptest.NewRecorder()
	h.ActivateBreakGlass(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestActivateBreakGlass_NoUserCtx_S13(t *testing.T) {
	h := newCatalogHandlerBreakGlassS13(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"justification":"test","ttl":""}`)), "id", "1")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ActivateBreakGlass(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestActivateBreakGlass_BadJSON_S13(t *testing.T) {
	h := newCatalogHandlerBreakGlassS13(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad json")), "id", "1"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ActivateBreakGlass(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestActivateBreakGlass_MissingJustification_S13(t *testing.T) {
	h := newCatalogHandlerBreakGlassS13(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"justification":""}`)), "id", "1"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ActivateBreakGlass(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestActivateBreakGlass_CoreError_InternalError_S13 — with a valid param, user ctx,
// and a justification, the core call fails because break-glass is not enabled.
// "ErrorPermissionDenied" is in en.json → i18n returns "permission denied" →
// the handler matches the permission-denied branch → 403.
func TestActivateBreakGlass_CoreError_InternalError_S13(t *testing.T) {
	h := newCatalogHandlerBreakGlassS13(t)
	body := strings.NewReader(`{"justification":"emergency access needed","ttl":"1h"}`)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", body), "id", "1"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ActivateBreakGlass(w, req)
	// break-glass not enabled → core returns "permission denied" → 403
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ── break_glass.go: ListBreakGlassActivations ─────────────────────────────────

func TestListBreakGlassActivations_BadProjectID_S13(t *testing.T) {
	h := newCatalogHandlerBreakGlassS13(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "xyz")
	w := httptest.NewRecorder()
	h.ListBreakGlassActivations(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListBreakGlassActivations_EmptyProject_S13(t *testing.T) {
	// BREAKGLASS-OWN-1: the handler authorizes the caller itself now (the route has no
	// permission gate), so the request carries an authenticated caller allowed to list:
	// user 1, the fixture's global admin.
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewCatalogHandler(cs)
	req := withUserCtxS7(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.ListBreakGlassActivations(w, req)
	// no project with id=9999, but ListBreakGlassActivations returns empty list not error
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── break_glass.go: RevokeBreakGlass ─────────────────────────────────────────

func TestRevokeBreakGlass_BadProjectID_S13(t *testing.T) {
	h := newCatalogHandlerBreakGlassS13(t)
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", nil),
		map[string]string{"id": "notanumber", "activationId": "1"})
	w := httptest.NewRecorder()
	h.RevokeBreakGlass(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRevokeBreakGlass_BadActivationID_S13(t *testing.T) {
	h := newCatalogHandlerBreakGlassS13(t)
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", nil),
		map[string]string{"id": "1", "activationId": "notanumber"})
	w := httptest.NewRecorder()
	h.RevokeBreakGlass(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRevokeBreakGlass_NoUserCtx_S13(t *testing.T) {
	h := newCatalogHandlerBreakGlassS13(t)
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", nil),
		map[string]string{"id": "1", "activationId": "1"})
	w := httptest.NewRecorder()
	h.RevokeBreakGlass(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRevokeBreakGlass_NotFound_S13(t *testing.T) {
	h := newCatalogHandlerBreakGlassS13(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", nil),
		map[string]string{"id": "1", "activationId": "999999"}))
	w := httptest.NewRecorder()
	h.RevokeBreakGlass(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── break_glass.go: ReviewBreakGlass (ADR-112 §3, break-glass review item 5) ──

func TestReviewBreakGlass_BadProjectID_S13(t *testing.T) {
	h := newCatalogHandlerBreakGlassS13(t)
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", nil),
		map[string]string{"id": "notanumber", "activationId": "1"})
	w := httptest.NewRecorder()
	h.ReviewBreakGlass(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestReviewBreakGlass_BadActivationID_S13(t *testing.T) {
	h := newCatalogHandlerBreakGlassS13(t)
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", nil),
		map[string]string{"id": "1", "activationId": "notanumber"})
	w := httptest.NewRecorder()
	h.ReviewBreakGlass(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestReviewBreakGlass_NoUserCtx_S13(t *testing.T) {
	h := newCatalogHandlerBreakGlassS13(t)
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", nil),
		map[string]string{"id": "1", "activationId": "1"})
	w := httptest.NewRecorder()
	h.ReviewBreakGlass(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestReviewBreakGlass_BadJSON_S13(t *testing.T) {
	h := newCatalogHandlerBreakGlassS13(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad json")),
		map[string]string{"id": "1", "activationId": "1"}))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ReviewBreakGlass(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestReviewBreakGlass_NotFound_S13(t *testing.T) {
	h := newCatalogHandlerBreakGlassS13(t)
	body := strings.NewReader(`{"note":"a perfectly good review note"}`)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", body),
		map[string]string{"id": "1", "activationId": "999999"}))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ReviewBreakGlass(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestReviewBreakGlass_NoteTooShort_S13(t *testing.T) {
	h := newCatalogHandlerBreakGlassS13(t)
	body := strings.NewReader(`{"note":"ok"}`)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", body),
		map[string]string{"id": "1", "activationId": "1"}))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ReviewBreakGlass(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// seedBreakGlassActivationS13 inserts an activation directly, so the transport
// tests below can exercise ReviewBreakGlass's refusals without driving a whole
// real activation flow (project + membership + emergency role + policy).
func seedBreakGlassActivationS13(t *testing.T, db *gorm.DB, userID uint, state string) uint {
	t.Helper()
	expires := time.Now().UTC().Add(4 * time.Hour)
	a := &models.BreakGlassActivation{
		ProjectID: 1, UserID: userID, RoleID: 3, RoleName: "project_developer",
		State: state, Justification: "seeded for a transport-layer test",
		CreatedAt: time.Now().UTC().Add(-2 * time.Hour), ExpiresAt: &expires,
	}
	require.NoError(t, db.Create(a).Error)
	return a.ID
}

// TestReviewBreakGlass_SelfReviewIsForbidden_S13 pins the STATUS CODE for
// #2461's self-review refusal, not just the refusal itself. The core error
// carries "an independent reviewer is required", and the handler's 400 arm
// matches "required" -- so without the permission-denied arm being checked
// FIRST, a deliberate authorization refusal would surface as a malformed
// request. withUserCtx authenticates as user 1, and the activation below is
// user 1's own.
func TestReviewBreakGlass_SelfReviewIsForbidden_S13(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewCatalogHandler(cs)
	id := seedBreakGlassActivationS13(t, db, 1, "revoked")

	body := strings.NewReader(`{"note":"I reviewed my own emergency access"}`)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", body),
		map[string]string{"id": "1", "activationId": fmt.Sprint(id)}))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ReviewBreakGlass(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code, "body: %s", w.Body.String())
}

// TestReviewBreakGlass_StillActiveIsBadRequest_S13: a still-live activation
// must be revoked or expired before it can be reviewed, surfaced as 400 rather
// than falling through to a 500 that reads as a server fault.
func TestReviewBreakGlass_StillActiveIsBadRequest_S13(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewCatalogHandler(cs)
	id := seedBreakGlassActivationS13(t, db, 2, "active")

	body := strings.NewReader(`{"note":"reviewing while the grant is still live"}`)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", body),
		map[string]string{"id": "1", "activationId": fmt.Sprint(id)}))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ReviewBreakGlass(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "still active")
}

// TestReviewBreakGlass_IndependentReviewerOnConcludedActivationSucceeds_S13 is
// the green side: the two refusals above must not have made the happy path
// unreachable over the transport.
func TestReviewBreakGlass_IndependentReviewerOnConcludedActivationSucceeds_S13(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewCatalogHandler(cs)
	id := seedBreakGlassActivationS13(t, db, 2, "revoked")

	body := strings.NewReader(`{"note":"checked the justification and what was accessed"}`)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", body),
		map[string]string{"id": "1", "activationId": fmt.Sprint(id)}))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ReviewBreakGlass(w, req)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	var got models.BreakGlassActivation
	require.NoError(t, db.First(&got, id).Error)
	require.NotNil(t, got.ReviewedAt)
	assert.Equal(t, uint(1), got.ReviewedBy)
	assert.Equal(t, "checked the justification and what was accessed", got.ReviewNote)
}
