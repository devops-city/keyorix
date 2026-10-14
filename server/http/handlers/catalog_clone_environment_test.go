// catalog_clone_environment_test.go — coverage for CloneEnvironment
// (catalog.go), previously untested (0% coverage). Uses freshCoreS12WithAdmin
// (withUserCtx's UserID=1 wired to a global admin role) so CopySecret's
// permission check inside CloneEnvironment passes via the RBAC fallback path
// (CheckSecretPermission -> AuthorizePrincipal -> admin bypass) without
// needing a separate per-project membership grant.
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestCloneEnvironment_Unauthorized(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewCatalogHandler(cs)
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/environments/1/clone", nil),
		map[string]string{"id": "1", "envId": "1"})
	w := httptest.NewRecorder()
	h.CloneEnvironment(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestCloneEnvironment_InvalidProjectID(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewCatalogHandler(cs)
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/api/v1/projects/abc/environments/1/clone", nil),
		map[string]string{"id": "abc", "envId": "1"})
	req = withUserCtx(req)
	w := httptest.NewRecorder()
	h.CloneEnvironment(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCloneEnvironment_InvalidEnvID(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewCatalogHandler(cs)
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/environments/abc/clone", nil),
		map[string]string{"id": "1", "envId": "abc"})
	req = withUserCtx(req)
	w := httptest.NewRecorder()
	h.CloneEnvironment(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCloneEnvironment_BadJSON(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewCatalogHandler(cs)
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/environments/1/clone",
		bytes.NewReader([]byte("{bad json}"))), map[string]string{"id": "1", "envId": "1"})
	req = withUserCtx(req)
	w := httptest.NewRecorder()
	h.CloneEnvironment(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCloneEnvironment_MissingDestination(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewCatalogHandler(cs)
	body, _ := json.Marshal(map[string]any{})
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/environments/1/clone",
		bytes.NewReader(body)), map[string]string{"id": "1", "envId": "1"})
	req = withUserCtx(req)
	w := httptest.NewRecorder()
	h.CloneEnvironment(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCloneEnvironment_CoreValidationError — same source and destination
// environment ID: core.CloneEnvironment's own validation error ("must
// differ"), mapped by the handler to 400 via its "must "/"belong"/"required"/
// "validation" substring match.
func TestCloneEnvironment_CoreValidationError(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewCatalogHandler(cs)
	body, _ := json.Marshal(map[string]any{"destination_environment_id": 1})
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/environments/1/clone",
		bytes.NewReader(body)), map[string]string{"id": "1", "envId": "1"})
	req = withUserCtx(req)
	w := httptest.NewRecorder()
	h.CloneEnvironment(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCloneEnvironment_SourceEnvNotFound exercises the errNotFound (404)
// branch: core.CloneEnvironment wraps GetEnvironment's not-found error as
// "Validation error: source environment: ...not found..." -- capital-V
// "Validation" does NOT match the handler's lowercase "validation" substring
// check, and none of "must "/"required"/"belong" match either, so this falls
// through to the errNotFound ("not found") check instead of the 400 branch
// above it.
func TestCloneEnvironment_SourceEnvNotFound(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewCatalogHandler(cs)
	proj, err := cs.Storage().CreateProject(context.Background(), &models.Project{Name: "clone-notfound-proj"})
	require.NoError(t, err)

	body, _ := json.Marshal(map[string]any{"destination_environment_id": 1})
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/environments/999999/clone",
		bytes.NewReader(body)), map[string]string{"id": machineUintToStr(proj.ID), "envId": "999999"})
	req = withUserCtx(req)
	w := httptest.NewRecorder()
	h.CloneEnvironment(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
}

// TestCloneEnvironment_StorageError closes the DB before the handler even
// reaches core.CloneEnvironment's storage calls, so GetEnvironment fails with
// a genuine connection error -- a message matching none of the 400/404
// substring checks, landing on the handler's final else (500, clientSafe)
// branch.
func TestCloneEnvironment_StorageError(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewCatalogHandler(cs)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	body, _ := json.Marshal(map[string]any{"destination_environment_id": 2})
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/environments/1/clone",
		bytes.NewReader(body)), map[string]string{"id": "1", "envId": "1"})
	req = withUserCtx(req)
	w := httptest.NewRecorder()
	h.CloneEnvironment(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestCloneEnvironment_Success seeds a project with two environments and
// three secrets in the source, then clones into the destination.
func TestCloneEnvironment_Success(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewCatalogHandler(cs)
	ctx := context.Background()

	proj, err := cs.Storage().CreateProject(ctx, &models.Project{Name: "clone-http-proj"})
	require.NoError(t, err)
	src, err := cs.Storage().CreateEnvironment(ctx, &models.Environment{Name: "src", ProjectID: proj.ID})
	require.NoError(t, err)
	dst, err := cs.Storage().CreateEnvironment(ctx, &models.Environment{Name: "dst", ProjectID: proj.ID})
	require.NoError(t, err)

	for _, name := range []string{"alpha", "beta", "gamma"} {
		_, err := cs.CreateSecret(ctx, &core.CreateSecretRequest{
			Name: name, Value: []byte("val-" + name),
			ProjectID: proj.ID, EnvironmentID: src.ID,
			Type: "generic", CreatedBy: "owner", OwnerID: 1,
		})
		require.NoError(t, err)
	}

	body, _ := json.Marshal(map[string]any{"destination_environment_id": dst.ID})
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/environments/1/clone",
		bytes.NewReader(body)), map[string]string{"id": machineUintToStr(proj.ID), "envId": machineUintToStr(src.ID)})
	req = withUserCtx(req)
	w := httptest.NewRecorder()
	h.CloneEnvironment(w, req)
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), `"secrets_cloned":3`)
}
