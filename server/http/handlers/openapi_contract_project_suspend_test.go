// openapi_contract_project_suspend_test.go — ADR-074 registry population for the project-wide
// suspend/resume operations (POST /projects/{id}/secrets/suspend-all and resume-all), which
// gained OpenAPI entries when suspend-all took the clear_synced_copies choice. Same
// convention as openapi_contract_pr5_test.go: drive the real handler through a happy path and
// call contracttest.AssertOpenAPIResponse.
package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/server/http/handlers/contracttest"
)

func projectSuspendRequest(t *testing.T, path, projID string, body map[string]any) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		require.NoError(t, json.NewEncoder(&buf).Encode(body))
	}
	req := withUserCtx(withChiParamsPR5(httptest.NewRequest(http.MethodPost, path, &buf), "id", projID))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestContractProjectSuspend_SuspendAll(t *testing.T) {
	h, cs, _, projID, envID := pr5SecretFixture(t)
	pr5CreateSecret(t, cs, projID, envID, "suspend-all-target")

	req := projectSuspendRequest(t, "/api/v1/projects/1/secrets/suspend-all", pr5IDStr(projID), map[string]any{"reason": "drill"})
	w := httptest.NewRecorder()
	h.SuspendProjectSecrets(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
	require.NotContains(t, w.Body.String(), "clear_synced_copies", "present only when the request carried the choice")
}

func TestContractProjectSuspend_SuspendAllClearSyncedCopies(t *testing.T) {
	h, cs, _, projID, envID := pr5SecretFixture(t)
	pr5CreateSecret(t, cs, projID, envID, "suspend-all-clear-target")

	req := projectSuspendRequest(t, "/api/v1/projects/1/secrets/suspend-all", pr5IDStr(projID),
		map[string]any{"reason": "leaked", "clear_synced_copies": true})
	w := httptest.NewRecorder()
	h.SuspendProjectSecrets(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
	var env struct {
		Data struct {
			Suspended         int  `json:"suspended"`
			ClearSyncedCopies bool `json:"clear_synced_copies"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env))
	require.Equal(t, 1, env.Data.Suspended)
	require.True(t, env.Data.ClearSyncedCopies)
}

func TestContractProjectSuspend_ResumeAll(t *testing.T) {
	h, cs, _, projID, envID := pr5SecretFixture(t)
	pr5CreateSecret(t, cs, projID, envID, "resume-all-target")
	_, err := cs.SuspendProjectSecrets(withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil)).Context(), projID, 1, "")
	require.NoError(t, err)

	req := projectSuspendRequest(t, "/api/v1/projects/1/secrets/resume-all", pr5IDStr(projID), nil)
	w := httptest.NewRecorder()
	h.ResumeProjectSecrets(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}
