// catalog_env_secret_count_test.go — DASH-SIGNALS-1 item 2: the environment list
// routes carry a server-computed secret_count per environment, so the web no longer
// issues one secrets request per environment to find where the secrets are.
package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestListProjectEnvironments_CarriesSecretCount(t *testing.T) {
	w := new2780World(t)
	mk := func(name string, isSecret bool) *models.SecretNode {
		s := &models.SecretNode{Name: name, ProjectID: w.projectA, EnvironmentID: w.envA1, Type: "password", IsSecret: isSecret}
		require.NoError(t, w.db.Create(s).Error)
		return s
	}
	mk("one", true)
	gone := mk("two", true)
	mk("folder", false)
	require.NoError(t, w.db.Delete(gone).Error) // soft-delete

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", fmt.Sprint(w.projectA))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()
	w.h.ListProjectEnvironments(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	var body struct {
		Data struct {
			Environments []struct {
				ID          uint   `json:"id"`
				Name        string `json:"name"`
				SecretCount *int64 `json:"secret_count"`
			} `json:"environments"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Len(t, body.Data.Environments, 2)
	for _, e := range body.Data.Environments {
		require.NotNil(t, e.SecretCount, "secret_count must always be present (0 included)")
		if e.ID == w.envA1 {
			assert.Equal(t, int64(1), *e.SecretCount, "one live secret; the soft-deleted one and the folder do not count")
		} else {
			assert.Zero(t, *e.SecretCount, "an empty environment reports 0")
		}
	}
}
