package http

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestProjectAccessReviewHTTP_NamesEnvironmentWithoutProjectGrantUntilFixed
// (ROLE-SHAPE-1, #2857 follow-up) drives the admin's surface end to end: a
// legacy grant at {project_id: 0, environment_id: X} (written straight into the
// table, as a release before #3546 could) makes GET
// /api/v1/projects/{P}/access-review answer degraded with a reason naming the
// grant and its fix; following that fix through the API (re-grant at {P, X},
// DELETE the {0, X} row) leaves the grant listed as an entry and the review
// complete. Red before ROLE-SHAPE-1: the first review read as complete.
func TestProjectAccessReviewHTTP_NamesEnvironmentWithoutProjectGrantUntilFixed(t *testing.T) {
	w := newSVWorld(t, "sqlite", 1)
	r, ctx := w.a, context.Background()
	u, err := r.c.CreateUser(ctx, &core.CreateUserRequest{Username: "legacy", Email: "legacy@x.io", Password: svPassword})
	require.NoError(t, err)
	dev, err := r.c.Storage().GetRoleByName(ctx, "project_developer")
	require.NoError(t, err)
	require.NoError(t, r.db.Create(&models.UserRole{UserID: u.ID, RoleID: dev.ID, EnvironmentID: w.envID}).Error)

	review := func() (degraded bool, reasons []string, entries []map[string]any) {
		code, body := awDo(r, http.MethodGet, w.tokens["human"], fmt.Sprintf("/api/v1/projects/%d/access-review", w.projID), nil)
		require.Equal(t, http.StatusOK, code, body)
		var resp struct {
			Data struct {
				Entries         []map[string]any `json:"entries"`
				Degraded        bool             `json:"degraded"`
				DegradedReasons []string         `json:"degraded_reasons"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal([]byte(body), &resp), body)
		return resp.Data.Degraded, resp.Data.DegradedReasons, resp.Data.Entries
	}
	holds := func(entries []map[string]any) bool {
		for _, e := range entries {
			if e["principal_id"] == float64(u.ID) && e["role_name"] == "project_developer" {
				return true
			}
		}
		return false
	}

	degraded, reasons, entries := review()
	require.True(t, degraded, "the review must not read as complete while a grant that applies here is missing from it")
	require.Len(t, reasons, 1, "%v", reasons)
	require.Contains(t, reasons[0], fmt.Sprintf("user %d holds role project_developer (id %d) at project_id=0, environment_id=%d", u.ID, dev.ID, w.envID))
	require.Contains(t, reasons[0], fmt.Sprintf("re-create it with project_id=%d", w.projID))
	require.False(t, holds(entries), "premise: the {0, X} grant is not an entry")

	// The fix the reason names, through the API.
	code, body := awDo(r, http.MethodPost, w.tokens["human"], "/api/v1/user-roles",
		[]byte(fmt.Sprintf(`{"user_id":%d,"role_id":%d,"project_id":%d,"environment_id":%d}`, u.ID, dev.ID, w.projID, w.envID)))
	require.Equal(t, http.StatusCreated, code, body)
	code, body = awDo(r, http.MethodDelete, w.tokens["human"], "/api/v1/user-roles",
		[]byte(fmt.Sprintf(`{"user_id":%d,"role_id":%d,"project_id":0,"environment_id":%d}`, u.ID, dev.ID, w.envID)))
	require.Less(t, code, 300, body)
	var left int64
	require.NoError(t, r.db.Model(&models.UserRole{}).Where("user_id = ? AND project_id = 0 AND environment_id <> 0", u.ID).Count(&left).Error)
	require.Zero(t, left, "the DELETE the reason names removes the {0, X} row")

	degraded, reasons, entries = review()
	require.False(t, degraded, "after the fix the review is complete: %s", strings.Join(reasons, "; "))
	require.True(t, holds(entries), "the re-created grant is listed")
}
