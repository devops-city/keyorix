package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/server/http/handlers/contracttest"
)

func TestExportAccessReviewCampaignCSV(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.AccessReviewCampaign{}, &models.AccessReviewItem{}, &models.User{}, &models.Project{},
	))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "auditor", Email: "a@t.com"}).Error)
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "web"}).Error)
	require.NoError(t, db.Create(&models.AccessReviewCampaign{
		ID: 5, ProjectID: 1, Name: "Q4 2026", State: "closed", CreatedBy: 1, CreatedAt: time.Now(),
	}).Error)
	decided := time.Now()
	require.NoError(t, db.Create(&models.AccessReviewItem{
		ID: 1, CampaignID: 5, PrincipalType: "user", PrincipalID: 10, PrincipalName: "alice",
		Source: "role", RoleName: "editor", AccessLevel: "write", EnvironmentID: 2,
		Decision: "attested", DecidedBy: 1, DecidedAt: &decided,
	}).Error)
	require.NoError(t, db.Create(&models.AccessReviewItem{
		ID: 2, CampaignID: 5, PrincipalType: "user", PrincipalID: 11, PrincipalName: "bob",
		Source: "role", RoleName: "viewer", AccessLevel: "read", EnvironmentID: 2,
		Decision: "revoked", Reason: "left team", DecidedBy: 1, DecidedAt: &decided,
	}).Error)

	h := NewCatalogHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))

	t.Run("returns a CSV record of the campaign's items and decisions", func(t *testing.T) {
		req := withChiParams(withUserCtx(httptest.NewRequest(http.MethodGet,
			"/api/v1/projects/1/access-review/campaigns/5/export.csv", nil)),
			map[string]string{"id": "1", "campaignId": "5"})
		w := httptest.NewRecorder()
		h.ExportAccessReviewCampaignCSV(w, req)
		contracttest.AssertOpenAPIResponse(t, req, w)

		require.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Header().Get("Content-Type"), "text/csv")
		assert.Contains(t, w.Header().Get("Content-Disposition"), "access-review-campaign-5.csv")

		body := w.Body.String()
		lines := strings.Split(strings.TrimSpace(body), "\n")
		require.Len(t, lines, 3, "header + two items")
		assert.Equal(t, "principal_type,principal,email,source,role,access_level,environment_id,secret,last_used_at,decision,reason,decided_by,decided_at,last_used_window_days", strings.TrimSpace(lines[0]))
		for _, l := range lines[1:] {
			assert.True(t, strings.HasSuffix(strings.TrimSpace(l), ",all_history"), "a campaign opened before the window existed says its last_used_at looked back over the whole history: %q", l)
		}
		assert.Contains(t, body, "alice")
		assert.Contains(t, body, "attested")
		assert.Contains(t, body, "bob")
		assert.Contains(t, body, "revoked")
		assert.Contains(t, body, "left team")
		assert.Contains(t, body, "auditor", "decider username is resolved")
	})

	t.Run("states the look-back window the campaign was opened with", func(t *testing.T) {
		require.NoError(t, db.Create(&models.AccessReviewCampaign{
			ID: 8, ProjectID: 1, Name: "Q2 2027", State: "closed", CreatedBy: 1, CreatedAt: time.Now(), ActivityWindowDays: 45,
		}).Error)
		require.NoError(t, db.Create(&models.AccessReviewItem{
			ID: 9, CampaignID: 8, PrincipalType: "user", PrincipalID: 20, PrincipalName: "dora",
			Source: "role", RoleName: "viewer", AccessLevel: "read", Decision: "attested", DecidedBy: 1, DecidedAt: &decided,
		}).Error)
		req := withChiParams(withUserCtx(httptest.NewRequest(http.MethodGet,
			"/api/v1/projects/1/access-review/campaigns/8/export.csv", nil)),
			map[string]string{"id": "1", "campaignId": "8"})
		w := httptest.NewRecorder()
		h.ExportAccessReviewCampaignCSV(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		lines := strings.Split(strings.TrimSpace(w.Body.String()), "\n")
		require.Len(t, lines, 2)
		assert.True(t, strings.HasSuffix(strings.TrimSpace(lines[1]), ",45"), "the row carries the campaign's window: %q", lines[1])
	})

	t.Run("neutralizes formula-injection payloads in attacker/reviewer-controlled fields", func(t *testing.T) {
		require.NoError(t, db.Create(&models.AccessReviewCampaign{
			ID: 6, ProjectID: 1, Name: "Q1 2027", State: "closed", CreatedBy: 1, CreatedAt: time.Now(),
		}).Error)
		require.NoError(t, db.Create(&models.AccessReviewItem{
			ID: 3, CampaignID: 6, PrincipalType: "user", PrincipalID: 12,
			PrincipalName: "=1+1", Email: "+cmd|calc!A0",
			Source: "role", RoleName: "@SUM(A1:A9)", AccessLevel: "-2+3", EnvironmentID: 2,
			SecretName: "=HYPERLINK(http://evil)", Decision: "revoked",
			Reason: "+cmd|calc!A0", DecidedBy: 1, DecidedAt: &decided,
		}).Error)

		req := withChiParams(withUserCtx(httptest.NewRequest(http.MethodGet,
			"/api/v1/projects/1/access-review/campaigns/6/export.csv", nil)),
			map[string]string{"id": "1", "campaignId": "6"})
		w := httptest.NewRecorder()
		h.ExportAccessReviewCampaignCSV(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		body := w.Body.String()
		assert.Contains(t, body, "'=1+1")
		assert.Contains(t, body, "'+cmd|calc!A0")
		assert.Contains(t, body, "'@SUM(A1:A9)")
		assert.Contains(t, body, "'-2+3")
		assert.Contains(t, body, "'=HYPERLINK(http://evil)")
		// Every raw (unescaped) payload must not appear on its own — only prefixed.
		assert.NotContains(t, body, "\n=1+1")
		assert.NotContains(t, body, ",=1+1")
	})

	t.Run("requires a user context", func(t *testing.T) {
		req := withChiParams(httptest.NewRequest(http.MethodGet,
			"/api/v1/projects/1/access-review/campaigns/5/export.csv", nil),
			map[string]string{"id": "1", "campaignId": "5"})
		w := httptest.NewRecorder()
		h.ExportAccessReviewCampaignCSV(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("a campaign from another project is not reachable", func(t *testing.T) {
		req := withChiParams(withUserCtx(httptest.NewRequest(http.MethodGet,
			"/api/v1/projects/2/access-review/campaigns/5/export.csv", nil)),
			map[string]string{"id": "2", "campaignId": "5"})
		w := httptest.NewRecorder()
		h.ExportAccessReviewCampaignCSV(w, req)
		assert.NotEqual(t, http.StatusOK, w.Code)
	})
}
