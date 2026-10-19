package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

func newCreateProjectHandler(t *testing.T) (*CatalogHandler, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	// AuditEvent: the project commits with its project.created row (AUDIT-TX-2).
	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.Environment{}, &models.AuditEvent{}))
	return NewCatalogHandler(core.NewKeyorixCore(store.NewLocalStorage(db))), db
}

func postCreateProject(t *testing.T, h *CatalogHandler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/projects", strings.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateProject(w, req)
	return w
}

func envNames(t *testing.T, db *gorm.DB, projectID uint) []string {
	t.Helper()
	var envs []models.Environment
	require.NoError(t, db.Where("project_id = ?", projectID).Order("name").Find(&envs).Error)
	names := make([]string, 0, len(envs))
	for _, e := range envs {
		names = append(names, e.Name)
	}
	return names
}

func TestCreateProject_DefaultEnvironments(t *testing.T) {
	h, db := newCreateProjectHandler(t)

	w := postCreateProject(t, h, `{"name":"web"}`)

	require.Equal(t, http.StatusCreated, w.Code)
	var p models.Project
	require.NoError(t, db.Where("name = ?", "web").First(&p).Error)
	// Default set is seeded when no environments are supplied.
	assert.ElementsMatch(t, []string{"development", "staging", "production"}, envNames(t, db, p.ID))
}

func TestCreateProject_CustomEnvironments(t *testing.T) {
	h, db := newCreateProjectHandler(t)

	// Blank entries are dropped; exactly the supplied set is seeded (no defaults).
	w := postCreateProject(t, h, `{"name":"api","environments":["dev","prod","  "]}`)

	require.Equal(t, http.StatusCreated, w.Code)
	var p models.Project
	require.NoError(t, db.Where("name = ?", "api").First(&p).Error)
	assert.ElementsMatch(t, []string{"dev", "prod"}, envNames(t, db, p.ID))
}

func TestCreateProject_BlankEnvironmentsFallBackToDefaults(t *testing.T) {
	h, db := newCreateProjectHandler(t)

	// An environments array of only blanks behaves like omitting it → default set.
	w := postCreateProject(t, h, `{"name":"svc","environments":["  ",""]}`)

	require.Equal(t, http.StatusCreated, w.Code)
	var p models.Project
	require.NoError(t, db.Where("name = ?", "svc").First(&p).Error)
	assert.ElementsMatch(t, []string{"development", "staging", "production"}, envNames(t, db, p.ID))
}

// #189: Project.Name is wired to the `identifier` validator so a name carrying an
// invisible or visually-deceptive character is rejected, rather than silently
// accepted and later shown, apparently-legitimate, in an access-review UI or audit log.
func TestCreateProject_RejectsDangerousNames(t *testing.T) {
	cases := map[string]string{
		"zero-width space":        "prod\u200bteam", // U+200B ZERO WIDTH SPACE
		"RTL override":            "prod\u202eteam", // U+202E RIGHT-TO-LEFT OVERRIDE
		"non-breaking space":      "prod team",      // U+00A0 NO-BREAK SPACE (not in allowlist)
		"cyrillic homograph 'a'":  "prodаpi",        // U+0430 CYRILLIC SMALL LETTER A looks like Latin "a"
		"CSV-formula-like prefix": "=cmd|'/calc'",
	}
	for name, dangerous := range cases {
		t.Run(name, func(t *testing.T) {
			h, _ := newCreateProjectHandler(t)
			body, err := json.Marshal(map[string]string{"name": dangerous})
			require.NoError(t, err)
			w := postCreateProject(t, h, string(body))
			assert.Equal(t, http.StatusBadRequest, w.Code, "response body: %s", w.Body.String())
		})
	}
}

// Non-regression: ordinary alphanumeric/space/hyphen/underscore names — the vast
// majority of real project names — must keep working.
func TestCreateProject_AcceptsLegitimateNames(t *testing.T) {
	legit := []string{"web", "api-gateway", "Payments_2026", "team one"}
	for _, name := range legit {
		t.Run(name, func(t *testing.T) {
			h, db := newCreateProjectHandler(t)
			body, err := json.Marshal(map[string]string{"name": name})
			require.NoError(t, err)
			w := postCreateProject(t, h, string(body))
			require.Equal(t, http.StatusCreated, w.Code, "response body: %s", w.Body.String())
			var p models.Project
			require.NoError(t, db.Where("name = ?", name).First(&p).Error)
		})
	}
}
