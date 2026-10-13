package handlers

import (
	"encoding/csv"
	"encoding/json"
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
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/server/http/handlers/contracttest"
)

func TestExportAuditLogsCSV(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.User{}))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", Email: "a@t.com"}).Error)

	uid := uint(1)
	pid := uint(5)
	tru := true
	require.NoError(t, db.Create(&models.AuditEvent{
		EventType: "secret.created", UserID: &uid, ProjectID: &pid, Success: &tru,
		Description: "created db", IPAddress: "10.0.0.1", EventTime: time.Now(),
	}).Error)

	h := NewAuditHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))

	t.Run("returns a CSV attachment with a header and the event", func(t *testing.T) {
		req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/audit/export.csv", nil))
		w := httptest.NewRecorder()
		h.ExportAuditLogsCSV(w, req)
		contracttest.AssertOpenAPIResponse(t, req, w)

		require.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Header().Get("Content-Type"), "text/csv")
		assert.Contains(t, w.Header().Get("Content-Disposition"), "audit-export.csv")

		body := w.Body.String()
		lines := strings.Split(strings.TrimSpace(body), "\n")
		require.GreaterOrEqual(t, len(lines), 2)
		assert.Equal(t, "id,event_time,event_type,actor,actor_type,user_id,project_id,secret_id,ip_address,success,description", strings.TrimSpace(lines[0]))
		assert.Contains(t, body, "secret.created")
		assert.Contains(t, body, "alice")
		assert.Contains(t, body, "created db")
	})

	t.Run("requires a user context", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/export.csv", nil)
		w := httptest.NewRecorder()
		h.ExportAuditLogsCSV(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

// TestExportAuditLogsCSV_FormulaInjection — an event whose actor_type begins with a
// formula-injection character (=, +, -, @) must be escaped with a leading single quote
// in the CSV export (G49: csvSafe() formula-injection escaping on the actor_type column).
func TestExportAuditLogsCSV_FormulaInjection(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.User{}))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", Email: "a@t.com"}).Error)

	uid := uint(1)
	tru := true
	require.NoError(t, db.Create(&models.AuditEvent{
		EventType: "secret.created", UserID: &uid, Success: &tru,
		Description: "created db", IPAddress: "10.0.0.1", EventTime: time.Now(),
		ActorType: "=cmd|' /C calc'!A1",
	}).Error)

	h := NewAuditHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/audit/export.csv", nil))
	w := httptest.NewRecorder()
	h.ExportAuditLogsCSV(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	records, err := csv.NewReader(w.Body).ReadAll()
	require.NoError(t, err)
	require.Len(t, records, 2, "CSV must have header + 1 data row")

	// header: id, event_time, event_type, actor, actor_type, user_id, project_id,
	// secret_id, ip_address, success, description
	actorTypeCell := records[1][4]
	assert.True(t, strings.HasPrefix(actorTypeCell, "'"), "formula-injection prefix must be neutralized with a leading quote, got %q", actorTypeCell)
	assert.Equal(t, "'=cmd|' /C calc'!A1", actorTypeCell)
}

// #3150 follow-up: a machine identity's row must carry the machine's name in the
// actor column (and its kind in actor_type) in the CSV download, as the JSON audit
// list does. No secret material is involved: the name is the identity's label.
func TestExportAuditLogsCSV_MachineRowCarriesMachineActor(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.User{}, &models.MachineIdentity{}))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", Email: "a@t.com"}).Error)
	require.NoError(t, db.Create(&models.MachineIdentity{ID: 7, Name: "ci-app"}).Error)

	uid, mid := uint(1), uint(7)
	tru := true
	require.NoError(t, db.Create(&models.AuditEvent{
		EventType: "secret.read", ActorType: core.ActorTypeMachine, MachineIdentityID: &mid, Success: &tru,
		Description: "Machine identity ci-app read secret", EventTime: time.Now(),
	}).Error)
	require.NoError(t, db.Create(&models.AuditEvent{
		EventType: "secret.created", ActorType: "user", UserID: &uid, Success: &tru, EventTime: time.Now().Add(-time.Minute),
	}).Error)

	h := NewAuditHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))
	w := httptest.NewRecorder()
	h.ExportAuditLogsCSV(w, withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/audit/export.csv", nil)))
	require.Equal(t, http.StatusOK, w.Code)

	records, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	require.NoError(t, err)
	byType := map[string][]string{}
	for _, r := range records[1:] {
		byType[r[2]] = r
	}
	require.Contains(t, byType, "secret.read")
	assert.Equal(t, "ci-app", byType["secret.read"][3], "machine row actor")
	assert.Equal(t, "machine_identity", byType["secret.read"][4], "machine row actor_type")
	assert.Equal(t, "alice", byType["secret.created"][3], "user row actor unchanged")
}

// The JSON export feed (what `keyorix audit export --csv` renders) fills the
// actor for a machine row the same way (#3150).
func TestExportAuditLogs_MachineRowCarriesMachineActor(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.User{}, &models.MachineIdentity{}))
	require.NoError(t, db.Create(&models.MachineIdentity{ID: 7, Name: "ci-app"}).Error)
	mid := uint(7)
	tru := true
	require.NoError(t, db.Create(&models.AuditEvent{
		EventType: "secret.read", ActorType: core.ActorTypeMachine, MachineIdentityID: &mid, Success: &tru, EventTime: time.Now(),
	}).Error)

	h := NewAuditHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))
	w := httptest.NewRecorder()
	h.ExportAuditLogs(w, withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/audit/export", nil)))
	require.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		Data struct {
			Events []struct {
				Actor     string `json:"actor"`
				ActorType string `json:"actor_type"`
			} `json:"events"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Len(t, resp.Data.Events, 1)
	assert.Equal(t, "ci-app", resp.Data.Events[0].Actor)
	assert.Equal(t, core.ActorTypeMachine, resp.Data.Events[0].ActorType)
}
