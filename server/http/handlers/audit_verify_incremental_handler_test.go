package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

type verifyBody struct {
	Data map[string]any `json:"data"`
}

func decodeVerifyBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var b verifyBody
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &b), rec.Body.String())
	return b.Data
}

// GET /audit/verify reports not_proven (valid=false, with the reason) before a
// full verification exists; ?full=true returns 202 and a job id; the job status
// endpoint reports the result; afterwards /verify is valid
// (docs/specs/audit-incremental-verification.md §5).
func TestAuditVerifyJob_StatusEndpoint(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.AuditCheckpoint{}, &models.SystemMetadata{}))
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1) // ":memory:" is per connection; the job goroutine must share it

	st := store.NewLocalStorage(db)
	coreService := core.NewKeyorixCore(st)
	coreService.SetAuditCheckpointKey(bytes.Repeat([]byte{0x7}, 32), "v1")
	tr := true
	for range 5 {
		require.NoError(t, st.LogAuditEvent(ctx, &models.AuditEvent{
			EventType: "secret.read", Description: "e", Success: &tr, ActorType: "user", EventTime: time.Now(),
		}))
	}
	_, _, err = coreService.WriteAuditCheckpoint(ctx) // a checkpoint from before the upgrade, no verification state
	require.NoError(t, err)
	coreService.SetAuditIncrementalVerification(24*time.Hour, core.DefaultAuditFullVerificationSegments)

	h := NewAuditHandler(coreService)
	r := chi.NewRouter()
	r.Get("/api/v1/audit/verify", h.VerifyAuditChain)
	r.Get("/api/v1/audit/verify/jobs/{id}", h.GetAuditVerifyJob)
	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, withUserCtx(httptest.NewRequest(http.MethodGet, path, nil)))
		return rec
	}

	rec := get("/api/v1/audit/verify")
	require.Equal(t, http.StatusOK, rec.Code)
	d := decodeVerifyBody(t, rec)
	assert.Equal(t, false, d["valid"], "not proven is never valid")
	assert.Equal(t, core.AuditVerifyStatusNotProven, d["status"])
	assert.Equal(t, core.AuditVerifyModeIncremental, d["mode"])
	assert.NotEmpty(t, d["not_proven_reason"])
	assert.Contains(t, d, "last_full_verification_at")
	assert.Nil(t, d["last_full_verification_at"])
	assert.NotContains(t, d, "reason", "not_proven is not a break: no break reason")
	cov, ok := d["coverage"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, true, cov["tail_complete"])

	rec = get("/api/v1/audit/verify?full=true")
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	d = decodeVerifyBody(t, rec)
	id, _ := d["job_id"].(string)
	require.NotEmpty(t, id)
	assert.Equal(t, "/api/v1/audit/verify/jobs/"+id, rec.Header().Get("Location"))

	var job map[string]any
	require.Eventually(t, func() bool {
		rec := get("/api/v1/audit/verify/jobs/" + id)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		job = decodeVerifyBody(t, rec)
		return job["state"] != core.AuditVerifyJobRunning
	}, 10*time.Second, 10*time.Millisecond)
	assert.Equal(t, core.AuditVerifyJobSucceeded, job["state"])
	assert.True(t, strings.HasSuffix(job["started_at"].(string), "Z"), "times are UTC")
	res, ok := job["result"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, true, res["valid"])
	assert.Equal(t, core.AuditVerifyModeFull, res["mode"])

	d = decodeVerifyBody(t, get("/api/v1/audit/verify"))
	assert.Equal(t, core.AuditVerifyStatusValid, d["status"])
	assert.Equal(t, true, d["valid"])
	assert.Equal(t, "job", d["last_full_verification_source"])

	assert.Equal(t, http.StatusNotFound, get("/api/v1/audit/verify/jobs/nope").Code)
}

func TestAuditVerifyJob_RequiresUserContext(t *testing.T) {
	h := NewAuditHandler(core.NewKeyorixCore(store.NewLocalStorage(openTestDB(t))))
	rec := httptest.NewRecorder()
	h.GetAuditVerifyJob(rec, httptest.NewRequest(http.MethodGet, "/api/v1/audit/verify/jobs/x", nil))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// Without a signing key no job state can be kept: ?full=true answers with the
// full walk itself (200, mode "full"), never a job id that could not be read.
func TestAuditVerifyFull_WithoutSigningKeyRunsInline(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.AuditCheckpoint{}, &models.SystemMetadata{}))
	h := NewAuditHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))
	rec := httptest.NewRecorder()
	h.VerifyAuditChain(rec, withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/audit/verify?full=true", nil)))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	d := decodeVerifyBody(t, rec)
	assert.Equal(t, core.AuditVerifyModeFull, d["mode"])
	assert.Equal(t, core.AuditVerifyStatusValid, d["status"])
}
