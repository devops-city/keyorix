package http

// break_glass_degraded_test.go — BREAKGLASS-OWED-1 over the real router: with the
// audit log refusing every write (a SQLite trigger, as an attacker with database
// access or a broken audit subsystem would leave it), POST
// /api/v1/projects/{id}/break-glass still answers 201, with the activation marked
// degraded and short-lived; an administrator sees it in GET /api/v1/system/info
// (security.break_glass_degraded); with the owed-record table refusing writes too
// the answer is 503 BreakGlassUnrecordable naming recover-admin and nothing is
// granted; and once the audit log recovers the backfill settles it.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestBreakGlass_DegradedOverTheRouter(t *testing.T) {
	d := newShareDemo(t)
	ctx := context.Background()
	d.c.SetBreakGlassPolicy(core.BreakGlassPolicy{Enabled: true, EmergencyRole: "project_developer", DefaultTTL: time.Hour, MaxTTL: 4 * time.Hour})
	require.NoError(t, d.c.AddProjectMember(ctx, d.adminID, d.projectID, d.bobID, "project_viewer", false))
	sess, _, err := d.c.Login(ctx, &core.LoginRequest{Username: "bob", Password: shareDemoPassword})
	require.NoError(t, err)
	bobTok := sess.SessionToken
	db := d.c.Storage().(interface{ DB() *gorm.DB }).DB()

	activate := func(tok string) (int, string) {
		body := []byte(`{"justification":"production outage, paging incident commander now","ttl":"4h"}`)
		return doMachineRequest(t, d.srv, tok, http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/break-glass", d.projectID), body)
	}
	type degradedStatus struct {
		Unsettled     int64  `json:"unsettled"`
		Unreviewed    int64  `json:"unreviewed"`
		ActivationIDs []uint `json:"activation_ids"`
	}
	status := func() *degradedStatus {
		code, raw := doMachineRequest(t, d.srv, d.adminTok, http.MethodGet, "/api/v1/system/info", nil)
		require.Equal(t, http.StatusOK, code, raw)
		var env struct {
			Data struct {
				Security struct {
					BreakGlassDegraded *degradedStatus `json:"break_glass_degraded"`
				} `json:"security"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal([]byte(raw), &env), raw)
		require.NotNil(t, env.Data.Security.BreakGlassDegraded, "an administrator must see break_glass_degraded: %s", raw)
		return env.Data.Security.BreakGlassDegraded
	}
	require.Zero(t, status().Unsettled)

	require.NoError(t, db.Exec(`CREATE TRIGGER bgd_refuse_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END`).Error)

	code, raw := activate(d.aliceTok)
	require.Equal(t, http.StatusCreated, code, "break-glass must work while the audit log refuses writes: %s", raw)
	var created struct {
		Data struct {
			Activation struct {
				ID        uint      `json:"id"`
				Degraded  bool      `json:"degraded"`
				CreatedAt time.Time `json:"created_at"`
				ExpiresAt time.Time `json:"expires_at"`
			} `json:"activation"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal([]byte(raw), &created), raw)
	a := created.Data.Activation
	assert.True(t, a.Degraded, "the response says it is degraded: %s", raw)
	assert.WithinDuration(t, a.CreatedAt.Add(15*time.Minute), a.ExpiresAt, time.Second, "a 4h request is cut to 15 minutes")
	st := status()
	assert.Equal(t, int64(1), st.Unsettled)
	assert.Equal(t, int64(1), st.Unreviewed)
	assert.Equal(t, []uint{a.ID}, st.ActivationIDs)

	require.NoError(t, db.Exec(`CREATE TRIGGER bgd_refuse_owed BEFORE INSERT ON pending_audit_events BEGIN SELECT RAISE(ABORT, 'owed table unavailable'); END`).Error)
	code, raw = activate(bobTok)
	require.Equal(t, http.StatusServiceUnavailable, code, raw)
	assert.Contains(t, raw, "BreakGlassUnrecordable")
	assert.Contains(t, raw, "recover-admin", "the refusal points to the offline recover-admin procedure")
	assert.NotContains(t, raw, "owed table unavailable", "no driver text reaches the client")
	var n int64
	require.NoError(t, db.Model(&models.BreakGlassActivation{}).Where("user_id = ?", d.bobID).Count(&n).Error)
	assert.Zero(t, n, "nothing granted")

	require.NoError(t, db.Exec(`DROP TRIGGER bgd_refuse_owed`).Error)
	require.NoError(t, db.Exec(`DROP TRIGGER bgd_refuse_audit`).Error)
	wrote, err := d.c.BackfillPendingAuditEvents(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, wrote, "role.assigned and break_glass.activated")
	st = status()
	assert.Zero(t, st.Unsettled, "settled once its rows are in the chain")
	assert.Equal(t, int64(1), st.Unreviewed, "the review is still owed")
}
