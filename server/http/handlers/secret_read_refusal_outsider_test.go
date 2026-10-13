package handlers

// secret_read_refusal_outsider_test.go — FIX-3175B, follow-up to ERRMAP-1 (#3175).
//
// The route-level family test (server/http, secret_value_read_refusal_family_test.go)
// only exercises outsiders that the ROUTE gate stops, so a secret-state guard that
// ran before the per-secret permission check inside core would never be noticed
// there (mutation shown in the #3175 review). These tests call the handlers
// directly, which is exactly "a principal that passed the route gate": the route
// middleware is not in the way, so the only thing between the outsider and a
// state-naming answer is the per-secret check in core.
//
// For every value-disclosing handler and every secret-state refusal that has a
// wire answer (suspended, expired, outside the access schedule) the outsider's
// answer for the refused secret must be exactly its answer for the same secret
// before the state applied: status, error code and message. For render, whose
// reference resolution collapses "missing" and "forbidden" by design, it must
// also equal the answer for a reference to a secret that does not exist.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// refusalWire is the part of a response a client can branch on.
type refusalWire struct {
	Status  int
	Error   string
	Message string
}

func wireOf(t *testing.T, rec *httptest.ResponseRecorder) refusalWire {
	t.Helper()
	var env struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &env)
	return refusalWire{Status: rec.Code, Error: env.Error, Message: env.Message}
}

type outsiderWorld struct {
	h  *SecretHandler
	db *gorm.DB
}

const (
	outsiderUserID  = 99
	outsiderProject = 1
	outsiderEnvName = "prod"
)

func newOutsiderWorld(t *testing.T) *outsiderWorld {
	t.Helper()
	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.Project{ID: outsiderProject, Name: "outsider-proj"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: outsiderProject, Name: outsiderEnvName}).Error)
	return &outsiderWorld{h: h, db: db}
}

// seed creates an active certificate secret owned by someone else (user 999), so
// neither user 99 (no roles, no share) nor anyone but admin user 1 may read it.
func (w *outsiderWorld) seed(t *testing.T, name string) *models.SecretNode {
	t.Helper()
	sec := &models.SecretNode{
		Name: name, IsSecret: true, Status: "active", Type: "certificate",
		OwnerID: 999, ProjectID: outsiderProject, EnvironmentID: 1,
	}
	require.NoError(t, w.db.Create(sec).Error)
	require.NoError(t, w.db.Create(&models.SecretVersion{
		SecretNodeID: sec.ID, VersionNumber: 1, EncryptedValue: selfSignedCertPEMS13(t),
	}).Error)
	return sec
}

type outsiderState struct {
	name  string
	code  string // wire code an AUTHORIZED reader gets
	apply func(t *testing.T, w *outsiderWorld, sec *models.SecretNode)
}

func outsiderStates() []outsiderState {
	return []outsiderState{
		{"suspended", core.SecretReadRefusalCodeSuspended, func(t *testing.T, w *outsiderWorld, sec *models.SecretNode) {
			require.NoError(t, w.db.Model(&models.SecretNode{}).Where("id = ?", sec.ID).Update("status", core.SecretStatusSuspended).Error)
		}},
		{"expired", core.SecretReadRefusalCodeExpired, func(t *testing.T, w *outsiderWorld, sec *models.SecretNode) {
			var row models.SecretNode
			require.NoError(t, w.db.First(&row, sec.ID).Error)
			past := time.Now().UTC().Add(-time.Hour)
			row.Expiration = &past
			require.NoError(t, w.db.Save(&row).Error) // Save so SecretNode's BeforeSave hook runs
		}},
		{"outside schedule", core.SecretReadRefusalCodeOutsideSchedule, func(t *testing.T, w *outsiderWorld, sec *models.SecretNode) {
			require.NoError(t, w.db.Create(&models.SecretAccessSchedule{
				SecretNodeID: sec.ID, AllowedDays: "*", StartHour: 0, EndHour: 0, Timezone: "UTC",
			}).Error)
		}},
	}
}

type outsiderRoute struct {
	name string
	// call serves the handler as userID for sec (whose row is passed so by-ref can
	// pin it on the context the way RequireScopedSecretRefPermission does).
	call func(t *testing.T, w *outsiderWorld, userID uint, username string, sec *models.SecretNode) *httptest.ResponseRecorder
	// missing serves the same handler for a secret that does not exist, or nil
	// when the handler cannot be asked that (by-ref needs a resolved row).
	missing func(w *outsiderWorld, userID uint, username string) *httptest.ResponseRecorder
	// uniform: the handler deliberately answers identically for "missing" and
	// "exists but forbidden" (render), so the outsider answer must equal missing.
	uniform bool
}

func asUserOW(r *http.Request, userID uint, username string) *http.Request {
	if userID == 1 {
		return withUserCtx(r)
	}
	return withUserCtxID2(r, userID, username)
}

func outsiderRoutes() []outsiderRoute {
	return []outsiderRoute{
		{
			name: "GET /secrets/{id}?include_value=true",
			call: func(t *testing.T, w *outsiderWorld, uid uint, un string, sec *models.SecretNode) *httptest.ResponseRecorder {
				req := asUserOW(withChiParam(httptest.NewRequest(http.MethodGet, "/?include_value=true", nil), "id", fmt.Sprint(sec.ID)), uid, un)
				rec := httptest.NewRecorder()
				w.h.GetSecret(rec, req)
				return rec
			},
			missing: func(w *outsiderWorld, uid uint, un string) *httptest.ResponseRecorder {
				req := asUserOW(withChiParam(httptest.NewRequest(http.MethodGet, "/?include_value=true", nil), "id", "987654"), uid, un)
				rec := httptest.NewRecorder()
				w.h.GetSecret(rec, req)
				return rec
			},
		},
		{
			name: "GET /secrets/value?ref=",
			call: func(t *testing.T, w *outsiderWorld, uid uint, un string, sec *models.SecretNode) *httptest.ResponseRecorder {
				req := asUserOW(httptest.NewRequest(http.MethodGet, "/", nil), uid, un)
				// The route gate resolves the secret and pins it; fetch it fresh so the
				// state under test is the one the handler sees.
				var row models.SecretNode
				require.NoError(t, w.db.First(&row, sec.ID).Error)
				req = req.WithContext(middleware.WithResolvedSecretRef(req.Context(), &row))
				rec := httptest.NewRecorder()
				w.h.GetSecretValueByRef(rec, req)
				return rec
			},
		},
		{
			name: "GET /secrets/{id}/certificate",
			call: func(t *testing.T, w *outsiderWorld, uid uint, un string, sec *models.SecretNode) *httptest.ResponseRecorder {
				req := asUserOW(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", fmt.Sprint(sec.ID)), uid, un)
				rec := httptest.NewRecorder()
				w.h.GetSecretCertificate(rec, req)
				return rec
			},
			missing: func(w *outsiderWorld, uid uint, un string) *httptest.ResponseRecorder {
				req := asUserOW(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "987654"), uid, un)
				rec := httptest.NewRecorder()
				w.h.GetSecretCertificate(rec, req)
				return rec
			},
		},
		{
			name: "POST /projects/{id}/secrets/render",
			call: func(t *testing.T, w *outsiderWorld, uid uint, un string, sec *models.SecretNode) *httptest.ResponseRecorder {
				return w.render(uid, un, sec.Name)
			},
			missing: func(w *outsiderWorld, uid uint, un string) *httptest.ResponseRecorder {
				return w.render(uid, un, "no-such-secret")
			},
			uniform: true,
		},
	}
}

func (w *outsiderWorld) render(uid uint, un, secretName string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"template": "${secret:" + outsiderEnvName + "/" + secretName + "}"})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = asUserOW(withChiParam(req, "id", fmt.Sprint(outsiderProject)), uid, un)
	rec := httptest.NewRecorder()
	w.h.RenderTemplate(rec, req)
	return rec
}

func TestSecretReadRefusals_OutsiderPastRouteGateLearnsNothing(t *testing.T) {
	w := newOutsiderWorld(t)
	n := 0
	for _, route := range outsiderRoutes() {
		for _, st := range outsiderStates() {
			t.Run(route.name+"/"+st.name, func(t *testing.T) {
				n++
				sec := w.seed(t, fmt.Sprintf("outsider-secret-%d", n))

				// Known-good first: the outsider is refused for lack of access, not
				// because the fixture is broken, and the owner-less admin can still
				// reach the secret (so the state below is what changes the admin's answer).
				before := wireOf(t, route.call(t, w, outsiderUserID, "outsider", sec))
				require.GreaterOrEqual(t, before.Status, 400, "precondition: outsider must not read the secret (got %+v)", before)
				require.NotContains(t, []string{
					core.SecretReadRefusalCodeSuspended, core.SecretReadRefusalCodeExpired,
					core.SecretReadRefusalCodeOutsideSchedule, core.SecretReadRefusalCodeMaxReadsExhausted,
				}, before.Error, "precondition: no state applied yet")

				st.apply(t, w, sec)

				// The authorized reader (global admin, user 1) sees the stable code: the
				// state really is refusing reads, so the outsider assertion is not vacuous.
				admin := wireOf(t, route.call(t, w, 1, "testuser", sec))
				assert.Equal(t, st.code, admin.Error, "an authorized reader must get the refusal code (got %+v)", admin)

				after := wireOf(t, route.call(t, w, outsiderUserID, "outsider", sec))
				assert.Equal(t, before, after, "the secret's state changed what a caller without read access sees")
				assert.NotEqual(t, http.StatusConflict, after.Status, "outsider got a secret-state status")
				assert.NotContains(t, []string{
					core.SecretReadRefusalCodeSuspended, core.SecretReadRefusalCodeExpired,
					core.SecretReadRefusalCodeOutsideSchedule, core.SecretReadRefusalCodeMaxReadsExhausted,
				}, after.Error, "outsider got a secret-state code")

				if route.uniform && route.missing != nil {
					assert.Equal(t, wireOf(t, route.missing(w, outsiderUserID, "outsider")), after,
						"the outsider's answer must equal the answer for a secret that does not exist")
				}
			})
		}
	}
}
