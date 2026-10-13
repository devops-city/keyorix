package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// #3155: the login response and GET /auth/profile tell the client which setup
// steps the session still owes, so it can route to the MFA page without
// rendering protected pages (and without the 403s that discovering the
// confinement through them costs). The field only reports the gate's state.

func TestLoginResponse_PendingSteps(t *testing.T) {
	session := &models.Session{SessionToken: "tok"}
	cases := []struct {
		name       string
		requireMFA bool
		user       models.User
		want       []string
	}{
		{"require_mfa off, no second factor: nothing owed", false, models.User{AccountState: "active"}, nil},
		{"require_mfa on, no second factor: enroll_mfa", true, models.User{AccountState: "active"}, []string{core.SetupStepEnrollMFA}},
		{"require_mfa on, TOTP enrolled: nothing owed", true, models.User{AccountState: "active", MFAEnabled: true}, nil},
		{"require_mfa on, passkey enrolled: nothing owed", true, models.User{AccountState: "active", WebAuthnEnabled: true}, nil},
		{"require_mfa on, restricted and no factor: both, password first", true,
			models.User{AccountState: core.AccountPendingFirstLogin},
			[]string{core.SetupStepChangePassword, core.SetupStepEnrollMFA}},
		{"require_mfa off, restricted: change_password only", false,
			models.User{AccountState: core.AccountPendingFirstLogin},
			[]string{core.SetupStepChangePassword}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := core.NewKeyorixCore(nil)
			c.SetRequireMFA(tc.requireMFA)
			h := NewAuthHandler(c, false)
			resp := h.loginResponseFromIdentity(session, &tc.user, core.UserIdentity{})
			assert.Equal(t, tc.want, resp.PendingSteps)

			raw, err := json.Marshal(resp)
			require.NoError(t, err)
			var m map[string]any
			require.NoError(t, json.Unmarshal(raw, &m))
			if tc.want == nil {
				assert.NotContains(t, m, "pending_steps", "an unconfined session must not carry the field")
			} else {
				assert.Contains(t, m, "pending_steps")
			}
		})
	}
}

func TestProfile_PendingSteps(t *testing.T) {
	cs := freshCoreS8(t)
	bootstrapS8(t, cs, "pendingsteps")
	user, err := cs.GetUserByUsername(context.Background(), "s8pendingsteps")
	require.NoError(t, err)
	h := NewAuthHandler(cs, false)

	profile := func(uc *middleware.UserContext) map[string]any {
		req := httptest.NewRequest(http.MethodGet, "/auth/profile", nil)
		req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), uc))
		w := httptest.NewRecorder()
		h.Profile(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		var body struct {
			Data map[string]any `json:"data"`
		}
		require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
		return body.Data
	}

	cs.SetRequireMFA(true)
	t.Cleanup(func() { cs.SetRequireMFA(false) })

	t.Run("interactive session without a second factor owes enroll_mfa", func(t *testing.T) {
		got := profile(&middleware.UserContext{UserID: user.ID, Username: user.Username, SessionAuth: true})
		assert.Equal(t, []any{core.SetupStepEnrollMFA}, got["pending_steps"])
	})
	t.Run("a second factor clears it", func(t *testing.T) {
		got := profile(&middleware.UserContext{UserID: user.ID, Username: user.Username, SessionAuth: true, MFAEnabled: true})
		assert.NotContains(t, got, "pending_steps")
	})
	t.Run("a PAT / machine credential is exempt (ADR-112)", func(t *testing.T) {
		got := profile(&middleware.UserContext{UserID: user.ID, Username: user.Username, SessionAuth: false})
		assert.NotContains(t, got, "pending_steps")
	})
	t.Run("a restricted account owes change_password", func(t *testing.T) {
		got := profile(&middleware.UserContext{UserID: user.ID, Username: user.Username, SessionAuth: true, MFAEnabled: true, Restricted: true})
		assert.Equal(t, []any{core.SetupStepChangePassword}, got["pending_steps"])
	})
	t.Run("require_mfa off: nothing owed", func(t *testing.T) {
		cs.SetRequireMFA(false)
		defer cs.SetRequireMFA(true)
		got := profile(&middleware.UserContext{UserID: user.ID, Username: user.Username, SessionAuth: true})
		assert.NotContains(t, got, "pending_steps")
	})
}
