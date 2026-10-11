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

// TestContractRecover1_ChangePassword: POST /api/v1/auth/change-password's 200
// matches openapi.yaml, including data.reauthentication_required (#3024).
func TestContractRecover1_ChangePassword(t *testing.T) {
	h, _, _ := setupMFAReauthTest(t)

	body, _ := json.Marshal(map[string]string{"current_password": reauthTestPassword, "new_password": "Fresh#Contract-Passw0rd-42"})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/change-password", bytes.NewReader(body))
	r = withUserContext(r, 1)
	w := httptest.NewRecorder()
	h.ChangePassword(w, r)

	contracttest.AssertOpenAPIResponse(t, r, w)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var env struct {
		Data struct {
			ReauthenticationRequired *bool `json:"reauthentication_required"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env))
	require.NotNil(t, env.Data.ReauthenticationRequired)
	require.False(t, *env.Data.ReauthenticationRequired, "an ordinary password change keeps the session")
}
