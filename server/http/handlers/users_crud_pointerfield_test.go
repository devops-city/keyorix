package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/server/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUpdateUser_PointerFieldValidation is a regression guard for #347 HIGH's
// secondary instance: UpdateUser's Email/Username/DisplayName are all
// pointer-typed (*string) so a caller can distinguish "not provided" (nil,
// leave unchanged) from "explicitly set" (non-nil). Before the fix, the
// validator's Kind()-based rule dispatch (validateEmail/validateMin/
// validateMax) silently no-op'd for any pointer Kind, so a malformed email,
// too-short username, or too-long display_name all passed clean.
func TestUpdateUser_PointerFieldValidation(t *testing.T) {
	require.NoError(t, i18n.Initialize(&config.Config{Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"}}))

	handler, err := NewUserHandler(nil)
	require.NoError(t, err)

	userCtx := &middleware.UserContext{UserID: 1, Username: "alice", ActorType: core.ActorTypeUser, SessionAuth: true}

	put := func(body map[string]any) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		r := httptest.NewRequest(http.MethodPut, "/api/v1/users/2", bytes.NewReader(raw))
		r = r.WithContext(context.WithValue(r.Context(), middleware.GetUserContextKey(), userCtx))
		rc := chi.NewRouteContext()
		rc.URLParams.Add("id", "2")
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rc))
		rr := httptest.NewRecorder()
		handler.UpdateUser(rr, r)
		return rr
	}

	t.Run("malformed email is rejected", func(t *testing.T) {
		rr := put(map[string]any{"email": "not-an-email <script>"})
		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "ValidationError")
	})

	t.Run("too-short username is rejected", func(t *testing.T) {
		rr := put(map[string]any{"username": "ab"})
		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "ValidationError")
	})

	t.Run("too-long display_name is rejected", func(t *testing.T) {
		rr := put(map[string]any{"display_name": strings.Repeat("a", 101)})
		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "ValidationError")
	})
}
