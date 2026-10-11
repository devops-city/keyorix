package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// OTP-EXPIRY-1: POST /api/v1/users with generate_one_time_password returns the
// expiry (UTC, RFC 3339) next to the password so the admin can tell the user.
func TestCreateUserWithOTP_ReportsExpiry(t *testing.T) {
	uh, _, _ := freshUserHandlerS12(t)
	body, _ := json.Marshal(map[string]interface{}{
		"username":                   "otp-expiry",
		"email":                      "otp-expiry@x.com",
		"display_name":               "OTP Expiry",
		"generate_one_time_password": true,
	})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	before := time.Now()
	uh.CreateUser(w, req)
	after := time.Now()
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	var env struct {
		Data struct {
			OneTimePassword struct {
				Email     string `json:"email"`
				Password  string `json:"one_time_password"`
				ExpiresAt string `json:"expires_at"`
			} `json:"one_time_password"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env))
	otp := env.Data.OneTimePassword
	require.NotEmpty(t, otp.Password)
	require.NotEmpty(t, otp.ExpiresAt, "the response must tell the operator when the one-time password expires")

	exp, err := time.Parse(time.RFC3339, otp.ExpiresAt)
	require.NoError(t, err, "expires_at is RFC 3339")
	assert.Equal(t, time.UTC, exp.Location(), "expires_at is UTC")
	// Default 72h, no config in this handler fixture.
	assert.False(t, exp.Before(before.Add(72*time.Hour).Add(-time.Second)), "expiry %s", exp)
	assert.False(t, exp.After(after.Add(72*time.Hour).Add(time.Second)), "expiry %s", exp)
}
