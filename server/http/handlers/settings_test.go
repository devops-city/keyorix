package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── MakeAuthConfigHandler ────────────────────────────────────────────────

func TestMakeAuthConfigHandler_Unauthenticated(t *testing.T) {
	cfg := &config.Config{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/auth-config", nil)
	rr := httptest.NewRecorder()
	MakeAuthConfigHandler(cfg)(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestMakeAuthConfigHandler_Authenticated(t *testing.T) {
	cfg := &config.Config{}
	req := userCtxForTest(httptest.NewRequest(http.MethodGet, "/api/v1/system/auth-config", nil))
	rr := httptest.NewRecorder()
	MakeAuthConfigHandler(cfg)(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	var resp map[string]any
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.True(t, resp["success"].(bool), "response must carry success:true")

	data, ok := resp["data"].(map[string]any)
	require.True(t, ok, "data field must be a JSON object")
	assert.Contains(t, data, "session")
	assert.Contains(t, data, "password_policy")
	assert.Contains(t, data, "login_lockout")
	assert.Contains(t, data, "require_mfa")
	assert.Contains(t, data, "webauthn")
	assert.Contains(t, data, "sso")
}

func TestMakeAuthConfigHandler_ReflectsConfig(t *testing.T) {
	cfg := &config.Config{}
	cfg.PasswordPolicy.MinLength = config.IntPtr(16)
	cfg.PasswordPolicy.RequireUppercase = config.BoolPtr(true)
	cfg.Security.RequireMFA = true
	cfg.Security.LoginLockout.Disabled = true
	cfg.Session.AccessTTL = "30m"
	cfg.WebAuthn.Enabled = true
	cfg.WebAuthn.RPID = "keyorix.example.com"

	req := userCtxForTest(httptest.NewRequest(http.MethodGet, "/api/v1/system/auth-config", nil))
	rr := httptest.NewRecorder()
	MakeAuthConfigHandler(cfg)(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	var resp map[string]any
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	data := resp["data"].(map[string]any)

	passwordPolicy := data["password_policy"].(map[string]any)
	assert.Equal(t, float64(16), passwordPolicy["min_length"])
	assert.Equal(t, true, passwordPolicy["require_uppercase"])

	assert.Equal(t, true, data["require_mfa"])

	loginLockout := data["login_lockout"].(map[string]any)
	assert.Equal(t, false, loginLockout["enabled"], "Disabled: true must resolve to enabled: false")

	session := data["session"].(map[string]any)
	assert.Equal(t, "30m0s", session["access_ttl"])

	webauthn := data["webauthn"].(map[string]any)
	assert.Equal(t, true, webauthn["enabled"])
	assert.Equal(t, "keyorix.example.com", webauthn["rp_id"])
}

func TestMakeAuthConfigHandler_LoginLockoutDefaultsToEnabled(t *testing.T) {
	cfg := &config.Config{} // Disabled left at its zero value (false) — lockout is on by default.
	req := userCtxForTest(httptest.NewRequest(http.MethodGet, "/api/v1/system/auth-config", nil))
	rr := httptest.NewRecorder()
	MakeAuthConfigHandler(cfg)(rr, req)

	var resp map[string]any
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	data := resp["data"].(map[string]any)
	loginLockout := data["login_lockout"].(map[string]any)
	assert.Equal(t, true, loginLockout["enabled"])
	assert.Equal(t, float64(5), loginLockout["max_attempts"], "must reflect the GetMaxAttempts() default")
}

func TestMakeAuthConfigHandler_NeverLeaksSecrets(t *testing.T) {
	cfg := &config.Config{}
	cfg.SSO.Enabled = true
	cfg.SSO.Providers = []config.SSOProviderConfig{
		{
			Name:         "okta",
			Type:         "oidc",
			Issuer:       "https://example.okta.com",
			ClientID:     "the-client-id",
			ClientSecret: "super-secret-client-value",
			RedirectURL:  "https://keyorix.example.com/auth/sso/callback",
			SAML: &config.SAMLProviderConfig{
				IDPMetadataXML: "<EntityDescriptor>fake-signing-cert-blob</EntityDescriptor>",
			},
		},
	}

	req := userCtxForTest(httptest.NewRequest(http.MethodGet, "/api/v1/system/auth-config", nil))
	rr := httptest.NewRecorder()
	MakeAuthConfigHandler(cfg)(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	body := rr.Body.String()
	assert.NotContains(t, body, "super-secret-client-value")
	assert.NotContains(t, body, "the-client-id")
	assert.NotContains(t, body, "https://example.okta.com")
	assert.NotContains(t, body, "https://keyorix.example.com/auth/sso/callback")
	assert.NotContains(t, body, "fake-signing-cert-blob")

	// The safe fields must still be present, so this isn't just an empty response.
	assert.Contains(t, body, "\"name\":\"okta\"")
	assert.Contains(t, body, "\"type\":\"oidc\"")
}

// ── MakeEncryptionConfigHandler ──────────────────────────────────────────

func TestMakeEncryptionConfigHandler_Unauthenticated(t *testing.T) {
	cfg := &config.Config{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/encryption-config", nil)
	rr := httptest.NewRecorder()
	MakeEncryptionConfigHandler(cfg)(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestMakeEncryptionConfigHandler_Authenticated(t *testing.T) {
	cfg := &config.Config{}
	req := userCtxForTest(httptest.NewRequest(http.MethodGet, "/api/v1/system/encryption-config", nil))
	rr := httptest.NewRecorder()
	MakeEncryptionConfigHandler(cfg)(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	var resp map[string]any
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.True(t, resp["success"].(bool))

	data, ok := resp["data"].(map[string]any)
	require.True(t, ok)
	assert.Contains(t, data, "enabled")
	assert.Contains(t, data, "key_provider")
}

func TestMakeEncryptionConfigHandler_ReflectsConfig(t *testing.T) {
	cfg := &config.Config{}
	cfg.Storage.Encryption.Enabled = true
	cfg.Storage.Encryption.KeyProvider.Type = "aws-kms"
	cfg.Storage.Encryption.KeyProvider.ShamirCommitment = "deadbeef"
	cfg.Storage.Encryption.KeyProvider.Fallbacks = []config.KeyProviderConfig{{Type: "password"}}

	req := userCtxForTest(httptest.NewRequest(http.MethodGet, "/api/v1/system/encryption-config", nil))
	rr := httptest.NewRecorder()
	MakeEncryptionConfigHandler(cfg)(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	var resp map[string]any
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	data := resp["data"].(map[string]any)
	assert.Equal(t, true, data["enabled"])

	keyProvider := data["key_provider"].(map[string]any)
	assert.Equal(t, "aws-kms", keyProvider["type"])
	assert.Equal(t, "deadbeef", keyProvider["shamir_commitment"])
	assert.Equal(t, float64(1), keyProvider["fallback_count"])
}

func TestMakeEncryptionConfigHandler_NeverLeaksSecrets(t *testing.T) {
	cfg := &config.Config{}
	cfg.Storage.Encryption.Enabled = true
	cfg.Storage.Encryption.DEKPath = "/var/lib/keyorix/dek.bin"
	cfg.Storage.Encryption.SaltPath = "/var/lib/keyorix/salt.bin"
	cfg.Storage.Encryption.KeyProvider = config.KeyProviderConfig{
		Type:           "exec",
		FilePath:       "/etc/keyorix/kek.key",
		EnvVar:         "KEYORIX_KEK_MATERIAL",
		WrappedKeyPath: "/var/lib/keyorix/wrapped-kek.bin",
		ExecCommand:    []string{"op", "read", "op://vault/kek/value"},
		KMSKeyID:       "arn:aws:kms:us-east-1:123456789012:key/abc-def",
		TPMDevice:      "/dev/tpmrm0",
	}

	req := userCtxForTest(httptest.NewRequest(http.MethodGet, "/api/v1/system/encryption-config", nil))
	rr := httptest.NewRecorder()
	MakeEncryptionConfigHandler(cfg)(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	body := rr.Body.String()
	assert.NotContains(t, body, "/var/lib/keyorix/dek.bin")
	assert.NotContains(t, body, "/var/lib/keyorix/salt.bin")
	assert.NotContains(t, body, "/etc/keyorix/kek.key")
	assert.NotContains(t, body, "KEYORIX_KEK_MATERIAL")
	assert.NotContains(t, body, "/var/lib/keyorix/wrapped-kek.bin")
	assert.NotContains(t, body, "op://vault/kek/value")
	assert.NotContains(t, body, "arn:aws:kms:us-east-1:123456789012:key/abc-def")
	assert.NotContains(t, body, "/dev/tpmrm0")

	// The safe field must still be present.
	assert.Contains(t, body, "\"type\":\"exec\"")
}
