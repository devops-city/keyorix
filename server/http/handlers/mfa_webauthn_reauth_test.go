// mfa_webauthn_reauth_test.go — #372 regression coverage: ActivateMFA,
// FinishWebAuthnRegistration and DeleteWebAuthnCredential must require a current
// TOTP code or the account password to re-authenticate the caller, exercised at
// the HTTP handler layer (request body shape + wiring through to core).
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/server/middleware"
)

const reauthTestPassword = "Secret#Passw0rd!"

// setupMFAReauthTest builds an AuthHandler over real SQLite with an enabled
// encryptor (TOTP secrets are encrypted at rest) and a WebAuthn relying party,
// seeding user id 1 = "alice" with a known password.
func setupMFAReauthTest(t *testing.T) (*AuthHandler, *core.KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"}}))

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.MFASecret{}, &models.MFARecoveryCode{},
		&models.MFAChallenge{}, &models.Session{}, &models.AuditEvent{},
		&models.WebAuthnCredential{}, &models.WebAuthnSession{},
		&models.MFAStepupToken{}, &models.MFAStepUpGrant{}))
	hash, err := bcrypt.GenerateFromPassword([]byte(reauthTestPassword), bcrypt.MinCost)
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", Email: "a@b.com",
		PasswordHash: string(hash), AccountState: "active"}).Error)

	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, t.TempDir())
	require.NoError(t, enc.Initialize("test-passphrase"))

	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	coreService.SetAuthEncryptor(enc)
	rp, err := webauthn.New(&webauthn.Config{
		RPID: "localhost", RPDisplayName: "Keyorix", RPOrigins: []string{"https://localhost"},
	})
	require.NoError(t, err)
	coreService.SetWebAuthn(rp)

	return NewAuthHandler(coreService, false), coreService, db
}

func withUserContext(r *http.Request, userID uint) *http.Request {
	userCtx := &middleware.UserContext{UserID: userID, ActorType: core.ActorTypeUser, SessionAuth: true}
	return r.WithContext(context.WithValue(r.Context(), middleware.GetUserContextKey(), userCtx))
}

func postJSON(path string, body any, userID uint) *http.Request {
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	return withUserContext(r, userID)
}

// TestActivateMFAHandler_RequiresPassword confirms the HTTP layer accepts the new
// "password" re-proof field and wires it through to core.ActivateMFA: a correct
// enrolment code with no (or a wrong) password is rejected, and the same code
// succeeds once the correct password is supplied.
func TestActivateMFAHandler_RequiresPassword(t *testing.T) {
	h, coreService, _ := setupMFAReauthTest(t)
	fixed := time.Now()

	_, secret, err := coreService.BeginMFAEnrollment(context.Background(), 1)
	require.NoError(t, err)
	code, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)

	t.Run("missing password is rejected", func(t *testing.T) {
		r := postJSON("/api/v1/auth/mfa/activate", map[string]string{"code": code}, 1)
		rr := httptest.NewRecorder()
		h.ActivateMFA(rr, r)
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("wrong password is rejected", func(t *testing.T) {
		r := postJSON("/api/v1/auth/mfa/activate", map[string]string{"code": code, "password": "wrong"}, 1)
		rr := httptest.NewRecorder()
		h.ActivateMFA(rr, r)
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("correct password succeeds", func(t *testing.T) {
		r := postJSON("/api/v1/auth/mfa/activate", map[string]string{"code": code, "password": reauthTestPassword}, 1)
		rr := httptest.NewRecorder()
		h.ActivateMFA(rr, r)
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		assert.Contains(t, rr.Body.String(), "recovery_codes")
	})
}

// TestFinishWebAuthnRegistrationHandler_RequiresReauth confirms the HTTP layer
// accepts and forwards the code/password re-proof: a request with neither is
// rejected by the core re-auth gate BEFORE the (here, deliberately invalid)
// attestation is ever evaluated — proving the wiring, not just that a garbled
// attestation fails for some other reason.
func TestFinishWebAuthnRegistrationHandler_RequiresReauth(t *testing.T) {
	h, coreService, _ := setupMFAReauthTest(t)
	ctx := context.Background()

	_, sessionToken, err := coreService.BeginWebAuthnRegistration(ctx, 1)
	require.NoError(t, err)

	body := map[string]any{
		"webauthn_session": sessionToken,
		"name":             "laptop",
		// Structurally valid so the request clears attestation parsing and
		// actually reaches core's re-auth gate — a garbled blob like `{}` would
		// fail at protocol.ParseCredentialCreationResponseBytes and never
		// exercise the wiring under test (the values are a well-known
		// go-webauthn fixture; cryptographic correctness is irrelevant here).
		"credential": json.RawMessage(validCredentialCreationResponseJSON),
	}
	r := postJSON("/api/v1/auth/webauthn/register/finish", body, 1)
	rr := httptest.NewRecorder()
	h.FinishWebAuthnRegistration(rr, r)
	require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
	// The failure must be the re-auth gate (core.requireReauth), not attestation
	// parsing — proving re-auth is checked first, before any ceremony data is
	// touched.
	assert.Contains(t, rr.Body.String(), "invalid code or password")
}

// validCredentialCreationResponseJSON is a structurally-valid WebAuthn
// PublicKeyCredential JSON blob (borrowed verbatim from go-webauthn's own
// protocol test suite, credential_test.go's "success" fixture) — enough to
// clear protocol.ParseCredentialCreationResponseBytes so a handler test can
// reach the code under test past attestation parsing. Not a real credential.
const validCredentialCreationResponseJSON = `{
	"id":"6xrtBhJQW6QU4tOaB4rrHaS2Ks0yDDL_q8jDC16DEjZ-VLVf4kCRkvl2xp2D71sTPYns-exsHQHTy3G-zJRK8g",
	"rawId":"6xrtBhJQW6QU4tOaB4rrHaS2Ks0yDDL_q8jDC16DEjZ-VLVf4kCRkvl2xp2D71sTPYns-exsHQHTy3G-zJRK8g",
	"type":"public-key",
	"authenticatorAttachment":"platform",
	"clientExtensionResults":{
		"appid":true
	},
	"response":{
		"attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEdKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQOsa7QYSUFukFOLTmgeK6x2ktirNMgwy_6vIwwtegxI2flS1X-JAkZL5dsadg-9bEz2J7PnsbB0B08txvsyUSvKlAQIDJiABIVggLKF5xS0_BntttUIrm2Z2tgZ4uQDwllbdIfrrBMABCNciWCDHwin8Zdkr56iSIh0MrB5qZiEzYLQpEOREhMUkY6q4Vw",
		"clientDataJSON":"eyJjaGFsbGVuZ2UiOiJXOEd6RlU4cEdqaG9SYldyTERsYW1BZnFfeTRTMUNaRzFWdW9lUkxBUnJFIiwib3JpZ2luIjoiaHR0cHM6Ly93ZWJhdXRobi5pbyIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ",
		"transports":["usb","nfc","fake"]
	}
}`

// TestDeleteWebAuthnCredentialHandler_RequiresReauth confirms the DELETE handler
// accepts code/password in the body and rejects the deletion without a valid one,
// even for the credential's rightful owner — a leaked bearer alone must not be
// able to wipe passkeys.
func TestDeleteWebAuthnCredentialHandler_RequiresReauth(t *testing.T) {
	h, _, db := setupMFAReauthTest(t)

	blob, _ := json.Marshal(webauthn.Credential{ID: []byte("cred-1")})
	require.NoError(t, db.Create(&models.WebAuthnCredential{
		UserID: 1, CredentialID: []byte("cred-1"), Name: "test key", CredentialBlob: blob,
	}).Error)
	var cred models.WebAuthnCredential
	require.NoError(t, db.Where("user_id = ?", 1).First(&cred).Error)
	credIDParam := fmt.Sprint(cred.ID)

	deleteReq := func(body any) *httptest.ResponseRecorder {
		var r *http.Request
		if body == nil {
			r = httptest.NewRequest(http.MethodDelete, "/api/v1/auth/webauthn/credentials/"+credIDParam, nil)
		} else {
			b, _ := json.Marshal(body)
			r = httptest.NewRequest(http.MethodDelete, "/api/v1/auth/webauthn/credentials/"+credIDParam, bytes.NewReader(b))
		}
		r = withUserContext(r, 1)
		r = withChiParams(r, map[string]string{"id": credIDParam})
		rr := httptest.NewRecorder()
		h.DeleteWebAuthnCredential(rr, r)
		return rr
	}

	t.Run("no body is rejected", func(t *testing.T) {
		rr := deleteReq(nil)
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("wrong password is rejected", func(t *testing.T) {
		rr := deleteReq(map[string]string{"password": "wrong"})
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("correct password succeeds", func(t *testing.T) {
		rr := deleteReq(map[string]string{"password": reauthTestPassword})
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	})
}
