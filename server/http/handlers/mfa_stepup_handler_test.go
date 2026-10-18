// mfa_stepup_handler_test.go — HTTP handler tests for POST /api/v1/auth/mfa/stepup.
package handlers

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

const stepUpTestPassword = "Secret#Passw0rd!"

// setupMFAStepUpTest builds an AuthHandler over real SQLite with an enabled encryptor
// (TOTP secrets are encrypted at rest), seeding user id 1 = "alice" with a known password.
func setupMFAStepUpTest(t *testing.T) (*AuthHandler, *core.KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"}}))

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.MFASecret{}, &models.MFARecoveryCode{},
		&models.MFAChallenge{}, &models.Session{}, &models.AuditEvent{},
		&models.MFAStepupToken{}, &models.MFAStepUpGrant{},
	))
	hash, err := bcrypt.GenerateFromPassword([]byte(stepUpTestPassword), bcrypt.MinCost)
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", Email: "a@b.com",
		PasswordHash: string(hash), AccountState: "active"}).Error)

	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, t.TempDir())
	require.NoError(t, enc.Initialize("test-passphrase"))

	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	coreService.SetAuthEncryptor(enc)

	return NewAuthHandler(coreService, false), coreService, db
}

// activateMFAForStepUpTest enrolls and activates MFA for user 1, returning the base32
// secret and initial recovery codes. It reads the core's own clock (the one ActivateMFA
// validates against) and retries on a fresh step if a 30 s TOTP step boundary passed
// between generating the code and submitting it (#3352): the code is the PREVIOUS step,
// so a boundary in that gap leaves it two steps behind the server's ±1 window and the
// activation fails "invalid code". Test helper only; the handlers are unchanged.
func activateMFAForStepUpTest(t *testing.T, coreService *core.KeyorixCore) (secret string, codes []string) {
	t.Helper()
	secret, codes, err := activateMFAWithRetry(context.Background(), coreService, coreService.EffectiveNow, nil, stepUpActivateAttempts)
	require.NoError(t, err)
	return secret, codes
}

// stepUpActivateAttempts bounds the retry: one boundary can pass in a test, two in a row
// only if the process stalls for a whole step.
const stepUpActivateAttempts = 3

// activateMFAWithRetry is activateMFAForStepUpTest with an injectable clock. now supplies
// the instant the code is generated for (the core's clock in production use). afterGenerate,
// when non-nil, runs between generating and submitting each attempt -- the window in which
// a step boundary can pass; tests use it to force the boundary with a fake clock. Only an
// "invalid code" result is retried; attempts <= 1 reproduces the pre-#3352 helper.
func activateMFAWithRetry(ctx context.Context, coreService *core.KeyorixCore, now func() time.Time, afterGenerate func(attempt int), attempts int) (secret string, codes []string, err error) {
	_, secret, err = coreService.BeginMFAEnrollment(ctx, 1)
	if err != nil {
		return "", nil, err
	}
	for attempt := 1; ; attempt++ {
		// Activate using the previous step so the current step remains available for test calls.
		actCode, gerr := totp.GenerateCode(secret, now().Add(-30*time.Second))
		if gerr != nil {
			return "", nil, gerr
		}
		if afterGenerate != nil {
			afterGenerate(attempt)
		}
		codes, err = coreService.ActivateMFA(ctx, 1, actCode, stepUpTestPassword, "")
		if err == nil {
			return secret, codes, nil
		}
		if attempt >= attempts || err.Error() != "invalid code" {
			return "", nil, err
		}
	}
}

// TestMFAStepUpHandler_NoUserContext_Unauthorized verifies that a request without
// a user context is rejected with 401.
func TestMFAStepUpHandler_NoUserContext_Unauthorized(t *testing.T) {
	h, _, _ := setupMFAStepUpTest(t)

	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/stepup",
		bytes.NewBufferString(`{"code":"123456"}`))
	rr := httptest.NewRecorder()
	h.MFAStepUp(rr, r)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// TestMFAStepUpHandler_BadJSON_BadRequest verifies that malformed JSON is rejected with 400.
func TestMFAStepUpHandler_BadJSON_BadRequest(t *testing.T) {
	h, _, _ := setupMFAStepUpTest(t)

	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/stepup",
		bytes.NewBufferString(`{not-json}`))
	r = withUserContext(r, 1)
	rr := httptest.NewRecorder()
	h.MFAStepUp(rr, r)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestMFAStepUpHandler_EmptyCode_BadRequest verifies that a request with an empty code
// is rejected with 400.
func TestMFAStepUpHandler_EmptyCode_BadRequest(t *testing.T) {
	h, _, _ := setupMFAStepUpTest(t)

	r := postJSON("/api/v1/auth/mfa/stepup", map[string]string{"code": ""}, 1)
	rr := httptest.NewRecorder()
	h.MFAStepUp(rr, r)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestMFAStepUpHandler_WrongCode_Unauthorized verifies that an incorrect TOTP code
// is rejected with 401.
func TestMFAStepUpHandler_WrongCode_Unauthorized(t *testing.T) {
	h, coreService, _ := setupMFAStepUpTest(t)
	activateMFAForStepUpTest(t, coreService)

	r := postJSON("/api/v1/auth/mfa/stepup", map[string]string{"code": "000000"}, 1)
	rr := httptest.NewRecorder()
	h.MFAStepUp(rr, r)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// TestMFAStepUpHandler_StorageError_ServiceUnavailable is the HTTP-layer
// sibling of core's TestVerifyMFAStepUp_GetMFASecretErrorDoesNotFeedLockout
// (FIX-1, #2548 sibling): a storage error during step-up verification must
// surface as a distinct 5xx, not the same 401 a genuinely wrong code gets.
func TestMFAStepUpHandler_StorageError_ServiceUnavailable(t *testing.T) {
	require.NoError(t, i18n.Initialize(&config.Config{Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"}}))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.MFASecret{}, &models.MFARecoveryCode{},
		&models.MFAChallenge{}, &models.Session{}, &models.AuditEvent{},
		&models.MFAStepupToken{}, &models.MFAStepUpGrant{},
	))
	hash, err := bcrypt.GenerateFromPassword([]byte(stepUpTestPassword), bcrypt.MinCost)
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", Email: "a@b.com",
		PasswordHash: string(hash), AccountState: "active"}).Error)
	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, t.TempDir())
	require.NoError(t, enc.Initialize("test-passphrase"))

	fs := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
	coreService := core.NewKeyorixCore(fs)
	coreService.SetAuthEncryptor(enc)
	h := NewAuthHandler(coreService, false)
	secret, _ := activateMFAForStepUpTest(t, coreService)

	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)

	fs.Arm(&faultstorage.FaultSpec{Method: "GetMFASecret", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
	r := postJSON("/api/v1/auth/mfa/stepup", map[string]string{"code": code}, 1)
	rr := httptest.NewRecorder()
	h.MFAStepUp(rr, r)
	require.True(t, fs.Fired())
	assert.Equal(t, http.StatusServiceUnavailable, rr.Code, rr.Body.String())
	assert.NotContains(t, rr.Body.String(), "invalid code", "a storage error must not be reported as a wrong code")
}

// TestMFAStepUpHandler_CorrectCode_Success verifies that a correct TOTP code returns 200
// and the success message.
func TestMFAStepUpHandler_CorrectCode_Success(t *testing.T) {
	h, coreService, _ := setupMFAStepUpTest(t)
	secret, _ := activateMFAForStepUpTest(t, coreService)

	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)

	r := postJSON("/api/v1/auth/mfa/stepup", map[string]string{"code": code}, 1)
	rr := httptest.NewRecorder()
	h.MFAStepUp(rr, r)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), "step-up verified")
}
