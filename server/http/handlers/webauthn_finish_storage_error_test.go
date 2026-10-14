// webauthn_finish_storage_error_test.go — regression for #2565 (found by
// FuzzStorageFaultOperations: op="REST POST /auth/webauthn/login/finish",
// fault=ListWebAuthnCredentials#1/error, then ConsumeMFAChallenge#1/error,
// oracle (a), differing tables [LoginAttempt]). FinishWebAuthnLogin reserved a
// per-IP login-attempt slot before the assertion check and never gave it back,
// so a storage error that stopped the check before any verdict still left a
// LoginAttempt row, counted exactly like a failed assertion. Same class as the
// MFA verify fix (#2398). The login must still be denied, but a request that
// was never evaluated must leave no LoginAttempt row and must not touch the
// account's own lockout counter; an ordinary bad challenge must stay counted.
package handlers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// webauthnFinishTestIP is httptest.NewRequest's default RemoteAddr host.
const webauthnFinishTestIP = "192.0.2.1"

func setupWebAuthnFinishStorageErrorTest(t *testing.T) (*AuthHandler, *faultstorage.FaultyStorage, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"}}))

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.MFAChallenge{}, &models.Session{},
		&models.AuditEvent{}, &models.LoginAttempt{}, &models.WebAuthnCredential{}, &models.WebAuthnSession{},
		&models.MFAStepupToken{}, &models.MFAStepUpGrant{}))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", Email: "a@b.com", AccountState: "active"}).Error)

	fs := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
	coreService := core.NewKeyorixCore(fs)
	coreService.SetLoginLockoutPolicy(core.LoginLockoutPolicy{
		Enabled: true, MaxAttempts: 3, Window: time.Hour, BaseCooldown: 15 * time.Minute, MaxCooldown: time.Hour,
	})
	rp, err := webauthn.New(&webauthn.Config{
		RPID: "localhost", RPDisplayName: "Keyorix", RPOrigins: []string{"https://localhost"},
	})
	require.NoError(t, err)
	coreService.SetWebAuthn(rp)
	return NewAuthHandler(coreService, false), fs, db
}

// seedWebAuthnLoginCeremony creates a live MFA challenge and a matching
// "login" ceremony session for user 1, as BeginWebAuthnLogin would.
func seedWebAuthnLoginCeremony(t *testing.T, h *AuthHandler, db *gorm.DB) (challenge, sessionToken string) {
	t.Helper()
	challenge, err := h.coreService.CreateMFAChallenge(context.Background(), 1)
	require.NoError(t, err)
	data, err := json.Marshal(&webauthn.SessionData{Challenge: "c2Vzc2lvbi1jaGFsbGVuZ2U", UserID: []byte{0, 0, 0, 0, 0, 0, 0, 1}})
	require.NoError(t, err)
	sessionToken = "webauthn-finish-storage-error-" + challenge
	sum := sha256.Sum256([]byte(sessionToken))
	require.NoError(t, db.Create(&models.WebAuthnSession{
		UserID: 1, TokenHash: hex.EncodeToString(sum[:]), Purpose: "login", Data: data,
		ExpiresAt: time.Now().Add(10 * time.Minute), CreatedAt: time.Now(),
	}).Error)
	return challenge, sessionToken
}

func finishWebAuthnLoginHTTP(t *testing.T, h *AuthHandler, challenge, sessionToken string) int {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"mfa_challenge": challenge, "webauthn_session": sessionToken,
		"credential": json.RawMessage(ltWebAuthnCredentialJSON),
	})
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodPost, "/auth/webauthn/login/finish", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.FinishWebAuthnLogin(w, r)
	return w.Code
}

func webauthnFinishLoginAttempts(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var n int64
	require.NoError(t, db.Model(&models.LoginAttempt{}).Where("ip = ?", webauthnFinishTestIP).Count(&n).Error)
	return n
}

// TestFinishWebAuthnLogin_StorageErrorBeforeVerdict_IsNotAFailedAttempt
// injects a storage error into each storage call FinishWebAuthnLogin makes
// before the assertion is evaluated. Each must deny the login and leave no
// LoginAttempt row and no per-account failure behind. FIX-1 (#2548,
// consistency with VerifyMFA/MFAStepUp): the status code is now a distinct
// 5xx, not the same 401 a genuinely failed assertion gets (previously this
// asserted only the DB effect and left the status code at 401 "either way" —
// that status-code distinction didn't exist yet).
func TestFinishWebAuthnLogin_StorageErrorBeforeVerdict_IsNotAFailedAttempt(t *testing.T) {
	for _, method := range []string{"ConsumeMFAChallenge", "ConsumeWebAuthnSession", "GetUser", "ListWebAuthnCredentials"} {
		t.Run(method, func(t *testing.T) {
			h, fs, db := setupWebAuthnFinishStorageErrorTest(t)
			const attempts = 5 // > MaxAttempts (3)
			for i := range attempts {
				challenge, token := seedWebAuthnLoginCeremony(t, h, db)
				fs.Arm(&faultstorage.FaultSpec{Method: method, NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
				code := finishWebAuthnLoginHTTP(t, h, challenge, token)
				assert.Equal(t, http.StatusServiceUnavailable, code, "attempt %d: a storage error must be a 5xx, not a failed-assertion 401", i)
				require.True(t, fs.Fired(), "attempt %d: the armed %s fault must actually have fired", i, method)
			}
			fs.Arm(nil)

			assert.Zero(t, webauthnFinishLoginAttempts(t, db),
				"a %s storage error never evaluated the assertion: its reserved LoginAttempt row must be released", method)
			var u models.User
			require.NoError(t, db.First(&u, 1).Error)
			assert.Zero(t, u.FailedLoginAttempts, "a storage error must not count toward the account lockout")
			assert.Nil(t, u.LoginLockedUntil, "a storage error must not lock the account")
		})
	}
}

// TestFinishWebAuthnLogin_InvalidChallengeStillCounted is the other direction:
// an unknown challenge is the expected negative result of a stale or guessed
// token, not a storage failure, and must keep consuming a budget slot. Without
// this, classifying every ConsumeMFAChallenge error as "not evaluated" would
// pass the test above while silently un-throttling challenge guessing.
func TestFinishWebAuthnLogin_InvalidChallengeStillCounted(t *testing.T) {
	h, _, db := setupWebAuthnFinishStorageErrorTest(t)
	_, token := seedWebAuthnLoginCeremony(t, h, db)
	code := finishWebAuthnLoginHTTP(t, h, "not-a-real-challenge", token)
	assert.Equal(t, http.StatusUnauthorized, code)
	assert.Equal(t, int64(1), webauthnFinishLoginAttempts(t, db), "an invalid challenge is a counted attempt")

	// Same for a valid challenge with an unknown ceremony session.
	challenge, _ := seedWebAuthnLoginCeremony(t, h, db)
	code = finishWebAuthnLoginHTTP(t, h, challenge, "not-a-real-session")
	assert.Equal(t, http.StatusUnauthorized, code)
	assert.Equal(t, int64(2), webauthnFinishLoginAttempts(t, db), "an invalid webauthn session is a counted attempt")
}
