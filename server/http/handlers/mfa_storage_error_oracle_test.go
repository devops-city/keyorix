package handlers

// #2740 review (option C): a storage failure may only be reported as a
// retryable 503 when it happened BEFORE any submitted code was evaluated. A
// failure AFTER the code was found correct (MarkTOTPStepUsed) must produce a
// response byte-for-byte identical to a wrong code, otherwise the 503 would
// confirm a correct guess. These tests pin both sides on the login path
// (/auth/mfa/verify) and the step-up path (/auth/mfa/stepup).

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func verifyMFARecorder(t *testing.T, h *AuthHandler, challenge, code string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]string{"mfa_challenge": challenge, "code": code})
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/verify", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.VerifyMFA(w, r)
	return w
}

func TestVerifyMFA_PostMatchStorageError_IndistinguishableFromWrongCode(t *testing.T) {
	h, fs, _, fixed := setupMFAVerifyStorageErrorTest(t)
	ctx := context.Background()

	_, secret, err := h.coreService.BeginMFAEnrollment(ctx, 1)
	require.NoError(t, err)
	actCode, err := totp.GenerateCode(secret, fixed.Add(-30*time.Second))
	require.NoError(t, err)
	_, err = h.coreService.ActivateMFA(ctx, 1, actCode, mfaVerifyStorageErrorTestPassword, "")
	require.NoError(t, err)
	good, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)

	// Reference: a genuinely wrong code.
	ch1, err := h.coreService.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	wrong := verifyMFARecorder(t, h, ch1, "000000")
	require.Equal(t, http.StatusUnauthorized, wrong.Code, wrong.Body.String())

	// The CORRECT code, with the post-match MarkTOTPStepUsed write failing.
	ch2, err := h.coreService.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	fs.Arm(&faultstorage.FaultSpec{Method: "MarkTOTPStepUsed", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
	post := verifyMFARecorder(t, h, ch2, good)
	require.True(t, fs.Fired(), "the armed MarkTOTPStepUsed fault must have fired")
	fs.Arm(nil)

	assert.Equal(t, wrong.Code, post.Code, "a post-match storage error must not be distinguishable from a wrong code by status")
	assert.Equal(t, wrong.Body.String(), post.Body.String(), "a post-match storage error must not be distinguishable from a wrong code by body")

	// Pre-evaluation failure (GetMFASecret) is the case that may say "retry".
	ch3, err := h.coreService.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	fs.Arm(&faultstorage.FaultSpec{Method: "GetMFASecret", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
	pre := verifyMFARecorder(t, h, ch3, good)
	require.True(t, fs.Fired(), "the armed GetMFASecret fault must have fired")
	fs.Arm(nil)
	assert.Equal(t, http.StatusServiceUnavailable, pre.Code, pre.Body.String())

	// The code was never marked used by the failed attempt, so it still works.
	ch4, err := h.coreService.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	ok := verifyMFARecorder(t, h, ch4, good)
	assert.Equal(t, http.StatusOK, ok.Code, ok.Body.String())
}

func TestMFAStepUpHandler_PostMatchStorageError_IndistinguishableFromWrongCode(t *testing.T) {
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

	wrong := httptest.NewRecorder()
	h.MFAStepUp(wrong, postJSON("/api/v1/auth/mfa/stepup", map[string]string{"code": "000000"}, 1))
	require.Equal(t, http.StatusUnauthorized, wrong.Code, wrong.Body.String())

	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	fs.Arm(&faultstorage.FaultSpec{Method: "MarkTOTPStepUsed", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
	post := httptest.NewRecorder()
	h.MFAStepUp(post, postJSON("/api/v1/auth/mfa/stepup", map[string]string{"code": code}, 1))
	require.True(t, fs.Fired(), "the armed MarkTOTPStepUsed fault must have fired")

	assert.Equal(t, wrong.Code, post.Code, "a post-match storage error must not be distinguishable from a wrong code by status")
	assert.Equal(t, wrong.Body.String(), post.Body.String(), "a post-match storage error must not be distinguishable from a wrong code by body")
}

// Review of #2947 (MERGE-MASTER): VerifyMFAStepUp returned raw storage errors from
// the steps AFTER the code matched (the login-lockout re-check's LockUserForUpdate,
// and CreateMFAStepUpGrant). Those reached the handler's generic branch as a 401
// carrying err.Error(): distinguishable from a wrong code, and now printed by the
// CLI. Every post-match storage fault that DENIES the step-up must answer exactly
// like a wrong code.
//
// UpdateLoginLockoutState is not in this list since #2894: the failure clear no
// longer runs before the grant (that order made a correct code cheaper than a
// wrong one when the grant then failed). It runs only after the grant was
// written, so its fault cannot deny anything; see
// TestMFAStepUpHandler_ClearFaultAfterGrant_GrantsAndKeepsTheCounter.
func TestMFAStepUpHandler_EveryPostMatchStorageFault_IndistinguishableFromWrongCode(t *testing.T) {
	for _, method := range []string{"MarkTOTPStepUsed", "LockUserForUpdate", "CreateMFAStepUpGrant"} {
		t.Run(method, func(t *testing.T) {
			h, fs, _, secret := newStepUpFaultFixture(t)

			// The reference wrong code also leaves one recorded failed attempt, so the
			// later success has state to clear.
			wrong := httptest.NewRecorder()
			h.MFAStepUp(wrong, postJSON("/api/v1/auth/mfa/stepup", map[string]string{"code": "000000"}, 1))
			require.Equal(t, http.StatusUnauthorized, wrong.Code, wrong.Body.String())

			code, err := totp.GenerateCode(secret, time.Now())
			require.NoError(t, err)
			fs.Arm(&faultstorage.FaultSpec{Method: method, NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
			post := httptest.NewRecorder()
			h.MFAStepUp(post, postJSON("/api/v1/auth/mfa/stepup", map[string]string{"code": code}, 1))
			require.True(t, fs.Fired(), "the armed %s fault must have fired", method)

			assert.Equal(t, wrong.Code, post.Code, "a post-match %s failure must not be distinguishable from a wrong code by status", method)
			assert.Equal(t, wrong.Body.String(), post.Body.String(), "a post-match %s failure must not be distinguishable from a wrong code by body (and must not echo the storage error)", method)
		})
	}
}

// #2894 x #2947: the failure clear (UpdateLoginLockoutState) runs only after the
// step-up grant is written. A fault there therefore cannot be an oracle: the step-up
// was delivered, which a correct code earns anyway. The fault must not be silently
// "fixed" by clearing anyway either: the counter stays where the wrong code left it
// (the strict side), and the grant really exists.
func TestMFAStepUpHandler_ClearFaultAfterGrant_GrantsAndKeepsTheCounter(t *testing.T) {
	h, fs, db, secret := newStepUpFaultFixture(t)

	wrong := httptest.NewRecorder()
	h.MFAStepUp(wrong, postJSON("/api/v1/auth/mfa/stepup", map[string]string{"code": "000000"}, 1))
	require.Equal(t, http.StatusUnauthorized, wrong.Code, wrong.Body.String())

	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	fs.Arm(&faultstorage.FaultSpec{Method: "UpdateLoginLockoutState", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
	post := httptest.NewRecorder()
	h.MFAStepUp(post, postJSON("/api/v1/auth/mfa/stepup", map[string]string{"code": code}, 1))
	require.True(t, fs.Fired(), "the armed UpdateLoginLockoutState fault must have fired")

	assert.Equal(t, http.StatusOK, post.Code, post.Body.String())
	assert.NotContains(t, post.Body.String(), assert.AnError.Error(), "the clear's storage error must not reach the caller")
	var grants int64
	require.NoError(t, db.Model(&models.MFAStepUpGrant{}).Where("user_id = ?", 1).Count(&grants).Error)
	assert.Equal(t, int64(1), grants, "a 200 must mean the grant was written BEFORE the clear was attempted")
	var u models.User
	require.NoError(t, db.First(&u, 1).Error)
	assert.Equal(t, 1, u.FailedLoginAttempts, "a failed clear must leave the wrong code's count in place")
}

func newStepUpFaultFixture(t *testing.T) (*AuthHandler, *faultstorage.FaultyStorage, *gorm.DB, string) {
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
	fs := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
	coreService := core.NewKeyorixCore(fs)
	coreService.SetAuthEncryptor(enc)
	// Lockout on, so the re-check actually runs LockUserForUpdate.
	coreService.SetLoginLockoutPolicy(core.LoginLockoutPolicy{
		Enabled: true, MaxAttempts: 10, Window: 15 * time.Minute, BaseCooldown: time.Minute, MaxCooldown: time.Hour,
	})
	h := NewAuthHandler(coreService, false)
	secret, _ := activateMFAForStepUpTest(t, coreService)
	return h, fs, db, secret
}
