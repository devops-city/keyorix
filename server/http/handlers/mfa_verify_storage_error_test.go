// mfa_verify_storage_error_test.go — handler-level regression for the second
// call site of docs/findings/2026-10-02-FINDING-mfa-login-getmfasecret-storage-error-counted-as-wrong-code.md
// (found by the fuzzer on PR #2392, CI seed 877139548d2805a6, out of that
// session's own work): VerifyMFA's reserveLoginAttempt call runs BEFORE
// VerifyMFALogin, so a storage error on ANY of VerifyMFACredentials'
// pre-verdict calls — GetUser included, not just GetMFASecret — used to still
// write a LoginAttempt row, even though VerifyMFACredentials itself never
// got anywhere near the account's own lockout counter. Exercises the
// account-lockout side end to end through the real HTTP handler: N GetUser
// failures with the CORRECT code must leave the account unlocked, and the
// same code must still verify once the fault clears.
package handlers

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
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

const mfaVerifyStorageErrorTestPassword = "Secret#Passw0rd!"

// setupMFAVerifyStorageErrorTest mirrors setupMFAReauthTest but wraps the real
// SQLite-backed LocalStorage in a faultstorage.FaultyStorage, so the test can
// arm a one-shot GetUser failure for VerifyMFA's internal
// VerifyMFACredentials call without needing access to KeyorixCore's private
// storage field (this file lives in package handlers, not core). Returns a
// fixed clock so the TOTP code generated for activation/login stays stable
// across the whole test regardless of real wall-clock timing.
func setupMFAVerifyStorageErrorTest(t *testing.T) (*AuthHandler, *faultstorage.FaultyStorage, *gorm.DB, time.Time) {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"}}))

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	// A :memory: SQLite DSN gives each physical connection its own PRIVATE
	// database -- the background goSafe(LogAuthLogin/RecordLogin) goroutines a
	// successful verify fires can otherwise race the test's own queries onto a
	// second, freshly-empty connection. Cap the pool at 1.
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.MFASecret{}, &models.MFARecoveryCode{},
		&models.MFAChallenge{}, &models.Session{}, &models.AuditEvent{}, &models.LoginAttempt{},
		&models.Role{}, &models.UserRole{}, &models.Permission{}, &models.RolePermission{}))

	hash, err := bcrypt.GenerateFromPassword([]byte(mfaVerifyStorageErrorTestPassword), bcrypt.MinCost)
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", Email: "a@b.com",
		PasswordHash: string(hash), AccountState: "active"}).Error)

	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, t.TempDir())
	require.NoError(t, enc.Initialize("test-passphrase"))

	fs := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
	coreService := core.NewKeyorixCore(fs)
	coreService.SetAuthEncryptor(enc)
	coreService.SetLoginLockoutPolicy(core.LoginLockoutPolicy{
		Enabled: true, MaxAttempts: 3, Window: time.Hour, BaseCooldown: 15 * time.Minute, MaxCooldown: time.Hour,
	})
	fixed := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	coreService.SetClockForTesting(func() time.Time { return fixed })

	return NewAuthHandler(coreService, false), fs, db, fixed
}

// verifyMFAHTTP posts challenge+code to /auth/mfa/verify and returns the
// response code, mirroring how the real router dispatches to VerifyMFA.
func verifyMFAHTTP(t *testing.T, h *AuthHandler, challenge, code string) int {
	t.Helper()
	body, err := json.Marshal(map[string]string{"mfa_challenge": challenge, "code": code})
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/verify", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.VerifyMFA(w, r)
	return w.Code
}

// TestVerifyMFA_GetUserStorageError_DoesNotFeedAccountLockout: N GetUser
// failures (N > the lockout's MaxAttempts) with the CORRECT TOTP code must
// leave the account unlocked — VerifyMFACredentials' own GetUser error return
// ("user not found") is indistinguishable, by message alone, from a genuine
// storage read failure, and must not be treated as a confirmed wrong guess.
// Once the fault clears, the SAME code (never actually checked, let alone
// consumed, while GetUser kept failing) must still verify successfully,
// proving the account was genuinely never locked rather than merely
// not-yet-checked.
func TestVerifyMFA_GetUserStorageError_DoesNotFeedAccountLockout(t *testing.T) {
	h, fs, db, fixed := setupMFAVerifyStorageErrorTest(t)
	ctx := context.Background()

	_, secret, err := h.coreService.BeginMFAEnrollment(ctx, 1)
	require.NoError(t, err)
	// Activate with the PREVIOUS step so the current step (fixed) stays fresh
	// for the login checks below — activation and login both consume a step
	// via MarkTOTPStepUsed, so reusing the same step would make the "good
	// code" check below a rejected replay instead of a genuine verify.
	actCode, err := totp.GenerateCode(secret, fixed.Add(-30*time.Second))
	require.NoError(t, err)
	_, err = h.coreService.ActivateMFA(ctx, 1, actCode, mfaVerifyStorageErrorTestPassword, "")
	require.NoError(t, err)

	good, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)

	const attempts = 5 // > MaxAttempts (3): if wrongly counted, the account would now be locked.
	for i := range attempts {
		challenge, cerr := h.coreService.CreateMFAChallenge(ctx, 1)
		require.NoError(t, cerr)

		// Arm exactly one GetUser failure for THIS attempt's VerifyMFACredentials
		// call. CreateMFAChallenge above never calls GetUser, so NthCall=1 lands
		// on the call VerifyMFALogin -> VerifyMFACredentials makes.
		fs.Arm(&faultstorage.FaultSpec{Method: "GetUser", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})

		code := verifyMFAHTTP(t, h, challenge, good)
		// FIX-1 (#2548): a storage error must refuse the login with a distinct
		// 5xx, not the same 401 a genuinely wrong code gets — see
		// errMFAVerificationUnavailable's doc (mfa.go).
		assert.Equal(t, http.StatusServiceUnavailable, code, "attempt %d: a storage error must be a 5xx, not a wrong-code 401", i)
		assert.True(t, fs.Fired(), "attempt %d: the armed GetUser fault must actually have fired", i)
	}

	fs.Arm(nil) // disarm before the real verify below

	var afterFaults models.User
	require.NoError(t, db.First(&afterFaults, 1).Error)
	assert.Nil(t, afterFaults.LoginLockedUntil,
		"account must NOT be locked — none of the 5 GetUser-storage-error attempts was a confirmed wrong code")

	// The IP-level reservation (reserveLoginAttempt, called before VerifyMFALogin
	// even runs) must have been released for every one of the 5 storage-error
	// attempts — this is the actual symptom the fuzzer found (seed
	// 877139548d2805a6): an orphaned LoginAttempt row with no accompanying
	// mfa.failed/mfa.error audit explanation, written regardless of outcome.
	// httptest.NewRequest defaults RemoteAddr to "192.0.2.1:1234".
	var attemptCount int64
	require.NoError(t, db.Model(&models.LoginAttempt{}).Where("ip = ?", "192.0.2.1").Count(&attemptCount).Error)
	assert.Zero(t, attemptCount,
		"each GetUser-storage-error attempt's reserved LoginAttempt row must be released, not left counted")

	// Fault clears: the SAME correct code (never consumed — MarkTOTPStepUsed
	// was never reached while GetUser kept failing before loadTOTPSecret even
	// ran) now verifies successfully, proving the account was genuinely never
	// locked, not just not-yet-checked.
	challenge, err := h.coreService.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	code := verifyMFAHTTP(t, h, challenge, good)
	assert.Equal(t, http.StatusOK, code, "the same, never-actually-wrong code must still verify once the fault clears")
}
