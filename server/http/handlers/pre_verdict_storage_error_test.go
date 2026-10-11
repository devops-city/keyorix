// pre_verdict_storage_error_test.go — AUTH-AUDIT-1 items 1-3 (the still-needed
// half of #2846) over HTTP.
//
// A storage error BEFORE any credential was checked is not a failed login. The
// rules (recorded decisions):
//   - it is audited as an error event, never as the *.failed event a wrong
//     credential gets;
//   - it does not keep the per-IP slot (#2936: the budget counts failed
//     credential attempts only);
//   - the client response is EXACTLY what main returns for the same request
//     today: same status, body bytes and headers as the matching negative
//     result, so the change adds no user-existence signal.
//
// Each test therefore drives a control (the ordinary negative result: an
// unknown username, a passkey handle naming no user, a wrong activation code)
// and a probe (the same request shape with the storage fault) and compares
// them byte for byte, then checks the two server-side differences.
package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"golang.org/x/crypto/bcrypt"
)

var errPreVerdictDown = errors.New("pq: connection reset by peer")

func eventCount(t *testing.T, db *gorm.DB, eventType string) int64 {
	t.Helper()
	var n int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", eventType).Count(&n).Error)
	return n
}

// requireSameResponse compares what the client sees: status, body bytes and
// headers.
func requireSameResponse(t *testing.T, control, probe *httptest.ResponseRecorder, what string) {
	t.Helper()
	assert.Equal(t, control.Code, probe.Code, "%s: status differs", what)
	assert.Equal(t, control.Body.String(), probe.Body.String(), "%s: body differs byte-for-byte", what)
	assert.Equal(t, control.Result().Header, probe.Result().Header, "%s: headers differ", what)
}

// --- item 1: /auth/login, GetUserByUsername storage error ---------------------

func TestLogin_UsernameLookupStorageError_AuditedAsErrorSlotReturnedResponseUnchanged(t *testing.T) {
	// Control: a username that does not exist (no fault).
	cenv := newLockoutOracleEnv(t)
	cw := postJSONTo(t, cenv.h.Login, "/auth/login", map[string]string{"username": "nobody-here", "password": lockoutOracleTestPassword})
	require.Equal(t, http.StatusUnauthorized, cw.Code)
	require.Eventually(t, func() bool { return eventCount(t, cenv.db, "auth.login_failed") == 1 }, 5*time.Second, 10*time.Millisecond)
	require.EqualValues(t, 1, budgetSlots(t, cenv.db), "control: a wrong credential keeps its slot")

	// Probe: a real account, the correct password, the username lookup faulted.
	penv := newLockoutOracleEnv(t)
	penv.fs.Arm(&faultstorage.FaultSpec{Method: "GetUserByUsername", NthCall: 1, Kind: faultstorage.KindError, Err: errPreVerdictDown})
	pw := penv.postLogin(t, lockoutOracleTestPassword)
	require.True(t, penv.fs.Fired())

	requireSameResponse(t, cw, pw, "login/GetUserByUsername")
	require.Eventually(t, func() bool { return eventCount(t, penv.db, "auth.login_error") == 1 }, 5*time.Second, 10*time.Millisecond,
		"a lookup that never checked the password must be audited as auth.login_error")
	assert.Zero(t, eventCount(t, penv.db, "auth.login_failed"), "and never as auth.login_failed (#2745)")
	assert.Zero(t, budgetSlots(t, penv.db), "no credential was checked, so the slot is handed back (#2936)")
	var u models.User
	require.NoError(t, penv.db.First(&u, 1).Error)
	assert.Zero(t, u.FailedLoginAttempts, "and the per-account counter is untouched")
}

// --- item 2: passwordless WebAuthn, GetUser storage error ----------------------

func TestPasswordlessLogin_UserLoadStorageError_AuditedAsErrorSlotReturnedResponseUnchanged(t *testing.T) {
	cred, challenge := wcAssertionJSONWithUserHandle(t, false)

	// Control: a valid assertion whose user handle names no user (alice is gone).
	ch, _, cdb := newWebAuthnCompletionEnv(t)
	require.NoError(t, cdb.Delete(&models.User{}, 1).Error)
	ctok := wcSeedCeremony(t, cdb, challenge, 0, "passwordless")
	cw := postJSONTo(t, ch.FinishWebAuthnPasswordlessLogin, "/auth/webauthn/passwordless/finish",
		map[string]any{"webauthn_session": ctok, "credential": cred})
	require.Equal(t, http.StatusUnauthorized, cw.Code, cw.Body.String())
	require.EqualValues(t, 1, eventCount(t, cdb, "webauthn.failed"), "control: a handle naming no user is a failed attempt")
	require.EqualValues(t, 1, budgetSlots(t, cdb), "control: and keeps its slot")

	// Probe: the same assertion, alice present, her row read faulted.
	ph, pfs, pdb := newWebAuthnCompletionEnv(t)
	ptok := wcSeedCeremony(t, pdb, challenge, 0, "passwordless")
	pfs.Arm(&faultstorage.FaultSpec{Method: "GetUser", NthCall: 1, Kind: faultstorage.KindError, Err: errPreVerdictDown})
	pw := postJSONTo(t, ph.FinishWebAuthnPasswordlessLogin, "/auth/webauthn/passwordless/finish",
		map[string]any{"webauthn_session": ptok, "credential": cred})
	require.True(t, pfs.Fired())

	requireSameResponse(t, cw, pw, "passwordless/GetUser")
	require.Eventually(t, func() bool { return eventCount(t, pdb, "auth.login_error") == 1 }, 5*time.Second, 10*time.Millisecond,
		"a passkey whose user could not be loaded was never evaluated: auth.login_error")
	assert.Zero(t, eventCount(t, pdb, "webauthn.failed"), "and must not be audited as a failed assertion (#2746)")
	assert.Zero(t, budgetSlots(t, pdb), "no credential was checked, so the slot is handed back")
}

// --- item 3: ActivateMFA, MarkTOTPStepUsed storage error -----------------------

func newActivateEnv(t *testing.T) (*AuthHandler, *faultstorage.FaultyStorage, *gorm.DB, string) {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"}}))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	if sqlDB, derr := db.DB(); derr == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.MFASecret{}, &models.MFARecoveryCode{},
		&models.MFAChallenge{}, &models.Session{}, &models.AuditEvent{}, &models.MFAStepupToken{}, &models.MFAStepUpGrant{}))
	hash, err := bcrypt.GenerateFromPassword([]byte(stepUpTestPassword), bcrypt.MinCost)
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", Email: "a@b.com", PasswordHash: string(hash), AccountState: "active"}).Error)
	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, t.TempDir())
	require.NoError(t, enc.Initialize("test-passphrase"))
	fs := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
	c := core.NewKeyorixCore(fs)
	c.SetAuthEncryptor(enc)
	_, secret, err := c.BeginMFAEnrollment(context.Background(), 1)
	require.NoError(t, err)
	return NewAuthHandler(c, false), fs, db, secret
}

func TestActivateMFA_MarkStepStorageError_AuditedAsErrorResponseUnchanged(t *testing.T) {
	ch, _, cdb, _ := newActivateEnv(t)
	cw := httptest.NewRecorder()
	ch.ActivateMFA(cw, postJSON("/api/v1/auth/mfa/activate", map[string]string{"code": "000000", "password": stepUpTestPassword}, 1))
	require.NotEqual(t, http.StatusOK, cw.Code)
	require.EqualValues(t, 1, eventCount(t, cdb, "mfa.failed"))

	ph, pfs, pdb, secret := newActivateEnv(t)
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	pfs.Arm(&faultstorage.FaultSpec{Method: "MarkTOTPStepUsed", NthCall: 1, Kind: faultstorage.KindError, Err: errPreVerdictDown})
	pw := httptest.NewRecorder()
	ph.ActivateMFA(pw, postJSON("/api/v1/auth/mfa/activate", map[string]string{"code": code, "password": stepUpTestPassword}, 1))
	require.True(t, pfs.Fired())

	requireSameResponse(t, cw, pw, "activate/MarkTOTPStepUsed")
	assert.EqualValues(t, 1, eventCount(t, pdb, "mfa.error"), "the storage error must be audited as mfa.error")
	assert.Zero(t, eventCount(t, pdb, "mfa.failed"), "and never as mfa.failed (#2744)")
}
