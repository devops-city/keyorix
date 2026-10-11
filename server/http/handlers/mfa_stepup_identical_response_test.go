// mfa_stepup_identical_response_test.go — #2894 review (MERGE-MASTER,
// blocking 1): POST /api/v1/auth/mfa/stepup must answer a CORRECT code whose
// post-verdict work faulted exactly like a WRONG code — status, body, headers
// and lockout columns — and must never echo a storage error.
//
// Before the fix the handler mapped only ErrMFAVerificationUnavailable and
// ErrMFAVerificationStorageFailure and sent err.Error() for everything else, so
// a CreateMFAStepUpGrant fault after a correct code answered
// "login denied by a storage error after the credential matched: ..." where a
// wrong code answered "invalid code".
package handlers

import (
	"context"
	"errors"
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
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// stepUpRecoveryFaultStub, once armed, fails ConsumeMFARecoveryCode always and
// MarkTOTPStepUsed when failMark is set. Inert until armed, so enrolment runs
// against real storage.
type stepUpRecoveryFaultStub struct {
	corestorage.Storage
	armed, failMark bool
}

func (s *stepUpRecoveryFaultStub) MarkTOTPStepUsed(ctx context.Context, userID uint, step int64) (bool, error) {
	if s.armed && s.failMark {
		return false, errors.New("injected: MarkTOTPStepUsed")
	}
	return s.Storage.MarkTOTPStepUsed(ctx, userID, step)
}

func (s *stepUpRecoveryFaultStub) ConsumeMFARecoveryCode(ctx context.Context, userID uint, codeHash string, now time.Time) (bool, error) {
	if s.armed {
		return false, errors.New("injected: ConsumeMFARecoveryCode")
	}
	return s.Storage.ConsumeMFARecoveryCode(ctx, userID, codeHash, now)
}

// stepUpFault is what one parity case injects into the step-up request only.
type stepUpFault struct {
	spec          *faultstorage.FaultSpec // one faultstorage fault, or nil
	recoveryDown  bool                    // ConsumeMFARecoveryCode fails
	markTOTPFails bool                    // MarkTOTPStepUsed fails (with recoveryDown)
}

// stepUpParityEnv is one fresh account at lockout threshold−1 with MFA active,
// over real SQLite. The fault is armed only after enrolment, so only the
// step-up request itself sees it.
func stepUpParityEnv(t *testing.T, f stepUpFault) (h *AuthHandler, db *gorm.DB, code string, fs *faultstorage.FaultyStorage) {
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

	stub := &stepUpRecoveryFaultStub{Storage: store.NewLocalStorage(db)}
	fs = faultstorage.NewFaultyStorage(stub, nil)
	c := core.NewKeyorixCore(fs)
	c.SetAuthEncryptor(enc)
	c.SetLoginLockoutPolicy(core.LoginLockoutPolicy{
		Enabled: true, MaxAttempts: 3, Window: time.Hour, BaseCooldown: 15 * time.Minute, MaxCooldown: time.Hour,
	})
	secret, _ := activateMFAForStepUpTest(t, c)
	require.NoError(t, db.Model(&models.User{}).Where("id = ?", 1).Updates(map[string]any{
		"failed_login_attempts": 2, "last_failed_login_at": time.Now().UTC(),
	}).Error)
	code, err = totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)

	stub.armed, stub.failMark = f.recoveryDown, f.markTOTPFails
	if f.spec != nil {
		fs.Arm(f.spec)
	}
	return NewAuthHandler(c, false), db, code, fs
}

func postStepUp(h *AuthHandler, code string) *httptest.ResponseRecorder {
	r := postJSON("/api/v1/auth/mfa/stepup", map[string]string{"code": code}, 1)
	w := httptest.NewRecorder()
	h.MFAStepUp(w, r)
	return w
}

func TestMFAStepUp_PostVerdictFaultIsIdenticalToAWrongCode(t *testing.T) {
	h, db, _, _ := stepUpParityEnv(t, stepUpFault{})
	control := observeHTTP(t, db, postStepUp(h, "000000"))
	require.Equal(t, http.StatusUnauthorized, control.status)
	require.True(t, control.lockout.locked, "control: a wrong code at threshold-1 must lock, or the lockout comparison is vacuous")

	cases := []struct {
		name  string
		fault stepUpFault
	}{
		{name: "CreateMFAStepUpGrant", fault: stepUpFault{spec: &faultstorage.FaultSpec{Method: "CreateMFAStepUpGrant", NthCall: 1, Kind: faultstorage.KindError, Err: errors.New("injected: grant write")}}},
		{name: "LockUserForUpdate recheck", fault: stepUpFault{spec: &faultstorage.FaultSpec{Method: "LockUserForUpdate", NthCall: 1, Kind: faultstorage.KindError, Err: errors.New("injected: recheck")}}},
		{name: "MarkTOTPStepUsed and recovery lookup", fault: stepUpFault{recoveryDown: true, markTOTPFails: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ph, pdb, good, fs := stepUpParityEnv(t, tc.fault)
			probe := observeHTTP(t, pdb, postStepUp(ph, good))
			if tc.fault.spec != nil {
				require.True(t, fs.Fired(), "the fault must have been reached")
			}
			requireIdenticalResponse(t, control, probe, "stepup/"+tc.name)
			assert.NotContains(t, probe.body, "injected", "a storage error must never reach the client")
			assert.NotContains(t, probe.body, "credential matched", "the response must not say the code was right")
		})
	}

	// The asymmetry's other half: a WRONG code while the recovery lookup is down
	// must still be a plain wrong code, not a 503.
	t.Run("wrong code with recovery lookup down", func(t *testing.T) {
		ph, pdb, _, _ := stepUpParityEnv(t, stepUpFault{recoveryDown: true})
		requireIdenticalResponse(t, control, observeHTTP(t, pdb, postStepUp(ph, "000000")), "stepup/wrong code, recovery down")
	})
}
