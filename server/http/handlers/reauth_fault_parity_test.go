// reauth_fault_parity_test.go — AUTH-VERIFY-1 (#2894 follow-up): the self-service
// re-auth endpoints (disable MFA, regenerate recovery codes, WebAuthn
// register/delete) must answer a storage fault that kept the code or password
// from being evaluated exactly like a wrong code or password -- same status, same
// body, same headers -- as POST /auth/login already does for a failed username
// lookup (ErrLoginNotEvaluated). Before the fix they answered a distinct
// "an internal error occurred" text, which told a caller which step failed.
package handlers

import (
	"context"
	"errors"
	"fmt"
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
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// reauthSecretFaultStub fails GetMFASecret once armed, which is the one read
// requireReauth makes BEFORE it evaluates the code or password.
type reauthSecretFaultStub struct {
	corestorage.Storage
	armed bool
}

func (s *reauthSecretFaultStub) GetMFASecret(ctx context.Context, userID uint) (*models.MFASecret, error) {
	if s.armed {
		return nil, errors.New("injected: GetMFASecret")
	}
	return s.Storage.GetMFASecret(ctx, userID)
}

func reauthFaultEnv(t *testing.T, faulted bool) (h *AuthHandler, code string, db *gorm.DB) {
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

	stub := &reauthSecretFaultStub{Storage: store.NewLocalStorage(db)}
	c := core.NewKeyorixCore(stub)
	c.SetAuthEncryptor(enc)
	secret, _ := activateMFAForStepUpTest(t, c)
	code, err = totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	stub.armed = faulted
	return NewAuthHandler(c, false), code, db
}

func TestReauthEndpoints_PreVerdictStorageFaultIsIdenticalToAWrongCode(t *testing.T) {
	endpoints := []struct {
		name string
		call func(h *AuthHandler, w http.ResponseWriter, code string)
	}{
		{"disable", func(h *AuthHandler, w http.ResponseWriter, code string) {
			h.DisableMFA(w, postJSON("/api/v1/auth/mfa/disable", map[string]string{"code": code}, 1))
		}},
		{"regenerate-recovery-codes", func(h *AuthHandler, w http.ResponseWriter, code string) {
			h.RegenerateRecoveryCodes(w, postJSON("/api/v1/auth/mfa/recovery-codes", map[string]string{"code": code}, 1))
		}},
	}
	for _, ep := range endpoints {
		t.Run(ep.name, func(t *testing.T) {
			// Control: a wrong code, healthy storage.
			ch, _, cdb := reauthFaultEnv(t, false)
			cw := httptest.NewRecorder()
			ep.call(ch, cw, "000000")
			control := observeHTTP(t, cdb, cw)
			require.Equal(t, http.StatusBadRequest, control.status)

			// Probe: the CORRECT code, but the secret read faults before it is checked.
			ph, good, pdb := reauthFaultEnv(t, true)
			pw := httptest.NewRecorder()
			ep.call(ph, pw, good)
			probe := observeHTTP(t, pdb, pw)

			// The lockout columns are deliberately not compared: a request that was
			// never evaluated is not counted (require_reauth_storage_error_test.go),
			// as login's ErrLoginNotEvaluated returns its slot.
			assert.Equal(t, control.status, probe.status, "status differs from a wrong code")
			assert.Equal(t, control.body, probe.body, "body differs from a wrong code")
			assert.Equal(t, control.headers, probe.headers, "headers differ from a wrong code")
			assert.NotContains(t, probe.body, "injected", "a storage error must never reach the client")
		})
	}
}

// TestWriteWebAuthnErr_ReauthStorageFaultIsIdenticalToAWrongCode covers the
// WebAuthn register/delete endpoints, which reach requireReauth through the same
// core gate but answer through writeWebAuthnErr.
func TestWriteWebAuthnErr_ReauthStorageFaultIsIdenticalToAWrongCode(t *testing.T) {
	h := NewAuthHandler(core.NewKeyorixCore(nil), false)
	wrong := httptest.NewRecorder()
	h.writeWebAuthnErr(wrong, errors.New("invalid code or password"))
	fault := httptest.NewRecorder()
	h.writeWebAuthnErr(fault, fmt.Errorf("%w: retrieval failed: %w", core.ErrMFAVerificationStorageFailure, errors.New("injected")))

	assert.Equal(t, wrong.Code, fault.Code)
	assert.Equal(t, wrong.Body.String(), fault.Body.String())
	assert.Equal(t, wrong.Result().Header, fault.Result().Header)
}
