// mfa_test.go — G50 regression coverage: mfa.go's self-service handlers must
// never forward a raw backend/driver error to the client. Mirrors the
// error_sanitization_test.go convention, but since core.KeyorixCore's MFA
// methods swallow a failed initial GetUser into the fixed-safe "user not
// found" message, closing the WHOLE database (as error_sanitization_test.go
// does) never actually reaches the raw fmt.Errorf("...: %w", err)-wrapped
// branches these handlers can hit. Instead, each test lets the setup reads
// succeed and then drops the SPECIFIC table backing the later write/read
// that the handler's error path wraps or returns raw, so a genuine SQLite
// driver error ("no such table: ...") is what clientSafe() must sanitize.
package handlers

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// captureLogBuf redirects the standard logger to a buffer for the duration of
// the test and restores it on cleanup.
func captureLogBuf(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	origOutput := log.Writer()
	origFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(origOutput)
		log.SetFlags(origFlags)
	})
	return &buf
}

// assertNoRawDBLeak checks BOTH halves of the fix: the client-facing response
// body must never contain the raw SQLite driver error text ("no such table",
// the dropped table's name), and the original error must still have reached
// the server-side log for operators to debug.
func assertNoRawDBLeak(t *testing.T, w *httptest.ResponseRecorder, logBuf *bytes.Buffer, droppedTable string) {
	t.Helper()
	body := w.Body.String()
	assert.NotContains(t, body, "no such table")
	assert.NotContains(t, body, droppedTable)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	msg, _ := resp["message"].(string)
	assert.NotEmpty(t, msg)
	assert.NotContains(t, msg, "no such table")
	assert.NotContains(t, msg, droppedTable)

	assert.Contains(t, logBuf.String(), "no such table",
		"the raw driver error must still be logged server-side for operators to debug")
}

// TestEnrollMFA_DBErrorSanitized forces BeginMFAEnrollment's UpsertMFASecret
// write to fail (mfa_secrets table dropped after the GetUser read succeeds)
// and proves the raw "failed to store TOTP secret: no such table: mfa_secrets"
// text never reaches the HTTP response.
func TestEnrollMFA_DBErrorSanitized(t *testing.T) {
	h, _, db := setupMFAReauthTest(t)
	require.NoError(t, db.Migrator().DropTable(&models.MFASecret{}))

	logBuf := captureLogBuf(t)

	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/enroll", nil)
	r = withUserContext(r, 1)
	w := httptest.NewRecorder()
	h.EnrollMFA(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assertNoRawDBLeak(t, w, logBuf, "mfa_secrets")
}

// TestActivateMFA_DBErrorSanitized completes a real pending enrolment (so the
// TOTP code validates and the mfa_secrets writes all succeed), then drops
// mfa_recovery_codes so ActivateMFA's final CreateMFARecoveryCodes write fails
// with a raw driver error, and proves it never reaches the response.
func TestActivateMFA_DBErrorSanitized(t *testing.T) {
	h, coreService, db := setupMFAReauthTest(t)

	_, secret, err := coreService.BeginMFAEnrollment(t.Context(), 1)
	require.NoError(t, err)
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)

	require.NoError(t, db.Migrator().DropTable(&models.MFARecoveryCode{}))

	logBuf := captureLogBuf(t)

	body, _ := json.Marshal(map[string]string{"code": code, "password": reauthTestPassword})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/activate", bytes.NewReader(body))
	r = withUserContext(r, 1)
	w := httptest.NewRecorder()
	h.ActivateMFA(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assertNoRawDBLeak(t, w, logBuf, "mfa_recovery_codes")
}

// TestDisableMFA_DBErrorSanitized fully enrols and activates MFA for user 1
// (so DisableMFA's password re-auth and SetUserMFAEnabled write both
// succeed), then drops mfa_secrets so DeleteMFAForUser's transaction fails on
// its first delete and returns the raw driver error UNWRAPPED — the
// bare `return err` at mfa.go's DisableMFA fallback.
func TestDisableMFA_DBErrorSanitized(t *testing.T) {
	h, coreService, db := setupMFAReauthTest(t)

	_, secret, err := coreService.BeginMFAEnrollment(t.Context(), 1)
	require.NoError(t, err)
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	_, err = coreService.ActivateMFA(t.Context(), 1, code, reauthTestPassword, "")
	require.NoError(t, err)

	require.NoError(t, db.Migrator().DropTable(&models.MFASecret{}))

	// MFA is enrolled, so a password alone no longer satisfies requireReauth's
	// second-factor requirement (#372-follow-up) — even here, where the TOTP
	// secret read fails silently because mfa_secrets is gone. Seed an active
	// step-up grant (the same proof VerifyMFAStepUp/a WebAuthn login would
	// produce) so password re-auth succeeds and the failure below genuinely
	// comes from DeleteMFAForUser, not re-auth.
	require.NoError(t, db.Create(&models.MFAStepUpGrant{UserID: 1, Purpose: models.MFAStepUpPurposeReauth, ExpiresAt: time.Now().Add(15 * time.Minute)}).Error)

	logBuf := captureLogBuf(t)

	body, _ := json.Marshal(map[string]string{"password": reauthTestPassword})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/disable", bytes.NewReader(body))
	r = withUserContext(r, 1)
	w := httptest.NewRecorder()
	h.DisableMFA(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assertNoRawDBLeak(t, w, logBuf, "mfa_secrets")
}

// TestRegenerateRecoveryCodes_DBErrorSanitized fully enrols and activates MFA,
// then drops mfa_recovery_codes so RegenerateMFARecoveryCodes' initial
// DeleteMFARecoveryCodes write fails with a raw driver error.
func TestRegenerateRecoveryCodes_DBErrorSanitized(t *testing.T) {
	h, coreService, db := setupMFAReauthTest(t)

	_, secret, err := coreService.BeginMFAEnrollment(t.Context(), 1)
	require.NoError(t, err)
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	_, err = coreService.ActivateMFA(t.Context(), 1, code, reauthTestPassword, "")
	require.NoError(t, err)

	require.NoError(t, db.Migrator().DropTable(&models.MFARecoveryCode{}))

	// MFA is enrolled, so a password alone no longer satisfies requireReauth's
	// second-factor requirement (#372-follow-up). Seed an active step-up grant so
	// password re-auth succeeds and the failure below genuinely comes from
	// DeleteMFARecoveryCodes, not re-auth.
	require.NoError(t, db.Create(&models.MFAStepUpGrant{UserID: 1, Purpose: models.MFAStepUpPurposeReauth, ExpiresAt: time.Now().Add(15 * time.Minute)}).Error)

	logBuf := captureLogBuf(t)

	body, _ := json.Marshal(map[string]string{"password": reauthTestPassword})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/recovery-codes/regenerate", bytes.NewReader(body))
	r = withUserContext(r, 1)
	w := httptest.NewRecorder()
	h.RegenerateRecoveryCodes(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assertNoRawDBLeak(t, w, logBuf, "mfa_recovery_codes")
}

// TestRecoveryCodesStatus_DBErrorSanitized fully enrols and activates MFA,
// then drops mfa_recovery_codes so MFARecoveryCodesRemaining's
// CountUnusedMFARecoveryCodes read fails with a raw driver error, returned
// completely unwrapped by mfa.go's RecoveryCodesStatus fallback.
func TestRecoveryCodesStatus_DBErrorSanitized(t *testing.T) {
	h, coreService, db := setupMFAReauthTest(t)

	_, secret, err := coreService.BeginMFAEnrollment(t.Context(), 1)
	require.NoError(t, err)
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	_, err = coreService.ActivateMFA(t.Context(), 1, code, reauthTestPassword, "")
	require.NoError(t, err)

	require.NoError(t, db.Migrator().DropTable(&models.MFARecoveryCode{}))

	logBuf := captureLogBuf(t)

	r := httptest.NewRequest(http.MethodGet, "/api/v1/auth/mfa/recovery-codes/status", nil)
	r = withUserContext(r, 1)
	w := httptest.NewRecorder()
	h.RecoveryCodesStatus(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assertNoRawDBLeak(t, w, logBuf, "mfa_recovery_codes")
}
