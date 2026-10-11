// login_budget_backup_restore_test.go — DR-FIX-1 (REBASE-22's finding on #2956).
//
// MFAChallenge.LoginAttemptID and WebAuthnSession.LoginAttemptID point at the
// per-IP login-budget slot (a login_attempts row) the flow reserved. A
// delivered login releases that slot by deleting the row, and the age prune and
// admin clear-login-lockout delete them too, while the challenge / ceremony row
// keeps its pointer. backupfmt classified both fields by naming convention as
// references to login_attempts, so `admin restore` refused every backup taken
// after a single delivered MFA or passkey login ("dangling reference").
//
// These tests drive real delivered logins over HTTP, then take a full-registry
// logical backup of that database and restore it into a fresh one.
package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"testing"

	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/backupfmt"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// backupAndRestore migrates every registry table onto src (the login envs only
// create the tables they use; the rest stay empty), writes a full logical
// backup, extracts it and loads it into a fresh, fully migrated database, and
// returns that database. The load runs restore's mandatory dangling-reference
// check.
func backupAndRestore(t *testing.T, src *gorm.DB) *gorm.DB {
	t.Helper()
	require.NoError(t, src.AutoMigrate(storage.AllModels()...))

	key := bytes.Repeat([]byte{0x5a}, 32)
	var archive bytes.Buffer
	_, err := backupfmt.WriteBackup(src, 1, "", key, nil, nil, &archive)
	require.NoError(t, err)

	staging := t.TempDir()
	manifest, err := backupfmt.ExtractArchive(&archive, staging, 0, 0)
	require.NoError(t, err)
	require.True(t, backupfmt.VerifyManifestSignature(manifest, key))

	dst, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "restored.db")), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, dst.AutoMigrate(storage.AllModels()...))
	require.NoError(t, dst.Transaction(func(tx *gorm.DB) error {
		return backupfmt.LoadArchive(tx, manifest, staging)
	}), "a backup taken after a delivered login must restore")
	return dst
}

// requireSlotPointersSurvive asserts the restored rows still carry a slot
// pointer whose login_attempts row is gone: the exact shape that used to be
// refused, so the test cannot pass by the pointer silently going missing.
func requireSlotPointersSurvive(t *testing.T, dst *gorm.DB, model any, what string) {
	t.Helper()
	var n int64
	require.NoError(t, dst.Model(model).
		Where("login_attempt_id IS NOT NULL AND login_attempt_id NOT IN (SELECT id FROM login_attempts)").
		Count(&n).Error)
	require.NotZero(t, n, "setup: the restored %s rows must keep a pointer to a released slot", what)
}

func TestBackupRestore_AfterDeliveredTOTPLogin(t *testing.T) {
	env := newLockoutOracleEnvWithMFA(t)
	ch := env.mfaPasswordStep(t)
	require.Equal(t, http.StatusOK, env.postVerify(t, ch, env.nextTOTP(t)).Code)
	require.Zero(t, budgetSlots(t, env.db), "setup: the delivered login released its slot")

	dst := backupAndRestore(t, env.db)
	requireSlotPointersSurvive(t, dst, &models.MFAChallenge{}, "mfa_challenges")
	var users int64
	require.NoError(t, dst.Model(&models.User{}).Count(&users).Error)
	require.EqualValues(t, 1, users)
}

func TestBackupRestore_AfterDeliveredPasskeyLogins(t *testing.T) {
	h, db := newPasskeyBudgetEnv(t)

	// Password -> WebAuthn second factor.
	cred, _ := wcAssertionJSON(t, false)
	lw := postJSONTo(t, h.Login, "/auth/login", map[string]string{"username": "alice", "password": lockoutOracleTestPassword})
	require.Equal(t, http.StatusOK, lw.Code, lw.Body.String())
	var lr struct {
		Data struct {
			MFAChallenge string `json:"mfa_challenge"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(lw.Body.Bytes(), &lr))
	tok := beginPasskey(t, db, postJSONTo(t, h.BeginWebAuthnLogin, "/auth/webauthn/login/begin",
		map[string]string{"mfa_challenge": lr.Data.MFAChallenge}), false)
	fw := postFinishWebAuthnLogin(t, h, lr.Data.MFAChallenge, tok, cred)
	require.Equal(t, http.StatusOK, fw.Code, fw.Body.String())

	// Passwordless.
	pcred, _ := wcAssertionJSONWithUserHandle(t, false)
	ptok := beginPasskey(t, db, postJSONTo(t, h.BeginWebAuthnPasswordlessLogin, "/auth/webauthn/passwordless/begin", map[string]string{}), true)
	pw := postJSONTo(t, h.FinishWebAuthnPasswordlessLogin, "/auth/webauthn/passwordless/finish",
		map[string]any{"webauthn_session": ptok, "credential": pcred})
	require.Equal(t, http.StatusOK, pw.Code, pw.Body.String())
	require.Zero(t, budgetSlots(t, db), "setup: the delivered logins released every slot")

	dst := backupAndRestore(t, db)
	requireSlotPointersSurvive(t, dst, &models.MFAChallenge{}, "mfa_challenges")
	requireSlotPointersSurvive(t, dst, &models.WebAuthnSession{}, "webauthn_sessions")
	var sessions int64
	require.NoError(t, dst.Model(&models.Session{}).Count(&sessions).Error)
	require.EqualValues(t, 2, sessions, fmt.Sprintf("both delivered logins' sessions must be restored, got %d", sessions))
}
