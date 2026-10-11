// login_budget_count_failures_test.go — #2936: the per-IP login budget counts
// FAILURES, not logins (Andrei, 2026-10-10: "count failures only").
//
// The budget (core.LoginMaxAttempts per core.LoginWindow, per IP, persisted in
// login_attempts) is shared by every unauthenticated login-family endpoint. F2
// reserves a slot BEFORE the slow credential check, to close the concurrent-
// burst race, and used to keep it whatever the outcome — so ordinary successful
// logins from one machine (a demo laptop, a booth NAT, an office egress) ate
// the brute-force budget and locked everybody out with a 429 for 15 minutes.
//
// What #2936 changes, and what each test below pins:
//
//   - a request that DELIVERS a session (login, MFA verify, refresh) returns its
//     own reserved slot. The slot is still reserved up front, so the race F2
//     closed stays closed — only the outcome bookkeeping changes;
//   - a multi-request flow keeps its earlier steps' slots only until it
//     finishes: the password step of an MFA login (and a WebAuthn Begin) bind
//     their slots to the challenge / ceremony row, and the step that delivers
//     the session returns them with its own — so a delivered MFA login costs
//     no slot (#2936 item 4; login_budget_mfa_slot_release_test.go);
//   - failures keep counting exactly as before, including post-verdict storage
//     faults (#2880/#2894: those are charged like a wrong credential and are
//     NOT a delivered session, so they never reach the release);
//   - the count is the persisted login_attempts table, so a restart does not
//     reset it.
package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

var loginBudgetDBCounter atomic.Int64

// openLoginBudgetDB opens (and migrates) the SQLite database at dsn with a
// single connection, and seeds user 1 "alice" with lockoutOracleTestPassword
// unless she already exists — so the restart test can reopen the same file.
func openLoginBudgetDB(t *testing.T, dsn string) *gorm.DB {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"}}))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	if sqlDB, derr := db.DB(); derr == nil {
		sqlDB.SetMaxOpenConns(1)
		t.Cleanup(func() { _ = sqlDB.Close() })
	}
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Session{}, &models.AuditEvent{}, &models.LoginAttempt{},
		&models.Role{}, &models.Permission{}, &models.RolePermission{}, &models.UserRole{},
		&models.PasswordHistory{},
	))
	var n int64
	require.NoError(t, db.Model(&models.User{}).Where("id = ?", 1).Count(&n).Error)
	if n == 0 {
		hash, herr := bcrypt.GenerateFromPassword([]byte(lockoutOracleTestPassword), bcrypt.MinCost)
		require.NoError(t, herr)
		require.NoError(t, db.Create(&models.User{
			ID: 1, Username: "alice", UsernameFolded: "alice", Email: "alice@example.com",
			EmailFolded: "alice@example.com", PasswordHash: string(hash), AccountState: "active", IsActive: true,
		}).Error)
	}
	return db
}

// newLoginBudgetHandler is one server process over db. The per-account
// lockout is left at its default (off) so these tests isolate the per-IP
// budget; the account lockout is #2894's subject and is pinned there.
func newLoginBudgetHandler(db *gorm.DB) *AuthHandler {
	return NewAuthHandler(core.NewKeyorixCore(store.NewLocalStorage(db)), false)
}

func postLoginAs(t *testing.T, h *AuthHandler, password string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]string{"username": "alice", "password": password})
	require.NoError(t, err)
	w := httptest.NewRecorder()
	h.Login(w, httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body)))
	return w
}

func loginAttemptsFor(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var n int64
	require.NoError(t, db.Model(&models.LoginAttempt{}).Where("ip = ?", lockoutOracleTestIP).Count(&n).Error)
	return n
}

// TestLoginBudget_SuccessfulLoginsDoNotConsumeTheBudget is #2936's headline
// repro: LoginMaxAttempts+1 correct-password logins from one IP within the
// window must all succeed.
func TestLoginBudget_SuccessfulLoginsDoNotConsumeTheBudget(t *testing.T) {
	db := openLoginBudgetDB(t, fmt.Sprintf("file:kxloginbudget%d?mode=memory&cache=shared", loginBudgetDBCounter.Add(1)))
	h := newLoginBudgetHandler(db)
	for i := 0; i < core.LoginMaxAttempts+1; i++ {
		w := postLoginAs(t, h, lockoutOracleTestPassword)
		require.Equal(t, http.StatusOK, w.Code,
			"successful login %d of %d from one IP was refused (%s) -- successful logins must not spend the brute-force budget (#2936)",
			i+1, core.LoginMaxAttempts+1, w.Body.String())
	}
	require.Zero(t, loginAttemptsFor(t, db), "no failure happened, so no slot may stay counted")
}

// TestLoginBudget_FailuresStillLockAtTheThreshold is the calibration: the fix
// must not have turned the budget off. LoginMaxAttempts wrong passwords, then
// even the CORRECT password is refused with 429 -- and a success interleaved
// before the threshold does not refund the failures already counted.
func TestLoginBudget_FailuresStillLockAtTheThreshold(t *testing.T) {
	db := openLoginBudgetDB(t, fmt.Sprintf("file:kxloginbudget%d?mode=memory&cache=shared", loginBudgetDBCounter.Add(1)))
	h := newLoginBudgetHandler(db)
	for i := 0; i < core.LoginMaxAttempts-1; i++ {
		require.Equal(t, http.StatusUnauthorized, postLoginAs(t, h, "wrong-password").Code, "failure %d", i+1)
	}
	require.Equal(t, http.StatusOK, postLoginAs(t, h, lockoutOracleTestPassword).Code,
		"one slot is still free, so a correct login succeeds")
	require.EqualValues(t, core.LoginMaxAttempts-1, loginAttemptsFor(t, db),
		"the success returned only its OWN slot; the failures before it stay counted")
	require.Equal(t, http.StatusUnauthorized, postLoginAs(t, h, "wrong-password").Code, "failure %d", core.LoginMaxAttempts)

	w := postLoginAs(t, h, lockoutOracleTestPassword)
	require.Equal(t, http.StatusTooManyRequests, w.Code,
		"after LoginMaxAttempts failures the IP must be refused even with the correct password: %s", w.Body.String())
}

// TestLoginBudget_FailureCountSurvivesRestart pins "no restart bypass": the
// budget is the persisted login_attempts table, so a fresh server process over
// the same database still refuses the IP.
func TestLoginBudget_FailureCountSurvivesRestart(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "keyorix.db")
	db := openLoginBudgetDB(t, dsn)
	h := newLoginBudgetHandler(db)
	for i := 0; i < core.LoginMaxAttempts; i++ {
		require.Equal(t, http.StatusUnauthorized, postLoginAs(t, h, "wrong-password").Code, "failure %d", i+1)
	}
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close(), "simulated server stop")

	restarted := newLoginBudgetHandler(openLoginBudgetDB(t, dsn))
	w := postLoginAs(t, restarted, lockoutOracleTestPassword)
	require.Equal(t, http.StatusTooManyRequests, w.Code,
		"a restart must not reset the failure count: %s", w.Body.String())
}

// TestLoginBudget_DeliveredMFALoginConsumesNoSlot: an MFA login is two requests
// (/auth/login, then /auth/mfa/verify). The password step keeps its slot while
// the flow is unfinished (bound to the MFA challenge); the verify step that
// delivers the session returns its own AND the password step's (#2936 item 4,
// Andrei 2026-10-10: the budget counts failures only, so a delivered MFA login
// costs nothing -- it used to cost one slot, which still locked an office IP
// out after ten ordinary MFA logins).
func TestLoginBudget_DeliveredMFALoginConsumesNoSlot(t *testing.T) {
	env := newLockoutOracleEnvWithMFA(t)
	before := loginAttemptsFor(t, env.db)

	w := env.postLogin(t, lockoutOracleTestPassword)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp struct {
		Data struct {
			MFARequired  bool   `json:"mfa_required"`
			MFAChallenge string `json:"mfa_challenge"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.True(t, resp.Data.MFARequired, "setup: alice has TOTP enrolled, so the password step must ask for it")

	code, err := totp.GenerateCode(env.totpSecret, env.clock)
	require.NoError(t, err)
	v := env.postVerify(t, resp.Data.MFAChallenge, code)
	require.Equal(t, http.StatusOK, v.Code, "the MFA step must complete the login: %s", v.Body.String())

	require.EqualValues(t, 0, loginAttemptsFor(t, env.db)-before,
		"a delivered MFA login flow (password + TOTP) must leave no slot of the per-IP budget counted (#2936 item 4)")
}

// TestLoginBudget_SuccessfulRefreshesDoNotConsumeTheBudget: /auth/refresh
// shares the same budget (it is unauthenticated and guards session-token
// guessing), and a logged-in client refreshes on a timer -- so a delivered
// refresh must return its slot too, or an open browser tab locks its own IP
// out of logging in.
func TestLoginBudget_SuccessfulRefreshesDoNotConsumeTheBudget(t *testing.T) {
	db := openLoginBudgetDB(t, fmt.Sprintf("file:kxloginbudget%d?mode=memory&cache=shared", loginBudgetDBCounter.Add(1)))
	h := newLoginBudgetHandler(db)
	w := postLoginAs(t, h, lockoutOracleTestPassword)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	token := resp.Data.Token
	require.NotEmpty(t, token)

	for i := 0; i < core.LoginMaxAttempts+1; i++ {
		r := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		rw := httptest.NewRecorder()
		h.RefreshToken(rw, r)
		require.Equal(t, http.StatusOK, rw.Code, "refresh %d was refused: %s", i+1, rw.Body.String())
		var rr struct {
			Data struct {
				Token string `json:"token"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &rr))
		token = rr.Data.Token
	}
	require.Zero(t, loginAttemptsFor(t, db))

	// A refresh with a dead token is still a counted failure.
	r := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	r.Header.Set("Authorization", "Bearer not-a-real-session-token")
	rw := httptest.NewRecorder()
	h.RefreshToken(rw, r)
	require.Equal(t, http.StatusUnauthorized, rw.Code)
	require.EqualValues(t, 1, loginAttemptsFor(t, db), "a failed refresh still spends a slot")
}
