// current_password_budget_test.go — AUTH-PW-BUDGET: POST /auth/change-password
// and PUT /auth/profile (with current_password) check the caller's password, so
// they spend the same per-IP login budget as /auth/login (one login_attempts
// count per IP, failures only) and audit a wrong password with the event a
// failed login writes. The per-account lockout half is core's
// (internal/core/account_current_password_lockout_test.go).
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/keyorixhq/keyorix/server/middleware"
)

const currentPwNew = "Brandnew#Passw0rd!y"

func openCurrentPasswordDB(t *testing.T) *gorm.DB {
	t.Helper()
	db := openLoginBudgetDB(t, sqlitetest.DSN("kxcurpwbudget"))
	require.NoError(t, db.AutoMigrate(&models.PersonalAccessToken{}))
	return db
}

// asAlice sends body to handler as an authenticated request from user 1, from
// lockoutOracleTestIP (httptest's default RemoteAddr).
func asAlice(t *testing.T, handler http.HandlerFunc, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(),
		&middleware.UserContext{UserID: 1, Username: "alice", Email: "alice@example.com"}))
	w := httptest.NewRecorder()
	handler(w, req)
	return w
}

func changePasswordAs(t *testing.T, h *AuthHandler, current, next string) *httptest.ResponseRecorder {
	t.Helper()
	return asAlice(t, h.ChangePassword, http.MethodPost, "/auth/change-password",
		map[string]string{"current_password": current, "new_password": next})
}

func updateProfileAs(t *testing.T, h *AuthHandler, body map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	return asAlice(t, h.UpdateProfile, http.MethodPut, "/auth/profile", body)
}

// Wrong current passwords spend the login budget: after LoginMaxAttempts the IP
// gets 429 on this endpoint, and on /auth/login, even with the right password.
func TestChangePassword_WrongPasswordsSpendTheLoginBudget(t *testing.T) {
	db := openCurrentPasswordDB(t)
	h := newLoginBudgetHandler(db)
	for i := range core.LoginMaxAttempts {
		w := changePasswordAs(t, h, "wrong-guess", currentPwNew)
		require.Equal(t, http.StatusUnauthorized, w.Code, "guess %d: %s", i+1, w.Body.String())
	}
	require.EqualValues(t, core.LoginMaxAttempts, loginAttemptsFor(t, db), "every wrong guess keeps its slot")

	w := changePasswordAs(t, h, lockoutOracleTestPassword, currentPwNew)
	require.Equal(t, http.StatusTooManyRequests, w.Code, "budget spent: refused before the check: %s", w.Body.String())
	w = postLoginAs(t, h, lockoutOracleTestPassword)
	require.Equal(t, http.StatusTooManyRequests, w.Code, "one budget: /auth/login from the same IP is refused too: %s", w.Body.String())

	var u models.User
	require.NoError(t, db.First(&u, 1).Error)
	require.NoError(t, bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(lockoutOracleTestPassword)), "the refused request changed nothing")
}

// Failed logins spend the budget this endpoint checks, too.
func TestChangePassword_RefusedOnceFailedLoginsSpentTheBudget(t *testing.T) {
	db := openCurrentPasswordDB(t)
	h := newLoginBudgetHandler(db)
	for range core.LoginMaxAttempts {
		require.Equal(t, http.StatusUnauthorized, postLoginAs(t, h, "wrong-guess").Code)
	}
	w := changePasswordAs(t, h, lockoutOracleTestPassword, currentPwNew)
	require.Equal(t, http.StatusTooManyRequests, w.Code, w.Body.String())
}

// Equivalence: a correct password still works and costs no slot (failures only,
// INV-HTTP-login-budget-counts-failures-only), as does a refused new password.
func TestChangePassword_SuccessAndPolicyRefusalReturnTheSlot(t *testing.T) {
	db := openCurrentPasswordDB(t)
	h := newLoginBudgetHandler(db)

	w := changePasswordAs(t, h, lockoutOracleTestPassword, "short")
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	require.Zero(t, loginAttemptsFor(t, db), "a refused NEW password is not a failed credential")

	w = changePasswordAs(t, h, lockoutOracleTestPassword, currentPwNew)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Zero(t, loginAttemptsFor(t, db), "a successful change returns its slot")
}

// A wrong current password is audited like a failed login: auth.login_failed,
// success=false, with the client IP (and the account, which is known here).
func TestChangePassword_WrongPasswordAuditedLikeAFailedLogin(t *testing.T) {
	db := openCurrentPasswordDB(t)
	h := newLoginBudgetHandler(db)
	require.Equal(t, http.StatusUnauthorized, changePasswordAs(t, h, "wrong-guess", currentPwNew).Code)
	DrainBackgroundGoroutines()
	core.DrainBackgroundGoroutines()

	var ev []models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", "auth.login_failed").Find(&ev).Error)
	require.Len(t, ev, 1)
	assert.Equal(t, lockoutOracleTestIP, ev[0].IPAddress)
	require.NotNil(t, ev[0].UserID)
	assert.EqualValues(t, 1, *ev[0].UserID)
	require.NotNil(t, ev[0].Success)
	assert.False(t, *ev[0].Success)
	assert.Contains(t, ev[0].Description, "change_password")
}

// PUT /auth/profile: an email change with a wrong current_password spends the
// budget; a request without current_password guesses nothing and is never
// throttled (a display-name edit from an IP whose budget is spent still works).
func TestUpdateProfile_PasswordGuessesSpendTheLoginBudget(t *testing.T) {
	db := openCurrentPasswordDB(t)
	h := newLoginBudgetHandler(db)
	guess := map[string]string{"email": "mallory@example.com", "current_password": "wrong-guess"}
	for i := range core.LoginMaxAttempts {
		w := updateProfileAs(t, h, guess)
		require.Equal(t, http.StatusUnauthorized, w.Code, "guess %d: %s", i+1, w.Body.String())
	}
	w := updateProfileAs(t, h, map[string]string{"email": "mallory@example.com", "current_password": lockoutOracleTestPassword})
	require.Equal(t, http.StatusTooManyRequests, w.Code, w.Body.String())

	w = updateProfileAs(t, h, map[string]string{"display_name": "Alice A."})
	require.Equal(t, http.StatusOK, w.Code, "no password, no guess, no budget: %s", w.Body.String())

	var u models.User
	require.NoError(t, db.First(&u, 1).Error)
	assert.Equal(t, "alice@example.com", u.Email)
	assert.Equal(t, "Alice A.", u.DisplayName)
}

// Equivalence for the email change: the right password works and costs no slot.
func TestUpdateProfile_CorrectPasswordReturnsTheSlot(t *testing.T) {
	db := openCurrentPasswordDB(t)
	h := newLoginBudgetHandler(db)
	w := updateProfileAs(t, h, map[string]string{"email": "alice@new.example.com", "current_password": lockoutOracleTestPassword})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Zero(t, loginAttemptsFor(t, db))
	var u models.User
	require.NoError(t, db.First(&u, 1).Error)
	assert.Equal(t, "alice@new.example.com", u.Email)
}

// A panic inside the check is a server bug: Recovery answers 500 and the
// unsettled slot is handed back, so the 500 changes nothing (the faultops sweep
// flagged the kept LoginAttempt row as oracle (a)). Covers a pre-verdict panic
// (GetUser) and post-verdict ones (SetPasswordHash, WithTransaction).
func TestChangePassword_PanicReturnsTheSlot(t *testing.T) {
	for _, method := range []string{"GetUser", "SetPasswordHash", "WithTransaction"} {
		t.Run(method, func(t *testing.T) {
			db := openCurrentPasswordDB(t)
			fs := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), &faultstorage.FaultSpec{
				Method: method, NthCall: 1, Kind: faultstorage.KindPanic,
			})
			h := NewAuthHandler(core.NewKeyorixCore(fs), false)
			w := asAlice(t, func(w http.ResponseWriter, r *http.Request) {
				middleware.Recovery()(http.HandlerFunc(h.ChangePassword)).ServeHTTP(w, r)
			}, http.MethodPost, "/auth/change-password",
				map[string]string{"current_password": lockoutOracleTestPassword, "new_password": currentPwNew})
			require.True(t, fs.Fired(), "the %s panic must have been reached", method)
			require.Equal(t, http.StatusInternalServerError, w.Code, w.Body.String())
			require.Zero(t, loginAttemptsFor(t, db), "a panic must not leave the slot counted")
		})
	}
}

// AUTH-2 sweep (pre-existing on main): PUT /auth/profile reads the identity for
// its response AFTER the update committed; a panic there answered 500 over a
// changed email. It is now reported like the read's error (empty identity).
func TestUpdateProfile_IdentityReadPanicAfterCommitStillAnswersOK(t *testing.T) {
	db := openCurrentPasswordDB(t)
	fs := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), &faultstorage.FaultSpec{
		Method: "GetUserRoles", NthCall: 1, Kind: faultstorage.KindPanic,
	})
	h := NewAuthHandler(core.NewKeyorixCore(fs), false)
	w := asAlice(t, func(w http.ResponseWriter, r *http.Request) {
		middleware.Recovery()(http.HandlerFunc(h.UpdateProfile)).ServeHTTP(w, r)
	}, http.MethodPut, "/auth/profile", map[string]string{"display_name": "Alice B."})
	require.True(t, fs.Fired())
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var u models.User
	require.NoError(t, db.First(&u, 1).Error)
	require.Equal(t, "Alice B.", u.DisplayName)
}
