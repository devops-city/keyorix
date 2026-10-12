// login_budget_fallback_slot_http_test.go — #3023 / #3029 review: a login
// slot taken by the in-memory fallback (core/login_budget_fallback.go) while
// ReserveLoginAttempt fails is a per-process id with the top bit set. It used
// to be persisted into mfa_challenges / web_authn_sessions login_attempt_id;
// SQLite then could not read the row back into a uint, so the second factor
// (or the passwordless Finish) of a user with the right credentials failed,
// and the MFA verify path charged a lockout strike for it. MFA and passkey
// logins broke during the very outage the fallback exists for.
//
// Here the reservation alone fails (the password step's, or Begin's), and the
// rest of the flow runs against healthy storage: it must deliver a session.
// The reservation fails on EVERY call while down, because core retries a failed
// reservation write once with the same key (#3050): a single failure is
// recovered by that retry and never reaches the fallback.
package handlers

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// reserveLoginAttemptDownStore fails ReserveLoginAttempt (only) while down,
// on every call, counting them.
type reserveLoginAttemptDownStore struct {
	corestorage.Storage
	down  *atomic.Bool
	calls *atomic.Int32
}

func (s reserveLoginAttemptDownStore) ReserveLoginAttempt(ctx context.Context, ip string, at time.Time, key string) (uint, error) {
	if s.down.Load() {
		s.calls.Add(1)
		return 0, errLoginAttemptsStoreDown
	}
	return s.Storage.ReserveLoginAttempt(ctx, ip, at, key)
}

// requireReservationFellBack is the calibration: both the reservation write
// and its retry failed, and no stored row exists.
func requireReservationFellBack(t *testing.T, db *gorm.DB, calls *atomic.Int32) {
	t.Helper()
	require.Equal(t, int32(2), calls.Load(), "calibration: the reservation and its one retry both failed")
	var n int64
	require.NoError(t, db.Model(&models.LoginAttempt{}).Count(&n).Error)
	require.Zero(t, n, "calibration: no stored reservation, so the slot came from the in-memory fallback")
}

func TestLoginBudgetFallbackSlot_TOTPLoginStillCompletes(t *testing.T) {
	var down atomic.Bool
	var calls atomic.Int32
	env := newLockoutOracleEnvWithMFAOver(t, func(s corestorage.Storage, _ *gorm.DB) corestorage.Storage {
		return reserveLoginAttemptDownStore{Storage: s, down: &down, calls: &calls}
	})
	down.Store(true)
	ch := env.mfaPasswordStep(t)
	requireReservationFellBack(t, env.db, &calls)
	down.Store(false)

	v := env.postVerify(t, ch, env.nextTOTP(t))
	require.Equal(t, http.StatusOK, v.Code,
		"a correct TOTP after a password step whose slot came from the fallback must log in: %s", v.Body.String())

	var u models.User
	require.NoError(t, env.db.First(&u, 1).Error)
	assert.Zero(t, u.FailedLoginAttempts, "a correct password and a correct code must not cost a lockout strike")
	assert.Nil(t, u.LoginLockedUntil)
}

func TestLoginBudgetFallbackSlot_PasswordlessLoginStillCompletes(t *testing.T) {
	var down atomic.Bool
	var calls atomic.Int32
	h, _, db := newWebAuthnCompletionEnvOver(t, func(s corestorage.Storage) corestorage.Storage {
		return reserveLoginAttemptDownStore{Storage: s, down: &down, calls: &calls}
	})
	cred, _ := wcAssertionJSONWithUserHandle(t, false)

	down.Store(true)
	tok := beginPasskey(t, db, postJSONTo(t, h.BeginWebAuthnPasswordlessLogin, "/auth/webauthn/passwordless/begin", map[string]string{}), true)
	requireReservationFellBack(t, db, &calls)
	down.Store(false)

	var ws models.WebAuthnSession
	require.NoError(t, db.First(&ws).Error, "Begin's ceremony row must be readable")
	assert.Nil(t, ws.LoginAttemptID, "a per-process fallback slot id must not be persisted to the shared ceremony row")

	fw := postJSONTo(t, h.FinishWebAuthnPasswordlessLogin, "/auth/webauthn/passwordless/finish",
		map[string]any{"webauthn_session": tok, "credential": cred})
	require.Equal(t, http.StatusOK, fw.Code,
		"a verifying passkey after a Begin whose slot came from the fallback must log in: %s", fw.Body.String())
}
