package handlers

// #2956 follow-up: a login-attempt reservation is identified by a key core
// generates BEFORE the write, so a write that landed but reported an error
// (a lost acknowledgement) is neither lost nor counted twice. Before this the
// reservation was known only by the row id the write returned: on such an
// error the request had no handle, so a delivered login could not hand its slot
// back (the success stayed counted, #2936's symptom), found by the exhaustive
// fault sweep as ReserveLoginAttempt#1/effect-then-error on /auth/login,
// /auth/mfa/verify and /auth/webauthn/login/finish.
//
// Each test reads the per-IP LoginAttempt rows back: the effect, not a return
// value, is what distinguishes "counted once" from "lost" or "counted twice".

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func newFaultyLoginBudgetHandler(t *testing.T) (*AuthHandler, *faultstorage.FaultyStorage, *gorm.DB) {
	t.Helper()
	db := openLoginBudgetDB(t, fmt.Sprintf("file:kxloginbudgetres%d?mode=memory&cache=shared", loginBudgetDBCounter.Add(1)))
	fs := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
	return NewAuthHandler(core.NewKeyorixCore(fs), false), fs, db
}

func armReserve(fs *faultstorage.FaultyStorage, kind faultstorage.FaultKind) {
	fs.Arm(&faultstorage.FaultSpec{Method: "ReserveLoginAttempt", NthCall: 1, Kind: kind, Err: errors.New("injected")})
}

func TestLoginBudget_ReservationThatLandedDespiteAnError_IsReturnedByADeliveredLogin(t *testing.T) {
	h, fs, db := newFaultyLoginBudgetHandler(t)
	armReserve(fs, faultstorage.KindEffectThenError)

	w := postLoginAs(t, h, lockoutOracleTestPassword)
	require.True(t, fs.Fired())
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Zero(t, loginAttemptsFor(t, db),
		"the reservation row landed; a delivered login must hand it back, not leave a success counted (#2936)")
}

func TestLoginBudget_ReservationThatLandedDespiteAnError_CountsAWrongPasswordOnce(t *testing.T) {
	h, fs, db := newFaultyLoginBudgetHandler(t)
	armReserve(fs, faultstorage.KindEffectThenError)

	w := postLoginAs(t, h, "wrong-password")
	require.True(t, fs.Fired())
	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.EqualValues(t, 1, loginAttemptsFor(t, db),
		"a failed credential counts exactly once: not lost, and the retry must not add a second row")
}

func TestLoginBudget_ReservationWriteFailedOnce_IsRetriedSoAWrongPasswordStillCounts(t *testing.T) {
	h, fs, db := newFaultyLoginBudgetHandler(t)
	armReserve(fs, faultstorage.KindError)

	w := postLoginAs(t, h, "wrong-password")
	require.True(t, fs.Fired())
	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.EqualValues(t, 1, loginAttemptsFor(t, db),
		"one failed reservation write must not let a wrong password go uncounted")
}

func TestLoginBudget_ReservationWriteFailedOnce_DeliveredLoginLeavesNoSlot(t *testing.T) {
	h, fs, db := newFaultyLoginBudgetHandler(t)
	armReserve(fs, faultstorage.KindError)

	w := postLoginAs(t, h, lockoutOracleTestPassword)
	require.True(t, fs.Fired())
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Zero(t, loginAttemptsFor(t, db), "calibration: the retried reservation is still released on delivery")
}
