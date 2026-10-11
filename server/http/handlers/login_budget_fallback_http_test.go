// login_budget_fallback_http_test.go — the per-IP login budget's in-memory
// fallback (core/login_budget_fallback.go) over HTTP: with LoginAttempt storage
// down the IP is still refused after LoginMaxAttempts failures, and the refusal
// is byte-for-byte the 429 the stored budget sends.
package handlers

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

type loginAttemptsDownStore struct{ corestorage.Storage }

var errLoginAttemptsStoreDown = errors.New("pq: connection reset by peer")

func (loginAttemptsDownStore) CountRecentLoginAttempts(context.Context, string, time.Time) (int64, error) {
	return 0, errLoginAttemptsStoreDown
}
func (loginAttemptsDownStore) RecordLoginAttempt(context.Context, string, time.Time) error {
	return errLoginAttemptsStoreDown
}
func (loginAttemptsDownStore) ReserveLoginAttempt(context.Context, string, time.Time) (uint, error) {
	return 0, errLoginAttemptsStoreDown
}
func (loginAttemptsDownStore) ReleaseLoginAttempt(context.Context, uint) error {
	return errLoginAttemptsStoreDown
}

func TestLoginBudget_StorageDownStillRefusesWithTheSame429(t *testing.T) {
	// Control: the stored budget's 429.
	cdb := openLoginBudgetDB(t, "file:kxfallbackctl?mode=memory&cache=shared")
	ch := newLoginBudgetHandler(cdb)
	for i := 0; i < core.LoginMaxAttempts; i++ {
		require.Equal(t, http.StatusUnauthorized, postLoginAs(t, ch, "wrong-password").Code)
	}
	control := postLoginAs(t, ch, lockoutOracleTestPassword)
	require.Equal(t, http.StatusTooManyRequests, control.Code)

	// Probe: every LoginAttempt call fails.
	pdb := openLoginBudgetDB(t, "file:kxfallbackprobe?mode=memory&cache=shared")
	ph := NewAuthHandler(core.NewKeyorixCore(loginAttemptsDownStore{store.NewLocalStorage(pdb)}), false)
	for i := 0; i < core.LoginMaxAttempts; i++ {
		require.Equal(t, http.StatusUnauthorized, postLoginAs(t, ph, "wrong-password").Code, "failure %d", i+1)
	}
	probe := postLoginAs(t, ph, lockoutOracleTestPassword)
	require.Equal(t, http.StatusTooManyRequests, probe.Code,
		"with LoginAttempt storage down the budget must still bind (it used to fail open): %s", probe.Body.String())
	requireSameResponse(t, control, probe, "429 from the in-memory fallback")
}
