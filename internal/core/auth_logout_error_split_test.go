package core

// auth_logout_error_split_test.go is the core-level red-proof for item 3 of the UX-fixes
// batch: Logout previously collapsed ANY storage.GetSession error into ErrSessionNotFound
// (#2337 fixed the double-logout case by doing exactly that unconditionally), so a real
// storage failure during the lookup got the same 401-mapped sentinel as an ordinary
// already-logged-out token -- a genuine server fault silently reported as an authentication
// outcome. Red on main: both cases returned ErrSessionNotFound. Green after the fix: only a
// genuine not-found does; any other GetSession failure propagates as a distinct error for the
// HTTP handler's existing (and already-correct) non-ErrSessionNotFound branch to map to 500.

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failGetSessionStorage fails GetSession for one specific token with a plain error — NOT
// wrapping storage.ErrSessionNotFound — to simulate a real retrieval failure (DB down, a
// timeout) distinct from a genuine "no such session."
func failGetSessionStorage(inner storage.Storage, failToken string) storage.Storage {
	return hooked(inner, &storeHooks{
		GetSession: func(next storage.Storage, ctx context.Context, token string) (*models.Session, error) {
			if token == failToken {
				return nil, errors.New("injected fault: simulated DB connection lost")
			}
			return next.GetSession(ctx, token)
		},
	})
}

func TestLogout_DistinguishesNotFoundFromStorageFailure(t *testing.T) {
	c, base := newBootstrappedCore(t)
	ctx := context.Background()

	// Genuine not-found: a token that never existed.
	err := c.Logout(ctx, "never-existed-token")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSessionNotFound), "a token that never existed must map to ErrSessionNotFound: %v", err)

	// Real storage failure: GetSession fails for a reason that is NOT "not found."
	c.storage = failGetSessionStorage(base, "fails-to-look-up")
	err = c.Logout(ctx, "fails-to-look-up")
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrSessionNotFound),
		"a real storage failure must NOT be reported as ErrSessionNotFound (would silently become a 401 in the HTTP handler): %v", err)
}
