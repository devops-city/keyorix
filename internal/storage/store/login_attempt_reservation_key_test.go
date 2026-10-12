package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestReserveLoginAttempt_IsIdempotentPerKey pins the property core's retry
// relies on (#2956 follow-up): reserving the same key twice writes ONE row and
// returns its id both times, so a retry after a write that landed but reported
// an error can never count the attempt twice. Different keys stay distinct
// reservations, and a key is required.
func TestReserveLoginAttempt_IsIdempotentPerKey(t *testing.T) {
	ctx := context.Background()
	ls := newStoreS3(t, "login_attempt_reservation_key", &models.LoginAttempt{})
	ip, now := "198.51.100.7", time.Now()

	id1, err := ls.ReserveLoginAttempt(ctx, ip, now, "key-a")
	require.NoError(t, err)
	id1again, err := ls.ReserveLoginAttempt(ctx, ip, now, "key-a")
	require.NoError(t, err)
	require.Equal(t, id1, id1again, "the same key must resolve to the same reservation")
	n, err := ls.CountRecentLoginAttempts(ctx, ip, now.Add(-time.Minute))
	require.NoError(t, err)
	require.EqualValues(t, 1, n, "a repeated reserve with one key must not count twice")

	id2, err := ls.ReserveLoginAttempt(ctx, ip, now, "key-b")
	require.NoError(t, err)
	require.NotEqual(t, id1, id2)
	n, err = ls.CountRecentLoginAttempts(ctx, ip, now.Add(-time.Minute))
	require.NoError(t, err)
	require.EqualValues(t, 2, n, "calibration: two different reservations are two attempts")

	require.NoError(t, ls.ReleaseLoginAttempt(ctx, id1))
	require.NoError(t, ls.ReleaseLoginAttempt(ctx, id1), "release is idempotent")
	n, err = ls.CountRecentLoginAttempts(ctx, ip, now.Add(-time.Minute))
	require.NoError(t, err)
	require.EqualValues(t, 1, n)

	// Plain RecordLoginAttempt rows carry no key and never collide with each other.
	require.NoError(t, ls.RecordLoginAttempt(ctx, ip, now))
	require.NoError(t, ls.RecordLoginAttempt(ctx, ip, now))
	n, err = ls.CountRecentLoginAttempts(ctx, ip, now.Add(-time.Minute))
	require.NoError(t, err)
	require.EqualValues(t, 3, n)

	_, err = ls.ReserveLoginAttempt(ctx, ip, now, "")
	require.Error(t, err, "a reservation without a key would be unidentifiable")
}
