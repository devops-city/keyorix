package store

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func newMFAStepUpGrantStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.MFAStepUpGrant{}))
	return NewLocalStorage(db)
}

func TestMFAStepUpGrant_CreateAndDeleteFor(t *testing.T) {
	ls := newMFAStepUpGrantStore(t)
	ctx := context.Background()

	require.NoError(t, ls.CreateMFAStepUpGrant(ctx, &models.MFAStepUpGrant{
		UserID: 1, Purpose: models.MFAStepUpPurposeRestrictedSecretRead, ExpiresAt: time.Now().Add(10 * time.Minute),
	}))
	require.NoError(t, ls.CreateMFAStepUpGrant(ctx, &models.MFAStepUpGrant{
		UserID: 1, Purpose: models.MFAStepUpPurposeRestrictedSecretRead, ExpiresAt: time.Now().Add(20 * time.Minute),
	}))
	require.NoError(t, ls.CreateMFAStepUpGrant(ctx, &models.MFAStepUpGrant{
		UserID: 2, Purpose: models.MFAStepUpPurposeRestrictedSecretRead, ExpiresAt: time.Now().Add(10 * time.Minute),
	}))

	g, err := ls.GetActiveMFAStepUpGrant(ctx, 1, models.MFAStepUpPurposeRestrictedSecretRead, time.Now())
	require.NoError(t, err)
	require.NotNil(t, g)
	assert.Equal(t, uint(1), g.UserID)

	require.NoError(t, ls.DeleteMFAStepUpGrantsFor(ctx, 1))

	g, err = ls.GetActiveMFAStepUpGrant(ctx, 1, models.MFAStepUpPurposeRestrictedSecretRead, time.Now())
	require.NoError(t, err)
	assert.Nil(t, g, "all of user 1's grants were deleted")

	// User 2's grant must be untouched.
	g2, err := ls.GetActiveMFAStepUpGrant(ctx, 2, models.MFAStepUpPurposeRestrictedSecretRead, time.Now())
	require.NoError(t, err)
	require.NotNil(t, g2)
}

func TestMFAStepUpGrant_PruneRemovesOnlyExpired(t *testing.T) {
	ls := newMFAStepUpGrantStore(t)
	ctx := context.Background()

	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)

	require.NoError(t, ls.CreateMFAStepUpGrant(ctx, &models.MFAStepUpGrant{UserID: 1, Purpose: models.MFAStepUpPurposeRestrictedSecretRead, ExpiresAt: past}))
	require.NoError(t, ls.CreateMFAStepUpGrant(ctx, &models.MFAStepUpGrant{UserID: 2, Purpose: models.MFAStepUpPurposeRestrictedSecretRead, ExpiresAt: past}))
	require.NoError(t, ls.CreateMFAStepUpGrant(ctx, &models.MFAStepUpGrant{UserID: 3, Purpose: models.MFAStepUpPurposeRestrictedSecretRead, ExpiresAt: future}))

	deleted, err := ls.PruneMFAStepUpGrants(ctx, time.Now())
	require.NoError(t, err)
	assert.Equal(t, int64(2), deleted)

	g3, err := ls.GetActiveMFAStepUpGrant(ctx, 3, models.MFAStepUpPurposeRestrictedSecretRead, time.Now())
	require.NoError(t, err)
	require.NotNil(t, g3, "the not-yet-expired grant must survive the prune")
}

func TestMFAStepUpGrant_GetActiveNoneReturnsNilNil(t *testing.T) {
	ls := newMFAStepUpGrantStore(t)
	g, err := ls.GetActiveMFAStepUpGrant(context.Background(), 99, models.MFAStepUpPurposeRestrictedSecretRead, time.Now())
	require.NoError(t, err)
	assert.Nil(t, g)
}

func TestMFAStepUpGrant_DeleteForNoneIsNoop(t *testing.T) {
	ls := newMFAStepUpGrantStore(t)
	require.NoError(t, ls.DeleteMFAStepUpGrantsFor(context.Background(), 404))
}

// TestConsumeMFAStepUpGrant_FirstCallSucceeds_SecondCallFails is the single-use
// regression at the storage layer (follow-up to #1775): the atomic conditional
// UPDATE ... WHERE consumed_at IS NULL must consume the grant on its first call
// and refuse every subsequent one, mirroring ConsumeMFARecoveryCode/
// ConsumeWebAuthnSession/ConsumeSSOLoginState's single-use shape.
func TestConsumeMFAStepUpGrant_FirstCallSucceeds_SecondCallFails(t *testing.T) {
	ls := newMFAStepUpGrantStore(t)
	ctx := context.Background()
	now := time.Now()

	require.NoError(t, ls.CreateMFAStepUpGrant(ctx, &models.MFAStepUpGrant{
		UserID: 1, Purpose: models.MFAStepUpPurposeReauth, ExpiresAt: now.Add(15 * time.Minute),
	}))

	consumed, err := ls.ConsumeMFAStepUpGrant(ctx, 1, models.MFAStepUpPurposeReauth, now)
	require.NoError(t, err)
	assert.True(t, consumed, "a live, unconsumed grant must be consumed on first call")

	// The grant is no longer reported active, whether read via the consuming or
	// the non-consuming lookup.
	consumed2, err := ls.ConsumeMFAStepUpGrant(ctx, 1, models.MFAStepUpPurposeReauth, now)
	require.NoError(t, err)
	assert.False(t, consumed2, "a second consume of the SAME already-consumed grant must fail -- this is exactly the single-use fix")

	g, err := ls.GetActiveMFAStepUpGrant(ctx, 1, models.MFAStepUpPurposeReauth, now)
	require.NoError(t, err)
	assert.Nil(t, g, "a consumed grant must not be reported active by the non-consuming lookup either")
}

// TestConsumeMFAStepUpGrant_ExpiredGrantNotConsumed confirms the atomic UPDATE's
// expiry predicate is honored: an expired grant is never consumable, even though
// its row still exists (kept for audit purposes, per PruneMFAStepUpGrants).
func TestConsumeMFAStepUpGrant_ExpiredGrantNotConsumed(t *testing.T) {
	ls := newMFAStepUpGrantStore(t)
	ctx := context.Background()
	now := time.Now()

	require.NoError(t, ls.CreateMFAStepUpGrant(ctx, &models.MFAStepUpGrant{
		UserID: 1, Purpose: models.MFAStepUpPurposeReauth, ExpiresAt: now.Add(-time.Minute),
	}))

	consumed, err := ls.ConsumeMFAStepUpGrant(ctx, 1, models.MFAStepUpPurposeReauth, now)
	require.NoError(t, err)
	assert.False(t, consumed, "an expired grant must never be consumable")
}

// TestConsumeMFAStepUpGrant_WrongPurposeNotConsumed confirms purpose is an exact
// match, not a filter of convenience -- consuming for Reauth must never touch (or
// report success against) a RestrictedSecretRead-purpose grant, and vice versa.
func TestConsumeMFAStepUpGrant_WrongPurposeNotConsumed(t *testing.T) {
	ls := newMFAStepUpGrantStore(t)
	ctx := context.Background()
	now := time.Now()

	require.NoError(t, ls.CreateMFAStepUpGrant(ctx, &models.MFAStepUpGrant{
		UserID: 1, Purpose: models.MFAStepUpPurposeRestrictedSecretRead, ExpiresAt: now.Add(15 * time.Minute),
	}))

	consumed, err := ls.ConsumeMFAStepUpGrant(ctx, 1, models.MFAStepUpPurposeReauth, now)
	require.NoError(t, err)
	assert.False(t, consumed, "a RestrictedSecretRead-purpose grant must not satisfy a Reauth-purpose consume")

	// The RestrictedSecretRead grant itself must remain untouched (still active,
	// still unconsumed) -- confirms the UPDATE's WHERE clause never matched it.
	g, err := ls.GetActiveMFAStepUpGrant(ctx, 1, models.MFAStepUpPurposeRestrictedSecretRead, now)
	require.NoError(t, err)
	require.NotNil(t, g, "the wrong-purpose grant must remain active -- untouched by the mismatched consume attempt")
}

// TestConsumeMFAStepUpGrant_NoneReturnsFalseNil mirrors
// TestMFAStepUpGrant_GetActiveNoneReturnsNilNil: no matching row is a normal,
// non-error outcome.
func TestConsumeMFAStepUpGrant_NoneReturnsFalseNil(t *testing.T) {
	ls := newMFAStepUpGrantStore(t)
	consumed, err := ls.ConsumeMFAStepUpGrant(context.Background(), 99, models.MFAStepUpPurposeReauth, time.Now())
	require.NoError(t, err)
	assert.False(t, consumed)
}

// TestConcurrency_ConsumeMFAStepUpGrant_OnlyOneWins is ConsumeSSOLoginState's
// #321 regression, repeated for MFAStepUpGrant: two near-simultaneous
// requireReauth calls (e.g. two browser tabs racing to disable MFA and to
// regenerate recovery codes off the SAME live grant) must not both observe the
// grant as live. A naive read-then-write ("is there an active grant?" followed
// by a separate "mark it consumed") would let both racers pass the read before
// either write lands. ConsumeMFAStepUpGrant's single conditional UPDATE (WHERE
// consumed_at IS NULL) closes that window -- only the racer whose UPDATE
// actually affects a row may proceed. Uses concurrentDB (file-backed SQLite,
// genuine multi-connection contention), not a shared :memory: connection, which
// would serialize every statement and mask the race entirely.
func TestConcurrency_ConsumeMFAStepUpGrant_OnlyOneWins(t *testing.T) {
	db := concurrentDB(t)
	require.NoError(t, db.AutoMigrate(&models.MFAStepUpGrant{}))
	ls := NewLocalStorage(db)
	ctx := context.Background()
	now := time.Now()

	require.NoError(t, ls.CreateMFAStepUpGrant(ctx, &models.MFAStepUpGrant{
		UserID: 1, Purpose: models.MFAStepUpPurposeReauth, ExpiresAt: now.Add(15 * time.Minute),
	}))

	const racers = 32
	var succeeded atomic.Int64
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range racers {
		wg.Go(func() {
			<-start
			consumed, err := ls.ConsumeMFAStepUpGrant(context.Background(), 1, models.MFAStepUpPurposeReauth, now)
			require.NoError(t, err)
			if consumed {
				succeeded.Add(1)
			}
		})
	}
	close(start) // release every racer at once
	wg.Wait()

	assert.Equal(t, int64(1), succeeded.Load(), "exactly one concurrent consume may win -- never zero, never more than one")
}
