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

func TestSSOLoginState_CreateConsumeIsSingleUse(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.SSOLoginState{}))
	ls := NewLocalStorage(db)
	ctx := context.Background()

	require.NoError(t, ls.CreateSSOLoginState(ctx, &models.SSOLoginState{
		State: "st-1", Nonce: "n-1", Provider: "okta", ExpiresAt: time.Now().Add(10 * time.Minute),
	}))

	got, err := ls.ConsumeSSOLoginState(ctx, "st-1")
	require.NoError(t, err)
	assert.Equal(t, "n-1", got.Nonce)
	assert.Equal(t, "okta", got.Provider)

	// Second consume of the same state fails — it was deleted (no replay).
	_, err = ls.ConsumeSSOLoginState(ctx, "st-1")
	require.Error(t, err)
}

// TestConcurrency_ConsumeSSOLoginState_OnlyOneWins is the #321 regression: two
// concurrent callback POSTs carrying the SAME state/RelayState must not both pass
// consumption and each mint a session. The old implementation was an unwrapped
// SELECT (First) followed by a separate DELETE — both racers could pass the SELECT
// before either DELETE landed. ConsumeSSOLoginState now scopes its DELETE with the
// same "id = ? AND state = ?" predicate and only the caller whose DELETE actually
// affects a row (RowsAffected == 1) may proceed; this drives real concurrent callers
// (file-backed SQLite, WAL, genuine multi-connection contention — a shared
// :memory: connection would serialize every statement and mask the race) and
// asserts exactly one of them ever succeeds.
func TestConcurrency_ConsumeSSOLoginState_OnlyOneWins(t *testing.T) {
	db := concurrentDB(t)
	require.NoError(t, db.AutoMigrate(&models.SSOLoginState{}))
	ls := NewLocalStorage(db)

	require.NoError(t, ls.CreateSSOLoginState(context.Background(), &models.SSOLoginState{
		State: "race-state", Nonce: "n-1", Provider: "okta", ExpiresAt: time.Now().Add(10 * time.Minute),
	}))

	const racers = 32
	var succeeded atomic.Int64
	errs := make(chan error, racers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range racers {
		wg.Go(func() {
			<-start
			_, err := ls.ConsumeSSOLoginState(context.Background(), "race-state")
			if err == nil {
				succeeded.Add(1)
				return
			}
			errs <- err
		})
	}
	close(start) // release every racer at once
	wg.Wait()
	close(errs)
	for err := range errs {
		require.Error(t, err, "every losing racer must get the ordinary not-found/already-consumed error")
	}

	assert.Equal(t, int64(1), succeeded.Load(), "exactly one concurrent consume may win — never zero, never more than one")

	var count int64
	require.NoError(t, db.Model(&models.SSOLoginState{}).Where("state = ?", "race-state").Count(&count).Error)
	assert.Zero(t, count, "the row must be gone after the winning consume, regardless of how many racers competed")
}
