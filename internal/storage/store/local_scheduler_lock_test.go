package store

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func newSchedLockStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	return NewLocalStorage(db)
}

// On SQLite (single instance) the job always runs and fn's result propagates.
func TestWithSchedulerLock_SQLiteAlwaysRuns(t *testing.T) {
	ls := newSchedLockStore(t)
	ctx := context.Background()

	ran := false
	got, err := ls.WithSchedulerLock(ctx, 123, func(context.Context) error {
		ran = true
		return nil
	})
	require.NoError(t, err)
	assert.True(t, got, "ran=true on SQLite")
	assert.True(t, ran, "fn executed")

	// fn's error propagates, still ran=true.
	sentinel := errors.New("boom")
	got, err = ls.WithSchedulerLock(ctx, 123, func(context.Context) error { return sentinel })
	assert.True(t, got)
	require.ErrorIs(t, err, sentinel)

	// Re-entrant: a second call still runs (no held lock on SQLite).
	got, err = ls.WithSchedulerLock(ctx, 123, func(context.Context) error { return nil })
	require.NoError(t, err)
	assert.True(t, got)
}

// A panic in the job is converted to an error rather than killing the caller's
// scheduler goroutine.
func TestWithSchedulerLock_RecoversPanic(t *testing.T) {
	ls := newSchedLockStore(t)
	got, err := ls.WithSchedulerLock(context.Background(), 7, func(context.Context) error {
		panic("kaboom")
	})
	assert.True(t, got)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "panicked")
}
