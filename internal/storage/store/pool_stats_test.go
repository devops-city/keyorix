package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

// #3037: the system-info pool numbers must be the live *sql.DB's, not config echoes or
// constants. PoolStats is the read of those numbers; it must follow the pool as
// connections are taken and returned.
func TestLocalStoragePoolStats_FollowsThePool(t *testing.T) {
	db := sqlitetest.OpenWithDialector(t, "poolstats_", sqlite.Open, &gorm.Config{})
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(5)
	ls := NewLocalStorage(db)

	stats, ok := ls.PoolStats()
	require.True(t, ok)
	assert.Equal(t, 5, stats.MaxOpenConnections, "the cap actually applied to the pool")
	assert.Equal(t, 0, stats.InUse)

	c1, err := sqlDB.Conn(context.Background())
	require.NoError(t, err)
	c2, err := sqlDB.Conn(context.Background())
	require.NoError(t, err)
	stats, ok = ls.PoolStats()
	require.True(t, ok)
	assert.Equal(t, 2, stats.InUse, "two connections held")

	require.NoError(t, c1.Close())
	require.NoError(t, c2.Close())
	stats, ok = ls.PoolStats()
	require.True(t, ok)
	assert.Equal(t, 0, stats.InUse, "returned to the pool")
	assert.Equal(t, stats.OpenConnections-stats.InUse, stats.Idle)
}

func TestLocalStoragePoolStats_NilSafe(t *testing.T) {
	var ls *LocalStorage
	_, ok := ls.PoolStats()
	assert.False(t, ok)
	_, ok = (&LocalStorage{}).PoolStats()
	assert.False(t, ok)
}
