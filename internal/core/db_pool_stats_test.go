package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// #3037: DBPoolStats exposes the backend's live pool where there is one, and says
// "not available" (never zeros) where there is none.
func TestDBPoolStats(t *testing.T) {
	t.Run("pooled backend reports its live pool", func(t *testing.T) {
		db := newHealthTestDB(t) // MaxOpenConns(1)
		c := NewKeyorixCore(store.NewLocalStorage(db))
		stats, ok := c.DBPoolStats()
		require.True(t, ok)
		assert.Equal(t, 1, stats.MaxOpenConnections)
	})
	t.Run("a backend with no local pool is not available", func(t *testing.T) {
		c := NewKeyorixCore(new(MockStorage))
		_, ok := c.DBPoolStats()
		assert.False(t, ok)
	})
	t.Run("nil storage is not available", func(t *testing.T) {
		var c *KeyorixCore
		_, ok := c.DBPoolStats()
		assert.False(t, ok)
		_, ok = (&KeyorixCore{}).DBPoolStats()
		assert.False(t, ok)
	})
}
