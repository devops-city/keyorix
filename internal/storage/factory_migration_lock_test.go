package storage

import (
	"path/filepath"
	"sync"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConcurrentCreateStorage_NoMigrationRace pins #266: startHTTPServer and
// startGRPCServer each independently call CreateStorage as separate goroutines
// when both are enabled (a documented example config) — before the fix, both
// could observe a fresh database and race AutoMigrate's CREATE TABLE/CREATE
// INDEX statements against it, with the loser erroring out and never starting.
// This drives N goroutines through CreateStorage concurrently against the SAME
// fresh, file-backed SQLite database (a real, separate *gorm.DB connection per
// goroutine, matching how the two real server-startup paths each open their own
// connection) and asserts every single one succeeds with no error.
func TestConcurrentCreateStorage_NoMigrationRace(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	dbPath := filepath.Join(t.TempDir(), "concurrent-migrate.db")

	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			cfg := &config.Config{}
			cfg.Storage.Type = "local"
			cfg.Storage.Database.Path = dbPath
			_, err := NewStorageFactory().CreateStorage(cfg)
			errs[idx] = err
		}(i)
	}
	close(start) // release all goroutines simultaneously, maximizing overlap
	wg.Wait()

	for i, err := range errs {
		assert.NoError(t, err, "goroutine %d: CreateStorage must not fail under concurrent first-boot migration", i)
	}
}
