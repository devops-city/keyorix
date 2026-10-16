package core

// last_used_coalescer_postgres_test.go — OPT-LASTUSED-1 concurrency proof on
// real Postgres: concurrent requests of ONE credential no longer queue on that
// credential's row lock. Before, every request ran
// UPDATE ... SET last_used_at WHERE id = ? AND (last_used_at IS NULL OR
// last_used_at < now-30s); while another transaction held the row (here: an
// explicit FOR UPDATE, in production: the request that won the stamp, until
// its commit fsync) every other request of that credential waited on
// Lock/tuple or Lock/transactionid.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func TestLastUsed_Postgres_RequestsDoNotWaitOnCredentialRowLock(t *testing.T) {
	dsn := pgIsolatedSchemaDSN(t, pgTestDSN(t))
	setup := pgOpen(t, dsn)
	require.NoError(t, setup.AutoMigrate(&models.PersonalAccessToken{}, &models.MachineIdentityCredential{}, &models.Session{}))
	require.NoError(t, setup.Create(&models.PersonalAccessToken{ID: 1, UserID: 1, Name: "ci", TokenHash: "h-pat"}).Error)
	require.NoError(t, setup.Create(&models.MachineIdentityCredential{ID: 1, MachineIdentityID: 1, Name: "c", TokenHash: "h-cred"}).Error)
	require.NoError(t, setup.Create(&models.Session{ID: 1, UserID: 1, SessionToken: "h-sess"}).Error)

	// The application's pool: enough connections that a request would wait on
	// the row lock, not on the pool.
	app, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	appSQL, err := app.DB()
	require.NoError(t, err)
	appSQL.SetMaxOpenConns(24)
	t.Cleanup(func() { _ = appSQL.Close() })
	c := NewKeyorixCore(store.NewLocalStorage(app))

	// Another transaction holds all three rows.
	locker := pgOpen(t, dsn)
	tx := locker.Begin()
	require.NoError(t, tx.Error)
	for _, q := range []string{
		"SELECT id FROM personal_access_tokens WHERE id = 1 FOR UPDATE",
		"SELECT id FROM machine_identity_credentials WHERE id = 1 FOR UPDATE",
		"SELECT id FROM sessions WHERE id = 1 FOR UPDATE",
	} {
		require.NoError(t, tx.Exec(q).Error)
	}
	released := false
	release := func() {
		if !released {
			released = true
			require.NoError(t, tx.Rollback().Error)
		}
	}
	t.Cleanup(release)

	const clients = 16
	const hold = 1500 * time.Millisecond
	var wg sync.WaitGroup
	durations := make([]time.Duration, clients)
	for i := range clients {
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			start := time.Now()
			// What the middleware / interceptors run after a request's checks pass.
			c.TouchPATLastUsed(ctx, 1)
			c.TouchMachineTokenLastUsed(ctx, 1)
			c.lastUsed().record(lastUsedKey{lastUsedSession, 1}, c.now()) // ValidateSessionToken's stamp
			durations[i] = time.Since(start)
		})
	}

	// While the rows are held, count backends waiting on a lock in this database.
	time.Sleep(300 * time.Millisecond)
	var waiting int64
	require.NoError(t, setup.Raw(
		"SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'").
		Scan(&waiting).Error)

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(hold):
	}
	release()
	<-done

	assert.Zero(t, waiting, "no request may wait on the credential's row lock")
	var worst time.Duration
	for _, d := range durations {
		worst = max(worst, d)
	}
	assert.Less(t, worst, hold/3, "requests of one credential must not serialize on its row (worst %v)", worst)

	// The coalesced stamps land once the lock is gone.
	c.FlushLastUsed(context.Background())
	var pat models.PersonalAccessToken
	require.NoError(t, setup.First(&pat, 1).Error)
	assert.NotNil(t, pat.LastUsedAt)
	var cred models.MachineIdentityCredential
	require.NoError(t, setup.First(&cred, 1).Error)
	assert.NotNil(t, cred.LastUsedAt)
	var sess models.Session
	require.NoError(t, setup.First(&sess, 1).Error)
	assert.NotNil(t, sess.LastSeenAt)
}
