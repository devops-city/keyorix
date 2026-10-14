// session_rotate_test.go — atomicity and reuse-detection invariants for
// RotateSession, the CAS at the heart of RefreshSession's fix for #211 (session
// refresh had no reuse-detection signal and was not atomic).
package store

import (
	"context"
	"fmt"
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

// TestRotateSession_SingleCallerWins is the sequential sanity check: rotating a
// live session succeeds, marks the old row rotated (excluded from GetSession, but
// still visible to GetSessionAny), and creates the replacement.
func TestRotateSession_SingleCallerWins(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.Session{}))
	ls := NewLocalStorage(db)
	// #2701: a session/PAT insert now re-reads its owning user and rolls back if
	// it is not live, so this fixture needs the owners it references to exist.
	seedCredentialOwners(t, ls.db)
	ctx := context.Background()
	now := time.Now().UTC()

	old, err := ls.CreateSession(ctx, &models.Session{UserID: 1, SessionToken: "old-plain", FamilyID: "fam-1"})
	require.NoError(t, err)

	newSession := &models.Session{UserID: 1, SessionToken: "new-plain", FamilyID: "fam-1"}
	created, won, err := ls.RotateSession(ctx, old.ID, newSession, now)
	require.NoError(t, err)
	assert.True(t, won)
	require.NotNil(t, created)
	assert.Equal(t, "new-plain", created.SessionToken, "the plaintext token is handed back to the caller")

	// The old token no longer authenticates via GetSession (rotated == dead for
	// auth purposes) but is still visible via GetSessionAny for reuse detection.
	_, err = ls.GetSession(ctx, "old-plain")
	assert.Error(t, err, "a rotated token must not authenticate")

	rotated, err := ls.GetSessionAny(ctx, "old-plain")
	require.NoError(t, err)
	assert.NotNil(t, rotated.RotatedAt, "GetSessionAny must still see the rotated row")

	// The new token is live.
	live, err := ls.GetSession(ctx, "new-plain")
	require.NoError(t, err)
	assert.Nil(t, live.RotatedAt)
}

// TestRotateSession_LoserGetsNoSession is the CAS guard's negative case: rotating
// an already-rotated row a second time must not create a second descendant.
func TestRotateSession_LoserGetsNoSession(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.Session{}))
	ls := NewLocalStorage(db)
	// #2701: a session/PAT insert now re-reads its owning user and rolls back if
	// it is not live, so this fixture needs the owners it references to exist.
	seedCredentialOwners(t, ls.db)
	ctx := context.Background()
	now := time.Now().UTC()

	old := &models.Session{UserID: 1, SessionToken: "old-plain", FamilyID: "fam-1"}
	require.NoError(t, db.Create(old).Error)

	first := &models.Session{UserID: 1, SessionToken: "first-plain", FamilyID: "fam-1"}
	_, won1, err := ls.RotateSession(ctx, old.ID, first, now)
	require.NoError(t, err)
	require.True(t, won1)

	second := &models.Session{UserID: 1, SessionToken: "second-plain", FamilyID: "fam-1"}
	created2, won2, err := ls.RotateSession(ctx, old.ID, second, now)
	require.NoError(t, err)
	assert.False(t, won2, "a second rotation of the same already-rotated row must lose")
	assert.Nil(t, created2)

	// Only ONE descendant session exists for this family, not two.
	var count int64
	require.NoError(t, db.Model(&models.Session{}).Where("family_id = ? AND rotated_at IS NULL", "fam-1").Count(&count).Error)
	assert.EqualValues(t, 1, count, "exactly one live descendant, no duplicate mint")
}

// TestConcurrency_RotateSession_OnlyOneWinnerPerToken drives many goroutines racing
// to rotate the SAME not-yet-rotated session concurrently against a real,
// file-backed SQLite DB with genuine multi-connection contention (concurrentDB,
// shared with the other atomic check-and-act invariant tests in this package).
// Exactly one must win the CAS and mint a descendant — this is the store-level
// proof behind #211's "a race on the same token can mint two independently valid
// sessions" fix.
func TestConcurrency_RotateSession_OnlyOneWinnerPerToken(t *testing.T) {
	db := concurrentDB(t)
	require.NoError(t, db.AutoMigrate(&models.Session{}))
	ls := NewLocalStorage(db)
	// #2701: a session/PAT insert now re-reads its owning user and rolls back if
	// it is not live, so this fixture needs the owners it references to exist.
	seedCredentialOwners(t, ls.db)
	ctx := context.Background()
	now := time.Now().UTC()

	old := &models.Session{UserID: 1, SessionToken: "shared-old-token", FamilyID: "fam-race"}
	require.NoError(t, db.Create(old).Error)

	const racers = 20
	var wins int64
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range racers {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			<-start
			candidate := &models.Session{UserID: 1, SessionToken: fmt.Sprintf("candidate-%d", n), FamilyID: "fam-race"}
			_, won, err := ls.RotateSession(ctx, old.ID, candidate, now)
			require.NoError(t, err)
			if won {
				atomic.AddInt64(&wins, 1)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	assert.EqualValues(t, 1, wins, "exactly one concurrent refresh of the same token may win the rotation")

	var count int64
	require.NoError(t, db.Model(&models.Session{}).Where("family_id = ? AND rotated_at IS NULL", "fam-race").Count(&count).Error)
	assert.EqualValues(t, 1, count, "at most one live descendant session must exist, no matter how many racers")
}

// TestDeleteSessionsByFamily_RevokesWholeLineage pins that family revocation kills
// every session sharing the family id, not just the row that triggered detection —
// the "revoke the whole session family" recommendation from #211.
func TestDeleteSessionsByFamily_RevokesWholeLineage(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.Session{}))
	ls := NewLocalStorage(db)
	ctx := context.Background()

	require.NoError(t, db.Create(&models.Session{UserID: 1, SessionToken: "gen1", FamilyID: "fam-x"}).Error)
	require.NoError(t, db.Create(&models.Session{UserID: 1, SessionToken: "gen2", FamilyID: "fam-x"}).Error)
	require.NoError(t, db.Create(&models.Session{UserID: 1, SessionToken: "unrelated", FamilyID: "fam-y"}).Error)

	hashes, err := ls.ListSessionTokenHashesByFamily(ctx, "fam-x")
	require.NoError(t, err)
	assert.Len(t, hashes, 2)

	require.NoError(t, ls.DeleteSessionsByFamily(ctx, "fam-x"))

	var remaining int64
	require.NoError(t, db.Model(&models.Session{}).Where("family_id = ?", "fam-x").Count(&remaining).Error)
	assert.EqualValues(t, 0, remaining, "every session in the family is revoked")

	var other int64
	require.NoError(t, db.Model(&models.Session{}).Where("family_id = ?", "fam-y").Count(&other).Error)
	assert.EqualValues(t, 1, other, "a different family is untouched")
}
