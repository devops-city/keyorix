package core

import (
	"context"
	"encoding/json"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// TestConcurrency_WebAuthnPersistUpdatedCredential_NoStaleCounterRegression is the
// clone-detection invariant under a race (#306): persistUpdatedCredential must never
// let a stale (lower) signature counter clobber an already-persisted higher one when
// two logins for the same credential race — e.g. a cloned authenticator authenticating
// concurrently with the legitimate device. Before the fix, GetWebAuthnCredentialByCredID
// + blind Save had no predicate at all: both requests could read the same stale row and
// the last UPDATE would win regardless of which counter was actually higher, silently
// regressing the persisted counter and suppressing the webauthn.clone_warning signal on
// future logins. The fix serializes persistUpdatedCredential (process mutex, mirroring
// recordFailedLogin's loginFailureMu) and re-reads the row's CURRENT counter inside a
// transaction (LockWebAuthnCredentialForUpdate takes a Postgres FOR UPDATE lock), only
// persisting a write whose counter is still greater than that fresh read — so the
// persisted counter is monotonic regardless of goroutine scheduling. Uses a real
// file-backed SQLite (not :memory:) so many concurrent connections behave like the
// production single-process case. Run with -race.
func TestConcurrency_WebAuthnPersistUpdatedCredential_NoStaleCounterRegression(t *testing.T) {
	t.Parallel()
	dsn := "file:" + filepath.Join(t.TempDir(), "webauthn.db") + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.WebAuthnCredential{}))

	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", AccountState: "active"}).Error)

	credID := []byte("cred-1")
	initialBlob, err := json.Marshal(webauthn.Credential{ID: credID, Authenticator: webauthn.Authenticator{SignCount: 0}})
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.WebAuthnCredential{
		UserID: 1, CredentialID: credID, Name: "test key", CredentialBlob: initialBlob,
	}).Error)

	fixed := time.Now()
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return fixed }}
	ctx := context.Background()

	// Repeated trials: each iteration races a "low" (stale/cloned) counter against a
	// much higher "legitimate" counter, both starting from the current persisted
	// baseline, and asserts the persisted counter always ends at the max of the two —
	// i.e. the stale write is rejected regardless of which goroutine's transaction
	// actually wins the race to run first.
	const trials = 25
	baseline := uint32(0)
	for i := range trials {
		low := baseline + 1
		high := baseline + 50

		lowCred := &webauthn.Credential{ID: credID, Authenticator: webauthn.Authenticator{SignCount: low}}
		highCred := &webauthn.Credential{ID: credID, Authenticator: webauthn.Authenticator{SignCount: high}}

		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			c.persistUpdatedCredential(ctx, 1, lowCred)
		}()
		go func() {
			defer wg.Done()
			<-start
			c.persistUpdatedCredential(ctx, 1, highCred)
		}()
		close(start)
		wg.Wait()

		var row models.WebAuthnCredential
		require.NoError(t, db.Where("credential_id = ?", credID).First(&row).Error)
		var stored webauthn.Credential
		require.NoError(t, json.Unmarshal(row.CredentialBlob, &stored))
		assert.Equal(t, high, stored.Authenticator.SignCount,
			"trial %d: the higher (legitimate) counter must win regardless of write order — a lost/regressed update would suppress clone detection", i)

		baseline = high
	}
}

// TestConcurrency_WebAuthnPersistUpdatedCredential_StaleWriteAfterWinnerIsRejected
// pins the exact ordering the backlog finding traces: the loser of the race (the
// stale/lower counter) attempts its write AFTER the winner has already committed a
// higher counter. Before the fix (blind read-then-Save with no predicate) this stale
// write would silently clobber the winner's persisted value. After the fix the
// transaction re-reads the row's current counter and skips the write.
func TestConcurrency_WebAuthnPersistUpdatedCredential_StaleWriteAfterWinnerIsRejected(t *testing.T) {
	t.Parallel()
	dsn := "file:" + filepath.Join(t.TempDir(), "webauthn2.db") + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.WebAuthnCredential{}))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", AccountState: "active"}).Error)

	credID := []byte("cred-1")
	initialBlob, err := json.Marshal(webauthn.Credential{ID: credID, Authenticator: webauthn.Authenticator{SignCount: 0}})
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.WebAuthnCredential{
		UserID: 1, CredentialID: credID, Name: "test key", CredentialBlob: initialBlob,
	}).Error)

	fixed := time.Now()
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return fixed }}
	ctx := context.Background()

	// Winner (legitimate device) commits first: counter advances 0 -> 100.
	c.persistUpdatedCredential(ctx, 1, &webauthn.Credential{ID: credID, Authenticator: webauthn.Authenticator{SignCount: 100}})

	var afterWinner models.WebAuthnCredential
	require.NoError(t, db.Where("credential_id = ?", credID).First(&afterWinner).Error)
	var afterWinnerCred webauthn.Credential
	require.NoError(t, json.Unmarshal(afterWinner.CredentialBlob, &afterWinnerCred))
	require.Equal(t, uint32(100), afterWinnerCred.Authenticator.SignCount)

	// Loser (cloned authenticator) had validated its assertion against the stale
	// baseline (0) and now tries to persist a counter that is higher than that stale
	// baseline but lower than what's now actually stored.
	c.persistUpdatedCredential(ctx, 1, &webauthn.Credential{ID: credID, Authenticator: webauthn.Authenticator{SignCount: 5}})

	var final models.WebAuthnCredential
	require.NoError(t, db.Where("credential_id = ?", credID).First(&final).Error)
	var finalCred webauthn.Credential
	require.NoError(t, json.Unmarshal(final.CredentialBlob, &finalCred))
	assert.Equal(t, uint32(100), finalCred.Authenticator.SignCount,
		"a stale write below the currently-persisted counter must be rejected, not silently applied")
}
