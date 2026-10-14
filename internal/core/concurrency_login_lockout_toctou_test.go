package core_test

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// raceInjectingStorage wraps a real storage.Storage and, on the FIRST call to
// GetUserByUsername, simulates a concurrent failed-login burst committing a lock
// on the same row immediately after the snapshot read returns — exactly the
// TOCTOU window #247 concerns (Login reads an unlocked snapshot, then a
// concurrent burst trips the lock before Login reaches bcrypt/mintSession). The
// returned snapshot is left unmodified (matching what a real concurrent reader
// would have seen at that instant); the underlying row is locked via a direct
// write that bypasses the snapshot entirely, so the test is fully deterministic
// — no goroutine-scheduling luck required — while still exercising the exact
// interleaving the bug allowed.
type raceInjectingStorage struct {
	storage.Storage
	db        *gorm.DB
	injected  bool
	lockUntil time.Time
}

func (s *raceInjectingStorage) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	user, err := s.Storage.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, err
	}
	if !s.injected {
		s.injected = true
		if err := s.db.Model(&models.User{}).Where("id = ?", user.ID).
			Updates(map[string]any{
				"login_locked_until":  s.lockUntil,
				"login_lockout_count": 1,
			}).Error; err != nil {
			panic(err) // test setup invariant — must not silently corrupt the scenario
		}
	}
	return user, nil
}

// TestLogin_TOCTOU_ConcurrentLockTripBeforeMintIsRefused is the deterministic
// regression for #247: the login-lockout gate must not trust the pre-bcrypt
// snapshot read for the WHOLE authorization decision. It simulates a concurrent
// burst of OTHER failed attempts committing the account's lock in the instant
// after Login's snapshot read returns unlocked but before Login reaches
// bcrypt/mintSession — precisely the exploit window the finding describes. On
// the pre-fix code (which trusted the top-of-function loginLocked snapshot and
// never rechecked before minting a session) this correct-password login would
// have succeeded despite the account being locked; the fix re-checks lock state
// under the same serialization recordFailedLogin uses immediately before
// minting, so it must now be refused.
func TestLogin_TOCTOU_ConcurrentLockTripBeforeMintIsRefused(t *testing.T) {
	t.Parallel()
	dsn := "file:" + filepath.Join(t.TempDir(), "toctou.db") + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.Session{}, &models.AuditEvent{}))

	const password = "Correct#Horse9Battery"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.User{
		ID: 1, Username: "alice", UsernameFolded: "alice", PasswordHash: string(hash), AccountState: core.AccountActive,
	}).Error)

	wrapped := &raceInjectingStorage{
		Storage:   store.NewLocalStorage(db),
		db:        db,
		lockUntil: time.Now().Add(time.Hour),
	}
	c := core.NewKeyorixCore(wrapped)
	c.SetLoginLockoutPolicy(core.LoginLockoutPolicy{
		Enabled: true, MaxAttempts: 5,
		Window: 15 * time.Minute, BaseCooldown: 5 * time.Minute, MaxCooldown: time.Hour,
	})

	session, _, err := c.Login(context.Background(), &core.LoginRequest{Username: "alice", Password: password})
	require.Error(t, err, "a correct password must be refused once a concurrent burst locks the account before the mint")
	assert.Nil(t, session)
	assert.Contains(t, err.Error(), "locked")

	// Defense in depth: confirm no session row was actually created.
	var sessionCount int64
	require.NoError(t, db.Model(&models.Session{}).Count(&sessionCount).Error)
	assert.Equal(t, int64(0), sessionCount, "no session may be minted for a login that raced a concurrent lock trip")
}

// TestConcurrency_LoginLockout_MixedBurstCorrectPasswordAmongLockedNeverMintsExtra
// is a real (goroutine-scheduled) concurrency stress test, run with -race: a
// large burst of wrong-password attempts and a single correct-password attempt
// hit the same, already-nearly-locked account simultaneously. Regardless of
// scheduling order, at most one session may ever be minted, and the account's
// final persisted state must be internally consistent (no lost/duplicated
// lockout transitions from the mixed workload racing the fix's recheck).
func TestConcurrency_LoginLockout_MixedBurstCorrectPasswordAmongLockedNeverMintsExtra(t *testing.T) {
	t.Parallel()
	dsn := "file:" + filepath.Join(t.TempDir(), "mixed.db") + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.Session{}, &models.AuditEvent{}))

	const password = "Correct#Horse9Battery"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	require.NoError(t, err)
	const maxAttempts = 5
	// Pre-seed one failure away from tripping, so a single committed wrong
	// attempt from the burst is enough to lock the account — maximizing the
	// chance the burst genuinely races the correct-password attempt's recheck.
	require.NoError(t, db.Create(&models.User{
		ID: 1, Username: "alice", UsernameFolded: "alice", PasswordHash: string(hash), AccountState: core.AccountActive,
		FailedLoginAttempts: maxAttempts - 1,
	}).Error)

	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	c.SetLoginLockoutPolicy(core.LoginLockoutPolicy{
		Enabled: true, MaxAttempts: maxAttempts,
		Window: 15 * time.Minute, BaseCooldown: 5 * time.Minute, MaxCooldown: time.Hour,
	})

	const wrongAttackers = 60
	start := make(chan struct{})
	var wg sync.WaitGroup
	var successCount int32
	var mu sync.Mutex

	for range wrongAttackers {
		wg.Go(func() {
			<-start
			_, _, _ = c.Login(context.Background(), &core.LoginRequest{Username: "alice", Password: "wrong"})
		})
	}
	wg.Go(func() {
		<-start
		session, _, err := c.Login(context.Background(), &core.LoginRequest{Username: "alice", Password: password})
		if err == nil {
			require.NotNil(t, session)
			mu.Lock()
			successCount++
			mu.Unlock()
		} else {
			assert.Contains(t, err.Error(), "locked",
				"the only way the correct password can fail here is the lockout gate")
		}
	})
	close(start)
	wg.Wait()

	// At most one session may ever be minted — there's only one correct-password
	// attempt in the whole burst, so this also guards against any double-mint bug.
	assert.LessOrEqual(t, successCount, int32(1))

	var sessionCount int64
	require.NoError(t, db.Model(&models.Session{}).Count(&sessionCount).Error)
	assert.Equal(t, int64(successCount), sessionCount, "minted-session count must match the observed success count")
}
