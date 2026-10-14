package core_test

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// TestConcurrency_UpdateSCIMUser_NoDuplicateEmail is the (#120/#218) regression, narrowed
// further by the #117 DB-level fix: UpdateSCIMUser's email-uniqueness guard is a plain
// check-then-act read (GetUserByEmail) with no transaction/lock, so two (or more)
// concurrent UpdateSCIMUser calls retargeting different users to the SAME new email can
// all pass the check before any write lands, reproducing the exact ambiguous-email
// scenario #120/#218 describe. This drives many concurrent UpdateSCIMUser calls, each
// retargeting a distinct existing user to the identical new email, against a real
// file-backed SQLite with the same partial unique index production installs get (mirrors
// factory.go's ensureUserEmailIndex exactly), and asserts exactly one update wins, with
// every loser getting the same clean "already in use" error UpdateSCIMUser's sequential
// pre-check already returns — not a raw constraint-violation message — and the DB holding
// exactly one row for the contested email.
func TestConcurrency_UpdateSCIMUser_NoDuplicateEmail(t *testing.T) {
	t.Parallel()
	dsn := "file:" + filepath.Join(t.TempDir(), "scim_update.db") + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Session{}, &models.AuditEvent{}, &models.Project{}, &models.Environment{},
	))
	// Mirror factory.go's ensureUserEmailIndex exactly (#1642: the folded-column
	// index, not the old SQL-side LOWER() index this test used to create — SQL-side
	// LOWER() is ASCII-only on modernc/SQLite and locale-dependent on Postgres, so it
	// enforces different uniqueness per backend for the same login identity), so this
	// test exercises the same DB-level guard production installs get (rather than
	// only the in-process check-then-act read).
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_users_email_folded_active "+
		"ON users (email_folded) WHERE deleted_at IS NULL AND email <> ''").Error)

	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	ctx := context.Background()

	const attackers = 20 // many concurrent SCIM updates racing to claim the same email
	for i := range attackers {
		username := fmt.Sprintf("user%d", i)
		email := fmt.Sprintf("user%d@x.io", i)
		require.NoError(t, db.Create(&models.User{
			ID: uint(i + 1), Username: username, UsernameFolded: username, Email: email, EmailFolded: email,
			IsActive: true, AccountState: core.AccountActive, ExternalID: fmt.Sprintf("okta|user%d", i),
		}).Error)
	}

	target := "shared@x.io"
	start := make(chan struct{})
	errs := make([]error, attackers)
	var wg sync.WaitGroup
	for i := range attackers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, uerr := c.UpdateSCIMUser(ctx, 9, uint(i+1), nil, &target, nil)
			errs[i] = uerr
		}(i)
	}
	close(start) // release every update at once
	wg.Wait()

	var successes, duplicateRejections int
	for _, uerr := range errs {
		if uerr == nil {
			successes++
			continue
		}
		// The loser of the race gets either the original sequential check's message or,
		// when it instead loses the DB-level race, the translated ErrDuplicateEmail
		// message. Both read as "already in use"; neither is a raw constraint-violation
		// string.
		if strings.Contains(uerr.Error(), "already in use") {
			duplicateRejections++
		}
	}
	assert.Equal(t, 1, successes, "exactly one concurrent SCIM update must win the contested email")
	assert.Equal(t, attackers-1, duplicateRejections,
		"every other concurrent SCIM update must get a clean 'already in use' error, not a raw DB error")

	var count int64
	require.NoError(t, db.Model(&models.User{}).
		Where("LOWER(email) = LOWER(?)", target).
		Count(&count).Error)
	assert.Equal(t, int64(1), count, "exactly one user row must hold the contested email — no ambiguous duplicate")
}
