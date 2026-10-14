package core_test

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// TestConcurrency_PlaceLegalHold_OnlyOneWins is the TOCTOU regression for #305.
// PlaceLegalHold's own "no active hold" check and its insert are not atomic, so
// many concurrent callers can all pass the check before any of them commits. The
// partial unique index on legal_holds (released) WHERE released = false (created by
// storage.ensureLegalHoldActiveIndex in production; replicated here per the
// TestGroupSoftDelete_NameReuse convention) must let exactly one insert win and
// reject every other one with a client error rather than creating a second,
// orphaned active-hold row. Uses a file-backed SQLite (real multi-connection
// concurrency), run under -race.
func TestConcurrency_PlaceLegalHold_OnlyOneWins(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	dsn := "file:" + filepath.Join(t.TempDir(), "c.db") + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	// #G01: PlaceLegalHold now resolves admin authority via isGlobalAdminRoleName
	// (scopedRoleIDs), which LEFT JOINs projects/environments and unions in
	// group-inherited roles (user_groups/groups/group_roles) — all must be
	// migrated even though this test grants the role directly, not via a group.
	require.NoError(t, db.AutoMigrate(&models.LegalHold{}, &models.AuditEvent{}, &models.Role{}, &models.UserRole{},
		&models.Project{}, &models.Environment{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{}))
	// The production migration (storage.ensureLegalHoldActiveIndex) creates this;
	// replicate it for the test DB.
	require.NoError(t, db.Exec(
		"CREATE UNIQUE INDEX uniq_legal_holds_active ON legal_holds (released) WHERE released = false",
	).Error)

	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	ctx := context.Background()
	// #377: placement now requires an admin-tier role.
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 2}).Error)

	const callers = 32
	var succeeded atomic.Int64
	unexpected := make(chan error, callers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range callers {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			<-start
			_, perr := c.PlaceLegalHold(ctx, 1, "concurrent litigation hold")
			if perr == nil {
				succeeded.Add(1)
				return
			}
			// The only expected failure is "already active" — PlaceLegalHold
			// returns this same client-facing message whether it came from the
			// pre-check or from the storage.ErrLegalHoldAlreadyActive mapping.
			if !strings.Contains(perr.Error(), "already active") {
				unexpected <- perr
			}
		}(i)
	}
	close(start) // release all callers simultaneously
	wg.Wait()
	close(unexpected)
	for e := range unexpected {
		require.NoError(t, e)
	}

	assert.Equal(t, int64(1), succeeded.Load(), "exactly one concurrent PlaceLegalHold call may succeed")

	// No orphaned duplicate: exactly one row, and it is the active one
	// GetActiveLegalHold reports.
	var count int64
	require.NoError(t, db.Model(&models.LegalHold{}).Where("released = ?", false).Count(&count).Error)
	assert.Equal(t, int64(1), count, "the DB must contain exactly one active hold row, never a duplicate")

	active, err := c.GetActiveLegalHold(ctx)
	require.NoError(t, err)
	require.NotNil(t, active)
	assert.False(t, active.Released)
}
