// mfa_upgrade_grace_test.go: ADR-112's require_mfa upgrade grace period at
// runtime (#2923), on SQLite and (KEYORIX_TEST_PG_DSN) PostgreSQL.
package core

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

const (
	testGraceMarker = "adr112.require_mfa.enforced"
	testGraceClock  = "adr112.require_mfa.grace_clock"
)

// graceClock is a controllable wall clock and monotonic elapsed time.
type graceClock struct {
	mu      sync.Mutex
	wall    time.Time
	elapsed time.Duration
}

func (k *graceClock) Wall() time.Time {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.wall
}

func (k *graceClock) Elapsed() time.Duration {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.elapsed
}

// Advance moves both clocks forward by d, as real time passing does.
func (k *graceClock) Advance(d time.Duration) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.wall = k.wall.Add(d)
	k.elapsed += d
}

// StepWall moves only the wall clock (an operator or NTP step).
func (k *graceClock) StepWall(d time.Duration) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.wall = k.wall.Add(d)
}

type graceFixture struct {
	c     *KeyorixCore
	db    *gorm.DB
	clock *graceClock
	start time.Time
}

var graceModels = []any{
	&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
	&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
	&models.SystemMetadata{}, &models.AuditEvent{},
}

// runGraceBackends runs fn on SQLite and, when KEYORIX_TEST_PG_DSN is set, on
// PostgreSQL.
func runGraceBackends(t *testing.T, fn func(t *testing.T, open func(t *testing.T) *gorm.DB)) {
	t.Run("sqlite", func(t *testing.T) {
		fn(t, func(t *testing.T) *gorm.DB {
			db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
			require.NoError(t, err)
			sqlDB, err := db.DB()
			require.NoError(t, err)
			sqlDB.SetMaxOpenConns(1) // one :memory: database
			return db
		})
	})
	t.Run("postgres", func(t *testing.T) {
		base := pgTestDSN(t)
		fn(t, func(t *testing.T) *gorm.DB { return pgOpen(t, pgIsolatedSchemaDSN(t, base)) })
	})
}

// newGraceFixture is an upgraded deployment with one admin (no second factor)
// and one non-admin, inside a grace window that started a day ago.
func newGraceFixture(t *testing.T, db *gorm.DB) *graceFixture {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	require.NoError(t, db.AutoMigrate(graceModels...))
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 11, Name: "viewer"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "admin", Email: "admin@x.io", IsActive: true, AccountState: AccountActive}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "viewer", Email: "viewer@x.io", IsActive: true, AccountState: AccountActive}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 10}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 11}).Error)

	start := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	clock := &graceClock{wall: start.Add(24 * time.Hour)}
	c := NewKeyorixCore(store.NewLocalStorage(db))
	c.SetRequireMFA(true)
	c.installMFAUpgradeGrace(MFAUpgradeGraceWindow{
		Start: start, Deadline: start.Add(30 * 24 * time.Hour), Floor: start,
		EnforcedMarkerKey: testGraceMarker, ClockKey: testGraceClock,
	}, clock.Wall, clock.Elapsed)
	return &graceFixture{c: c, db: db, clock: clock, start: start}
}

// recheck lets the next evaluation run instead of reusing the cached one.
func (f *graceFixture) recheck() { f.clock.Advance(mfaGraceRecheck) }

func (f *graceFixture) marker(t *testing.T) (string, bool) {
	t.Helper()
	v, found, err := f.c.storage.GetSystemMetadata(context.Background(), testGraceMarker)
	require.NoError(t, err)
	return v, found
}

// During the grace period an admin without MFA owes no MFA step and the
// status reports the days left; after it, the step is owed again.
func TestMFAUpgradeGrace_ActiveUntilFirstAdminEnrolment(t *testing.T) {
	runGraceBackends(t, func(t *testing.T, open func(t *testing.T) *gorm.DB) {
		f := newGraceFixture(t, open(t))

		st, ok := f.c.MFAUpgradeGraceStatus()
		require.True(t, ok, "an upgraded deployment with no enrolled admin is inside the grace period")
		assert.Equal(t, 29, st.DaysLeft)
		assert.Equal(t, f.start.Add(30*24*time.Hour), st.EndsAt)
		assert.False(t, f.c.MFARequired())
		assert.Empty(t, f.c.PendingSetupStepsFor(false, false, true), "no MFA step during the grace period")

		// A non-admin enrolling does not end it.
		require.NoError(t, f.db.Model(&models.User{}).Where("id = ?", 2).Update("mfa_enabled", true).Error)
		f.recheck()
		assert.True(t, f.c.MFAUpgradeGraceActive(), "a non-admin's enrolment must not end the grace period")

		// The first admin enrolment ends it, for good.
		require.NoError(t, f.db.Model(&models.User{}).Where("id = ?", 1).Update("web_authn_enabled", true).Error)
		f.recheck()
		assert.False(t, f.c.MFAUpgradeGraceActive(), "the first admin with a second factor ends the grace period")
		assert.True(t, f.c.MFAUpgradeGraceEnded())
		assert.True(t, f.c.MFARequired())
		assert.Equal(t, []string{SetupStepEnrollMFA}, f.c.PendingSetupStepsFor(false, false, true),
			"after the grace period a user without a second factor is sent to enrolment")
		_, found := f.marker(t)
		assert.True(t, found, "the end writes the enforcement marker, so no later boot grants the grace period")
		var ended int64
		require.NoError(t, f.db.Model(&models.AuditEvent{}).Where("event_type = ?", "security.require_mfa_grace_ended").Count(&ended).Error)
		assert.EqualValues(t, 1, ended, "the end of the grace period is audited once")

		// The admin dropping the passkey again does not reopen it.
		require.NoError(t, f.db.Model(&models.User{}).Where("id = ?", 1).Update("web_authn_enabled", false).Error)
		f.recheck()
		assert.False(t, f.c.MFAUpgradeGraceActive(), "an ended grace period never reopens")
	})
}

// The 30-day hard stop ends the grace period even if no admin ever enrols.
func TestMFAUpgradeGrace_EndsAtTheDeadline(t *testing.T) {
	runGraceBackends(t, func(t *testing.T, open func(t *testing.T) *gorm.DB) {
		f := newGraceFixture(t, open(t))
		require.True(t, f.c.MFAUpgradeGraceActive())

		f.clock.Advance(29*24*time.Hour - time.Minute) // one minute before the deadline
		st, ok := f.c.MFAUpgradeGraceStatus()
		require.True(t, ok)
		assert.Equal(t, 1, st.DaysLeft, "the last day counts as one day left")

		f.clock.Advance(time.Minute)
		assert.False(t, f.c.MFAUpgradeGraceActive(), "the grace period ends at the deadline")
		assert.True(t, f.c.MFAUpgradeGraceEnded())
		assert.True(t, f.c.MFARequired())
		_, found := f.marker(t)
		assert.True(t, found)
	})
}

// A wall clock stepped backwards never extends the grace period: the monotonic
// time since install still reaches the deadline, and the days left never grow.
func TestMFAUpgradeGrace_BackwardClockStepDoesNotExtend(t *testing.T) {
	runGraceBackends(t, func(t *testing.T, open func(t *testing.T) *gorm.DB) {
		f := newGraceFixture(t, open(t))
		f.clock.Advance(20 * 24 * time.Hour)
		st, ok := f.c.MFAUpgradeGraceStatus()
		require.True(t, ok)
		require.Equal(t, 9, st.DaysLeft)

		f.clock.StepWall(-15 * 24 * time.Hour)
		f.recheck()
		st, ok = f.c.MFAUpgradeGraceStatus()
		require.True(t, ok)
		assert.LessOrEqual(t, st.DaysLeft, 9, "a backward wall-clock step must not add days")

		f.clock.Advance(9 * 24 * time.Hour)
		assert.False(t, f.c.MFAUpgradeGraceActive(), "the deadline is reached on elapsed time even with the wall clock 15 days behind")
	})
}

// A forward wall-clock step only ends the grace period sooner.
func TestMFAUpgradeGrace_ForwardClockStepEndsSooner(t *testing.T) {
	runGraceBackends(t, func(t *testing.T, open func(t *testing.T) *gorm.DB) {
		f := newGraceFixture(t, open(t))
		f.clock.StepWall(40 * 24 * time.Hour)
		f.recheck()
		assert.False(t, f.c.MFAUpgradeGraceActive())
	})
}

// The floor (the latest time any boot recorded) bounds the grace clock from
// below: a process whose wall clock starts behind it counts from the floor.
func TestMFAUpgradeGrace_FloorBoundsTheClock(t *testing.T) {
	runGraceBackends(t, func(t *testing.T, open func(t *testing.T) *gorm.DB) {
		f := newGraceFixture(t, open(t))
		clock := &graceClock{wall: f.start.Add(2 * 24 * time.Hour)}
		f.c.installMFAUpgradeGrace(MFAUpgradeGraceWindow{
			Start: f.start, Deadline: f.start.Add(30 * 24 * time.Hour), Floor: f.start.Add(28 * 24 * time.Hour),
			EnforcedMarkerKey: testGraceMarker, ClockKey: testGraceClock,
		}, clock.Wall, clock.Elapsed)
		st, ok := f.c.MFAUpgradeGraceStatus()
		require.True(t, ok)
		assert.Equal(t, 2, st.DaysLeft, "days left are counted from the recorded floor, not the earlier wall clock")
	})
}

// The grace clock's high-water mark is written back while the period runs, so
// a restart resumes from it.
func TestMFAUpgradeGrace_PersistsTheClock(t *testing.T) {
	runGraceBackends(t, func(t *testing.T, open func(t *testing.T) *gorm.DB) {
		f := newGraceFixture(t, open(t))
		f.clock.Advance(3 * time.Hour)
		require.True(t, f.c.MFAUpgradeGraceActive())
		v, found, err := f.c.storage.GetSystemMetadata(context.Background(), testGraceClock)
		require.NoError(t, err)
		require.True(t, found)
		got, err := time.Parse(time.RFC3339, v)
		require.NoError(t, err)
		assert.Equal(t, f.clock.Wall(), got)
	})
}

// Another replica's marker ends the grace period here too.
func TestMFAUpgradeGrace_MarkerFromAnotherReplicaEndsIt(t *testing.T) {
	runGraceBackends(t, func(t *testing.T, open func(t *testing.T) *gorm.DB) {
		f := newGraceFixture(t, open(t))
		require.True(t, f.c.MFAUpgradeGraceActive())
		require.NoError(t, f.c.storage.SetSystemMetadata(context.Background(), testGraceMarker, f.start.Format(time.RFC3339)))
		f.recheck()
		assert.False(t, f.c.MFAUpgradeGraceActive())
		assert.True(t, f.c.MFAUpgradeGraceEnded())
	})
}

// No grace window installed (fresh install, explicit key, ratcheted): MFA is
// required whenever the deployment requires it.
func TestMFAUpgradeGrace_NoneInstalled(t *testing.T) {
	c := NewKeyorixCore(nil)
	c.SetRequireMFA(true)
	assert.True(t, c.MFARequired())
	assert.False(t, c.MFAUpgradeGraceActive())
	assert.False(t, c.MFAUpgradeGraceEnded())
	c.SetRequireMFA(false)
	assert.False(t, c.MFARequired())
}

// Fail closed: while the admin set cannot be read the grace period is not in
// effect (MFA enforced), and it is suspended, not ended, so it resumes when the
// read works again.
func TestMFAUpgradeGrace_UnreadableFactsFailClosed(t *testing.T) {
	runGraceBackends(t, func(t *testing.T, open func(t *testing.T) *gorm.DB) {
		f := newGraceFixture(t, open(t))
		// Fails the reads the grace evaluation depends on.
		var fail atomic.Bool
		f.c.storage = hooked(f.c.storage, &storeHooks{
			ListProjectRoleAssignments: func(next corestorage.Storage, ctx context.Context, projectID uint) ([]corestorage.RoleAssignment, error) {
				if fail.Load() {
					return nil, errors.New("injected: role assignments unavailable")
				}
				return next.ListProjectRoleAssignments(ctx, projectID)
			},
		})

		fail.Store(true)
		assert.False(t, f.c.MFAUpgradeGraceActive(), "an unreadable admin set must not keep the grace period running")
		assert.True(t, f.c.MFARequired(), "fail closed: MFA enforced")
		assert.False(t, f.c.MFAUpgradeGraceEnded(), "a failed read suspends the grace period, it does not end it")
		_, found := f.marker(t)
		assert.False(t, found, "a failed read must not write the enforcement marker")

		fail.Store(false)
		f.recheck()
		assert.True(t, f.c.MFAUpgradeGraceActive())
	})
}
