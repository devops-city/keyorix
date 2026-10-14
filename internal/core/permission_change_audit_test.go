package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// newPermAuditCore creates a minimal core backed by an in-memory SQLite DB with
// the tables needed for permission-change-audit tests.
func newPermAuditCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.AuditEvent{},
		&models.User{},
		&models.Role{},
		&models.UserRole{},
		&models.Permission{},
		&models.RolePermission{},
		&models.Group{},
		&models.UserGroup{},
		&models.GroupRole{},
		&models.Project{},
		&models.Environment{},
		&models.SoDPolicy{},
	))
	return NewKeyorixCore(store.NewLocalStorage(db)), db
}

// seedAuditEvent inserts an audit_event row directly to give precise control
// over EventType, EventTime, and Diff without triggering higher-level logic.
func seedAuditEvent(t *testing.T, db *gorm.DB, eventType string, actorID *uint, diff string, at time.Time) *models.AuditEvent {
	t.Helper()
	tr := true
	e := &models.AuditEvent{
		EventType: eventType,
		UserID:    actorID,
		Diff:      diff,
		Success:   &tr,
		EventTime: at,
	}
	require.NoError(t, db.Create(e).Error)
	return e
}

// TestGetPermissionChangeAudit_NoEvents — empty DB yields empty report.
func TestGetPermissionChangeAudit_NoEvents(t *testing.T) {
	t.Parallel()
	c, _ := newPermAuditCore(t)
	now := time.Now()
	since := now.Add(-time.Hour)
	until := now.Add(time.Hour)

	report, err := c.GetPermissionChangeAudit(context.Background(), since, until, 0)
	require.NoError(t, err)
	assert.Equal(t, 0, report.Total)
	assert.Empty(t, report.Changes)
}

// TestGetPermissionChangeAudit_RoleGranted — role.assigned event → action="role.assigned".
func TestGetPermissionChangeAudit_RoleGranted(t *testing.T) {
	t.Parallel()
	c, db := newPermAuditCore(t)
	ctx := context.Background()

	// Seed actor and target users.
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "admin"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "alice"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 3, Name: "editor"}).Error)

	actorID := uint(1)
	diff := `{"target_user_id":2,"role_id":3}`
	now := time.Now()
	seedAuditEvent(t, db, EventRoleAssigned, &actorID, diff, now)

	report, err := c.GetPermissionChangeAudit(ctx, now.Add(-time.Minute), now.Add(time.Minute), 100)
	require.NoError(t, err)
	require.Equal(t, 1, report.Total)

	e := report.Changes[0]
	assert.Equal(t, EventRoleAssigned, e.Action)
	assert.Equal(t, "admin", e.ActorName)
	assert.Equal(t, "alice", e.TargetUser)
	assert.Equal(t, "editor", e.RoleName)
	assert.Equal(t, "global", e.Scope)
}

// TestGetPermissionChangeAudit_RoleRevoked — role.removed event → action="role.removed".
func TestGetPermissionChangeAudit_RoleRevoked(t *testing.T) {
	t.Parallel()
	c, db := newPermAuditCore(t)
	ctx := context.Background()

	require.NoError(t, db.Create(&models.User{ID: 1, Username: "admin"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 5, Username: "bob"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 7, Name: "viewer"}).Error)

	actorID := uint(1)
	diff := `{"target_user_id":5,"role_id":7,"project_id":9}`
	now := time.Now()
	seedAuditEvent(t, db, EventRoleRemoved, &actorID, diff, now)

	report, err := c.GetPermissionChangeAudit(ctx, now.Add(-time.Minute), now.Add(time.Minute), 100)
	require.NoError(t, err)
	require.Equal(t, 1, report.Total)

	e := report.Changes[0]
	assert.Equal(t, EventRoleRemoved, e.Action)
	assert.Equal(t, "bob", e.TargetUser)
	assert.Equal(t, "viewer", e.RoleName)
	assert.Equal(t, "project:9", e.Scope)
}

// TestGetPermissionChangeAudit_RoleExpired — role.expired event is included.
func TestGetPermissionChangeAudit_RoleExpired(t *testing.T) {
	t.Parallel()
	c, db := newPermAuditCore(t)
	ctx := context.Background()

	require.NoError(t, db.Create(&models.User{ID: 3, Username: "carol"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "operator"}).Error)

	actorID := uint(3)
	diff := `{"target_user_id":3,"role_id":2}`
	now := time.Now()
	seedAuditEvent(t, db, EventRoleExpired, &actorID, diff, now)

	report, err := c.GetPermissionChangeAudit(ctx, now.Add(-time.Minute), now.Add(time.Minute), 100)
	require.NoError(t, err)
	require.Equal(t, 1, report.Total)
	assert.Equal(t, EventRoleExpired, report.Changes[0].Action)
}

// TestGetPermissionChangeAudit_NonRoleEventExcluded — other event types are not returned.
func TestGetPermissionChangeAudit_NonRoleEventExcluded(t *testing.T) {
	t.Parallel()
	c, db := newPermAuditCore(t)
	ctx := context.Background()

	now := time.Now()
	// These should NOT appear in the report.
	seedAuditEvent(t, db, "secret.read", nil, "", now)
	seedAuditEvent(t, db, EventRoleGroupAssigned, nil, `{"group_id":1,"role_id":2}`, now)
	seedAuditEvent(t, db, EventPermissionAdded, nil, `{"role_id":1,"permission_id":3}`, now)

	report, err := c.GetPermissionChangeAudit(ctx, now.Add(-time.Minute), now.Add(time.Minute), 100)
	require.NoError(t, err)
	assert.Equal(t, 0, report.Total)
}

// TestGetPermissionChangeAudit_SinceUntilFiltering — only events in range returned.
func TestGetPermissionChangeAudit_SinceUntilFiltering(t *testing.T) {
	t.Parallel()
	c, db := newPermAuditCore(t)
	ctx := context.Background()

	base := time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC)
	oldEvent := base.Add(-48 * time.Hour)   // outside window
	inWindow := base                        // inside window
	futureEvent := base.Add(48 * time.Hour) // outside window

	seedAuditEvent(t, db, EventRoleAssigned, nil, `{"role_id":1}`, oldEvent)
	seedAuditEvent(t, db, EventRoleAssigned, nil, `{"role_id":2}`, inWindow)
	seedAuditEvent(t, db, EventRoleAssigned, nil, `{"role_id":3}`, futureEvent)

	since := base.Add(-time.Hour)
	until := base.Add(time.Hour)
	report, err := c.GetPermissionChangeAudit(ctx, since, until, 100)
	require.NoError(t, err)
	assert.Equal(t, 1, report.Total)
}

// TestGetPermissionChangeAudit_ZeroSinceDefaultsTo30Days — events older than
// 30 days are excluded when since is zero.
func TestGetPermissionChangeAudit_ZeroSinceDefaultsTo30Days(t *testing.T) {
	t.Parallel()
	c, db := newPermAuditCore(t)
	ctx := context.Background()

	now := time.Now()
	// One event inside the 30-day window, one 31 days ago (should be excluded).
	recent := now.Add(-5 * 24 * time.Hour)
	old := now.Add(-31 * 24 * time.Hour)

	seedAuditEvent(t, db, EventRoleAssigned, nil, `{"role_id":1}`, recent)
	seedAuditEvent(t, db, EventRoleAssigned, nil, `{"role_id":2}`, old)

	// zero since + zero until → defaults apply
	report, err := c.GetPermissionChangeAudit(ctx, time.Time{}, time.Time{}, 0)
	require.NoError(t, err)
	// Only the recent event should appear.
	assert.Equal(t, 1, report.Total)
	assert.False(t, report.Since.IsZero())
	assert.False(t, report.Until.IsZero())
}

// TestGetPermissionChangeAudit_LimitApplied — results capped at requested limit.
func TestGetPermissionChangeAudit_LimitApplied(t *testing.T) {
	t.Parallel()
	c, db := newPermAuditCore(t)
	ctx := context.Background()

	now := time.Now()
	for i := range 5 {
		at := now.Add(-time.Duration(i) * time.Second)
		seedAuditEvent(t, db, EventRoleAssigned, nil, `{"role_id":1}`, at)
	}

	report, err := c.GetPermissionChangeAudit(ctx, now.Add(-time.Minute), now.Add(time.Minute), 3)
	require.NoError(t, err)
	// #G24: Total now reports the TRUE matching count (5), not the returned page
	// size — Changes is what's capped at the requested limit, and Truncated
	// signals the gap between them.
	assert.LessOrEqual(t, len(report.Changes), 3)
	assert.Equal(t, 5, report.Total)
	assert.True(t, report.Truncated)
}

// TestGetPermissionChangeAudit_LimitExceedsMax — limit > 1000 is capped at 1000.
func TestGetPermissionChangeAudit_LimitExceedsMax(t *testing.T) {
	t.Parallel()
	c, db := newPermAuditCore(t)
	ctx := context.Background()

	now := time.Now()
	// Seed 3 events; request limit=9999 (should clamp to 1000 without error).
	for i := range 3 {
		at := now.Add(-time.Duration(i) * time.Second)
		seedAuditEvent(t, db, EventRoleRemoved, nil, `{"role_id":1}`, at)
	}

	report, err := c.GetPermissionChangeAudit(ctx, now.Add(-time.Minute), now.Add(time.Minute), 9999)
	require.NoError(t, err)
	assert.Equal(t, 3, report.Total)
}

// TestGetPermissionChangeAudit_UnknownActorUserID — actor user not in DB → empty actor name, no error.
func TestGetPermissionChangeAudit_UnknownActorUserID(t *testing.T) {
	t.Parallel()
	c, db := newPermAuditCore(t)
	ctx := context.Background()

	now := time.Now()
	actorID := uint(99) // not seeded
	seedAuditEvent(t, db, EventRoleAssigned, &actorID, `{"role_id":1}`, now)

	report, err := c.GetPermissionChangeAudit(ctx, now.Add(-time.Minute), now.Add(time.Minute), 100)
	require.NoError(t, err)
	require.Equal(t, 1, report.Total)
	assert.Empty(t, report.Changes[0].ActorName)
}

// TestGetPermissionChangeAudit_UnknownTargetUserID — target user not in DB →
// "user:<id>" fallback, no error.
func TestGetPermissionChangeAudit_UnknownTargetUserID(t *testing.T) {
	t.Parallel()
	c, db := newPermAuditCore(t)
	ctx := context.Background()

	now := time.Now()
	diff := `{"target_user_id":42,"role_id":1}`
	seedAuditEvent(t, db, EventRoleAssigned, nil, diff, now)

	report, err := c.GetPermissionChangeAudit(ctx, now.Add(-time.Minute), now.Add(time.Minute), 100)
	require.NoError(t, err)
	require.Equal(t, 1, report.Total)
	assert.Equal(t, "user:42", report.Changes[0].TargetUser)
}

// TestGetPermissionChangeAudit_UnknownRoleID — role not in DB → "role:<id>" fallback.
func TestGetPermissionChangeAudit_UnknownRoleID(t *testing.T) {
	t.Parallel()
	c, db := newPermAuditCore(t)
	ctx := context.Background()

	now := time.Now()
	diff := `{"role_id":77}`
	seedAuditEvent(t, db, EventRoleAssigned, nil, diff, now)

	report, err := c.GetPermissionChangeAudit(ctx, now.Add(-time.Minute), now.Add(time.Minute), 100)
	require.NoError(t, err)
	require.Equal(t, 1, report.Total)
	assert.Equal(t, "role:77", report.Changes[0].RoleName)
}

// TestGetPermissionChangeAudit_NilActorID — event without UserID → empty actor name.
func TestGetPermissionChangeAudit_NilActorID(t *testing.T) {
	t.Parallel()
	c, db := newPermAuditCore(t)
	ctx := context.Background()

	now := time.Now()
	seedAuditEvent(t, db, EventRoleAssigned, nil, `{"role_id":1}`, now)

	report, err := c.GetPermissionChangeAudit(ctx, now.Add(-time.Minute), now.Add(time.Minute), 100)
	require.NoError(t, err)
	require.Equal(t, 1, report.Total)
	assert.Empty(t, report.Changes[0].ActorName)
}

// TestGetPermissionChangeAudit_EmptyDiff — event with no Diff is handled gracefully.
func TestGetPermissionChangeAudit_EmptyDiff(t *testing.T) {
	t.Parallel()
	c, db := newPermAuditCore(t)
	ctx := context.Background()

	now := time.Now()
	seedAuditEvent(t, db, EventRoleAssigned, nil, "", now)

	report, err := c.GetPermissionChangeAudit(ctx, now.Add(-time.Minute), now.Add(time.Minute), 100)
	require.NoError(t, err)
	require.Equal(t, 1, report.Total)
	e := report.Changes[0]
	assert.Empty(t, e.TargetUser)
	assert.Empty(t, e.RoleName)
	assert.Equal(t, "global", e.Scope)
}

// TestGetPermissionChangeAudit_StorageError — storage failure propagated as error.
func TestGetPermissionChangeAudit_StorageError(t *testing.T) {
	t.Parallel()
	// Use a core backed by an erroring storage stub.
	c := NewKeyorixCore(&storageErrorStub{})
	_, err := c.GetPermissionChangeAudit(context.Background(), time.Time{}, time.Time{}, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission_change_audit")
}

// TestGetPermissionChangeAudit_ChronologicalOrder — events returned oldest-first.
// Events are seeded in ascending time order so the DB insertion order (and thus
// the ascending-id order the storage layer uses) matches the chronological order.
func TestGetPermissionChangeAudit_ChronologicalOrder(t *testing.T) {
	t.Parallel()
	c, db := newPermAuditCore(t)
	ctx := context.Background()

	base := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	// Seed in time order: id 1 < id 2 < id 3 ≡ time 1min < 2min < 3min.
	seedAuditEvent(t, db, EventRoleRemoved, nil, `{"role_id":2}`, base.Add(1*time.Minute))
	seedAuditEvent(t, db, EventRoleAssigned, nil, `{"role_id":1}`, base.Add(2*time.Minute))
	seedAuditEvent(t, db, EventRoleAssigned, nil, `{"role_id":3}`, base.Add(3*time.Minute))

	report, err := c.GetPermissionChangeAudit(ctx, base, base.Add(5*time.Minute), 100)
	require.NoError(t, err)
	require.Len(t, report.Changes, 3)
	// With Ascending:true the storage orders by id ASC (insertion order).
	// Because we inserted events in time order, ChangedAt must be non-decreasing.
	assert.True(t, !report.Changes[0].ChangedAt.After(report.Changes[1].ChangedAt))
	assert.True(t, !report.Changes[1].ChangedAt.After(report.Changes[2].ChangedAt))
}

// storageErrorStub is a minimal storage.Storage that returns errors for every
// call — used to verify error propagation in GetPermissionChangeAudit.
type storageErrorStub struct {
	storage.Storage // embed to satisfy the full interface with zero values
}

func (s *storageErrorStub) GetAuditLogs(_ context.Context, _ *storage.AuditFilter) ([]*models.AuditEvent, int64, error) {
	return nil, 0, errors.New("storage unavailable")
}
