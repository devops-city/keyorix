package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func newComplianceSnapshotStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.CompliancePostureSnapshot{}))
	return NewLocalStorage(db)
}

func TestSaveCompliancePostureSnapshot_CreatesRow(t *testing.T) {
	ls := newComplianceSnapshotStore(t)
	ctx := context.Background()
	today := time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)

	snap := &models.CompliancePostureSnapshot{
		TotalControls:    15,
		PassedControls:   12,
		FailedControls:   2,
		DegradedControls: 1,
		SnapshotDate:     today,
	}

	require.NoError(t, ls.SaveCompliancePostureSnapshot(ctx, snap))
	assert.NotZero(t, snap.ID, "expected ID to be set after create")

	// Calling again for the same SnapshotDate must upsert (not error or duplicate).
	snap2 := &models.CompliancePostureSnapshot{
		TotalControls:    15,
		PassedControls:   13,
		FailedControls:   1,
		DegradedControls: 1,
		SnapshotDate:     today,
	}
	require.NoError(t, ls.SaveCompliancePostureSnapshot(ctx, snap2), "second save for same date must succeed (upsert)")

	var count int64
	require.NoError(t, ls.db.Model(&models.CompliancePostureSnapshot{}).Count(&count).Error)
	assert.EqualValues(t, 1, count, "upsert must not create a duplicate row for the same snapshot_date")
}

func TestGetPreviousCompliancePostureSnapshot_ReturnsNilWhenNone(t *testing.T) {
	ls := newComplianceSnapshotStore(t)
	ctx := context.Background()

	got, err := ls.GetPreviousCompliancePostureSnapshot(ctx, time.Now())
	require.NoError(t, err)
	assert.Nil(t, got, "expected nil when no prior snapshot exists")
}

func TestGetPreviousCompliancePostureSnapshot_SkipsRecentSnapshot(t *testing.T) {
	ls := newComplianceSnapshotStore(t)
	ctx := context.Background()

	now := time.Now().UTC()
	todayMidnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	yesterdayMidnight := todayMidnight.AddDate(0, 0, -1)

	// A snapshot for TODAY must NOT be returned (same-day self-comparison guard).
	require.NoError(t, ls.db.Create(&models.CompliancePostureSnapshot{
		TotalControls:  15,
		PassedControls: 10,
		SnapshotDate:   todayMidnight,
	}).Error)

	got, err := ls.GetPreviousCompliancePostureSnapshot(ctx, now)
	require.NoError(t, err)
	assert.Nil(t, got, "today's snapshot must not be returned as a prior snapshot")

	// A snapshot for YESTERDAY must be returned.
	require.NoError(t, ls.db.Create(&models.CompliancePostureSnapshot{
		TotalControls:  15,
		PassedControls: 8,
		SnapshotDate:   yesterdayMidnight,
	}).Error)

	got, err = ls.GetPreviousCompliancePostureSnapshot(ctx, now)
	require.NoError(t, err)
	require.NotNil(t, got, "expected yesterday's snapshot to be returned")
	assert.Equal(t, 8, got.PassedControls)
}

func TestListCompliancePostureSnapshots_EmptyTable(t *testing.T) {
	ls := newComplianceSnapshotStore(t)
	snaps, err := ls.ListCompliancePostureSnapshots(context.Background(), 0)
	require.NoError(t, err)
	assert.Empty(t, snaps)
}

func TestListCompliancePostureSnapshots_OrderedDescending(t *testing.T) {
	ls := newComplianceSnapshotStore(t)
	ctx := context.Background()

	d1 := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	d2 := time.Date(2026, 7, 2, 0, 0, 0, 0, time.UTC)
	d3 := time.Date(2026, 7, 3, 0, 0, 0, 0, time.UTC)
	for _, d := range []time.Time{d2, d1, d3} {
		require.NoError(t, ls.db.Create(&models.CompliancePostureSnapshot{SnapshotDate: d}).Error)
	}

	snaps, err := ls.ListCompliancePostureSnapshots(ctx, 0) // 0 → default limit
	require.NoError(t, err)
	require.Len(t, snaps, 3)
	assert.True(t, snaps[0].SnapshotDate.Equal(d3), "most recent first")
	assert.True(t, snaps[2].SnapshotDate.Equal(d1), "oldest last")
}

func TestListCompliancePostureSnapshots_RespectsLimit(t *testing.T) {
	ls := newComplianceSnapshotStore(t)
	ctx := context.Background()

	for i := range 5 {
		d := time.Date(2026, 7, i+1, 0, 0, 0, 0, time.UTC)
		require.NoError(t, ls.db.Create(&models.CompliancePostureSnapshot{SnapshotDate: d}).Error)
	}

	snaps, err := ls.ListCompliancePostureSnapshots(ctx, 2)
	require.NoError(t, err)
	assert.Len(t, snaps, 2)
}

func TestListCompliancePostureSnapshots_DBError(t *testing.T) {
	ls := newComplianceSnapshotStore(t)
	// Drop the table so Find returns a DB error.
	require.NoError(t, ls.db.Exec("DROP TABLE compliance_posture_snapshots").Error)
	_, err := ls.ListCompliancePostureSnapshots(context.Background(), 0)
	require.Error(t, err)
}
