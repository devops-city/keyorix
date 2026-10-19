package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// complianceTrendCore builds a KeyorixCore backed by a sqlite DB that has both the
// minimal tables GetCompliancePosture needs (Project, to avoid a fatal error on
// ListProjects) and CompliancePostureSnapshot (for the trend machinery).
// Additional tables left unmigrated degrade the posture sub-rollups gracefully.
//
// c.now is fixed to a date far in the future (2099-01-15) so that snapshots saved
// during tests are dated in 2099 and are never returned by GetPreviousCompliancePostureSnapshot
// (which queries WHERE snapshot_date < real-today's midnight). Only explicitly seeded
// rows in the past qualify as "previous", keeping tests deterministic regardless of
// the actual calendar date they run on.
func complianceTrendCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	// Full schema (#2834): GetCompliancePosture persists the trend snapshot only
	// when no sub-rollup is degraded, and a minimal fixture's missing tables
	// degrade it (see #2461 round 2 for the same effect on the Role/UserRole
	// queries). Every rollup must be readable for a snapshot to be saved.
	require.NoError(t, db.AutoMigrate(models.AllTestModels()...))
	c := &KeyorixCore{storage: store.NewLocalStorage(db)}
	c.now = func() time.Time { return time.Date(2099, 1, 15, 12, 0, 0, 0, time.UTC) }
	return c, db
}

// TestGetCompliancePosture_TrendNoData verifies that the first call with no prior
// snapshot returns a Trend with Direction "no_data".
func TestGetCompliancePosture_TrendNoData(t *testing.T) {
	t.Parallel()
	c, _ := complianceTrendCore(t)

	p, err := c.GetCompliancePosture(context.Background())
	require.NoError(t, err)

	require.NotNil(t, p.Trend, "Trend must be populated even on first call")
	assert.Equal(t, "no_data", p.Trend.Direction)
	assert.Nil(t, p.Trend.PreviousDate, "PreviousDate must be nil when no prior snapshot exists")
	assert.Nil(t, p.Trend.PassedDelta, "PassedDelta must be nil when there is no prior data")
	assert.Nil(t, p.Trend.FailedDelta, "FailedDelta must be nil when there is no prior data")
}

// TestGetCompliancePosture_TrendImproving verifies that when the previous snapshot
// had fewer passed controls than the current one, Direction = "improving".
func TestGetCompliancePosture_TrendImproving(t *testing.T) {
	t.Parallel()
	c, db := complianceTrendCore(t)
	ctx := context.Background()

	// Seed a prior snapshot with only 5 passed controls — older than 20 hours so it
	// qualifies as a "previous" snapshot.
	prevDate := time.Date(2026, 7, 17, 0, 0, 0, 0, time.UTC) // two days ago
	require.NoError(t, db.Create(&models.CompliancePostureSnapshot{
		TotalControls:  15,
		PassedControls: 5,
		FailedControls: 8,
		SnapshotDate:   prevDate,
	}).Error)

	p, err := c.GetCompliancePosture(ctx)
	require.NoError(t, err)

	require.NotNil(t, p.Trend)
	assert.Equal(t, "improving", p.Trend.Direction,
		"more controls passing now than in the prior snapshot → improving")
	require.NotNil(t, p.Trend.PassedDelta)
	assert.Greater(t, *p.Trend.PassedDelta, 0,
		"PassedDelta must be positive when more controls are passing now")
	require.NotNil(t, p.Trend.PreviousDate)
	assert.Equal(t, prevDate, *p.Trend.PreviousDate)
}

// TestGetCompliancePosture_TrendStable verifies that when the passed-control and
// failed-control counts are identical to the prior snapshot, Direction = "stable".
func TestGetCompliancePosture_TrendStable(t *testing.T) {
	t.Parallel()
	c, db := complianceTrendCore(t)
	ctx := context.Background()

	// First, run a call to discover the actual counts this core produces so we can
	// seed a matching prior snapshot.
	p1, err := c.GetCompliancePosture(ctx)
	require.NoError(t, err)
	require.NotNil(t, p1.Trend)
	// p1.Trend.Direction is "no_data" (no prior snapshot existed for this first call).

	// Now retrieve the snapshot that was just saved.
	var savedSnap models.CompliancePostureSnapshot
	require.NoError(t, db.First(&savedSnap).Error)

	// Seed an older snapshot with the SAME passed/failed counts, dated 48 hours
	// before the fixed clock so it falls outside the 20-hour window.
	olderDate := time.Date(2026, 7, 17, 0, 0, 0, 0, time.UTC)
	require.NoError(t, db.Create(&models.CompliancePostureSnapshot{
		TotalControls:    savedSnap.TotalControls,
		PassedControls:   savedSnap.PassedControls,
		FailedControls:   savedSnap.FailedControls,
		DegradedControls: savedSnap.DegradedControls,
		SnapshotDate:     olderDate,
	}).Error)

	// Delete the snapshot for today so the second call produces a fresh save that
	// will compare against our older seed row.
	require.NoError(t, db.Delete(&savedSnap).Error)

	p2, err := c.GetCompliancePosture(ctx)
	require.NoError(t, err)
	require.NotNil(t, p2.Trend)
	assert.Equal(t, "stable", p2.Trend.Direction,
		"identical passed/failed counts → stable")
	require.NotNil(t, p2.Trend.PassedDelta)
	assert.Equal(t, 0, *p2.Trend.PassedDelta)
	require.NotNil(t, p2.Trend.FailedDelta)
	assert.Equal(t, 0, *p2.Trend.FailedDelta)
}

// TestComputeComplianceTrend_Regressing verifies the "regressing" branch
// (passedDelta < 0 || failedDelta > 0) of computeComplianceTrend directly,
// using a seeded previous snapshot with more passed controls than the current one.
func TestComputeComplianceTrend_Regressing(t *testing.T) {
	t.Parallel()
	c, db := complianceTrendCore(t)
	ctx := context.Background()

	// Seed a previous snapshot with high passed-control counts.
	prevDate := time.Date(2026, 7, 17, 0, 0, 0, 0, time.UTC)
	require.NoError(t, db.Create(&models.CompliancePostureSnapshot{
		TotalControls:  20,
		PassedControls: 18, // previous had many passing
		FailedControls: 2,
		SnapshotDate:   prevDate,
	}).Error)

	// Current snapshot has fewer passed controls (regression).
	current := &models.CompliancePostureSnapshot{
		TotalControls:  20,
		PassedControls: 10, // fewer passing now
		FailedControls: 8,
		SnapshotDate:   time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC),
	}

	trend := c.computeComplianceTrend(ctx, current)
	require.NotNil(t, trend)
	assert.Equal(t, "regressing", trend.Direction,
		"fewer controls passing now than in the prior snapshot → regressing")
	require.NotNil(t, trend.PassedDelta)
	assert.Less(t, *trend.PassedDelta, 0,
		"PassedDelta must be negative when fewer controls are passing now")
	require.NotNil(t, trend.FailedDelta)
	assert.Greater(t, *trend.FailedDelta, 0,
		"FailedDelta must be positive when more controls are failing now")
	require.NotNil(t, trend.PreviousDate)
	assert.Equal(t, prevDate, *trend.PreviousDate)
}

// TestComputeComplianceTrend_RegressingOnFailedDelta covers the sub-case where
// passedDelta is zero but failedDelta > 0 (more controls failing with the same
// passed count — still a regression).
func TestComputeComplianceTrend_RegressingOnFailedDelta(t *testing.T) {
	t.Parallel()
	c, db := complianceTrendCore(t)
	ctx := context.Background()

	prevDate := time.Date(2026, 7, 17, 0, 0, 0, 0, time.UTC)
	require.NoError(t, db.Create(&models.CompliancePostureSnapshot{
		TotalControls:  20,
		PassedControls: 10,
		FailedControls: 2, // previously only 2 failing
		SnapshotDate:   prevDate,
	}).Error)

	current := &models.CompliancePostureSnapshot{
		TotalControls:  20,
		PassedControls: 10, // same passed count
		FailedControls: 8,  // more failing now
		SnapshotDate:   time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC),
	}

	trend := c.computeComplianceTrend(ctx, current)
	require.NotNil(t, trend)
	assert.Equal(t, "regressing", trend.Direction,
		"same passed count but more controls failing → regressing")
	require.NotNil(t, trend.PassedDelta)
	assert.Equal(t, 0, *trend.PassedDelta)
	require.NotNil(t, trend.FailedDelta)
	assert.Greater(t, *trend.FailedDelta, 0)
}

// TestComputeComplianceTrend_ErrorPathReturnsNoData verifies that when
// GetPreviousCompliancePostureSnapshot returns an error, computeComplianceTrend
// returns a "no_data" trend rather than propagating the error.
func TestComputeComplianceTrend_ErrorPathReturnsNoData(t *testing.T) {
	t.Parallel()
	c, db := complianceTrendCore(t)
	ctx := context.Background()

	// Build a current snapshot to pass into computeComplianceTrend directly.
	current := &models.CompliancePostureSnapshot{
		TotalControls:  10,
		PassedControls: 7,
		FailedControls: 3,
		SnapshotDate:   time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC),
	}

	// Force the DB to return an error by closing the underlying sql.DB.
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	// computeComplianceTrend must fall back to "no_data" on a storage error.
	trend := c.computeComplianceTrend(ctx, current)
	require.NotNil(t, trend)
	assert.Equal(t, "no_data", trend.Direction,
		"a storage error from GetPreviousCompliancePostureSnapshot must yield no_data, not an error response")
	assert.Nil(t, trend.PreviousDate)
	assert.Nil(t, trend.PassedDelta)
	assert.Nil(t, trend.FailedDelta)
}

// TestBuildCompliancePostureSnapshot_DegradedControlsCounter verifies that when a
// CompliancePosture has sub-rollup failures (Degraded=true with matching reasons),
// EvaluateControls produces ControlStatusUnknown entries and buildCompliancePostureSnapshot
// correctly increments DegradedControls rather than counting those controls as passed
// or failed.
func TestBuildCompliancePostureSnapshot_DegradedControlsCounter(t *testing.T) {
	t.Parallel()
	// Construct a posture with a degraded identity sub-rollup. "identity" is the
	// DegradedArea prefix checked by the second-factor control in EvaluateControls,
	// so that control will evaluate to ControlStatusUnknown.
	p := &CompliancePosture{
		Degraded:        true,
		DegradedReasons: []string{"identity: sql: database is closed"},
	}
	snapshotDate := time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)

	snap := buildCompliancePostureSnapshot(p, snapshotDate)

	require.NotNil(t, snap)
	assert.Equal(t, snapshotDate, snap.SnapshotDate)
	assert.Greater(t, snap.DegradedControls, 0,
		"a posture with a degraded sub-rollup must produce at least one DegradedControls entry in the snapshot")
	assert.Equal(t, len(EvaluateControls(p)), snap.TotalControls,
		"TotalControls must equal the number of controls EvaluateControls returns")

	// The degraded count must be consistent: total = passed + failed + degraded.
	assert.Equal(t, snap.TotalControls, snap.PassedControls+snap.FailedControls+snap.DegradedControls,
		"passed + failed + degraded must sum to total controls")
}

// failingListProjectsStore wraps LocalStorage and overrides ListProjects to return
// an error, driving the fatal-error branch in buildComplianceSnapshot (and therefore
// GetCompliancePosture).
func failingListProjectsStore(inner storage.Storage) storage.Storage {
	return hooked(inner, &storeHooks{
		ListProjects: func(_ storage.Storage, _ context.Context) ([]*models.Project, error) {
			return nil, errors.New("simulated list-projects failure")
		},
	})
}

// TestGetCompliancePosture_ReturnsErrorWhenListProjectsFails covers the one statement
// in GetCompliancePosture that was previously unreachable: the `return nil, err` on the
// buildComplianceSnapshot error path.  All normal test helpers keep the DB alive so
// ListProjects always succeeds; this test injects a store that always fails it.
func TestGetCompliancePosture_ReturnsErrorWhenListProjectsFails(t *testing.T) {
	t.Parallel()
	c, db := complianceTrendCore(t)
	// Replace the storage with a wrapper that fails ListProjects.
	c.storage = failingListProjectsStore(c.storage.(*store.LocalStorage))
	// Also ensure the DB is still alive so the store wrapper itself is valid.
	_ = db

	_, err := c.GetCompliancePosture(context.Background())
	require.Error(t, err, "GetCompliancePosture must propagate a ListProjects failure")
	assert.Contains(t, err.Error(), "simulated list-projects failure",
		"the wrapped error message must be preserved in the returned error")
}
