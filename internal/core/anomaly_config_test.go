package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func newAnomalyConfigCore(store *MockStorage) *KeyorixCore {
	return &KeyorixCore{storage: store}
}

func TestGetAnomalyConfig_DelegatesToStorage(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newAnomalyConfigCore(store)
	ctx := context.Background()

	want := &models.AnomalyConfigRecord{LookbackDays: 14, QuarantineHours: 48}
	store.On("GetAnomalyConfig", ctx).Return(want, nil)

	got, err := c.GetAnomalyConfig(ctx)
	require.NoError(t, err)
	assert.Equal(t, 14, got.LookbackDays)
	assert.Equal(t, 48, got.QuarantineHours)
}

func TestGetAnomalyConfig_PropagatesError(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newAnomalyConfigCore(store)
	ctx := context.Background()

	store.On("GetAnomalyConfig", ctx).Return(nil, errors.New("db error"))

	_, err := c.GetAnomalyConfig(ctx)
	require.Error(t, err)
}

func TestUpdateAnomalyConfig_SetsUpdatedByAndDelegatesToStorage(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newAnomalyConfigCore(store)
	ctx := context.Background()

	cfg := &models.AnomalyConfigRecord{LookbackDays: 30}
	store.On("GetAnomalyConfig", ctx).Return(&models.AnomalyConfigRecord{LookbackDays: 7}, nil)
	store.On("SaveAnomalyConfig", ctx, mock.MatchedBy(func(r *models.AnomalyConfigRecord) bool {
		return r.UpdatedBy == "admin" && r.LookbackDays == 30
	})).Return(nil)
	var captured *models.AuditEvent
	store.On("LogAuditEvent", ctx, mock.AnythingOfType("*models.AuditEvent")).
		Run(func(args mock.Arguments) { captured = args.Get(1).(*models.AuditEvent) }).
		Return(nil)

	err := c.UpdateAnomalyConfig(ctx, cfg, "admin", 7)
	require.NoError(t, err)
	assert.Equal(t, "admin", cfg.UpdatedBy)
	assert.False(t, cfg.UpdatedAt.IsZero())
	require.NotNil(t, captured, "updating the anomaly config must write an audit event")
	assert.Equal(t, EventAnomalyConfigUpdated, captured.EventType)
	require.NotNil(t, captured.UserID)
	assert.Equal(t, uint(7), *captured.UserID)
	assert.Contains(t, captured.Diff, `"lookback_days":30`)
	assert.Contains(t, captured.Diff, `"lookback_days":7`, "the diff must carry the PRIOR config too, not just the new one")
}

func TestUpdateAnomalyConfig_PropagatesStorageError(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newAnomalyConfigCore(store)
	ctx := context.Background()

	cfg := &models.AnomalyConfigRecord{}
	store.On("GetAnomalyConfig", ctx).Return(&models.AnomalyConfigRecord{}, nil)
	store.On("SaveAnomalyConfig", ctx, mock.AnythingOfType("*models.AnomalyConfigRecord")).
		Return(errors.New("write failed"))

	err := c.UpdateAnomalyConfig(ctx, cfg, "user", 1)
	require.Error(t, err)
	store.AssertNotCalled(t, "LogAuditEvent", mock.Anything, mock.Anything)
}

func TestApplyAnomalyConfig_SetsLookback(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newAnomalyConfigCore(store)
	ctx := context.Background()

	cfg := &models.AnomalyConfigRecord{LookbackDays: 14}
	store.On("GetAnomalyConfig", ctx).Return(cfg, nil)

	detector := NewAnomalyDetector(store)
	err := c.ApplyAnomalyConfig(ctx, detector)
	require.NoError(t, err)
	assert.Equal(t, 14*24*time.Hour, detector.lookback)
}

func TestApplyAnomalyConfig_SetsQuarantine(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newAnomalyConfigCore(store)
	ctx := context.Background()

	cfg := &models.AnomalyConfigRecord{QuarantineHours: 48}
	store.On("GetAnomalyConfig", ctx).Return(cfg, nil)

	detector := NewAnomalyDetector(store)
	err := c.ApplyAnomalyConfig(ctx, detector)
	require.NoError(t, err)
	assert.Equal(t, 48*time.Hour, detector.quarantine)
}

func TestApplyAnomalyConfig_SetsMLConfig(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newAnomalyConfigCore(store)
	ctx := context.Background()

	cfg := &models.AnomalyConfigRecord{
		MLEnabled:    true,
		MLThreshold:  0.75,
		MLNumTrees:   100,
		MLSampleSize: 256,
	}
	store.On("GetAnomalyConfig", ctx).Return(cfg, nil)

	detector := NewAnomalyDetector(store)
	err := c.ApplyAnomalyConfig(ctx, detector)
	require.NoError(t, err)
	assert.True(t, detector.ml.Enabled)
	assert.Equal(t, 0.75, detector.ml.Threshold)
	assert.Equal(t, 100, detector.ml.NumTrees)
}

func TestApplyAnomalyConfig_ZeroValuesNotApplied(t *testing.T) {
	t.Parallel()
	// LookbackDays=0 and QuarantineHours=0 should not override detector defaults.
	store := new(MockStorage)
	c := newAnomalyConfigCore(store)
	ctx := context.Background()

	cfg := &models.AnomalyConfigRecord{LookbackDays: 0, QuarantineHours: 0}
	store.On("GetAnomalyConfig", ctx).Return(cfg, nil)

	detector := NewAnomalyDetector(store)
	originalLookback := detector.lookback
	originalQuarantine := detector.quarantine

	err := c.ApplyAnomalyConfig(ctx, detector)
	require.NoError(t, err)
	assert.Equal(t, originalLookback, detector.lookback)
	assert.Equal(t, originalQuarantine, detector.quarantine)
}

func TestApplyAnomalyConfig_OffHoursEnabled_AppliesBand(t *testing.T) {
	t.Parallel()
	// Legitimate case: OffHoursEnabled with a valid, distinct hour pair must be
	// applied to the live detector and audited, with no error.
	store := new(MockStorage)
	c := newAnomalyConfigCore(store)
	ctx := context.Background()

	cfg := &models.AnomalyConfigRecord{
		OffHoursEnabled:  true,
		OffHoursTimezone: "UTC",
		OffHoursStart:    20,
		OffHoursEnd:      7,
	}
	store.On("GetAnomalyConfig", ctx).Return(cfg, nil)
	store.On("LogAuditEvent", ctx, mock.Anything).Return(nil)

	detector := NewAnomalyDetector(store)
	err := c.ApplyAnomalyConfig(ctx, detector)
	require.NoError(t, err)
	assert.Equal(t, 20, detector.offHours.start)
	assert.Equal(t, 7, detector.offHours.end)
}

// TestApplyAnomalyConfig_PropagatesBusinessHoursError is the wave6/G05 regression:
// previously ApplyAnomalyConfig discarded SetBusinessHours' error entirely
// (`_ = detector.SetBusinessHours(...)`), so a rejected/invalid persisted off-hours
// config — including the accidental-collision case where a partial update leaves one
// field matching the other's still-in-effect value — surfaced no error anywhere. The
// detector must keep its prior (safe) policy, but the caller must now be told the
// persisted config didn't take effect, AND the other independent knobs (ML here)
// must still be applied rather than the whole config apply aborting.
func TestApplyAnomalyConfig_PropagatesBusinessHoursError(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newAnomalyConfigCore(store)
	ctx := context.Background()

	// OffHoursStart=6 collides with the hardcoded default OffHoursEnd (6) once
	// OffHoursEnd is out of range and would (pre-fix) have silently fallen back to
	// that default, producing a degenerate {6,6} band with no error.
	cfg := &models.AnomalyConfigRecord{
		OffHoursEnabled:  true,
		OffHoursTimezone: "UTC",
		OffHoursStart:    6,
		OffHoursEnd:      -1,
		MLEnabled:        true,
		MLThreshold:      0.75,
	}
	store.On("GetAnomalyConfig", ctx).Return(cfg, nil)

	detector := NewAnomalyDetector(store)
	before := detector.offHours

	err := c.ApplyAnomalyConfig(ctx, detector)
	require.Error(t, err, "a rejected off-hours config must be surfaced, not swallowed")
	assert.Equal(t, before, detector.offHours, "the detector must keep its prior policy, not a degenerate band")
	// Independent knobs still applied despite the off-hours rejection.
	assert.True(t, detector.ml.Enabled)
	assert.Equal(t, 0.75, detector.ml.Threshold)
}

// TestApplyAnomalyConfig_HotloadDoesNotDuplicateAuditOnUnchangedConfig is the
// findings-core-2/core-anomaly.json#1 regression at the ApplyAnomalyConfig level:
// server/main.go's scheduler calls ApplyAnomalyConfig on every tick to hot-load the
// persisted config, and it previously called SetBusinessHours -> the audit write
// unconditionally, so an unchanged persisted off-hours config produced a fresh
// anomaly.business_hours_configured audit event every single tick. Calling
// ApplyAnomalyConfig repeatedly with the SAME persisted config (simulating
// consecutive scheduler ticks) must only audit once.
func TestApplyAnomalyConfig_HotloadDoesNotDuplicateAuditOnUnchangedConfig(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newAnomalyConfigCore(store)
	ctx := context.Background()

	cfg := &models.AnomalyConfigRecord{
		OffHoursEnabled:  true,
		OffHoursTimezone: "UTC",
		OffHoursStart:    20,
		OffHoursEnd:      7,
	}
	store.On("GetAnomalyConfig", ctx).Return(cfg, nil)
	store.On("LogAuditEvent", ctx, mock.Anything).Return(nil)

	detector := NewAnomalyDetector(store)

	// Simulate five consecutive scheduler ticks hot-loading the same persisted
	// config, as server/main.go's runScheduler loop does every scan interval.
	for range 5 {
		require.NoError(t, c.ApplyAnomalyConfig(ctx, detector))
	}

	store.AssertNumberOfCalls(t, "LogAuditEvent", 1)
}

// TestApplyAnomalyConfig_HotloadAuditsGenuineChange confirms the fix above doesn't
// just suppress the audit event outright: a real operator change to the persisted
// off-hours config must still produce a fresh audit event on the next hot-load
// tick, and that new value must then stop re-auditing on subsequent unchanged ticks.
func TestApplyAnomalyConfig_HotloadAuditsGenuineChange(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newAnomalyConfigCore(store)
	ctx := context.Background()

	cfg := &models.AnomalyConfigRecord{
		OffHoursEnabled:  true,
		OffHoursTimezone: "UTC",
		OffHoursStart:    20,
		OffHoursEnd:      7,
	}
	store.On("GetAnomalyConfig", ctx).Return(cfg, nil)
	store.On("LogAuditEvent", ctx, mock.Anything).Return(nil)

	detector := NewAnomalyDetector(store)

	require.NoError(t, c.ApplyAnomalyConfig(ctx, detector))
	require.NoError(t, c.ApplyAnomalyConfig(ctx, detector))
	store.AssertNumberOfCalls(t, "LogAuditEvent", 1)

	// A genuine operator change to the persisted band...
	cfg.OffHoursStart = 21
	require.NoError(t, c.ApplyAnomalyConfig(ctx, detector))
	store.AssertNumberOfCalls(t, "LogAuditEvent", 2)

	// ...and re-applying that NEW value on subsequent ticks must not duplicate it
	// again either.
	require.NoError(t, c.ApplyAnomalyConfig(ctx, detector))
	store.AssertNumberOfCalls(t, "LogAuditEvent", 2)
}

func TestApplyAnomalyConfig_PropagatesGetError(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newAnomalyConfigCore(store)
	ctx := context.Background()

	store.On("GetAnomalyConfig", ctx).Return(nil, errors.New("db error"))

	detector := NewAnomalyDetector(store)
	err := c.ApplyAnomalyConfig(ctx, detector)
	require.Error(t, err)
}
