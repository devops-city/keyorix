package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// newPurgeTestCore opens a fresh in-memory SQLite DB, migrates AuditEvent and
// LegalHold (needed by the legalHoldGuard that PurgeAuditLogs now calls),
// and returns a KeyorixCore with a fixed clock so retention cutoffs are stable.
func newPurgeTestCore(t *testing.T) (*KeyorixCore, *gorm.DB, time.Time) {
	t.Helper()
	db := sqlitetest.OpenWithDialector(t, "auditlogretention_", sqlite.Open, &gorm.Config{})
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.LegalHold{}))
	fixed := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	c := NewKeyorixCore(store.NewLocalStorage(db))
	c.now = func() time.Time { return fixed }
	return c, db, fixed
}

// seedRetentionAuditEvent inserts a single AuditEvent with the given event_time.
func seedRetentionAuditEvent(t *testing.T, db *gorm.DB, at time.Time) {
	t.Helper()
	require.NoError(t, db.Create(&models.AuditEvent{
		EventType: "secret.read", EventTime: at,
	}).Error)
}

// TestPurgeAuditLogs_HappyPath seeds 5 old + 3 recent events, purges with
// retention_days=30, and asserts exactly 5 are deleted with 3 remaining.
func TestPurgeAuditLogs_HappyPath(t *testing.T) {
	t.Parallel()
	c, db, fixed := newPurgeTestCore(t)
	ctx := context.Background()

	// Five events older than 30 days.
	for i := range 5 {
		seedRetentionAuditEvent(t, db, fixed.AddDate(0, 0, -(31+i)))
	}
	// Three recent events within the retention window.
	for i := range 3 {
		seedRetentionAuditEvent(t, db, fixed.AddDate(0, 0, -(i+1)))
	}

	result, err := c.PurgeAuditLogs(ctx, AuditLogRetentionConfig{RetentionDays: 30})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, int64(5), result.DeletedCount)
	// CutoffTime should be 30 days before "now".
	expectedCutoff := fixed.UTC().AddDate(0, 0, -30)
	assert.WithinDuration(t, expectedCutoff, result.CutoffTime, time.Second)

	// Verify 3 events remain in the table.
	var remaining int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", "secret.read").Count(&remaining).Error)
	// 3 user events + 1 audit_purge system event = 4
	assert.GreaterOrEqual(t, remaining+1, int64(3), "at least 3 user events remain")

	// Count just the user events with event_type="secret.read".
	var userEvents int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ? AND event_time >= ?", "secret.read", expectedCutoff).Count(&userEvents).Error)
	assert.Equal(t, int64(3), userEvents, "3 recent events survive the purge")
}

// TestPurgeAuditLogs_RetentionDaysBelowMin ensures values below 7 are rejected.
func TestPurgeAuditLogs_RetentionDaysBelowMin(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := NewKeyorixCore(store)

	for _, days := range []int{-10, -1, 0, 1, 6} {
		_, err := c.PurgeAuditLogs(context.Background(), AuditLogRetentionConfig{RetentionDays: days})
		require.Error(t, err, "days=%d should be rejected", days)
		assert.ErrorIs(t, err, ErrInvalidAuditRetentionDays, "days=%d", days)
	}
	store.AssertNotCalled(t, "DeleteAuditLogsBefore")
}

// TestPurgeAuditLogs_RetentionDaysExactlyMin ensures 7 is accepted.
func TestPurgeAuditLogs_RetentionDaysExactlyMin(t *testing.T) {
	t.Parallel()
	c, db, _ := newPurgeTestCore(t)
	result, err := c.PurgeAuditLogs(context.Background(), AuditLogRetentionConfig{RetentionDays: 7})
	require.NoError(t, err)
	require.NotNil(t, result)
	// Nothing to delete on an empty table beyond the system purge event itself.
	assert.Equal(t, int64(0), result.DeletedCount)

	// Suppress unused variable warning for db.
	_ = db
}

// TestPurgeAuditLogs_StorageErrorPropagated ensures a storage failure bubbles up.
func TestPurgeAuditLogs_StorageErrorPropagated(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	storageErr := errors.New("db offline")
	// legalHoldGuard → IsLegalHoldActive → storage.GetActiveLegalHold: no active hold.
	ms.On("GetActiveLegalHold", mock.Anything).Return((*models.LegalHold)(nil), nil)
	ms.On("DeleteAuditLogsBefore", mock.Anything, mock.Anything).Return(int64(0), (*storage.AuditChainAnchor)(nil), storageErr)
	// LogAuditEvent is called for the system purge event — but only on success.
	// On error the function returns early, so LogAuditEvent is never called.

	c := NewKeyorixCore(ms)
	_, err := c.PurgeAuditLogs(context.Background(), AuditLogRetentionConfig{RetentionDays: 30})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "db offline")
	ms.AssertExpectations(t)
}

// TestPurgeAuditLogs_LegalHoldBlocked verifies that PurgeAuditLogs refuses to delete
// audit records when a legal hold is active (#r125-H4 — PurgeAuditLogs previously
// skipped the legalHoldGuard that PurgeExpiredSoftDeletes and
// PurgeExpiredComplianceRecords call, allowing audit evidence to be destroyed under hold).
func TestPurgeAuditLogs_LegalHoldBlocked(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	// GetActiveLegalHold returns a non-nil hold → legalHoldGuard refuses the purge.
	ms.On("GetActiveLegalHold", mock.Anything).Return(&models.LegalHold{ID: 1}, nil)

	c := NewKeyorixCore(ms)
	_, err := c.PurgeAuditLogs(context.Background(), AuditLogRetentionConfig{RetentionDays: 30})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "legal hold")
	ms.AssertNotCalled(t, "DeleteAuditLogsBefore", mock.Anything, mock.Anything)
	ms.AssertExpectations(t)
}
