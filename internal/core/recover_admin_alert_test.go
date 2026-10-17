// recover_admin_alert_test.go — coverage for RunRecoverAdminAlerting (F7,
// Akeyless-style alerting on recover-admin use).
package core

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func recoverAdminEvent(id uint) *models.AuditEvent {
	return &models.AuditEvent{
		ID:          id,
		EventType:   recoverAdminAuditEventType,
		Description: "keyorix-server admin recover-admin restored account",
	}
}

// TestRunRecoverAdminAlerting_NewEventNotifiesAndAdvancesMark verifies the
// core loop: one new recover-admin event, no prior high-water mark, one
// enabled webhook channel — the webhook is called exactly once and the
// mark is advanced to that event's ID.
func TestRunRecoverAdminAlerting_NewEventNotifiesAndAdvancesMark(t *testing.T) {
	received := make(chan struct{}, 1)
	tr := &fakeWebhookTransport{called: received}

	store := new(MockStorage)
	ev := recoverAdminEvent(42)
	// URLEnc, not URL (#2433): ListNotificationChannels (the core-layer wrapper
	// RunRecoverAdminAlerting now calls via recover_admin_alert.go) decrypts
	// ch.URLEnc into ch.URL -- a fixture that only set the latter would read
	// back empty, and postJSONToURL below would never actually reach tr.
	ch := &models.NotificationChannel{ID: 1, Name: "ops-webhook", Type: "webhook", URLEnc: plaintextURLEnc("https://fake-webhook.test/hook"), Enabled: true}

	store.On("GetSystemMetadata", mock.Anything, recoverAdminAlertHighWaterKey).Return("", false, nil)
	store.On("MaxAuditEventID", mock.Anything).Return(uint(42), nil)
	store.On("GetAuditLogs", mock.Anything, mock.AnythingOfType("*storage.AuditFilter")).
		Return([]*models.AuditEvent{ev}, int64(1), nil)
	store.On("ListNotificationChannels", mock.Anything).Return([]*models.NotificationChannel{ch}, nil)
	store.On("SetSystemMetadata", mock.Anything, recoverAdminAlertHighWaterKey, "42").Return(nil)

	c := NewKeyorixCore(store)
	c.httpClient = &http.Client{Transport: tr}

	n, err := c.RunRecoverAdminAlerting(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	select {
	case <-received:
	default:
		t.Error("webhook was not called")
	}
	store.AssertExpectations(t)
}

// TestRunRecoverAdminAlerting_NoNewAuditRowsIsNoOp verifies that when the
// highest audit id is not past the mark (the common steady-state tick), the run
// reads no audit rows and writes nothing.
func TestRunRecoverAdminAlerting_NoNewAuditRowsIsNoOp(t *testing.T) {
	store := new(MockStorage)
	store.On("GetSystemMetadata", mock.Anything, recoverAdminAlertHighWaterKey).Return("42", true, nil)
	store.On("MaxAuditEventID", mock.Anything).Return(uint(42), nil)

	c := NewKeyorixCore(store)
	n, err := c.RunRecoverAdminAlerting(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, n)

	store.AssertNotCalled(t, "GetAuditLogs", mock.Anything, mock.Anything)
	store.AssertNotCalled(t, "ListNotificationChannels", mock.Anything)
	store.AssertNotCalled(t, "SetSystemMetadata", mock.Anything, mock.Anything, mock.Anything)
}

// TestRunRecoverAdminAlerting_NoMatchAdvancesMarkToHighestExamined is the core
// of AUDIT-SCAN-FIX-1: new audit rows but none a recover-admin use. Nothing is
// alerted, yet the mark moves to the highest id examined so the next run starts
// there instead of re-reading the range.
func TestRunRecoverAdminAlerting_NoMatchAdvancesMarkToHighestExamined(t *testing.T) {
	store := new(MockStorage)
	store.On("GetSystemMetadata", mock.Anything, recoverAdminAlertHighWaterKey).Return("42", true, nil)
	store.On("MaxAuditEventID", mock.Anything).Return(uint(5000), nil)
	store.On("GetAuditLogs", mock.Anything, mock.MatchedBy(func(f *storage.AuditFilter) bool {
		return f.AfterID != nil && *f.AfterID == 42 && f.UpToID != nil && *f.UpToID == 5000
	})).Return([]*models.AuditEvent{}, int64(0), nil)
	store.On("SetSystemMetadata", mock.Anything, recoverAdminAlertHighWaterKey, "5000").Return(nil)

	c := NewKeyorixCore(store)
	n, err := c.RunRecoverAdminAlerting(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, n)
	store.AssertExpectations(t)
	store.AssertNotCalled(t, "ListNotificationChannels", mock.Anything)
}

// TestRunRecoverAdminAlerting_FullBatchAdvancesOnlyToLastEvent verifies that a
// full batch does not skip the matches beyond it: the mark stops at the batch's
// last event, not at the highest id.
func TestRunRecoverAdminAlerting_FullBatchAdvancesOnlyToLastEvent(t *testing.T) {
	events := make([]*models.AuditEvent, recoverAdminAlertBatchSize)
	for i := range events {
		events[i] = recoverAdminEvent(uint(100 + i))
	}
	last := events[len(events)-1].ID

	store := new(MockStorage)
	store.On("GetSystemMetadata", mock.Anything, recoverAdminAlertHighWaterKey).Return("42", true, nil)
	store.On("MaxAuditEventID", mock.Anything).Return(uint(9000), nil)
	store.On("GetAuditLogs", mock.Anything, mock.Anything).Return(events, int64(0), nil)
	store.On("ListNotificationChannels", mock.Anything).Return([]*models.NotificationChannel{}, nil)
	store.On("SetSystemMetadata", mock.Anything, recoverAdminAlertHighWaterKey, fmt.Sprint(last)).Return(nil)

	c := NewKeyorixCore(store)
	n, err := c.RunRecoverAdminAlerting(context.Background())
	require.NoError(t, err)
	assert.Equal(t, recoverAdminAlertBatchSize, n)
	store.AssertExpectations(t)
}

// TestRunRecoverAdminAlerting_MarkNeverMovesBack verifies the monotonic write: a
// run that lost the scheduler lease to a replica which already advanced the mark
// must not overwrite it with an older value.
func TestRunRecoverAdminAlerting_MarkNeverMovesBack(t *testing.T) {
	store := new(MockStorage)
	// Read at start: 42. Re-read just before the write: another replica moved it to 9000.
	store.On("GetSystemMetadata", mock.Anything, recoverAdminAlertHighWaterKey).Return("42", true, nil).Once()
	store.On("GetSystemMetadata", mock.Anything, recoverAdminAlertHighWaterKey).Return("9000", true, nil).Once()
	store.On("MaxAuditEventID", mock.Anything).Return(uint(5000), nil)
	store.On("GetAuditLogs", mock.Anything, mock.Anything).Return([]*models.AuditEvent{}, int64(0), nil)

	c := NewKeyorixCore(store)
	_, err := c.RunRecoverAdminAlerting(context.Background())
	require.NoError(t, err)
	store.AssertNotCalled(t, "SetSystemMetadata", mock.Anything, mock.Anything, mock.Anything)
}

// TestRunRecoverAdminAlerting_ResumesFromHighWaterMark verifies the AfterID
// cursor is built from the stored mark, not always from 0 -- the "no
// duplicate after restart" property.
func TestRunRecoverAdminAlerting_ResumesFromHighWaterMark(t *testing.T) {
	store := new(MockStorage)
	store.On("GetSystemMetadata", mock.Anything, recoverAdminAlertHighWaterKey).Return("42", true, nil)
	store.On("MaxAuditEventID", mock.Anything).Return(uint(100), nil)
	store.On("GetAuditLogs", mock.Anything, mock.MatchedBy(func(f *storage.AuditFilter) bool {
		return f.AfterID != nil && *f.AfterID == 42
	})).Return([]*models.AuditEvent{}, int64(0), nil)
	store.On("SetSystemMetadata", mock.Anything, recoverAdminAlertHighWaterKey, "100").Return(nil)

	c := NewKeyorixCore(store)
	_, err := c.RunRecoverAdminAlerting(context.Background())
	require.NoError(t, err)
	store.AssertExpectations(t)
}

// TestRunRecoverAdminAlerting_CorruptMarkTreatedAsZero verifies a
// non-integer stored value doesn't error the whole run -- it's treated as
// "nothing notified yet" and logged, not fatal.
func TestRunRecoverAdminAlerting_CorruptMarkTreatedAsZero(t *testing.T) {
	store := new(MockStorage)
	store.On("GetSystemMetadata", mock.Anything, recoverAdminAlertHighWaterKey).Return("not-a-number", true, nil)
	store.On("MaxAuditEventID", mock.Anything).Return(uint(7), nil)
	store.On("GetAuditLogs", mock.Anything, mock.Anything).Return([]*models.AuditEvent{}, int64(0), nil)
	store.On("SetSystemMetadata", mock.Anything, recoverAdminAlertHighWaterKey, "7").Return(nil)

	c := NewKeyorixCore(store)
	n, err := c.RunRecoverAdminAlerting(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, n)
}

// ---- End-to-end integration (real SQLite, no mocks) ----
//
// This is the exact acceptance shape the session item describes: run
// recover-admin (here: write the real "admin.recover_admin" audit event,
// matching recordRecoveryAuditEvent's own EventType literal exactly) →
// start the server (here: call RunRecoverAdminAlerting, as the scheduler's
// first, immediate run does) → exactly one alert; call it again (a restart
// or the next scheduler tick) → no duplicate.

func newRecoverAdminAlertIntegrationCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.AuditEvent{}, &models.SystemMetadata{}, &models.NotificationChannel{},
	))
	return NewKeyorixCore(store.NewLocalStorage(db)), db
}

func TestRunRecoverAdminAlerting_Integration_ExactlyOneAlertNoDuplicateAfterRestart(t *testing.T) {
	received := make(chan struct{}, 4)
	tr := &fakeWebhookTransport{called: received}

	c, db := newRecoverAdminAlertIntegrationCore(t)
	c.httpClient = &http.Client{Transport: tr}
	ctx := context.Background()

	// "run recover-admin": write the real event, same EventType literal
	// recordRecoveryAuditEvent uses.
	// URLEnc, not URL (#2433): URL is gorm:"-" (not a persisted column) -- a
	// raw db.Create setting only URL would silently persist no URL at all.
	require.NoError(t, db.Create(&models.NotificationChannel{
		Name: "ops-webhook", Type: "webhook", URLEnc: plaintextURLEnc("https://fake-webhook.test/hook"), Enabled: true,
	}).Error)
	uid := uint(1)
	ok := true
	require.NoError(t, c.storage.LogAuditEvent(ctx, &models.AuditEvent{
		EventType:   recoverAdminAuditEventType,
		UserID:      &uid,
		Description: "keyorix-server admin recover-admin restored account \"alice\" (user id 1)",
		Success:     &ok,
		ActorType:   "system",
		EventTime:   time.Now(),
	}))

	// "start the server": first alerting pass.
	n, err := c.RunRecoverAdminAlerting(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n, "exactly one recover-admin use must produce exactly one alerted event")

	select {
	case <-received:
	default:
		t.Fatal("webhook was not called on the first pass")
	}

	// "restart" (or the next scheduler tick): re-run with no new events.
	n2, err := c.RunRecoverAdminAlerting(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, n2, "a restart must not re-alert an already-notified recover-admin use")

	select {
	case <-received:
		t.Fatal("webhook was called AGAIN after restart — duplicate alert")
	default:
	}
}
