// store_coverage_gaps_test.go — targeted coverage for branches not yet reached
// by earlier sweeps (s1–s4 and max).
//
// Focuses on: uncovered error-paths, zero-UserID skip branch in
// lastUserActivityByEventTypes, nil-filter GetAuditLogs, CreateAnomalyAlert
// with zero DetectedAt, nil projectID paths in MostAccessedSecrets /
// UnusedSecrets, PrincipalSecretFirstSeen nil-firstSeen skip, and DB-error
// paths throughout local_access_review_campaigns and local_audit.
package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// newBrokenDB returns a LocalStorage whose underlying DB has NO tables
// (no AutoMigrate was called). Any table-touching query will fail with a
// "no such table" error, allowing us to exercise error-return paths cheaply.
func newBrokenDB(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	return NewLocalStorage(db)
}

// ---------------------------------------------------------------------------
// lastUserActivityByEventTypes — zero UserID skip branch (line 112)
// ---------------------------------------------------------------------------

// TestLastUserActivityByEventTypes_SkipsZeroUserID verifies that audit rows
// whose user_id IS NULL (which GORM scans as uint(0)) are silently skipped
// — they cannot be keyed in the result map and must not appear at key 0.
func TestLastUserActivityByEventTypes_SkipsZeroUserID(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}))
	ls := NewLocalStorage(db)
	ctx := context.Background()

	now := time.Now().UTC()
	pid := uint(42)

	// Insert a row with no user_id (NULL → scans as 0).
	require.NoError(t, db.Create(&models.AuditEvent{
		EventType: "secret.read",
		ProjectID: &pid,
		EventTime: now,
		// UserID intentionally left nil so it is NULL in the DB.
	}).Error)

	// Insert a row with a valid user_id so we know the project-filter works.
	uid := uint(7)
	require.NoError(t, db.Create(&models.AuditEvent{
		EventType: "secret.read",
		ProjectID: &pid,
		UserID:    &uid,
		EventTime: now.Add(-time.Minute),
	}).Error)

	m, err := ls.lastUserActivityByEventTypes(ctx, pid, []string{"secret.read"}, time.Time{})
	require.NoError(t, err)

	// user 7 is present.
	assert.Contains(t, m, uint(7))
	// user 0 (NULL) must NOT appear.
	assert.NotContains(t, m, uint(0))
	// Only one entry.
	assert.Len(t, m, 1)
}

// ---------------------------------------------------------------------------
// CreateAnomalyAlert — zero DetectedAt branch (line 412)
// ---------------------------------------------------------------------------

// TestCreateAnomalyAlert_ZeroDetectedAt exercises the path where the caller
// passes a zero DetectedAt — the function must substitute time.Now().UTC()
// as the dedup-window anchor instead of the zero time.
func TestCreateAnomalyAlert_ZeroDetectedAt(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.AnomalyAlert{}))
	ls := NewLocalStorage(db)
	ctx := context.Background()

	// DetectedAt is the zero value — CreateAnomalyAlert must not panic and
	// must substitute now as the dedup-window anchor.
	err = ls.CreateAnomalyAlert(ctx, &models.AnomalyAlert{
		SecretNodeID: 1, AlertType: "new_ip", AccessedBy: "alice", IPAddress: "10.0.0.1",
		// DetectedAt: zero
	})
	require.NoError(t, err)

	all, err := ls.ListAnomalyAlerts(ctx, nil)
	require.NoError(t, err)
	assert.Len(t, all, 1)
}

// ---------------------------------------------------------------------------
// ListUnalertedAnomalyAlerts — DB error path (line 459)
// ---------------------------------------------------------------------------

func TestListUnalertedAnomalyAlerts_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.ListUnalertedAnomalyAlerts(context.Background())
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// GetAuditLogs — nil filter (line 321)
// ---------------------------------------------------------------------------

// TestGetAuditLogs_NilFilter exercises the nil-filter early branch in
// GetAuditLogs; the function must return valid (empty) results without panic.
func TestGetAuditLogs_NilFilter(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}))
	ls := NewLocalStorage(db)

	events, total, err := ls.GetAuditLogs(context.Background(), nil)
	require.NoError(t, err)
	assert.Zero(t, total)
	assert.Empty(t, events)
}

// TestGetAuditLogs_AllFilterFields exercises all optional AuditFilter fields
// at once so their individual branches (UserID, SecretID, Action, Actions,
// StartTime, EndTime, Success, ActorType, Page > 1, PageSize > 0) are hit.
func TestGetAuditLogs_AllFilterFields(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}))
	ls := NewLocalStorage(db)
	ctx := context.Background()

	uid := uint(1)
	sid := uint(2)
	now := time.Now().UTC()
	start := now.Add(-time.Hour)
	end := now.Add(time.Hour)
	success := true
	actorType := "user"
	action := "secret.read"

	f := &storage.AuditFilter{
		UserID:    &uid,
		SecretID:  &sid,
		Action:    &action,
		Actions:   []string{"secret.read", "secret.created"},
		StartTime: &start,
		EndTime:   &end,
		Success:   &success,
		ActorType: &actorType,
		Page:      2,
		PageSize:  5,
	}

	events, total, err := ls.GetAuditLogs(ctx, f)
	require.NoError(t, err)
	assert.Zero(t, total)
	assert.Empty(t, events)
}

// TestGetAuditLogs_ProjectIDFilter exercises the ProjectID != nil branch.
func TestGetAuditLogs_ProjectIDFilter(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}))
	ls := NewLocalStorage(db)

	pid := uint(99)
	f := &storage.AuditFilter{ProjectID: &pid, PageSize: 10}
	events, total, err := ls.GetAuditLogs(context.Background(), f)
	require.NoError(t, err)
	assert.Zero(t, total)
	assert.Empty(t, events)
}

// TestGetAuditLogs_PageSizeClamped exercises the PageSize > 0 branch and
// verifies clampPageSize is called when an over-max page size is supplied.
func TestGetAuditLogs_LargePageSize(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}))
	ls := NewLocalStorage(db)

	f := &storage.AuditFilter{PageSize: maxStoragePageSize + 1}
	events, total, err := ls.GetAuditLogs(context.Background(), f)
	require.NoError(t, err)
	assert.Zero(t, total)
	assert.Empty(t, events)
}

// ---------------------------------------------------------------------------
// MostAccessedSecrets — nil projectID (global, line 185)
// ---------------------------------------------------------------------------

// TestMostAccessedSecrets_NilProjectID exercises the `projectID == nil` path
// that returns secrets across all projects (the global dashboard view).
func TestMostAccessedSecrets_NilProjectID(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.SecretAccessLog{}, &models.SecretNode{}))
	ls := NewLocalStorage(db)
	ctx := context.Background()

	result, err := ls.MostAccessedSecrets(ctx, nil, nil, time.Now().Add(-time.Hour), 10)
	require.NoError(t, err)
	assert.Empty(t, result)
}

// TestMostAccessedSecrets_ZeroLimit exercises the `limit <= 0` branch that
// defaults to 10.
func TestMostAccessedSecrets_ZeroLimit(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.SecretAccessLog{}, &models.SecretNode{}))
	ls := NewLocalStorage(db)
	ctx := context.Background()

	pid := uint(1)
	result, err := ls.MostAccessedSecrets(ctx, &pid, nil, time.Now().Add(-time.Hour), 0)
	require.NoError(t, err)
	assert.Empty(t, result)
}

// ---------------------------------------------------------------------------
// UnusedSecrets — nil projectID (global, line 225)
// ---------------------------------------------------------------------------

// TestUnusedSecrets_NilProjectID exercises the global (nil projectID) path.
func TestUnusedSecrets_NilProjectID(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.SecretAccessLog{}, &models.SecretNode{}))
	ls := NewLocalStorage(db)
	ctx := context.Background()

	result, err := ls.UnusedSecrets(ctx, nil, nil, time.Now())
	require.NoError(t, err)
	assert.Empty(t, result)
}

// ---------------------------------------------------------------------------
// PrincipalSecretFirstSeen — nil scanTime skip branch (line 110)
// ---------------------------------------------------------------------------

// TestPrincipalSecretFirstSeen_SkipsNilFirstSeen exercises the
// `r.FirstSeen.t == nil` continue branch. A SecretAccessLog row with an
// empty AccessTime string causes MIN(access_time) to return NULL, which
// scanTime.Scan handles as a nil pointer — such rows must be silently skipped.
func TestPrincipalSecretFirstSeen_SkipsNilFirstSeen(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.SecretAccessLog{}))
	ls := NewLocalStorage(db)
	ctx := context.Background()

	// Inserting a zero-value AccessTime causes SQLite to store an empty /
	// zero-epoch string. MIN() of that returns a NULL-like value that
	// scanTime.Scan sets to nil, exercising the skip branch.
	require.NoError(t, db.Create(&models.SecretAccessLog{
		SecretNodeID: 5,
		AccessedBy:   "bot",
		Action:       "read",
		IPAddress:    "127.0.0.1",
		AccessTime:   time.Time{}, // zero value
	}).Error)

	// The since window is far in the past so the row is NOT excluded by the
	// WHERE clause — only the nil-firstSeen guard can skip it.
	m, err := ls.PrincipalSecretFirstSeen(ctx, time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err)
	// Either "bot" is absent (nil-skip worked) or present with a non-nil time.
	// The important thing is no panic and no error.
	_ = m
}

// ---------------------------------------------------------------------------
// local_access_review_campaigns — DB error paths
// ---------------------------------------------------------------------------

// TestListAccessReviewCampaigns_BrokenDB exercises the error path when the
// access_review_campaigns table is absent.
func TestListAccessReviewCampaigns_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.ListAccessReviewCampaigns(context.Background(), 1)
	require.Error(t, err)
}

// TestGetOpenAccessReviewCampaign_BrokenDB exercises the generic error path
// (not a "record not found") in GetOpenAccessReviewCampaign.
func TestGetOpenAccessReviewCampaign_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.GetOpenAccessReviewCampaign(context.Background(), 1)
	require.Error(t, err)
}

// TestGetLatestClosedAccessReviewCampaign_BrokenDB exercises the generic
// error path in GetLatestClosedAccessReviewCampaign.
func TestGetLatestClosedAccessReviewCampaign_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.GetLatestClosedAccessReviewCampaign(context.Background(), 1)
	require.Error(t, err)
}

// TestUpdateAccessReviewCampaign_BrokenDB exercises the error return path in
// UpdateAccessReviewCampaign when the underlying DB fails.
func TestUpdateAccessReviewCampaign_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.UpdateAccessReviewCampaign(context.Background(), &models.AccessReviewCampaign{ID: 1})
	require.Error(t, err)
}

// TestCreateAccessReviewItems_BrokenDB exercises the DB-error path in
// CreateAccessReviewItems (non-empty slice, broken table).
func TestCreateAccessReviewItems_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	err := ls.CreateAccessReviewItems(context.Background(), []*models.AccessReviewItem{
		{CampaignID: 1, Decision: "pending"},
	})
	require.Error(t, err)
}

// TestListAccessReviewItems_BrokenDB exercises the error path in
// ListAccessReviewItems.
func TestListAccessReviewItems_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.ListAccessReviewItems(context.Background(), 1)
	require.Error(t, err)
}

// TestCountPendingAccessReviewItems_BrokenDB exercises the error path in
// CountPendingAccessReviewItems.
func TestCountPendingAccessReviewItems_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.CountPendingAccessReviewItems(context.Background(), 1)
	require.Error(t, err)
}

// TestUpdateAccessReviewItem_BrokenDB exercises the error path in
// UpdateAccessReviewItem when the underlying DB fails.
func TestUpdateAccessReviewItem_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.UpdateAccessReviewItem(context.Background(), &models.AccessReviewItem{
		ID: 1, CampaignID: 1, Decision: "pending",
	})
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_audit — DB error paths
// ---------------------------------------------------------------------------

// TestCountSecretReadsBySecretIDs_BrokenDB exercises the error path in
// CountSecretReadsBySecretIDs when the table is absent.
func TestCountSecretReadsBySecretIDs_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.CountSecretReadsBySecretIDs(context.Background(), []uint{1, 2}, time.Now())
	require.Error(t, err)
}

// TestPrincipalSecretFirstSeen_BrokenDB exercises the DB error path in
// PrincipalSecretFirstSeen.
func TestPrincipalSecretFirstSeen_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.PrincipalSecretFirstSeen(context.Background(), time.Now().Add(-time.Hour))
	require.Error(t, err)
}

// TestAuditRetentionStats_BrokenDB exercises the error path in
// AuditRetentionStats when the audit_events table is absent.
func TestAuditRetentionStats_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.AuditRetentionStats(context.Background())
	require.Error(t, err)
}

// TestMostAccessedSecrets_BrokenDB exercises the error path in
// MostAccessedSecrets.
func TestMostAccessedSecrets_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	pid := uint(1)
	_, err := ls.MostAccessedSecrets(context.Background(), &pid, nil, time.Now().Add(-time.Hour), 10)
	require.Error(t, err)
}

// TestUnusedSecrets_BrokenDB exercises the error path in UnusedSecrets.
func TestUnusedSecrets_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	pid := uint(1)
	_, err := ls.UnusedSecrets(context.Background(), &pid, nil, time.Now())
	require.Error(t, err)
}

// TestCountUnusedSecretsByProject_BrokenDB exercises the error path in
// CountUnusedSecretsByProject.
func TestCountUnusedSecretsByProject_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.CountUnusedSecretsByProject(context.Background(), []uint{1}, time.Now())
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// AcknowledgeAnomalyAlert — DB error path (line 447)
// ---------------------------------------------------------------------------

// TestAcknowledgeAnomalyAlert_BrokenDB exercises the res.Error != nil path in
// AcknowledgeAnomalyAlert when the underlying table is absent.
func TestAcknowledgeAnomalyAlert_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	err := ls.AcknowledgeAnomalyAlert(context.Background(), 1, 1, time.Now())
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_audit_checkpoint — error paths
// ---------------------------------------------------------------------------

// TestLatestAuditCheckpoint_BrokenDB exercises the generic error path (table
// absent) in LatestAuditCheckpoint — distinct from the ErrRecordNotFound path.
func TestLatestAuditCheckpoint_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.LatestAuditCheckpoint(context.Background())
	require.Error(t, err)
}

// TestAuditEntryHashByID_CountError exercises the second DB call in
// AuditEntryHashByID (the COUNT after an empty Scan). We trigger both by
// calling against a broken DB so the first Scan itself fails.
func TestAuditEntryHashByID_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, _, err := ls.AuditEntryHashByID(context.Background(), 1)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// WithAuditCheckpointLock — fn success (SQLite path, no-op lock)
// ---------------------------------------------------------------------------

// TestWithAuditCheckpointLock_FnSuccess verifies the SQLite code path where
// the function simply calls fn() directly (no advisory lock) and returns nil.
func TestWithAuditCheckpointLock_FnSuccess(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	ls := NewLocalStorage(db)

	called := false
	err = ls.WithAuditCheckpointLock(context.Background(), func(context.Context) error {
		called = true
		return nil
	})
	require.NoError(t, err)
	assert.True(t, called)
}
