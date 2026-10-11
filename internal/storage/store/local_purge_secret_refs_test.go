package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// secretPurgeCascadeModels returns the models of every table the secret purge
// cascades into. A fixture that purges secrets must migrate them, as production
// (which migrates every model) does.
func secretPurgeCascadeModels() []any {
	var out []any
	seen := map[string]bool{}
	for _, c := range SecretPurgeIndirectCascades() {
		if !seen[c.Table] {
			seen[c.Table] = true
			out = append(out, c.Model)
		}
	}
	for _, c := range SecretPurgeCascades() {
		if !seen[c.Table] {
			seen[c.Table] = true
			out = append(out, c.Model)
		}
	}
	return out
}

func newSecretRefsPurgeDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	all := append([]any{&models.SecretNode{}, &models.SecretVersion{}, &models.SecretDependency{}, &models.SecretACL{},
		&models.AuditEvent{}, &models.AccessReviewItem{}, &models.AnomalyAlert{}, &models.SecretAccessLog{}}, secretPurgeCascadeModels()...)
	require.NoError(t, db.AutoMigrate(all...))
	return db
}

func countPurgeRefRows(t *testing.T, db *gorm.DB, table, where string, args ...any) int64 {
	t.Helper()
	var n int64
	require.NoError(t, db.Table(table).Unscoped().Where(where, args...).Count(&n).Error)
	return n
}

// TestPurgeDeletedSecretsBefore_RemovesEveryClassifiedReference seeds one row in
// every table that references the secret (and its version), purges the secret,
// and asserts every CASCADE row is gone, the HISTORICAL rows (audit_events,
// anomaly_alerts, secret_access_logs, access_review_items) are untouched, and
// rows of a LIVE secret survive (#3085).
func TestPurgeDeletedSecretsBefore_RemovesEveryClassifiedReference(t *testing.T) {
	db := newSecretRefsPurgeDB(t)
	ls := NewLocalStorage(db)
	ctx := context.Background()

	gone := &models.SecretNode{ProjectID: 1, EnvironmentID: 1, Name: "purge-me", IsSecret: true}
	live := &models.SecretNode{ProjectID: 1, EnvironmentID: 1, Name: "keep-me", IsSecret: true}
	require.NoError(t, db.Create(gone).Error)
	require.NoError(t, db.Create(live).Error)
	goneVer := &models.SecretVersion{SecretNodeID: gone.ID, VersionNumber: 1, EncryptedValue: []byte("x")}
	liveVer := &models.SecretVersion{SecretNodeID: live.ID, VersionNumber: 1, EncryptedValue: []byte("y")}
	require.NoError(t, db.Create(goneVer).Error)
	require.NoError(t, db.Create(liveVer).Error)

	seed := func(sec uint, ver uint) {
		s := sec
		req := &models.AccessRequest{ProjectID: 1, UserID: 1, SecretID: &s, State: "pending"}
		require.NoError(t, db.Create(req).Error)
		for _, row := range []any{
			&models.AccessRequestApproval{RequestID: req.ID, ApproverID: 1},
			&models.ShareRecord{SecretID: sec, OwnerID: 1, RecipientID: 2, Permission: "read"},
			&models.SecretTag{SecretNodeID: sec, TagID: 1},
			&models.SecretAccessSchedule{SecretNodeID: sec},
			&models.SecretMetadataHistory{SecretNodeID: sec},
			&models.SecretVersionComment{VersionID: ver, SecretID: sec, UserID: 1, Comment: "c"},
			&models.Notification{UserID: 1, SecretNodeID: &s},
			&models.AnomalyAlert{SecretNodeID: sec},
			&models.SecretAccessLog{SecretNodeID: sec, SecretVersionID: ver, Action: "read"},
			&models.AuditEvent{EventType: "secret.read", SecretNodeID: &s},
			&models.AccessReviewItem{CampaignID: 1, SecretID: sec, PrincipalType: "user", PrincipalID: 1},
		} {
			require.NoError(t, db.Create(row).Error)
		}
	}
	seed(gone.ID, goneVer.ID)
	seed(live.ID, liveVer.ID)
	// A log row keyed ONLY by the purged version (node column 0) is history too.
	require.NoError(t, db.Create(&models.SecretAccessLog{SecretVersionID: goneVer.ID, Action: "read"}).Error)
	require.NoError(t, db.Create(&models.SecretVersionComment{VersionID: goneVer.ID, SecretID: 0, UserID: 1, Comment: "v-only"}).Error)

	require.NoError(t, db.Exec("UPDATE secret_nodes SET deleted_at = ? WHERE id = ?", time.Now().Add(-48*time.Hour), gone.ID).Error)
	n, err := ls.PurgeDeletedSecretsBefore(ctx, time.Now())
	require.NoError(t, err)
	require.EqualValues(t, 1, n)

	for _, c := range SecretPurgeCascades() {
		keyed := gone.ID
		if c.Parent == PurgeParentSecretVersion {
			keyed = goneVer.ID
		}
		require.Zero(t, countPurgeRefRows(t, db, c.Table, c.Column+" = ?", keyed), "%s.%s still references the purged secret", c.Table, c.Column)
		keptKey := live.ID
		if c.Parent == PurgeParentSecretVersion {
			keptKey = liveVer.ID
		}
		require.EqualValues(t, 1, countPurgeRefRows(t, db, c.Table, c.Column+" = ?", keptKey), "%s.%s: the live secret's row must survive", c.Table, c.Column)
	}
	for _, c := range SecretPurgeIndirectCascades() {
		require.EqualValues(t, 1, countPurgeRefRows(t, db, c.Table, "1 = 1"), "%s: only the live secret's request keeps its approval", c.Table)
	}
	require.Zero(t, countPurgeRefRows(t, db, "secret_versions", "secret_node_id = ?", gone.ID))
	// The approval of the purged secret's request went with it; the live one stays.
	require.Zero(t, countPurgeRefRows(t, db, "access_request_approvals", "request_id NOT IN (SELECT id FROM access_requests)"))
	require.Zero(t, countPurgeRefRows(t, db, "secret_acls", "secret_id = ?", gone.ID))

	// Historical references are never deleted or rewritten.
	require.EqualValues(t, 1, countPurgeRefRows(t, db, "audit_events", "secret_node_id = ?", gone.ID), "audit rows must survive a purge untouched")
	require.EqualValues(t, 1, countPurgeRefRows(t, db, "access_review_items", "secret_id = ?", gone.ID), "the review snapshot must survive a purge untouched")
	require.EqualValues(t, 1, countPurgeRefRows(t, db, "anomaly_alerts", "secret_node_id = ? AND acknowledged = ?", gone.ID, false),
		"an unacknowledged anomaly alert is a live security signal and must survive a purge")
	require.EqualValues(t, 2, countPurgeRefRows(t, db, "secret_access_logs", "secret_node_id = ? OR secret_version_id = ?", gone.ID, goneVer.ID),
		"the append-only access log must survive a purge untouched")
}

// TestSecretPurgeIndirectCascades_ParentIsDerived: an indirect cascade's parent
// subquery comes from the SecretPurgeCascades entry for ParentTable, so every
// ParentTable must resolve to a secret-keyed cascade, and one that does not is an
// error rather than a silently wrong delete.
func TestSecretPurgeIndirectCascades_ParentIsDerived(t *testing.T) {
	db := newSecretRefsPurgeDB(t)
	eligible := func() *gorm.DB { return db.Model(&models.SecretNode{}).Select("id") }
	for _, c := range SecretPurgeIndirectCascades() {
		_, err := indirectParentIDs(db, c, eligible)
		require.NoError(t, err, "%s.%s: ParentTable %q must be a secret-keyed cascade", c.Table, c.Column, c.ParentTable)
	}
	bad := SecretPurgeIndirectCascade{Model: &models.AccessRequestApproval{}, Table: "access_request_approvals",
		Column: "request_id", ParentTable: "no_such_table"}
	_, err := indirectParentIDs(db, bad, eligible)
	require.Error(t, err)
}

// TestPurgeDeletedSecretsBefore_CascadeFailureRollsBackThePurge: if any cascade
// delete fails, nothing is purged (one transaction, #3085): the secret and its
// ciphertext stay, and the next sweep retries.
func TestPurgeDeletedSecretsBefore_CascadeFailureRollsBackThePurge(t *testing.T) {
	db := newSecretRefsPurgeDB(t)
	ls := NewLocalStorage(db)
	s := &models.SecretNode{ProjectID: 1, EnvironmentID: 1, Name: "purge-me", IsSecret: true}
	require.NoError(t, db.Create(s).Error)
	require.NoError(t, db.Create(&models.SecretVersion{SecretNodeID: s.ID, VersionNumber: 1, EncryptedValue: []byte("x")}).Error)
	sid := s.ID
	// Rows in tables the cascade deletes BEFORE the one that fails, so the
	// rollback is proven to undo deletes that already ran.
	req := &models.AccessRequest{ProjectID: 1, UserID: 1, SecretID: &sid, State: "pending"}
	require.NoError(t, db.Create(req).Error)
	require.NoError(t, db.Create(&models.AccessRequestApproval{RequestID: req.ID, ApproverID: 1}).Error)
	require.NoError(t, db.Create(&models.ShareRecord{SecretID: s.ID, OwnerID: 1, RecipientID: 2, Permission: "read"}).Error)
	require.NoError(t, db.Create(&models.SecretTag{SecretNodeID: s.ID, TagID: 1}).Error)
	require.NoError(t, db.Exec("UPDATE secret_nodes SET deleted_at = ? WHERE id = ?", time.Now().Add(-48*time.Hour), s.ID).Error)
	require.NoError(t, db.Migrator().DropTable("notifications"))

	_, err := ls.PurgeDeletedSecretsBefore(context.Background(), time.Now())
	require.Error(t, err)
	require.EqualValues(t, 1, countPurgeRefRows(t, db, "secret_nodes", "id = ?", s.ID))
	require.EqualValues(t, 1, countPurgeRefRows(t, db, "secret_versions", "secret_node_id = ?", s.ID))
	require.EqualValues(t, 1, countPurgeRefRows(t, db, "access_requests", "secret_id = ?", s.ID), "an earlier cascade delete must be rolled back")
	require.EqualValues(t, 1, countPurgeRefRows(t, db, "access_request_approvals", "request_id = ?", req.ID), "an earlier indirect delete must be rolled back")
	require.EqualValues(t, 1, countPurgeRefRows(t, db, "share_records", "secret_id = ?", s.ID), "an earlier cascade delete must be rolled back")
	require.EqualValues(t, 1, countPurgeRefRows(t, db, "secret_tags", "secret_node_id = ?", s.ID), "an earlier cascade delete must be rolled back")
}
