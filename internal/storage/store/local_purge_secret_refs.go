// local_purge_secret_refs.go — the per-column classification of every row that
// references a secret (secret_nodes) or one of its versions (secret_versions),
// and the cascade PurgeDeletedSecretsBefore derives from it (#3085).
//
// A purge hard-deletes the secret_nodes row. Any table that still points at the
// purged id is an orphan, and backupfmt's mandatory dangling-reference check
// makes `admin restore` refuse a backup that holds one. Every referencing
// column therefore has exactly one answer, recorded here or in backupfmt:
//
//   - CASCADE: the purge deletes the referencing rows in the same transaction
//     (SecretPurgeCascades, plus SecretPurgeIndirectCascades for the children
//     of a cascaded table).
//   - HISTORICAL: the row is a record (audit trail, security signal, access
//     log, review snapshot) with its own lifetime and is kept;
//     backupfmt.HistoricalReferences names those columns, with a reason each,
//     and the restore check skips exactly them. A purge never shortens a
//     retention window another table owns: anomaly_alerts (kept while
//     unacknowledged) and secret_access_logs (append-only, exported) are
//     historical for that reason.
//
// TestSecretReferencesAreClassified (backupfmt/purge_refs_guard_test.go) fails when a
// new column referencing a secret is in neither list, so the next table cannot
// silently orphan.
package store

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// SecretPurgeParent names which purged id a cascaded column holds.
type SecretPurgeParent string

const (
	// PurgeParentSecretNode: the column holds a secret_nodes.id.
	PurgeParentSecretNode SecretPurgeParent = "secret_nodes"
	// PurgeParentSecretVersion: the column holds a secret_versions.id.
	PurgeParentSecretVersion SecretPurgeParent = "secret_versions"
)

// SecretPurgeCascade is one referencing column PurgeDeletedSecretsBefore
// deletes the rows of.
type SecretPurgeCascade struct {
	Model  any
	Table  string
	Column string
	Parent SecretPurgeParent
}

// SecretPurgeIndirectCascade is a table that references a CASCADED table (not
// the secret itself): its rows go before the rows they reference.
type SecretPurgeIndirectCascade struct {
	Model       any
	Table       string
	Column      string
	ParentTable string // the cascaded table the column references
}

// SecretPurgeCascades lists every mutable table whose rows reference a purged
// secret or version and are deleted with it. Order is the deletion order.
//
// access_requests (and, through them, access_request_approvals) are cascaded on
// purpose: a request for a secret that no longer exists can never be approved,
// and backup restore keeps refusing a dangling access_requests.secret_id. The
// approve/reject decisions themselves are audit events, which stay.
func SecretPurgeCascades() []SecretPurgeCascade {
	return []SecretPurgeCascade{
		{&models.AccessRequest{}, "access_requests", "secret_id", PurgeParentSecretNode},
		{&models.ShareRecord{}, "share_records", "secret_id", PurgeParentSecretNode},
		{&models.SecretTag{}, "secret_tags", "secret_node_id", PurgeParentSecretNode},
		{&models.SecretAccessSchedule{}, "secret_access_schedules", "secret_node_id", PurgeParentSecretNode},
		{&models.SecretMetadataHistory{}, "secret_metadata_histories", "secret_node_id", PurgeParentSecretNode},
		{&models.SecretVersionComment{}, "secret_version_comments", "secret_id", PurgeParentSecretNode},
		{&models.Notification{}, "notifications", "secret_node_id", PurgeParentSecretNode},
		// Version-keyed: must run before secret_versions is deleted.
		{&models.SecretVersionComment{}, "secret_version_comments", "version_id", PurgeParentSecretVersion},
	}
}

// SecretPurgeIndirectCascades lists the children of cascaded tables. They are
// deleted BEFORE the cascades above (children first).
func SecretPurgeIndirectCascades() []SecretPurgeIndirectCascade {
	return []SecretPurgeIndirectCascade{
		{&models.AccessRequestApproval{}, "access_request_approvals", "request_id", "access_requests"},
	}
}

// SecretPurgeStatementCount is the number of delete statements the cascade
// issues (indirect + direct), for tests that count statements.
func SecretPurgeStatementCount() int {
	return len(SecretPurgeIndirectCascades()) + len(SecretPurgeCascades())
}

// indirectParentIDs returns the subquery of ids, in c.ParentTable, that the
// direct cascade below deletes: derived from the SecretPurgeCascades entry for
// that table rather than hard-coded, so an indirect cascade follows its parent.
func indirectParentIDs(tx *gorm.DB, c SecretPurgeIndirectCascade, eligible func() *gorm.DB) (*gorm.DB, error) {
	for _, d := range SecretPurgeCascades() {
		if d.Table == c.ParentTable && d.Parent == PurgeParentSecretNode {
			return tx.Unscoped().Table(d.Table).Select("id").Where(d.Column+" IN (?)", eligible()), nil
		}
	}
	return nil, fmt.Errorf("secret purge: indirect cascade %s.%s names parent table %q, which is not a secret-keyed cascade",
		c.Table, c.Column, c.ParentTable)
}

// purgeSecretReferences deletes every row classified CASCADE above. eligible
// returns a fresh subquery of the secret_nodes ids being purged (a *gorm.DB is
// stateful, so one per use).
func purgeSecretReferences(tx *gorm.DB, eligible func() *gorm.DB) error {
	for _, c := range SecretPurgeIndirectCascades() {
		parents, err := indirectParentIDs(tx, c, eligible)
		if err != nil {
			return err
		}
		if e := tx.Unscoped().Where(c.Column+" IN (?)", parents).Delete(c.Model).Error; e != nil {
			return e
		}
	}
	for _, c := range SecretPurgeCascades() {
		var ids *gorm.DB
		switch c.Parent {
		case PurgeParentSecretVersion:
			ids = tx.Model(&models.SecretVersion{}).Select("id").Where("secret_node_id IN (?)", eligible())
		default:
			ids = eligible()
		}
		// ShareRecord carries its own deleted_at: Unscoped makes this a hard delete.
		if e := tx.Unscoped().Where(c.Column+" IN (?)", ids).Delete(c.Model).Error; e != nil {
			return e
		}
	}
	return nil
}
