// local_sharing.go — ShareRecord operations for LocalStorage.
//
// Covers: CreateShareRecord, GetShareRecord, UpdateShareRecord, DeleteShareRecord,
//
//	ListSharesBySecret, ListSharesByUser, ListSharesByOwner, ListSharesByGroup,
//	ListSharedSecrets, CheckSharePermission.
//
// Sharing logic includes soft-delete awareness (deleted_at IS NULL filters),
// group-based share resolution, and upsert behaviour on CreateShareRecord.
// For the remote (HTTP) equivalent see remote_sharing.go.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

// CreateShareRecord creates a share record, or updates the permission if one already exists.
//
// #2646/#2647: the whole upsert runs in one transaction that ends by re-checking the
// secret's liveness under lockLiveParent (FOR SHARE on Postgres), and rolls back if the
// secret is gone. Without it, a DeleteSecret committing between the GetSecret read
// below and the INSERT revoked every share it could see (#370) but not this one, which
// then committed live on the deleted secret and reactivated on RestoreSecret.
func (ls *LocalStorage) CreateShareRecord(ctx context.Context, share *models.ShareRecord) (*models.ShareRecord, error) {
	if err := models.ValidateShareRecord(share); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}
	var out *models.ShareRecord
	err := ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		created, err := createShareRecordTx(tx, share)
		if err != nil {
			return err
		}
		live, err := lockLiveParent(tx, &models.SecretNode{}, sqlWhereID, share.SecretID)
		if err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
		}
		if !live {
			return fmt.Errorf("%s", i18n.T("ErrorSecretNotFound", nil))
		}
		// #3102: the FOR SHARE above is held to commit, so the secret's owner_id read
		// here cannot change under us. createShareRecordTx compared share.OwnerID with
		// the owner it read BEFORE its write; a TransferSecretOwnership that committed
		// in between has already re-stamped the shares it could see, so this row would
		// commit stamped with the PREVIOUS owner on a secret the new owner owns, the
		// exact state the transfer exists to prevent. Re-check, and roll back (fail
		// closed) if the owner moved. A transfer that starts after the lock blocks on
		// the secret row until we commit, then re-stamps this row with the rest.
		var owners []uint
		if err := tx.Model(&models.SecretNode{}).Where(sqlWhereID, share.SecretID).
			Limit(1).Pluck("owner_id", &owners).Error; err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
		}
		if len(owners) != 1 || owners[0] != share.OwnerID {
			return fmt.Errorf("%s", i18n.T("ErrorNotAuthorized", nil))
		}
		out = created
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// createShareRecordTx is CreateShareRecord's upsert body, run against tx. The caller
// owns the transaction and the closing parent-liveness re-check.
func createShareRecordTx(tx *gorm.DB, share *models.ShareRecord) (*models.ShareRecord, error) { // NOSONAR -- cognitive complexity 25, suppress go:S3776
	var secret models.SecretNode
	if err := tx.First(&secret, share.SecretID).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}

	if secret.OwnerID != share.OwnerID {
		return nil, fmt.Errorf("%s", i18n.T("ErrorNotAuthorized", nil))
	}

	if share.IsGroup {
		var count int64
		if err := tx.Model(&models.Group{}).Where("id = ?", share.RecipientID).Count(&count).Error; err != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
		}
		if count == 0 {
			return nil, fmt.Errorf("%s", i18n.T("ErrorGroupNotFound", nil))
		}
	} else {
		var count int64
		if err := tx.Model(&models.User{}).Where("id = ?", share.RecipientID).Count(&count).Error; err != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
		}
		if count == 0 {
			return nil, fmt.Errorf("%s", i18n.T("ErrorUserNotFound", nil))
		}
	}

	var existing models.ShareRecord
	result := tx.Where(sqlWhereShareActive,
		share.SecretID, share.RecipientID, share.IsGroup).First(&existing)

	if result.Error == nil {
		existing.Permission = share.Permission
		// ExpiresAt reflects the caller's requested value verbatim (nil = permanent,
		// non-nil = time-bound), mirroring UpdateShareRecord's behaviour — a re-share
		// must be able to tighten (or clear) an existing grant's expiry, not just its
		// permission. Save writes nil as NULL.
		existing.ExpiresAt = share.ExpiresAt
		existing.UpdatedAt = time.Now()
		if err := tx.Save(&existing).Error; err != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
		}
		return &existing, nil
	} else if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), result.Error)
	}

	// The INSERT runs in a nested transaction (a SAVEPOINT): on Postgres a failed
	// statement aborts the whole enclosing transaction, so the unique-violation
	// fallback below can only read and update after rolling back to the savepoint.
	if err := tx.Transaction(func(sp *gorm.DB) error { return sp.Create(share).Error }); err != nil {
		// #136: the SELECT above and this INSERT are not atomic — a concurrent
		// CreateShareRecord for the same (secret, recipient, is_group) can race between
		// them, both miss the SELECT, and both attempt the INSERT. The partial unique
		// index on share_records (see ensureShareRecordUniqueIndex) turns the loser's
		// INSERT into a constraint violation instead of a second live duplicate row;
		// treat that specific failure as "someone else just created it" and fall back to
		// updating the row that won the race, preserving CreateShareRecord's upsert
		// contract instead of surfacing a raw constraint error to the caller.
		if isUniqueConstraintErr(err) {
			if tx.Where(sqlWhereShareActive,
				share.SecretID, share.RecipientID, share.IsGroup).First(&existing).Error == nil {
				existing.Permission = share.Permission
				existing.UpdatedAt = time.Now()
				if serr := tx.Save(&existing).Error; serr != nil {
					return nil, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), serr)
				}
				return &existing, nil
			}
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
	}
	return share, nil
}

// GetShareRecord retrieves a share record by ID.
func (ls *LocalStorage) GetShareRecord(ctx context.Context, shareID uint) (*models.ShareRecord, error) {
	var share models.ShareRecord
	if err := ls.db.First(&share, shareID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%s", i18n.T("ErrorShareNotFound", nil))
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
	}
	return &share, nil
}

// UpdateShareRecord updates the permission (and caller-resolved expiry) on an
// existing, live share record. It writes only those columns plus updated_at,
// through a conditional UPDATE that GORM scopes to deleted_at IS NULL, and
// fails closed (ErrorShareNotFound) when that matches no row — i.e. the share
// was revoked after the caller read it.
//
// Bug origin (#2648):
//
//	Introduced-by: the original GORM Save(existing) full-row write
//	Detected-by:   C-GUARD2-EXEMPT-REVIEW #2662
//	Class:         cross-replica check-then-act (stale Save upsert)
//	Severity:      high (a share whose revocation reported success is live
//	               again, with the permission the update asked for)
//	Guard:         TestCTAReview_UpdateSharePermission_vs_RevokeShare_CrossReplicaPostgres,
//	               TestUpdateSharePermission_IsColumnScoped
//
// Save is an upsert: against a concurrently revoked (soft-deleted) row its
// UPDATE ... WHERE deleted_at IS NULL matches nothing and GORM falls back to
// INSERT ... ON CONFLICT (id) DO UPDATE SET <every column>, deleted_at = NULL
// included, resurrecting the revoked share. Never persist this row with Save.
func (ls *LocalStorage) UpdateShareRecord(ctx context.Context, share *models.ShareRecord) (*models.ShareRecord, error) {
	if err := models.ValidateShareUpdate(share); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}
	existing, err := ls.GetShareRecord(ctx, share.ID)
	if err != nil {
		return nil, err
	}
	existing.Permission = share.Permission
	// ExpiresAt is caller-resolved (the core layer preserves the current value unless a
	// change was requested), so copy it through — including nil to clear a time-bound
	// share back to permanent. A map update writes the nil as NULL; it bypasses the
	// model's BeforeSave hook, so normalize to UTC here (G81, see ShareRecord.BeforeSave).
	existing.ExpiresAt = nil
	if share.ExpiresAt != nil {
		u := share.ExpiresAt.UTC()
		existing.ExpiresAt = &u
	}
	existing.UpdatedAt = time.Now()
	res := ls.db.WithContext(ctx).Model(&models.ShareRecord{}).
		Where(sqlWhereID, existing.ID).
		Updates(map[string]any{
			"permission": existing.Permission,
			"expires_at": existing.ExpiresAt,
			"updated_at": existing.UpdatedAt,
		})
	if res.Error != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), res.Error)
	}
	if res.RowsAffected != 1 {
		return nil, fmt.Errorf("%s", i18n.T("ErrorShareNotFound", nil))
	}
	return existing, nil
}

// DeleteShareRecord soft-deletes a share record. #136: a pre-existing duplicate row
// for the same (secret, recipient, is_group) — from before the unique index in
// ensureShareRecordUniqueIndex closed the create-race that produced them — would
// otherwise survive a revoke by ID, leaving access live. Delete every active row for
// that same tuple, not just shareID, so a revoke is complete regardless of how many
// duplicates accumulated.
func (ls *LocalStorage) DeleteShareRecord(ctx context.Context, shareID uint) error {
	share, err := ls.GetShareRecord(ctx, shareID)
	if err != nil {
		return err
	}
	if err := ls.db.Where(sqlWhereShareActive,
		share.SecretID, share.RecipientID, share.IsGroup).Delete(&models.ShareRecord{}).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
	}
	return nil
}

// DeleteExpiredShareRecords soft-deletes time-bound shares whose ExpiresAt is
// non-NULL and at or before the cutoff, returning the removed rows so the caller can
// audit each. Runs in a transaction so the rows it reports are exactly the rows it
// removed. Idempotent — a tick that finds nothing removes nothing.
func (ls *LocalStorage) DeleteExpiredShareRecords(ctx context.Context, before time.Time) ([]*models.ShareRecord, error) {
	// G81 (ShareRecord.ExpiresAt): normalize internally — see GetAuditLogs.
	before = before.UTC()
	var removed []*models.ShareRecord
	err := ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where(
			"expires_at IS NOT NULL AND expires_at <= ? AND deleted_at IS NULL", before,
		).Find(&removed).Error; err != nil {
			return err
		}
		if len(removed) == 0 {
			return nil
		}
		ids := make([]uint, len(removed))
		for i, s := range removed {
			ids[i] = s.ID
		}
		return tx.Where("id IN ?", ids).Delete(&models.ShareRecord{}).Error
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
	}
	return removed, nil
}

// ReassignSecretShareOwner re-stamps owner_id on every share_records row of secretID
// (#3102) — Unscoped on purpose, so expired-unswept and soft-deleted (revoked) rows are
// included: a row that ever comes back live (a restore path, a stale write) must not
// carry the previous owner as the share's owner. Writes owner_id only (no updated_at:
// the grant itself did not change), as a conditional UPDATE, never a Save — see
// UpdateShareRecord's bug-origin note on why a Save of a share row is unsafe.
//
// Core calls it inside the same WithTransaction as the secret's owner_id write.
func (ls *LocalStorage) ReassignSecretShareOwner(ctx context.Context, secretID, newOwnerID uint) (int64, error) {
	if secretID == 0 || newOwnerID == 0 {
		return 0, fmt.Errorf("%s: secret ID and new owner ID are required", i18n.T("ErrorValidation", nil))
	}
	res := ls.db.WithContext(ctx).Unscoped().Model(&models.ShareRecord{}).
		Where("secret_id = ?", secretID).
		Update("owner_id", newOwnerID)
	if res.Error != nil {
		return 0, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), res.Error)
	}
	return res.RowsAffected, nil
}

// ListSharesBySecret lists currently-active share records for a secret — soft-deleted
// AND expired (time-bound) shares are excluded, matching the expiry filter every
// authorization path (CheckSharePermission, CheckSecretPermission via activeShares)
// already applies. #402: this used to return expired shares too, so reporting/
// compliance/risk-scoring callers built on it over-counted access that no longer
// authorizes anything, even though the real permission-check path was never fooled.
func (ls *LocalStorage) ListSharesBySecret(ctx context.Context, secretID uint, now time.Time) ([]*models.ShareRecord, error) {
	var shares []*models.ShareRecord
	if err := ls.db.Where(
		"secret_id = ? AND deleted_at IS NULL AND (expires_at IS NULL OR expires_at > ?)",
		secretID, now.UTC(),
	).Limit(maxUnboundedListRows).Find(&shares).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
	}
	return shares, nil
}

// ListSharesBySecretIDs is the batch form of ListSharesBySecret: currently-active
// share records (same soft-delete/expiry filter, #402) for every secret in
// secretIDs, in one query. Used by the rotation planner's risk-scoring batch
// (#409) instead of one ListSharesBySecret call per candidate secret.
func (ls *LocalStorage) ListSharesBySecretIDs(ctx context.Context, secretIDs []uint, now time.Time) ([]*models.ShareRecord, error) {
	if len(secretIDs) == 0 {
		return nil, nil
	}
	var shares []*models.ShareRecord
	if err := ls.db.WithContext(ctx).Where(
		"secret_id IN ? AND deleted_at IS NULL AND (expires_at IS NULL OR expires_at > ?)",
		secretIDs, now.UTC(),
	).Find(&shares).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
	}
	return shares, nil
}

// ListSharesByUser lists currently-active share records where userID is the direct
// recipient. See ListSharesBySecret for why expired shares are excluded (#402).
func (ls *LocalStorage) ListSharesByUser(ctx context.Context, userID uint, now time.Time) ([]*models.ShareRecord, error) {
	var shares []*models.ShareRecord
	if err := ls.db.Where(
		"recipient_id = ? AND is_group = ? AND deleted_at IS NULL AND (expires_at IS NULL OR expires_at > ?)",
		userID, false, now.UTC(),
	).Limit(maxUnboundedListRows).Find(&shares).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
	}
	return shares, nil
}

// ListSharesByOwner lists currently-active share records created by ownerID. See
// ListSharesBySecret for why expired shares are excluded (#402) — this feeds the
// dashboard's outgoing-share count and ListSharesByUser's owned-share half, both of
// which must reflect what actually still grants access, not stale time-bound grants.
func (ls *LocalStorage) ListSharesByOwner(ctx context.Context, ownerID uint, now time.Time) ([]*models.ShareRecord, error) {
	var shares []*models.ShareRecord
	if err := ls.db.Where(
		"owner_id = ? AND deleted_at IS NULL AND (expires_at IS NULL OR expires_at > ?)",
		ownerID, now.UTC(),
	).Limit(maxUnboundedListRows).Find(&shares).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
	}
	return shares, nil
}

// ListSharesByGroup lists currently-active share records where groupID is the
// recipient. See ListSharesBySecret for why expired shares are excluded (#402).
func (ls *LocalStorage) ListSharesByGroup(ctx context.Context, groupID uint, now time.Time) ([]*models.ShareRecord, error) {
	var shares []*models.ShareRecord
	if err := ls.db.Where(
		"recipient_id = ? AND is_group = ? AND deleted_at IS NULL AND (expires_at IS NULL OR expires_at > ?)",
		groupID, true, now.UTC(),
	).Limit(maxUnboundedListRows).Find(&shares).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
	}
	return shares, nil
}

// ListSharedSecrets returns all secrets shared with userID, directly or via group membership.
func (ls *LocalStorage) ListSharedSecrets(ctx context.Context, userID uint, now time.Time) ([]*models.SecretNode, error) {
	var secrets []*models.SecretNode
	// Expired (time-bound) shares no longer authorize, so they must not surface in
	// the "shared with me" listing either — filter them the same way the auth queries do.
	// G81 (ShareRecord.ExpiresAt): normalize internally — see GetAuditLogs.
	now = now.UTC()
	// store-secret-acl-002: JOIN users ... deleted_at IS NULL mirrors the group query's
	// user-liveness guard below (and CheckSharePermission's identical direct-share
	// guard) — a soft-deleted recipient's direct ShareRecord row stays live for
	// audit/restore, so without this guard a deleted user's own "shared with me"
	// listing would keep surfacing secrets whose access CheckSharePermission already
	// denies for that same account.
	directQuery := fmt.Sprintf(`
		SELECT %s FROM secret_nodes s
		JOIN share_records sr ON s.id = sr.secret_id
		JOIN users u ON u.id = sr.recipient_id AND u.deleted_at IS NULL
		WHERE sr.recipient_id = ? AND sr.is_group = ? AND sr.deleted_at IS NULL AND s.deleted_at IS NULL
		  AND (sr.expires_at IS NULL OR sr.expires_at > ?)
		LIMIT %d
	`, modelColumns(ls.db, &models.SecretNode{}, "s"), maxUnboundedListRows)
	if err := ls.db.Raw(directQuery, userID, false, now).Scan(&secrets).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
	}

	// JOIN groups … deleted_at IS NULL: a soft-deleted group's shares grant nothing,
	// even though the share/membership rows are kept for restore.
	//
	// #G01: ug.project_id = 0 OR ug.project_id = s.project_id — a membership
	// scoped to a DIFFERENT project than the secret being listed must not
	// confer access to it. Without this, a user who is only a project-scoped
	// member of a group in project X could see secrets shared with that group
	// in every other project too (mirrors GetUserRoleIDsAt/
	// GetUserGroupRoleIDsAt's own project_id=0-OR-exact-match convention).
	groupQuery := fmt.Sprintf(`
		SELECT %s FROM secret_nodes s
		JOIN share_records sr ON s.id = sr.secret_id
		JOIN user_groups ug ON sr.recipient_id = ug.group_id
		JOIN groups g ON g.id = ug.group_id AND g.deleted_at IS NULL
		JOIN users u ON u.id = ug.user_id AND u.deleted_at IS NULL
		WHERE ug.user_id = ? AND sr.is_group = ? AND sr.deleted_at IS NULL AND s.deleted_at IS NULL
		  AND (sr.expires_at IS NULL OR sr.expires_at > ?)
		  AND (ug.project_id = 0 OR ug.project_id = s.project_id)
		LIMIT %d
	`, modelColumns(ls.db, &models.SecretNode{}, "s"), maxUnboundedListRows)
	var groupSecrets []*models.SecretNode
	if err := ls.db.Raw(groupQuery, userID, true, now).Scan(&groupSecrets).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
	}

	return append(secrets, groupSecrets...), nil
}

// permissionRank mirrors the rank convention established in
// internal/core/secret_access_list.go (read < write < owner) so that
// direct-vs-group conflict resolution here stays consistent with the "strongest
// grant wins" rule used across the codebase. Kept as a local copy — store must
// not import core (core already imports store).
var permissionRank = map[string]int{"read": 1, "write": 2, "owner": 3}

// CheckSharePermission returns the effective permission level for userID on secretID.
// Owner → "write". Direct share → share.Permission. Group share → share.Permission.
// #252: when a user has BOTH a direct share and a group share on the same secret,
// the STRONGER of the two wins — a weaker direct grant must never silently
// override a stronger group grant (or vice versa).
func (ls *LocalStorage) CheckSharePermission(ctx context.Context, secretID, userID uint, now time.Time) (string, error) {
	var secret models.SecretNode
	if err := ls.db.First(&secret, secretID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", fmt.Errorf("%s", i18n.T("ErrorSecretNotFound", nil))
		}
		return "", fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
	}

	// #136: OwnerID==0 means the secret has NO human owner (e.g. machine-created); a
	// machine actor's userID is also 0, so an unguarded equality would match every
	// ownerless secret via 0==0 and grant it owner-level "write". The core-layer
	// secretOwnedBy helper (permissions.go) already carries this guard for its own
	// callers, but this storage-layer check reimplemented the comparison independently
	// — closing it here too rather than relying solely on callers validating userID != 0.
	//
	// store-secret-acl-002: a soft-deleted (deprovisioned) owner's account row stays
	// live for audit/restore, and DeleteUser's session/token-cache invalidation runs on
	// a separate code path whose propagation isn't instantaneous across instances — so
	// the OwnerID==userID branch must independently verify the owner account is still
	// active, exactly as the group-share branch below already verifies group-member
	// liveness. Without this, a deleted owner's STRONGEST access path (owner-level
	// "write") would outlive its WEAKEST (group share), which is already denied.
	if secret.OwnerID != 0 && secret.OwnerID == userID {
		var ownerActive int64
		if err := ls.db.Model(&models.User{}).
			Where("id = ? AND deleted_at IS NULL", secret.OwnerID).
			Count(&ownerActive).Error; err != nil {
			return "", fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
		}
		if ownerActive > 0 {
			return "write", nil
		}
		// Owner account soft-deleted: fall through to the direct/group share checks
		// below instead of returning here — fail-closed, not fail-open.
	}

	// Skip expired (time-bound) shares — an expired share grants no permission.
	// G81 (ShareRecord.ExpiresAt): normalize internally — see GetAuditLogs.
	now = now.UTC()
	// store-secret-acl-002: JOIN users ... deleted_at IS NULL mirrors the group-share
	// query's user-liveness guard below — a soft-deleted recipient's direct
	// ShareRecord row stays live for audit/restore, so without this guard a deleted
	// user's direct share would keep granting access even though the equivalent
	// group-share path already denies it for a deleted group member.
	var directShare models.ShareRecord
	directQuery := fmt.Sprintf(`
		SELECT %s FROM share_records sr
		JOIN users u ON u.id = sr.recipient_id AND u.deleted_at IS NULL
		WHERE sr.secret_id = ? AND sr.recipient_id = ? AND sr.is_group = ? AND sr.deleted_at IS NULL
		  AND (sr.expires_at IS NULL OR sr.expires_at > ?)
		LIMIT 1
	`, modelColumns(ls.db, &models.ShareRecord{}, "sr"))
	dres := ls.db.Raw(directQuery, secretID, userID, false, now).Scan(&directShare)
	haveDirect := dres.Error == nil && directShare.ID != 0
	if dres.Error != nil && !errors.Is(dres.Error, gorm.ErrRecordNotFound) {
		return "", fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), dres.Error)
	}

	// #G01: ug.project_id = 0 OR ug.project_id = ? (secret.ProjectID) — a
	// membership scoped to a DIFFERENT project than this secret must not
	// confer the group's share permission on it. See ListSharedSecrets's
	// identical fix above for the full reasoning.
	var groupShare models.ShareRecord
	groupQuery := fmt.Sprintf(`
		SELECT %s FROM share_records sr
		JOIN user_groups ug ON sr.recipient_id = ug.group_id
		JOIN groups g ON g.id = ug.group_id AND g.deleted_at IS NULL
		JOIN users u ON u.id = ug.user_id AND u.deleted_at IS NULL
		WHERE sr.secret_id = ? AND ug.user_id = ? AND sr.is_group = ? AND sr.deleted_at IS NULL
		  AND (sr.expires_at IS NULL OR sr.expires_at > ?)
		  AND (ug.project_id = 0 OR ug.project_id = ?)
		LIMIT 1
	`, modelColumns(ls.db, &models.ShareRecord{}, "sr"))
	res := ls.db.Raw(groupQuery, secretID, userID, true, now, secret.ProjectID).Scan(&groupShare)
	haveGroup := res.Error == nil && groupShare.ID != 0
	if res.Error != nil && !errors.Is(res.Error, gorm.ErrRecordNotFound) {
		return "", fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), res.Error)
	}

	switch {
	case haveDirect && haveGroup:
		if permissionRank[groupShare.Permission] > permissionRank[directShare.Permission] {
			return groupShare.Permission, nil
		}
		return directShare.Permission, nil
	case haveDirect:
		return directShare.Permission, nil
	case haveGroup:
		return groupShare.Permission, nil
	}

	return "", fmt.Errorf("%s", i18n.T("ErrorNotAuthorized", nil))
}
