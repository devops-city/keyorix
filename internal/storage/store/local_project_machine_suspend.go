// local_project_machine_suspend.go — the machine-identity step of the project
// soft-delete / restore cascade (#3433).
//
// Decision (2026-10-17, option a): soft-deleting a project suspends the machine
// identities whose only live roles are in that project, and restoring it re-activates
// exactly those. Before this, a machine token of a soft-deleted project kept
// authenticating (AUTHZ-WALKS-HTTP-1's dead-credential walk).
//
// Both methods run inside the caller's transaction (core.DeleteProject /
// core.RestoreProject, which also write one audit event per identity in it). Both
// row-lock the project first, unscoped, exactly as deleteProjectCascade and
// RestoreProject do, then row-lock the identities they change (Postgres FOR UPDATE;
// SQLite's BEGIN IMMEDIATE already serializes the whole transaction), so the set
// they return is the set they wrote.
//
// The suspension marker is copied from projects.deleted_at by the UPDATE itself, not
// round-tripped through Go, so the restore's equality test compares two copies of the
// same stored value on both backends.
package store

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// machineIdentityStateSuspended mirrors core.MachineSuspended (see
// machineIdentityStateActive for why the store keeps its own copy).
const machineIdentityStateSuspended = "suspended"

// sqlProjectDeletedAt is the deleted_at of the project bound to its one argument.
const sqlProjectDeletedAt = "(SELECT deleted_at FROM projects WHERE id = ?)"

// lockSoftDeletedProject row-locks project id regardless of deleted_at (the same
// unscoped FOR UPDATE lockProjectRowForCascade and RestoreProject take) and refuses
// unless the locked row is soft-deleted.
func lockSoftDeletedProject(tx *gorm.DB, id uint) error {
	q := tx.Unscoped().Model(&models.Project{})
	if tx.Dialector.Name() == "postgres" {
		q = q.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var deletedAt []gorm.DeletedAt
	if err := q.Where(sqlWhereID, id).Limit(1).Pluck("deleted_at", &deletedAt).Error; err != nil {
		return fmt.Errorf("failed to lock project: %w", err)
	}
	if len(deletedAt) == 0 || !deletedAt[0].Valid {
		// RestoreProject's own wording: the restore path reaches this first.
		return fmt.Errorf("project not found or not deleted")
	}
	return nil
}

// lockMachineIdentityIDs runs q (a query on machine_identities) with FOR UPDATE on
// Postgres and returns the matching ids in id order.
func lockMachineIdentityIDs(tx, q *gorm.DB) ([]uint, error) {
	if tx.Dialector.Name() == "postgres" {
		q = q.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var ids []uint
	if err := q.Order("id").Pluck("id", &ids).Error; err != nil {
		return nil, err
	}
	return ids, nil
}

func machineIdentitiesByID(tx *gorm.DB, ids []uint) ([]*models.MachineIdentity, error) {
	var rows []*models.MachineIdentity
	if err := tx.Where("id IN ?", ids).Order("id").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("failed to re-read machine identities: %w", err)
	}
	return rows, nil
}

// SuspendMachineIdentitiesForDeletedProject: see the storage.Storage interface doc.
//
// "Belongs to the project" is its home project OR a role row there: core only grants
// a machine role in the identity's home project, but the rule is about the rows. "A
// role elsewhere" is a role at global scope (project_id 0, which ADR-030 forbids for a
// machine but storage can hold) or in another project that exists and is not
// soft-deleted: a role in an already-deleted project confers nothing, so it does not
// keep the identity alive. Pending/suspended/revoked identities are not touched.
func (ls *LocalStorage) SuspendMachineIdentitiesForDeletedProject(ctx context.Context, id uint) ([]*models.MachineIdentity, error) {
	tx := ls.db.WithContext(ctx)
	if err := lockSoftDeletedProject(tx, id); err != nil {
		return nil, err
	}
	ids, err := lockMachineIdentityIDs(tx, tx.Model(&models.MachineIdentity{}).
		Where("state = ?", machineIdentityStateActive).
		Where("(project_id = ? OR id IN (SELECT machine_identity_id FROM machine_identity_roles WHERE project_id = ?))", id, id).
		Where(`NOT EXISTS (SELECT 1 FROM machine_identity_roles r LEFT JOIN projects p ON p.id = r.project_id
			WHERE r.machine_identity_id = machine_identities.id AND r.project_id <> ?
			AND (r.project_id = 0 OR (p.id IS NOT NULL AND p.deleted_at IS NULL)))`, id))
	if err != nil {
		return nil, fmt.Errorf("failed to list the project's machine identities: %w", err)
	}
	if len(ids) == 0 {
		return nil, nil
	}
	deletedAt := gorm.Expr(sqlProjectDeletedAt, id)
	res := tx.Model(&models.MachineIdentity{}).
		Where("id IN ? AND state = ?", ids, machineIdentityStateActive).
		UpdateColumns(map[string]any{
			"state":                        machineIdentityStateSuspended,
			"cascade_suspended_project_id": id,
			"cascade_suspended_at":         deletedAt,
			"updated_at":                   deletedAt,
		})
	if res.Error != nil {
		return nil, fmt.Errorf("failed to suspend the project's machine identities: %w", res.Error)
	}
	if res.RowsAffected != int64(len(ids)) {
		// Every row is locked above; a mismatch means the lock did not hold.
		return nil, fmt.Errorf("suspended %d of %d machine identities of project %d", res.RowsAffected, len(ids), id)
	}
	return machineIdentitiesByID(tx, ids)
}

// ReactivateMachineIdentitiesForRestoredProject: see the storage.Storage interface doc.
//
// An identity qualifies only while all of these still hold: suspended; its marker
// names this project and equals the project's CURRENT deleted_at (a marker left by an
// earlier deletion of the same project does not match); and updated_at still equals
// the marker, i.e. nothing has written the row since the cascade did. Every core
// transition clears the marker, and any write moves updated_at, which also covers a
// write by an older binary that does not know the marker columns.
func (ls *LocalStorage) ReactivateMachineIdentitiesForRestoredProject(ctx context.Context, id uint, now time.Time) ([]*models.MachineIdentity, error) {
	tx := ls.db.WithContext(ctx)
	if err := lockSoftDeletedProject(tx, id); err != nil {
		return nil, err
	}
	ids, err := lockMachineIdentityIDs(tx, tx.Model(&models.MachineIdentity{}).
		Where("state = ? AND cascade_suspended_project_id = ?", machineIdentityStateSuspended, id).
		Where("cascade_suspended_at = "+sqlProjectDeletedAt, id).
		Where("updated_at = cascade_suspended_at"))
	if err != nil {
		return nil, fmt.Errorf("failed to list the project's cascade-suspended machine identities: %w", err)
	}
	if len(ids) == 0 {
		return nil, nil
	}
	res := tx.Model(&models.MachineIdentity{}).
		Where("id IN ? AND state = ?", ids, machineIdentityStateSuspended).
		UpdateColumns(map[string]any{
			"state":                        machineIdentityStateActive,
			"cascade_suspended_project_id": 0,
			"cascade_suspended_at":         nil,
			"updated_at":                   now,
		})
	if res.Error != nil {
		return nil, fmt.Errorf("failed to re-activate the project's machine identities: %w", res.Error)
	}
	if res.RowsAffected != int64(len(ids)) {
		return nil, fmt.Errorf("re-activated %d of %d machine identities of project %d", res.RowsAffected, len(ids), id)
	}
	return machineIdentitiesByID(tx, ids)
}
