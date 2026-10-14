// local_parent_liveness.go — the child-write side of the "a grant, share, lease or
// environment never survives under a deleted parent" invariant (INV-STORE-21).
package store

import (
	"context"
	"fmt"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// lockLiveParent re-reads the parent row matching where/args inside tx and reports
// whether it still exists (live). On Postgres it takes SELECT ... FOR SHARE on that
// row, so it serializes against the parent's delete cascade, which UPDATEs (and
// therefore row-locks) the parent row before it sweeps the children. SQLite has no
// row lock, so the clause is omitted there and the transaction alone serializes it
// (SQLite is always single-process — same split as LockMachineIdentityForUpdate).
//
// Callers MUST call this AFTER their own child write, inside the same transaction,
// and roll back when it returns false. Write-then-check is what makes this sound
// under READ COMMITTED, in every interleaving with a cascade that locks the parent
// row first:
//   - the cascade locked the parent first: this read blocks until the cascade
//     commits, then sees the parent deleted (Postgres re-checks the WHERE against the
//     committed row version), and the caller rolls its child write back;
//   - this read locked the parent first: the cascade's parent UPDATE blocks until
//     this transaction commits, so every later cascade statement (a fresh snapshot
//     under READ COMMITTED) sees the committed child row and sweeps it.
//
// Checking BEFORE the write instead is not enough: a cascade that runs entirely
// between the check and the write never sees the child, and the child commits under
// a deleted parent. What this does NOT cover: a delete path that sweeps the children
// before it touches (and so locks) the parent row — every such cascade must lock the
// parent row first for this to hold.
func lockLiveParent(tx *gorm.DB, model any, where string, args ...any) (bool, error) {
	q := tx.Model(model).Where(where, args...)
	if tx.Dialector.Name() == "postgres" {
		q = q.Clauses(clause.Locking{Strength: "SHARE"})
	}
	var ids []uint
	if err := q.Limit(1).Pluck("id", &ids).Error; err != nil {
		return false, fmt.Errorf("failed to re-check parent liveness: %w", err)
	}
	return len(ids) == 1, nil
}

// LockLiveProject is lockLiveParent specialised to a project, exported on
// Storage so a core-layer caller already inside WithTransaction can apply the
// same write-then-check it gives store-internal callers — see the interface
// doc for the ordering contract, and lockLiveParent's own doc for why
// write-then-check is what makes it sound.
//
// ls.db is the transaction-scoped handle when this is reached through the
// Storage WithTransaction hands fn (local_transaction.go passes db: tx), which
// is what keeps the FOR SHARE held across the caller's own write. On a
// non-transactional LocalStorage the answer is still correct but guarantees
// nothing, since the lock releases with the autocommit statement.
func (ls *LocalStorage) LockLiveProject(ctx context.Context, projectID uint) (bool, error) {
	return lockLiveParent(ls.db.WithContext(ctx), &models.Project{}, "id = ?", projectID)
}
