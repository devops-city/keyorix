// audit_chain_migrate.go — one-time re-encoding of the audit hash chain
// (ADR-029) after computeAuditEntryHash's length-prefixed-encoding fix, a
// breaking hash-format change (see local_audit_chain.go's doc comment for
// why the old NUL-delimited encoding was non-injective and had to change).
//
// This is deliberately an operator-triggered maintenance operation, not
// something that runs automatically at startup or on a schedule: rewriting
// every historical row of the one dataset whose entire purpose is tamper
// evidence is exactly the kind of change that should happen with an operator
// watching, during a maintenance window, not silently on the next deploy.
package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// MigrateAuditChainEncoding re-derives entry_hash/prev_hash for every chained
// audit_events row under the current hash encoding. See
// storage.Storage.MigrateAuditChainEncoding's doc for the full contract,
// including why the caller MUST ensure no other process is concurrently
// writing to this database's audit_events table for the duration of a
// non-dry-run call (stop the server, or run during a maintenance window —
// this call's own transaction only protects against concurrent writes
// through this SAME storage backend's LogAuditEvent path).
//
// dryRun computes and returns the result WITHOUT persisting anything.
//
// On a real (non-dry-run) run: if a retention-anchored row was migrated, the
// anchor is re-signed and persisted under the row's newly computed
// entry_hash (its PrevHash is unchanged — it represents an already-purged
// predecessor that cannot be recomputed under any encoding). A new audit
// event recording the migration is then appended, chained under the new
// encoding — becoming the chain's fresh, self-consistent head.
func (c *KeyorixCore) MigrateAuditChainEncoding(ctx context.Context, actorID uint, dryRun bool) (*storage.AuditChainMigrationResult, error) {
	anchor, err := c.loadAuditRetentionAnchor(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load audit chain re-anchor: %w", err)
	}

	result, err := c.storage.MigrateAuditChainEncoding(ctx, dryRun, anchor)
	if err != nil {
		return nil, fmt.Errorf("failed to migrate audit chain encoding: %w", err)
	}
	if dryRun {
		// No audit event on a dry run (F5, audit-completeness campaign):
		// confirmed intentional, not a gap — the dry run persists nothing and
		// has no effect to record, and TestMigrateAuditChainEncoding_Core_
		// DryRunPersistsNothing already asserts zero "audit.chain_migrated"
		// events after a dry-run call. Only a real run appends one, below.
		return result, nil
	}

	if result.AnchorRowID != 0 {
		if err := c.persistAuditRetentionAnchor(ctx, c.storage, result.AnchorRowID, anchor.PrevHash, result.AnchorNewEntryHash, anchor.PurgedEvents); err != nil {
			return nil, fmt.Errorf(
				"audit chain rows were migrated successfully, but re-signing the retention anchor failed (%w) — "+
					"re-run the migration to retry; row hashes are already correct and re-running is safe", err)
		}
	}

	c.writeAuditEventFull(ctx, "audit.chain_migrated", &actorID, nil, nil, "",
		fmt.Sprintf("audit hash-chain re-encoded: %d rows migrated, %d unchained legacy rows skipped, new head id %d",
			result.RowsMigrated, result.UnchainedRowsSkipped, result.HeadID))

	return result, nil
}
