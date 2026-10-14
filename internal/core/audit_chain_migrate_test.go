// audit_chain_migrate_test.go — regression coverage for
// KeyorixCore.MigrateAuditChainEncoding (ADR-029 hash-format migration).
package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// relegacyChain rewrites EVERY chained event in the database so it carries a
// GENUINE pre-#1452 hash, in id order, seeded from the first chained row's own
// stored prev_hash (genesis normally, the anchor value after a retention purge)
// so the chain linkage stays intact. Whole-database, because that is the real
// scenario: an install that predates the encoding change has no current-encoded
// rows at all.
//
// The fixture this replaces wrote the literal string "legacy-"+hash[:16] — not
// a hash under any encoding this code has ever used. Every migration test built
// on it therefore proved only that MigrateAuditChainEncoding overwrites
// arbitrary bytes, which is precisely the unconditional-overwrite behaviour
// that let it re-hash a tampered row as readily as a stale one: the tests
// asserted the defect as the expectation. With real legacy hashes these tests
// exercise the upgrade the function exists for, and pass the pre-flight check
// that now refuses rows matching neither encoding.
func relegacyChain(t *testing.T, db *gorm.DB) {
	t.Helper()
	var events []models.AuditEvent
	require.NoError(t, db.Order("id ASC").Find(&events).Error)

	var prev string
	started := false
	for i := range events {
		e := events[i]
		if e.EntryHash == "" {
			continue // leading unchained (pre-ADR-029) rows, as the real walker skips them
		}
		if !started {
			prev = e.PrevHash // genesis normally; the anchor value after a purge
			started = true
		}
		e.PrevHash = prev
		entry := store.ComputeAuditEntryHashPre1452(&e, prev)
		require.NoError(t, db.Model(&models.AuditEvent{}).Where("id = ?", e.ID).
			Updates(map[string]any{"prev_hash": prev, "entry_hash": entry}).Error)
		prev = entry
	}
	require.True(t, started, "fixture must contain at least one chained event to re-encode")
}

func TestMigrateAuditChainEncoding_Core_AppliesAndVerifiesAfterward(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db, fixed := newReanchorTestCore(t)

	logChainedEvent(t, c, "secret.read", fixed.AddDate(0, 0, -3))
	logChainedEvent(t, c, "secret.updated", fixed.AddDate(0, 0, -2))
	logChainedEvent(t, c, "secret.deleted", fixed.AddDate(0, 0, -1))

	// Genuine pre-#1452 hashes — see relegacyChain.
	relegacyChain(t, db)

	v, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.False(t, v.Valid, "sanity: legacy-encoded rows must not verify before migration")

	result, err := c.MigrateAuditChainEncoding(ctx, 1, false)
	require.NoError(t, err)
	assert.Equal(t, int64(3), result.RowsMigrated)
	assert.NotEmpty(t, result.HeadHash)

	v2, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.True(t, v2.Valid, "chain must verify after a real migration run: %s", v2.Reason)

	// A completion event was appended, chained under the new encoding —
	// becoming the chain's fresh head.
	var head models.AuditEvent
	require.NoError(t, db.Order("id DESC").First(&head).Error)
	assert.Equal(t, "audit.chain_migrated", head.EventType)
	assert.Equal(t, head.ID, v2.HeadID, "the completion event itself must verify as the new head")
}

func TestMigrateAuditChainEncoding_Core_DryRunPersistsNothing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db, fixed := newReanchorTestCore(t)

	e1 := logChainedEvent(t, c, "secret.read", fixed.AddDate(0, 0, -1))
	relegacyChain(t, db)

	var before models.AuditEvent
	require.NoError(t, db.First(&before, e1.ID).Error)

	result, err := c.MigrateAuditChainEncoding(ctx, 1, true)
	require.NoError(t, err)
	assert.Equal(t, int64(1), result.RowsMigrated, "dry run still reports what would change")

	var after models.AuditEvent
	require.NoError(t, db.First(&after, e1.ID).Error)
	assert.Equal(t, before.EntryHash, after.EntryHash, "dry run must not persist row changes")

	// No completion event is appended on a dry run — nothing to record.
	var count int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", "audit.chain_migrated").Count(&count).Error)
	assert.Equal(t, int64(0), count, "a dry run must not append a completion audit event")
}

// TestMigrateAuditChainEncoding_Core_ReSignsAnchorAfterPurge covers the
// interaction with a preceding retention purge: the earliest surviving row
// carries an anchor (its real predecessor was purged). A real migration run
// must re-sign that anchor with the row's newly computed hash so
// VerifyAuditChain (which authenticates the anchor against the signing key)
// keeps accepting it after the migration.
func TestMigrateAuditChainEncoding_Core_ReSignsAnchorAfterPurge(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db, fixed := newReanchorTestCore(t)

	for i := range 3 {
		logChainedEvent(t, c, "secret.read", fixed.AddDate(0, 0, -(40+i)))
	}
	for range 2 {
		logChainedEvent(t, c, "secret.updated", fixed.AddDate(0, 0, -1))
	}

	_, err := c.PurgeAuditLogs(ctx, AuditLogRetentionConfig{RetentionDays: 30})
	require.NoError(t, err)

	v, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	require.True(t, v.Valid, "sanity: purge alone must not break verification")

	// Simulate the anchored (earliest surviving) row being legacy-encoded:
	// rewrite its entry_hash directly (its prev_hash — the anchor's PrevHash —
	// must stay untouched, since it represents an already-purged predecessor).
	var earliest models.AuditEvent
	require.NoError(t, db.Where("event_type != ?", "system.audit_purge").Order("id ASC").First(&earliest).Error)
	relegacyChain(t, db)

	v2, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.False(t, v2.Valid, "sanity: legacy-encoded anchored row must not verify before migration")

	result, err := c.MigrateAuditChainEncoding(ctx, 1, false)
	require.NoError(t, err)
	require.Equal(t, earliest.ID, result.AnchorRowID, "the anchored row must be reported for re-signing")
	assert.NotEmpty(t, result.AnchorNewEntryHash)

	v3, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.True(t, v3.Valid, "chain must verify after the anchor is re-signed by the migration: %s", v3.Reason)
}
