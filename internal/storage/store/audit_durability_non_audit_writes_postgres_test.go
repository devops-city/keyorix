package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
)

// TestAuditDurabilityStandard_NonAuditWritesStayDurable: at
// storage.database.audit_durability standard (ADR-112 Amendment 3, the
// PostgreSQL default) only the audit commit skips the disk-sync wait.
// Non-audit writes -- secret writes, revocations, rotations -- commit
// durably, including a business transaction that writes its own audit row.
//
// On one pooled connection (newPostgresAuditStore pins the pool to 1), after
// an audit commit that DID issue SET LOCAL synchronous_commit = off:
//   - a plain non-audit write issues no synchronous_commit statement;
//   - inside a WithTransaction business transaction that also appends an
//     audit row, SHOW synchronous_commit is still "on" right before its
//     commit, and no SET LOCAL was sent in it.
func TestAuditDurabilityStandard_NonAuditWritesStayDurable(t *testing.T) {
	ls, cap := newPostgresAuditStore(t)
	require.NoError(t, ls.db.AutoMigrate(&models.SystemMetadata{}))
	ls.SetAuditSkipDurableSync(true) // standard
	ctx := context.Background()

	var clusterDefault string
	require.NoError(t, ls.db.Raw("SHOW synchronous_commit").Scan(&clusterDefault).Error)
	require.Equal(t, "on", clusterDefault, "the test cluster must commit durably by default, or this proves nothing")

	cap.stmts = nil
	appendEvent(t, ls, "audit_durability.standard", "audit commit", time.Now().UTC())
	require.True(t, cap.saw("set local synchronous_commit = off"),
		"precondition: the audit commit must have relaxed its own commit; statements: %v", cap.stmts)

	cap.stmts = nil
	require.NoError(t, ls.SetSystemMetadata(ctx, "audit_durability_probe", "v1"))
	require.False(t, cap.saw("synchronous_commit"),
		"a non-audit write touched synchronous_commit at standard; statements: %v", cap.stmts)

	cap.stmts = nil
	var inTx string
	require.NoError(t, ls.WithTransaction(ctx, func(tx storage.Storage) error {
		if err := tx.SetSystemMetadata(ctx, "audit_durability_probe", "v2"); err != nil {
			return err
		}
		tr := true
		if err := tx.LogAuditEvent(ctx, &models.AuditEvent{
			EventType: "audit_durability.in_business_tx", Description: "audit row inside a write transaction",
			Success: &tr, EventTime: time.Now().UTC(), ActorType: "user",
		}); err != nil {
			return err
		}
		return tx.(*LocalStorage).db.Raw("SHOW synchronous_commit").Scan(&inTx).Error
	}))
	require.Equal(t, "on", inTx,
		"a write transaction carrying its own audit row would commit with synchronous_commit=%q at standard -- "+
			"the relaxation must stay on the audit chain's own transaction", inTx)
	require.False(t, cap.saw("set local synchronous_commit"),
		"a SET LOCAL reached the write transaction; statements: %v", cap.stmts)

	v, err := ls.VerifyAuditChain(ctx, nil)
	require.NoError(t, err)
	require.True(t, v.Valid, "chain must verify: reason=%q", v.Reason)
}
