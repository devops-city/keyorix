// local_audit_chain_golden_test.go — PERF-FIX-1: the audit chain a fixed input
// produces is pinned as bytes. The digest below was recorded on main before the
// Postgres group commit moved to two pipelined flights, so any change to what is
// hashed, in which order, or how rows link turns this red on either dialect.
package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// goldenAuditChainDigest is SHA-256 over "prev_hash entry_hash\n" for every
// row runGoldenAuditChain writes, in id order.
const goldenAuditChainDigest = "65830cac2f442c3f04a2ee192e5349cb4fd3a5cf749330cf0bdc47dba0374111"

// runGoldenAuditChain writes a fixed sequence through the batch committer (a
// genesis batch, a full-size batch, a one-item batch) and through the public
// entry point, then compares the stored chain with the golden digest.
func runGoldenAuditChain(t *testing.T, newStore func(*testing.T) *LocalStorage) {
	ctx := context.Background()
	ls := newStore(t)

	for _, b := range [][]*auditBatchItem{
		buildMultiRowBatch(3, "golden-prefix"),
		buildMultiRowBatch(auditFlusherMaxBatch, "golden-full"),
		buildMultiRowBatch(1, "golden-one"),
	} {
		for i, err := range ls.commitAuditBatch(b) {
			require.NoError(t, err, "item %d", i)
		}
	}
	for _, item := range buildMultiRowBatch(5, "golden-public") {
		require.NoError(t, ls.LogAuditEventWithAccessLog(ctx, item.event, item.accessLog))
	}

	events, logs := loadAuditRows(t, ls)
	require.Len(t, events, 3+auditFlusherMaxBatch+1+5)
	require.NotEmpty(t, logs)
	h := sha256.New()
	for _, e := range events {
		_, _ = h.Write([]byte(e.PrevHash + " " + e.EntryHash + "\n"))
	}
	assert.Equal(t, goldenAuditChainDigest, hex.EncodeToString(h.Sum(nil)))

	v, err := ls.VerifyAuditChain(ctx, nil)
	require.NoError(t, err)
	assert.True(t, v.Valid, v.Reason)
	assert.Equal(t, int64(len(events)), v.ChainedEvents)
}

func TestAuditChain_GoldenBytes_SQLite(t *testing.T) {
	runGoldenAuditChain(t, multiRowSQLiteStore)
}

func TestAuditChain_GoldenBytes_Postgres(t *testing.T) {
	runGoldenAuditChain(t, multiRowPGStore)
}
