package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// appendLegacyEncodedEvent inserts a row already stored with a hash chain,
// then rewrites its prev_hash/entry_hash to simulate a row that was chained
// under a DIFFERENT (older) encoding than computeAuditEntryHash currently
// produces — exactly the state MigrateAuditChainEncoding exists to repair.
func appendLegacyEncodedEvent(t *testing.T, ls *LocalStorage, desc string, at time.Time, prevHash string) *models.AuditEvent {
	t.Helper()
	e := appendEvent(t, ls, "secret.read", desc, at)
	// A REAL pre-#1452 hash, derived by the frozen legacy encoder, not a
	// placeholder. This used to be `"legacy-" + e.EntryHash[:16]` -- a literal
	// string that is not a hash under any encoding this code has ever used. Every
	// test below therefore proved only that MigrateAuditChainEncoding overwrites
	// arbitrary bytes, which was precisely the unconditional-overwrite behaviour
	// that let it re-hash a tampered row as readily as a stale one. The fixture
	// asserted the defect as the expectation. With a genuine legacy hash the same
	// tests now exercise the real upgrade these functions exist for.
	e.PrevHash = prevHash
	legacyEntryHash := ComputeAuditEntryHashPre1452(e, prevHash)
	require.NoError(t, ls.db.Model(&models.AuditEvent{}).Where("id = ?", e.ID).
		Updates(map[string]any{"prev_hash": prevHash, "entry_hash": legacyEntryHash}).Error)
	e.EntryHash = legacyEntryHash
	return e
}

func TestMigrateAuditChainEncoding_RechainsUnderCurrentEncoding(t *testing.T) {
	ls := newAuditChainTestStore(t)
	base := time.Now().UTC()

	e1 := appendLegacyEncodedEvent(t, ls, "first", base, auditGenesisHash)
	e2 := appendLegacyEncodedEvent(t, ls, "second", base.Add(time.Second), e1.EntryHash)
	e3 := appendLegacyEncodedEvent(t, ls, "third", base.Add(2*time.Second), e2.EntryHash)

	// Sanity: as stored, the chain does NOT verify under the current encoding.
	v, err := ls.VerifyAuditChain(context.Background(), nil)
	require.NoError(t, err)
	assert.False(t, v.Valid, "legacy-encoded rows must not verify under the current encoding before migration")

	result, err := ls.MigrateAuditChainEncoding(context.Background(), false, nil)
	require.NoError(t, err)
	assert.Equal(t, int64(3), result.RowsMigrated)
	assert.Equal(t, int64(0), result.UnchainedRowsSkipped)
	assert.Equal(t, e3.ID, result.HeadID)
	assert.NotEmpty(t, result.HeadHash)
	assert.Equal(t, uint(0), result.AnchorRowID, "no anchor supplied, none should be reported")

	v2, err := ls.VerifyAuditChain(context.Background(), nil)
	require.NoError(t, err)
	assert.True(t, v2.Valid, "chain must verify under the current encoding after migration: %s", v2.Reason)
	assert.Equal(t, int64(3), v2.ChainedEvents)
	assert.Equal(t, result.HeadHash, v2.HeadHash)
	assert.Equal(t, result.HeadID, v2.HeadID)
}

func TestMigrateAuditChainEncoding_DryRunMakesNoChanges(t *testing.T) {
	ls := newAuditChainTestStore(t)
	base := time.Now().UTC()

	e1 := appendLegacyEncodedEvent(t, ls, "first", base, auditGenesisHash)
	e2 := appendLegacyEncodedEvent(t, ls, "second", base.Add(time.Second), e1.EntryHash)

	result, err := ls.MigrateAuditChainEncoding(context.Background(), true, nil)
	require.NoError(t, err)
	assert.Equal(t, int64(2), result.RowsMigrated, "dry run still computes what WOULD change")
	assert.NotEmpty(t, result.HeadHash)

	// Nothing was actually persisted: the stored rows are unchanged, and the
	// chain still fails verification exactly as before the call.
	var stored1, stored2 models.AuditEvent
	require.NoError(t, ls.db.First(&stored1, e1.ID).Error)
	require.NoError(t, ls.db.First(&stored2, e2.ID).Error)
	assert.Equal(t, e1.EntryHash, stored1.EntryHash, "dry run must not persist row 1")
	assert.Equal(t, e2.EntryHash, stored2.EntryHash, "dry run must not persist row 2")

	v, err := ls.VerifyAuditChain(context.Background(), nil)
	require.NoError(t, err)
	assert.False(t, v.Valid, "chain must still fail verification after a dry run")
}

func TestMigrateAuditChainEncoding_LeavesUnchainedLegacyPrefixAlone(t *testing.T) {
	ls := newAuditChainTestStore(t)
	base := time.Now().UTC()

	// Two pre-ADR-029 rows: no hash chain at all (empty entry_hash).
	tr := true
	for i, d := range []string{"unchained-1", "unchained-2"} {
		require.NoError(t, ls.db.Create(&models.AuditEvent{
			EventType: "secret.read", Description: d, Success: &tr,
			EventTime: base.Add(time.Duration(i) * time.Second), ActorType: "user",
		}).Error)
	}
	c1 := appendLegacyEncodedEvent(t, ls, "chained-1", base.Add(10*time.Second), auditGenesisHash)
	_ = appendLegacyEncodedEvent(t, ls, "chained-2", base.Add(11*time.Second), c1.EntryHash)

	result, err := ls.MigrateAuditChainEncoding(context.Background(), false, nil)
	require.NoError(t, err)
	assert.Equal(t, int64(2), result.RowsMigrated, "only the chained rows are migrated")
	assert.Equal(t, int64(2), result.UnchainedRowsSkipped, "the unchained legacy prefix is left untouched")

	v, err := ls.VerifyAuditChain(context.Background(), nil)
	require.NoError(t, err)
	assert.True(t, v.Valid, "chain must verify after migration: %s", v.Reason)
	assert.Equal(t, int64(2), v.UnchainedEvents)
	assert.Equal(t, int64(2), v.ChainedEvents)
}

// TestMigrateAuditChainEncoding_ReSignsRetentionAnchor covers the interaction
// with a retention purge that ran BEFORE the migration: the earliest
// surviving row's prev_hash is a non-genesis anchor value (its real
// predecessor was purged and can never be recomputed under any encoding).
// The migration must recompute that row's entry_hash under the current
// encoding while leaving its prev_hash exactly as the anchor says, and
// report it back to the caller so the anchor itself can be re-signed.
func TestMigrateAuditChainEncoding_ReSignsRetentionAnchor(t *testing.T) {
	ls := newAuditChainTestStore(t)
	base := time.Now().UTC()

	const purgedPredecessorHash = "purged-predecessor-hash"
	anchored := appendLegacyEncodedEvent(t, ls, "first-surviving", base, purgedPredecessorHash)
	_ = appendLegacyEncodedEvent(t, ls, "second", base.Add(time.Second), anchored.EntryHash)

	anchor := &storage.AuditChainAnchor{
		RowID:     anchored.ID,
		PrevHash:  purgedPredecessorHash,
		EntryHash: anchored.EntryHash,
	}

	result, err := ls.MigrateAuditChainEncoding(context.Background(), false, anchor)
	require.NoError(t, err)
	assert.Equal(t, int64(2), result.RowsMigrated)
	require.Equal(t, anchored.ID, result.AnchorRowID, "the earliest migrated row must be reported for anchor re-signing")
	assert.NotEmpty(t, result.AnchorNewEntryHash)
	assert.NotEqual(t, anchored.EntryHash, result.AnchorNewEntryHash, "the anchor row's hash changed under the new encoding")

	var stored models.AuditEvent
	require.NoError(t, ls.db.First(&stored, anchored.ID).Error)
	assert.Equal(t, purgedPredecessorHash, stored.PrevHash, "the purged predecessor's hash is preserved verbatim, not recomputed")
	assert.Equal(t, result.AnchorNewEntryHash, stored.EntryHash)

	// A re-signed anchor (matching what the caller is expected to persist)
	// must let the migrated chain verify from that point forward.
	newAnchor := &storage.AuditChainAnchor{
		RowID:     anchored.ID,
		PrevHash:  purgedPredecessorHash,
		EntryHash: result.AnchorNewEntryHash,
	}
	v, err := ls.VerifyAuditChain(context.Background(), newAnchor)
	require.NoError(t, err)
	assert.True(t, v.Valid, "chain must verify against the re-signed anchor: %s", v.Reason)
}

func TestMigrateAuditChainEncoding_Empty(t *testing.T) {
	ls := newAuditChainTestStore(t)
	result, err := ls.MigrateAuditChainEncoding(context.Background(), false, nil)
	require.NoError(t, err)
	assert.Equal(t, int64(0), result.RowsMigrated)
	assert.Equal(t, int64(0), result.UnchainedRowsSkipped)
	assert.Equal(t, uint(0), result.HeadID)
}

func TestMigrateAuditChainEncoding_AlreadyCurrentEncodingIsIdempotent(t *testing.T) {
	ls := newAuditChainTestStore(t)
	base := time.Now().UTC()
	appendEvent(t, ls, "auth.login", "first", base)
	appendEvent(t, ls, "secret.read", "second", base.Add(time.Second))

	// Rows already chained under the CURRENT encoding: migration should be a
	// no-op in effect (same hashes recomputed) and the chain stays valid.
	result, err := ls.MigrateAuditChainEncoding(context.Background(), false, nil)
	require.NoError(t, err)
	assert.Equal(t, int64(2), result.RowsMigrated, "rows are re-walked and rewritten even if already current")

	v, err := ls.VerifyAuditChain(context.Background(), nil)
	require.NoError(t, err)
	assert.True(t, v.Valid, "re-migrating already-current rows must not break the chain: %s", v.Reason)
}

// TestMigrateAuditChainEncoding_RefusesToLaunderATamperedRow is the protection
// this operation was missing.
//
// Before the pre-flight check, MigrateAuditChainEncoding recomputed and
// overwrote every row's entry_hash/prev_hash unconditionally. Run on a database
// where someone had edited an audit event, it re-hashed the edited contents
// like any other row and the chain verified cleanly afterwards. The only
// residue was the migration event the function appends, which records that a
// migration happened, not what it erased.
//
// That is an evidence-destroying write on the one dataset whose entire purpose
// is evidence, reachable through a documented maintenance procedure an operator
// is told to run after upgrading — and the operator would have every reason to
// believe the resulting green chain meant their audit log was intact.
func TestMigrateAuditChainEncoding_RefusesToLaunderATamperedRow(t *testing.T) {
	ls := newAuditChainTestStore(t)
	base := time.Now().UTC()

	e1 := appendLegacyEncodedEvent(t, ls, "first", base, auditGenesisHash)
	e2 := appendLegacyEncodedEvent(t, ls, "second", base.Add(time.Second), e1.EntryHash)
	_ = appendLegacyEncodedEvent(t, ls, "third", base.Add(2*time.Second), e2.EntryHash)

	// Tamper: change an event's contents and leave its hash alone — exactly what
	// a direct database edit looks like. The row now matches neither encoding.
	require.NoError(t, ls.db.Model(&models.AuditEvent{}).Where("id = ?", e2.ID).
		Update("description", "second (quietly edited)").Error)

	var before []models.AuditEvent
	require.NoError(t, ls.db.Order("id ASC").Find(&before).Error)

	_, err := ls.MigrateAuditChainEncoding(context.Background(), false, nil)
	require.Error(t, err, "a tampered row must stop the migration, not be re-hashed into a valid chain")
	assert.Contains(t, err.Error(), "matches neither the current encoding nor the pre-#1452 one")
	assert.Contains(t, err.Error(), "destroying the evidence")

	// The refusal must leave the database exactly as it was: the whole point is
	// that nothing is rewritten, so a forensic copy taken afterwards is still
	// the original.
	var after []models.AuditEvent
	require.NoError(t, ls.db.Order("id ASC").Find(&after).Error)
	require.Len(t, after, len(before))
	for i := range before {
		assert.Equal(t, before[i].EntryHash, after[i].EntryHash,
			"event %d's entry_hash must be untouched after a refused migration", before[i].ID)
		assert.Equal(t, before[i].PrevHash, after[i].PrevHash,
			"event %d's prev_hash must be untouched after a refused migration", before[i].ID)
	}

	// A dry run must refuse identically. An operator checking "what would this
	// do?" before committing must be told about the tampering, not handed a
	// clean preview of the laundering.
	_, err = ls.MigrateAuditChainEncoding(context.Background(), true, nil)
	require.Error(t, err, "dry run must surface the same refusal")
}

// TestMigrateAuditChainEncoding_RefusesABrokenLink covers the other way
// re-encoding could repair evidence invisibly: the row contents are all
// self-consistent, but a row was removed, so prev_hash no longer links. Because
// the migration rewrites prev_hash for every row as it walks, it would have
// closed that gap and produced a chain that verifies with a row missing.
func TestMigrateAuditChainEncoding_RefusesABrokenLink(t *testing.T) {
	ls := newAuditChainTestStore(t)
	base := time.Now().UTC()

	e1 := appendLegacyEncodedEvent(t, ls, "first", base, auditGenesisHash)
	e2 := appendLegacyEncodedEvent(t, ls, "second", base.Add(time.Second), e1.EntryHash)
	e3 := appendLegacyEncodedEvent(t, ls, "third", base.Add(2*time.Second), e2.EntryHash)

	// Delete the middle event. e3 still points at e2's hash, which is now gone.
	require.NoError(t, ls.db.Where("id = ?", e2.ID).Delete(&models.AuditEvent{}).Error)

	_, err := ls.MigrateAuditChainEncoding(context.Background(), false, nil)
	require.Error(t, err, "a deleted row must stop the migration")
	assert.Contains(t, err.Error(), "inserted, deleted, or reordered")
	assert.Contains(t, err.Error(), fmt.Sprintf("event %d", e3.ID))
}
