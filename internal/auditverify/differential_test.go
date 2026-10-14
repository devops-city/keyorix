package auditverify_test

// Parity/differential tests: the SAME fixture chains, written through the
// REAL server code path (internal/storage/store's LocalStorage), must be
// agreed upon by this module's independent auditverify.Verify — including
// every tamper case (design §9). This file is the one place in this module
// that legitimately imports internal/core and internal/storage/store: it
// builds known-good (and known-tampered) fixtures with the real writer, then
// hands the resulting SQLite FILE to the independent verifier and compares
// verdicts. TestDependencyGuard_NoCoreOrStorageImports (a package-internal
// test, not this one) is what proves the PRODUCTION package never takes
// this shortcut itself.

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/auditverify"
	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlitedialect "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

var fixedCheckpointKey = bytes.Repeat([]byte{0x7}, 32)

// diffFixture is a real, file-backed SQLite chain built through the actual
// server write path (store.LocalStorage), plus a KeyorixCore over the same
// DB handle for checkpoint writes and the "oracle" (online) verification.
type diffFixture struct {
	t      *testing.T
	path   string
	db     *gorm.DB
	local  *store.LocalStorage
	core   *core.KeyorixCore
	ctx    context.Context
	nextID int
}

func newDiffFixture(t *testing.T) *diffFixture {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	path := filepath.Join(t.TempDir(), "audit.db")
	db, err := gorm.Open(sqlitedialect.Open(path), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.AuditCheckpoint{}, &models.SystemMetadata{}, &models.LegalHold{}))

	local := store.NewLocalStorage(db)
	c := core.NewKeyorixCore(local)
	c.SetAuditCheckpointKey(fixedCheckpointKey, "v1")

	return &diffFixture{t: t, path: path, db: db, local: local, core: c, ctx: context.Background()}
}

// logEvents appends n events with strictly increasing, second-aligned
// timestamps ending `age` before now (so a subsequent PurgeAuditLogs call
// with a real wall-clock cutoff can deterministically include or exclude
// them without needing a fake clock — KeyorixCore.now() is not test-
// overridable from outside package core).
func (f *diffFixture) logEvents(n int, age time.Duration) {
	f.t.Helper()
	base := time.Now().UTC().Add(-age).Truncate(time.Second)
	tr := true
	for i := range n {
		f.nextID++
		require.NoError(f.t, f.local.LogAuditEvent(f.ctx, &models.AuditEvent{
			EventType:   "secret.read",
			Description: fmt.Sprintf("event %d", f.nextID),
			Success:     &tr,
			EventTime:   base.Add(time.Duration(i) * time.Second),
			ActorType:   "user",
		}))
	}
}

// exec runs a raw SQL statement against the fixture's own DB handle — used
// to inject the exact tamper shapes design §9 enumerates (modified row,
// reordered, deleted, truncated, forged checkpoint), mirroring the pattern
// internal/core/audit_checkpoint_test.go already uses for the same purpose.
func (f *diffFixture) exec(sql string, args ...any) {
	f.t.Helper()
	require.NoError(f.t, f.db.Exec(sql, args...).Error)
}

// openIndependent opens the fixture's SQLite file through auditverify's own
// read-only DB access (never through gorm/store) and closes it on cleanup.
func (f *diffFixture) openIndependent() *auditverify.DB {
	f.t.Helper()
	db, err := auditverify.OpenSQLiteReadOnly(f.path)
	require.NoError(f.t, err)
	f.t.Cleanup(func() { _ = db.Close() })
	return db
}

// oracle runs the server's own (online) verification for comparison.
func (f *diffFixture) oracle() *corestorage.AuditChainVerification {
	f.t.Helper()
	v, err := f.core.VerifyAuditChain(f.ctx)
	require.NoError(f.t, err)
	return v
}

// TestDifferential_HappyPath proves the two implementations agree on a
// clean, checkpointed chain, and that every row's independently-recomputed
// entry_hash matches the value the REAL writer (store.computeAuditEntryHash,
// unexported and never imported here) actually persisted — the strongest
// form of "byte-identical output" design §4 asks for, since it compares
// against production-written data rather than a second call to the same
// function.
func TestDifferential_HappyPath(t *testing.T) {
	t.Parallel()
	f := newDiffFixture(t)
	f.logEvents(25, time.Hour)
	_, written, err := f.core.WriteAuditCheckpoint(f.ctx)
	require.NoError(t, err)
	require.True(t, written)

	want := f.oracle()
	require.True(t, want.Valid)

	db := f.openIndependent()
	got, err := auditverify.Verify(f.ctx, db, auditverify.Options{CheckpointKey: fixedCheckpointKey})
	require.NoError(t, err)

	require.Equal(t, auditverify.VerdictValid, got.Verdict, "reason: %s", got.Reason)
	require.Equal(t, want.ChainedEvents, got.ChainedEvents)
	require.Equal(t, want.UnchainedEvents, got.UnchainedLegacyEvents)
	require.True(t, got.Checkpoint.Present)
	require.True(t, got.Checkpoint.Authenticated)

	assertEveryHashMatchesStored(t, db)
}

// assertEveryHashMatchesStored re-derives every stored row's entry_hash via
// auditverify.ComputeEntryHash and asserts it equals the value the real
// server writer persisted — proving the two hash derivations are
// byte-identical over real, non-synthetic data.
func assertEveryHashMatchesStored(t *testing.T, db *auditverify.DB) {
	t.Helper()
	ctx := context.Background()
	var lastID uint64
	total := 0
	for {
		batch, err := db.StreamAuditEvents(ctx, lastID, 500)
		require.NoError(t, err)
		if len(batch) == 0 {
			break
		}
		for _, e := range batch {
			if e.EntryHash == "" {
				continue // legacy unchained prefix — nothing to compare
			}
			require.Equal(t, e.EntryHash, auditverify.ComputeEntryHash(e, e.PrevHash),
				"event #%d: independently-derived hash does not match the value the real writer persisted", e.ID)
			total++
		}
		lastID = batch[len(batch)-1].ID
		if len(batch) < 500 {
			break
		}
	}
	require.Positive(t, total, "no chained rows were compared — the fixture produced nothing to differentiate against")
}

// TestDifferential_GoldenPath_NoCheckpoint proves a clean chain with no
// checkpoint configured at all verifies VALID under a bare walk — the base
// case every tamper/checkpoint scenario in this file is a variation of.
func TestDifferential_GoldenPath_NoCheckpoint(t *testing.T) {
	t.Parallel()
	f := newDiffFixture(t)
	f.logEvents(15, time.Hour)

	want := f.oracle()
	require.True(t, want.Valid)
	require.False(t, want.Checkpointed)

	db := f.openIndependent()
	got, err := auditverify.Verify(f.ctx, db, auditverify.Options{})
	require.NoError(t, err)
	require.Equal(t, auditverify.VerdictValid, got.Verdict, "reason: %s", got.Reason)
	require.Equal(t, want.ChainedEvents, got.ChainedEvents)
	require.False(t, got.Checkpoint.Present)
}

// TestDifferential_TamperMatrix drives every tamper shape design §9
// enumerates through the SAME real-writer fixture and asserts the online
// (oracle) and offline (auditverify) verifiers agree on pass/fail.
func TestDifferential_TamperMatrix(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		tamper     func(f *diffFixture)
		wantBroken bool
	}{
		{
			name: "modified row content",
			tamper: func(f *diffFixture) {
				f.exec("UPDATE audit_events SET description = 'tampered' WHERE id = 3")
			},
			wantBroken: true,
		},
		{
			name: "deleted middle row",
			tamper: func(f *diffFixture) {
				f.exec("DELETE FROM audit_events WHERE id = 3")
			},
			wantBroken: true,
		},
		{
			name: "reordered rows (swapped content)",
			tamper: func(f *diffFixture) {
				var d2, d3 string
				require.NoError(f.t, f.db.Raw("SELECT description FROM audit_events WHERE id = 2").Scan(&d2).Error)
				require.NoError(f.t, f.db.Raw("SELECT description FROM audit_events WHERE id = 3").Scan(&d3).Error)
				f.exec("UPDATE audit_events SET description = ? WHERE id = 2", d3)
				f.exec("UPDATE audit_events SET description = ? WHERE id = 3", d2)
			},
			wantBroken: true,
		},
		{
			name: "truncated tail",
			tamper: func(f *diffFixture) {
				f.exec("DELETE FROM audit_events WHERE id > 5")
			},
			// A shorter, self-consistent chain still verifies under a bare
			// re-walk — this is the exact ADR-029 limitation both verifiers
			// share. Confirmed BROKEN by the checkpoint-enforced variant
			// below, not this case.
			wantBroken: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newDiffFixture(t)
			f.logEvents(10, time.Hour)

			tc.tamper(f)

			want := f.oracle()
			db := f.openIndependent()
			got, err := auditverify.Verify(f.ctx, db, auditverify.Options{})
			require.NoError(t, err)

			require.Equal(t, tc.wantBroken, !want.Valid, "test bug: oracle's own Valid flag does not match this case's expectation")
			if tc.wantBroken {
				require.Equal(t, auditverify.VerdictBroken, got.Verdict, "reason: %s", got.Reason)
			} else {
				require.NotEqual(t, auditverify.VerdictBroken, got.Verdict, "reason: %s", got.Reason)
			}
		})
	}
}

// TestDifferential_TruncatedTail_CheckpointEnforced proves the offline
// verifier, like the online one, DOES catch a tail-truncation once a
// checkpoint key is available — the counterpart to the bare-re-walk case
// above, and the specific test design §9 says "exists precisely to keep
// that limitation honest and visible."
func TestDifferential_TruncatedTail_CheckpointEnforced(t *testing.T) {
	t.Parallel()
	f := newDiffFixture(t)
	f.logEvents(10, time.Hour)
	_, written, err := f.core.WriteAuditCheckpoint(f.ctx)
	require.NoError(t, err)
	require.True(t, written)

	f.exec("DELETE FROM audit_events WHERE id > 5")

	want := f.oracle()
	require.False(t, want.Valid, "test bug: the oracle should catch this truncation via its own checkpoint enforcement")

	db := f.openIndependent()
	got, err := auditverify.Verify(f.ctx, db, auditverify.Options{CheckpointKey: fixedCheckpointKey})
	require.NoError(t, err)
	require.Equal(t, auditverify.VerdictBroken, got.Verdict, "reason: %s", got.Reason)
}

// TestDifferential_ForgedCheckpoint proves a flipped signature byte is
// caught identically by both verifiers.
func TestDifferential_ForgedCheckpoint(t *testing.T) {
	t.Parallel()
	f := newDiffFixture(t)
	f.logEvents(5, time.Hour)
	_, written, err := f.core.WriteAuditCheckpoint(f.ctx)
	require.NoError(t, err)
	require.True(t, written)

	f.exec("UPDATE audit_checkpoints SET signature = 'not-a-real-signature'")

	want := f.oracle()
	require.False(t, want.Valid)

	db := f.openIndependent()
	got, err := auditverify.Verify(f.ctx, db, auditverify.Options{CheckpointKey: fixedCheckpointKey})
	require.NoError(t, err)
	require.Equal(t, auditverify.VerdictBroken, got.Verdict, "reason: %s", got.Reason)
	require.Contains(t, got.Reason, "signature")
}

// TestDifferential_RetentionGap_KeyAvailable proves a sanctioned retention
// purge is reported VALID by both verifiers when the checkpoint key is
// available — the "sanctioned gap" path of design §5.
func TestDifferential_RetentionGap_KeyAvailable(t *testing.T) {
	t.Parallel()
	f := newDiffFixture(t)
	f.logEvents(5, 40*24*time.Hour) // old enough to be purged
	f.logEvents(5, time.Hour)       // kept

	res, err := f.core.PurgeAuditLogs(f.ctx, core.AuditLogRetentionConfig{RetentionDays: 7})
	require.NoError(t, err)
	require.Positive(t, res.DeletedCount, "test bug: the purge must actually remove rows for this to be a retention-gap fixture")

	want := f.oracle()
	require.True(t, want.Valid, "reason: %s", want.Reason)

	db := f.openIndependent()
	got, err := auditverify.Verify(f.ctx, db, auditverify.Options{CheckpointKey: fixedCheckpointKey})
	require.NoError(t, err)
	require.Equal(t, auditverify.VerdictValid, got.Verdict, "reason: %s", got.Reason)
	require.True(t, got.RetentionGap.Present)
	require.True(t, got.RetentionGap.Sanctioned)
}

// TestDifferential_RetentionGap_KeyUnavailable is "the test this design most
// wants to exist" (§9): the same sanctioned purge, verified WITHOUT the
// checkpoint key, must read INDETERMINATE — never BROKEN (a false alarm on
// every purged deployment) and never VALID (silently trusting an
// unauthenticated gap).
func TestDifferential_RetentionGap_KeyUnavailable(t *testing.T) {
	t.Parallel()
	f := newDiffFixture(t)
	f.logEvents(5, 40*24*time.Hour)
	f.logEvents(5, time.Hour)

	res, err := f.core.PurgeAuditLogs(f.ctx, core.AuditLogRetentionConfig{RetentionDays: 7})
	require.NoError(t, err)
	require.Positive(t, res.DeletedCount)

	db := f.openIndependent()
	got, err := auditverify.Verify(f.ctx, db, auditverify.Options{}) // no key
	require.NoError(t, err)

	require.Equal(t, auditverify.VerdictIndeterminate, got.Verdict, "reason: %s", got.Reason)
	require.NotEqual(t, auditverify.VerdictBroken, got.Verdict, "a sanctioned retention gap must never be reported BROKEN")
	require.True(t, got.RetentionGap.Present)
	require.False(t, got.RetentionGap.Sanctioned)
}

// TestDifferential_RetentionAnchor_AuthenticatedButMismatched proves that an
// authenticated retention anchor which no longer matches the live earliest
// row (rows were removed beyond what the anchor recorded, or the anchor is
// stale) is reported BROKEN, not sanctioned and not merely INDETERMINATE —
// mirrors VerifyAuditChain's own pre-check exactly.
func TestDifferential_RetentionAnchor_AuthenticatedButMismatched(t *testing.T) {
	t.Parallel()
	f := newDiffFixture(t)
	f.logEvents(5, 40*24*time.Hour)
	f.logEvents(5, time.Hour)

	res, err := f.core.PurgeAuditLogs(f.ctx, core.AuditLogRetentionConfig{RetentionDays: 7})
	require.NoError(t, err)
	require.Positive(t, res.DeletedCount)

	// The anchor now authenticates the earliest SURVIVING row after the
	// purge; deleting that exact row (but not its successors) leaves a live
	// earliest row that no longer matches what the anchor recorded.
	var earliestID int
	require.NoError(t, f.db.Raw("SELECT MIN(id) FROM audit_events").Scan(&earliestID).Error)
	f.exec("DELETE FROM audit_events WHERE id = ?", earliestID)

	db := f.openIndependent()
	got, err := auditverify.Verify(f.ctx, db, auditverify.Options{CheckpointKey: fixedCheckpointKey})
	require.NoError(t, err)
	require.Equal(t, auditverify.VerdictBroken, got.Verdict, "reason: %s", got.Reason)
	require.Contains(t, got.Reason, "does not match the authenticated retention re-anchor")
}
