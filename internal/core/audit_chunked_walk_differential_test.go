// audit_chunked_walk_differential_test.go — AUDIT-READER-HYGIENE-1 item 2: every
// chunked audit-chain walk gives the verdict of one whole-chain walk.
//
// The long readers never hold one snapshot for a whole walk (item 1,
// audit_long_reader_snapshot_test.go): each batch is its own read, the walk
// resumes by id and re-anchors on the last verified hash. That is only sound if
// the chunk boundaries never change the verdict. This test pins it, on a chain
// whose tampered rows sit on and next to every boundary in play:
//
//   - reference: auditverify.Verify with one batch larger than the table, i.e.
//     one SELECT, one snapshot, the whole chain;
//   - auditverify.Verify with batch sizes 1, 7 and the default (`admin
//     verify-audit`): the same Result, field for field;
//   - LocalStorage.VerifyAuditChain (statement batches of 1000) and the core
//     full walk with checkpoint enforcement (KeyorixCore.VerifyAuditChain);
//   - the audit_checkpoint rolling cycle in three segments, each resuming from
//     the previous segment's head id and hash.
//
// Scenarios: a valid chain, one altered row, one deleted row, and a
// retention-purged prefix re-anchored by a v1 and by a v2 retention anchor
// (alone and with an altered row after it). Same verdict, same first broken
// id and, on a valid chain, the same head.
package core

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/auditverify"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const (
	diffChainRows = 2_500 // crosses the 1000-row statement batches twice
	diffSegments  = 3     // rolling segments of 834 ids: boundaries 834|835, 1668|1669
)

var diffCheckpointKey = []byte("reanchor-test-key-32-bytes-long")

// chainScenario mutates a freshly built, checkpointed chain.
type chainScenario struct {
	name string
	// purgeBefore > 0 deletes every row below it and re-anchors the chain on
	// it with a signed retention anchor of anchorLayout ("v1" or "v2") BEFORE
	// the checkpoint is written, as a sanctioned purge does.
	purgeBefore  uint
	anchorLayout string
	// after the checkpoint: tamper with the chain.
	alter, del uint
	wantValid  bool
}

func chunkedWalkScenarios() []chainScenario {
	s := []chainScenario{{name: "valid", wantValid: true}}
	for _, k := range []uint{1, 2, 834, 835, 999, 1000, 1001, 1668, 1669, 2000, 2001, diffChainRows} {
		s = append(s, chainScenario{name: fmt.Sprintf("altered-%d", k), alter: k})
	}
	for _, k := range []uint{2, 834, 835, 1000, 1001, 1668, 1669, 2000, 2001, 2499} {
		s = append(s, chainScenario{name: fmt.Sprintf("deleted-%d", k), del: k})
	}
	for _, layout := range []string{"v1", "v2"} {
		for _, p := range []uint{835, 1001} {
			s = append(s,
				chainScenario{name: fmt.Sprintf("purged-below-%d-anchor-%s", p, layout), purgeBefore: p, anchorLayout: layout, wantValid: true},
				chainScenario{name: fmt.Sprintf("purged-below-%d-anchor-%s-altered-1669", p, layout), purgeBefore: p, anchorLayout: layout, alter: 1669},
				chainScenario{name: fmt.Sprintf("purged-below-%d-anchor-%s-deleted-2000", p, layout), purgeBefore: p, anchorLayout: layout, del: 2000},
			)
		}
	}
	return s
}

// applyScenario builds the chain, applies the purge, writes a checkpoint and
// then tampers.
func applyScenario(t *testing.T, env *longReaderEnv, sc chainScenario) {
	t.Helper()
	ctx := context.Background()
	buildSyntheticAuditChain(t, env.db, diffChainRows)
	if sc.purgeBefore > 0 {
		var head models.AuditEvent
		require.NoError(t, env.db.Where("id = ?", sc.purgeBefore).Take(&head).Error)
		require.NoError(t, env.db.Exec("DELETE FROM audit_events WHERE id < ?", sc.purgeBefore).Error)
		c := env.c
		var val string
		switch sc.anchorLayout {
		case "v1":
			val = auditRetentionAnchorValue(head.ID, head.PrevHash, head.EntryHash, c.auditCkptKeyVersion,
				c.signRetentionAnchorWithVersion(head.ID, head.PrevHash, head.EntryHash, c.auditCkptKeyVersion))
		case "v2":
			purged := int64(sc.purgeBefore - 1)
			val = auditRetentionAnchorValueV2(head.ID, head.PrevHash, head.EntryHash, purged, c.auditCkptKeyVersion,
				c.signRetentionAnchorV2(head.ID, head.PrevHash, head.EntryHash, purged))
		default:
			t.Fatalf("unknown anchor layout %q", sc.anchorLayout)
		}
		require.NoError(t, c.storage.SetSystemMetadata(ctx, auditRetentionAnchorKey, val))
	}
	_, written, err := env.c.WriteAuditCheckpoint(ctx)
	require.NoError(t, err)
	require.True(t, written)
	if sc.alter > 0 {
		tamperDescription(t, env.db, sc.alter)
	}
	if sc.del > 0 {
		require.NoError(t, env.db.Exec("DELETE FROM audit_events WHERE id = ?", sc.del).Error)
	}
}

// walkVerdict is the part of a verdict every walker reports.
type walkVerdict struct {
	Valid       bool
	FirstBroken uint // 0: none
	HeadID      uint // valid chains only
	HeadHash    string
}

func firstBroken(p *uint) uint {
	if p == nil {
		return 0
	}
	return *p
}

func (env *longReaderEnv) headOf(t *testing.T, id uint) string {
	t.Helper()
	var e models.AuditEvent
	require.NoError(t, env.db.Where("id = ?", id).Take(&e).Error)
	return e.EntryHash
}

// offlineVerify runs `admin verify-audit`'s verification with batchSize.
func offlineVerify(t *testing.T, env *longReaderEnv, batchSize int) *auditverify.Result {
	t.Helper()
	fixed := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	res, err := auditverify.Verify(context.Background(), env.openVerifier(t), auditverify.Options{
		CheckpointKey: diffCheckpointKey, BatchSize: batchSize, Now: func() time.Time { return fixed },
	})
	require.NoError(t, err)
	return res
}

// rollingCycleVerdict drives audit_checkpoint ticks until one rolling cycle of
// diffSegments segments has completed or recorded a failure.
func rollingCycleVerdict(t *testing.T, env *longReaderEnv) walkVerdict {
	t.Helper()
	ctx := context.Background()
	c := env.c
	c.SetAuditIncrementalVerification(24*time.Hour, diffSegments)
	c.auditVerifyMinWidth = 1
	cp, err := c.storage.LatestAuditCheckpoint(ctx)
	require.NoError(t, err)
	for range diffSegments + 1 {
		// The tick's own checkpoint write may refuse a tampered chain; the
		// segment walks regardless (RunAuditVerificationTick's contract).
		_, _ = c.RunAuditVerificationTick(ctx)
		st, reason, err := c.loadAuditVerifyState(ctx)
		require.NoError(t, err)
		require.Empty(t, reason)
		if st.Cycle == nil && st.LastFull != nil && st.LastFull.Source == auditFullSourceRolling {
			v := walkVerdict{Valid: st.LastFull.Valid, FirstBroken: firstBroken(st.LastFull.FirstBrokenID)}
			if v.Valid {
				v.HeadID, v.HeadHash = st.LastFull.ThroughID, cp.HeadHash
			}
			return v
		}
	}
	t.Fatalf("the rolling cycle did not finish in %d ticks", diffSegments+1)
	return walkVerdict{}
}

func runChunkedWalkDifferential(t *testing.T, newEnv func(*testing.T) *longReaderEnv) {
	for _, sc := range chunkedWalkScenarios() {
		t.Run(sc.name, func(t *testing.T) {
			env := newEnv(t)
			applyScenario(t, env, sc)
			ctx := context.Background()

			// Reference: the whole chain in one SELECT (one snapshot).
			ref := offlineVerify(t, env, diffChainRows*2)
			want := walkVerdict{Valid: ref.Verdict == auditverify.VerdictValid, FirstBroken: uint(firstBroken64(ref.FirstBrokenID))}
			if want.Valid {
				want.HeadID = uint(ref.Range.ToID)
				want.HeadHash = env.headOf(t, want.HeadID)
			}
			require.Equal(t, sc.wantValid, want.Valid, "reference verdict: %s %s", ref.Verdict, ref.Reason)
			if !sc.wantValid {
				require.NotZero(t, want.FirstBroken, "a broken reference names its first broken row: %s", ref.Reason)
			}

			// admin verify-audit at other batch sizes: the identical Result.
			for _, bs := range []int{1, 7, auditverify.DefaultBatchSize} {
				require.Equal(t, ref, offlineVerify(t, env, bs), "auditverify batch size %d", bs)
			}

			// The store walk (1000-row statements), seeded from the
			// authenticated anchor exactly as the checkpoint writer seeds it.
			anchor, err := env.c.loadAuditRetentionAnchor(ctx)
			require.NoError(t, err)
			require.Equal(t, sc.purgeBefore > 0, anchor != nil, "the retention anchor authenticates")
			raw, err := env.c.storage.VerifyAuditChain(ctx, anchor)
			require.NoError(t, err)
			got := walkVerdict{Valid: raw.Valid, FirstBroken: firstBroken(raw.FirstBrokenID)}
			if got.Valid {
				got.HeadID, got.HeadHash = raw.HeadID, raw.HeadHash
			}
			require.Equal(t, want, got, "store walk: %s", raw.Reason)

			// The core full walk with checkpoint enforcement.
			full, err := env.c.VerifyAuditChain(ctx)
			require.NoError(t, err)
			got = walkVerdict{Valid: full.Valid, FirstBroken: firstBroken(full.FirstBrokenID)}
			if got.Valid {
				got.HeadID, got.HeadHash = full.HeadID, full.HeadHash
			}
			require.Equal(t, want, got, "core full walk: %s / %s", full.Reason, full.CheckpointReason)

			// The rolling cycle, resumed segment by segment.
			require.Equal(t, want, rollingCycleVerdict(t, env), "rolling cycle")
		})
	}
}

func firstBroken64(p *uint64) uint64 {
	if p == nil {
		return 0
	}
	return *p
}

func TestAuditChunkedWalk_SameVerdictAsWholeChainWalk_SQLite(t *testing.T) {
	runChunkedWalkDifferential(t, newFactorySQLiteLongReaderEnv)
}

func TestAuditChunkedWalk_SameVerdictAsWholeChainWalk_Postgres(t *testing.T) {
	pgTestDSN(t)
	runChunkedWalkDifferential(t, newPostgresLongReaderEnv)
}
