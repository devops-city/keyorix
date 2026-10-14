package core

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/ports"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// newCheckpointCore builds a real-SQLite core with a fixed checkpoint signing key.
func newCheckpointCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.AuditCheckpoint{}, &models.SystemMetadata{}))
	c := &KeyorixCore{storage: store.NewLocalStorage(db)}
	c.SetAuditCheckpointKey(bytes.Repeat([]byte{0x7}, 32), "v1")
	return c, db
}

func logEvents(t *testing.T, c *KeyorixCore, n int) {
	t.Helper()
	// A fixed, second-aligned UTC base so EventTime round-trips through SQLite
	// exactly (sub-microsecond precision from time.Now() would not, making the
	// recomputed entry hash flaky).
	base := time.Date(2026, 6, 13, 10, 0, 0, 0, time.UTC)
	tr := true
	for i := range n {
		require.NoError(t, c.storage.LogAuditEvent(context.Background(), &models.AuditEvent{
			EventType:   "secret.read",
			Description: fmt.Sprintf("event %d", i),
			Success:     &tr,
			EventTime:   base.Add(time.Duration(i) * time.Second),
			// Set explicitly: the column defaults to "user", and the hash binds
			// ActorType raw, so an unset field would hash "" but store "user".
			ActorType: "user",
		}))
	}
}

func TestAuditCheckpoint_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, _ := newCheckpointCore(t)
	logEvents(t, c, 5)

	cp, written, err := c.WriteAuditCheckpoint(ctx)
	require.NoError(t, err)
	require.True(t, written)
	assert.Equal(t, int64(5), cp.ChainedEvents)
	assert.Equal(t, "v1", cp.KeyVersion)
	assert.NotEmpty(t, cp.Signature)

	v, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.True(t, v.Valid)
	assert.True(t, v.Checkpointed)
	assert.Empty(t, v.CheckpointReason)
}

// Deleting or garbling the persistent high-water mark while a signed checkpoint still
// exists is a rollback attempt (the mark is written with every checkpoint, so its
// absence/corruption alongside a checkpoint means it was tampered with). This also
// simulates the restart case: the in-memory watermark is cleared, so detection must
// come from the persistent-mark/checkpoint cross-check, not the in-memory floor.
func TestAuditCheckpoint_MissingHighWaterWithCheckpointIsTamper(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("deleted mark", func(t *testing.T) {
		c, db := newCheckpointCore(t)
		logEvents(t, c, 5)
		_, written, err := c.WriteAuditCheckpoint(ctx)
		require.NoError(t, err)
		require.True(t, written)

		v, err := c.VerifyAuditChain(ctx)
		require.NoError(t, err)
		require.True(t, v.Valid)

		// Attacker deletes the anti-rollback mark; simulate a restart losing the watermark.
		require.NoError(t, db.Exec("DELETE FROM system_metadata WHERE key = ?", auditHighWaterKey).Error)
		c.auditMaxCertified = 0

		v, err = c.VerifyAuditChain(ctx)
		require.NoError(t, err)
		assert.False(t, v.Valid, "a missing high-water mark while a checkpoint exists is tamper")
		assert.Contains(t, v.CheckpointReason, "anti-rollback mark")
	})

	t.Run("garbled mark", func(t *testing.T) {
		c, _ := newCheckpointCore(t)
		logEvents(t, c, 5)
		_, written, err := c.WriteAuditCheckpoint(ctx)
		require.NoError(t, err)
		require.True(t, written)

		// Overwrite the mark with an unparseable value; simulate a restart.
		require.NoError(t, c.storage.SetSystemMetadata(ctx, auditHighWaterKey, "not-a-valid-mark"))
		c.auditMaxCertified = 0

		v, err := c.VerifyAuditChain(ctx)
		require.NoError(t, err)
		assert.False(t, v.Valid, "a malformed high-water mark while a checkpoint exists is tamper")
		assert.Contains(t, v.CheckpointReason, "anti-rollback mark")
	})
}

// SeedAuditWatermark restores the in-memory watermark from the persisted mark, so a
// restart followed by a truncation (with the mark intact at seed time) is still caught.
func TestSeedAuditWatermark_RestoresFloorAfterRestart(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db := newCheckpointCore(t)
	logEvents(t, c, 5)
	_, _, err := c.WriteAuditCheckpoint(ctx)
	require.NoError(t, err)

	// Simulate a restart: a fresh core over the same DB with the same key (in-memory
	// watermark starts at 0), then seed from the persisted mark.
	c2 := &KeyorixCore{storage: store.NewLocalStorage(db)}
	c2.SetAuditCheckpointKey(bytes.Repeat([]byte{0x7}, 32), "v1")
	c2.SeedAuditWatermark(ctx)
	assert.Equal(t, int64(5), c2.watermark(), "watermark restored from persisted high-water")

	// Truncate the checkpoint rows AND the mark, leaving a self-consistent shorter chain;
	// the restored in-memory watermark still catches the regression.
	require.NoError(t, db.Exec("DELETE FROM audit_checkpoints").Error)
	require.NoError(t, db.Exec("DELETE FROM system_metadata WHERE key = ?", auditHighWaterKey).Error)
	require.NoError(t, db.Exec("DELETE FROM audit_events WHERE id > (SELECT MIN(id) FROM audit_events)").Error)

	v, err := c2.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.False(t, v.Valid, "truncation below the restored watermark is detected after restart")
}

// fakeNotary is a stand-in external authority for the anchoring wiring tests
// (the real RFC 3161 verify path is covered by the notary package round-trip).
type fakeNotary struct {
	token   []byte
	at      time.Time
	err     error
	calls   int
	lastMsg []byte
}

func (f *fakeNotary) Anchor(_ context.Context, msg []byte) (*ports.NotaryReceipt, error) {
	f.calls++
	f.lastMsg = append([]byte(nil), msg...)
	if f.err != nil {
		return nil, f.err
	}
	return &ports.NotaryReceipt{Token: f.token, Time: f.at, Provider: "fake"}, nil
}
func (f *fakeNotary) Provider() string { return "fake" }

// fakeVerifyReceiptAlwaysFails is a stub ports.VerifyReceiptFunc that never
// verifies — used where a test needs SetCheckpointAnchorRoots' verifier wired
// but is exercising CORE's handling of a verification failure/success surface,
// not notary's own RFC 3161 crypto (that round-trip is covered by
// internal/notary's own tests).
func fakeVerifyReceiptAlwaysFails(_ *x509.CertPool, _, _ []byte) (time.Time, error) {
	return time.Time{}, fmt.Errorf("fake: receipt does not verify")
}

func TestAuditCheckpoint_AnchorsWhenNotarySet(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db := newCheckpointCore(t)
	logEvents(t, c, 3)
	fn := &fakeNotary{token: []byte("opaque-tsa-token"), at: time.Date(2026, 6, 15, 9, 0, 0, 0, time.UTC)}
	c.SetCheckpointNotary(fn)

	cp, written, err := c.WriteAuditCheckpoint(ctx)
	require.NoError(t, err)
	require.True(t, written)

	// The receipt is reflected on the returned checkpoint...
	require.Equal(t, 1, fn.calls)
	require.NotNil(t, cp.AnchoredAt)
	assert.Equal(t, "fake", cp.AnchorProvider)
	assert.Equal(t, []byte("opaque-tsa-token"), cp.AnchorToken)
	// ...the notary saw exactly the checkpoint's canonical bytes...
	assert.Equal(t, []byte(checkpointCanonical(cp)), fn.lastMsg)
	// ...and the receipt was persisted on the row.
	var row models.AuditCheckpoint
	require.NoError(t, db.First(&row, cp.ID).Error)
	assert.Equal(t, []byte("opaque-tsa-token"), row.AnchorToken)
	require.NotNil(t, row.AnchoredAt)
	assert.Equal(t, "fake", row.AnchorProvider)
}

func TestAuditCheckpoint_AnchorIsBestEffort(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db := newCheckpointCore(t)
	logEvents(t, c, 2)
	c.SetCheckpointNotary(&fakeNotary{err: fmt.Errorf("tsa unreachable")})

	// A notary failure must NOT fail the checkpoint write.
	cp, written, err := c.WriteAuditCheckpoint(ctx)
	require.NoError(t, err)
	require.True(t, written)
	assert.Nil(t, cp.AnchoredAt)

	var row models.AuditCheckpoint
	require.NoError(t, db.First(&row, cp.ID).Error)
	assert.Empty(t, row.AnchorToken, "an un-anchored checkpoint is still a valid checkpoint")
}

// TestAuditCheckpoint_AnchorTrustRootConfigured_NoRoots confirms that anchoring
// without a configured trust root (SetCheckpointAnchorRoots never called) still
// records the raw TSA receipt (a legitimate, intentional configuration — see
// CheckpointNotaryConfig.CACertPath's doc comment) but surfaces
// AnchorTrustRootConfigured=false on every read, so a caller/auditor can tell a
// recorded-but-unverifiable anchor apart from one this server actually checked
// against a root of trust (#baseline/notary-findings.json#1).
func TestAuditCheckpoint_AnchorTrustRootConfigured_NoRoots(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, _ := newCheckpointCore(t)
	logEvents(t, c, 3)
	fn := &fakeNotary{token: []byte("opaque-tsa-token"), at: time.Date(2026, 6, 15, 9, 0, 0, 0, time.UTC)}
	c.SetCheckpointNotary(fn)
	// Deliberately no SetCheckpointAnchorRoots call.

	_, written, err := c.WriteAuditCheckpoint(ctx)
	require.NoError(t, err)
	require.True(t, written)

	assert.False(t, c.CheckpointAnchorVerifiable())

	v, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, v.AnchorToken, "the anchor was still recorded")
	assert.False(t, v.AnchorTrustRootConfigured, "no trust root configured — must not read as verified")
	assert.True(t, v.Valid, "recording without a trust root must not itself fail the checkpoint")
}

// TestAuditCheckpoint_AnchorTrustRootConfigured_WithRoots confirms
// AnchorTrustRootConfigured flips true once a trust root is wired
// (SetCheckpointAnchorRoots), independent of whether the specific stored token
// actually verifies against it (checked separately by the tamper-detection path).
func TestAuditCheckpoint_AnchorTrustRootConfigured_WithRoots(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, _ := newCheckpointCore(t)
	logEvents(t, c, 3)
	fn := &fakeNotary{token: []byte("opaque-tsa-token"), at: time.Date(2026, 6, 15, 9, 0, 0, 0, time.UTC)}
	c.SetCheckpointNotary(fn)
	c.SetCheckpointAnchorRoots(x509.NewCertPool(), fakeVerifyReceiptAlwaysFails)

	_, written, err := c.WriteAuditCheckpoint(ctx)
	require.NoError(t, err)
	require.True(t, written)

	assert.True(t, c.CheckpointAnchorVerifiable())

	v, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, v.AnchorToken)
	assert.True(t, v.AnchorTrustRootConfigured, "a trust root is configured — server can locally re-verify")
}

func TestVerifyCheckpointAnchor_NoAnchor(t *testing.T) {
	t.Parallel()
	c, _ := newCheckpointCore(t)
	at, ok, err := c.VerifyCheckpointAnchor(&models.AuditCheckpoint{ID: 1})
	require.NoError(t, err)
	assert.False(t, ok)
	assert.True(t, at.IsZero())
}

func TestVerifyCheckpointAnchor_NoTrustAnchorFailsClosed(t *testing.T) {
	t.Parallel()
	c, _ := newCheckpointCore(t)
	// A checkpoint carries an anchor token, but no trust anchor is configured:
	// verification must fail closed (ok=true, error) rather than assert a proof.
	cp := &models.AuditCheckpoint{ID: 1, AnchorToken: []byte("some-token")}
	_, ok, err := c.VerifyCheckpointAnchor(cp)
	assert.True(t, ok, "an anchor is present")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "trust anchor")
}

func TestAuditCheckpoint_DetectsTailTruncation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db := newCheckpointCore(t)
	logEvents(t, c, 5)
	_, _, err := c.WriteAuditCheckpoint(ctx) // certifies 5
	require.NoError(t, err)

	// Drop the tail → a self-consistent SHORTER chain. The bare re-walk passes;
	// only the signed checkpoint catches the drop.
	require.NoError(t, db.Exec("DELETE FROM audit_events WHERE id >= 4").Error)

	raw, err := c.storage.VerifyAuditChain(ctx, nil)
	require.NoError(t, err)
	assert.True(t, raw.Valid, "the bare chain walk cannot catch tail-truncation on its own")

	v, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.False(t, v.Valid, "the checkpoint catches it")
	assert.True(t, v.Checkpointed)
	assert.Contains(t, v.CheckpointReason, "truncated below signed checkpoint")
}

func TestAuditCheckpoint_DetectsForgedCheckpoint(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db := newCheckpointCore(t)
	logEvents(t, c, 5)
	_, _, err := c.WriteAuditCheckpoint(ctx)
	require.NoError(t, err)

	// A DB-level actor lowers the certified count to mask a planned truncation,
	// but cannot re-sign without the key → signature no longer recomputes.
	require.NoError(t, db.Exec("UPDATE audit_checkpoints SET chained_events = 1").Error)

	v, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.False(t, v.Valid)
	assert.Contains(t, v.CheckpointReason, "does not verify under the current signing key")
}

// A DB-level actor must not be able to disable enforcement by editing the
// unauthenticated key_version column — the HMAC binds key_version, so the edit
// fails the signature check (regression guard for the pre-merge security finding).
func TestAuditCheckpoint_TamperedKeyVersionDetected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db := newCheckpointCore(t)
	logEvents(t, c, 5)
	_, _, err := c.WriteAuditCheckpoint(ctx)
	require.NoError(t, err)

	// Attacker flips key_version to force the (old) "not enforced" branch, then
	// truncates. The signature now fails, so enforcement is NOT skipped.
	require.NoError(t, db.Exec("UPDATE audit_checkpoints SET key_version = 'forged'").Error)
	require.NoError(t, db.Exec("DELETE FROM audit_events WHERE id >= 4").Error)

	v, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.False(t, v.Valid, "a tampered key_version must not disable enforcement")
	assert.Contains(t, v.CheckpointReason, "does not verify under the current signing key")
}

// After a genuine signing-key rotation (a KEK-provider migration — since #502 the
// audit-checkpoint key is KEK-derived, so a routine DEK rotation no longer changes
// it at all; see TestAuditCheckpointKey_StableAcrossDEKRotation in the encryption
// package) the prior checkpoint cannot be re-verified, so verify reports invalid
// until the next checkpoint write re-baselines under the new key — and that write
// must succeed (no deadlock).
func TestAuditCheckpoint_RotationRebaselines(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, _ := newCheckpointCore(t)
	logEvents(t, c, 5)
	_, _, err := c.WriteAuditCheckpoint(ctx) // signed under "v1"
	require.NoError(t, err)

	// Simulate a KEK-provider migration → a new signing key + version wired in at
	// the next server startup (SetAuditCheckpointKey is only called at startup; see
	// server/main.go).
	c.SetAuditCheckpointKey(bytes.Repeat([]byte{0x9}, 32), "v2")

	// The stale "v1" checkpoint no longer verifies → flagged (fail closed).
	v, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.False(t, v.Valid, "a stale checkpoint after rotation is not silently trusted")
	assert.Contains(t, v.CheckpointReason, "does not verify under the current signing key")

	// A fresh checkpoint re-baselines under the new key (no deadlock).
	cp, written, err := c.WriteAuditCheckpoint(ctx)
	require.NoError(t, err)
	require.True(t, written)
	assert.Equal(t, "v2", cp.KeyVersion)

	v, err = c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.True(t, v.Valid, "recovered after re-baseline")
	assert.True(t, v.Checkpointed)
}

func TestAuditCheckpoint_NoKeyIsNoOp(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, _ := newCheckpointCore(t)
	c.SetAuditCheckpointKey(nil, "") // simulate encryption disabled
	logEvents(t, c, 3)

	cp, written, err := c.WriteAuditCheckpoint(ctx)
	require.NoError(t, err)
	assert.False(t, written)
	assert.Nil(t, cp)

	v, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.True(t, v.Valid)
	assert.False(t, v.Checkpointed, "no key → no on-box checkpoint enforcement")
}

// A checkpoint written over an empty chain (HeadID=0) must not later false-alarm
// once events accumulate — there is no head row 0 to "go missing".
func TestAuditCheckpoint_GenesisCheckpointNoFalsePositive(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, _ := newCheckpointCore(t)

	cp, written, err := c.WriteAuditCheckpoint(ctx) // empty chain → certifies 0
	require.NoError(t, err)
	require.True(t, written)
	assert.Equal(t, int64(0), cp.ChainedEvents)
	assert.Equal(t, uint(0), cp.HeadID)

	logEvents(t, c, 4) // chain grows past the genesis checkpoint

	v, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.True(t, v.Valid, "a growing chain is not a truncation of the genesis checkpoint")
	assert.True(t, v.Checkpointed)
}

func TestAuditCheckpoint_RefusesBrokenChain(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db := newCheckpointCore(t)
	logEvents(t, c, 5)

	// Delete a MIDDLE row → linkage breaks; the chain does not verify.
	require.NoError(t, db.Exec("DELETE FROM audit_events WHERE id = 3").Error)

	_, written, err := c.WriteAuditCheckpoint(ctx)
	require.Error(t, err)
	assert.False(t, written)
	assert.Contains(t, err.Error(), "refusing to checkpoint")
}

func TestAuditCheckpoint_NoRebaselineOverTruncation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db := newCheckpointCore(t)
	logEvents(t, c, 5)
	_, _, err := c.WriteAuditCheckpoint(ctx) // certifies 5
	require.NoError(t, err)

	require.NoError(t, db.Exec("DELETE FROM audit_events WHERE id >= 4").Error) // truncate to 3

	// A subsequent scheduled checkpoint must NOT silently re-baseline to the
	// shorter chain (which would erase the tamper evidence going forward).
	_, written, err := c.WriteAuditCheckpoint(ctx)
	require.Error(t, err)
	assert.False(t, written)
	assert.Contains(t, err.Error(), "truncated below signed checkpoint")

	var n int64
	require.NoError(t, db.Model(&models.AuditCheckpoint{}).Count(&n).Error)
	assert.Equal(t, int64(1), n, "no new checkpoint papered over the truncation")
}

// A DB-level actor must not be able to LAUNDER a tail-truncation by corrupting the
// prior checkpoint's signature: that makes it unverifiable, but its key_version
// still matches the current signing key, so it is tampering (not a DEK rotation) and
// WriteAuditCheckpoint must refuse to re-baseline over the shortened chain.
func TestAuditCheckpoint_NoRebaselineOverCorruptedSignature(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db := newCheckpointCore(t)
	logEvents(t, c, 5)
	_, _, err := c.WriteAuditCheckpoint(ctx) // certifies 5 under "v1"
	require.NoError(t, err)

	// Truncate the tail, then corrupt the checkpoint signature (key_version unchanged).
	require.NoError(t, db.Exec("DELETE FROM audit_events WHERE id >= 4").Error)
	require.NoError(t, db.Exec("UPDATE audit_checkpoints SET signature = 'tampered-byte'").Error)

	// The scheduled write must NOT bless the truncation by re-baselining.
	_, written, err := c.WriteAuditCheckpoint(ctx)
	require.Error(t, err)
	assert.False(t, written)
	assert.Contains(t, err.Error(), "tampered with, not rotated")

	var n int64
	require.NoError(t, db.Model(&models.AuditCheckpoint{}).Count(&n).Error)
	assert.Equal(t, int64(1), n, "no fresh checkpoint papered over the corrupted one")

	// And verification still reports the tamper (signal not erased).
	v, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.False(t, v.Valid)
}

// The headline rollback attack: an attacker with DB write deletes the newer
// checkpoint(s) and truncates the trail back to an OLDER but still-authentic
// checkpoint's head. The latest-checkpoint comparison alone is satisfied (the older
// checkpoint verifies and matches the shortened chain), but the signed high-water mark
// — a single overwritten row attesting the MAX certified length — still records the
// longer length, so verification must flag the rollback. A FRESH core (no in-memory
// watermark — i.e. a server restart) must catch it purely from the persistent mark.
func TestAuditCheckpoint_DetectsRollbackToOlderCheckpoint(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db := newCheckpointCore(t)

	logEvents(t, c, 5)
	_, _, err := c.WriteAuditCheckpoint(ctx) // checkpoint #1 certifies 5; high-water = 5
	require.NoError(t, err)
	logEvents(t, c, 5)                      // 10 total
	_, _, err = c.WriteAuditCheckpoint(ctx) // checkpoint #2 certifies 10; high-water = 10
	require.NoError(t, err)

	// Attack: truncate the trail back to 5 events AND delete the newer checkpoint so the
	// authentic older checkpoint (certifying 5) becomes the latest.
	require.NoError(t, db.Exec("DELETE FROM audit_events WHERE id > 5").Error)
	require.NoError(t, db.Exec("DELETE FROM audit_checkpoints WHERE chained_events = 10").Error)

	// Sanity: the latest-checkpoint comparison alone is now satisfied — the surviving
	// checkpoint certifies 5 and exactly 5 self-consistent events remain.
	raw, err := c.storage.VerifyAuditChain(ctx, nil)
	require.NoError(t, err)
	assert.True(t, raw.Valid, "the bare walk passes")

	// A FRESH core (server restart: in-memory watermark starts at 0) still catches the
	// rollback via the persistent signed high-water mark.
	fresh := &KeyorixCore{storage: store.NewLocalStorage(db)}
	fresh.SetAuditCheckpointKey(bytes.Repeat([]byte{0x7}, 32), "v1")
	v, err := fresh.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.False(t, v.Valid, "the high-water mark catches the rollback to an older checkpoint")
	assert.True(t, v.Checkpointed)
	assert.Contains(t, v.CheckpointReason, "high-water mark")
}

// Deleting the high-water row mid-run does not help an online attacker: the in-memory
// watermark remembers the max length certified this session.
func TestAuditCheckpoint_InMemoryWatermarkSurvivesHighWaterDeletion(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db := newCheckpointCore(t)
	logEvents(t, c, 8)
	_, _, err := c.WriteAuditCheckpoint(ctx) // high-water = 8 (persistent + in-memory)
	require.NoError(t, err)

	// Attacker truncates and wipes BOTH the checkpoint rows and the persistent mark.
	require.NoError(t, db.Exec("DELETE FROM audit_events WHERE id > 3").Error)
	require.NoError(t, db.Exec("DELETE FROM audit_checkpoints").Error)
	require.NoError(t, db.Exec("DELETE FROM system_metadata").Error)

	// The SAME running core still flags it from its in-memory watermark.
	v, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.False(t, v.Valid, "the in-memory watermark catches truncation after the mark is wiped")
	assert.Contains(t, v.CheckpointReason, "high-water mark")
}

// Editing the persistent high-water row under the current key is detected (the HMAC
// won't recompute) and is reported as tampering, not silently trusted.
func TestAuditCheckpoint_TamperedHighWaterDetected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db := newCheckpointCore(t)
	logEvents(t, c, 6)
	_, _, err := c.WriteAuditCheckpoint(ctx)
	require.NoError(t, err)

	// Lower the high-water's claimed length to mask a planned truncation; the signature
	// no longer matches. Use a fresh core so only the persistent mark is consulted.
	require.NoError(t, db.Exec("UPDATE system_metadata SET value = ? WHERE key = ?",
		"v1\x1f2\x1f2\x1fdeadbeef\x1fv1\x1fbogussig", auditHighWaterKey).Error)

	fresh := &KeyorixCore{storage: store.NewLocalStorage(db)}
	fresh.SetAuditCheckpointKey(bytes.Repeat([]byte{0x7}, 32), "v1")
	v, err := fresh.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.False(t, v.Valid)
	assert.Contains(t, v.CheckpointReason, "high-water mark")
}

// TestAuditCheckpoint_ForgedKeyVersionHighWaterDetected pins #110 — the exact
// exploit the prior fix missed: a forged high-water mark whose key_version is
// simply set to something OTHER than the current one was excused as "consistent
// with a DEK rotation" and its found=true routed around the missing-mark tamper
// check entirely, silently resetting the anti-rollback floor. Combined with
// deleting the newest checkpoint (keeping an older authentic one) and truncating
// events between them, VerifyAuditChain reported Valid=true over a rolled-back
// trail. The read path must not trust an unauthenticated key_version claim on a
// signature that fails to verify.
func TestAuditCheckpoint_ForgedKeyVersionHighWaterDetected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db := newCheckpointCore(t)

	// Establish an older, authentic checkpoint (the kept "#50" in the exploit
	// narrative) and a newer one (the "#100" the attacker will delete).
	logEvents(t, c, 5)
	_, written, err := c.WriteAuditCheckpoint(ctx)
	require.NoError(t, err)
	require.True(t, written)
	logEvents(t, c, 5) // now 10 events total
	_, written, err = c.WriteAuditCheckpoint(ctx)
	require.NoError(t, err)
	require.True(t, written)

	// Attacker: forge the high-water mark with a FABRICATED key_version (not the
	// real current "v1", and not a genuinely-ever-used version either) and a
	// garbage signature — this is the exact shape that was previously excused.
	require.NoError(t, db.Exec("UPDATE system_metadata SET value = ? WHERE key = ?",
		"v1\x1f1\x1f1\x1fdeadbeef\x1ffabricated-v99\x1fbogussig", auditHighWaterKey).Error)
	// Attacker: delete the newer checkpoint, keeping the older authentic one.
	require.NoError(t, db.Exec("DELETE FROM audit_checkpoints WHERE chained_events = 10").Error)
	// Attacker: truncate events below what the deleted checkpoint certified, but
	// still at/above what the surviving older checkpoint certified.
	require.NoError(t, db.Exec("DELETE FROM audit_events WHERE id > 7").Error)

	// Simulate a restart: fresh core, in-memory watermark reset.
	fresh := &KeyorixCore{storage: store.NewLocalStorage(db)}
	fresh.SetAuditCheckpointKey(bytes.Repeat([]byte{0x7}, 32), "v1")

	v, err := fresh.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.False(t, v.Valid, "a forged high-water mark claiming an arbitrary key_version must not bypass anti-rollback")
	assert.Contains(t, v.CheckpointReason, "high-water mark")
}

// When an external-notary trust root is configured, the latest checkpoint's stored
// anchor is re-verified on the read path: a token that doesn't verify against the
// configured root is flagged (previously the anchor was written but never checked).
func TestAuditCheckpoint_VerifiesAnchorWhenRootsConfigured(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, _ := newCheckpointCore(t)
	logEvents(t, c, 3)
	fn := &fakeNotary{token: []byte("not-a-real-rfc3161-token"), at: time.Date(2026, 6, 15, 9, 0, 0, 0, time.UTC)}
	c.SetCheckpointNotary(fn)
	c.SetCheckpointAnchorRoots(x509.NewCertPool(), fakeVerifyReceiptAlwaysFails) // roots configured → anchor verified on read
	_, _, err := c.WriteAuditCheckpoint(ctx)
	require.NoError(t, err)

	v, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.False(t, v.Valid, "a checkpoint anchor that doesn't verify against the configured root is flagged")
	assert.Contains(t, v.CheckpointReason, "external anchor failed verification")
}

// #182: VerifyCheckpointAnchor was cryptographically sound but unreachable in
// production — nothing outside its own unit tests ever called it, and the raw
// anchor token was never surfaced anywhere a verifier could reach it (only
// anchored_at/anchor_provider strings were). VerifyAuditChain (already exposed via
// GET /api/v1/audit/verify, the gRPC AuditService, and `keyorix audit verify`) now
// surfaces the latest checkpoint's raw external-notary receipt on its result,
// regardless of whether local trust roots are configured — so an operator can pull
// it and verify it independently, out-of-band, without trusting this server's own
// verification of it.
func TestVerifyAuditChain_SurfacesRawAnchorToken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, _ := newCheckpointCore(t)
	logEvents(t, c, 3)
	fn := &fakeNotary{token: []byte("opaque-tsa-token"), at: time.Date(2026, 6, 15, 9, 0, 0, 0, time.UTC)}
	c.SetCheckpointNotary(fn)
	// Deliberately NO SetCheckpointAnchorRoots: the raw token must still be surfaced
	// even when this server can't (or hasn't been configured to) verify it itself.
	_, written, err := c.WriteAuditCheckpoint(ctx)
	require.NoError(t, err)
	require.True(t, written)

	v, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	require.True(t, v.Valid)
	assert.Equal(t, []byte("opaque-tsa-token"), v.AnchorToken, "the raw receipt must be reachable off the verify result")
	assert.Equal(t, "fake", v.AnchorProvider)
	require.NotNil(t, v.AnchoredAt)
	assert.True(t, v.AnchoredAt.Equal(fn.at))
}

// A checkpoint with no anchor (no notary configured) must not fabricate one on the
// verify result.
func TestVerifyAuditChain_NoAnchorTokenWhenUnanchored(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, _ := newCheckpointCore(t)
	logEvents(t, c, 3)
	_, written, err := c.WriteAuditCheckpoint(ctx) // no notary set → unanchored
	require.NoError(t, err)
	require.True(t, written)

	v, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.Empty(t, v.AnchorToken)
	assert.Nil(t, v.AnchoredAt)
}

func TestAuditCheckpoint_SignDeterministicAndBinding(t *testing.T) {
	t.Parallel()
	c := &KeyorixCore{}
	c.SetAuditCheckpointKey(bytes.Repeat([]byte{0x1}, 32), "v1")
	cp := &models.AuditCheckpoint{ChainedEvents: 5, HeadID: 5, HeadHash: "abc", KeyVersion: "v1"}
	sig := c.signCheckpoint(cp)
	require.NotEmpty(t, sig)
	assert.Equal(t, sig, c.signCheckpoint(cp), "deterministic for fixed inputs")

	cp.Signature = sig
	assert.True(t, c.checkpointSignatureValid(cp))

	for _, mut := range []func(){
		func() { cp.ChainedEvents = 4 },
		func() { cp.HeadID = 6 },
		func() { cp.HeadHash = "abd" },
		func() { cp.KeyVersion = "v2" },
	} {
		fresh := &models.AuditCheckpoint{ChainedEvents: 5, HeadID: 5, HeadHash: "abc", KeyVersion: "v1", Signature: sig}
		cp = fresh
		mut()
		assert.False(t, c.checkpointSignatureValid(cp), "every signed field is bound")
	}
}
