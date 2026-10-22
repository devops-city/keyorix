// audit_checkpoint_keyversion_launder_test.go — a DB-write actor without the
// signing key must not be able to launder an audit tail truncation by
// relabelling the key_version of the latest checkpoint and of the high-water
// mark (RECOVERY-DESIGN-1 F1).
//
// The write path re-baselines over a checkpoint or mark that fails its HMAC
// under a key_version other than the current one, because that is what a
// signing-key change (rotate-kek, migrate-provider) looks like. key_version is
// not authenticated once the HMAC fails, so on its own it cannot tell a key
// change from a relabel. The signed verification state can: it is HMAC'd with
// the same key, so after a real key change it fails too, while a relabel
// leaves it authentic and still pinning the head the chain had reached. The
// write paths now refuse to certify a chain that this signed state proves was
// truncated.
package core

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// launderCertify builds the pre-attack state through the scheduler path:
// 6 events and a tick (checkpoint #1 via the full walk), then 4 more and a
// tick (checkpoint #2 via the tail check). Checkpoint #2, the high-water mark
// and the signed verification state all certify 10 events with head id 10.
func launderCertify(t *testing.T, c *KeyorixCore, clk *incrClock) {
	t.Helper()
	ctx := context.Background()
	logIncrEvents(t, c, clk, 6)
	_, err := c.RunAuditVerificationTick(ctx)
	require.NoError(t, err)
	clk.advance()
	logIncrEvents(t, c, clk, 4)
	res, err := c.RunAuditVerificationTick(ctx)
	require.NoError(t, err)
	require.True(t, res.Written)
	require.Equal(t, int64(10), res.Checkpoint.ChainedEvents)
}

// relabelHighWater rewrites the key_version field of the stored high-water
// mark without the key (its signature then fails under a "superseded" claim).
func relabelHighWater(t *testing.T, db *gorm.DB) {
	t.Helper()
	var row models.SystemMetadata
	require.NoError(t, db.Where(&models.SystemMetadata{Key: auditHighWaterKey}).First(&row).Error)
	parts := strings.Split(row.Value, auditHighWaterSep)
	require.Len(t, parts, 6)
	parts[4] = "forged"
	require.NoError(t, db.Model(&models.SystemMetadata{}).Where(&models.SystemMetadata{Key: auditHighWaterKey}).
		Update("value", strings.Join(parts, auditHighWaterSep)).Error)
}

// launderAttack truncates the tail to 4 events and relabels the latest
// checkpoint and the high-water mark (the F1 probe).
func launderAttack(t *testing.T, db *gorm.DB) {
	t.Helper()
	require.NoError(t, db.Exec("DELETE FROM audit_events WHERE id > 4").Error)
	require.NoError(t, db.Exec("UPDATE audit_checkpoints SET key_version = 'forged'").Error)
	relabelHighWater(t, db)
}

// restartCore is a fresh process on the same database and key: the in-memory
// watermark and generation floor start empty, the watermark is seeded as at
// server startup.
func restartCore(t *testing.T, s *store.LocalStorage, clk *incrClock, incremental bool) *KeyorixCore {
	t.Helper()
	c := NewKeyorixCore(s)
	c.now = clk.now
	c.SetAuditCheckpointKey([]byte("reanchor-test-key-32-bytes-long"), "v1")
	if incremental {
		c.SetAuditIncrementalVerification(24*time.Hour, 3)
		c.auditVerifyMinWidth = 1
	}
	c.SeedAuditWatermark(context.Background())
	return c
}

// assertFullPathRefusesLaunder: after the attack and a restart, the full-walk
// write path (no incremental verification) refuses, and nothing re-certifies
// the shorter chain.
func assertFullPathRefusesLaunder(t *testing.T, c *KeyorixCore, db *gorm.DB) {
	t.Helper()
	ctx := context.Background()
	before := testutil.ToFloat64(auditCheckpointTruncationRefused)

	_, _, err := c.WriteAuditCheckpoint(ctx)
	require.ErrorIs(t, err, ErrAuditCheckpointRefused, "a relabelled key_version must not re-baseline a truncated chain")
	assert.Contains(t, err.Error(), "signed audit verification state")
	assert.GreaterOrEqual(t, testutil.ToFloat64(auditCheckpointTruncationRefused)-before, float64(1))

	var n int64
	require.NoError(t, db.Model(&models.AuditCheckpoint{}).Where("key_version = ?", "v1").Count(&n).Error)
	assert.Zero(t, n, "no checkpoint was signed over the truncated chain")

	v, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.False(t, v.Valid, "the truncation stays visible")

	// The refusal is recorded as a sticky failure in the signed state.
	st, reason, err := c.loadAuditVerifyStateUnobserved(ctx)
	require.NoError(t, err)
	require.Empty(t, reason)
	require.NotNil(t, st.Failure)
	assert.Contains(t, st.Failure.Reason, "signed audit verification state")
}

// assertIncrementalPathRefusesLaunder: the scheduler tick (incremental
// verification) refuses on every tick, records the failure and reports broken.
func assertIncrementalPathRefusesLaunder(t *testing.T, c *KeyorixCore, clk *incrClock) {
	t.Helper()
	ctx := context.Background()
	for range 3 {
		clk.advance()
		res, err := c.RunAuditVerificationTick(ctx)
		require.ErrorIs(t, err, ErrAuditCheckpointRefused)
		assert.False(t, res.Written)
	}
	r := incrVerify(t, c)
	assert.Equal(t, AuditVerifyStatusBroken, r.Status, "the truncation must not read as valid: %s", r.Reason)
	st, reason, err := c.loadAuditVerifyStateUnobserved(ctx)
	require.NoError(t, err)
	require.Empty(t, reason)
	require.NotNil(t, st.Failure, "the refusal is a recorded break")

	v, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.False(t, v.Valid)
}

func newLaunderSQLite(t *testing.T) (*KeyorixCore, *gorm.DB, *incrClock) {
	t.Helper()
	return newIncrementalTestCore(t, 3)
}

func TestAuditCheckpointLaunder_FullPathRefuses(t *testing.T) {
	t.Parallel()
	c, db, clk := newLaunderSQLite(t)
	launderCertify(t, c, clk)
	launderAttack(t, db)
	assertFullPathRefusesLaunder(t, restartCore(t, c.storage.(*store.LocalStorage), clk, false), db)
}

func TestAuditCheckpointLaunder_IncrementalPathRefuses(t *testing.T) {
	t.Parallel()
	c, db, clk := newLaunderSQLite(t)
	launderCertify(t, c, clk)
	launderAttack(t, db)
	assertIncrementalPathRefusesLaunder(t, restartCore(t, c.storage.(*store.LocalStorage), clk, true), clk)
}

// After the truncation, ordinary activity appends events until the live count
// passes the certified one again. A count-only floor would then let the
// re-baseline through; the signed state also pins the certified head row.
func TestAuditCheckpointLaunder_RefusedAfterCountRecovers(t *testing.T) {
	t.Parallel()
	c, db, clk := newLaunderSQLite(t)
	launderCertify(t, c, clk)
	launderAttack(t, db)
	c2 := restartCore(t, c.storage.(*store.LocalStorage), clk, false)
	logIncrEvents(t, c2, clk, 8) // 12 live events > 10 certified
	_, _, err := c2.WriteAuditCheckpoint(context.Background())
	require.ErrorIs(t, err, ErrAuditCheckpointRefused)
	assert.Contains(t, err.Error(), "#10")
}

// Variant through the tail-check write path: the actor deletes checkpoint #2
// (leaving the authentic #1 at 6 events), truncates to 6 and relabels the
// mark. The tail check from #1 then sees exactly what #1 certified.
func TestAuditCheckpointLaunder_TailPathRefusesAfterNewerCheckpointsDeleted(t *testing.T) {
	t.Parallel()
	c, db, clk := newLaunderSQLite(t)
	launderCertify(t, c, clk)
	require.NoError(t, db.Exec("DELETE FROM audit_events WHERE id > 6").Error)
	require.NoError(t, db.Exec("DELETE FROM audit_checkpoints WHERE id > 1").Error)
	relabelHighWater(t, db)

	c2 := restartCore(t, c.storage.(*store.LocalStorage), clk, true)
	clk.advance()
	_, err := c2.RunAuditVerificationTick(context.Background())
	require.ErrorIs(t, err, ErrAuditCheckpointRefused)
	assert.Equal(t, AuditVerifyStatusBroken, incrVerify(t, c2).Status)
}

func newLaunderPG(t *testing.T) (*KeyorixCore, *gorm.DB, *incrClock, string) {
	t.Helper()
	dsn := pgIsolatedSchemaDSN(t, pgTestDSN(t))
	db := pgOpen(t, dsn)
	require.NoError(t, db.AutoMigrate(
		&models.AuditEvent{}, &models.AuditCheckpoint{}, &models.SystemMetadata{}, &models.LegalHold{},
	))
	clk := &incrClock{t: time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)}
	return newIncrementalPGReplica(t, dsn, clk), db, clk, dsn
}

func TestAuditCheckpointLaunder_FullPathRefuses_Postgres(t *testing.T) {
	t.Parallel()
	c, db, clk, dsn := newLaunderPG(t)
	launderCertify(t, c, clk)
	launderAttack(t, db)
	// The restarted process has its own connection pool.
	assertFullPathRefusesLaunder(t, restartCore(t, store.NewLocalStorage(pgOpen(t, dsn)), clk, false), db)
}

func TestAuditCheckpointLaunder_IncrementalPathRefuses_Postgres(t *testing.T) {
	t.Parallel()
	c, db, clk, dsn := newLaunderPG(t)
	launderCertify(t, c, clk)
	launderAttack(t, db)
	assertIncrementalPathRefusesLaunder(t, restartCore(t, store.NewLocalStorage(pgOpen(t, dsn)), clk, true), clk)
}

// rotate-kek regression: rotate-kek (encryptionops.RotateKEKWithConfig) writes
// nothing to the database, so after it every audit artifact — checkpoints,
// high-water mark, verification state — is signed under the old key. The
// first tick under the new key must still re-baseline (full path and
// incremental path), and the trail must verify afterwards. Simulated with
// SetAuditCheckpointKey, as TestAuditCheckpoint_RotationRebaselines does: the
// server wires the new KEK-derived key at startup.
func TestAuditCheckpointLaunder_KeyRotationStillRebaselines(t *testing.T) {
	t.Parallel()
	rotated := func(t *testing.T, s *store.LocalStorage, clk *incrClock, incremental bool) *KeyorixCore {
		c := restartCore(t, s, clk, incremental)
		c.SetAuditCheckpointKey([]byte("rotated-key-32-bytes-long-------"), "v2")
		return c
	}
	t.Run("full", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		c, _, clk := newLaunderSQLite(t)
		launderCertify(t, c, clk)
		c2 := rotated(t, c.storage.(*store.LocalStorage), clk, false)
		cp, written, err := c2.WriteAuditCheckpoint(ctx)
		require.NoError(t, err, "a key change must still re-baseline")
		require.True(t, written)
		assert.Equal(t, "v2", cp.KeyVersion)
		assert.Equal(t, int64(10), cp.ChainedEvents)
		v, err := c2.VerifyAuditChain(ctx)
		require.NoError(t, err)
		assert.True(t, v.Valid, v.Reason)
	})
	t.Run("incremental", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		c, _, clk := newLaunderSQLite(t)
		launderCertify(t, c, clk)
		c2 := rotated(t, c.storage.(*store.LocalStorage), clk, true)
		clk.advance()
		logIncrEvents(t, c2, clk, 2)
		res, err := c2.RunAuditVerificationTick(ctx)
		require.NoError(t, err, "a key change must still re-baseline")
		require.True(t, res.Written)
		assert.Equal(t, "v2", res.Checkpoint.KeyVersion)
		// Later ticks extend the new checkpoint by the tail check.
		for range 3 {
			clk.advance()
			logIncrEvents(t, c2, clk, 1)
			res, err = c2.RunAuditVerificationTick(ctx)
			require.NoError(t, err)
			require.True(t, res.Written)
		}
		assert.Equal(t, AuditVerifyStatusValid, incrVerify(t, c2).Status)
		v, err := c2.VerifyAuditChain(ctx)
		require.NoError(t, err)
		assert.True(t, v.Valid, v.Reason)
	})
}

// A save that starts from an untrusted load (here the actor inserted a junk
// checkpoint row with a higher id, so the authentic row reads as a replay)
// must not drop the pin: the next save carries the stored row's pin forward.
// Without that carry the count would survive through Bind.HighWater, but the
// head pin — what TestAuditCheckpointLaunder_RefusedAfterCountRecovers needs —
// would be lost.
func TestAuditCheckpointLaunder_PinSurvivesUntrustedSave(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db, clk := newLaunderSQLite(t)
	launderCertify(t, c, clk)
	require.NoError(t, db.Exec("INSERT INTO audit_checkpoints (id, chained_events, head_id, head_hash, key_version, signature, created_at) VALUES (99, 0, 0, '', 'forged', 'x', CURRENT_TIMESTAMP)").Error)

	c2 := restartCore(t, c.storage.(*store.LocalStorage), clk, true)
	_, reason, err := c2.loadAuditVerifyStateUnobserved(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, reason, "precondition: the authentic row reads as untrusted")
	require.NoError(t, c2.updateAuditVerifyState(ctx, func(*auditVerifyState) *auditVerifyFailure { return nil }))

	pin, err := c2.signedAuditVerifyPin(ctx)
	require.NoError(t, err)
	require.NotNil(t, pin)
	assert.Equal(t, int64(10), pin.Events)
	assert.Equal(t, uint(10), pin.HeadID, "the head pin survives a save from an untrusted load")
}
