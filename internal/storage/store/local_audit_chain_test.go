package store

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func newAuditChainTestStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}))
	return NewLocalStorage(db)
}

func appendEvent(t *testing.T, ls *LocalStorage, eventType, desc string, at time.Time) *models.AuditEvent {
	t.Helper()
	tr := true
	e := &models.AuditEvent{
		EventType: eventType, Description: desc, Success: &tr,
		EventTime: at, ActorType: "user",
	}
	require.NoError(t, ls.LogAuditEvent(context.Background(), e))
	return e
}

func TestLogAuditEvent_BuildsChain(t *testing.T) {
	ls := newAuditChainTestStore(t)
	base := time.Now().UTC()

	e1 := appendEvent(t, ls, "auth.login", "first", base)
	e2 := appendEvent(t, ls, "secret.read", "second", base.Add(time.Second))
	e3 := appendEvent(t, ls, "secret.updated", "third", base.Add(2*time.Second))

	// First event anchors to the genesis hash; each subsequent prev_hash is the
	// previous entry_hash.
	assert.Equal(t, auditGenesisHash, e1.PrevHash)
	assert.NotEmpty(t, e1.EntryHash)
	assert.Equal(t, e1.EntryHash, e2.PrevHash)
	assert.Equal(t, e2.EntryHash, e3.PrevHash)
	assert.NotEqual(t, e1.EntryHash, e2.EntryHash)

	v, err := ls.VerifyAuditChain(context.Background(), nil)
	require.NoError(t, err)
	assert.True(t, v.Valid)
	assert.Equal(t, int64(3), v.ChainedEvents)
	assert.Equal(t, int64(0), v.UnchainedEvents)
	assert.Nil(t, v.FirstBrokenID)
}

// The verifier exposes the chain head so an external monitor can anchor on it. A
// tail-truncation leaves a self-consistent shorter chain that on-box verify still
// accepts (the documented ADR-029 limitation) — but the head hash and count change,
// which is the off-box tamper signal.
func TestVerifyAuditChain_HeadAnchorDetectsTruncation(t *testing.T) {
	ls := newAuditChainTestStore(t)
	base := time.Now().UTC()
	appendEvent(t, ls, "auth.login", "first", base)
	appendEvent(t, ls, "secret.read", "second", base.Add(time.Second))
	e3 := appendEvent(t, ls, "secret.updated", "third", base.Add(2*time.Second))

	v, err := ls.VerifyAuditChain(context.Background(), nil)
	require.NoError(t, err)
	require.True(t, v.Valid)
	assert.Equal(t, int64(3), v.ChainedEvents)
	assert.Equal(t, e3.EntryHash, v.HeadHash, "head anchors on the last chained event")
	assert.Equal(t, e3.ID, v.HeadID)

	// A DB-writer truncates the tail. On-box verify still passes…
	require.NoError(t, ls.db.Where("id = ?", e3.ID).Delete(&models.AuditEvent{}).Error)
	v2, err := ls.VerifyAuditChain(context.Background(), nil)
	require.NoError(t, err)
	assert.True(t, v2.Valid, "truncated chain stays internally consistent (the documented limitation)")
	// …but the recorded anchor moved — the count dropped and the head changed.
	assert.Equal(t, int64(2), v2.ChainedEvents)
	assert.NotEqual(t, v.HeadHash, v2.HeadHash)
}

func TestVerifyAuditChain_DetectsModification(t *testing.T) {
	ls := newAuditChainTestStore(t)
	base := time.Now().UTC()
	appendEvent(t, ls, "auth.login", "first", base)
	e2 := appendEvent(t, ls, "secret.read", "second", base.Add(time.Second))
	appendEvent(t, ls, "secret.updated", "third", base.Add(2*time.Second))

	// Tamper: rewrite a field directly, leaving the stored hash stale.
	require.NoError(t, ls.db.Model(&models.AuditEvent{}).
		Where("id = ?", e2.ID).
		Update("description", "TAMPERED").Error)

	v, err := ls.VerifyAuditChain(context.Background(), nil)
	require.NoError(t, err)
	assert.False(t, v.Valid)
	require.NotNil(t, v.FirstBrokenID)
	assert.Equal(t, e2.ID, *v.FirstBrokenID)
	assert.Contains(t, v.Reason, "modified")
	// One clean event verified before the break.
	assert.Equal(t, int64(1), v.ChainedEvents)
}

func TestVerifyAuditChain_DetectsDeletion(t *testing.T) {
	ls := newAuditChainTestStore(t)
	base := time.Now().UTC()
	appendEvent(t, ls, "auth.login", "first", base)
	e2 := appendEvent(t, ls, "secret.read", "second", base.Add(time.Second))
	e3 := appendEvent(t, ls, "secret.updated", "third", base.Add(2*time.Second))

	// Delete a middle event; e3's prev_hash now links to a vanished entry.
	require.NoError(t, ls.db.Delete(&models.AuditEvent{}, e2.ID).Error)

	v, err := ls.VerifyAuditChain(context.Background(), nil)
	require.NoError(t, err)
	assert.False(t, v.Valid)
	require.NotNil(t, v.FirstBrokenID)
	assert.Equal(t, e3.ID, *v.FirstBrokenID, "break surfaces at the row after the deleted one")
	assert.Contains(t, v.Reason, "link")
}

func TestVerifyAuditChain_LegacyPrefix(t *testing.T) {
	ls := newAuditChainTestStore(t)
	base := time.Now().UTC()

	// Two pre-ADR-029 rows: inserted raw with empty hashes.
	tr := true
	for i, d := range []string{"legacy-1", "legacy-2"} {
		require.NoError(t, ls.db.Create(&models.AuditEvent{
			EventType: "secret.read", Description: d, Success: &tr,
			EventTime: base.Add(time.Duration(i) * time.Second), ActorType: "user",
		}).Error)
	}

	// New chained events appended afterward.
	appendEvent(t, ls, "auth.login", "chained-1", base.Add(10*time.Second))
	appendEvent(t, ls, "secret.read", "chained-2", base.Add(11*time.Second))

	v, err := ls.VerifyAuditChain(context.Background(), nil)
	require.NoError(t, err)
	assert.True(t, v.Valid)
	assert.Equal(t, int64(2), v.UnchainedEvents, "legacy rows counted, not failed")
	assert.Equal(t, int64(2), v.ChainedEvents)
}

func TestVerifyAuditChain_Empty(t *testing.T) {
	ls := newAuditChainTestStore(t)
	v, err := ls.VerifyAuditChain(context.Background(), nil)
	require.NoError(t, err)
	assert.True(t, v.Valid)
	assert.Equal(t, int64(0), v.ChainedEvents)
	assert.Equal(t, int64(0), v.UnchainedEvents)
}

func TestLogAuditEvent_ConcurrentAppendsStayChained(t *testing.T) {
	ls := newAuditChainTestStore(t)
	base := time.Now().UTC()

	const writers = 8
	const perWriter = 25
	var wg sync.WaitGroup
	wg.Add(writers)
	for w := range writers {
		go func(w int) {
			defer wg.Done()
			tr := true
			for i := range perWriter {
				e := &models.AuditEvent{
					EventType: "secret.read", Description: "concurrent", Success: &tr,
					EventTime: base.Add(time.Duration(w*perWriter+i) * time.Millisecond),
					ActorType: "user",
				}
				// Serialized internally; concurrent callers must not corrupt the chain.
				require.NoError(t, ls.LogAuditEvent(context.Background(), e))
			}
		}(w)
	}
	wg.Wait()

	v, err := ls.VerifyAuditChain(context.Background(), nil)
	require.NoError(t, err)
	assert.True(t, v.Valid, "chain intact under concurrent writers: %s", v.Reason)
	assert.Equal(t, int64(writers*perWriter), v.ChainedEvents)
}

// An event written with ActorType left empty (as the sharing/impersonation audit
// helpers do) must still verify: LogAuditEvent normalizes it to the column default
// ("user") BEFORE hashing, so the hashed value matches the row GORM persists. Without
// that normalization the hash is taken over "" while the stored row holds "user", and
// VerifyAuditChain false-fails an untampered chain at the first such event.
func TestLogAuditEvent_EmptyActorTypeStillVerifies(t *testing.T) {
	ls := newAuditChainTestStore(t)
	base := time.Now().UTC()
	tr := true

	// A normal event, then one with ActorType deliberately unset (the share path).
	require.NoError(t, ls.LogAuditEvent(context.Background(), &models.AuditEvent{
		EventType: "auth.login", Description: "first", Success: &tr, EventTime: base, ActorType: "user",
	}))
	shareEvt := &models.AuditEvent{
		EventType: "share_created", Description: "shared with user 2",
		Success: &tr, EventTime: base.Add(time.Second), // ActorType intentionally empty
	}
	require.NoError(t, ls.LogAuditEvent(context.Background(), shareEvt))

	// The persisted row carries the column default, and the in-memory event was
	// pinned to the same value so its hash matches.
	assert.Equal(t, "user", shareEvt.ActorType, "empty ActorType is normalized to the stored default before hashing")
	var stored models.AuditEvent
	require.NoError(t, ls.db.First(&stored, shareEvt.ID).Error)
	assert.Equal(t, "user", stored.ActorType)

	v, err := ls.VerifyAuditChain(context.Background(), nil)
	require.NoError(t, err)
	assert.True(t, v.Valid, "chain with an empty-ActorType event must verify: %s", v.Reason)
	assert.Equal(t, int64(2), v.ChainedEvents)
	assert.Nil(t, v.FirstBrokenID)
}

func TestLogAuditEvent_NilSuccessStillVerifies(t *testing.T) {
	ls := newAuditChainTestStore(t)
	base := time.Now().UTC()
	tr := true

	// A normal event, then one with Success deliberately nil (the share path:
	// every sharing_audit.go helper leaves Success unset).
	require.NoError(t, ls.LogAuditEvent(context.Background(), &models.AuditEvent{
		EventType: "auth.login", Description: "first", Success: &tr, EventTime: base, ActorType: "user",
	}))
	shareEvt := &models.AuditEvent{
		EventType: "share_created", Description: "shared with user 2",
		EventTime: base.Add(time.Second), ActorType: "user", // Success intentionally nil
	}
	require.NoError(t, ls.LogAuditEvent(context.Background(), shareEvt))

	// The persisted row carries the column default (true), and the in-memory event
	// was pinned to the same value before hashing so its hash matches.
	require.NotNil(t, shareEvt.Success, "nil Success is normalized to the stored default before hashing")
	assert.True(t, *shareEvt.Success)
	var stored models.AuditEvent
	require.NoError(t, ls.db.First(&stored, shareEvt.ID).Error)
	require.NotNil(t, stored.Success)
	assert.True(t, *stored.Success)

	v, err := ls.VerifyAuditChain(context.Background(), nil)
	require.NoError(t, err)
	assert.True(t, v.Valid, "chain with a nil-Success event must verify: %s", v.Reason)
	assert.Equal(t, int64(2), v.ChainedEvents)
	assert.Nil(t, v.FirstBrokenID)
}

func TestComputeAuditEntryHash_Deterministic(t *testing.T) {
	at := time.Unix(1_700_000_000, 123000).UTC() // 123µs exactly
	uid := uint(7)
	tr := true
	e := &models.AuditEvent{
		EventType: "secret.read", UserID: &uid, Description: "d",
		Success: &tr, EventTime: at, ActorType: "user",
	}
	// UnixMicro encoding means sub-microsecond differences do not change the hash.
	e2 := *e
	e2.EventTime = at.Add(500 * time.Nanosecond) // stays within the same µs

	assert.Equal(t,
		computeAuditEntryHash(e, auditGenesisHash),
		computeAuditEntryHash(&e2, auditGenesisHash),
		"hash is stable across sub-microsecond timestamp jitter (Postgres µs round-trip)")
	assert.NotEqual(t,
		computeAuditEntryHash(e, auditGenesisHash),
		computeAuditEntryHash(e, "different-prev"),
		"prev_hash is bound into the entry hash")
}

// TestComputeAuditEntryHash_FieldBoundaryCollisionRejected is the regression
// test for the NUL-delimiter injectivity bug (findings-store/store-audit.json#1).
//
// IPAddress and Description are adjacent in computeAuditEntryHash's write
// order. Under the OLD scheme (each field followed by a single 0x00
// separator, no length prefix), these two field-value pairs concatenate to
// the byte-identical stream even though the field values themselves differ:
//
//	e1: IPAddress="1.2.3.4\x00evil", Description="normal"
//	    -> "1.2.3.4" 0x00 "evil" 0x00 "normal" 0x00
//	e2: IPAddress="1.2.3.4",         Description="evil\x00normal"
//	    -> "1.2.3.4" 0x00 "evil" 0x00 "normal" 0x00   (same bytes!)
//
// e2's Description simply contains the 0x00 delimiter byte itself plus the
// bytes that used to be e1's next field content — the delimiter byte inside a
// field's own value is indistinguishable from a real field boundary. A
// SQLite-backed deployment accepts an embedded NUL in a TEXT column (unlike
// Postgres), and IngestAuditEventProxy passes a caller-supplied
// models.AuditEvent straight to LogAuditEvent without the control-character
// stripping the normal emitAudit path applies — so a caller reaching that
// proxy can supply exactly this kind of value.
//
// The length-prefixed encoding must NOT collide here: the byte length of each
// field is carried out-of-band, so no field content — NUL or otherwise — can
// be mistaken for a length prefix or shift a boundary.
func TestComputeAuditEntryHash_FieldBoundaryCollisionRejected(t *testing.T) {
	tr := true
	at := time.Unix(1_700_000_000, 0).UTC()

	base := models.AuditEvent{
		EventType: "secret.read", Success: &tr, EventTime: at, ActorType: "user",
	}

	e1 := base
	e1.IPAddress = "1.2.3.4\x00evil"
	e1.Description = "normal"

	e2 := base
	e2.IPAddress = "1.2.3.4"
	e2.Description = "evil\x00normal"

	require.NotEqual(t, e1.IPAddress, e2.IPAddress, "sanity: the two events carry different IPAddress values")
	require.NotEqual(t, e1.Description, e2.Description, "sanity: the two events carry different Description values")

	h1 := computeAuditEntryHash(&e1, auditGenesisHash)
	h2 := computeAuditEntryHash(&e2, auditGenesisHash)
	assert.NotEqual(t, h1, h2,
		"logically different field values must never hash to the same entry_hash, regardless of embedded delimiter-like bytes")
}
