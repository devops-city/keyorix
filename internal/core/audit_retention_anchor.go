// audit_retention_anchor.go — chain re-anchor for retention-purge compatibility
// (ADR-029).
//
// The audit hash chain (local_audit_chain.go) always starts at auditGenesisHash
// — the true first-ever row. Once a retention purge (PurgeAuditLogs) hard-
// deletes the earliest rows, the new earliest surviving row still carries a
// real prev_hash pointing at its now-deleted predecessor, so a bare re-walk
// from genesis reports a broken chain forever — indistinguishable from real
// tampering, and permanently disabling both VerifyAuditChain and
// WriteAuditCheckpoint (which refuses to sign over a broken chain).
//
// A retention anchor closes that gap: it records that a purge was sanctioned by
// persisting the new earliest surviving row's id/prev_hash/entry_hash, HMAC-
// signed with the same checkpoint signing key (KEK-derived, held in memory by
// this process only — the database/DBA does not have it, mirroring
// audit_checkpoint.go's own signing key). A DB-level actor cannot forge an
// anchor claiming an arbitrary gap is fine: without the key, any forged value
// fails signature verification and is ignored, and the walk then requires
// genesis again — the existing, safe (if inconvenient) failure mode.
//
// Persisted as a SINGLE overwritten system_metadata row (like the high-water
// mark, auditHighWaterKey) — it always reflects the earliest surviving row as
// of the MOST RECENT purge that reached into the chained (post-ADR-029)
// region, so an older anchor can never be replayed to claim a LARGER surviving
// prefix than what a subsequent purge actually left: any mismatch between the
// anchor's claimed row and the live earliest row is reported as a broken
// chain (see local_audit_chain.go's VerifyAuditChain), never silently trusted.
//
// Purged count (#3257, layout v2): the anchor also carries purged_events, the
// cumulative number of CHAINED rows removed by sanctioned purges, covered by
// the same HMAC and written in the same transaction as the DELETE. Checkpoints
// certify chained + purged, and the checkpoint/high-water checks compare the
// live chained count plus this number against the certified one, so a purge
// below a certified count is not reported as truncation while any removal the
// anchor does not cover still is. A v1 anchor (written before #3257) has no
// count and authenticates as purged = 0 — the pre-#3257 behaviour.
package core

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// auditRetentionAnchorKey is the system_metadata key holding the signed
// retention re-anchor.
const auditRetentionAnchorKey = "audit_retention_anchor" // #nosec G101 -- metadata key name, not a credential

// auditRetentionAnchorSep separates fields in the persisted value. Must not be
// "\x00": PostgreSQL text/varchar columns reject an embedded NUL byte outright
// (see auditHighWaterSep's doc comment for the same constraint on the
// high-water mark, which this mirrors).
const auditRetentionAnchorSep = "\x1f"

// auditRetentionAnchorCanonical is the exact byte string signed/verified for a
// retention anchor. The "retanchor-v1" prefix domain-separates it from
// checkpointCanonical and auditHighWaterValue's own layouts — an HMAC valid for
// one of those must never also verify as a valid retention anchor, or vice
// versa, even though all three share the same underlying signing key.
func auditRetentionAnchorCanonical(rowID uint, prevHash, entryHash, keyVersion string) string {
	return fmt.Sprintf("retanchor-v1\x00%d\x00%s\x00%s\x00%s", rowID, prevHash, entryHash, keyVersion)
}

// auditRetentionAnchorCanonicalV2 is the signed byte string of a v2 anchor:
// v1's fields plus the cumulative purged count. Its own "retanchor-v2" prefix
// keeps the two layouts apart, so a v2 signature never verifies as a v1 anchor
// (which would drop the count) and a v1 signature never verifies as a v2
// anchor with a count the signer never saw.
func auditRetentionAnchorCanonicalV2(rowID uint, prevHash, entryHash string, purged int64, keyVersion string) string {
	return fmt.Sprintf("retanchor-v2\x00%d\x00%s\x00%s\x00%d\x00%s", rowID, prevHash, entryHash, purged, keyVersion)
}

// signRetentionAnchorWithVersion computes the HMAC over the anchor fields under
// the given key_version label (not necessarily the current one — see
// loadAuditRetentionAnchor, which recomputes under a STORED key_version purely
// to tell an actual tamper apart from a stale anchor left by a signing-key
// rotation; either way c.auditCkptKey is the only key bytes this process has).
func (c *KeyorixCore) signRetentionAnchorWithVersion(rowID uint, prevHash, entryHash, keyVersion string) string {
	mac := hmac.New(sha256.New, c.auditCkptKey)
	mac.Write([]byte(auditRetentionAnchorCanonical(rowID, prevHash, entryHash, keyVersion)))
	return hex.EncodeToString(mac.Sum(nil))
}

// signRetentionAnchorV2WithVersion is the v2 counterpart of
// signRetentionAnchorWithVersion.
func (c *KeyorixCore) signRetentionAnchorV2WithVersion(rowID uint, prevHash, entryHash string, purged int64, keyVersion string) string {
	mac := hmac.New(sha256.New, c.auditCkptKey)
	mac.Write([]byte(auditRetentionAnchorCanonicalV2(rowID, prevHash, entryHash, purged, keyVersion)))
	return hex.EncodeToString(mac.Sum(nil))
}

// signRetentionAnchorV2 signs a fresh v2 anchor under the CURRENT signing
// key/version.
func (c *KeyorixCore) signRetentionAnchorV2(rowID uint, prevHash, entryHash string, purged int64) string {
	return c.signRetentionAnchorV2WithVersion(rowID, prevHash, entryHash, purged, c.auditCkptKeyVersion)
}

// auditRetentionAnchorValue serializes a v1 (pre-#3257, no purged count)
// retention anchor. Nothing writes this layout any more; it is kept so tests
// can produce the value an older server left behind.
func auditRetentionAnchorValue(rowID uint, prevHash, entryHash, keyVersion, sig string) string {
	return strings.Join([]string{
		"v1",
		strconv.FormatUint(uint64(rowID), 10),
		prevHash,
		entryHash,
		keyVersion,
		sig,
	}, auditRetentionAnchorSep)
}

// auditRetentionAnchorValueV2 serializes a v2 retention anchor (with the
// cumulative purged count) for persistence via SetSystemMetadata.
func auditRetentionAnchorValueV2(rowID uint, prevHash, entryHash string, purged int64, keyVersion, sig string) string {
	return strings.Join([]string{
		"v2",
		strconv.FormatUint(uint64(rowID), 10),
		prevHash,
		entryHash,
		strconv.FormatInt(purged, 10),
		keyVersion,
		sig,
	}, auditRetentionAnchorSep)
}

// storedRetentionAnchor is a parsed, NOT yet authenticated anchor value.
type storedRetentionAnchor struct {
	layout     string // "v1" or "v2"
	rowID      uint
	prevHash   string
	entryHash  string
	purged     int64 // always 0 for v1
	keyVersion string
	sig        string
}

// parseAuditRetentionAnchor parses a stored value (v1 or v2 layout) back into
// its fields. ok is false on any malformed value (treated as "no anchor"),
// including a negative purged count.
func parseAuditRetentionAnchor(val string) (a storedRetentionAnchor, ok bool) {
	parts := strings.Split(val, auditRetentionAnchorSep)
	switch {
	case len(parts) == 6 && parts[0] == "v1":
		a = storedRetentionAnchor{layout: "v1", prevHash: parts[2], entryHash: parts[3], keyVersion: parts[4], sig: parts[5]}
	case len(parts) == 7 && parts[0] == "v2":
		purged, err := strconv.ParseInt(parts[4], 10, 64)
		if err != nil || purged < 0 {
			return storedRetentionAnchor{}, false
		}
		a = storedRetentionAnchor{layout: "v2", prevHash: parts[2], entryHash: parts[3], purged: purged, keyVersion: parts[5], sig: parts[6]}
	default:
		return storedRetentionAnchor{}, false
	}
	id, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil || id == 0 {
		return storedRetentionAnchor{}, false
	}
	a.rowID = uint(id)
	return a, true
}

// expectedRetentionAnchorSig recomputes the signature a's own layout calls
// for, under a's stored key_version.
func (c *KeyorixCore) expectedRetentionAnchorSig(a storedRetentionAnchor) string {
	if a.layout == "v1" {
		return c.signRetentionAnchorWithVersion(a.rowID, a.prevHash, a.entryHash, a.keyVersion)
	}
	return c.signRetentionAnchorV2WithVersion(a.rowID, a.prevHash, a.entryHash, a.purged, a.keyVersion)
}

// persistAuditRetentionAnchor signs and stores a fresh retention anchor for the
// given new-earliest-surviving row. Called by PurgeAuditLogs INSIDE the same
// transaction as the delete (via tx, the transaction-scoped storage.Storage)
// whenever DeleteAuditLogsBefore reports the purge reached into the chained
// (post-ADR-029) region — see its doc comment. A no-op (logged, not fatal) when
// no signing key is configured: without a key, no marker could be authenticated
// anyway (see AuditCheckpointsAvailable), so writing an unsigned one would only
// create a plain, DB-forgeable marker — worse than no marker at all.
//
// purged is the CUMULATIVE chained-events count to sign into the anchor (the
// caller adds this purge's count to the previous authenticated anchor's).
func (c *KeyorixCore) persistAuditRetentionAnchor(ctx context.Context, tx storage.Storage, rowID uint, prevHash, entryHash string, purged int64) error {
	if !c.AuditCheckpointsAvailable() {
		log.Printf("audit retention: purge reached into the chained region but no checkpoint signing key is configured — the audit chain will not verify past this purge until encryption is enabled and a subsequent purge re-anchors it")
		return nil
	}
	sig := c.signRetentionAnchorV2(rowID, prevHash, entryHash, purged)
	val := auditRetentionAnchorValueV2(rowID, prevHash, entryHash, purged, c.auditCkptKeyVersion, sig)
	return tx.SetSystemMetadata(ctx, auditRetentionAnchorKey, val)
}

// loadAuditRetentionAnchor reads and authenticates the current retention
// anchor, returning nil when none exists, it fails to parse, or its signature
// does not verify — either genuine tampering, or a stale anchor left by a
// signing-key rotation (a KEK-provider migration; we hold only the CURRENT key,
// so an anchor signed under a superseded one can never be re-verified here).
// Either way it is safest to ignore an unverifiable anchor rather than trust
// it: the walk then requires genesis and correctly reports the trail broken
// until a fresh purge re-anchors it under the current key — never silently
// treats an unauthenticated value as a valid seed point. Only a genuine storage
// failure reading it is returned as an error.
//
// The returned anchor's PurgedEvents is the authenticated cumulative purged
// count (0 for a v1 anchor). An ignored anchor contributes no purged count, so
// an unverifiable value can only make the checkpoint checks stricter.
func (c *KeyorixCore) loadAuditRetentionAnchor(ctx context.Context) (*storage.AuditChainAnchor, error) {
	return c.loadAuditRetentionAnchorFrom(ctx, c.storage)
}

// loadAuditRetentionAnchorFrom is loadAuditRetentionAnchor reading through st
// (the transaction-scoped storage inside PurgeAuditLogs).
func (c *KeyorixCore) loadAuditRetentionAnchorFrom(ctx context.Context, st storage.Storage) (*storage.AuditChainAnchor, error) {
	if !c.AuditCheckpointsAvailable() {
		return nil, nil
	}
	val, ok, err := st.GetSystemMetadata(ctx, auditRetentionAnchorKey)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	a, parsed := parseAuditRetentionAnchor(val)
	if !parsed {
		log.Printf("audit retention anchor is malformed — ignoring it")
		return nil, nil
	}
	if !hmac.Equal([]byte(c.expectedRetentionAnchorSig(a)), []byte(a.sig)) {
		if a.keyVersion == c.auditCkptKeyVersion {
			log.Printf("audit retention anchor fails its signature under the current key version %q — ignoring it (the marker was tampered with; chain verification requires genesis and will report broken until a fresh purge re-anchors it)", a.keyVersion)
		} else {
			log.Printf("audit retention anchor is signed under a superseded key version %q — ignoring it (a KEK-provider migration likely occurred; a fresh retention purge re-anchors it under the current key)", a.keyVersion)
		}
		return nil, nil
	}
	return &storage.AuditChainAnchor{RowID: a.rowID, PrevHash: a.prevHash, EntryHash: a.entryHash, PurgedEvents: a.purged}, nil
}

// anchorPurgedEvents returns an authenticated anchor's cumulative purged count,
// or 0 when there is no (authenticated) anchor.
func anchorPurgedEvents(a *storage.AuditChainAnchor) int64 {
	if a == nil {
		return 0
	}
	return a.PurgedEvents
}
