package auditverify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// RetentionAnchor is this package's own representation of an authenticated
// retention re-anchor point (ADR-029 / audit_retention_anchor.go): the new
// earliest surviving row's id/prev_hash/entry_hash after a purge reached
// into the chained region. Deliberately not
// internal/core/storage.AuditChainAnchor.
type RetentionAnchor struct {
	RowID     uint64
	PrevHash  string
	EntryHash string
	// PurgedEvents is the cumulative count of chained rows removed by
	// sanctioned purges, covered by the anchor's signature (v2 layout, #3257);
	// 0 for a v1 anchor.
	PurgedEvents int64
}

// auditRetentionAnchorSep matches internal/core.auditRetentionAnchorSep —
// \x1f, not \x00, for the same PostgreSQL text-column reason as the
// high-water mark.
const auditRetentionAnchorSep = "\x1f"

// retentionAnchorCanonical is the exact byte string signed/verified for a
// retention anchor. The "retanchor-v1" prefix domain-separates it from
// checkpointCanonical/the high-water layout — byte-identical
// reimplementation of internal/core.auditRetentionAnchorCanonical.
func retentionAnchorCanonical(rowID uint64, prevHash, entryHash, keyVersion string) string {
	return fmt.Sprintf("retanchor-v1\x00%d\x00%s\x00%s\x00%s", rowID, prevHash, entryHash, keyVersion)
}

// retentionAnchorCanonicalV2 is the signed byte string of a v2 anchor (with
// the cumulative purged count) — byte-identical reimplementation of
// internal/core.auditRetentionAnchorCanonicalV2. Its "retanchor-v2" prefix
// domain-separates it from the v1 layout.
func retentionAnchorCanonicalV2(rowID uint64, prevHash, entryHash string, purged int64, keyVersion string) string {
	return fmt.Sprintf("retanchor-v2\x00%d\x00%s\x00%s\x00%d\x00%s", rowID, prevHash, entryHash, purged, keyVersion)
}

// SignRetentionAnchorV2 computes the hex HMAC-SHA256 over a v2 anchor's fields
// — mirrors internal/core.signRetentionAnchorV2WithVersion.
func SignRetentionAnchorV2(rowID uint64, prevHash, entryHash string, purged int64, keyVersion string, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(retentionAnchorCanonicalV2(rowID, prevHash, entryHash, purged, keyVersion)))
	return hex.EncodeToString(mac.Sum(nil))
}

// StoredRetentionAnchor is a parsed, not yet authenticated retention anchor
// value in either layout.
type StoredRetentionAnchor struct {
	Layout       string // "v1" or "v2"
	RowID        uint64
	PrevHash     string
	EntryHash    string
	PurgedEvents int64 // always 0 for v1
	KeyVersion   string
	Signature    string
}

// ParseRetentionAnchorValue parses a stored "audit_retention_anchor" value in
// the v1 or v2 layout. ok is false on any malformed value (treated as "no
// anchor"), including a negative purged count — same contract as
// internal/core.parseAuditRetentionAnchor.
func ParseRetentionAnchorValue(val string) (StoredRetentionAnchor, bool) {
	parts := strings.Split(val, auditRetentionAnchorSep)
	if len(parts) == 6 && parts[0] == "v1" {
		rowID, prevHash, entryHash, keyVersion, sig, ok := ParseRetentionAnchor(val)
		if !ok {
			return StoredRetentionAnchor{}, false
		}
		return StoredRetentionAnchor{Layout: "v1", RowID: rowID, PrevHash: prevHash, EntryHash: entryHash,
			KeyVersion: keyVersion, Signature: sig}, true
	}
	if len(parts) != 7 || parts[0] != "v2" {
		return StoredRetentionAnchor{}, false
	}
	id, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil || id == 0 {
		return StoredRetentionAnchor{}, false
	}
	purged, err := strconv.ParseInt(parts[4], 10, 64)
	if err != nil || purged < 0 {
		return StoredRetentionAnchor{}, false
	}
	return StoredRetentionAnchor{Layout: "v2", RowID: id, PrevHash: parts[2], EntryHash: parts[3],
		PurgedEvents: purged, KeyVersion: parts[5], Signature: parts[6]}, true
}

// SigMatches reports whether a's signature is the valid HMAC, under key, over
// the canonical bytes of a's own layout.
func (a StoredRetentionAnchor) SigMatches(key []byte) bool {
	if a.Layout == "v1" {
		return RetentionAnchorSigMatches(a.RowID, a.PrevHash, a.EntryHash, a.KeyVersion, a.Signature, key)
	}
	computed := SignRetentionAnchorV2(a.RowID, a.PrevHash, a.EntryHash, a.PurgedEvents, a.KeyVersion, key)
	return hmac.Equal([]byte(computed), []byte(a.Signature))
}

// SignRetentionAnchor computes the hex HMAC-SHA256 over the v1 anchor fields
// under the given key/keyVersion — mirrors
// internal/core.signRetentionAnchorWithVersion.
func SignRetentionAnchor(rowID uint64, prevHash, entryHash, keyVersion string, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(retentionAnchorCanonical(rowID, prevHash, entryHash, keyVersion)))
	return hex.EncodeToString(mac.Sum(nil))
}

// ParseRetentionAnchor parses a v1-layout (pre-#3257) stored
// "audit_retention_anchor" value into its fields; ok is false on any other
// value. Use ParseRetentionAnchorValue for a value in either layout.
func ParseRetentionAnchor(val string) (rowID uint64, prevHash, entryHash, keyVersion, sig string, ok bool) {
	parts := strings.Split(val, auditRetentionAnchorSep)
	if len(parts) != 6 || parts[0] != "v1" {
		return 0, "", "", "", "", false
	}
	id, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil || id == 0 {
		return 0, "", "", "", "", false
	}
	return id, parts[2], parts[3], parts[4], parts[5], true
}

// RetentionAnchorSigMatches reports whether sig is the valid HMAC over the v1
// anchor fields under key/keyVersion.
func RetentionAnchorSigMatches(rowID uint64, prevHash, entryHash, keyVersion, sig string, key []byte) bool {
	computed := SignRetentionAnchor(rowID, prevHash, entryHash, keyVersion, key)
	return hmac.Equal([]byte(computed), []byte(sig))
}
