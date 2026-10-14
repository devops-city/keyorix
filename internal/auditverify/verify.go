package auditverify

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/notary"
)

// auditHighWaterKey/auditRetentionAnchorKey must byte-for-byte match the
// system_metadata keys internal/core writes under (auditHighWaterKey,
// auditRetentionAnchorKey) — a differential test asserts that.
const (
	auditHighWaterKey       = "audit_checkpoint_highwater"
	auditRetentionAnchorKey = "audit_retention_anchor"
)

// DefaultBatchSize matches internal/storage/store's auditChainVerifyBatch —
// the same shape, not necessarily the same number, but keeping it identical
// means a rows/sec comparison between the online and offline verifiers is
// apples-to-apples.
const DefaultBatchSize = 1000

// Verdict is the top-level result of an offline verification run.
type Verdict string

const (
	// VerdictValid means the chain re-walked cleanly and every check this
	// run was able to perform (given the inputs it was handed) passed. It
	// does NOT mean "no tampering is possible" — see Result.NotProven.
	VerdictValid Verdict = "VALID"
	// VerdictBroken means tamper evidence was found: a modified row, a
	// broken linkage, a certified checkpoint/high-water regression, or an
	// anchor that fails to authenticate.
	VerdictBroken Verdict = "BROKEN"
	// VerdictIndeterminate means the chain re-walks internally consistently
	// from a given point forward, but this run could not authenticate
	// something it needed to in order to rule out tampering — most notably
	// a retention gap with no usable checkpoint key. This is deliberately
	// distinct from both VALID and BROKEN: reporting it as either would be
	// a false alarm or a false assurance (design §5).
	VerdictIndeterminate Verdict = "INDETERMINATE"
)

// verdictRank orders verdicts by severity so escalate() only ever moves a
// Result toward the more severe finding, regardless of check order.
var verdictRank = map[Verdict]int{
	VerdictValid:         0,
	VerdictIndeterminate: 1,
	VerdictBroken:        2,
}

// Range bounds the audit_events rows this run actually walked.
type Range struct {
	FromID   uint64    `json:"from_id"`
	ToID     uint64    `json:"to_id"`
	FromTime time.Time `json:"from_time"`
	ToTime   time.Time `json:"to_time"`
}

// CheckpointStatus reports what this run found for the latest
// audit_checkpoints row.
type CheckpointStatus struct {
	Present                bool   `json:"present"`
	Authenticated          bool   `json:"authenticated"` // signature checked and valid under a supplied key
	KeyVersion             string `json:"key_version,omitempty"`
	ChainedEventsCertified int64  `json:"chained_events_certified,omitempty"`
}

// RetentionGapStatus reports whether the chained region's earliest
// surviving row carries a non-genesis prev_hash (i.e. rows before it were
// removed, sanctioned or not).
type RetentionGapStatus struct {
	Present       bool   `json:"present"`
	RowID         uint64 `json:"row_id,omitempty"`
	Authenticated bool   `json:"authenticated"` // an authenticated retention anchor confirmed this gap
	Sanctioned    bool   `json:"sanctioned"`    // Present && Authenticated
}

// AnchorStatus reports the external-notary (RFC 3161) receipt on the latest
// checkpoint, if any.
type AnchorStatus struct {
	Present    bool      `json:"present"`
	Verified   bool      `json:"verified"`
	Provider   string    `json:"provider,omitempty"`
	AnchoredAt time.Time `json:"anchored_at"`
}

// ExternalAnchorStatus reports what this run did with an Options.
// ExternalAnchor bundle, if one was supplied. This is a DISTINCT anchor from
// AnchorStatus above (which only ever reflects the in-DB checkpoint's own
// RFC 3161 receipt) — a bundle supplied via `--anchor` is a copy held
// outside this host's blast radius (design §2/§3), and its authentication
// outcome must never be conflated with the in-DB checkpoint's.
type ExternalAnchorStatus struct {
	Supplied      bool `json:"supplied"`
	Authenticated bool `json:"authenticated"`
}

// Result is the verdict of one offline verification run. Its JSON shape
// mirrors internal/core/storage.AuditChainVerification's fields (design §7)
// so a compliance pack or dashboard can render either source with one
// renderer.
type Result struct {
	Verdict Verdict `json:"verdict"`
	Reason  string  `json:"reason,omitempty"`

	Range                 Range   `json:"range"`
	ChainedEvents         int64   `json:"chained_events"`
	UnchainedLegacyEvents int64   `json:"unchained_legacy_events"`
	FirstBrokenID         *uint64 `json:"first_broken_id,omitempty"`

	Checkpoint     CheckpointStatus     `json:"checkpoint"`
	RetentionGap   RetentionGapStatus   `json:"retention_gap"`
	Anchor         AnchorStatus         `json:"anchor"`
	ExternalAnchor ExternalAnchorStatus `json:"external_anchor"`

	// AnchorSource records how this run resolved its Options.ExternalAnchor
	// bundle: "flag" (the caller's --anchor was passed explicitly), "config
	// (audit.offline_anchor_path)" (resolved from config because --anchor was
	// not passed), or "none" (no anchor bundle was resolved from either).
	// Set by the caller (server/admin/audit_verify.go's resolveOfflineAnchor)
	// after Verify returns -- this package has no notion of flags or config,
	// only of the bundle it was handed (design §10 Q5 addendum: reviewers of
	// #2084 asked the report to disclose which source served the anchor, not
	// just whether one was authenticated).
	AnchorSource string `json:"anchor_source,omitempty"`

	// NotProven states, in plain language, what this specific run — given
	// the inputs it was handed — does NOT establish. Always non-empty: even
	// a fully-authenticated VALID run cannot rule out a host admin who holds
	// both the database and the checkpoint signing key (design §2). A
	// compliance tool that omits this is overstating what it proves.
	NotProven []string `json:"not_proven"`

	GeneratedAt     time.Time `json:"generated_at"`
	VerifierVersion string    `json:"verifier_version"`
}

// escalate raises r's verdict to v (with reason) only if v outranks the
// current verdict — BROKEN always wins over INDETERMINATE, which always
// wins over VALID, regardless of which check ran first.
func (r *Result) escalate(v Verdict, reason string) {
	if verdictRank[v] > verdictRank[r.Verdict] {
		r.Verdict = v
		r.Reason = reason
	}
}

// ExitCode maps this run's verdict to the process exit code
// docs/design-b4-offline-audit-verify.md §6 specifies: 0 VALID, 1 BROKEN
// (tamper detected), 2 INDETERMINATE (could not fully verify — e.g. an
// unauthenticated retention gap, or no key to check a real truncation).
// Never 0 when something was silently unverified — that distinction is the
// single most important behavior of the whole command (design §6). Exit
// code 3 (usage/input error) is NOT represented here: that is a condition
// this package signals by returning a non-nil error from Verify/Open before
// any Result exists, not a verdict on a Result — the caller (the cobra
// command) maps that error case to 3 itself.
func (r *Result) ExitCode() int {
	switch r.Verdict {
	case VerdictValid:
		return 0
	case VerdictBroken:
		return 1
	case VerdictIndeterminate:
		return 2
	default:
		return 1
	}
}

// Options configures a Verify run.
type Options struct {
	// CheckpointKey is the KEK-derived audit-checkpoint signing key,
	// extracted by the operator out of band (design Q1). Without it,
	// checkpoint/high-water/retention-anchor rows are read and reported but
	// their signatures are never checked.
	CheckpointKey []byte
	// TSARoots, if set, lets this run independently re-verify an RFC 3161
	// external-notary anchor on the latest checkpoint — the one check that
	// needs no shared secret at all (design §3).
	TSARoots *x509.CertPool
	// ExternalAnchor, if set, is a signed checkpoint snapshot held outside
	// this host's blast radius (design §3's `--anchor`) — cross-checked
	// against the live chain once authenticated by CheckpointKey and/or
	// TSARoots. See crossCheckExternalAnchor.
	ExternalAnchor *ExternalAnchorBundle
	// BatchSize overrides DefaultBatchSize for the keyset-paginated walk.
	BatchSize int
	// Now overrides time.Now for Result.GeneratedAt (tests only).
	Now func() time.Time
}

// Verify re-walks db's audit hash chain and reports whether it is intact,
// per the trust model in docs/design-b4-offline-audit-verify.md.
func Verify(ctx context.Context, db *DB, opts Options) (*Result, error) {
	batchSize := opts.BatchSize
	if batchSize <= 0 {
		batchSize = DefaultBatchSize
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}

	result := &Result{Verdict: VerdictValid, GeneratedAt: now().UTC(), VerifierVersion: Version}

	fromID, toID, fromTime, toTime, empty, err := db.EventRange(ctx)
	if err != nil {
		return nil, err
	}
	if !empty {
		result.Range = Range{FromID: fromID, ToID: toID, FromTime: fromTime, ToTime: toTime}
	}

	// Best-effort load + authenticate the retention anchor before the walk,
	// so the first-batch check below can seed from it when it both exists
	// and verifies under the supplied key.
	var anchor *RetentionAnchor
	anchorAuthenticated := false
	if rawVal, found, err := db.GetSystemMetadata(ctx, auditRetentionAnchorKey); err != nil {
		return nil, err
	} else if found {
		if rowID, prevHash, entryHash, keyVersion, sig, ok := ParseRetentionAnchor(rawVal); ok {
			if len(opts.CheckpointKey) > 0 && RetentionAnchorSigMatches(rowID, prevHash, entryHash, keyVersion, sig, opts.CheckpointKey) {
				anchor = &RetentionAnchor{RowID: rowID, PrevHash: prevHash, EntryHash: entryHash}
				anchorAuthenticated = true
			}
		}
	}

	if err := walkChain(ctx, db, batchSize, result, anchor, anchorAuthenticated); err != nil {
		return nil, err
	}

	// A genuine content/linkage break (or an authenticated-but-mismatched
	// retention anchor) already fully explains the verdict; enforcing
	// checkpoint/high-water on top adds nothing but noise.
	if result.Verdict != VerdictBroken {
		if err := enforceCheckpoint(ctx, db, opts, result); err != nil {
			return nil, err
		}
	} else {
		// Still surface checkpoint presence informationally even when the
		// walk itself already failed — an operator comparing this report
		// against the compliance page shouldn't see checkpoint fields
		// silently blank for no stated reason.
		if cp, err := db.LatestCheckpoint(ctx); err == nil && cp != nil {
			result.Checkpoint.Present = true
			result.Checkpoint.KeyVersion = cp.KeyVersion
			result.Checkpoint.ChainedEventsCertified = cp.ChainedEvents
		}
	}

	if opts.ExternalAnchor != nil && result.Verdict != VerdictBroken {
		if err := crossCheckExternalAnchor(ctx, db, opts, result); err != nil {
			return nil, err
		}
	}

	result.NotProven = buildNotProven(opts, result)
	return result, nil
}

// walkChain re-derives every chained row's entry_hash in ascending id order,
// in bounded batches, mirroring internal/storage/store.VerifyAuditChain's
// walk exactly except for the retention-gap seeding, which additionally
// distinguishes an authenticated sanction from an unauthenticated one
// (design §5 — the online code has no INDETERMINATE concept to report).
func walkChain(ctx context.Context, db *DB, batchSize int, result *Result, anchor *RetentionAnchor, anchorAuthenticated bool) error {
	prevHash := GenesisHash
	started := false
	firstBatch := true
	var lastID uint64
	var chainedEvents, unchained int64

	for {
		batch, err := db.StreamAuditEvents(ctx, lastID, batchSize)
		if err != nil {
			return err
		}
		if len(batch) == 0 {
			break
		}

		if firstBatch {
			firstBatch = false
			head := batch[0]
			if head.EntryHash != "" && head.PrevHash != GenesisHash {
				result.RetentionGap.Present = true
				result.RetentionGap.RowID = head.ID

				switch {
				case anchor != nil && anchorAuthenticated &&
					head.ID == anchor.RowID && head.PrevHash == anchor.PrevHash && head.EntryHash == anchor.EntryHash:
					result.RetentionGap.Authenticated = true
					result.RetentionGap.Sanctioned = true
					prevHash = anchor.PrevHash
					started = true

				case anchor != nil && anchorAuthenticated:
					// An authenticated anchor exists but does not match the
					// live earliest row: rows were removed outside a
					// sanctioned purge, or the anchor is stale. Real tamper
					// evidence, not ambiguity — mirrors
					// VerifyAuditChain's exact check.
					id := head.ID
					result.FirstBrokenID = &id
					result.escalate(VerdictBroken, fmt.Sprintf(
						"earliest surviving audit event #%d does not match the authenticated retention re-anchor "+
							"(rows removed outside a sanctioned purge, or the re-anchor is stale)", head.ID))
					result.ChainedEvents, result.UnchainedLegacyEvents = chainedEvents, unchained
					return nil

				default:
					// No usable anchor: seed from the row's own claimed
					// prev_hash so the REST of the chain can still be
					// checked for internal consistency, but do not claim
					// this gap is sanctioned.
					result.RetentionGap.Authenticated = false
					result.escalate(VerdictIndeterminate, fmt.Sprintf(
						"retention gap present before event #%d, unauthenticated: no checkpoint signing key was "+
							"supplied (or the retention anchor does not verify), so this cannot be distinguished "+
							"from a broken chain — the surviving chain from here forward re-walks internally "+
							"consistently", head.ID))
					prevHash = head.PrevHash
					started = true
				}
			}
		}

		for _, e := range batch {
			if !started {
				if e.EntryHash == "" {
					unchained++
					continue
				}
				started = true
			}
			if e.EntryHash == "" {
				id := e.ID
				result.FirstBrokenID = &id
				result.escalate(VerdictBroken, fmt.Sprintf(
					"event #%d has no entry_hash (chain data removed after a chained region began)", e.ID))
				result.ChainedEvents, result.UnchainedLegacyEvents = chainedEvents, unchained
				return nil
			}
			if e.PrevHash != prevHash {
				id := e.ID
				result.FirstBrokenID = &id
				result.escalate(VerdictBroken, fmt.Sprintf(
					"event #%d's prev_hash does not link to the preceding event (row inserted, deleted, or reordered)", e.ID))
				result.ChainedEvents, result.UnchainedLegacyEvents = chainedEvents, unchained
				return nil
			}
			if ComputeEntryHash(e, e.PrevHash) != e.EntryHash {
				id := e.ID
				result.FirstBrokenID = &id
				if ComputeEntryHashPre1452(e, e.PrevHash) == e.EntryHash {
					result.escalate(VerdictBroken, fmt.Sprintf(
						"event #%d's entry_hash is valid under the pre-#1452 audit-hash encoding but not the "+
							"current one — this chain has not been re-encoded since the 2026-08-16 format change. "+
							"This is an un-migrated upgrade, NOT evidence of tampering; run the server's one-time "+
							"chain-encoding migration", e.ID))
				} else {
					result.escalate(VerdictBroken, fmt.Sprintf(
						"event #%d's entry_hash matches neither the current encoding nor the pre-#1452 one — "+
							"its contents changed after it was written", e.ID))
				}
				result.ChainedEvents, result.UnchainedLegacyEvents = chainedEvents, unchained
				return nil
			}
			prevHash = e.EntryHash
			chainedEvents++
		}

		lastID = batch[len(batch)-1].ID
		if len(batch) < batchSize {
			break
		}
	}

	result.ChainedEvents, result.UnchainedLegacyEvents = chainedEvents, unchained
	return nil
}

// enforceCheckpoint augments a clean walk with checkpoint/high-water/anchor
// checks. Unlike internal/core's online enforcement (which reconciles a
// stale-vs-tampered checkpoint by comparing key VERSIONS), this offline tool
// is handed a single raw key by the operator (design Q1) with no separate
// version-rotation concept to reconcile against — so a signature that fails
// to verify under the supplied key is reported as tamper evidence directly,
// not excused as a possible rotation. That is a deliberate simplification
// for a read-only, single-shot tool, not an oversight; see this function's
// call sites in verify_test.go for the exact behavior this produces on a
// forged checkpoint.
func enforceCheckpoint(ctx context.Context, db *DB, opts Options, result *Result) error {
	cp, err := db.LatestCheckpoint(ctx)
	if err != nil {
		return err
	}
	if cp != nil {
		result.Checkpoint.Present = true
		result.Checkpoint.KeyVersion = cp.KeyVersion
		result.Checkpoint.ChainedEventsCertified = cp.ChainedEvents
		if len(cp.AnchorToken) > 0 {
			result.Anchor.Present = true
			result.Anchor.Provider = cp.AnchorProvider
			if cp.AnchoredAt != nil {
				result.Anchor.AnchoredAt = *cp.AnchoredAt
			}
		}
	}

	if len(opts.CheckpointKey) == 0 {
		return nil // nothing further can be authenticated without a key
	}

	// High-water anti-rollback check (mirrors internal/core's
	// enforceAuditHighWater, strict path — this offline tool only ever runs
	// the read path, never the write/recovery path).
	var floor int64
	hwVal, hwFound, err := db.GetSystemMetadata(ctx, auditHighWaterKey)
	if err != nil {
		return err
	}
	markAuthenticated := false
	if hwFound {
		if hwCP, hwSig, parsed := ParseHighWater(hwVal); parsed {
			if HighWaterSigMatches(hwCP, hwSig, opts.CheckpointKey) {
				markAuthenticated = true
				floor = hwCP.ChainedEvents
			} else {
				result.escalate(VerdictBroken, fmt.Sprintf(
					"audit high-water mark fails its signature under the supplied checkpoint key (claims key "+
						"version %q) — the high-water row was tampered with, or the wrong key was supplied", hwCP.KeyVersion))
			}
		}
		// A malformed mark is treated as absent, matching internal/core.
	}
	if !markAuthenticated && result.Verdict != VerdictBroken && cp != nil {
		result.escalate(VerdictBroken,
			"audit high-water mark is missing or malformed although a signed checkpoint exists — "+
				"the anti-rollback mark was deleted or tampered with")
	}
	if result.Verdict != VerdictBroken && result.ChainedEvents < floor {
		result.escalate(VerdictBroken, fmt.Sprintf(
			"audit trail truncated below the certified high-water mark: %d events were previously certified, only %d remain",
			floor, result.ChainedEvents))
	}

	if cp == nil || result.Verdict == VerdictBroken {
		return nil
	}

	if !CheckpointSignatureValid(&Checkpoint{
		ChainedEvents: cp.ChainedEvents, HeadID: cp.HeadID, HeadHash: cp.HeadHash,
		KeyVersion: cp.KeyVersion, Signature: cp.Signature,
	}, opts.CheckpointKey) {
		result.escalate(VerdictBroken, fmt.Sprintf(
			"audit checkpoint #%d does not verify under the supplied checkpoint key — it fails its signature "+
				"(tampered, or the wrong key was supplied)", cp.ID))
		return nil
	}
	result.Checkpoint.Authenticated = true

	if result.ChainedEvents < cp.ChainedEvents {
		result.escalate(VerdictBroken, fmt.Sprintf(
			"audit trail truncated below signed checkpoint #%d: it certified %d chained events, only %d remain",
			cp.ID, cp.ChainedEvents, result.ChainedEvents))
		return nil
	}
	if cp.HeadID != 0 {
		hash, found, err := db.AuditEntryHashByID(ctx, cp.HeadID)
		if err != nil {
			return err
		}
		if !found {
			result.escalate(VerdictBroken, fmt.Sprintf(
				"audit event #%d certified by checkpoint #%d is missing (tail-truncation or genesis re-seed)",
				cp.HeadID, cp.ID))
			return nil
		}
		if hash != cp.HeadHash {
			result.escalate(VerdictBroken, fmt.Sprintf(
				"audit event #%d hash differs from signed checkpoint #%d (certified head was rewritten)",
				cp.HeadID, cp.ID))
			return nil
		}
	}

	if result.Anchor.Present && opts.TSARoots != nil {
		localCP := &Checkpoint{ChainedEvents: cp.ChainedEvents, HeadID: cp.HeadID, HeadHash: cp.HeadHash, KeyVersion: cp.KeyVersion}
		if _, err := notary.VerifyReceipt(opts.TSARoots, []byte(checkpointCanonical(localCP)), cp.AnchorToken); err != nil {
			result.escalate(VerdictBroken, fmt.Sprintf(
				"audit checkpoint #%d external anchor failed verification against the configured trust root: %v",
				cp.ID, err))
			return nil
		}
		result.Anchor.Verified = true
	}

	return nil
}

// buildNotProven states, in plain language and derived purely from what
// opts actually supplied, what this specific run does not establish. Always
// includes the host-admin caveat (design §2) regardless of inputs — no
// combination of flags to this offline tool can close that gap; only an
// anchor genuinely held outside the host's blast radius can, and even then
// only from the moment the anchor was taken.
func buildNotProven(opts Options, result *Result) []string {
	notProven := []string{
		"a host admin holding both this database and its checkpoint signing key can fabricate a fully " +
			"self-consistent, validly-checkpointed history; this verification proves only that a DB-only actor " +
			"(without that key) could not have tampered undetectably",
	}
	if len(opts.CheckpointKey) == 0 {
		notProven = append(notProven,
			"no checkpoint signing key was supplied: tail-truncation and genesis re-seed are not detected by a "+
				"bare linkage re-walk alone (a shorter, self-consistent chain still verifies) — only the linkage "+
				"of rows still present in the table was checked")
	}
	if result.RetentionGap.Present && !result.RetentionGap.Authenticated {
		notProven = append(notProven, fmt.Sprintf(
			"a retention gap before event #%d could not be authenticated as a sanctioned purge; anything before "+
				"it is neither confirmed sanctioned nor confirmed tampered", result.RetentionGap.RowID))
	}
	if result.Anchor.Present && !result.Anchor.Verified {
		reason := "no --tsa-roots trust anchor was supplied"
		if opts.TSARoots != nil {
			reason = "the external-notary anchor did not verify against the supplied trust root"
		}
		notProven = append(notProven, fmt.Sprintf(
			"a checkpoint anchor token is present but was not independently re-verified against a TSA trust root (%s)", reason))
	}
	if result.ExternalAnchor.Supplied && !result.ExternalAnchor.Authenticated {
		notProven = append(notProven,
			"an --anchor bundle was supplied but could not be authenticated by either the checkpoint key or an "+
				"RFC 3161 trust root; its claims were not cross-checked against this database and are advisory only")
	}
	return notProven
}
