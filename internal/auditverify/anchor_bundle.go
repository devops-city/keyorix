// anchor_bundle.go keeps internal/auditverify's public API stable after the
// pure ExternalAnchorBundle parser moved to the leaf package
// internal/auditverify/anchorbundle (see that package's doc.go for why: fuzz
// throughput). ExternalAnchorBundle is a type alias, so values are
// interchangeable; ParseExternalAnchorBundle is a thin wrapper.
package auditverify

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/auditverify/anchorbundle"
	"github.com/keyorixhq/keyorix/internal/notary"
)

// ExternalAnchorBundle is anchorbundle.ExternalAnchorBundle.
type ExternalAnchorBundle = anchorbundle.ExternalAnchorBundle

// ParseExternalAnchorBundle parses the JSON bundle design §3's `--anchor`
// flag takes. All interpretation of this file lives here and in
// crossCheckExternalAnchor below — the caller (the cobra command) only
// reads the bytes off disk and hands them to this function.
func ParseExternalAnchorBundle(data []byte) (*ExternalAnchorBundle, error) {
	return anchorbundle.ParseExternalAnchorBundle(data)
}

// checkpointFromAnchorBundle converts an externally-supplied anchor bundle to
// this package's own Checkpoint shape. A package-level function rather than a
// method on ExternalAnchorBundle — that type's now an alias to a type
// defined in package anchorbundle, and Go does not allow attaching a new
// method to a type via an alias from a different package.
func checkpointFromAnchorBundle(b *ExternalAnchorBundle) *Checkpoint {
	return &Checkpoint{
		ChainedEvents: b.ChainedEvents,
		HeadID:        b.HeadID,
		HeadHash:      b.HeadHash,
		KeyVersion:    b.KeyVersion,
		Signature:     b.Signature,
	}
}

// crossCheckExternalAnchor authenticates opts.ExternalAnchor by whatever
// means are available — the supplied checkpoint key (its HMAC signature), an
// RFC 3161 token against opts.TSARoots, or both — and, if authenticated by
// EITHER method, compares its certified chain length and head against the
// LIVE walk. This catches a truncation or genesis re-seed even if the
// database's own local checkpoint/high-water rows were ALSO deleted or
// forged, since this anchor's ground truth came from outside the host
// (design §2's strongest leg — RFC 3161 in particular needs no shared secret
// at all). An unauthenticated bundle (no key, no roots, or both fail) is
// reported as present-but-unauthenticated and never trusted for the
// chain-length comparison — see buildNotProven.
func crossCheckExternalAnchor(ctx context.Context, db *DB, opts Options, result *Result) error {
	b := opts.ExternalAnchor
	cp := checkpointFromAnchorBundle(b)

	result.ExternalAnchor.Supplied = true

	keyAuthenticated := len(opts.CheckpointKey) > 0 && CheckpointSignatureValid(cp, opts.CheckpointKey)

	tokenVerified := false
	if len(b.AnchorToken) > 0 && opts.TSARoots != nil {
		if _, err := notary.VerifyReceipt(opts.TSARoots, []byte(checkpointCanonical(cp)), b.AnchorToken); err == nil {
			tokenVerified = true
		} else {
			result.escalate(VerdictBroken, fmt.Sprintf(
				"the externally-supplied anchor's RFC 3161 token failed verification against the configured "+
					"trust root: %v — it does not authenticate what it claims", err))
			return nil
		}
	}

	if !keyAuthenticated && !tokenVerified {
		return nil // unauthenticated bundle — advisory only, see buildNotProven
	}
	result.ExternalAnchor.Authenticated = true

	// result.PurgedEvents is non-zero only when the retention anchor
	// authenticated under the supplied key (#3257): a bundle checked with TSA
	// roots alone gets no purge credit, so a purge after its export still reads
	// BROKEN there (fail closed).
	if result.ChainedEvents+result.PurgedEvents < b.ChainedEvents {
		result.escalate(VerdictBroken, fmt.Sprintf(
			"audit trail truncated below an externally-held anchor: it certified %d chained events (a copy this "+
				"host does not control), only %s — caught even if this database's own local "+
				"checkpoint/high-water rows were also deleted or forged", b.ChainedEvents,
			describeCount(result.ChainedEvents, result.PurgedEvents, "remain")))
		return nil
	}
	if b.HeadID != 0 {
		hash, found, err := db.AuditEntryHashByID(ctx, b.HeadID)
		if err != nil {
			return err
		}
		if !found {
			result.escalate(VerdictBroken, fmt.Sprintf(
				"audit event #%d certified by the externally-held anchor is missing from this database", b.HeadID))
			return nil
		}
		if hash != b.HeadHash {
			result.escalate(VerdictBroken, fmt.Sprintf(
				"audit event #%d hash differs from the externally-held anchor (certified head was rewritten)", b.HeadID))
			return nil
		}
	}
	return nil
}
