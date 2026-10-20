// audit_split.go — a request that narrows access and, in the same call, widens it
// (MERGE-FIX-3482G; Andrei 2026-10-20, ask 3482-mixed-request-rule, option (a)).
//
// Such a request is applied as two commits, narrowing first:
//
//  1. The narrowing part alone (a deactivation or restriction, a membership removal,
//     a per-project MFA requirement turned on, the end of a user's sessions) through
//     runOwedAuditMutation: never blocked by the audit log, its row owed
//     (INV-CORE-revocation-audit-owed), appended after the auth-cache eviction.
//  2. The rest (a username or email change, a membership add, a rename or new
//     description, a new credential) fail closed (withAuditedMutation): its row
//     commits with it, or none of it commits.
//
// The caller decides each part's direction from what it changes against the row it
// read under the call's lock, never from the request alone, and rejects no mixed
// request up front: an IdP that sends a multi-op SCIM PATCH must still be able to
// offboard. A widening never commits without its row; a revocation never waits for
// the audit log.
//
// If commit 2 fails, commit 1 stays: the call returns a *PartialMutationError
// (errors.Is ErrMutationPartiallyApplied), which the transports answer with HTTP 503 /
// SCIM 503 / gRPC Unavailable and a body that says machine-readably which half was
// applied (PartialMutationError.Details). A retry of the same request is safe: commit
// 1 is idempotent (a second deactivation, removal or MFA-on changes nothing), so only
// commit 2 has anything left to do.
package core

import (
	"context"
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// ErrMutationPartiallyApplied matches every PartialMutationError: the narrowing part of a
// mixed request committed, the rest did not.
var ErrMutationPartiallyApplied = errors.New("the access-narrowing part of the request was applied and the rest was not; retry the same request")

// PartialMutationErrorCode is the stable machine-readable code the transports send with
// a PartialMutationError (details.code; the gRPC ErrorInfo metadata "code").
const PartialMutationErrorCode = "mutation_partially_applied"

// PartialMutationErrorType is the HTTP error type ("error") and the gRPC ErrorInfo
// reason of a PartialMutationError.
const PartialMutationErrorType = "MutationPartiallyApplied"

// PartialMutationError is commit 2 of a split request failing after commit 1 committed.
type PartialMutationError struct {
	// Applied names what commit 1 applied ("deactivation", "member removal", ...).
	Applied string
	// NotApplied names what commit 2 would have applied ("email change", ...).
	NotApplied string
	// Err is why commit 2 failed (ErrMutationAuditUnavailable during an audit outage).
	Err error
}

func (e *PartialMutationError) Error() string {
	return fmt.Sprintf("%s applied; %s not applied: %v", e.Applied, e.NotApplied, e.Err)
}

// Is makes errors.Is(err, ErrMutationPartiallyApplied) true.
func (e *PartialMutationError) Is(target error) bool { return target == ErrMutationPartiallyApplied }

// Unwrap exposes why commit 2 failed (errors.Is(err, ErrMutationAuditUnavailable)).
func (e *PartialMutationError) Unwrap() error { return e.Err }

// ClientMessage is the fixed text the transports send (never Err's text).
func (e *PartialMutationError) ClientMessage() string {
	return fmt.Sprintf("%s was applied; %s was not (the change could not be completed, retry the same request)", e.Applied, e.NotApplied)
}

// Details is the machine-readable body the transports send with it: which half was
// applied, and that a retry of the same request is safe.
func (e *PartialMutationError) Details() map[string]any {
	return map[string]any{
		"code":               PartialMutationErrorCode,
		"revocation_applied": true,
		"remainder_applied":  false,
		"applied":            e.Applied,
		"not_applied":        e.NotApplied,
		"retry_safe":         true,
	}
}

// Metadata is Details as strings (gRPC google.rpc.ErrorInfo metadata).
func (e *PartialMutationError) Metadata() map[string]string {
	out := map[string]string{}
	for k, v := range e.Details() {
		out[k] = fmt.Sprint(v)
	}
	return out
}

// AsPartialMutationError returns err's PartialMutationError, if it carries one.
func AsPartialMutationError(err error) (*PartialMutationError, bool) {
	return errors.AsType[*PartialMutationError](err)
}

// commitSplitRemainder is commit 2 of a split request: fn in one transaction, fail closed
// through withAuditedMutation when audited (a plain transaction otherwise, for a caller
// whose untagged transport writes the row itself, mutationTx). The caller has already
// committed commit 1 through runOwedAuditMutation, evicted the auth cache and settled its
// owed rows, so the narrowing is in force whatever happens here. A failure comes back as
// a *PartialMutationError naming both halves.
func (c *KeyorixCore) commitSplitRemainder(ctx context.Context, applied, notApplied string, audited bool, fn func(tx storage.Storage, tgt auditTarget) error) error {
	if err := c.mutationTx(ctx, audited, fn); err != nil {
		return &PartialMutationError{Applied: applied, NotApplied: notApplied, Err: err}
	}
	return nil
}
