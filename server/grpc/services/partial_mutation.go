// partial_mutation.go — the gRPC answer to a mixed request whose narrowing commit
// went through and whose second commit did not (core.PartialMutationError,
// internal/core/audit_split.go, MERGE-FIX-3482G).
package services

import (
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/core"
)

// partialMutationErrorDomain is the google.rpc.ErrorInfo domain of a partial apply.
const partialMutationErrorDomain = "keyorix.audit"

// partialMutationStatus maps err to codes.Unavailable with a google.rpc.ErrorInfo
// (reason core.PartialMutationErrorType, metadata: code, revocation_applied,
// remainder_applied, applied, not_applied, retry_safe) when err carries a
// core.PartialMutationError, so a client can tell which half was applied without
// matching text. ok is false otherwise. Check it before any other error mapping.
func partialMutationStatus(err error) (out error, ok bool) {
	pe, ok := core.AsPartialMutationError(err)
	if !ok {
		return nil, false
	}
	st := status.New(codes.Unavailable, pe.ClientMessage())
	if withInfo, derr := st.WithDetails(&errdetails.ErrorInfo{
		Reason: core.PartialMutationErrorType, Domain: partialMutationErrorDomain, Metadata: pe.Metadata(),
	}); derr == nil {
		st = withInfo
	}
	return st.Err(), true
}
