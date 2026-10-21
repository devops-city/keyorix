// partial_mutation.go — the HTTP and SCIM answer to a mixed request whose
// narrowing commit went through and whose second commit did not
// (core.PartialMutationError, internal/core/audit_split.go, MERGE-FIX-3482G).
package handlers

import (
	"net/http"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/core"
)

// scimPartialMutationSchema names the Keyorix extension of the SCIM error body that
// carries which half of a split request was applied.
const scimPartialMutationSchema = "urn:keyorix:params:scim:api:messages:2.0:PartialMutation"

// sendPartialMutation answers err with 503 and a body that says machine-readably which
// half was applied (details: code, revocation_applied, remainder_applied, applied,
// not_applied, retry_safe), when err carries a core.PartialMutationError. It reports
// whether it answered. Check it before any other error mapping: the error also
// unwraps to why the second commit failed.
func sendPartialMutation(w http.ResponseWriter, err error) bool {
	pe, ok := core.AsPartialMutationError(err)
	if !ok {
		return false
	}
	sendError(w, core.PartialMutationErrorType, pe.ClientMessage(), http.StatusServiceUnavailable, pe.Details())
	return true
}

// scimPartialMutation is sendPartialMutation for the SCIM endpoints: an RFC 7644 error
// body (status "503") plus the Keyorix extension holding the same fields.
func scimPartialMutation(w http.ResponseWriter, err error) bool {
	pe, ok := core.AsPartialMutationError(err)
	if !ok {
		return false
	}
	writeSCIM(w, http.StatusServiceUnavailable, map[string]any{
		"schemas":                 []string{scimErrorSchema, scimPartialMutationSchema},
		"status":                  strconv.Itoa(http.StatusServiceUnavailable),
		"detail":                  pe.ClientMessage(),
		scimPartialMutationSchema: pe.Details(),
	})
	return true
}
