package handlers

import (
	"net/http"

	"github.com/keyorixhq/keyorix/internal/core"
)

// secretReadRefusalStatus is the HTTP status for a refusal kind: 403 for the
// permission-class refusal (access schedule), 409 for a secret-state refusal
// (expired, suspended, max reads exhausted). See internal/core/secret_read_refusal.go
// for why 409 and not 410 or 403.
func secretReadRefusalStatus(kind core.SecretReadRefusalKind) int {
	if kind == core.SecretReadRefusalDenied {
		return http.StatusForbidden
	}
	return http.StatusConflict
}

// sendSecretReadRefusal answers a value read the secret's own state refused
// (core.ClassifySecretReadRefusal) with its status, stable code and fixed
// message, and reports whether it did. It never echoes err's text. Call it only
// once the caller's read permission on the secret is established: before that,
// a refusal would confirm the secret exists to a caller who cannot see it.
func (h *SecretHandler) sendSecretReadRefusal(w http.ResponseWriter, err error) bool {
	refusal, ok := core.ClassifySecretReadRefusal(err)
	if !ok {
		return false
	}
	var details any
	if refusal.ClearSyncedCopies {
		// The suspension asked for synced Kubernetes copies to be cleared; the operator
		// and k8s-sync read this to treat the secret as onSuspend: Clear. Additive:
		// a client that ignores `details` still sees the same status, code and message.
		details = map[string]bool{"clear_synced_copies": true}
	}
	h.sendError(w, refusal.Code, refusal.Message, secretReadRefusalStatus(refusal.Kind), details)
	return true
}
