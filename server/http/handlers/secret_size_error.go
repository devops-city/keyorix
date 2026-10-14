// secret_size_error.go — shared 413 mapping for the maximum-secret-value-size
// cap (internal/core.checkSecretSize, config.DeriveMaxRequestBodySize), used by
// CreateSecret, UpdateSecret, and RotateSecret. A "too large" condition can
// surface at two different points, both mapped here so every caller handles
// both the same way instead of one being missed:
//
//   - the wire-level body limit (server/http/router.go's secretBodyLimit,
//     applied via http.MaxBytesReader) trips DURING json.Decode, before a
//     Go value ever exists to inspect -- surfaced as *http.MaxBytesError;
//   - the DECODED value's exact byte length exceeds
//     secrets.limits.max_secret_size -- surfaced as
//     *core.SecretValueTooLargeError from the core-layer check.
package handlers

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/keyorixhq/keyorix/internal/core"
)

// trySendSecretSizeError reports whether err is either shape of "secret value
// too large" and, if so, has already written a 413 response naming the actual
// limit. false means err was something else and the caller should continue
// with its own error mapping.
func (h *SecretHandler) trySendSecretSizeError(w http.ResponseWriter, err error) bool {
	if mbe, ok := errors.AsType[*http.MaxBytesError](err); ok {
		h.sendError(w, "PayloadTooLarge",
			fmt.Sprintf("request body exceeds the %d-byte limit derived from the configured maximum secret size", mbe.Limit),
			http.StatusRequestEntityTooLarge, nil)
		return true
	}
	if tooLarge, ok := errors.AsType[*core.SecretValueTooLargeError](err); ok {
		h.sendError(w, "PayloadTooLarge", tooLarge.Error(), http.StatusRequestEntityTooLarge, nil)
		return true
	}
	return false
}
