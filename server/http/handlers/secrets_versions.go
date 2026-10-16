// secrets_versions.go — GetSecretVersions and RotateSecret handlers.
//
// Handles secret versioning and rotation.
// For CRUD see secrets_crud.go. For listing see secrets_list.go.
package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// GetSecretVersions handles GET /api/v1/secrets/{id}/versions
func (h *SecretHandler) GetSecretVersions(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", errInvalidSecretID, http.StatusBadRequest, nil)
		return
	}

	// Machine principals (ADR-030) are already authorized at the secret's scope
	// by the route's RequireScopedSecretPermission(permSecretsRead) gate; the
	// per-user owner/sharing check (and its user-id requirement — a machine
	// caller's userCtx.UserID is always 0) does not apply to them, so fetch
	// directly. Mirrors the isMachine split secrets_crud.go's GetSecret uses
	// (W1, machine-identity-read gap: this was the one versions.go entry point
	// an HTTP handler still called unconditionally).
	isMachine := userCtx.MachineIdentityID != nil
	var versions []*models.SecretVersion
	if isMachine {
		versions, err = h.coreService.GetSecretVersions(r.Context(), uint(id))
	} else {
		versions, err = h.coreService.GetSecretVersionsWithPermissionCheck(r.Context(), uint(id), userCtx.UserID)
	}
	if err != nil {
		log.Printf("Error getting secret versions: %v", err)
		if strings.Contains(err.Error(), errNotFound) {
			h.sendError(w, "NotFound", "Secret not found", http.StatusNotFound, nil)
		} else if strings.Contains(err.Error(), "permission denied") {
			h.sendError(w, "Forbidden", "Access denied", http.StatusForbidden, nil)
		} else {
			h.sendError(w, "InternalError", "Failed to get secret versions", http.StatusInternalServerError, nil)
		}
		return
	}

	// Audit the listing as secret.versions_listed, not secret.read: the response
	// carries version metadata, never a value (EncryptedValue is json:"-"), and
	// secret.read means a value disclosure (AUDIT-UX-2, #2951). Still
	// audit-before-response (SESSION-PERF #2403 follow-up, item 3): `versions` is
	// only sent below AFTER its audit entry has been durably committed.
	secret, sErr := h.coreService.GetSecret(r.Context(), uint(id))
	if sErr == nil && secret != nil {
		ip, ua := clientIP(r), r.Header.Get("User-Agent")
		auditCtx := core.DetachedAuditContext(r.Context())
		if auditErr := h.coreService.LogSecretVersionsListed(auditCtx, userCtx.UserID, uint(id), secret.ProjectID, userCtx.Username, secret.Name, ip, ua); auditErr != nil {
			log.Printf("SECURITY: audit write failed for secret versions listing (secret=%d): %v -- failing closed", id, auditErr)
			h.sendError(w, "InternalError", "Failed to record audit trail", http.StatusInternalServerError, nil)
			return
		}
	}

	resp := map[string]any{"versions": versions}
	// total_reads: the secret's lifetime value-read count (core.SecretTotalReads),
	// next to each version's ReadCount (max_reads accounting only, #2963).
	// Display only: omitted if it cannot be read.
	if n, terr := h.coreService.SecretTotalReads(r.Context(), uint(id)); terr == nil {
		resp["total_reads"] = n
	} else {
		log.Printf("total_reads for secret %d unavailable: %v", id, terr)
	}
	h.sendSuccess(w, resp, "")
}

// RotateSecret handles POST /api/v1/secrets/{id}/rotate
func (h *SecretHandler) RotateSecret(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		h.sendError(w, "BadRequest", errInvalidSecretID, http.StatusBadRequest, nil)
		return
	}

	var reqBody struct {
		// The `validate:"required"` tag here is decorative: this handler never
		// calls h.validator.Validate, relying instead on the manual == ""
		// check below. Harmless today (the manual check covers the same
		// case), but the tag would silently fail to protect a future rule
		// added to the tag without a matching manual check (see #347).
		NewValue string `json:"new_value" validate:"required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		if h.trySendSecretSizeError(w, err) {
			return
		}
		h.sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}
	if reqBody.NewValue == "" {
		h.sendError(w, "ValidationError", "new_value is required", http.StatusBadRequest, nil)
		return
	}

	// RotateSecretOnDemand (#193): for a backend-bound secret this rotates the upstream
	// credential too (the same machinery the auto-rotation scheduler uses) rather than
	// just overwriting the stored value — never report success while the real,
	// potentially compromised credential is still live untouched upstream.
	// The secret.rotated row commits with the new version (AUDIT-MUTATION-TX-1), so
	// the rotation inspector, the activity feed and a client that refetches History
	// right after the response all see it, and a rotation is never stored without it.
	secret, err := h.coreService.RotateSecretOnDemand(secretMutationAuditContext(r, userCtx), uint(id), []byte(reqBody.NewValue), userCtx.UserID, userCtx.Username)
	if err != nil {
		if h.trySendSecretSizeError(w, err) {
			return
		}
		switch {
		case errors.Is(err, core.ErrSecretVersionContentionExhausted):
			// W3 (Session W, 2026-09-29): see secrets_crud.go's sendUpdateSecretError
			// for why this is 409-and-retry, not a generic 500.
			h.sendError(w, "Conflict", "High write contention on this secret; retry the request", http.StatusConflict, nil)
		case strings.Contains(err.Error(), errNotFound):
			h.sendError(w, "NotFound", "Secret not found", http.StatusNotFound, nil)
		case strings.Contains(err.Error(), "backend"):
			// The upstream rotation failed or only partially completed — surfaced
			// distinctly (502) so the caller never mistakes this for a clean success,
			// even though a partial attempt may have stored a new value; see the audit
			// trail (secret.rotate_failed / secret.rotate_incomplete) for the outcome.
			log.Printf("rotation backend error for secret %d: %v", uint(id), err)
			h.sendError(w, "BackendRotationFailed", "Rotation backend call failed; see server logs for details", http.StatusBadGateway, nil)
		case strings.Contains(err.Error(), i18n.T("ErrorValidation", nil)):
			h.sendError(w, "ValidationError", err.Error(), http.StatusBadRequest, nil)
		default:
			log.Printf("rotate secret %d: unexpected error: %v", uint(id), err)
			h.sendError(w, "InternalError", "Failed to rotate secret", http.StatusInternalServerError, nil)
		}
		return
	}

	h.sendSuccess(w, newSecretNodeWire(secret), "Secret rotated successfully")
}

// RollbackSecret handles POST /api/v1/secrets/{id}/rollback — restores the secret to a
// prior version's value as a new version. Scoped secrets.write (route-gated).
func (h *SecretHandler) RollbackSecret(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		h.sendError(w, "BadRequest", errInvalidSecretID, http.StatusBadRequest, nil)
		return
	}
	var reqBody struct {
		// The `validate:"required"` tag here is decorative: this handler never
		// calls h.validator.Validate, relying instead on the manual <= 0
		// check below. See the same note on RotateSecret's NewValue above.
		Version int `json:"version" validate:"required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		h.sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}
	if reqBody.Version <= 0 {
		h.sendError(w, "ValidationError", "version must be a positive version number", http.StatusBadRequest, nil)
		return
	}
	secret, err := h.coreService.RollbackSecret(secretMutationAuditContext(r, userCtx), uint(id), reqBody.Version, userCtx.UserID, userCtx.Username)
	if err != nil {
		switch {
		case errors.Is(err, core.ErrSecretVersionContentionExhausted):
			// W3 (Session W, 2026-09-29): RollbackSecret calls RotateSecret internally,
			// which shares UpdateSecret's contention-exhaustion path — see
			// secrets_crud.go's sendUpdateSecretError for why this is 409, not 500.
			h.sendError(w, "Conflict", "High write contention on this secret; retry the request", http.StatusConflict, nil)
		case strings.Contains(err.Error(), errNotFound):
			h.sendError(w, "NotFound", err.Error(), http.StatusNotFound, nil)
		case strings.Contains(err.Error(), "already the current version"), strings.Contains(err.Error(), "version number must be positive"):
			h.sendError(w, "ValidationError", err.Error(), http.StatusBadRequest, nil)
		default:
			log.Printf("roll back secret %d: unexpected error: %v", uint(id), err)
			h.sendError(w, "InternalError", "Failed to roll back secret", http.StatusInternalServerError, nil)
		}
		return
	}
	h.sendSuccess(w, newSecretNodeWire(secret), fmt.Sprintf("Secret rolled back to version %d", reqBody.Version))
}
