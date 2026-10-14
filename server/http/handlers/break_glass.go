// break_glass.go — self-service emergency-access endpoints. Activation is NOT
// RBAC-gated (the point is access the caller does not have); the controls are
// config-enablement, a mandatory justification, loud audit, and auto-expiry. Revoke
// and review ARE gated (roles.assign) — they're review actions. List is authorized in
// core: roles.read sees the project's activations, any other member only their own.
package handlers

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// ActivateBreakGlass handles POST /api/v1/projects/{id}/break-glass (self-service).
func (h *CatalogHandler) ActivateBreakGlass(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidProjectID, http.StatusBadRequest, nil)
		return
	}
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		Justification string `json:"justification"`
		TTL           string `json:"ttl"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	if body.Justification == "" {
		sendError(w, "ValidationError", "justification is required", http.StatusBadRequest, nil)
		return
	}
	activation, err := h.coreService.ActivateBreakGlass(r.Context(), uint(id), actor.UserID, body.Justification, body.TTL)
	if err != nil {
		// PAT-GUARD-2: the same refusal shape as ErrRestrictedPATCannotMintPAT.
		if errors.Is(err, core.ErrRestrictedPATCannotBreakGlass) {
			sendError(w, "Forbidden", err.Error(), http.StatusForbidden, nil)
			return
		}
		status := http.StatusInternalServerError
		msg := err.Error()
		// A typed code for "disabled" (same 403, same message, same position in the
		// order of checks as before): clients switch on the code, not on the text.
		if errors.Is(err, core.ErrBreakGlassDisabled) {
			sendError(w, core.BreakGlassDisabledCode, msg, http.StatusForbidden, nil)
			return
		}
		// #2905: mapped by sentinel (errors.Is), not by matching text that
		// embeds i18n.T's locale-dependent output.
		switch {
		case errors.Is(err, core.ErrBreakGlassNotProjectMember):
			status = http.StatusForbidden
		case errors.Is(err, core.ErrBreakGlassInvalidRequest):
			status = http.StatusBadRequest
		default:
			log.Printf("Error activating break-glass for project %d: %v", id, err)
			msg = clientSafe(err)
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	// sendCreated, not w.WriteHeader(201)+sendSuccess: the latter sequence sets
	// Content-Type AFTER the first WriteHeader call, which net/http silently
	// drops -- confirmed live via scripts/cli-parity-check.sh against a real
	// server, the same defect class as rotation_policies_handler.go's Create
	// (see its sendCreated doc comment for the full writeup). Without a
	// Content-Type header, ADR-108 PR 1's generated CLI client can't tell this
	// 201 response apart from a non-JSON one and never populates JSON201.
	sendCreated(w, map[string]any{"activation": activation}, "Emergency access activated")
}

// ListBreakGlassActivations handles GET /api/v1/projects/{id}/break-glass. The route
// carries no permission gate: core.ListBreakGlassActivationsForCaller is the
// authorization (roles.read at the project lists every activation; any other project member
// lists only their own; anyone else is refused with the 403 the old roles.read gate
// gave). The per-project MFA policy applies to both views, as it did at the gate.
func (h *CatalogHandler) ListBreakGlassActivations(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidProjectID, http.StatusBadRequest, nil)
		return
	}
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	activations, scope, err := h.coreService.ListBreakGlassActivationsForCaller(r.Context(), actor.ActorKind(), actor.PrincipalID(), actor.UserID, uint(id))
	if err != nil {
		switch {
		case errors.Is(err, core.ErrBreakGlassListForbidden):
			sendError(w, "Forbidden", "Insufficient permissions", http.StatusForbidden, nil)
		case errors.Is(err, core.ErrBreakGlassInvalidRequest):
			sendError(w, "ValidationError", errInvalidProjectID, http.StatusBadRequest, nil)
		default:
			log.Printf("Error listing break-glass activations for project %d: %v", id, err)
			sendError(w, "Error", clientSafe(err), http.StatusInternalServerError, nil)
		}
		return
	}
	if middleware.ProjectMFABlocked(r, h.coreService, uint(id)) {
		middleware.WriteProjectMFARequired(w)
		return
	}
	s := h.coreService.BreakGlassSettings()
	sendSuccess(w, map[string]any{
		"activations": activations, "count": len(activations), "scope": scope,
		// Only reached for a caller the list authorization allowed (a project member or a
		// roles.read holder) and after the MFA policy: deployment limits, no secrets.
		"settings": map[string]any{
			"enabled":             s.Enabled,
			"emergency_role":      s.EmergencyRole,
			"default_ttl_seconds": int64(s.DefaultTTL / time.Second),
			"max_ttl_seconds":     int64(s.MaxTTL / time.Second),
		},
	}, "")
}

// RevokeBreakGlass handles POST /api/v1/projects/{id}/break-glass/{activationId}/revoke.
func (h *CatalogHandler) RevokeBreakGlass(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidProjectID, http.StatusBadRequest, nil)
		return
	}
	activationID, err := strconv.ParseUint(chi.URLParam(r, "activationId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid activation ID", http.StatusBadRequest, nil)
		return
	}
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	if err := h.coreService.RevokeBreakGlass(r.Context(), actor.UserID, machineID(r), uint(id), uint(activationID)); err != nil {
		status := http.StatusInternalServerError
		msg := err.Error()
		// #2905: by sentinel, as in ActivateBreakGlass above. A genuine
		// retrieval FAILURE is deliberately not a 404: it falls to the 500.
		switch {
		case errors.Is(err, storage.ErrBreakGlassNotFound):
			status = http.StatusNotFound
		case errors.Is(err, storage.ErrBreakGlassNotActive), errors.Is(err, core.ErrBreakGlassInvalidRequest):
			status = http.StatusBadRequest
		default:
			log.Printf("Error revoking break-glass activation %d for project %d: %v", activationID, id, err)
			msg = clientSafe(err)
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	sendSuccess(w, nil, "Emergency access revoked")
}

// ReviewBreakGlass handles POST /api/v1/projects/{id}/break-glass/{activationId}/review
// (ADR-112 §3, break-glass review item 5): a post-activation check, distinct from and
// independent of revoke -- it is a record about what happened, not a control over the
// grant, so it neither extends nor shortens the activation.
//
// The activation must have CONCLUDED first (revoked or expired, #2461) and the reviewer
// must be someone other than the activating user; ReviewBreakGlass itself enforces both,
// and the error mapping below surfaces them as 400 and 403 rather than letting a
// deliberate refusal read as a server fault.
func (h *CatalogHandler) ReviewBreakGlass(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidProjectID, http.StatusBadRequest, nil)
		return
	}
	activationID, err := strconv.ParseUint(chi.URLParam(r, "activationId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid activation ID", http.StatusBadRequest, nil)
		return
	}
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		Note string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.ReviewBreakGlass(r.Context(), actor.UserID, uint(id), uint(activationID), body.Note); err != nil {
		status := http.StatusInternalServerError
		msg := err.Error()
		switch {
		// #2461 round 2: mapped by sentinel (errors.Is), not by matching English
		// message text against i18n.T's LOCALE-DEPENDENT output -- the previous
		// strings.Contains(msg, "permission denied") etc. only worked because
		// the server happened to be running in English; under ru/fr/de i18n.T
		// returns translated text, so every one of these arms would silently
		// stop matching and every refusal would fall through to 500.
		//
		// Self-review and unattributable-reviewer are listed BEFORE the 400 arm
		// because ErrBreakGlassSelfReview's own message also contains "required"
		// ("an independent reviewer is required"), which would otherwise
		// classify a deliberate authorization refusal as a malformed request --
		// confirmed: with this arm removed, the self-review case returns 400 and
		// the still-active case 500.
		case errors.Is(err, core.ErrBreakGlassSelfReview), errors.Is(err, core.ErrBreakGlassUnattributableReviewer):
			status = http.StatusForbidden
		// Both "no such activation" and "that activation belongs to another
		// project" arrive as storage.ErrBreakGlassNotFound, so both are 404 —
		// a project-ID mismatch must not read as a server fault, and must not
		// disclose that the ID exists elsewhere. A genuine retrieval FAILURE is
		// deliberately not in this arm: it falls through to the default 500.
		case errors.Is(err, storage.ErrBreakGlassNotFound):
			status = http.StatusNotFound
		case errors.Is(err, storage.ErrBreakGlassAlreadyReviewed), errors.Is(err, core.ErrBreakGlassStillActive),
			errors.Is(err, core.ErrBreakGlassInvalidNote), errors.Is(err, core.ErrInvalidInput):
			status = http.StatusBadRequest
		default:
			log.Printf("Error reviewing break-glass activation %d for project %d: %v", activationID, id, err)
			msg = clientSafe(err)
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	sendSuccess(w, nil, "Break-glass activation reviewed")
}
