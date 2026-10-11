// secrets_crud.go — CreateSecret, GetSecret, UpdateSecret, DeleteSecret handlers.
//
// Handles the core CRUD lifecycle for secrets.
// For list/filter see secrets_list.go. For versioning see secrets_versions.go.
package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// CreateSecret handles POST /api/v1/secrets
func (h *SecretHandler) CreateSecret(w http.ResponseWriter, r *http.Request) {
	userCtx, ok := mustGetUser(w, r)
	if !ok {
		return
	}

	var reqBody struct {
		Name           string            `json:"name" validate:"required,min=1,max=255"`
		Value          string            `json:"value" validate:"required"`
		ProjectID      uint              `json:"project_id"`
		EnvironmentID  uint              `json:"environment_id" validate:"required"`
		Type           string            `json:"type" validate:"required"`
		MaxReads       *int              `json:"max_reads,omitempty" validate:"omitempty,min=1"`
		Metadata       map[string]string `json:"metadata,omitempty"`
		Tags           []string          `json:"tags,omitempty"`
		Classification string            `json:"classification,omitempty"`
		// ParentID optionally places the secret inside a folder node.
		// The parent must exist and be a folder (IsSecret=false).
		ParentID *uint `json:"parent_id,omitempty"`
		// Description and Expiration (found by the #1808 differential
		// conformance harness): this struct never had a slot for either, so
		// no caller of this route -- direct API client or the now-deleted
		// RemoteStorage proxy alike -- could ever set them; core.CreateSecretRequest and
		// core.CreateSecret already fully support both (length-validate
		// Description, persist Expiration), they just never reached here.
		Description string     `json:"description,omitempty"`
		Expiration  *time.Time `json:"expiration,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		if h.trySendSecretSizeError(w, err) {
			return
		}
		h.sendError(w, "InvalidJSON", errInvalidJSON, http.StatusBadRequest, nil)
		return
	}
	if err := h.validator.Validate(&reqBody); err != nil {
		h.sendError(w, "ValidationError", "Invalid request data", http.StatusBadRequest, err)
		return
	}

	// Authorize against the target project/environment from the body — the
	// create route carries no path scope for the middleware to resolve.
	scope := core.Scope{ProjectID: reqBody.ProjectID, EnvironmentID: reqBody.EnvironmentID}
	if allowed, err := h.coreService.AuthorizePrincipal(r.Context(), userCtx.ActorKind(), userCtx.PrincipalID(), "secrets.write", scope); err != nil || !allowed {
		h.sendError(w, "Forbidden", "Insufficient permissions", http.StatusForbidden, nil)
		return
	}
	// Per-project MFA policy (ADR-037): create carries no path scope for the
	// scoped-permission middleware, so enforce it here too (same as the other
	// in-handler-authorized mutations).
	if middleware.ProjectMFABlocked(r, h.coreService, scope.ProjectID) {
		middleware.WriteProjectMFARequired(w)
		return
	}

	req := &core.CreateSecretRequest{
		Name:           reqBody.Name,
		Value:          []byte(reqBody.Value),
		ProjectID:      reqBody.ProjectID,
		EnvironmentID:  reqBody.EnvironmentID,
		Type:           reqBody.Type,
		MaxReads:       reqBody.MaxReads,
		Metadata:       reqBody.Metadata,
		Tags:           reqBody.Tags,
		Classification: reqBody.Classification,
		ParentID:       reqBody.ParentID,
		Description:    reqBody.Description,
		Expiration:     reqBody.Expiration,
		CreatedBy:      userCtx.Username,
		OwnerID:        userCtx.UserID,
	}
	// #1625 (#1573 machine-actor attribution family, Part 2 continuation
	// finding): CreateSecretRequest.OwnerMachineIdentityID exists and is
	// threaded through to the persisted model (core/secrets.go), matching
	// every sibling model this PR family touched -- but this real entry point
	// never populated it. Without this, a machine identity's secret creation
	// lands with OwnerID=0 AND OwnerMachineIdentityID=0, indistinguishable
	// from an orphaned/legacy row for exactly the incident-response/
	// compliance-audit use case the discriminator-field pattern exists for.
	if userCtx.MachineIdentityID != nil {
		req.OwnerMachineIdentityID = *userCtx.MachineIdentityID
	}

	response, err := h.coreService.CreateSecret(r.Context(), req)
	if err != nil {
		log.Printf("Error creating secret: %v", err)
		if h.trySendSecretSizeError(w, err) {
			return
		}
		if strings.Contains(err.Error(), "already exists") {
			h.sendError(w, "ConflictError", "Secret with this name already exists", http.StatusConflict, nil)
		} else if strings.Contains(err.Error(), "does not belong to project") || strings.Contains(err.Error(), "environment") && strings.Contains(err.Error(), errNotFound) {
			h.sendError(w, "ValidationError", err.Error(), http.StatusUnprocessableEntity, nil)
		} else if strings.Contains(err.Error(), i18n.T("ErrorValidation", nil)) {
			h.sendError(w, "ValidationError", err.Error(), http.StatusBadRequest, nil)
		} else {
			h.sendError(w, "InternalError", "Failed to create secret", http.StatusInternalServerError, nil)
		}
		return
	}

	uid, sID, uname, sname := userCtx.UserID, response.ID, userCtx.Username, response.Name
	ip, ua := r.RemoteAddr, r.Header.Get(hdrUserAgent)
	// #2545: a client-asserted origin (e.g. keyorix-migrate's source path) is recorded as a
	// labelled note on the audit event — never as attribution; see core.ClientOriginHeader.
	auditCtx := core.WithClientOrigin(core.DetachedAuditContext(r.Context()), r.Header.Get(core.ClientOriginHeader))
	goSafe(func() {
		h.coreService.LogSecretCreatedWithProject(auditCtx, uid, sID, response.ProjectID, uname, sname, ip, ua)
	}) // #nosec G118

	sendCreated(w, newSecretNodeWire(response), i18n.T("SuccessSecretCreated", nil))
}

// ClassifySecret handles PATCH /api/v1/secrets/{id}/classification — set or clear
// the data-classification label (A.5.12). Gated by secrets.write at the secret's
// scope (via the route middleware).
func (h *SecretHandler) ClassifySecret(w http.ResponseWriter, r *http.Request) {
	userCtx, ok := mustGetUser(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", errInvalidSecretID, http.StatusBadRequest, nil)
		return
	}
	var reqBody struct {
		Classification string `json:"classification"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		h.sendError(w, "InvalidJSON", errInvalidJSON, http.StatusBadRequest, nil)
		return
	}
	secret, err := h.coreService.ClassifySecret(r.Context(), userCtx.UserID, userCtx.Username, uint(id), reqBody.Classification)
	if err != nil {
		status := http.StatusInternalServerError
		msg := err.Error()
		switch {
		case strings.Contains(msg, "classification must be"):
			status = http.StatusBadRequest
		case strings.Contains(msg, errNotFound):
			status = http.StatusNotFound
		default:
			log.Printf("Error classifying secret %d: %v", id, err)
			msg = clientSafe(err)
		}
		h.sendError(w, "Error", msg, status, nil)
		return
	}
	h.sendSuccess(w, newSecretNodeWire(secret), "Classification updated")
}

// SetAutoRotate handles PATCH /api/v1/secrets/{id}/auto-rotate — toggles automated
// rotation (ADR-046) for a secret. Enable only for secrets whose value Keyorix owns.
func (h *SecretHandler) SetAutoRotate(w http.ResponseWriter, r *http.Request) {
	userCtx, ok := mustGetUser(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", errInvalidSecretID, http.StatusBadRequest, nil)
		return
	}
	var reqBody struct {
		Enabled bool   `json:"enabled"`
		Length  int    `json:"length"`  // 0 = default
		Charset string `json:"charset"` // "" = default alphanumeric
		Backend string `json:"backend"` // "" = regenerate in Keyorix only
		Ref     string `json:"ref"`     // upstream identifier (required iff backend set)
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		h.sendError(w, "InvalidJSON", errInvalidJSON, http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.SetSecretAutoRotate(r.Context(), uint(id), core.AutoRotateSpec{
		Enabled: reqBody.Enabled, Length: reqBody.Length, Charset: reqBody.Charset,
		Backend: reqBody.Backend, Ref: reqBody.Ref,
	}, userCtx.UserID); err != nil {
		status := http.StatusInternalServerError
		msg := err.Error()
		switch {
		case strings.Contains(msg, errNotFound):
			status = http.StatusNotFound
		case strings.Contains(msg, "unknown rotation charset"),
			strings.Contains(msg, "out of range"),
			strings.Contains(msg, "must be set together"),
			strings.Contains(msg, "unknown rotation backend"),
			strings.Contains(msg, "no rotation backends"):
			status = http.StatusBadRequest
		default:
			log.Printf("Error setting auto-rotate for secret %d: %v", id, err)
			msg = clientSafe(err)
		}
		h.sendError(w, "Error", msg, status, nil)
		return
	}
	h.sendSuccess(w, map[string]interface{}{
		"id": id, "auto_rotate": reqBody.Enabled, "length": reqBody.Length,
		"charset": reqBody.Charset, "backend": reqBody.Backend, "ref": reqBody.Ref,
	}, "Auto-rotation updated")
}

// GetSecret handles GET /api/v1/secrets/{id}
func (h *SecretHandler) GetSecret(w http.ResponseWriter, r *http.Request) { // NOSONAR -- cognitive complexity 19, suppress go:S3776
	userCtx, ok := mustGetUser(w, r)
	if !ok {
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", errInvalidSecretID, http.StatusBadRequest, nil)
		return
	}

	// Machine principals (ADR-030) are already authorized at the secret's scope
	// by the route's scoped-permission gate; the per-user owner/sharing check
	// (and its user-id requirement) does not apply to them, so fetch directly.
	isMachine := userCtx.MachineIdentityID != nil

	var secret *models.SecretNode
	if isMachine {
		// SESSION-PERF (#2403 follow-up): reuse the EXACT resolution
		// RequireScopedSecretPermission already fetched to compute the
		// authorization scope, instead of fetching this same row again.
		// Defensive fallback only: every route serving this handler's machine
		// branch goes through that middleware, which always sets this on
		// success (mirrors GetSecretValueByRef's identical defensive check).
		//
		// Coordinator review, #2420, item 5: trusting the resolved secret
		// WITHOUT checking it actually matches this request's path id would
		// let a future middleware or route wiring change serve one secret's
		// value under another secret's authorization check (the middleware
		// authorized THAT secret's scope, not necessarily this URL's id) --
		// cheap to check, and it keeps this handler correct independent of
		// what the middleware is trusted to have done.
		secret = middleware.GetResolvedSecretFromContext(r.Context())
		if secret == nil || secret.ID != uint(id) {
			// Fail closed: the scoped-permission middleware did not authorize
			// THIS path id (it resolved nothing, or a different secret), so
			// re-authorize the machine principal against the path secret's own
			// scope before serving anything. core.GetSecret itself performs no
			// authorization; the previous fallback served the path secret
			// unchecked.
			secret, err = h.coreService.GetSecret(r.Context(), uint(id))
			if err == nil {
				allowed, aerr := h.coreService.AuthorizeSecretPrincipalForSecret(r.Context(), userCtx.ActorKind(), userCtx.PrincipalID(), secret, permSecretsRead)
				if aerr != nil || !allowed {
					log.Printf("SECURITY: GetSecret machine branch: path secret %d not authorized for principal %d after resolved-secret mismatch", id, userCtx.PrincipalID())
					h.sendError(w, "Forbidden", errAccessDenied, http.StatusForbidden, nil)
					return
				}
			}
		}
	} else {
		secret, err = h.coreService.GetSecretWithPermissionCheck(r.Context(), uint(id), userCtx.UserID)
	}
	if err != nil {
		log.Printf("Error getting secret: %v", err)
		if errors.Is(err, core.ErrAccessOutsideSchedule) {
			h.sendError(w, "Forbidden", err.Error(), http.StatusForbidden, nil)
		} else if strings.Contains(err.Error(), errNotFound) {
			h.sendError(w, "NotFound", errSecretNotFound, http.StatusNotFound, nil)
		} else if strings.Contains(err.Error(), errPermissionDenied) {
			h.sendError(w, "Forbidden", errAccessDenied, http.StatusForbidden, nil)
		} else {
			h.sendError(w, "InternalError", "Failed to get secret", http.StatusInternalServerError, nil)
		}
		return
	}

	var response interface{}
	valueIncluded := r.URL.Query().Get("include_value") == "true" //nolint:goconst
	if valueIncluded {
		var value []byte
		if isMachine {
			// Reuses the SAME resolved secret as above, instead of letting
			// getSecretValueForUser fetch it a third time (SESSION-PERF, #2403
			// follow-up).
			value, err = h.coreService.GetSecretValueResolved(r.Context(), secret)
		} else {
			value, err = h.coreService.GetSecretValueWithPermissionCheck(r.Context(), uint(id), userCtx.UserID)
		}
		if err != nil {
			log.Printf("Error getting secret value: %v", err)
			if strings.Contains(err.Error(), errPermissionDenied) {
				h.sendError(w, "Forbidden", errAccessDenied, http.StatusForbidden, nil)
			} else {
				h.sendError(w, "InternalError", "Failed to get secret value", http.StatusInternalServerError, nil)
			}
			return
		}
		// AUDIT-001 / SESSION-PERF #2403 follow-up (item 3, audit-before-disclosure):
		// the value is only assigned into `response` AFTER its audit entry has been
		// durably committed, below. A metadata-only fetch (include_value omitted)
		// never reaches this branch at all — it doesn't expose the sensitive payload
		// and must not be conflated with a value read in the audit trail.
		uid, sID, uname, sname := userCtx.UserID, uint(id), userCtx.Username, secret.Name
		ip, ua := r.RemoteAddr, r.Header.Get(hdrUserAgent)
		auditCtx := core.DetachedAuditContext(r.Context())
		if auditErr := h.coreService.LogSecretReadWithProject(auditCtx, uid, sID, secret.ProjectID, uname, sname, ip, ua); auditErr != nil {
			log.Printf("SECURITY: audit write failed for secret read (secret=%d): %v -- failing closed, value NOT returned", sID, auditErr)
			h.sendError(w, "InternalError", "Failed to record audit trail", http.StatusInternalServerError, nil)
			return
		}
		response = map[string]interface{}{"secret": h.secretWireWithTotalReads(r.Context(), secret), "value": string(value)}
	} else {
		response = h.secretWireWithTotalReads(r.Context(), secret)
	}

	h.sendSuccess(w, response, "")
}

// secretWireWithTotalReads is newSecretNodeWire plus total_reads, the secret's
// lifetime value-read count (core.SecretTotalReads), for the single-secret GETs.
// Display only: if the count cannot be read the field is omitted and the
// response is otherwise unchanged. On a value read it is computed after that
// read's own audit + access-log write, so it includes this read.
func (h *SecretHandler) secretWireWithTotalReads(ctx context.Context, secret *models.SecretNode) SecretNodeWire {
	w := newSecretNodeWire(secret)
	if n, err := h.coreService.SecretTotalReads(ctx, secret.ID); err == nil {
		w.TotalReads = &n
	} else {
		log.Printf("total_reads for secret %d unavailable: %v", secret.ID, err)
	}
	return w
}

// GetSecretByName handles GET /api/v1/secrets/by-name?name=X&project_id=Y&environment_id=Z
// — looks up a secret's metadata by its name scoped to a project/environment, for
// callers (e.g. the CLI) that only have the name rather than the numeric ID.
// The route's scoped-permission gate (ScopeFromQuery) authorizes the caller against
// the project_id/environment_id query params, matching ListSecrets' convention; the
// per-user ownership/sharing check then runs against the resolved secret's own ID,
// the same belt-and-suspenders pattern GetSecret (by id) uses.
func (h *SecretHandler) GetSecretByName(w http.ResponseWriter, r *http.Request) {
	userCtx, ok := mustGetUser(w, r)
	if !ok {
		return
	}

	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		h.sendError(w, "InvalidParameter", "name is required", http.StatusBadRequest, nil)
		return
	}
	projectID, err := strconv.ParseUint(r.URL.Query().Get("project_id"), 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", "project_id is required", http.StatusBadRequest, nil)
		return
	}
	environmentID, err := strconv.ParseUint(r.URL.Query().Get("environment_id"), 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", "environment_id is required", http.StatusBadRequest, nil)
		return
	}

	// Machine principals (ADR-030) are already authorized at the query-param scope by
	// the route gate; the per-user owner/sharing check does not apply to them, so
	// resolve directly (same split GetSecret uses for the by-id route).
	isMachine := userCtx.MachineIdentityID != nil

	var secret *models.SecretNode
	if isMachine {
		secret, err = h.coreService.GetSecretByName(r.Context(), name, uint(projectID), uint(environmentID))
	} else {
		secret, err = h.coreService.GetSecretByNameWithPermissionCheck(r.Context(), name, uint(projectID), uint(environmentID), userCtx.UserID)
	}
	if err != nil {
		log.Printf("Error getting secret by name: %v", err)
		if strings.Contains(err.Error(), errNotFound) {
			h.sendError(w, "NotFound", errSecretNotFound, http.StatusNotFound, nil)
		} else if strings.Contains(err.Error(), errPermissionDenied) {
			h.sendError(w, "Forbidden", errAccessDenied, http.StatusForbidden, nil)
		} else {
			h.sendError(w, "InternalError", "Failed to get secret", http.StatusInternalServerError, nil)
		}
		return
	}

	// Metadata-only response (no value disclosed below) — stays fire-and-forget,
	// unlike the value-disclosing read paths in this file. Still logged, not
	// silently discarded, but as secret.metadata_read, not secret.read: secret.read
	// means a value disclosure (AUDIT-UX-3).
	uid, sID, uname, sname := userCtx.UserID, secret.ID, userCtx.Username, secret.Name
	ip, ua := r.RemoteAddr, r.Header.Get(hdrUserAgent)
	auditCtx := core.DetachedAuditContext(r.Context())
	goSafe(func() {
		if auditErr := h.coreService.LogSecretMetadataRead(auditCtx, uid, sID, secret.ProjectID, uname, sname, ip, ua); auditErr != nil {
			log.Printf("SECURITY: audit write failed for secret-by-name read (secret=%d): %v", sID, auditErr)
		}
	}) // #nosec G118

	// No total_reads here: this lookup is itself audited as a secret.read (async, above),
	// so a count would be non-deterministic and would include non-value reads.
	h.sendSuccess(w, newSecretNodeWire(secret), "")
}

// GetSecretValueByRef handles GET /api/v1/secrets/value?ref=project/environment/name —
// reads a secret's value resolved by a human-readable reference instead of a numeric
// ID, for integrations (e.g. the External Secrets Operator) that template a key string.
// It reuses the exact by-id read path: the route's scoped-permission gate
// (middleware.RequireScopedSecretRefPermission) resolves the ref, authorizes the caller
// against the resolved secret's scope, and pins the resolution on the request context —
// this handler reuses THAT SAME resolution (middleware.GetResolvedSecretRefFromContext)
// rather than resolving the ref again by name. core.ResolveSecretRef has no
// snapshot/version guarantee (a soft-deleted project's name is free for reuse), so two
// independent resolutions of one ref string could legitimately return secrets from two
// different projects if a delete-and-recreate landed between them; resolving once in the
// middleware and threading the result here closes that TOCTOU window structurally. The
// value is read through the same max-reads / suspension / audit machinery as GetSecret.
func (h *SecretHandler) GetSecretValueByRef(w http.ResponseWriter, r *http.Request) {
	userCtx, ok := mustGetUser(w, r)
	if !ok {
		return
	}

	secret := middleware.GetResolvedSecretRefFromContext(r.Context())
	if secret == nil {
		// Defensive only: every route serving this handler goes through
		// RequireScopedSecretRefPermission, which always sets this on success.
		h.sendError(w, "InternalError", "Failed to resolve secret", http.StatusInternalServerError, nil)
		return
	}

	// Machine principals are already authorized at the secret's scope by the route gate
	// (RequireScopedSecretRefPermission); the per-user owner/sharing check applies to
	// users only.
	isMachine := userCtx.MachineIdentityID != nil
	var value []byte
	var err error
	if isMachine {
		value, err = h.coreService.GetSecretValue(r.Context(), secret.ID)
	} else {
		value, err = h.coreService.GetSecretValueWithPermissionCheck(r.Context(), secret.ID, userCtx.UserID)
	}
	if err != nil {
		log.Printf("Error getting secret value by ref: %v", err)
		if strings.Contains(err.Error(), errPermissionDenied) {
			h.sendError(w, "Forbidden", errAccessDenied, http.StatusForbidden, nil)
		} else {
			h.sendError(w, "InternalError", "Failed to get secret value", http.StatusInternalServerError, nil)
		}
		return
	}

	// SESSION-PERF #2403 follow-up (item 3, audit-before-disclosure): the value is
	// only sent below AFTER its audit entry has been durably committed.
	uid, sID, uname, sname := userCtx.UserID, secret.ID, userCtx.Username, secret.Name
	ip, ua := r.RemoteAddr, r.Header.Get(hdrUserAgent)
	auditCtx := core.DetachedAuditContext(r.Context())
	if auditErr := h.coreService.LogSecretReadWithProject(auditCtx, uid, sID, secret.ProjectID, uname, sname, ip, ua); auditErr != nil {
		log.Printf("SECURITY: audit write failed for secret read by ref (secret=%d): %v -- failing closed, value NOT returned", sID, auditErr)
		h.sendError(w, "InternalError", "Failed to record audit trail", http.StatusInternalServerError, nil)
		return
	}

	h.sendSuccess(w, map[string]interface{}{"secret": newSecretNodeWire(secret), "value": string(value)}, "")
}

// RestoreSecret handles POST /api/v1/secrets/{id}/restore — clears a
// soft-deleted secret's deleted_at (ADR-033). Authorized by the route's scoped
// secrets.write gate at the secret's own project/environment.
func (h *SecretHandler) RestoreSecret(w http.ResponseWriter, r *http.Request) {
	userCtx, ok := mustGetUser(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", errInvalidSecretID, http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.RestoreSecret(r.Context(), userCtx.UserID, uint(id)); err != nil {
		status := http.StatusInternalServerError
		msg := err.Error()
		if strings.Contains(msg, errNotFound) {
			status = http.StatusNotFound
		} else {
			log.Printf("Error restoring secret %d: %v", id, err)
			msg = clientSafe(err)
		}
		h.sendError(w, "Error", msg, status, nil)
		return
	}
	h.sendSuccess(w, map[string]interface{}{"id": id, "restored": true}, "Secret restored")
}

// UpdateSecret handles PUT /api/v1/secrets/{id}
func (h *SecretHandler) UpdateSecret(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	// Machine principals (ADR-030) are already authorized at the secret's scope
	// by the route's RequireScopedSecretPermission(permSecretsWrite) gate; the
	// per-user owner/sharing check (and its user-id requirement — a machine
	// caller's userCtx.UserID is always 0) does not apply to them, so update
	// directly. Mirrors the isMachine split GetSecret/GetSecretByName/
	// GetSecretValueByRef/DeleteSecret already use in this file — UpdateSecret
	// was the one CRUD handler missing it (W1, machine-identity-write gap).
	isMachine := userCtx.MachineIdentityID != nil

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", errInvalidSecretID, http.StatusBadRequest, nil)
		return
	}

	var reqBody struct {
		Value    string `json:"value,omitempty"`
		Type     string `json:"type,omitempty"`
		MaxReads *int   `json:"max_reads,omitempty" validate:"omitempty,min=1"`
		// Expiration sets a new expiry (RFC3339); ClearExpiration removes an existing
		// one. They are mutually exclusive.
		Expiration      string `json:"expiration,omitempty"`
		ClearExpiration bool   `json:"clear_expiration,omitempty"`
		// Secret, when present, is the now-deleted RemoteStorage's full desired
		// SecretNode state (G80 Phase 0) — it takes over the whole request and every
		// other field above is ignored. See updateSecretViaDiff / secret_update_diff.go
		// for why this is a separate, default-deny path rather than folded into the
		// named fields above: those can only ever express the plain-secrets.write-
		// safe fields (there is no JSON key for OwnerID etc.), so a caller using
		// them was never able to smuggle a gated field through — Secret's whole
		// point was to safely accept a caller's full local state without trusting
		// all of it. Not in openapi.yaml's updateSecret schema; no known live
		// caller reaches this branch today (see secret_update_diff.go's package doc).
		Secret *models.SecretNode `json:"secret,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		if h.trySendSecretSizeError(w, err) {
			return
		}
		h.sendError(w, "InvalidJSON", errInvalidJSON, http.StatusBadRequest, nil)
		return
	}

	if reqBody.Secret != nil {
		h.updateSecretViaDiff(w, r, uint(id), userCtx, reqBody.Secret)
		return
	}

	if err := h.validator.Validate(&reqBody); err != nil {
		h.sendError(w, "ValidationError", "Invalid request data", http.StatusBadRequest, err)
		return
	}
	if reqBody.Expiration != "" && reqBody.ClearExpiration {
		h.sendError(w, "ValidationError", "expiration and clear_expiration are mutually exclusive", http.StatusBadRequest, nil)
		return
	}

	req := &core.UpdateSecretRequest{
		ID:              uint(id),
		Type:            reqBody.Type,
		MaxReads:        reqBody.MaxReads,
		ClearExpiration: reqBody.ClearExpiration,
		UpdatedBy:       userCtx.Username,
		UserID:          userCtx.UserID,
	}
	if reqBody.Value != "" {
		req.Value = []byte(reqBody.Value)
	}
	if reqBody.Expiration != "" {
		exp, perr := time.Parse(time.RFC3339, reqBody.Expiration)
		if perr != nil {
			h.sendError(w, "ValidationError", "invalid expiration (use RFC3339)", http.StatusBadRequest, nil)
			return
		}
		req.Expiration = &exp
	}

	// Capture pre-update metadata for the audit diff (raw fetch, no read-count
	// side effect). Best-effort: a miss just yields an empty diff.
	oldSecret, _ := h.coreService.Storage().GetSecret(r.Context(), uint(id))

	var response *models.SecretNode
	if isMachine {
		response, err = h.coreService.UpdateSecret(r.Context(), req)
	} else {
		response, err = h.coreService.UpdateSecretWithPermissionCheck(r.Context(), req)
	}
	if err != nil {
		log.Printf("Error updating secret: %v", err)
		h.sendUpdateSecretError(w, err)
		return
	}

	uid, sID, uname, sname := userCtx.UserID, uint(id), userCtx.Username, response.Name
	ip, ua := r.RemoteAddr, r.Header.Get(hdrUserAgent)
	diff := core.BuildSecretUpdateDiff(oldSecret, req, reqBody.Value != "")
	auditCtx := core.WithClientOrigin(core.DetachedAuditContext(r.Context()), r.Header.Get(core.ClientOriginHeader)) // #2545, see CreateSecret
	goSafe(func() {
		h.coreService.LogSecretUpdatedWithDiff(auditCtx, uid, sID, response.ProjectID, uname, sname, ip, ua, diff)
	}) // #nosec G118

	h.sendSuccess(w, newSecretNodeWire(response), i18n.T("SuccessSecretUpdated", nil))
}

// DeleteSecret handles DELETE /api/v1/secrets/{id}
func (h *SecretHandler) DeleteSecret(w http.ResponseWriter, r *http.Request) {
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
	// by the route's RequireScopedSecretPermission(permSecretsDelete) gate; the
	// per-user owner/sharing check (and its user-id requirement -- a machine
	// caller's userCtx.UserID is always 0, see UserContext.PrincipalID's doc
	// comment) does not apply to them, so delete directly. Found by the #1808
	// differential conformance harness: DeleteSecret was the one CRUD handler
	// in this file missing the isMachine split GetSecret/GetSecretByName/
	// GetSecretValueByRef already use, so every machine-identity-authenticated
	// delete unconditionally failed CheckSecretPermission's userID==0 guard.
	isMachine := userCtx.MachineIdentityID != nil

	// Pre-fetch name and project for audit log before the record is deleted. Plain,
	// unauthorized read: authorization for this delete already happened above, via the
	// route's RequireScopedSecretPermission middleware gate, and happens again below via
	// DeleteSecretWithPermissionCheck itself — a second *WithPermissionCheck call here
	// bought nothing but a second CheckSecretPermission storage round trip (see
	// docs/findings/2026-09-23-FINDING-redundant-authz-prefetch.md).
	prefetched, prefetchErr := h.coreService.GetSecret(r.Context(), uint(id))
	secretName := fmt.Sprintf("id=%d", id)
	var secretProjectID uint
	if prefetchErr == nil {
		secretName = prefetched.Name
		secretProjectID = prefetched.ProjectID
	}

	var deleteErr error
	if isMachine {
		deleteErr = h.coreService.DeleteSecret(r.Context(), uint(id))
	} else {
		deleteErr = h.coreService.DeleteSecretWithPermissionCheck(r.Context(), uint(id), userCtx.UserID)
	}
	if deleteErr != nil {
		log.Printf("Error deleting secret: %v", deleteErr)
		if strings.Contains(deleteErr.Error(), errNotFound) {
			h.sendError(w, "NotFound", errSecretNotFound, http.StatusNotFound, nil)
		} else if strings.Contains(deleteErr.Error(), errPermissionDenied) {
			h.sendError(w, "Forbidden", errAccessDenied, http.StatusForbidden, nil)
		} else {
			h.sendError(w, "InternalError", "Failed to delete secret", http.StatusInternalServerError, nil)
		}
		return
	}

	uid, sID, uname := userCtx.UserID, uint(id), userCtx.Username
	ip, ua := r.RemoteAddr, r.Header.Get(hdrUserAgent)
	auditCtx := core.DetachedAuditContext(r.Context())
	goSafe(func() {
		h.coreService.LogSecretDeletedWithProject(auditCtx, uid, sID, secretProjectID, uname, secretName, ip, ua)
	}) // #nosec G118

	w.WriteHeader(http.StatusNoContent)
}

func (h *SecretHandler) sendUpdateSecretError(w http.ResponseWriter, err error) {
	if h.trySendSecretSizeError(w, err) {
		return
	}
	// W3 (Session W, 2026-09-29): under sustained heavy concurrent writes to the
	// SAME secret, updateSecretWithNewVersion's retry loop can legitimately
	// exhaust — this is expected contention, not a server malfunction, and must
	// tell the caller to retry (409), not report a generic 500. Checked before
	// the generic i18n ErrorStorageFailed fallback below (this error wraps that
	// same i18n prefix too, so it would otherwise fall all the way to the
	// InternalError branch).
	if errors.Is(err, core.ErrSecretVersionContentionExhausted) {
		h.sendError(w, "Conflict", "High write contention on this secret; retry the request", http.StatusConflict, nil)
		return
	}
	if strings.Contains(err.Error(), "not found") {
		h.sendError(w, "NotFound", "Secret not found", http.StatusNotFound, nil)
	} else if strings.Contains(err.Error(), "permission denied") {
		h.sendError(w, "Forbidden", "Access denied", http.StatusForbidden, nil)
	} else if strings.Contains(err.Error(), i18n.T("ErrorValidation", nil)) {
		h.sendError(w, "ValidationError", err.Error(), http.StatusBadRequest, nil)
	} else {
		h.sendError(w, "InternalError", "Failed to update secret", http.StatusInternalServerError, nil)
	}
}
