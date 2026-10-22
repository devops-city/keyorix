// machine_identities.go — machine identity endpoints (ADR-023).
//
// Non-human project members, segmented from human members in the Members view.
// Project-scoped: list is users.read; create/transition need roles.assign.
package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// machineIdentityProxyWire mirrors models.MachineIdentity's fields in explicit
// snake_case (the model carries no json tags of its own, so a direct marshal
// would send Go-cased keys instead of this API's wire convention). Named
// "Proxy" for its ADR-108-deleted origin (server/http/handlers/
// machine_identities_proxy.go, removed with the /system proxy tier); kept
// here unrenamed since this handler's live callers already depend on it.
type machineIdentityProxyWire struct {
	ID                         uint       `json:"id"`
	ProjectID                  uint       `json:"project_id"`
	Name                       string     `json:"name"`
	IdentityType               string     `json:"identity_type"`
	State                      string     `json:"state"`
	Description                string     `json:"description"`
	CreatedBy                  uint       `json:"created_by"`
	CreatedAt                  time.Time  `json:"created_at"`
	UpdatedAt                  time.Time  `json:"updated_at"`
	LastSeenAt                 *time.Time `json:"last_seen_at"`
	RevokedAt                  *time.Time `json:"revoked_at"`
	Classification             string     `json:"classification"`
	CreatedByMachineIdentityID uint       `json:"created_by_machine_identity_id,omitempty"` // #1573 machine-caller attribution; mirrors models.MachineIdentity
}

func newMachineIdentityProxyWire(m *models.MachineIdentity) machineIdentityProxyWire {
	return machineIdentityProxyWire{
		ID:                         m.ID,
		ProjectID:                  m.ProjectID,
		Name:                       m.Name,
		IdentityType:               m.IdentityType,
		State:                      m.State,
		Description:                m.Description,
		CreatedBy:                  m.CreatedBy,
		CreatedAt:                  m.CreatedAt,
		UpdatedAt:                  m.UpdatedAt,
		LastSeenAt:                 m.LastSeenAt,
		RevokedAt:                  m.RevokedAt,
		Classification:             m.Classification,
		CreatedByMachineIdentityID: m.CreatedByMachineIdentityID,
	}
}

// ListMachineIdentities handles GET /api/v1/projects/{id}/machine-identities.
func (h *CatalogHandler) ListMachineIdentities(w http.ResponseWriter, r *http.Request) {
	id, ok := mustParseProjectID(w, r)
	if !ok {
		return
	}
	identities, err := h.coreService.ListMachineIdentities(r.Context(), id)
	if err != nil {
		log.Printf("Error listing machine identities for project %d: %v", id, err)
		sendError(w, "Error", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	// machineIdentityProxyWire (machine_identities_proxy.go), not identities directly:
	// models.MachineIdentity carries no json tags, so a raw marshal sends Go-cased keys
	// ("IdentityType", "ProjectID", ...) instead of this API's snake_case convention --
	// confirmed live against this exact route (docs/cli-split-inventory.md PR 2's
	// live-verification step: `machine create`/`machine list` silently rendered an
	// empty type/project fields). The proxy path already solved this; reuse its wire
	// type rather than duplicating it.
	wire := make([]machineIdentityProxyWire, 0, len(identities))
	for _, m := range identities {
		wire = append(wire, newMachineIdentityProxyWire(m))
	}
	sendSuccess(w, map[string]any{"machine_identities": wire}, "")
}

// ListStaleMachineIdentities handles GET /api/v1/projects/{id}/machine-identities/stale?days=N
// — active machine identities not seen within the window (default 90, capped 3650).
func (h *CatalogHandler) ListStaleMachineIdentities(w http.ResponseWriter, r *http.Request) {
	id, ok := mustParseProjectID(w, r)
	if !ok {
		return
	}
	days := 90
	if v := r.URL.Query().Get("days"); v != "" {
		if n, perr := strconv.Atoi(v); perr == nil && n > 0 {
			days = n
		}
	}
	if days > 3650 {
		days = 3650
	}
	identities, err := h.coreService.ListStaleMachineIdentities(r.Context(), id, time.Duration(days)*24*time.Hour)
	if err != nil {
		log.Printf("Error listing stale machine identities for project %d: %v", id, err)
		sendError(w, "Error", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]any{"machine_identities": identities, "total": len(identities)}, "")
}

// CreateMachineIdentity handles POST /api/v1/projects/{id}/machine-identities.
func (h *CatalogHandler) CreateMachineIdentity(w http.ResponseWriter, r *http.Request) {
	id, ok := mustParseProjectID(w, r)
	if !ok {
		return
	}
	actor, ok := mustGetUser(w, r)
	if !ok {
		return
	}
	var body struct {
		Name           string `json:"name"`
		IdentityType   string `json:"identity_type"`
		Description    string `json:"description"`
		Classification string `json:"classification"`
	}
	if !mustDecodeBody(w, r, &body) {
		return
	}
	if body.Name == "" {
		sendError(w, "ValidationError", "name is required", http.StatusBadRequest, nil)
		return
	}
	// #2545, extended to machine identities: a client-asserted origin (e.g. keyorix-migrate's
	// source Vault auth-role) is recorded as a labelled note on the audit event, never as
	// attribution.
	auditCtx := core.WithClientOrigin(r.Context(), r.Header.Get(core.ClientOriginHeader))
	m, err := h.coreService.CreateMachineIdentity(auditCtx, id, body.Name, body.IdentityType, body.Description, body.Classification, actor.UserID, machineID(r))
	if err != nil {
		status := http.StatusInternalServerError
		msg := err.Error()
		if strings.Contains(msg, "invalid identity_type") || strings.Contains(msg, "required") {
			status = http.StatusBadRequest
		} else {
			log.Printf("Error creating machine identity for project %d: %v", id, err)
			msg = clientSafe(err)
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	// sendCreated, not WriteHeader+sendSuccess -- see CreatePAT's comment
	// (pat_handler.go) for why the latter silently sends the wrong Content-Type.
	// machineIdentityProxyWire, not m directly -- see ListMachineIdentities' comment
	// above for why a raw models.MachineIdentity marshal is wrong here.
	sendCreated(w, map[string]any{"machine_identity": newMachineIdentityProxyWire(m)}, "Machine identity created")
}

// MigrateUserToMachine handles POST /api/v1/projects/{id}/machine-identities/migrate-from-user
// (ADR-023) — converts a service-account-shaped human user into a project machine
// identity and, unless keep_user is set, suspends the source user so it can no longer log
// in. The user is never deleted. Needs roles.assign (project) AND users.write (the suspend).
func (h *CatalogHandler) MigrateUserToMachine(w http.ResponseWriter, r *http.Request) {
	id, ok := mustParseProjectID(w, r)
	if !ok {
		return
	}
	actor, ok := mustGetUser(w, r)
	if !ok {
		return
	}
	var body struct {
		Username     string `json:"username"`
		IdentityType string `json:"identity_type"`
		Name         string `json:"name"`
		// KeepUser leaves the source user able to log in; the default (false) suspends
		// it so the human-login path is closed once the machine identity exists.
		KeepUser bool `json:"keep_user"`
	}
	if !mustDecodeBody(w, r, &body) {
		return
	}
	if body.Username == "" {
		sendError(w, "ValidationError", "username is required", http.StatusBadRequest, nil)
		return
	}

	m, err := h.coreService.MigrateUserToMachine(r.Context(), body.Username, id, body.IdentityType, body.Name, actor.UserID, machineID(r), !body.KeepUser)
	if err != nil {
		status := http.StatusInternalServerError
		msg := err.Error()
		switch {
		case strings.Contains(msg, errNotFound):
			status = http.StatusNotFound
		case strings.Contains(msg, "required") || strings.Contains(msg, "invalid identity_type"):
			status = http.StatusBadRequest
		default:
			log.Printf("Error migrating user %q to machine identity in project %d: %v", body.Username, id, err)
			msg = clientSafe(err)
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	sendCreated(w, map[string]any{"machine_identity": m}, "User migrated to machine identity")
}

// TransitionMachineIdentity handles PUT /api/v1/projects/{id}/machine-identities/{machineId}.
// Body: {"action": "activate" | "suspend" | "revoke"}.
func (h *CatalogHandler) TransitionMachineIdentity(w http.ResponseWriter, r *http.Request) {
	projectID, ok := mustParseProjectID(w, r)
	if !ok {
		return
	}
	machineID, err := strconv.ParseUint(chi.URLParam(r, "machineId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidMachineID, http.StatusBadRequest, nil)
		return
	}
	actor, ok := mustGetUser(w, r)
	if !ok {
		return
	}
	var body struct {
		Action string `json:"action"`
	}
	if !mustDecodeBody(w, r, &body) {
		return
	}
	to, ok := machineActionState(body.Action)
	if !ok {
		sendError(w, "ValidationError", "action must be activate, suspend, or revoke", http.StatusBadRequest, nil)
		return
	}
	m, err := h.coreService.TransitionMachineIdentity(r.Context(), projectID, uint(machineID), to, actor.UserID)
	if err != nil {
		status := http.StatusInternalServerError
		msg := err.Error()
		switch {
		case strings.Contains(msg, errNotFound):
			status = http.StatusNotFound
		case strings.Contains(msg, "cannot transition"):
			status = http.StatusConflict
		default:
			log.Printf("Error transitioning machine identity %d in project %d: %v", machineID, projectID, err)
			msg = clientSafe(err)
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	// Suspending or revoking the identity must reject its tokens immediately, not after
	// the auth-cache TTL — evict every credential's cache entry.
	if to == core.MachineSuspended || to == core.MachineRevoked {
		if hashes, herr := h.coreService.MachineTokenHashes(r.Context(), uint(machineID)); herr == nil {
			for _, hsh := range hashes {
				middleware.InvalidateTokenCacheByHash(hsh)
			}
		}
	}
	sendSuccess(w, map[string]any{"machine_identity": m}, "Machine identity updated")
}

// IssueMachineToken handles POST /api/v1/projects/{id}/machine-identities/{machineId}/tokens.
// Returns the raw token ONCE. Body: {"name": "...", "expires_in_days": 90}.
func (h *CatalogHandler) IssueMachineToken(w http.ResponseWriter, r *http.Request) {
	projectID, ok := mustParseProjectID(w, r)
	if !ok {
		return
	}
	machineID, err := strconv.ParseUint(chi.URLParam(r, "machineId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidMachineID, http.StatusBadRequest, nil)
		return
	}
	actor, ok := mustGetUser(w, r)
	if !ok {
		return
	}
	var body struct {
		Name                string   `json:"name"`
		ExpiresInDays       int      `json:"expires_in_days"`
		Classification      string   `json:"classification"`
		AllowedCIDRs        []string `json:"allowed_cidrs"`
		ReplaceCredentialID uint     `json:"replace_credential_id"` // PAT-006: atomic rotation
	}
	if !mustDecodeBody(w, r, &body) {
		return
	}
	var expiresAt *time.Time
	if body.ExpiresInDays > 0 {
		t := time.Now().AddDate(0, 0, body.ExpiresInDays)
		expiresAt = &t
	}
	// #2545, extended to machine credentials: a client-asserted origin is recorded as a
	// labelled note on the audit event, never as attribution.
	auditCtx := core.WithClientOrigin(r.Context(), r.Header.Get(core.ClientOriginHeader))
	result, err := h.coreService.IssueMachineToken(auditCtx, projectID, uint(machineID), actor.UserID, core.IssueMachineTokenParams{
		Name:                body.Name,
		ExpiresAt:           expiresAt,
		Classification:      body.Classification,
		AllowedCIDRs:        body.AllowedCIDRs,
		ReplaceCredentialID: body.ReplaceCredentialID,
	})
	if err != nil {
		// A rotation revokes the old credential first (never blocked by the audit log);
		// if issuing the new one then fails, the old one stays revoked (503, partial
		// apply; core already evicted it from the auth cache).
		if sendPartialMutation(w, err) {
			log.Printf("Rotation of machine token for machine %d in project %d partially applied: %v", machineID, projectID, err)
			return
		}
		status := http.StatusInternalServerError
		msg := err.Error()
		switch {
		case strings.Contains(msg, errNotFound):
			status = http.StatusNotFound
		case strings.Contains(msg, "replace_credential_id"):
			status = http.StatusNotFound
		case strings.Contains(msg, "must be active"):
			status = http.StatusConflict
		default:
			log.Printf("Error issuing machine token for machine %d in project %d: %v", machineID, projectID, err)
			msg = clientSafe(err)
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	// PAT-006: evict the replaced credential from the auth cache so it stops
	// authenticating immediately — the same eviction RevokeMachineToken performs.
	if result.ReplacedTokenHash != "" {
		middleware.InvalidateTokenCacheByHash(result.ReplacedTokenHash)
	}
	msg := "Machine token issued — copy it now; it will not be shown again"
	if result.ReplacedTokenHash != "" {
		msg = "Machine token rotated — old credential revoked; copy the new token now, it will not be shown again"
	}
	// sendCreated, not WriteHeader+sendSuccess -- see CreatePAT's comment
	// (pat_handler.go) for why the latter silently sends the wrong Content-Type.
	sendCreated(w, map[string]any{
		"token":          result.PlainToken, // shown once
		"id":             result.Credential.ID,
		"prefix":         result.Credential.TokenPrefix,
		"expires_at":     result.Credential.ExpiresAt,
		"classification": result.Credential.Classification,
		// Echo the PERSISTED restriction (decoded from the stored credential), not
		// the raw request body — encodePATCIDRs normalizes/dedups/validates CIDRs
		// server-side, so the two can legitimately differ.
		"allowed_cidrs": core.DecodePATCIDRs(result.Credential.AllowedCIDRs),
	}, msg)
}

// ListMachineTokens handles GET /api/v1/projects/{id}/machine-identities/{machineId}/tokens.
// Returns credential metadata only — never the token.
func (h *CatalogHandler) ListMachineTokens(w http.ResponseWriter, r *http.Request) {
	projectID, ok := mustParseProjectID(w, r)
	if !ok {
		return
	}
	machineID, err := strconv.ParseUint(chi.URLParam(r, "machineId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidMachineID, http.StatusBadRequest, nil)
		return
	}
	creds, err := h.coreService.ListMachineTokens(r.Context(), projectID, uint(machineID))
	if err != nil {
		log.Printf("Error listing machine tokens for machine %d in project %d: %v", machineID, projectID, err)
		sendError(w, "Error", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	out := make([]map[string]any, 0, len(creds))
	for _, c := range creds {
		out = append(out, map[string]any{
			"id":             c.ID,
			"name":           c.Name,
			"prefix":         c.TokenPrefix,
			"last_used_at":   c.LastUsedAt,
			"expires_at":     c.ExpiresAt,
			"revoked":        c.Revoked,
			"classification": c.Classification,
			"created_at":     c.CreatedAt,
		})
	}
	sendSuccess(w, map[string]any{"tokens": out}, "")
}

// RevokeMachineToken handles DELETE /api/v1/projects/{id}/machine-identities/{machineId}/tokens/{tokenId}.
func (h *CatalogHandler) RevokeMachineToken(w http.ResponseWriter, r *http.Request) {
	projectID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidProjectID, http.StatusBadRequest, nil)
		return
	}
	machineID, err := strconv.ParseUint(chi.URLParam(r, "machineId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidMachineID, http.StatusBadRequest, nil)
		return
	}
	tokenID, err := strconv.ParseUint(chi.URLParam(r, "tokenId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid token ID", http.StatusBadRequest, nil)
		return
	}
	actor, ok := mustGetUser(w, r)
	if !ok {
		return
	}
	tokenHash, err := h.coreService.RevokeMachineToken(r.Context(), uint(projectID), uint(machineID), uint(tokenID), actor.UserID)
	if err != nil {
		status := http.StatusInternalServerError
		msg := err.Error()
		if strings.Contains(msg, errNotFound) {
			status = http.StatusNotFound
		} else {
			log.Printf("Error revoking machine token %d for machine %d in project %d: %v", tokenID, machineID, projectID, err)
			msg = clientSafe(err)
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	// Evict the auth cache so the revoked token stops authenticating immediately.
	middleware.InvalidateTokenCacheByHash(tokenHash)
	sendSuccess(w, nil, "Machine token revoked")
}

// ClassifyMachineIdentity handles PATCH
// /api/v1/projects/{id}/machine-identities/{machineId}/classification.
func (h *CatalogHandler) ClassifyMachineIdentity(w http.ResponseWriter, r *http.Request) {
	projectID, machineID, actor, ok := h.machineRouteCtx(w, r)
	if !ok {
		return
	}
	var body struct {
		Classification string `json:"classification"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", errInvalidRequestBody, http.StatusBadRequest, nil)
		return
	}
	m, err := h.coreService.ClassifyMachineIdentity(r.Context(), projectID, machineID, body.Classification, actor.UserID)
	if err != nil {
		status := http.StatusBadRequest
		msg := err.Error()
		switch {
		case strings.Contains(msg, errNotFound):
			status = http.StatusNotFound
		case strings.Contains(msg, "classification must be"):
			// keep 400, msg is the deliberate validation message
		default:
			status = http.StatusInternalServerError
			log.Printf("Error classifying machine identity %d in project %d: %v", machineID, projectID, err)
			msg = clientSafe(err)
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	sendSuccess(w, map[string]any{"machine_identity": m}, "Classification updated")
}

// ClassifyMachineToken handles PATCH
// /api/v1/projects/{id}/machine-identities/{machineId}/tokens/{tokenId}/classification.
func (h *CatalogHandler) ClassifyMachineToken(w http.ResponseWriter, r *http.Request) {
	projectID, machineID, actor, ok := h.machineRouteCtx(w, r)
	if !ok {
		return
	}
	tokenID, err := strconv.ParseUint(chi.URLParam(r, "tokenId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid token ID", http.StatusBadRequest, nil)
		return
	}
	var body struct {
		Classification string `json:"classification"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", errInvalidRequestBody, http.StatusBadRequest, nil)
		return
	}
	cred, err := h.coreService.ClassifyMachineToken(r.Context(), projectID, machineID, uint(tokenID), body.Classification, actor.UserID)
	if err != nil {
		status := http.StatusBadRequest
		msg := err.Error()
		switch {
		case strings.Contains(msg, errNotFound):
			status = http.StatusNotFound
		case strings.Contains(msg, "classification must be"):
			// keep 400, msg is the deliberate validation message
		default:
			status = http.StatusInternalServerError
			log.Printf("Error classifying machine token %d for machine %d in project %d: %v", tokenID, machineID, projectID, err)
			msg = clientSafe(err)
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	sendSuccess(w, map[string]any{
		"id": cred.ID, "classification": cred.Classification,
	}, "Classification updated")
}

// GrantMachineRole handles POST /api/v1/projects/{id}/machine-identities/{machineId}/roles.
// Body: {"role_id": 5}. The role is granted at the project scope.
func (h *CatalogHandler) GrantMachineRole(w http.ResponseWriter, r *http.Request) {
	h.changeMachineRole(w, r, true)
}

// RemoveMachineRole handles DELETE /api/v1/projects/{id}/machine-identities/{machineId}/roles/{roleId}[?environment_id=N].
func (h *CatalogHandler) RemoveMachineRole(w http.ResponseWriter, r *http.Request) {
	h.changeMachineRole(w, r, false)
}

func (h *CatalogHandler) changeMachineRole(w http.ResponseWriter, r *http.Request, grant bool) { // NOSONAR -- cognitive complexity 16, suppress go:S3776
	projectID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidProjectID, http.StatusBadRequest, nil)
		return
	}
	machineID, err := strconv.ParseUint(chi.URLParam(r, "machineId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidMachineID, http.StatusBadRequest, nil)
		return
	}
	actor, ok := mustGetUser(w, r)
	if !ok {
		return
	}

	var roleID uint
	var environmentID uint
	if grant {
		// EnvironmentID mirrors AssignRoleRequest's own field (server/http/handlers/rbac.go)
		// -- 0 = global (every environment in this project), matching core.Scope's existing
		// sentinel. Added so a machine identity can be granted a role scoped to ONE
		// environment, not only project-wide -- previously this endpoint always passed
		// EnvironmentID: 0 regardless of the body, the one gap keyorix-migrate's ADR-114
		// access-model migration depends on closing (#2542).
		var body struct {
			RoleID        uint `json:"role_id"`
			EnvironmentID uint `json:"environment_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.RoleID == 0 {
			sendError(w, "ValidationError", "role_id is required", http.StatusBadRequest, nil)
			return
		}
		roleID = body.RoleID
		environmentID = body.EnvironmentID
	} else {
		rid, err := strconv.ParseUint(chi.URLParam(r, "roleId"), 10, 32)
		if err != nil {
			sendError(w, "InvalidParameter", "Invalid role ID", http.StatusBadRequest, nil)
			return
		}
		roleID = uint(rid)
		// Optional ?environment_id=N names the environment of an environment-scoped
		// grant (matches the grant body's environment_id); absent/0 = the project-wide
		// grant. Parsed strictly: a malformed value must not silently fall back to the
		// project-wide grant and remove the wrong one.
		if v := r.URL.Query().Get("environment_id"); v != "" {
			eid, perr := strconv.ParseUint(v, 10, 32)
			if perr != nil {
				sendError(w, "InvalidParameter", "Invalid environment_id", http.StatusBadRequest, nil)
				return
			}
			environmentID = uint(eid)
		}
	}

	scope := core.Scope{ProjectID: uint(projectID), EnvironmentID: environmentID}
	if grant {
		// #2545, extended to machine role grants: a client-asserted origin is recorded as a
		// labelled note on the audit event, never as attribution.
		ctx := core.WithClientOrigin(r.Context(), r.Header.Get(core.ClientOriginHeader))
		if actor.ActorKind() == core.ActorTypeMachine {
			// A genuine, directly-authenticated machine actor requesting this
			// grant as itself (not a /system proxy relay) -- tag ctx so
			// requireGranterHoldsRolePermissions checks ITS real permissions
			// instead of unconditionally refusing. See that function's doc.
			ctx = core.WithSelfMachineGranter(ctx, actor.PrincipalID())
		}
		err = h.coreService.AssignMachineRole(ctx, uint(machineID), roleID, scope, actor.UserID, actor.ActorKind() == core.ActorTypeMachine)
	} else {
		err = h.coreService.RemoveMachineRole(r.Context(), uint(machineID), roleID, scope, actor.UserID)
	}
	if err != nil {
		if sendRoleScopeError(w, err) {
			return
		}
		status := http.StatusInternalServerError
		msg := err.Error()
		switch {
		case strings.Contains(msg, errNotFound):
			status = http.StatusNotFound
		case strings.Contains(msg, "already") || strings.Contains(msg, "not assigned"):
			status = http.StatusConflict
		case strings.Contains(msg, "does not belong to project"):
			status = http.StatusBadRequest
		default:
			log.Printf("Error changing machine role for machine %d in project %d: %v", machineID, projectID, err)
			msg = clientSafe(err)
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	verb := "granted"
	if !grant {
		verb = "removed"
	}
	sendSuccess(w, nil, "Machine role "+verb)
}

// ListMachineRoles handles GET /api/v1/projects/{id}/machine-identities/{machineId}/roles.
// Mirrors GetUserRolesForUser's response shape (data.roles[] of {id, name}) —
// core.ListMachineRoles already verifies the machine identity belongs to the
// given project before returning its granted roles.
func (h *CatalogHandler) ListMachineRoles(w http.ResponseWriter, r *http.Request) {
	projectID, machineID, _, ok := h.machineRouteCtx(w, r)
	if !ok {
		return
	}
	roles, err := h.coreService.ListMachineRoles(r.Context(), projectID, machineID)
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, errNotFound) {
			sendError(w, "NotFound", clientSafe(err), http.StatusNotFound, nil)
			return
		}
		log.Printf("Error listing machine roles for machine %d in project %d: %v", machineID, projectID, err)
		sendError(w, "Error", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	apiRoles := make([]apiRole, 0, len(roles))
	for _, role := range roles {
		apiRoles = append(apiRoles, apiRole{ID: role.ID, Name: role.Name})
	}
	sendSuccess(w, map[string]any{"roles": apiRoles}, "")
}

// CreateOIDCBinding handles POST /api/v1/projects/{id}/machine-identities/{machineId}/oidc-bindings.
// Body: {"issuer": "...", "subject": "..."} (ADR-031).
func (h *CatalogHandler) CreateOIDCBinding(w http.ResponseWriter, r *http.Request) {
	projectID, machineID, actor, ok := h.machineRouteCtx(w, r)
	if !ok {
		return
	}
	var body struct {
		Issuer  string `json:"issuer"`
		Subject string `json:"subject"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", errInvalidRequestBody, http.StatusBadRequest, nil)
		return
	}
	// #2545, extended to OIDC bindings: a client-asserted origin is recorded as a labelled
	// note on the audit event, never as attribution.
	auditCtx := core.WithClientOrigin(r.Context(), r.Header.Get(core.ClientOriginHeader))
	b, err := h.coreService.CreateOIDCBinding(auditCtx, projectID, machineID, body.Issuer, body.Subject, actor.UserID)
	if err != nil {
		status := http.StatusInternalServerError
		msg := err.Error()
		switch {
		case strings.Contains(msg, errNotFound):
			status = http.StatusNotFound
		case strings.Contains(msg, "required"):
			status = http.StatusBadRequest
		case strings.Contains(msg, "already bound"):
			status = http.StatusConflict
		default:
			log.Printf("Error creating OIDC binding for machine %d in project %d: %v", machineID, projectID, err)
			msg = clientSafe(err)
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	// sendCreated, not WriteHeader+sendSuccess -- see CreatePAT's comment
	// (pat_handler.go) for why the latter silently sends the wrong Content-Type.
	sendCreated(w, map[string]any{"id": b.ID, "issuer": b.Issuer, "subject": b.Subject}, "OIDC binding created")
}

// ListOIDCBindings handles GET /api/v1/projects/{id}/machine-identities/{machineId}/oidc-bindings.
func (h *CatalogHandler) ListOIDCBindings(w http.ResponseWriter, r *http.Request) {
	projectID, machineID, _, ok := h.machineRouteCtx(w, r)
	if !ok {
		return
	}
	bindings, err := h.coreService.ListOIDCBindings(r.Context(), projectID, machineID)
	if err != nil {
		status := http.StatusInternalServerError
		msg := err.Error()
		if strings.Contains(msg, errNotFound) {
			status = http.StatusNotFound
		} else {
			log.Printf("Error listing OIDC bindings for machine %d in project %d: %v", machineID, projectID, err)
			msg = clientSafe(err)
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	out := make([]map[string]any, 0, len(bindings))
	for _, b := range bindings {
		out = append(out, map[string]any{"id": b.ID, "issuer": b.Issuer, "subject": b.Subject, "created_at": b.CreatedAt})
	}
	sendSuccess(w, map[string]any{"bindings": out}, "")
}

// DeleteOIDCBinding handles DELETE /api/v1/projects/{id}/machine-identities/{machineId}/oidc-bindings/{bindingId}.
func (h *CatalogHandler) DeleteOIDCBinding(w http.ResponseWriter, r *http.Request) {
	projectID, machineID, actor, ok := h.machineRouteCtx(w, r)
	if !ok {
		return
	}
	bindingID, err := strconv.ParseUint(chi.URLParam(r, "bindingId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid binding ID", http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.DeleteOIDCBinding(r.Context(), projectID, machineID, uint(bindingID), actor.UserID); err != nil {
		status := http.StatusInternalServerError
		msg := err.Error()
		if strings.Contains(msg, errNotFound) {
			status = http.StatusNotFound
		} else {
			log.Printf("Error deleting OIDC binding %d for machine %d in project %d: %v", bindingID, machineID, projectID, err)
			msg = clientSafe(err)
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	sendSuccess(w, nil, "OIDC binding removed")
}

// machineRouteCtx parses the project + machine path params and the actor,
// writing the appropriate error response and returning ok=false on failure.
func (h *CatalogHandler) machineRouteCtx(w http.ResponseWriter, r *http.Request) (projectID, machineID uint, actor *middleware.UserContext, ok bool) {
	pid, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidProjectID, http.StatusBadRequest, nil)
		return
	}
	mid, err := strconv.ParseUint(chi.URLParam(r, "machineId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidMachineID, http.StatusBadRequest, nil)
		return
	}
	actor = middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	return uint(pid), uint(mid), actor, true
}

func machineActionState(action string) (string, bool) {
	switch action {
	case "activate":
		return core.MachineActive, true
	case "suspend":
		return core.MachineSuspended, true
	case "revoke":
		return core.MachineRevoked, true
	default:
		return "", false
	}
}
