// pat_handler.go — HTTP handlers for self-service Personal Access Tokens (ADR-027).
//
// Routes (all under /api/v1/auth/tokens, authenticated, self-scoped):
//
//	GET    /auth/tokens        — list the caller's tokens (never returns the secret)
//	POST   /auth/tokens        — create a token (returns the raw token once)
//	DELETE /auth/tokens/{id}   — revoke one of the caller's tokens (204 No Content)
package handlers

import (
	"encoding/json"
	"errors"
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

// PATHandler handles personal-access-token HTTP requests.
type PATHandler struct {
	coreService *core.KeyorixCore
}

// NewPATHandler constructs a PATHandler.
func NewPATHandler(coreService *core.KeyorixCore) *PATHandler {
	return &PATHandler{coreService: coreService}
}

// patResponse is the safe DTO — omits TokenHash; carries only the display prefix.
// scopes/project_scope surface the ADR-042 least-privilege restriction (read-only;
// a token's scope is fixed at creation).
type patResponse struct {
	ID               uint     `json:"id"`
	Name             string   `json:"name"`
	TokenPrefix      string   `json:"token_prefix"`
	Revoked          bool     `json:"revoked"`
	CreatedAt        string   `json:"created_at"`
	ExpiresAt        *string  `json:"expires_at"`
	LastUsedAt       *string  `json:"last_used_at"`
	Scopes           []string `json:"scopes"`            // empty = inherits the owner's full permissions
	ProjectScope     uint     `json:"project_scope"`     // 0 = any project the owner can reach
	EnvironmentScope uint     `json:"environment_scope"` // 0 = any environment
	AllowedCIDRs     []string `json:"allowed_cidrs"`     // empty = no network restriction
}

func toPATResponse(t *models.PersonalAccessToken) patResponse {
	resp := patResponse{
		ID:               t.ID,
		Name:             t.Name,
		TokenPrefix:      t.TokenPrefix,
		Revoked:          t.Revoked,
		CreatedAt:        t.CreatedAt.UTC().Format(time.RFC3339),
		Scopes:           core.DecodePATScopes(t.Scopes),
		ProjectScope:     t.ProjectScope,
		EnvironmentScope: t.EnvironmentScope,
		AllowedCIDRs:     core.DecodePATCIDRs(t.AllowedCIDRs),
	}
	if t.ExpiresAt != nil {
		v := t.ExpiresAt.UTC().Format(time.RFC3339)
		resp.ExpiresAt = &v
	}
	if t.LastUsedAt != nil {
		v := t.LastUsedAt.UTC().Format(time.RFC3339)
		resp.LastUsedAt = &v
	}
	return resp
}

// ListPATs handles GET /auth/tokens.
func (h *PATHandler) ListPATs(w http.ResponseWriter, r *http.Request) {
	userCtx, ok := mustGetHumanUser(w, r)
	if !ok {
		return
	}
	tokens, err := h.coreService.ListOwnPATs(r.Context(), userCtx.UserID)
	if err != nil {
		sendError(w, "InternalError", "Failed to list tokens", http.StatusInternalServerError, nil)
		return
	}
	out := make([]patResponse, 0, len(tokens))
	for _, t := range tokens {
		out = append(out, toPATResponse(t))
	}
	sendSuccess(w, out, "")
}

// patHygieneResponse is one flagged token in the admin hygiene view: the safe PAT DTO
// (no hash) plus the owner and the reasons it was flagged.
type patHygieneResponse struct {
	patResponse
	UserID  uint `json:"user_id"`
	Expired bool `json:"expired"`
	Stale   bool `json:"stale"`
}

// PATHygiene handles GET /api/v1/pat-hygiene?days=N — the deployment-wide list of
// non-revoked tokens that are expired-but-active or stale (unused for the window), so
// an admin can revoke token sprawl. Global audit.read is enforced by the router (it
// discloses every user's PAT scopes/CIDRs/owning user ID deployment-wide, so the
// universal system_viewer baseline is not enough).
// days defaults to 90 and is capped at 3650.
func (h *PATHandler) PATHygiene(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	days := 90
	if v := r.URL.Query().Get("days"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			days = n
		}
	}
	if days > 3650 {
		days = 3650
	}

	entries, err := h.coreService.ListPATHygiene(r.Context(), time.Duration(days)*24*time.Hour)
	if err != nil {
		sendError(w, "InternalError", "Failed to list token hygiene", http.StatusInternalServerError, nil)
		return
	}
	out := make([]patHygieneResponse, 0, len(entries))
	for _, e := range entries {
		out = append(out, patHygieneResponse{
			patResponse: toPATResponse(e.Token),
			UserID:      e.Token.UserID,
			Expired:     e.Expired,
			Stale:       e.Stale,
		})
	}
	sendSuccess(w, map[string]any{"tokens": out, "total": len(out)}, "")
}

type createPATRequestBody struct {
	Name      string  `json:"name"`
	ExpiresAt *string `json:"expires_at"` // RFC3339; omit/null for a non-expiring token
	// Scopes is an optional least-privilege permission allowlist (ADR-042). Omit or
	// leave empty to inherit the owner's full permission set (the default).
	Scopes []string `json:"scopes"`
	// ProjectScope optionally confines the token to a single project (0/omit = any).
	ProjectScope uint `json:"project_scope"`
	// EnvironmentScope optionally confines the token to one environment (0/omit = any).
	EnvironmentScope uint `json:"environment_scope"`
	// AllowedCIDRs optionally restricts the token to source IPs within these CIDR blocks
	// (e.g. ["10.0.0.0/8"]). Omit/empty = no network restriction.
	AllowedCIDRs []string `json:"allowed_cidrs"`
}

// CreatePAT handles POST /auth/tokens. The raw token is returned exactly once.
func (h *PATHandler) CreatePAT(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	var body createPATRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "BadRequest", "Invalid request body", http.StatusBadRequest, nil)
		return
	}

	var expiresAt *time.Time
	if body.ExpiresAt != nil && *body.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, *body.ExpiresAt)
		if err != nil {
			sendError(w, "BadRequest", "Invalid expires_at (want RFC3339)", http.StatusBadRequest, nil)
			return
		}
		expiresAt = &t
	}

	result, err := h.coreService.CreateOwnPAT(r.Context(), userCtx.UserID, body.Name, expiresAt, body.Scopes, body.ProjectScope, body.EnvironmentScope, body.AllowedCIDRs)
	if err != nil {
		if errors.Is(err, core.ErrRestrictedPATCannotMintPAT) {
			sendError(w, "Forbidden", err.Error(), http.StatusForbidden, nil)
			return
		}
		if strings.Contains(err.Error(), i18n.T("ErrorValidation", nil)) {
			sendError(w, "BadRequest", err.Error(), http.StatusBadRequest, nil)
		} else {
			log.Printf("CreateOwnPAT storage error for user %d: %v", userCtx.UserID, err)
			sendError(w, "InternalError", clientSafe(err), http.StatusInternalServerError, nil)
		}
		return
	}

	resp := toPATResponse(result.Token)
	// The plaintext token is included once here and never again.
	//
	// sendCreated, not WriteHeader+sendSuccess: WriteHeader flushes headers
	// immediately, so a Content-Type set inside sendSuccess afterward is a
	// silent no-op -- Go's http.ResponseWriter then sniffs the JSON body's
	// leading '{' as "text/plain; charset=utf-8" (its sniffer has no JSON
	// case), which a spec-compliant generated client (the thin CLI's
	// oapi-codegen apiclient) correctly refuses to parse as JSON. Found via
	// docs/cli-split-inventory.md PR 2's live-server verification: curl -i
	// showed the wrong Content-Type on this exact response.
	sendCreated(w, map[string]any{
		"token": result.PlainToken,
		"pat":   resp,
	}, "Token created — copy it now, it will not be shown again")
}

// RevokePAT handles DELETE /auth/tokens/{id}.
func (h *PATHandler) RevokePAT(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "BadRequest", "Invalid token ID", http.StatusBadRequest, nil)
		return
	}
	tokenHash, err := h.coreService.RevokeOwnPAT(r.Context(), userCtx.UserID, uint(id))
	if err != nil {
		sendError(w, "NotFound", "Token not found", http.StatusNotFound, nil)
		return
	}
	// Evict the auth cache so the revoked token stops authenticating immediately rather
	// than lingering for the positive-cache TTL.
	middleware.InvalidateTokenCacheByHash(tokenHash)
	w.WriteHeader(http.StatusNoContent)
}
