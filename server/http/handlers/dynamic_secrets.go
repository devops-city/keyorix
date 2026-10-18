// dynamic_secrets.go — HTTP handlers for dynamic secrets (ADR-035): register a
// target config, issue short-lived leases, list/revoke them. Authorization is
// in-handler against each config/lease's project/environment scope, reusing the
// secrets.read / secrets.write permissions.
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
	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// isSafeDynamicSecretError reports whether msg is one of the small set of
// deliberately-crafted, safe messages core's dynamic-secret lease functions
// (IssueLease/RevokeLease/RenewLease/RevokeLeasesForConfig) produce without
// wrapping a lower-layer error. Everything else wraps (via %w) the actual
// backend operation's error — issuing/revoking a credential against the
// target database/cloud engine — which can carry connection detail (host,
// driver wording) that must not reach the client verbatim (backlog #116).
func isSafeDynamicSecretError(msg string) bool {
	for _, safe := range []string{
		"config not found",
		"lease not found",
		"lease is not active",
		"lease has expired; issue a new lease instead",
		"cannot issue from the",
		"active-lease limit reached",
		"mints self-expiring credentials that cannot be renewed",
		"unsupported backend",
	} {
		if strings.Contains(msg, safe) {
			return true
		}
	}
	return false
}

// dynamicSecretClientMessage is the message an API caller gets for a failed dynamic-secret
// operation, and logs op's failure server-side. The egress policy's refusal of a
// private-network target is a deliberate, safe message (what was refused, which setting
// allows it); the allowlisted core messages pass through; anything else is masked, because
// it can carry driver, storage or connection detail (backlog #116).
func dynamicSecretClientMessage(err error, op string) string {
	if refused, ok := errors.AsType[*core.DynamicSecretTargetRefusedError](err); ok {
		log.Printf("%s: %s", op, refused.Error()) // full text, including any resolved address
		return refused.ClientMessage()
	}
	msg := err.Error()
	if isSafeDynamicSecretError(msg) {
		return msg
	}
	log.Printf("%s: %s", op, dynamic.SanitizeErrorMessage(err))
	return clientSafe(err)
}

// DynamicSecretHandler handles dynamic-secrets HTTP requests.
type DynamicSecretHandler struct {
	coreService *core.KeyorixCore
}

// NewDynamicSecretHandler creates a new DynamicSecretHandler.
func NewDynamicSecretHandler(coreService *core.KeyorixCore) *DynamicSecretHandler {
	return &DynamicSecretHandler{coreService: coreService}
}

// authorize checks both RBAC and the per-project MFA policy (ADR-037). It returns
// the failure mode so the caller can send the right response: permission denied
// vs. MFA required.
func (h *DynamicSecretHandler) authorize(r *http.Request, perm string, scope core.Scope) (ok bool, mfaBlocked bool) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		return false, false
	}
	allowed, err := h.coreService.AuthorizePrincipal(r.Context(), userCtx.ActorKind(), userCtx.PrincipalID(), perm, scope)
	if err != nil || !allowed {
		return false, false
	}
	if middleware.ProjectMFABlocked(r, h.coreService, scope.ProjectID) {
		return false, true
	}
	return true, false
}

// denyAuthz writes the appropriate response for a failed authorize().
func (h *DynamicSecretHandler) denyAuthz(w http.ResponseWriter, mfaBlocked bool) {
	if mfaBlocked {
		middleware.WriteProjectMFARequired(w)
		return
	}
	sendError(w, "Forbidden", "Insufficient permissions", http.StatusForbidden, nil)
}

// CreateConfig handles POST /api/v1/dynamic-secrets/configs
func (h *DynamicSecretHandler) CreateConfig(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		Name              string `json:"name"`
		ProjectID         uint   `json:"project_id"`
		EnvironmentID     uint   `json:"environment_id"`
		BackendType       string `json:"backend_type"`
		AdminDSN          string `json:"admin_dsn"`
		CreationTemplate  string `json:"creation_template"`
		DefaultTTLSeconds int    `json:"default_ttl_seconds"`
		MaxTTLSeconds     int    `json:"max_ttl_seconds"`
		MaxActiveLeases   int    `json:"max_active_leases"`
		Classification    string `json:"classification"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "BadRequest", errInvalidRequestBody, http.StatusBadRequest, nil)
		return
	}
	scope := core.Scope{ProjectID: body.ProjectID, EnvironmentID: body.EnvironmentID}
	if ok, mfaBlocked := h.authorize(r, permSecretsWrite, scope); !ok {
		h.denyAuthz(w, mfaBlocked)
		return
	}
	cfg, err := h.coreService.CreateDynamicSecretConfig(r.Context(), &core.CreateDynamicSecretConfigRequest{
		Name:              body.Name,
		ProjectID:         body.ProjectID,
		EnvironmentID:     body.EnvironmentID,
		BackendType:       body.BackendType,
		AdminDSN:          body.AdminDSN,
		CreationTemplate:  body.CreationTemplate,
		DefaultTTLSeconds: body.DefaultTTLSeconds,
		MaxTTLSeconds:     body.MaxTTLSeconds,
		MaxActiveLeases:   body.MaxActiveLeases,
		Classification:    body.Classification,
		CreatedBy:         userCtx.Username,
		ActorID:           userCtx.PrincipalID(),
	})
	if err != nil {
		msg := dynamicSecretClientMessage(err, "Error creating dynamic-secret config")
		sendError(w, "Error", msg, http.StatusBadRequest, nil)
		return
	}
	// Never echo the admin DSN ciphertext back.
	sendSuccess(w, sanitizeConfig(cfg), "Dynamic-secret config created.")
}

// ListConfigs handles GET /api/v1/dynamic-secrets/configs?project_id=&environment_id=
func (h *DynamicSecretHandler) ListConfigs(w http.ResponseWriter, r *http.Request) {
	projectID, environmentID, ok := parseScopeQuery(w, r)
	if !ok {
		return
	}
	if ok, mfaBlocked := h.authorize(r, permSecretsRead, core.Scope{ProjectID: projectID, EnvironmentID: environmentID}); !ok {
		h.denyAuthz(w, mfaBlocked)
		return
	}
	cfgs, err := h.coreService.ListDynamicSecretConfigs(r.Context(), projectID, environmentID)
	if err != nil {
		log.Printf("Error listing dynamic-secret configs: %s", dynamic.SanitizeErrorMessage(err))
		sendError(w, "InternalError", "Failed to list configs", http.StatusInternalServerError, nil)
		return
	}
	out := make([]map[string]any, 0, len(cfgs))
	for _, c := range cfgs {
		out = append(out, sanitizeConfig(c))
	}
	sendSuccess(w, out, "")
}

// GetConfig handles GET /api/v1/dynamic-secrets/configs/{id}
func (h *DynamicSecretHandler) GetConfig(w http.ResponseWriter, r *http.Request) {
	cfg, ok := h.loadConfig(w, r)
	if !ok {
		return
	}
	sendSuccess(w, sanitizeConfig(cfg), "")
}

// IssueLease handles POST /api/v1/dynamic-secrets/configs/{id}/issue
func (h *DynamicSecretHandler) IssueLease(w http.ResponseWriter, r *http.Request) {
	userCtx, ok := mustGetUser(w, r)
	if !ok {
		return
	}
	cfg, ok := h.loadConfig(w, r)
	if !ok {
		return
	}
	var body struct {
		TTLSeconds int `json:"ttl_seconds"`
	}
	// Body is optional; ignore decode errors on an empty body.
	_ = json.NewDecoder(r.Body).Decode(&body)

	lease, err := h.coreService.IssueLease(r.Context(), cfg.ID, body.TTLSeconds, userCtx.UserID)
	if err != nil {
		msg := dynamicSecretClientMessage(err, fmt.Sprintf("Error issuing dynamic-secret lease for config %d", cfg.ID))
		sendError(w, "Error", msg, http.StatusBadGateway, nil)
		return
	}
	sendSuccess(w, lease, "Credential issued — it is shown once and will auto-revoke at expiry.")
}

// ListLeases handles GET /api/v1/dynamic-secrets/configs/{id}/leases
func (h *DynamicSecretHandler) ListLeases(w http.ResponseWriter, r *http.Request) {
	cfg, ok := h.loadConfig(w, r)
	if !ok {
		return
	}
	leases, err := h.coreService.ListDynamicSecretLeases(r.Context(), cfg.ID)
	if err != nil {
		log.Printf("Error listing leases: %s", dynamic.SanitizeErrorMessage(err))
		sendError(w, "InternalError", "Failed to list leases", http.StatusInternalServerError, nil)
		return
	}
	out := make([]map[string]any, 0, len(leases))
	for _, l := range leases {
		out = append(out, sanitizeLease(l))
	}
	sendSuccess(w, out, "")
}

// RevokeLease handles POST /api/v1/dynamic-secrets/leases/{leaseID}/revoke
func (h *DynamicSecretHandler) RevokeLease(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	leaseID := chi.URLParam(r, "leaseID")
	if _, ok := h.loadLease(w, r, leaseID); !ok {
		return
	}
	if err := h.coreService.RevokeLease(r.Context(), leaseID, userCtx.UserID, "manual"); err != nil {
		msg := dynamicSecretClientMessage(err, fmt.Sprintf("Error revoking dynamic-secret lease %q", leaseID))
		sendError(w, "Error", msg, http.StatusBadGateway, nil)
		return
	}
	sendSuccess(w, map[string]any{"lease_id": leaseID, "status": "revoked"}, "Lease revoked.")
}

// RenewLease handles POST /api/v1/dynamic-secrets/leases/{leaseID}/renew
func (h *DynamicSecretHandler) RenewLease(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	leaseID := chi.URLParam(r, "leaseID")
	if _, ok := h.loadLease(w, r, leaseID); !ok {
		return
	}
	var body struct {
		TTLSeconds int `json:"ttl_seconds"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body) // body optional; default TTL on absence
	newExpiry, err := h.coreService.RenewLease(r.Context(), leaseID, body.TTLSeconds, userCtx.UserID)
	if err != nil {
		msg := dynamicSecretClientMessage(err, fmt.Sprintf("Error renewing dynamic-secret lease %q", leaseID))
		sendError(w, "Error", msg, http.StatusBadGateway, nil)
		return
	}
	sendSuccess(w, map[string]any{"lease_id": leaseID, "expires_at": newExpiry}, "Lease renewed.")
}

// RevokeAllLeases handles POST /api/v1/dynamic-secrets/configs/{id}/revoke-all —
// the incident kill switch: revoke every active lease from a config at once.
func (h *DynamicSecretHandler) RevokeAllLeases(w http.ResponseWriter, r *http.Request) {
	userCtx, ok := mustGetUser(w, r)
	if !ok {
		return
	}
	cfg, ok := h.loadConfig(w, r)
	if !ok {
		return
	}
	revoked, failed, err := h.coreService.RevokeLeasesForConfig(r.Context(), cfg.ID, userCtx.UserID, "bulk")
	if err != nil {
		msg := dynamicSecretClientMessage(err, fmt.Sprintf("Error revoking all dynamic-secret leases for config %d", cfg.ID))
		sendError(w, "Error", msg, http.StatusBadGateway, nil)
		return
	}
	sendSuccess(w, map[string]any{
		"config_id": cfg.ID, "revoked": revoked, "failed": failed,
	}, fmt.Sprintf("Revoked %d active lease(s); %d failed.", revoked, failed))
}

// ClassifyConfig handles PATCH /api/v1/dynamic-secrets/configs/{id}/classification —
// sets (or clears) the config's data-classification label.
func (h *DynamicSecretHandler) ClassifyConfig(w http.ResponseWriter, r *http.Request) {
	userCtx, ok := mustGetUser(w, r)
	if !ok {
		return
	}
	cfg, ok := h.loadConfig(w, r)
	if !ok {
		return
	}
	var body struct {
		Classification string `json:"classification"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "BadRequest", errInvalidRequestBody, http.StatusBadRequest, nil)
		return
	}
	updated, err := h.coreService.ClassifyDynamicSecretConfig(r.Context(), userCtx.UserID, cfg.ID, body.Classification)
	if err != nil {
		msg := dynamicSecretClientMessage(err, fmt.Sprintf("Error classifying dynamic-secret config %d", cfg.ID))
		sendError(w, "Error", msg, http.StatusBadRequest, nil)
		return
	}
	sendSuccess(w, sanitizeConfig(updated), "Classification updated.")
}

// SetConfigEnabled handles PATCH /api/v1/dynamic-secrets/configs/{id}/enabled —
// manually enables or disables a config (#369). DeleteProject's cascade disables
// a project's configs automatically; this is how an admin re-enables one
// afterward (project restore deliberately does not do so on its own), or
// disables one directly outside of a project delete.
func (h *DynamicSecretHandler) SetConfigEnabled(w http.ResponseWriter, r *http.Request) {
	userCtx, ok := mustGetUser(w, r)
	if !ok {
		return
	}
	cfg, ok := h.loadConfig(w, r)
	if !ok {
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "BadRequest", errInvalidRequestBody, http.StatusBadRequest, nil)
		return
	}
	updated, err := h.coreService.SetDynamicSecretConfigEnabled(r.Context(), userCtx.UserID, cfg.ID, body.Enabled)
	if err != nil {
		msg := dynamicSecretClientMessage(err, fmt.Sprintf("Error setting enabled state for dynamic-secret config %d", cfg.ID))
		sendError(w, "Error", msg, http.StatusBadRequest, nil)
		return
	}
	sendSuccess(w, sanitizeConfig(updated), "Config enabled state updated.")
}

// loadConfig fetches the {id} config. #1645/ADR-096: authorization against
// the config's project/environment scope now runs as route-level
// RequireScopedPermission middleware (router.go, ScopeFromDynamicSecretConfigParam)
// before this handler is ever reached — a caller who lacks the permission or
// whose target doesn't exist gets the shared 403-for-both collapse
// (handleScopeResolutionError) there, not a second, independently-derived
// collapse here. This function only re-fetches the already-authorized row;
// a "not found" here means a benign TOCTOU race (deleted between the
// middleware's check and this handler running), not an oracle — the caller
// already passed authorization for this exact ID.
func (h *DynamicSecretHandler) loadConfig(w http.ResponseWriter, r *http.Request) (*models.DynamicSecretConfig, bool) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid config id", http.StatusBadRequest, nil)
		return nil, false
	}
	cfg, err := h.coreService.GetDynamicSecretConfig(r.Context(), uint(id))
	if err != nil {
		sendError(w, "NotFound", "Config not found", http.StatusNotFound, nil)
		return nil, false
	}
	return cfg, true
}

// loadLease fetches the leaseID lease, mirroring loadConfig's #1645/ADR-096
// treatment above (authorization already ran via RequireScopedPermission +
// ScopeFromDynamicSecretLeaseParam before this handler runs). Shared by
// RevokeLease/RenewLease so the fetch isn't duplicated.
func (h *DynamicSecretHandler) loadLease(w http.ResponseWriter, r *http.Request, leaseID string) (*models.DynamicSecretLease, bool) {
	lease, err := h.coreService.GetDynamicSecretLease(r.Context(), leaseID)
	if err != nil {
		sendError(w, "NotFound", "Lease not found", http.StatusNotFound, nil)
		return nil, false
	}
	return lease, true
}

// sanitizeConfig returns the safe public view of a config — never the encrypted
// admin DSN bytes.
func sanitizeConfig(c *models.DynamicSecretConfig) map[string]any {
	return map[string]any{
		"id":                  c.ID,
		"name":                c.Name,
		"project_id":          c.ProjectID,
		"environment_id":      c.EnvironmentID,
		"backend_type":        c.BackendType,
		"creation_template":   c.CreationTemplate,
		"default_ttl_seconds": c.DefaultTTLSeconds,
		"max_ttl_seconds":     c.MaxTTLSeconds,
		"max_active_leases":   c.MaxActiveLeases,
		"classification":      c.Classification,
		"disabled":            c.Disabled,
		"created_by":          c.CreatedBy,
		"created_at":          c.CreatedAt,
	}
}

// sanitizeLease returns the safe public view of a lease — never the encrypted
// credential bytes.
func sanitizeLease(l *models.DynamicSecretLease) map[string]any {
	return map[string]any{
		"lease_id":      l.LeaseID,
		"config_id":     l.ConfigID,
		"role_name":     l.RoleName,
		"status":        l.Status,
		"revoke_reason": l.RevokeReason,
		"revoke_error":  l.RevokeError,
		"issued_at":     l.IssuedAt,
		"expires_at":    l.ExpiresAt,
		"revoked_at":    l.RevokedAt,
	}
}

func parseScopeQuery(w http.ResponseWriter, r *http.Request) (projectID, environmentID uint, ok bool) {
	if v := r.URL.Query().Get("project_id"); v != "" {
		id, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			sendError(w, "InvalidParameter", "Invalid project_id", http.StatusBadRequest, nil)
			return 0, 0, false
		}
		projectID = uint(id)
	}
	if v := r.URL.Query().Get("environment_id"); v != "" {
		id, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			sendError(w, "InvalidParameter", "Invalid environment_id", http.StatusBadRequest, nil)
			return 0, 0, false
		}
		environmentID = uint(id)
	}
	return projectID, environmentID, true
}
