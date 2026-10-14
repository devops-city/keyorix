// connect.go — HTTP handlers for Keyorix Connect (ADR-043): list configured
// external-store connectors and proxy an authorized, audited read-through of a
// secret. Both are gated by connect.read in the router (ADR-044); values are never
// persisted.
package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// isSafeConnectError reports whether err is one of the small set of
// deliberately-crafted, safe sentinel errors core.ReadFederatedSecret /
// CreateConnectRefGrant / DeleteConnectRefGrant themselves produce (an
// unknown/disabled connector, a missing role, a platform-scoped connector
// rejected at grant creation (#1479), or a per-reference policy denial). This
// checks err's type via errors.Is against the core package's sentinels rather
// than substring-matching err.Error(): connectorName and ref are
// caller-controlled and, if an upstream connector (e.g. Vault) happened to
// echo either back in its own raw error text, a substring match against the
// message could be spoofed into passing as "safe" and leaking that raw text
// to the client (backlog #116). Anything that doesn't match one of these
// sentinels is assumed to originate from a lower layer — the storage layer or
// an upstream connector — whose raw error text must be sanitized before it
// reaches the client.
func isSafeConnectError(err error) bool {
	return errors.Is(err, core.ErrConnectDisabled) ||
		errors.Is(err, core.ErrConnectUnknownConnector) ||
		errors.Is(err, core.ErrConnectRoleRequired) ||
		errors.Is(err, core.ErrConnectRefGrantAgainstPlatformConnector) ||
		errors.Is(err, core.ErrConnectRefNotPermitted)
}

// ConnectHandler serves the /connect federation endpoints.
type ConnectHandler struct {
	coreService *core.KeyorixCore
}

// NewConnectHandler creates a connect handler.
func NewConnectHandler(coreService *core.KeyorixCore) *ConnectHandler {
	return &ConnectHandler{coreService: coreService}
}

// ListConnectors returns the connector names the caller can reach (ADR-082 §E) —
// discovery is filtered by ownership so a caller never sees a connector name they
// cannot subsequently read.
func (h *ConnectHandler) ListConnectors(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	names, err := h.coreService.ConnectReadableConnectorNames(r.Context(), userCtx.ActorKind(), userCtx.PrincipalID())
	if err != nil {
		log.Printf("Error listing readable connectors: %v", err)
		sendError(w, "ConnectError", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]any{"connectors": names}, "")
}

// ReadSecret proxies a read-through of the named connector. ref is taken from the
// JSON request body, not a query-string parameter: a ref names the secret's exact
// path/identifier inside the external store (e.g. a Vault mount path or AWS secret
// name), and a GET query string is routinely captured in infrastructure access logs
// (reverse proxies, TLS-terminating middleboxes, CDN/load-balancer log pipelines) in
// a way a POST body normally is not — someone with read access to those logs but no
// connect.read grant inside Keyorix could otherwise passively harvest every ref
// operators query.
func (h *ConnectHandler) ReadSecret(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	name := chi.URLParam(r, "name")
	var body struct {
		Ref string `json:"ref"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		sendError(w, "InvalidBody", "invalid JSON request body", http.StatusBadRequest, nil)
		return
	}
	ref := body.Ref
	if ref == "" {
		sendError(w, "InvalidParameter", "ref is required in the request body", http.StatusBadRequest, nil)
		return
	}
	value, err := h.coreService.ReadFederatedSecret(r.Context(), userCtx.ActorKind(), userCtx.PrincipalID(), name, ref)
	if err != nil {
		// Unknown connector / disabled is a client error; backend failures surface as
		// a bad gateway since the upstream store is external. Either way, the raw error
		// text may embed the upstream connector's hostname or connection detail (e.g. a
		// Vault error) — log it server-side and return a generic message to the client
		// unless it's one of the deliberately-crafted, safe messages core.ReadFederatedSecret
		// itself produces (backlog #116).
		msg := err.Error()
		if !isSafeConnectError(err) {
			log.Printf("Error reading federated secret via connector %q: %v", name, err)
			msg = clientSafe(err)
		}
		sendError(w, "ConnectError", msg, http.StatusBadGateway, nil)
		return
	}
	sendSuccess(w, map[string]any{
		"connector": name,
		"ref":       ref,
		"value":     value,
	}, "")
}

// ListRefGrants returns all per-reference grants (ADR-045) for management.
func (h *ConnectHandler) ListRefGrants(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	grants, err := h.coreService.ListConnectRefGrants(r.Context())
	if err != nil {
		log.Printf("Error listing connect ref-grants: %v", err)
		sendError(w, "ConnectError", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	out := make([]map[string]any, 0, len(grants))
	for _, g := range grants {
		out = append(out, map[string]any{
			"id":         g.ID,
			"role_id":    g.RoleID,
			"connector":  g.Connector,
			"ref_prefix": g.RefPrefix,
			"expires_at": g.ExpiresAt,
			"created_at": g.CreatedAt,
		})
	}
	sendSuccess(w, map[string]any{"grants": out}, "")
}

// CreateRefGrant adds a per-reference grant (ADR-045). ExpiresAt is optional: omitted
// or null makes the grant permanent (backward compatible); otherwise the grant stops
// authorizing the moment it passes, mirroring how secret shares support a time-bound,
// JIT expiry.
func (h *ConnectHandler) CreateRefGrant(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		RoleID    uint       `json:"role_id"`
		Connector string     `json:"connector"`
		RefPrefix string     `json:"ref_prefix"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidParameter", "invalid JSON body", http.StatusBadRequest, nil)
		return
	}
	g, err := h.coreService.CreateConnectRefGrant(r.Context(), userCtx.UserID, body.RoleID, body.Connector, body.RefPrefix, body.ExpiresAt)
	if err != nil {
		msg := err.Error()
		status := http.StatusBadRequest
		if !isSafeConnectError(err) {
			log.Printf("Error creating connect ref-grant: %v", err)
			msg = clientSafe(err)
			status = http.StatusInternalServerError
		}
		sendError(w, "ConnectError", msg, status, nil)
		return
	}
	sendSuccess(w, map[string]any{
		"id":         g.ID,
		"role_id":    g.RoleID,
		"connector":  g.Connector,
		"ref_prefix": g.RefPrefix,
		"expires_at": g.ExpiresAt,
	}, "Connect ref-grant created")
}

// DeleteRefGrant removes a per-reference grant by id.
func (h *ConnectHandler) DeleteRefGrant(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "invalid grant id", http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.DeleteConnectRefGrant(r.Context(), userCtx.UserID, uint(id)); err != nil {
		log.Printf("Error deleting connect ref-grant %d: %v", id, err)
		sendError(w, "ConnectError", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]any{"id": id}, "Connect ref-grant deleted")
}
