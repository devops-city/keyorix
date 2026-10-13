// admin_impersonation.go — admin impersonation start/end endpoints.
//
// Start (POST /api/v1/admin/impersonate) is gated by the users.impersonate
// permission, which only global admins hold (admin-bypass). It issues a separate
// short-lived session for the target user and sets its cookie; the admin's own
// session token is stashed in a second cookie (see AdminSessionCookieName) so
// the client can swap back without re-authentication.
//
// End (POST /api/v1/auth/end-impersonation) is self-scoped: it terminates the
// impersonation session, then restores the admin's stashed session if it's
// still live, or clears everything and routes to a fresh login if it's not.
// See internal/core/impersonation.go for the core-layer session lifecycle.
package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// ImpersonationHandler handles admin impersonation requests.
type ImpersonationHandler struct {
	coreService *core.KeyorixCore
	// tlsEnabled is the configured half of the Secure decision, always passed
	// through middleware.RequestIsHTTPS — see AuthHandler's field of the same name.
	tlsEnabled bool
}

// NewImpersonationHandler constructs an ImpersonationHandler.
func NewImpersonationHandler(coreService *core.KeyorixCore, tlsEnabled bool) *ImpersonationHandler {
	return &ImpersonationHandler{coreService: coreService, tlsEnabled: tlsEnabled}
}

type startImpersonationBody struct {
	UserID uint `json:"user_id"`
}

// impersonationResponse no longer carries Token — the impersonation session's
// cookie is set directly on the response (see Start); the client never holds
// the token value at all now, matching the same shape change Login/RefreshToken
// went through.
type impersonationResponse struct {
	ExpiresAt      string `json:"expires_at,omitempty"`
	UserID         uint   `json:"user_id"`
	Username       string `json:"username"`
	DisplayName    string `json:"display_name"`
	ImpersonatedBy uint   `json:"impersonated_by"`
}

// Start handles POST /api/v1/admin/impersonate.
func (h *ImpersonationHandler) Start(w http.ResponseWriter, r *http.Request) {
	admin := middleware.GetUserFromContext(r.Context())
	if admin == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	// An impersonation session must not itself be used to start another one.
	if admin.ImpersonatedBy != nil {
		sendError(w, "Forbidden", "Cannot impersonate while impersonating", http.StatusForbidden, nil)
		return
	}

	var body startImpersonationBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "BadRequest", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	if body.UserID == 0 {
		sendError(w, "BadRequest", "user_id is required", http.StatusBadRequest, nil)
		return
	}

	// Capture the admin's own current token BEFORE it's superseded by the
	// impersonation session's cookie below — this is the plaintext value the
	// browser just sent us on this very request. Stashing it in a second cookie
	// is how End restores it later without the server ever needing to recall a
	// plaintext token from storage (see AdminSessionCookieName's doc comment).
	adminToken := extractBearerToken(r)

	session, target, err := h.coreService.StartImpersonation(r.Context(), admin.UserID, body.UserID, clientIP(r))
	if err != nil {
		switch {
		case strings.Contains(err.Error(), "yourself"):
			sendError(w, "BadRequest", "Cannot impersonate yourself", http.StatusBadRequest, nil)
		case strings.Contains(err.Error(), "not found"):
			sendError(w, "NotFound", "Target user not found", http.StatusNotFound, nil)
		default:
			sendError(w, "InternalError", "Failed to start impersonation", http.StatusInternalServerError, nil)
		}
		return
	}

	secure := middleware.RequestIsHTTPS(r, h.tlsEnabled)
	middleware.SetSessionCookie(w, session.SessionToken, session.ExpiresAt, secure)
	if adminToken != "" {
		middleware.SetAdminSessionCookie(w, adminToken, session.ExpiresAt, secure)
	}
	if csrfToken, cerr := middleware.GenerateCSRFToken(); cerr == nil {
		middleware.SetCSRFCookie(w, csrfToken, secure)
	}

	resp := impersonationResponse{
		UserID:         target.ID,
		Username:       target.Username,
		DisplayName:    target.DisplayName,
		ImpersonatedBy: admin.UserID,
	}
	if session.ExpiresAt != nil {
		resp.ExpiresAt = session.ExpiresAt.UTC().Format(time.RFC3339)
	}
	sendSuccess(w, resp, "Impersonation started")
}

// End handles POST /api/v1/auth/end-impersonation. On success it restores the
// admin's stashed session cookie when it's still live, or clears everything
// (routing to a fresh login) when it's not — e.g. the admin's own session
// expired, or was revoked, while they were impersonating.
func (h *ImpersonationHandler) End(w http.ResponseWriter, r *http.Request) {
	token := extractBearerToken(r)
	if token == "" {
		sendError(w, "BadRequest", "Missing authorization token", http.StatusBadRequest, nil)
		return
	}
	adminID, err := h.coreService.EndImpersonation(r.Context(), token)
	if err != nil {
		if strings.Contains(err.Error(), "not an impersonation") {
			sendError(w, "BadRequest", "Not an impersonation session", http.StatusBadRequest, nil)
		} else {
			sendError(w, "InternalError", "Failed to end impersonation", http.StatusInternalServerError, nil)
		}
		return
	}
	// Evict the impersonation token from the auth cache immediately.
	middleware.InvalidateTokenCache(token)

	// Ending impersonation always succeeds once we get here (the impersonation
	// session is deleted either way) — admin_session_restored tells the client
	// which of the two outcomes happened, since only one of them leaves the
	// browser still logged in.
	restored := false
	secure := middleware.RequestIsHTTPS(r, h.tlsEnabled)
	if adminCookie, cerr := r.Cookie(middleware.AdminSessionCookieName); cerr == nil && adminCookie.Value != "" {
		// Validate before trusting it back as the active session — it may have
		// expired, or the admin's account may have been suspended, while they
		// were impersonating. This is the same check every other request goes
		// through, not a new trust boundary.
		//
		// Beyond validity, the resolved session must belong to the SAME admin
		// who was just impersonating (adminID, from the ended session's own
		// ImpersonatedBy — resolved server-side, not client-supplied). Without
		// this binding, ANY currently-valid session token sitting in the
		// AdminSessionCookieName cookie — a stale cookie left over from a
		// PREVIOUS, different admin's impersonation on a shared browser
		// profile, or one substituted by a client capable of setting an
		// arbitrary Cookie header for this origin — would be silently promoted
		// to the caller's active session. The cookie is HttpOnly, so this isn't
		// exploitable from in-browser JS, but nothing else here enforces that
		// the restored session actually belongs to the admin who started this
		// impersonation.
		if adminUser, _, verr := h.coreService.ValidateSessionToken(r.Context(), adminCookie.Value); verr == nil && adminUser != nil && adminUser.ID == adminID {
			// #1974: carry the restored session's real expiry (earliest of its
			// idle and absolute ceilings), like every other SetSessionCookie call
			// site — nil would make this a browser-session cookie that outlives
			// the server-side session it points at.
			middleware.SetSessionCookie(w, adminCookie.Value, h.coreService.SessionEffectiveExpiry(r.Context(), adminCookie.Value), secure)
			if csrfToken, cerr2 := middleware.GenerateCSRFToken(); cerr2 == nil {
				middleware.SetCSRFCookie(w, csrfToken, secure)
			}
			restored = true
		}
	}
	middleware.ClearAdminSessionCookie(w, secure)

	message := "Impersonation ended"
	if !restored {
		middleware.ClearSessionCookie(w, secure)
		middleware.ClearCSRFCookie(w, secure)
		message = "Impersonation ended, but your admin session had expired — please sign in again"
	}
	sendSuccess(w, map[string]interface{}{"admin_session_restored": restored}, message)
}

// clientIP returns r.RemoteAddr's IP in canonical form, for audit attribution
// and as the rate-limit key several handlers in this package share.
//
// #G20: the naive strings.LastIndex(":")-based port strip this replaced didn't
// account for IPv6 at all — a bracketed "[::1]:8080" kept its brackets, and an
// address with NO port (e.g. one already stripped elsewhere) had its LAST
// colon truncated as if it were a port separator, corrupting the address
// (e.g. "2001:db8::1" → "2001:db8:"). core.CanonicalIP handles both correctly.
func clientIP(r *http.Request) string {
	return core.CanonicalIP(r.RemoteAddr)
}
