// sso.go — human SSO login endpoints (OIDC authorization-code flow). All three are
// unauthenticated (mounted outside the session middleware): the login redirect, the
// IdP callback, and the provider list the login page reads. On success the callback
// hands the SPA its session by redirecting to the web completion page with the token
// in the URL fragment (kept out of server logs / the Referer header).
package handlers

import (
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/keyorixhq/keyorix/internal/core"
)

// oauthErrorAllowlist is the fixed set of error codes defined by RFC 6749 §4.1.2.1 and
// RFC 6749 §5.2, plus common OIDC extensions. Any error code NOT in this list is
// replaced with a generic message to prevent injection via a crafted callback URL.
var oauthErrorAllowlist = map[string]bool{
	"access_denied":              true,
	"invalid_request":            true,
	"unauthorized_client":        true,
	"unsupported_response_type":  true,
	"invalid_scope":              true,
	"server_error":               true,
	"temporarily_unavailable":    true,
	"interaction_required":       true,
	"login_required":             true,
	"account_selection_required": true,
	"consent_required":           true,
}

// sanitiseSSOError returns the IdP-supplied error code if it is a known OAuth 2.0 / OIDC
// code, or a generic "SSO login failed" string otherwise, preventing untrusted input from
// being reflected into the SPA fragment.
func sanitiseSSOError(code string) string {
	if oauthErrorAllowlist[code] {
		return code
	}
	return "SSO login failed"
}

// isSafeSSOError reports whether msg is one of the small set of deliberately-
// crafted, safe messages core.CompleteSSO itself produces without wrapping a
// lower-layer error. Everything else — an authorization-code exchange failure,
// an id_token verification failure, or a storage-layer lookup error — wraps a
// raw error via %w and can carry internal detail (a library's wording, an
// upstream IdP response fragment, DB/ORM text). Reflecting that verbatim into
// the redirect fragment the browser receives would leak it to the client
// (backlog #116), so anything not on this allowlist is sanitized.
func isSafeSSOError(msg string) bool {
	for _, safe := range []string{
		errUnknownSSOProvider,
		"unknown SAML provider",
		"invalid or expired login state",
		"login state does not match the callback provider",
		"login state expired",
		"the token response carried no id_token",
		"the assertion carried no subject or email",
		"no Keyorix account matches this SSO identity",
		"the IdP returned no email; cannot auto-provision an account",
		errDomainNotAllowed,
		// #2903: a login refused because the IdP's group/role assertion could
		// not be fully applied. Safe because core returns these as the WHOLE
		// Error() of its refusal (ssoLoginRefusedError), with the storage cause
		// kept only in the Unwrap chain -- a substring match on a message that
		// had the cause appended would reflect that cause too.
		core.SSOMsgGroupReconcileRefused,
		core.SSOMsgRoleReconcileRefused,
		core.SSOMsgLastAdminRemovalRefused,
	} {
		if strings.Contains(msg, safe) {
			return true
		}
	}
	return false
}

// ListSSOProviders handles GET /auth/sso/providers — the enabled provider names, so
// the login page can render the right "Sign in with …" buttons.
func (h *AuthHandler) ListSSOProviders(w http.ResponseWriter, _ *http.Request) {
	sendSuccess(w, map[string]interface{}{"providers": h.coreService.SSOProviderNames()}, "")
}

// BeginSSO handles GET /auth/sso/{provider}/login — redirects the browser to the IdP
// authorization endpoint with a fresh state + nonce.
func (h *AuthHandler) BeginSSO(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if h.coreService.IsSSOBeginRateLimited(r.Context(), ip) {
		sendError(w, "TooManyRequests", "Too many login attempts. Try again later.", http.StatusTooManyRequests, nil)
		return
	}
	h.coreService.RecordSSOBeginAttempt(r.Context(), ip)

	provider := chi.URLParam(r, "provider")
	authURL, err := h.coreService.BeginSSO(r.Context(), provider, r.URL.Query().Get("return_to"))
	if err != nil {
		msg := err.Error()
		if !strings.Contains(msg, errUnknownSSOProvider) {
			log.Printf("Error beginning SSO login via provider %q: %v", provider, err)
			msg = clientSafe(err)
		}
		sendError(w, "SSOError", msg, http.StatusBadRequest, nil)
		return
	}
	// authURL is built by core from the provider's operator-configured, discovery-
	// resolved OIDC authorization endpoint (plus our state/nonce) — never user input.
	http.Redirect(w, r, authURL, http.StatusFound) // #nosec G710 -- operator-configured IdP endpoint, not user-controlled
}

// CompleteSSO handles GET /auth/sso/{provider}/callback — exchanges the code, mints a
// session, and redirects to the SPA completion page with the token in the fragment.
func (h *AuthHandler) CompleteSSO(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	completeURL, ok := h.coreService.SSOCompleteURL(provider)
	if !ok {
		sendError(w, "SSOError", errUnknownSSOProvider, http.StatusBadRequest, nil)
		return
	}

	q := r.URL.Query()
	if errParam := q.Get("error"); errParam != "" {
		// Validate against the OAuth 2.0 error code allowlist before reflecting
		// into the fragment — the raw IdP parameter is untrusted input.
		h.redirectFragment(w, r, completeURL, url.Values{"error": {sanitiseSSOError(errParam)}})
		return
	}
	code, state := q.Get("code"), q.Get("state")
	if code == "" || state == "" {
		h.redirectFragment(w, r, completeURL, url.Values{"error": {"missing code or state"}})
		return
	}

	session, _, returnTo, err := h.coreService.CompleteSSO(r.Context(), provider, code, state, r.Header.Get("User-Agent"), clientIP(r))
	if err != nil {
		msg := err.Error()
		if !isSafeSSOError(msg) {
			log.Printf("Error completing SSO login via provider %q: %v", provider, err)
			msg = clientSafe(err)
		}
		h.redirectFragment(w, r, completeURL, url.Values{"error": {msg}})
		return
	}

	// Cookies survive a redirect fine — the browser stores them from this 302
	// response before following Location. The session is delivered exclusively
	// via the HttpOnly/Secure cookie; the token is NOT included in the fragment
	// (#r125-H3: a fragment token is exposed to JS, browser history, and
	// extensions — the cookie is the correct and sufficient delivery mechanism).
	h.setSessionCookies(w, r, session)

	frag := url.Values{}
	if session.ExpiresAt != nil {
		frag.Set("expires_at", session.ExpiresAt.Format(time.RFC3339))
	}
	if session.AbsoluteExpiresAt != nil {
		frag.Set("absolute_expires_at", session.AbsoluteExpiresAt.Format(time.RFC3339))
	}
	if returnTo != "" {
		frag.Set("return_to", returnTo)
	}
	h.redirectFragment(w, r, completeURL, frag)
}

// redirectFragment 302-redirects to base#<encoded values>, delivering the token (or
// an error) to the SPA without it touching query logs. base is the provider's
// operator-configured completion URL (SSOCompleteURL); the fragment carries data.
func (h *AuthHandler) redirectFragment(w http.ResponseWriter, r *http.Request, base string, values url.Values) {
	// base is operator-configured (the SSO completion URL derived from redirect_url),
	// not user input; the fragment is data the SPA reads.
	http.Redirect(w, r, base+"#"+values.Encode(), http.StatusFound) // #nosec G710 -- operator-configured completion URL, not user-controlled
}
