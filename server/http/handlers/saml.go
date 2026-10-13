// saml.go — human SSO login endpoints for the SAML 2.0 binding (ADR-063). Like the OIDC
// endpoints they are unauthenticated (mounted outside the session middleware): the SP
// metadata, the login redirect (AuthnRequest), and the Assertion Consumer Service (ACS)
// that consumes the IdP's signed response. On success the ACS hands the SPA its session
// the same way the OIDC callback does — token in the URL fragment.
package handlers

import (
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/go-chi/chi/v5"
)

// SAMLMetadata handles GET /auth/saml/{provider}/metadata — the SP metadata XML the IdP
// administrator imports to register Keyorix.
func (h *AuthHandler) SAMLMetadata(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	md, err := h.coreService.SAMLMetadata(provider)
	if err != nil {
		msg := err.Error()
		if !isSafeSSOError(msg) {
			log.Printf("Error generating SAML metadata for provider %q: %v", provider, err)
			msg = clientSafe(err)
		}
		sendError(w, "SSOError", msg, http.StatusNotFound, nil)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	// md is server-generated SP metadata XML (from operator config, no request input)
	// served as non-HTML — not an XSS vector.
	_, _ = w.Write(md) // #nosec G705 -- server-generated SAML metadata, non-HTML content type
}

// BeginSAML handles GET /auth/saml/{provider}/login — redirects the browser to the IdP
// SSO endpoint with a fresh AuthnRequest.
func (h *AuthHandler) BeginSAML(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if h.coreService.IsSSOBeginRateLimited(r.Context(), ip) {
		sendError(w, "TooManyRequests", "Too many login attempts. Try again later.", http.StatusTooManyRequests, nil)
		return
	}
	h.coreService.RecordSSOBeginAttempt(r.Context(), ip)

	provider := chi.URLParam(r, "provider")
	redirectURL, err := h.coreService.BeginSAML(r.Context(), provider, r.URL.Query().Get("return_to"))
	if err != nil {
		msg := err.Error()
		if !isSafeSSOError(msg) {
			log.Printf("Error beginning SAML login via provider %q: %v", provider, err)
			msg = clientSafe(err)
		}
		sendError(w, "SSOError", msg, http.StatusBadRequest, nil)
		return
	}
	// redirectURL is built by core from the provider's operator-configured IdP SSO
	// endpoint (from the IdP metadata) plus our AuthnRequest — never user input.
	http.Redirect(w, r, redirectURL, http.StatusFound) // #nosec G710 -- operator-configured IdP endpoint, not user-controlled
}

// CompleteSAML handles POST /auth/saml/{provider}/acs — the Assertion Consumer Service.
// It validates the SAMLResponse (via core/the vetted library), mints a session, and
// redirects to the SPA completion page with the token in the fragment.
func (h *AuthHandler) CompleteSAML(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	completeURL, ok := h.coreService.SSOCompleteURL(provider)
	if !ok {
		sendError(w, "SSOError", "unknown SSO provider", http.StatusBadRequest, nil)
		return
	}
	if err := r.ParseForm(); err != nil {
		h.redirectFragment(w, r, completeURL, url.Values{"error": {"invalid ACS request"}})
		return
	}
	relayState := r.PostFormValue("RelayState")

	session, _, returnTo, err := h.coreService.CompleteSAML(
		r.Context(), provider, r, relayState, r.Header.Get("User-Agent"), clientIP(r))
	if err != nil {
		msg := err.Error()
		if !isSafeSSOError(msg) {
			log.Printf("Error completing SAML login via provider %q: %v", provider, err)
			msg = clientSafe(err)
		}
		h.redirectFragment(w, r, completeURL, url.Values{"error": {msg}})
		return
	}

	// Cookies survive a redirect fine — see the equivalent comment in sso.go's
	// CompleteSSO. Token is NOT included in the fragment — cookie-only delivery
	// (#r125-H3, mirrors sso.go's CompleteSSO).
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
