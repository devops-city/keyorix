package middleware

import "net/http"

// contentSecurityPolicy mirrors the policy the Helm chart's nginx frontend already sends
// (deploy/helm/keyorix/templates/web-config.yaml) — the two serving modes (embedded
// single-binary SPA vs. the separate nginx+API-proxy deployment) should present the same
// policy to the browser. style-src allows 'unsafe-inline' for the SPA's runtime style
// injection (a common CSS-in-JS/Tailwind requirement); script-src does not, so an
// attacker-injected inline <script> — the primary XSS vector — is blocked regardless of
// where the malicious markup came from.
//
// connect-src uses 'self' only — this already covers same-origin WebSocket connections
// (ws:/wss: to the same host) in all modern browsers. The bare ws: and wss: scheme
// values that were here previously allowed WebSocket connections to ANY host, which
// is a CSP bypass for data exfiltration via WebSocket.
//
// form-action, base-uri, frame-ancestors do NOT inherit from default-src; they must be
// explicit. object-src 'none' blocks Flash/Java plugins. img-src omits the https: scheme
// wildcard (#1212) — all images are same-origin or inline data URIs.
const contentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'self'; frame-ancestors 'none'; object-src 'none';"

// SecurityHeaders sets standard hardening response headers on every response. For a
// secrets manager these matter beyond the usual:
//   - X-Content-Type-Options: nosniff — never let a browser MIME-sniff a response into
//     something executable.
//   - X-Frame-Options: DENY — the dashboard must never be framed (clickjacking).
//   - Referrer-Policy: no-referrer — never leak the request URL via the Referer header;
//     Keyorix URLs can carry tokens (e.g. the SSO completion fragment), so stripping the
//     referrer closes a token-leak channel to third-party pages.
//   - Content-Security-Policy — #112: the single-binary/air-gap serving mode (the
//     embedded SPA, server/webui) previously sent NO CSP at all (only the separate Helm
//     nginx frontend did), so the strongest practical mitigation against an XSS reading
//     the SSO/SAML session-token URL fragment or localStorage was entirely absent in
//     that mode. Now sent unconditionally, matching the nginx config's policy.
//   - Cross-Origin-Resource-Policy: same-origin — opt-in Spectre mitigation; prevents
//     cross-origin reads of responses via speculative execution side channels.
//   - Cross-Origin-Embedder-Policy: require-corp — all subresources must carry CORP or
//     CORS; together with COOP this enables cross-origin isolation in the browser.
//   - Cross-Origin-Opener-Policy: same-origin — isolates the browsing context group so
//     cross-origin documents cannot share the same context (closes window.opener leaks).
//   - X-Permitted-Cross-Domain-Policies: none — no Adobe cross-domain policy file is
//     honored (a legacy Flash/PDF data-exfiltration channel); also a header web security
//     scanners expect to see set.
//
// Strict-Transport-Security is sent only for a request that reached the client over
// TLS: either this process terminates TLS (tlsEnabled, or r.TLS set), or ClientIP
// marked the request as coming from a configured trusted proxy that says
// X-Forwarded-Proto: https (ForwardedHTTPSFromTrustedProxy). It is never sent for
// plain http, and never on the word of an untrusted peer forging the header. The
// value is HSTSValue(hstsPreload): one year, includeSubDomains, and preload only
// when the operator opts in (server.http.hsts_preload) — preload-list submission is
// a decision about the whole registrable domain that only its owner can make.
//
// Headers are set before the handler runs, so they apply to every response — including
// errors, panics (the recovery middleware runs after this), and static assets — not just
// the handlers that set nosniff themselves today.
func SecurityHeaders(tlsEnabled, hstsPreload bool) func(http.Handler) http.Handler {
	hsts := HSTSValue(hstsPreload)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "no-referrer")
			h.Set("Content-Security-Policy", contentSecurityPolicy)
			h.Set("Cross-Origin-Resource-Policy", "same-origin")
			h.Set("Cross-Origin-Embedder-Policy", "require-corp")
			h.Set("Cross-Origin-Opener-Policy", "same-origin")
			h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()")
			h.Set("X-Permitted-Cross-Domain-Policies", "none")
			if RequestIsHTTPS(r, tlsEnabled) {
				h.Set("Strict-Transport-Security", hsts)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// hstsMaxAge is one year, the same default as the web nginx (KEYORIX_WEB_HSTS_MAX_AGE,
// web.hsts.maxAge) and the minimum the browser preload lists accept.
const hstsMaxAge = "31536000"

// HSTSValue is the Strict-Transport-Security value the backend sends.
// includeSubDomains is always on, matching the web nginx default: Keyorix serves
// secrets and session cookies, and a sibling host left on plain http could set a
// cookie for the parent domain or be used to strip TLS. An operator whose subdomains
// cannot all do https terminates TLS at their own proxy and sets HSTS there.
func HSTSValue(preload bool) string {
	v := "max-age=" + hstsMaxAge + "; includeSubDomains"
	if preload {
		v += "; preload"
	}
	return v
}
