- **INV-MW-secure-cookie-follows-effective-https** The `Secure` attribute of EVERY cookie the
  server sets or clears (`kx_session`, `csrf_token`, `kx_admin_session`) comes from the one
  per-request decision `middleware.RequestIsHTTPS(r, tlsEnabled)`: this process terminates TLS
  (`tlsEnabled` or `r.TLS != nil`), or `ClientIP` marked the request because its immediate TCP
  peer is in `server.http.trusted_proxies` AND that peer's last X-Forwarded-Proto is exactly
  `https`. It is the same function `SecurityHeaders` uses for HSTS (INV-MW-hsts-only-over-tls-or-trusted-proxy),
  so cookies and HSTS cannot disagree. It reads only `r.TLS` and the `ClientIP` mark, never a raw
  X-Forwarded-Proto, so an untrusted peer forging the header changes nothing and a missing
  `ClientIP` fails closed (no `Secure` added). Handlers call it once per request into a local
  `secure` and pass that to the cookie helpers; the helpers set `Secure: secure`, never a constant.
  `Secure` is never removed where it is set today (direct TLS and `tls.enabled` are unchanged).
  Only `server/middleware/session_cookie.go` builds cookies. Why: COOKIE-SECURE-1 (follow-up to
  HSTS-LB-1 / #3181: behind a TLS-terminating LB the cookies went out without `Secure`). Guard:
  `server/http/cookie_secure_trusted_proxy_test.go:TestSessionCookies_SecureBehindTrustedProxy`
  (every cookie of login, refresh, impersonation begin/end and logout through the production
  router: trusted https, trusted http, no header, untrusted forged, no proxies configured, direct
  TLS, `tls.enabled`; forged == plain http), and the static scan
  `server/http/cookie_secure_invariant_test.go` (`TestCookieSecureInvariant_*`: no `http.SetCookie`,
  `http.Cookie` literal or raw `Set-Cookie` write outside `session_cookie.go`, the cookie-name set
  is the one the behavioural test drives, every handler cookie call passes the shared `secure`,
  `tlsEnabled` is never read directly, at most one decision per handler). The scan recognises
  `http.SetCookie`, `http.Cookie{}` literals and `Header().Set/Add("Set-Cookie", ...)`; a cookie
  written by another library would not be seen.
<!-- section: Security headers -->
