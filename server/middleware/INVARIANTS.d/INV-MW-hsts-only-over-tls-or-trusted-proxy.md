- **INV-MW-hsts-only-over-tls-or-trusted-proxy** `SecurityHeaders` sends
  `Strict-Transport-Security` only when the request reached the client over TLS: this
  process terminates TLS (`tlsEnabled` or `r.TLS != nil`), or `ClientIP` marked the request
  because its immediate TCP peer is in `server.http.trusted_proxies` AND that peer's
  X-Forwarded-Proto (last value, exactly `https`) says so. The trust decision is
  `ClientIP`'s own `peerIsTrustedProxy`, never a second implementation, and it is taken
  before `ClientIP` rewrites `r.RemoteAddr`. Never over plain http; never for an untrusted
  peer forging the header; without `ClientIP` in front of it the mark is absent, so a wrong
  middleware order fails closed (no HSTS). The value is `HSTSValue`: one year,
  `includeSubDomains`, `preload` only with `server.http.hsts_preload`. Why: HSTS-LB-1
  (Andrei 2026-10-12: backend HSTS behind a trusted TLS-terminating proxy only); the web
  nginx's equivalent rule is #3043/#3058. Guard:
  `hsts_trusted_proxy_test.go` (`TestSecurityHeaders_HSTSBehindTrustedProxy`,
  `_HSTSWithoutClientIPIgnoresForwardedProto`, `_HSTSPreloadOptIn`); production router:
  `server/http/hsts_trusted_proxy_e2e_test.go:TestSecurityHeaders_HSTS_TrustedProxyRealRouter`.
<!-- section: Security headers -->
