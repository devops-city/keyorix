# Response hygiene

Security headers on every response (errors and the static web UI included), cache
control, error bodies, and what an error may reveal. See
`docs/security/production-hardening-matrix.md` for the row rules.

## REST API and web UI (`server.http`)

`SecurityHeaders` and `NoStore` are global middleware registered before every route,
so they run before any handler, error or panic (`server/http/router.go`).

| Control | Where | Setting | Default | Test |
|---|---|---|---|---|
| `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, CORP/COEP/COOP, `Permissions-Policy`, `X-Permitted-Cross-Domain-Policies: none` on every response | `server/middleware/security_headers.go` `SecurityHeaders` | fixed | on | `server/middleware/security_headers_test.go:TestSecurityHeaders_AlwaysSet`, `server/http/security_headers_e2e_test.go:TestSecurityHeaders_RealRouter` |
| CSP incl. `frame-ancestors 'none'`, `script-src 'self'`, `object-src 'none'` (API and embedded web UI) | `contentSecurityPolicy` | fixed | on | `server/middleware/security_headers_test.go:TestSecurityHeaders_CSPAlwaysSet`, `server/http/security_headers_e2e_test.go:TestSecurityHeaders_RealRouter` |
| HSTS only when the request reached the client over TLS (this listener, or a trusted proxy's `X-Forwarded-Proto: https`) | `RequestIsHTTPS` | `server.http.tls.enabled`, `trusted_proxies`, `hsts_preload` | 1 year, includeSubDomains | `server/middleware/security_headers_test.go:TestSecurityHeaders_HSTSOnlyWithTLS`, `server/http/security_headers_e2e_test.go:TestSecurityHeaders_HSTS_GatedByTLSEnabled`, `server/http/hsts_trusted_proxy_e2e_test.go:TestSecurityHeaders_HSTS_TrustedProxyRealRouter` |
| `Cache-Control: no-store` on every response except hashed static assets and health/status pages | `server/middleware` `NoStore` | fixed | on | `server/http/no_store_route_test.go:TestNoStore_GlobalDefaultCoversNonGroupedRoutes`, `server/http/no_store_route_test.go:TestNoStore_CoversAuthAndTokenEndpoints`, `server/http/no_store_route_test.go:TestNoStore_StaticAssetExceptionPreserved` |
| Every error response (every route, plus the router's own 404/405/401 and a missing static asset) carries the baseline headers, `no-store` and the JSON error body | `server/http/router.go` `writeJSONError`, handler `sendError` | fixed | on | `server/http/error_response_hygiene_test.go:TestEveryErrorResponse_HeadersNoStoreAndJSONBody` |
| Static assets are GET/HEAD only; directories never listed | `registerWebUI`, `noDirListing` | fixed | on | `server/http/static_methods_test.go:TestStaticAssets_RejectMutatingMethods` |
| A panic answers an opaque JSON 500 (no panic value, no stack trace); the stack goes to the log with secrets in the URL redacted | `server/middleware/recovery.go` | fixed | on | `server/middleware/recovery_test.go:TestRecovery_DoesNotLeakInternals`, `server/middleware/recovery_test.go:TestRecovery_RedactsSetupTokenInPanicContextLog`, `server/http/recovery_order_test.go:TestRecoveryIsOutermostMiddleware` |
| A 5xx never carries an error's raw text (storage/driver messages) | `server/http/handlers` `errorMessageFor`, `clientSafe` | fixed | on | `server/http/handlers/raw_error_text_guard_test.go:TestNoRawErrorTextOnServerErrors`, `server/http/handlers/raw_error_text_guard_test.go:TestErrorMessageFor_FiveXXIsGeneric` |
| Real server: headers, no-store and JSON body on 401/404/405 | built `keyorix-server`, SQLite | as above | as above | `scripts/e2e/response_hygiene_test.go:TestResponseHygiene_SQLite` |

## gRPC (`server.grpc`)

| Control | Where | Setting | Default | Test |
|---|---|---|---|---|
| A panic in any interceptor or handler becomes a clean `INTERNAL` status | `interceptors.RecoveryInterceptor` (outermost) | fixed | on | `server/grpc/interceptors/recovery_chain_order_test.go:TestRecoveryInterceptor_CatchesPanicInDownstreamInterceptor`, `server/grpc/interceptors/recovery_chain_order_test.go:TestStreamRecoveryInterceptor_CatchesPanicInDownstreamInterceptor` |
| No raw error / stack trace in `Unknown`/`Internal` statuses, over every registered RPC | `FuzzGRPCProtoreflectInvariants` oracle 1 | fixed | on | `server/grpc/protoreflect_oracle_mechanism_test.go:TestClassifyStatusLeak` |

## Not covered here

- Responses net/http writes before any handler runs (400 for a malformed request
  line, 431 for oversized headers) carry none of these headers; they contain no data.
- `auth.go` `InitSystem` still sends a raw error's text on its 500 branch: the auth
  handlers are owned by FIX-3277 (listed as an exemption in
  `TestNoRawErrorTextOnServerErrors`, reported in the HARDEN-HTTP-1 session report).
- The Helm chart's nginx web frontend sets its own headers (`deploy/helm`, owned by
  PROD-HELM-1); checking it needs a cluster: pending e2e VM.
