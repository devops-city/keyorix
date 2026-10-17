# Rate limiting and brute-force bounds

Every unauthenticated or credential-checking endpoint, and the limiter that bounds
guessing against it. See `docs/security/production-hardening-matrix.md` for the row
rules.

Limiters referred to below:

- **login budget**: per client IP, DB-backed so it holds across replicas
  (`checkLoginRateLimit` / `reserveLoginAttempt`, reserved before the credential check,
  INV-HTTP-19), falling back to an in-memory budget when its storage is down
  (`security.auth_rate_limit_fallback`).
- **account lockout**: per account, in core (`recordFailedLogin` / `loginLocked`).
- **failed-token budget**: per client IP, in memory, 10 failures then 1/s
  (`server/middleware/rate_limit.go`, `recordTokenAuthFailure`); gRPC has its own
  (`interceptors/rate_limit.go`).
- **failure budget**: `customMiddleware.FailureBudget`, per client IP, in memory, counts
  only rejected-secret responses, reserved before the handler.

Client IP is the TCP peer unless `server.http.trusted_proxies` names the peer
(`TestLoginRateLimit_DefaultConfig_IgnoresSpoofedForwardedFor`).

## REST: unauthenticated routes

| Endpoint | Limiter | Setting | Default | Test |
|---|---|---|---|---|
| `POST /auth/login` | login budget + account lockout | fixed `LoginMaxAttempts`/`LoginWindow`; `security.login_lockout.*` | 10 per 15 min per IP; lockout on | `server/http/handlers/auth_budget_routes_guard_test.go:TestEveryAuthRoute_IsClassifiedAndBudgeted`, `server/http/handlers/login_rate_limit_reserve_test.go:TestLogin_ConcurrentBurst_RateLimitBoundsCredentialChecks`, `server/http/handlers/auth_sso_s13_test.go:TestLogin_RateLimited_S13` |
| `POST /auth/refresh` | login budget | as login | 10 per 15 min per IP | `server/http/handlers/auth_sso_s13_test.go:TestRefreshToken_RateLimited_S13` |
| `POST /auth/mfa/verify` (TOTP / recovery code) | login budget + account lockout | as login | 10 per 15 min per IP | `server/http/handlers/handlers_s13b_test.go:TestVerifyMFA_RateLimited_S13B`, `internal/core/mfa_test.go:TestVerifyMFALogin_FailedCodesFeedAccountLockout` |
| `POST /auth/webauthn/login/{begin,finish}`, `/auth/webauthn/passwordless/{begin,finish}` | login budget (+ account lockout on finish) | as login | 10 per 15 min per IP | `server/http/handlers/handlers_s13b_test.go:TestBeginWebAuthnLogin_RateLimited_S13B`, `server/http/handlers/handlers_s13b_test.go:TestFinishWebAuthnLogin_RateLimited_S13B`, `server/http/handlers/handlers_s13b_test.go:TestFinishWebAuthnPasswordlessLogin_RateLimited_S13B` |
| `POST /auth/setup/consume` (setup link, ADR-028) | login budget | as login | 10 per 15 min per IP | `server/http/handlers/auth_budget_routes_guard_test.go:TestEveryAuthBudget_HoldsWithItsStorageDown` |
| `POST /auth/password-reset` | password-reset budget | fixed `PasswordResetMaxAttempts`/`Window` | 5 per 15 min per IP | `server/http/handlers/password_reset_rate_limit_test.go:TestPasswordReset_RateLimitedByIP` |
| `GET /auth/sso/{provider}/login`, `GET /auth/saml/{provider}/login` | SSO-begin budget | fixed `SSOBeginMaxAttempts`/`Window` | 20 per 15 min per IP | `server/http/handlers/auth_budget_routes_guard_test.go:TestEveryAuthBudget_HoldsWithItsStorageDown` |
| `GET /auth/sso/{provider}/callback`, `POST /auth/saml/{provider}/acs` (OIDC / SAML federation) | none needed: consume a single-use state minted by the budgeted begin; the IdP authenticates | — | — | `server/http/handlers/auth_budget_routes_guard_test.go:TestEveryAuthRoute_IsClassifiedAndBudgeted` |
| `GET /auth/setup/{token}` | none needed: 256-bit single-use token, read-only | — | — | `server/http/handlers/auth_budget_routes_guard_test.go:TestEveryAuthRoute_IsClassifiedAndBudgeted` |
| `POST /system/init` (bootstrap token) | failure budget on 403 | fixed `bootstrapFailureBurst` / `Refill` | 5, then 1 per 30s | `server/http/failure_budget_routes_test.go:TestSystemInit_BootstrapTokenGuessingThrottled`, `server/middleware/failure_budget_test.go:TestFailureBudget_ConcurrentBurstBoundedByBudget` |
| `GET /metrics` with `metrics_token` | failure budget on 401 | fixed `metricsFailureBurst` / `Refill` | 10, then 1 per 6s | `server/http/failure_budget_routes_test.go:TestMetrics_TokenGuessingThrottled`, `server/middleware/failure_budget_test.go:TestFailureBudget_SuccessesCostNothing` |
| `/scim/v2/*` (SCIM bearer token) | SCIM failed-token throttle | fixed | on | `server/middleware/scim_test.go:TestSCIMToken_ThrottlesRepeatedFailures` |

## REST: authenticated routes

| Endpoint | Limiter | Setting | Default | Test |
|---|---|---|---|---|
| Any `/api/v1/*` bearer credential (session, PAT, machine token, OIDC/Kubernetes JWT) | failed-token budget | fixed | 10, then 1/s | `server/http/failure_budget_routes_test.go:TestBearerTokenGuessingThrottledThroughRouter`, `server/middleware/rate_limit_test.go:TestIPFailureLimiter_StillEnforcesBudget` |
| OIDC federation: unknown-`kid` JWKS refetch (outbound amplification) | per issuer | fixed `jwksMinRefetchInterval` | 1/min | `internal/core/oidc_jwks_test.go:TestHTTPJWKSResolver_UnknownKidRefetchRateLimited`, `internal/core/oidc_jwks_test.go:TestHTTPJWKSResolver_ColdCacheRefetchRateLimited` |
| `POST /auth/mfa/stepup`, WebAuthn re-auth, MFA disable / recovery-code regenerate (second factor re-checked) | account lockout | `security.login_lockout.*` | on | `internal/core/mfa_stepup_test.go:TestVerifyMFAStepUp_AccountLocked`, `internal/core/mfa_test.go:TestDisableMFA_FailedCodesFeedAccountLockout`, `internal/core/mfa_test.go:TestRegenerateMFARecoveryCodes_FailedCodesFeedAccountLockout` |
| Real server: bearer guessing gets 429; idempotent `/system/init` after init never throttled | built `keyorix-server`, SQLite | as above | as above | `scripts/e2e/rate_limits_test.go:TestRateLimits_SQLite` |
| Per-principal request budget (nuisance backstop, not an authz boundary) | `PrincipalRateLimit` | `server.http.ratelimit.*` | off | `server/middleware/rate_limit_test.go:TestPrincipalRateLimit_EnforcesPerPrincipalBudget` |

## gRPC

| Endpoint | Limiter | Setting | Default | Test |
|---|---|---|---|---|
| Every RPC's bearer credential (unary and stream) | gRPC failed-auth budget per IP | fixed | on | `server/grpc/interceptors/auth_test.go:TestAuthInterceptor_FailedAuthHammering_ThrottledByIP`, `server/grpc/interceptors/auth_test.go:TestStreamAuthInterceptor_FailedAuthHammering_ThrottledByIP` |
| Per-principal unary / stream-open budget | `GRPCRateLimitInterceptor`, `StreamRateLimitInterceptor` | `server.grpc.ratelimit.*` | off | `server/grpc/interceptors/rate_limit_test.go:TestGRPCRateLimitInterceptor_EnforcesPerPrincipalBudget`, `server/grpc/interceptors/rate_limit_test.go:TestStreamRateLimitInterceptor_EnforcesPerPrincipalBudget` |

## Gaps (reported, not changed here)

- **`POST /auth/change-password` and `PUT /auth/profile` (email change)** check the
  caller's current password with `bcrypt.CompareHashAndPassword` and feed neither the
  account lockout nor a budget (`internal/core/account.go` `ChangePassword`,
  `UpdateProfile`). Someone holding a stolen session can guess the account's password
  at the per-principal budget's rate, which is off by default. Owned by the auth
  handler work (FIX-3277); recorded in the HARDEN-HTTP-1 session report.
- The per-principal budgets (`server.http.ratelimit`, `server.grpc.ratelimit`) are off
  by default; the server warns at start. The failed-token and failure budgets are in
  memory and per replica: N replicas allow N times the budget (the login budget and
  account lockout are DB-backed and do not).
- `GET /health`, `/readyz`, `/api/v1/version` and `/status` check no credential and
  are not limited.
- `keyorix-server admin recover-admin` is a local command that needs host access and
  the offline recovery key; it has no network endpoint to limit.
