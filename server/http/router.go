package http

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/http/handlers"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
	"github.com/keyorixhq/keyorix/server/webui"
)

const (
	cacheNoCache                  = "no-cache" // NOSONAR -- cognitive complexity 20, suppress go:S3776
	hdrCacheControl               = "Cache-Control"
	hdrContentType                = "Content-Type"
	contentTypeHTML               = "text/html"
	pathEnvironmentsID            = "/environments/{id}"
	pathGroups                    = "/groups"
	pathGroupsID                  = "/groups/{id}"
	pathIDPermissions             = "/{id}/permissions"
	pathIDRestore                 = "/{id}/restore"
	pathIDRoles                   = "/{id}/roles"
	pathIDSchedule                = "/{id}/schedule"
	pathInvitations               = "/invitations"
	pathNotificationChannelsID    = "/notification-channels/{id}"
	pathAlertEscalationPolicies   = "/alert-escalation-policies"
	pathAlertEscalationPoliciesID = "/alert-escalation-policies/{id}"
	pathLegalHold                 = "/legal-hold"
	pathMetrics                   = "/metrics"
	pathProjectEnvs               = "/projects/{id}/environments"
	pathProjectMembers            = "/projects/{id}/members"
	pathProjects                  = "/projects"
	pathProjectsID                = "/projects/{id}"
	pathRiskExceptions            = "/risk-exceptions"
	pathRiskExceptionsID          = "/risk-exceptions/{id}"
	pathSCIMGroupsID              = "/Groups/{id}"
	pathSCIMUsersID               = "/Users/{id}"
	pathStatus                    = "/status"
	permAuditRead                 = "audit.read"
	permRolesAssign               = "roles.assign"
	permRolesRead                 = "roles.read"
	permRolesWrite                = "roles.write"
	permSecretsDelete             = "secrets.delete"
	permSecretsManage             = "secrets.manage"
	permSecretsRead               = "secrets.read"
	permSecretsWrite              = "secrets.write"
	permSystemRead                = "system.read"
	permSystemWrite               = "system.write"
	permUsersRead                 = "users.read"
	permUsersWrite                = "users.write"
	// permAlertsWrite (F1, ADR-110 follow-up, Andrei 2026-09-28): the narrower
	// "alerting operator" persona split off system.write — notification
	// channels, escalation policies, and the on-demand job triggers that only
	// ever emit/dispatch a notification. system.write remains a strict
	// superset (see internal/core/alerts_write_role_reconcile.go).
	permAlertsWrite = "alerts.write"
)

// NewRouter creates and configures the HTTP router
func NewRouter(cfg *config.Config, coreService *core.KeyorixCore) (http.Handler, error) { // NOSONAR -- cognitive complexity 20, suppress go:S3776
	r := chi.NewRouter()

	// Apply middleware. Recovery is registered FIRST so it is the OUTERMOST handler in
	// the chain (chi wraps middleware in registration order: the first Use() call wraps
	// everything registered after it). A panic in any later-registered middleware —
	// RequestID, ClientIP, Logger, or anything below — must still be caught and turned
	// into a clean 500 rather than propagating out to net/http's own bare panic
	// recovery (which just logs and drops the connection, with none of Recovery's
	// structured JSON response or panic-context logging). Recovery itself only reads
	// the raw request (header, context — best-effort, nil-safe) so it has no ordering
	// dependency on anything registered after it.
	r.Use(customMiddleware.Recovery())
	r.Use(middleware.RequestID)
	// Trusted-proxy-aware client IP: honor X-Forwarded-For / X-Real-IP ONLY when the TCP
	// peer is a configured trusted proxy, otherwise use the real peer. chi's RealIP trusts
	// the header unconditionally, which lets any client spoof its source IP and defeat the
	// per-IP login/MFA brute-force rate limiter.
	r.Use(customMiddleware.ClientIP(cfg.Server.HTTP.TrustedProxies))
	r.Use(customMiddleware.Logger())
	r.Use(customMiddleware.SecurityHeaders(cfg.Server.HTTP.TLS.Enabled))
	// Global default: no-store on every response (#433). This is a secrets manager — a
	// browser or intermediate proxy must never be allowed to cache anything by default,
	// including routes registered outside the auth/SCIM/API groups (health/status/metrics,
	// the OpenAPI spec, swagger docs, the web UI shell) or any route added here later.
	// Registered early (before per-route handlers/middleware further down the chain) so it
	// merely sets the header first: a handler that deliberately wants different caching
	// (the health/readiness checks' own cacheNoCache, the status pages' own cacheNoCache, and
	// the web UI's hashed static assets via setCacheHeaders) calls w.Header().Set on the
	// same key afterward and wins, since Set replaces rather than appends. Routes with no
	// opinion of their own keep the safe no-store default instead of silently having none.
	r.Use(customMiddleware.NoStore)
	r.Use(customMiddleware.PrometheusMiddleware)
	r.Use(customMiddleware.MaxBodyBytes(cfg.Server.HTTP.EffectiveMaxRequestBodyBytes()))
	r.Use(middleware.Timeout(60 * time.Second))
	// RESIL-1 (#2637 follow-up): a request whose write timed out on the SQLite write
	// gate answers 503 + Retry-After instead of a generic 500. Inside Timeout (it must
	// see the context the handlers see) and outside every handler; the credential
	// surface (/auth/) is exempt inside the middleware itself.
	r.Use(customMiddleware.WriteContention)

	// A tighter body-size limit for the three routes that carry a secret VALUE
	// (create/update/rotate), scoped in addition to (not instead of) the global
	// EffectiveMaxRequestBodyBytes limit above. Derived from
	// secrets.limits.max_secret_size rather than left at the generous global
	// default (10 MiB) — see DeriveMaxRequestBodySize's doc comment for why this
	// is NOT simply max_secret_size itself (a secret value travels base64-encoded
	// inside a JSON envelope, which inflates it well past the raw byte count).
	secretBodyLimit := customMiddleware.MaxBodyBytes(config.DeriveMaxRequestBodySize(cfg.Secrets.Limits.MaxSecretSize))

	// CORS configuration. AllowCredentials is set because MFA, WebAuthn, and SSO
	// login paths now issue session cookies (r121); cross-origin requests from the
	// dashboard must be allowed to send them. Credentials are only sent to origins
	// in AllowedOrigins (never "*"), so this does not broaden the attack surface.
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   getAllowedOrigins(cfg),
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowedHeaders:   []string{"Accept", "Authorization", hdrContentType, "X-CSRF-Token", "X-Requested-With"},
		ExposedHeaders:   []string{"Link", "X-Total-Count", "X-Page-Count"},
		MaxAge:           300,
		AllowCredentials: true,
	}))

	// Initialize handlers. First return value discarded since ADR-108 Phase 6 (its
	// only callers were /system UsersActiveTransitionProxy/UsersCredentialsProxy/
	// WebauthnProxy routes, deleted with the proxy tier) -- InitCoreHandlers' side
	// effect of setting the package-level defaultUserHandler is still required by
	// users_handler.go's live wrapper functions.
	_, groupHandler, err := handlers.InitCoreHandlers(coreService)
	if err != nil {
		return nil, fmt.Errorf("failed to init core HTTP handlers: %w", err)
	}

	authHandler := handlers.NewAuthHandler(coreService, cfg.Server.HTTP.TLS.Enabled)
	patHandler := handlers.NewPATHandler(coreService)
	patExpiryHandler := handlers.NewPATExpiryHandler(coreService)
	impersonationHandler := handlers.NewImpersonationHandler(coreService, cfg.Server.HTTP.TLS.Enabled)

	secretHandler, err := handlers.NewSecretHandler(coreService)
	if err != nil {
		return nil, fmt.Errorf("failed to create secret handler: %w", err)
	}

	shareHandler, err := handlers.NewShareHandler(coreService)
	if err != nil {
		return nil, fmt.Errorf("failed to create share handler: %w", err)
	}

	catalogHandler := handlers.NewCatalogHandler(coreService)
	machineAuditHandler := handlers.NewMachineAuditHandler(coreService)
	dashboardHandler := handlers.NewDashboardHandler(coreService)
	adminUsageHandler := handlers.NewAdminUsageHandler(coreService)
	adminBillingHandler := handlers.NewAdminBillingHandler(coreService)
	auditHandler := handlers.NewAuditHandler(coreService)
	licenseHandler := handlers.NewLicenseHandler(coreService)
	rotationPolicyHandler := handlers.NewRotationPolicyHandler(coreService)
	dynamicSecretHandler := handlers.NewDynamicSecretHandler(coreService)
	rbacHandler := handlers.NewRBACHandler(coreService)
	usersRolesHandler := handlers.NewUsersRolesHandler(coreService)
	notificationHandler := handlers.NewNotificationHandler(coreService)
	notificationChannelHandler := handlers.NewNotificationChannelHandler(coreService)
	connectHandler := handlers.NewConnectHandler(coreService)
	adminJobsHandler := handlers.NewAdminJobsHandler(coreService)
	hygieneTrendsHandler := handlers.NewHygieneTrendsHandler(coreService)
	folderHandler := handlers.NewFolderHandler(coreService)
	versionCommentHandler := handlers.NewSecretVersionCommentHandler(coreService)
	secretTemplateHandler := handlers.NewSecretTemplateHandler(coreService)
	alertEscalationHandler := handlers.NewAlertEscalationHandler(coreService)
	rotationCalendarHandler := handlers.NewRotationCalendarHandler(coreService)

	// Auth endpoints (no authentication middleware). Several of these mint or hand back a
	// session token (login, refresh, MFA/WebAuthn verify, the SSO/SAML callbacks) or
	// bootstrap/setup credentials (system/init, setup consume) — a browser or intermediate
	// cache must never be allowed to cache that response. Covered by the router's global
	// no-store default (above) rather than a group-local one.
	r.Group(func(r chi.Router) {
		r.Post("/auth/login", authHandler.Login)
		// RequireCSRF is applied individually: logout lives in the unauthenticated
		// group because it accepts both session-cookie and Bearer callers, but a
		// cookie-carrying browser is still susceptible to logout-CSRF without this
		// check. Bearer-only callers (no session cookie) pass through unchanged per
		// RequireCSRF's own logic (#r124).
		r.With(customMiddleware.RequireCSRF).Post("/auth/logout", authHandler.Logout)
		r.Post("/auth/refresh", authHandler.RefreshToken)
		r.Post("/auth/password-reset", authHandler.PasswordReset)
		// MFA second-step: unauthenticated — the bearer is the single-use challenge
		// issued by /auth/login, not a session.
		r.Post("/auth/mfa/verify", authHandler.VerifyMFA)
		// WebAuthn second-step assertion — also unauthenticated; the bearer is the same
		// single-use challenge from /auth/login plus the ceremony's webauthn_session.
		r.Post("/auth/webauthn/login/begin", authHandler.BeginWebAuthnLogin)
		r.Post("/auth/webauthn/login/finish", authHandler.FinishWebAuthnLogin)
		// Passwordless (usernameless) passkey login — public; a single resident-passkey
		// gesture with user verification mints a session, no password (ADR-036 addendum).
		r.Post("/auth/webauthn/passwordless/begin", authHandler.BeginWebAuthnPasswordlessLogin)
		r.Post("/auth/webauthn/passwordless/finish", authHandler.FinishWebAuthnPasswordlessLogin)
		r.Post("/system/init", authHandler.InitSystem)

		// Credential-delivery setup links (ADR-028) — unauthenticated: the bearer is the
		// single-use setup token in the URL / request body, not a session.
		r.Get("/auth/setup/{token}", authHandler.GetSetupToken)
		r.Post("/auth/setup/consume", authHandler.ConsumeSetup)

		// Human SSO login (OIDC authorization-code flow) — unauthenticated: the IdP is
		// the authenticator. The login redirect, the IdP callback, and the provider list
		// the login page reads. With sso disabled the provider list is empty and BeginSSO
		// 400s on any provider.
		r.Get("/auth/sso/providers", authHandler.ListSSOProviders)
		r.Get("/auth/sso/{provider}/login", authHandler.BeginSSO)
		r.Get("/auth/sso/{provider}/callback", authHandler.CompleteSSO)
		// SAML 2.0 SP endpoints (ADR-063): metadata for the IdP admin, the login redirect
		// (AuthnRequest), and the Assertion Consumer Service. Unauthenticated, like OIDC.
		r.Get("/auth/saml/{provider}/metadata", authHandler.SAMLMetadata)
		r.Get("/auth/saml/{provider}/login", authHandler.BeginSAML)
		r.Post("/auth/saml/{provider}/acs", authHandler.CompleteSAML)
	})

	// Health check endpoint — lightweight liveness signal (does not touch the DB, so a
	// transient DB outage won't get the pod restarted).
	r.Get("/health", handlers.HealthCheck)

	// Version-skew endpoint (ADR-108 PR 0, docs/cli-split-inventory.md §5): unauthenticated,
	// like /health, so a thin CLI can check compatibility before it has credentials. Kept
	// separate from /system/info (system.read-gated) rather than adding fields there —
	// see server/http/handlers/version.go's VersionInfo doc comment for why.
	r.Get("/api/v1/version", handlers.MakeVersionHandler(cfg))

	// Readiness probe — verifies the database is reachable before routing traffic to
	// this replica. Unauthenticated, like /health (k8s probes are unauthenticated).
	r.Get("/readyz", handlers.ReadinessCheck(coreService))

	// Prometheus metrics. When cfg.HTTP.MetricsToken is set, require a matching
	// "Authorization: Bearer <token>" header — suitable for internet-facing deploys
	// where network perimeter control is not available. When unset, the endpoint is
	// unauthenticated (standard for in-cluster Prometheus scraping); keep it inside
	// your perimeter. Exposes HTTP request metrics + Go runtime/process.
	metricsHandler := customMiddleware.MetricsHandler()
	if tok := cfg.Server.HTTP.MetricsToken; tok != "" {
		inner := metricsHandler
		metricsHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			auth := req.Header.Get("Authorization")
			if len(auth) < 8 || auth[:7] != "Bearer " || subtle.ConstantTimeCompare([]byte(auth[7:]), []byte(tok)) != 1 {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			inner.ServeHTTP(w, req)
		})
	}
	r.Handle(pathMetrics, metricsHandler)

	// Status page endpoint - serves stylish status dashboard
	r.Get(pathStatus, func(w http.ResponseWriter, r *http.Request) {
		webDir := getWebAssetsPath(cfg)
		if webDir != "" {
			statusPath := filepath.Join(webDir, "status.html")
			if _, err := os.Stat(statusPath); err == nil {
				w.Header().Set(hdrContentType, contentTypeHTML)
				w.Header().Set(hdrCacheControl, cacheNoCache)
				http.ServeFile(w, r, statusPath)
				return
			}
		}
		// Fallback to JSON health check if status.html not found
		handlers.HealthCheck(w, r)
	})

	// Spanish status page endpoint
	r.Get("/status-es", func(w http.ResponseWriter, r *http.Request) {
		webDir := getWebAssetsPath(cfg)
		if webDir != "" {
			statusPath := filepath.Join(webDir, "status-es.html")
			if _, err := os.Stat(statusPath); err == nil {
				w.Header().Set(hdrContentType, contentTypeHTML)
				w.Header().Set(hdrCacheControl, cacheNoCache)
				http.ServeFile(w, r, statusPath)
				return
			}
		}
		// Fallback to JSON health check if status-es.html not found
		handlers.HealthCheck(w, r)
	})

	// API v1 routes
	// SCIM 2.0 provisioning (RFC 7644) — opt-in, authenticated by a static bearer
	// token (NOT the session/PAT auth) so an IdP can provision/deprovision users.
	if cfg.SCIM.Enabled {
		// Fail startup on a too-short SCIM bearer token rather than silently serving
		// the provisioning endpoint behind a weak, brute-forceable credential (unlike
		// a PAT/machine token, this one is operator-supplied, not server-generated).
		if err := core.ValidateSCIMTokenStrength(cfg.SCIM.GetToken()); err != nil {
			return nil, fmt.Errorf("scim: %w", err)
		}
		scimHandler := handlers.NewSCIMHandler(coreService)
		r.Route("/scim/v2", func(r chi.Router) {
			// no-store is covered by the router's global default (above).
			r.Use(customMiddleware.SCIMToken(cfg.SCIM.GetToken()))
			r.Get("/ServiceProviderConfig", scimHandler.GetServiceProviderConfig)
			r.Get("/Users", scimHandler.ListUsers)
			r.Post("/Users", scimHandler.CreateUser)
			r.Get(pathSCIMUsersID, scimHandler.GetUser)
			r.Put(pathSCIMUsersID, scimHandler.ReplaceUser)
			r.Patch(pathSCIMUsersID, scimHandler.PatchUser)
			r.Delete(pathSCIMUsersID, scimHandler.DeleteUser)
			r.Get("/Groups", scimHandler.ListGroups)
			r.Post("/Groups", scimHandler.CreateGroup)
			r.Get(pathSCIMGroupsID, scimHandler.GetGroup)
			r.Put(pathSCIMGroupsID, scimHandler.ReplaceGroup)
			r.Patch(pathSCIMGroupsID, scimHandler.PatchGroup)
			r.Delete(pathSCIMGroupsID, scimHandler.DeleteGroup)
		})
	}

	r.Route("/api/v1", func(r chi.Router) {
		// Never let any API response (secret values, tokens, …) be cached by a browser or
		// proxy. Covered by the router's global no-store default (above), which runs
		// before Authentication too, so even a 401 carries it.
		// Authentication middleware for API routes
		r.Use(customMiddleware.Authentication(coreService))
		// General per-principal request budget (#163) — a backstop against one
		// already-authorized principal hammering expensive endpoints (e.g. the
		// deployment-wide compliance-posture/secrets-inventory-export handlers), not
		// an authorization boundary. Runs right after Authentication so the
		// principal is resolved. No-op unless server.http.ratelimit.enabled is set.
		r.Use(customMiddleware.PrincipalRateLimit(cfg.Server.HTTP.RateLimit))
		// Double-submit CSRF check for cookie-authenticated state-changing requests
		// (Phase 1 auth-cookie migration) — no-op for Bearer-only callers (PATs,
		// machine tokens, CI/API clients), see RequireCSRF's doc comment.
		r.Use(customMiddleware.RequireCSRF)
		// Confine a principal that still owes account setup to the endpoints of the
		// steps it owes: change-password while restricted (ADR-025), MFA enrolment for
		// an interactive session without a second factor when the deployment mandates
		// MFA (security.require_mfa, ADR-112). Owing both opens both, in either order
		// (#3024). core learns the same policy so a login owing both steps gets a
		// short-lived setup-only session that is revoked once setup is done.
		coreService.SetRequireMFA(cfg.Security.RequireMFA)
		r.Use(customMiddleware.EnforceAccountSetup(cfg.Security.RequireMFA))

		// Self-service account endpoints (My Account). Authenticated but not
		// permission-gated — every user manages their own profile, password,
		// sessions, and personal access tokens. ADR-021 / ADR-027.
		r.Get("/auth/profile", authHandler.Profile)
		r.Put("/auth/profile", authHandler.UpdateProfile)
		r.Post("/auth/change-password", authHandler.ChangePassword)
		// MFA self-service (acts on the authenticated caller's own account). The
		// authenticator-lifecycle routes are blocked under impersonation so an admin
		// acting as a user cannot alter the user's MFA / plant a durable credential that
		// outlives the impersonation session.
		r.With(customMiddleware.BlockWhenImpersonating).Post("/auth/mfa/enroll", authHandler.EnrollMFA)
		r.With(customMiddleware.BlockWhenImpersonating).Post("/auth/mfa/activate", authHandler.ActivateMFA)
		r.With(customMiddleware.BlockWhenImpersonating).Post("/auth/mfa/disable", authHandler.DisableMFA)
		r.Get("/auth/mfa/recovery-codes", authHandler.RecoveryCodesStatus)
		r.With(customMiddleware.BlockWhenImpersonating).Post("/auth/mfa/recovery-codes/regenerate", authHandler.RegenerateRecoveryCodes)
		// Explicit MFA step-up: re-verify TOTP (or a recovery code) without re-logging
		// in to open the 15-minute restricted-secret read window. Blocked under
		// impersonation — an admin acting as a user must not be able to mint a step-up
		// token on behalf of the target account.
		r.With(customMiddleware.BlockWhenImpersonating).Post("/auth/mfa/stepup", authHandler.MFAStepUp)
		// WebAuthn / passkey self-service (acts on the authenticated caller's account).
		r.With(customMiddleware.BlockWhenImpersonating).Post("/auth/webauthn/register/begin", authHandler.BeginWebAuthnRegistration)
		r.With(customMiddleware.BlockWhenImpersonating).Post("/auth/webauthn/register/finish", authHandler.FinishWebAuthnRegistration)
		r.Get("/auth/webauthn/credentials", authHandler.ListWebAuthnCredentials)
		// Deleting a passkey disables WebAuthn when it removes the last one — the same
		// durable MFA-downgrade that /auth/mfa/disable is blocked from doing under
		// impersonation. There is no admin API to remove another user's passkey, so without
		// this guard impersonation would be the one path to weaken a user's second factor.
		r.With(customMiddleware.BlockWhenImpersonating).Delete("/auth/webauthn/credentials/{id}", authHandler.DeleteWebAuthnCredential)
		// WebAuthn step-up re-authentication: a live passkey re-assertion for a
		// WebAuthn-only account (no TOTP factor) to satisfy requireReauth's
		// account-security-factor-change gate -- mints an MFAStepUpGrant scoped
		// to MFAStepUpPurposeReauth only, distinct from the ambient login-time
		// grant. Blocked under impersonation, same reasoning as the step-up above.
		r.With(customMiddleware.BlockWhenImpersonating).Post("/auth/webauthn/reauth/begin", authHandler.BeginWebAuthnReauth)
		r.With(customMiddleware.BlockWhenImpersonating).Post("/auth/webauthn/reauth/finish", authHandler.FinishWebAuthnReauth)
		r.Get("/auth/sessions", authHandler.ListSessions)
		r.Delete("/auth/sessions/{id}", authHandler.RevokeSession)
		r.Get("/auth/tokens", patHandler.ListPATs)
		// Minting a PAT under impersonation would create a durable token owned by the
		// target that outlives the session — block it.
		r.With(customMiddleware.BlockWhenImpersonating).Post("/auth/tokens", patHandler.CreatePAT)
		r.Delete("/auth/tokens/{id}", patHandler.RevokePAT)
		// Expired-token self-service: list and bulk-revoke the caller's own expired PATs.
		r.Get("/auth/tokens/expired", patExpiryHandler.ListExpiredPATs)
		r.Delete("/auth/tokens/expired", patExpiryHandler.BulkRevokeExpiredPATs)
		// Self-scoped: end the current impersonation session (no permission gate).
		r.Post("/auth/end-impersonation", impersonationHandler.End)

		// In-app notifications (ADR-024) — self-scoped, no permission gate.
		r.Get("/notifications", notificationHandler.List)
		r.Post("/notifications/read-all", notificationHandler.MarkAllRead)
		r.Post("/notifications/{id}/read", notificationHandler.MarkRead)

		// Notification channel management — alerting-operator (alerts.write, F1/
		// ADR-110 follow-up). system.write holders keep access via the one-time
		// backfill (internal/core/alerts_write_role_reconcile.go).
		r.With(customMiddleware.RequirePermission(permAlertsWrite)).Get("/notification-channels", notificationChannelHandler.List)
		r.With(customMiddleware.RequirePermission(permAlertsWrite)).Post("/notification-channels", notificationChannelHandler.Create)
		r.With(customMiddleware.RequirePermission(permAlertsWrite)).Get(pathNotificationChannelsID, notificationChannelHandler.Get)
		r.With(customMiddleware.RequirePermission(permAlertsWrite)).Put(pathNotificationChannelsID, notificationChannelHandler.Update)
		r.With(customMiddleware.RequirePermission(permAlertsWrite)).Delete(pathNotificationChannelsID, notificationChannelHandler.Delete)
		r.With(customMiddleware.RequirePermission(permAlertsWrite)).Put("/notification-channels/{id}/retry-policy", notificationChannelHandler.SetRetryPolicy)
		r.With(customMiddleware.RequirePermission(permSystemRead)).Get("/notification-channels/{id}/retry-policy", notificationChannelHandler.GetRetryPolicy)

		// Alert escalation policy management — alerting-operator (alerts.write,
		// same F1 split as notification channels immediately above).
		r.With(customMiddleware.RequirePermission(permAlertsWrite)).Post(pathAlertEscalationPolicies, alertEscalationHandler.Create)
		r.With(customMiddleware.RequirePermission(permAlertsWrite)).Get(pathAlertEscalationPolicies, alertEscalationHandler.List)
		r.With(customMiddleware.RequirePermission(permAlertsWrite)).Get(pathAlertEscalationPoliciesID, alertEscalationHandler.Get)
		r.With(customMiddleware.RequirePermission(permAlertsWrite)).Put(pathAlertEscalationPoliciesID, alertEscalationHandler.Update)
		r.With(customMiddleware.RequirePermission(permAlertsWrite)).Delete(pathAlertEscalationPoliciesID, alertEscalationHandler.Delete)

		// Dashboard endpoints
		// GetStats is the caller's OWN home dashboard (their secret/share counts,
		// their expiring secrets) so it stays reachable by any real principal — but it
		// previously required NO permission at all, not even the universal system_viewer
		// baseline, so a principal holding zero permissions in this system (e.g. a
		// narrowly-scoped machine identity/PAT) could still reach it. Require system.read
		// to close that: every human user holds it from CreateUser (ADR-021), so this is
		// a no-op for the product's normal users and only turns away a principal with no
		// legitimate standing here at all. The deployment-wide aggregate fields the
		// handler also returns (active users, audit-event counts, failed-auth counts) are
		// separately scoped to audit.read INSIDE GetDashboardStats (core/dashboard.go),
		// mirroring the recent-activity scoping already there — a baseline caller gets
		// their own numbers with the org-wide aggregates zeroed, not a 403 on their own
		// home page.
		r.With(customMiddleware.RequirePermission(permSystemRead)).Get("/dashboard/stats", dashboardHandler.GetStats)
		// The full activity feed is org-wide audit data — gate it behind audit.read.
		// (Per-user dashboard stats scope their own recent-activity in core.)
		r.With(customMiddleware.RequirePermission(permAuditRead)).Get("/dashboard/activity", dashboardHandler.GetActivity)

		// Read-only, redacted config summaries for an admin UI to display (never edit —
		// config stays YAML-only to change). Deliberately NOT inside the /system route
		// group below: that group is the RemoteStorage server-to-server proxy API
		// (machine credentials only, system.write-gated) — these are human-facing reads,
		// so they sit here alongside /dashboard/stats at system.read instead.
		r.With(customMiddleware.RequirePermission(permSystemRead)).Get("/system/auth-config", handlers.MakeAuthConfigHandler(cfg))
		r.With(customMiddleware.RequirePermission(permSystemRead)).Get("/system/encryption-config", handlers.MakeEncryptionConfigHandler(cfg))
		// Same reasoning as auth-config/encryption-config above: server version/
		// build/runtime info and memory/GC/HTTP/DB metrics are human-facing reads,
		// not RemoteStorage proxy traffic, so they don't belong behind the /system
		// group's system.write gate either — moved out to system.read here
		// (previously squatted inside that group; see its own comment for why that
		// group itself stays system.write).
		r.With(customMiddleware.RequirePermission(permSystemRead)).Get("/system/info", handlers.MakeSystemInfoHandler(cfg, coreService))
		r.With(customMiddleware.RequirePermission(permSystemRead)).Get("/system"+pathMetrics, handlers.GetMetrics)

		// Catalog endpoints (projects, environments).
		// List endpoints need global read (browse everything); accessing a
		// specific project/environment is scoped to that project. Creating a
		// project has no parent scope, so it requires global write.
		projectScope := customMiddleware.ScopeFromProjectParam("id")
		// Keyorix Connect (ADR-043): read-through federation to external secret stores.
		// Gated by the dedicated connect.read permission (ADR-044) — distinct from
		// native secrets.read, so external-store access is granted explicitly.
		r.With(customMiddleware.RequirePermission("connect.read")).Get("/connect/connectors", connectHandler.ListConnectors)
		r.With(customMiddleware.RequirePermission("connect.read")).Post("/connect/{name}/secret:read", connectHandler.ReadSecret)
		// Per-reference grant management (ADR-045) — scopes which refs which roles may
		// read. Privileged role-authorization config, so gated by roles.read/roles.write
		// rather than connect.read.
		r.With(customMiddleware.RequirePermission(permRolesRead)).Get("/connect/ref-grants", connectHandler.ListRefGrants)
		r.With(customMiddleware.RequirePermission(permRolesWrite)).Post("/connect/ref-grants", connectHandler.CreateRefGrant)
		r.With(customMiddleware.RequirePermission(permRolesWrite)).Delete("/connect/ref-grants/{id}", connectHandler.DeleteRefGrant)
		// ListProjects authorizes INSIDE the handler (no RequirePermission here) so a
		// project-scoped reader receives the projects they can actually read instead of
		// a blanket 403 — the same shape, and the same reasoning, as ListSecrets below.
		// #2780: the global gate here made the UI's project switcher, /projects page and
		// New Secret dialog come up empty for a persona that could read the project's
		// secrets perfectly well. The handler's own doc comment carries the full
		// argument, including why ?include_deleted=true keeps the global requirement.
		r.Get(pathProjects, catalogHandler.ListProjects)
		r.With(customMiddleware.RequireScopedPermission(permSecretsRead, projectScope)).Get(pathProjectsID, catalogHandler.GetProject)
		r.With(customMiddleware.RequirePermission(permSecretsWrite)).Post(pathProjects, catalogHandler.CreateProject)
		r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, projectScope)).Put(pathProjectsID, catalogHandler.UpdateProject)
		r.With(customMiddleware.RequireScopedPermission(permSecretsDelete, projectScope)).Delete(pathProjectsID, catalogHandler.DeleteProject)
		// Restore reinstates every role grant the project carried at deletion — the
		// same blast radius as a role grant — so gate on roles.assign (#161), not
		// secrets.write, mirroring the direct-grant paths (matching #147's group fix).
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Post("/projects/{id}/restore", catalogHandler.RestoreProject)
		r.With(customMiddleware.RequireScopedPermission(permSecretsRead, projectScope)).Get("/projects/{id}/drift", catalogHandler.GetProjectDrift)
		r.With(customMiddleware.RequireScopedPermission(permSecretsRead, projectScope)).Get("/projects/{id}/rotation-order", secretHandler.GetProjectRotationOrder)
		r.With(customMiddleware.RequireScopedPermission(permSecretsRead, projectScope)).Get("/projects/{id}/rotation-plan", secretHandler.GetProjectRotationPlan)
		r.With(customMiddleware.RequireScopedPermission(permSecretsRead, projectScope)).Get("/projects/{id}/health", secretHandler.GetProjectHealth)
		r.With(customMiddleware.RequireScopedPermission(permSecretsRead, projectScope)).Get("/projects/{id}/stats", secretHandler.GetProjectStats)
		// Deployment-wide rotation plan (ADR-053): aggregates every project. Gated by
		// GLOBAL secrets.read — the same access level as listing all projects — so it
		// reveals no project the caller cannot already see.
		r.With(customMiddleware.RequirePermission(permSecretsRead)).Get("/rotation-plan", secretHandler.GetDeploymentRotationPlan)
		// Project membership (ADR-021 two-tier model). Read = project members may
		// view the roster; mutations require roles.assign at the project scope, so
		// a project_admin can manage their own project's members.
		r.With(customMiddleware.RequireScopedPermission(permUsersRead, projectScope)).Get(pathProjectMembers, catalogHandler.ListProjectMembers)
		r.With(customMiddleware.RequireScopedPermission(permRolesRead, projectScope)).Get("/projects/{id}/access-review", catalogHandler.GetProjectAccessReview)
		// Recertification decisions (ISO 27001 A.5.18): attest is a reviewer action
		// (roles.read); revoke removes the grant and needs roles.assign.
		r.With(customMiddleware.RequireScopedPermission(permRolesRead, projectScope)).Post("/projects/{id}/access-review/attest", catalogHandler.AttestProjectAccessReview)
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Post("/projects/{id}/access-review/revoke", catalogHandler.RevokeProjectAccessReview)
		// Access-review campaigns (A.5.18 periodic recertification): reads roles.read,
		// mutations roles.assign, at the project scope.
		r.With(customMiddleware.RequireScopedPermission(permRolesRead, projectScope)).Get("/projects/{id}/access-review/campaigns", catalogHandler.ListAccessReviewCampaigns)
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Post("/projects/{id}/access-review/campaigns", catalogHandler.OpenAccessReviewCampaign)
		r.With(customMiddleware.RequireScopedPermission(permRolesRead, projectScope)).Get("/projects/{id}/access-review/campaigns/{campaignId}", catalogHandler.GetAccessReviewCampaign)
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Post("/projects/{id}/access-review/campaigns/{campaignId}/items/{itemId}/decide", catalogHandler.DecideAccessReviewCampaignItem)
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Post("/projects/{id}/access-review/campaigns/{campaignId}/close", catalogHandler.CloseAccessReviewCampaign)
		// CSV export of a campaign's items + decisions — the auditor's signed-off
		// recertification record (ISO 27001 A.5.18). Read-only, roles.read (project).
		r.With(customMiddleware.RequireScopedPermission(permRolesRead, projectScope)).Get("/projects/{id}/access-review/campaigns/{campaignId}/export.csv", catalogHandler.ExportAccessReviewCampaignCSV)
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Post(pathProjectMembers, catalogHandler.AddProjectMember)
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Put("/projects/{id}/members/{userId}", catalogHandler.UpdateProjectMember)
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Delete("/projects/{id}/members/{userId}", catalogHandler.RemoveProjectMember)
		// Membership lifecycle (ADR-022): onboarding state machine, separate from
		// the role grant above. List is project-read; mutations need roles.assign.
		r.With(customMiddleware.RequireScopedPermission(permUsersRead, projectScope)).Get("/projects/{id}/memberships", catalogHandler.ListProjectMemberships)
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Post("/projects/{id}/memberships", catalogHandler.InviteMember)
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Put("/projects/{id}/memberships/{membershipId}", catalogHandler.TransitionMembership)
		// Invitations (ADR-024): admin-driven (roles.assign at the project scope).
		r.With(customMiddleware.RequireScopedPermission(permUsersRead, projectScope)).Get("/projects/{id}/invitations", catalogHandler.ListInvitations)
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Post("/projects/{id}/invitations", catalogHandler.CreateInvitation)
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Delete("/projects/{id}/invitations/{invitationId}", catalogHandler.RevokeInvitation)
		// Resend the invitation's setup link (ADR-028).
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Post("/projects/{id}/invitations/{invitationId}/resend", catalogHandler.ResendInvitation)
		// Global (non-project-scoped) invitation (ADR-024): system role + multi-project
		// assignments applied atomically on accept. A system-admin operation (users.write).
		r.With(customMiddleware.RequirePermission(permUsersWrite)).Post(pathInvitations, catalogHandler.CreateGlobalInvitation)
		// Access requests (ADR-024): requesting + withdrawing are self-service (any
		// authenticated user — they don't have project access yet); listing and
		// approving/rejecting require roles.assign at the project scope.
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Get("/projects/{id}/access-requests", catalogHandler.ListAccessRequests)
		r.Post("/projects/{id}/access-requests", catalogHandler.CreateAccessRequest)
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Put("/projects/{id}/access-requests/{requestId}", catalogHandler.ResolveAccessRequest)
		r.Post("/projects/{id}/access-requests/{requestId}/withdraw", catalogHandler.WithdrawAccessRequest)
		// Bulk approve/reject: process multiple pending access requests in one call.
		// Require roles.assign (same gate as the per-request ResolveAccessRequest).
		r.With(customMiddleware.RequirePermission(permRolesAssign)).Post("/access-requests/bulk-approve", catalogHandler.BulkApproveAccessRequests)
		r.With(customMiddleware.RequirePermission(permRolesAssign)).Post("/access-requests/bulk-reject", catalogHandler.BulkRejectAccessRequests)
		// Secret-scoped access requests (classification_gate.go): approval to
		// read ONE restricted secret's value, distinct from the project/role
		// family above. None of the underlying core functions take a project ID
		// (RequestSecretAccess/ApproveSecretAccessRequest infer it from the
		// secret or the request row itself), so this family is NOT nested under
		// /projects/{id} — see secret_access_requests.go's package doc. Create,
		// list, get-one, and withdraw are self-service (visibility/ownership is
		// enforced inside the core layer, not by a route-level permission gate);
		// approve/reject enforce admin authority at the request's own project
		// inside ApproveSecretAccessRequest/RejectSecretAccessRequest — roles.assign
		// is not the bar the classification gate sets, so there is no coarser
		// HTTP-layer permission check to duplicate it here.
		r.Post("/secret-access-requests", catalogHandler.CreateSecretAccessRequest)
		r.Get("/secret-access-requests", catalogHandler.ListSecretAccessRequests)
		r.Get("/secret-access-requests/{requestId}", catalogHandler.GetSecretAccessRequest)
		r.Put("/secret-access-requests/{requestId}", catalogHandler.ResolveSecretAccessRequest)
		r.Post("/secret-access-requests/{requestId}/withdraw", catalogHandler.WithdrawSecretAccessRequest)
		// Rejection reason templates: pre-defined reasons for rejecting access requests.
		// Creating/deleting requires roles.assign; listing is accessible to all admins.
		r.With(customMiddleware.RequirePermission(permRolesAssign)).Post("/rejection-reason-templates", catalogHandler.CreateRejectionReasonTemplate)
		r.With(customMiddleware.RequirePermission(permRolesAssign)).Get("/rejection-reason-templates", catalogHandler.ListRejectionReasonTemplates)
		r.With(customMiddleware.RequirePermission(permRolesAssign)).Delete("/rejection-reason-templates/{id}", catalogHandler.DeleteRejectionReasonTemplate)
		// Break-glass emergency access: activation is self-service (un-gated — the
		// point is access the caller lacks; controlled by config + justification +
		// audit + auto-expiry). Listing/revoking are review actions (roles.read/assign).
		// #G07: blocked while impersonating, same as IssueMachineToken below — it
		// mints a durable, time-bound role grant attributed to the impersonated
		// TARGET that outlives the bounded, audited impersonation session.
		r.With(customMiddleware.BlockWhenImpersonating).Post("/projects/{id}/break-glass", catalogHandler.ActivateBreakGlass)
		r.With(customMiddleware.RequireScopedPermission(permRolesRead, projectScope)).Get("/projects/{id}/break-glass", catalogHandler.ListBreakGlassActivations)
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Post("/projects/{id}/break-glass/{activationId}/revoke", catalogHandler.RevokeBreakGlass)
		// #2461 watchdog review (2026-10-09): blocked while impersonating, same
		// reasoning as ActivateBreakGlass above. ReviewBreakGlass's self-review
		// refusal compares actorID against activation.UserID -- an impersonating
		// actor's context carries the IMPERSONATED user's ID, not the real
		// admin's, so an activator who can impersonate any roles.assign holder
		// could impersonate one and pass the self-review check, forging an
		// independent "reviewed" record for their own activation. Blocking
		// impersonation here outright is the same structural fix as the
		// activation route: the whole point of ADR-112's independent review is
		// defeated by a puppet identity, so no impersonated session may submit
		// one, regardless of whose account it is impersonating.
		r.With(customMiddleware.BlockWhenImpersonating, customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Post("/projects/{id}/break-glass/{activationId}/review", catalogHandler.ReviewBreakGlass)
		// Machine identities (ADR-023): non-human members, segmented from humans.
		r.With(customMiddleware.RequireScopedPermission(permUsersRead, projectScope)).Get("/projects/{id}/machine-identities", catalogHandler.ListMachineIdentities)
		r.With(customMiddleware.RequireScopedPermission(permUsersRead, projectScope)).Get("/projects/{id}/machine-identities/stale", catalogHandler.ListStaleMachineIdentities)
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Post("/projects/{id}/machine-identities", catalogHandler.CreateMachineIdentity)
		// User→machine migration creates a machine identity (roles.assign, project) AND
		// suspends the source user (users.write, global) — require both.
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).
			With(customMiddleware.RequirePermission(permUsersWrite)).
			Post("/projects/{id}/machine-identities/migrate-from-user", catalogHandler.MigrateUserToMachine)
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Put("/projects/{id}/machine-identities/{machineId}", catalogHandler.TransitionMachineIdentity)
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Patch("/projects/{id}/machine-identities/{machineId}/classification", catalogHandler.ClassifyMachineIdentity)
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Patch("/projects/{id}/machine-identities/{machineId}/tokens/{tokenId}/classification", catalogHandler.ClassifyMachineToken)
		// Machine-token credentials + role grants (ADR-030). Issuing a token is blocked
		// while impersonating — like PAT creation — so an admin acting as another user
		// cannot plant a durable (potentially non-expiring) credential that outlives the
		// bounded, audited impersonation session.
		r.With(customMiddleware.BlockWhenImpersonating, customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Post("/projects/{id}/machine-identities/{machineId}/tokens", catalogHandler.IssueMachineToken)
		r.With(customMiddleware.RequireScopedPermission(permUsersRead, projectScope)).Get("/projects/{id}/machine-identities/{machineId}/tokens", catalogHandler.ListMachineTokens)
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Delete("/projects/{id}/machine-identities/{machineId}/tokens/{tokenId}", catalogHandler.RevokeMachineToken)
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Post("/projects/{id}/machine-identities/{machineId}/roles", catalogHandler.GrantMachineRole)
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Delete("/projects/{id}/machine-identities/{machineId}/roles/{roleId}", catalogHandler.RemoveMachineRole)
		r.With(customMiddleware.RequireScopedPermission(permRolesRead, projectScope)).Get("/projects/{id}/machine-identities/{machineId}/roles", catalogHandler.ListMachineRoles)
		// OIDC / Kubernetes-JWT federation bindings (ADR-031).
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Post("/projects/{id}/machine-identities/{machineId}/oidc-bindings", catalogHandler.CreateOIDCBinding)
		r.With(customMiddleware.RequireScopedPermission(permUsersRead, projectScope)).Get("/projects/{id}/machine-identities/{machineId}/oidc-bindings", catalogHandler.ListOIDCBindings)
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Delete("/projects/{id}/machine-identities/{machineId}/oidc-bindings/{bindingId}", catalogHandler.DeleteOIDCBinding)
		r.With(customMiddleware.RequireScopedPermission(permSecretsRead, projectScope)).Post("/projects/{id}/secrets/render", secretHandler.RenderTemplate)
		r.With(customMiddleware.RequireScopedPermission(permSecretsRead, projectScope)).Get("/projects/{id}/secrets/deleted", secretHandler.DeletedSecrets)
		r.With(customMiddleware.RequireScopedPermission(permSecretsRead, projectScope)).Get("/projects/{id}/secrets/orphaned", secretHandler.OrphanedSecrets)
		r.With(customMiddleware.RequireScopedPermission(permSecretsRead, projectScope)).Get("/projects/{id}/hygiene", secretHandler.ProjectHygiene)
		r.With(customMiddleware.RequireScopedPermission(permSecretsRead, projectScope)).Get("/projects/{id}/secrets/expiring", secretHandler.ExpiringSecrets)
		// Asset inventory (ISO 27001 A.5.9) — CSV metadata manifest of the project's
		// secrets (no values) for compliance hand-off.
		r.With(customMiddleware.RequireScopedPermission(permSecretsRead, projectScope)).Get("/projects/{id}/secrets/inventory.csv", secretHandler.SecretsInventoryCSV)
		// Naming-policy conformance — live secrets whose names violate the current naming
		// policy (enforced only at create, so a tightened policy leaves stragglers).
		r.With(customMiddleware.RequireScopedPermission(permSecretsRead, projectScope)).Get("/projects/{id}/secrets/name-conformance", secretHandler.SecretNameConformance)
		r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, projectScope)).Post("/projects/{id}/secrets/suspend-all", secretHandler.SuspendProjectSecrets)
		r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, projectScope)).Post("/projects/{id}/secrets/resume-all", secretHandler.ResumeProjectSecrets)
		// Bulk reassignment is always the offboarding/recovery case (re-homing a departed
		// owner's secrets), which core.ReassignOwnedSecrets/transferOwnership now gate on
		// roles.assign — the same blast radius as a role grant (mirroring RestoreProject's
		// gate above) — so the router matches rather than admitting secrets.write callers
		// core will always then reject.
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Post("/projects/{id}/secrets/reassign-owner", secretHandler.ReassignOwner)
		// Bulk expiry renewal — push out the expiration of every expiring/expired secret.
		r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, projectScope)).Post("/projects/{id}/secrets/extend-expiring", secretHandler.ExtendExpiringSecrets)
		// Bulk rename toward naming-policy conformance — remediation for name-conformance.
		r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, projectScope)).Post("/projects/{id}/secrets/bulk-rename", secretHandler.BulkRenameSecrets)
		// Bulk rotation — trigger rotation for multiple secrets at once (incident response).
		r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, projectScope)).Post("/projects/{id}/secrets/bulk-rotate", secretHandler.BulkRotateSecrets)
		// Bulk delete — remove multiple secrets in one call; same cleanup as single delete.
		r.With(customMiddleware.RequireScopedPermission(permSecretsDelete, projectScope)).Post("/projects/{id}/secrets/bulk-delete", secretHandler.BulkDeleteSecrets)
		// Bulk copy also requires secrets.read on the SOURCE environment (resolved from
		// the envId path param, not attacker-supplied input) — mirroring the single-secret
		// copy route below, which gates secrets.read on the source in addition to
		// secrets.write on the target. Without this leg, a write-only-scoped principal
		// could use the bulk copy to duplicate secret VALUES out of an environment they
		// were deliberately denied read access to, defeating the write-only RBAC role
		// this product's custom-role system is designed to support.
		r.With(
			customMiddleware.RequireScopedPermission(permSecretsWrite, projectScope),
			customMiddleware.RequireScopedPermission(permSecretsRead, customMiddleware.ScopeFromEnvParam("envId")),
		).Post("/projects/{id}/environments/{envId}/copy-secrets", secretHandler.CopyEnvironmentSecrets)
		// Environment clone: copies all secrets from one environment to another within the same
		// project (staging → production promotion). Requires secrets.write on the project scope
		// (creates in destination) AND secrets.read on the source environment (reads values).
		r.With(
			customMiddleware.RequireScopedPermission(permSecretsWrite, projectScope),
			customMiddleware.RequireScopedPermission(permSecretsRead, customMiddleware.ScopeFromEnvParam("envId")),
		).Post("/projects/{id}/environments/{envId}/clone", catalogHandler.CloneEnvironment)
		r.With(customMiddleware.RequireScopedPermission(permSecretsRead, projectScope)).Get(pathProjectEnvs, catalogHandler.ListProjectEnvironments)
		r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, projectScope)).Post(pathProjectEnvs, catalogHandler.CreateProjectEnvironment)
		// Environment restore is nested under the project so the scope resolves
		// from the (live) project ID — the env row is soft-deleted and unloadable.
		// Restore reinstates the environment's role grants, so gate on roles.assign
		// (#161), not secrets.write — same shape as the project-restore fix above.
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, customMiddleware.ScopeFromProjectParam("projectId"))).Post("/projects/{projectId}/environments/{id}/restore", catalogHandler.RestoreEnvironment)
		r.With(customMiddleware.RequireScopedPermission(permSecretsDelete, customMiddleware.ScopeFromEnvParam("id"))).Delete(pathEnvironmentsID, catalogHandler.DeleteEnvironment)
		// The cross-project environment list, same treatment as ListProjects above and
		// for the same reason (#2780, fix-siblings): the web New Secret dialog's
		// required Environment select is populated from HERE, so scoping the project
		// list alone would leave that dialog unsatisfiable for a project-scoped reader.
		r.Get("/environments", catalogHandler.ListEnvironments)

		// Secrets endpoints. Per-secret routes resolve scope from the secret's
		// own project/environment via RequireScopedSecretPermission, which ALSO
		// consults per-secret SecretACL grants (RBAC Phase 3) in addition to the
		// project-scope role check that ScopeFromSecretParam +
		// RequireScopedPermission alone would give — a caller granted
		// secrets.read/write on this one secret (or an ancestor folder) needs no
		// project role at all, matching what ListSecrets already honors. List
		// authorizes against the project_id/environment_id query filter (a
		// scoped reader must narrow to a project they can read; the same filter
		// then bounds the returned rows). Create authorizes in-handler against
		// the project/environment in the body.
		r.Route("/secrets", func(r chi.Router) {
			// ListSecrets performs its own authorization inside the handler so that
			// project-scoped readers receive the union of their accessible scopes
			// rather than a 403 on an unfiltered request. See secrets_list.go.
			r.Get("/", secretHandler.ListSecrets)
			// Active create-time policies (naming/value) — any authenticated caller.
			r.Get("/policy", secretHandler.SecretPolicy)
			// Usage analytics (static paths, before /{id}).
			r.With(customMiddleware.RequireScopedPermission(permSecretsRead, customMiddleware.ScopeFromQuery)).Get("/usage/most-accessed", secretHandler.UsageMostAccessed)
			r.With(customMiddleware.RequireScopedPermission(permSecretsRead, customMiddleware.ScopeFromQuery)).Get("/usage/unused", secretHandler.UsageUnused)
			// Read-quota report — deployment-wide secrets approaching MaxReads cap. It
			// discloses usage-percentage/status metadata, not secret values, so it is a
			// report-viewing endpoint in the same disclosure family as the other
			// deployment-wide compliance/audit reports — gate on audit.read (global),
			// not the broader secrets.read (which is scoped for actual secret-value
			// access and is the wrong tier/shape for a report that never discloses a
			// value) (G16).
			r.With(customMiddleware.RequirePermission(permAuditRead)).Get("/quota-report", secretHandler.GetQuotaReport)
			// Org-wide secret asset inventory (ISO 27001 A.5.9) — CSV manifest of every
			// project's secrets, metadata only (no values), but it DOES disclose every
			// secret's real NAME/classification/owner deployment-wide, so it is gated on
			// audit.read (global), NOT the universal system_viewer baseline system.read —
			// same disclosure-family calibration as /compliance/evidence. Static path,
			// before /{id}.
			r.With(customMiddleware.RequirePermission(permAuditRead)).Get("/inventory.csv", secretHandler.DeploymentSecretsInventoryCSV)
			// Org-wide naming-policy conformance — every project's secrets whose names
			// violate the current (global) policy; discloses the violating secrets' real
			// names deployment-wide, so audit.read (global), not the baseline. Static
			// path, before /{id}.
			r.With(customMiddleware.RequirePermission(permAuditRead)).Get("/name-conformance", secretHandler.DeploymentSecretNameConformance)
			// By-reference value read (ESO etc.): resolve project/environment/name → the
			// secret's value. Scoped to the resolved secret; static path, before /{id}.
			// RequireScopedSecretRefPermission resolves the ref exactly once and pins
			// the result on the request context so GetSecretValueByRef reuses it
			// instead of re-resolving by name (closes a TOCTOU window — see its doc).
			r.With(customMiddleware.RequireScopedSecretRefPermission(permSecretsRead)).Get("/value", secretHandler.GetSecretValueByRef)
			// By-name metadata lookup, scoped by project_id/environment_id query params
			// (same gate/convention as ListSecrets above) — the server-side counterpart
			// RemoteStorage.GetSecretByName (#497) needs; a caller with only a secret's
			// name (not its numeric ID) resolves it here. Static path, before /{id}.
			r.With(customMiddleware.RequireScopedPermission(permSecretsRead, customMiddleware.ScopeFromQuery)).Get("/by-name", secretHandler.GetSecretByName)
			r.With(customMiddleware.RequireScopedSecretPermission(permSecretsRead, "id")).Get("/{id}", secretHandler.GetSecret)
			r.With(customMiddleware.RequireScopedSecretPermission(permSecretsRead, "id")).Get("/{id}/versions", secretHandler.GetSecretVersions)
			r.With(customMiddleware.RequireScopedSecretPermission(permSecretsRead, "id")).Get("/{id}/versions/{from}/diff/{to}", secretHandler.DiffSecretVersions)

			// Secret version comments — free-text annotations on a specific version.
			r.With(customMiddleware.RequireScopedSecretPermission(permSecretsRead, "id")).Get("/{id}/versions/{versionId}/comments", versionCommentHandler.ListComments)
			r.With(customMiddleware.RequireScopedSecretPermission(permSecretsWrite, "id")).Post("/{id}/versions/{versionId}/comments", versionCommentHandler.CreateComment)
			// Delete is gated on secrets.manage (admin-only), matching the ACL delete pattern.
			r.With(customMiddleware.RequireScopedSecretPermission(permSecretsManage, "id")).Delete("/{id}/versions/{versionId}/comments/{commentId}", versionCommentHandler.DeleteComment)
			r.With(customMiddleware.RequireScopedSecretPermission(permSecretsRead, "id")).Get("/{id}/risk", secretHandler.GetSecretRisk)
			r.With(customMiddleware.RequireScopedSecretPermission(permSecretsRead, "id")).Get("/{id}/shares", shareHandler.ListSecretShares)
			r.With(customMiddleware.RequireScopedSecretPermission(permSecretsRead, "id")).Get("/{id}/access", secretHandler.ListAccessors)
			r.With(customMiddleware.RequireScopedSecretPermission(permSecretsRead, "id")).Get("/{id}/access-log", secretHandler.AccessHistory)
			r.With(customMiddleware.RequireScopedSecretPermission(permSecretsRead, "id")).Get("/{id}/access-log/export", secretHandler.ExportAccessLog)
			// Per-secret read statistics — lifetime total + recent-window summary.
			r.With(customMiddleware.RequireScopedSecretPermission(permSecretsRead, "id")).Get("/{id}/stats", secretHandler.GetSecretAccessStats)
			r.With(customMiddleware.RequireScopedSecretPermission(permSecretsRead, "id")).Get("/{id}/audit", secretHandler.AuditTrail)
			r.With(customMiddleware.RequireScopedSecretPermission(permSecretsRead, "id")).Get("/{id}/ownership-history", secretHandler.OwnershipHistory)
			r.With(customMiddleware.RequireScopedSecretPermission(permSecretsRead, "id")).Get("/{id}/tags", secretHandler.GetTags)
			r.With(customMiddleware.RequireScopedSecretPermission(permSecretsWrite, "id")).Put("/{id}/tags", secretHandler.SetTags)

			// Secret dependency graph (ADR-052).
			r.With(customMiddleware.RequireScopedSecretPermission(permSecretsRead, "id")).Get("/{id}/dependencies", secretHandler.ListSecretDependencies)
			r.With(customMiddleware.RequireScopedSecretPermission(permSecretsWrite, "id")).Post("/{id}/dependencies", secretHandler.AddSecretDependency)
			r.With(customMiddleware.RequireScopedSecretPermission(permSecretsWrite, "id")).Delete("/{id}/dependencies/{depId}", secretHandler.RemoveSecretDependency)
			r.With(customMiddleware.RequireScopedSecretPermission(permSecretsRead, "id")).Get("/{id}/impact", secretHandler.GetSecretImpact)
			// Blast-radius report: richer impact view with OwnerID, ProjectID, and risk level.
			r.With(customMiddleware.RequireScopedSecretPermission(permSecretsRead, "id")).Get("/{id}/blast-radius", secretHandler.GetBlastRadius)
			// Secret read aggregation report: top readers of a secret over a time window.
			r.With(customMiddleware.RequireScopedSecretPermission(permSecretsManage, "id")).Get("/{id}/read-summary", secretHandler.GetSecretReadSummary)
			// Impact preview: flat cascade-delete count/summary before committing a delete.
			r.With(customMiddleware.RequireScopedSecretPermission(permSecretsRead, "id")).Get("/{id}/impact-preview", secretHandler.GetSecretImpactPreview)

			// Rotation state — per-policy execution state (idle/pending/rotating/succeeded/failed).
			// Gated on secrets.read because it exposes metadata (when rotation last ran, any error)
			// without disclosing the secret value.
			r.With(customMiddleware.RequireScopedSecretPermission(permSecretsRead, "id")).Get("/{id}/rotation-state", rotationPolicyHandler.GetRotationState)

			// Per-secret ACLs (RBAC Phase 3): fine-grained user grants independent of project RBAC.
			r.With(customMiddleware.RequireScopedSecretPermission(permSecretsManage, "id")).Get("/{id}/acl", secretHandler.ListSecretACLs)
			r.With(customMiddleware.RequireScopedSecretPermission(permSecretsManage, "id")).Post("/{id}/acl", secretHandler.GrantSecretACL)
			r.With(customMiddleware.RequireScopedSecretPermission(permSecretsManage, "id")).Delete("/{id}/acl/{aclId}", secretHandler.RevokeSecretACL)

			// Temporal access schedule: restrict a secret's reads to a time window.
			r.With(customMiddleware.RequireScopedSecretPermission(permSecretsManage, "id")).Get(pathIDSchedule, secretHandler.GetSecretSchedule)
			r.With(customMiddleware.RequireScopedSecretPermission(permSecretsManage, "id")).Put(pathIDSchedule, secretHandler.SetSecretSchedule)
			r.With(customMiddleware.RequireScopedSecretPermission(permSecretsManage, "id")).Delete(pathIDSchedule, secretHandler.DeleteSecretSchedule)

			// Per-secret retention policy override: allows operators to give a
			// specific secret a longer (or shorter) retention window than the global
			// data-retention policy (ADR-032). Gated by secrets.manage because it
			// changes how long the secret persists after deletion — a privileged
			// policy decision, not a routine write.
			r.With(customMiddleware.RequireScopedSecretPermission(permSecretsManage, "id")).Patch("/{id}/retention", secretHandler.SetRetentionOverride)

			// Certificate inspection (ADR-054) — public X.509 metadata, no value/key.
			r.With(customMiddleware.RequireScopedSecretPermission(permSecretsRead, "id")).Get("/{id}/certificate", secretHandler.GetSecretCertificate)

			// Create: authorized inside the handler (scope comes from the body).
			r.With(secretBodyLimit).Post("/", secretHandler.CreateSecret)
			r.With(secretBodyLimit, customMiddleware.RequireScopedSecretPermission(permSecretsWrite, "id")).Put("/{id}", secretHandler.UpdateSecret)
			r.With(customMiddleware.RequireScopedSecretPermission(permSecretsWrite, "id")).Patch("/{id}/classification", secretHandler.ClassifySecret)
			r.With(customMiddleware.RequireScopedSecretPermission(permSecretsWrite, "id")).Patch("/{id}/description", secretHandler.DescribeSecret)
			// Copy into another environment: read the source ({id}); the handler also
			// authorizes secrets.write at the target environment's scope.
			r.With(customMiddleware.RequireScopedSecretPermission(permSecretsRead, "id")).Post("/{id}/copy", secretHandler.CopySecret)
			r.With(customMiddleware.RequireScopedSecretPermission(permSecretsWrite, "id")).Patch("/{id}/auto-rotate", secretHandler.SetAutoRotate)
			r.With(secretBodyLimit, customMiddleware.RequireScopedSecretPermission(permSecretsWrite, "id")).Post("/{id}/rotate", secretHandler.RotateSecret)
			// Rotation dry-run / simulation (ADR-047): validates the rotation config without
			// making any live change. Read-only — requires only secrets.read.
			r.With(customMiddleware.RequireScopedSecretPermission(permSecretsRead, "id")).Post("/{id}/rotation/simulate", secretHandler.SimulateRotation)
			r.With(customMiddleware.RequireScopedSecretPermission(permSecretsWrite, "id")).Post("/{id}/rollback", secretHandler.RollbackSecret)
			r.With(customMiddleware.RequireScopedSecretPermission(permSecretsWrite, "id")).Post("/{id}/transfer-ownership", secretHandler.TransferOwnership)
			r.With(customMiddleware.RequireScopedSecretPermission(permSecretsWrite, "id")).Post("/{id}/move", secretHandler.MoveSecret)
			r.With(customMiddleware.RequireScopedSecretPermission(permSecretsWrite, "id")).Post("/{id}/suspend", secretHandler.SuspendSecret)
			r.With(customMiddleware.RequireScopedSecretPermission(permSecretsWrite, "id")).Post("/{id}/resume", secretHandler.ResumeSecret)
			r.With(customMiddleware.RequireScopedSecretPermission(permSecretsWrite, "id")).Post("/{id}/share", shareHandler.ShareSecret)
			// Self-service: a recipient removes their OWN direct share. No scoped
			// permission — the action is on the caller's own grant (core only removes a
			// share whose RecipientID == the caller), so it needs just authentication.
			r.Delete("/{id}/self-share", shareHandler.RemoveSelfFromShare)

			r.With(customMiddleware.RequireScopedSecretPermission(permSecretsDelete, "id")).Delete("/{id}", secretHandler.DeleteSecret)
			// Restore resolves scope from the (soft-deleted) secret via the unscoped resolver.
			r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, customMiddleware.ScopeFromDeletedSecretParam("id"))).Post(pathIDRestore, secretHandler.RestoreSecret)
		})

		// Shares endpoints. The user's own share list stays a global-read op;
		// mutating a specific share is scoped to the shared secret.
		shareScope := customMiddleware.ScopeFromShareParam("id")
		r.Route("/shares", func(r chi.Router) {
			r.With(customMiddleware.RequirePermission(permSecretsRead)).Get("/", shareHandler.ListShares)
			r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, shareScope)).Put("/{id}", shareHandler.UpdateSharePermission)
			r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, shareScope)).Delete("/{id}", shareHandler.RevokeShare)
		})

		// Shared secrets endpoint (the caller's own shares)
		r.With(customMiddleware.RequirePermission(permSecretsRead)).Get("/shared-secrets", shareHandler.ListSharedSecrets)

		// Folder endpoints. Create authorizes in-handler (scope from the body).
		// List scopes via the project_id query param. Delete resolves scope from
		// the folder node's own project/environment.
		folderScope := customMiddleware.ScopeFromSecretParam("id")
		r.Route("/folders", func(r chi.Router) {
			r.With(customMiddleware.RequireScopedPermission(permSecretsRead, customMiddleware.ScopeFromQuery)).Get("/", folderHandler.ListFolders)
			r.Post("/", folderHandler.CreateFolder)
			r.With(customMiddleware.RequireScopedPermission(permSecretsDelete, folderScope)).Delete("/{id}", folderHandler.DeleteFolder)
		})

		// Rotation calendar. Deployment-wide by default (requires global secrets.read),
		// but — like the rotation-policies List/Evaluate/Status routes below — accepts
		// an optional ?project_id=/&environment_id= scope filter via ScopeFromQuery, in
		// which case only a project (or environment) scoped secrets.read grant is
		// required and the response is confined to that scope. This lets a caller who
		// isn't authorized deployment-wide get their own project's calendar instead of
		// needing the broader global grant just to see one project's rotation schedule.
		r.With(customMiddleware.RequireScopedPermission(permSecretsRead, customMiddleware.ScopeFromQuery)).Get("/rotation-calendar", rotationCalendarHandler.Get)

		// Rotation policies endpoints. List/evaluate take an optional scope
		// filter; per-policy routes resolve scope from the policy; create
		// authorizes in-handler against the body.
		policyScope := customMiddleware.ScopeFromRotationPolicyParam("id")
		r.Route("/rotation-policies", func(r chi.Router) {
			r.With(customMiddleware.RequireScopedPermission(permSecretsRead, customMiddleware.ScopeFromQuery)).Get("/", rotationPolicyHandler.List)
			r.With(customMiddleware.RequireScopedPermission(permSecretsRead, customMiddleware.ScopeFromQuery)).Get("/evaluate", rotationPolicyHandler.Evaluate)
			r.With(customMiddleware.RequireScopedPermission(permSecretsRead, customMiddleware.ScopeFromQuery)).Get(pathStatus, rotationPolicyHandler.Status)
			r.With(customMiddleware.RequireScopedPermission(permSecretsRead, policyScope)).Get("/{id}", rotationPolicyHandler.Get)
			r.Post("/", rotationPolicyHandler.Create)
			r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, policyScope)).Put("/{id}", rotationPolicyHandler.Update)
			r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, policyScope)).Delete("/{id}", rotationPolicyHandler.Delete)
		})

		// Secret templates — reusable metadata presets for secret creation (tags,
		// classification, description hints). Read/list: secrets.read; mutations:
		// secrets.write. Authorization is global (templates are deployment-wide).
		r.Route("/secret-templates", func(r chi.Router) {
			r.With(customMiddleware.RequirePermission(permSecretsRead)).Get("/", secretTemplateHandler.List)
			r.With(customMiddleware.RequirePermission(permSecretsWrite)).Post("/", secretTemplateHandler.Create)
			r.With(customMiddleware.RequirePermission(permSecretsRead)).Get("/{id}", secretTemplateHandler.Get)
			r.With(customMiddleware.RequirePermission(permSecretsWrite)).Put("/{id}", secretTemplateHandler.Update)
			r.With(customMiddleware.RequirePermission(permSecretsWrite)).Delete("/{id}", secretTemplateHandler.Delete)
			r.With(customMiddleware.RequirePermission(permSecretsRead)).Post("/{id}/apply", secretTemplateHandler.Apply)
		})

		// Dynamic secrets (ADR-035). #1645/ADR-096: authorization against each
		// config/lease's project/environment scope (reusing secrets.read/write)
		// now runs as scoped-permission middleware, matching every other
		// scoped resource -- it used to run in-handler
		// (DynamicSecretHandler.loadAuthorizedConfig/loadAuthorizedLease),
		// collapsing "doesn't exist" and "exists, denied" into a uniform 404
		// regardless of caller privilege (Convention B) instead of the
		// 403-for-both (narrow real-404-for-global-holders exception)
		// every other scoped route gets from this same middleware.
		r.Route("/dynamic-secrets", func(r chi.Router) {
			configScope := customMiddleware.ScopeFromDynamicSecretConfigParam("id")
			leaseScope := customMiddleware.ScopeFromDynamicSecretLeaseParam("leaseID")
			r.Post("/configs", dynamicSecretHandler.CreateConfig)
			r.Get("/configs", dynamicSecretHandler.ListConfigs)
			r.With(customMiddleware.RequireScopedPermission(permSecretsRead, configScope)).Get("/configs/{id}", dynamicSecretHandler.GetConfig)
			r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, configScope)).Patch("/configs/{id}/classification", dynamicSecretHandler.ClassifyConfig)
			r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, configScope)).Patch("/configs/{id}/enabled", dynamicSecretHandler.SetConfigEnabled)
			r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, configScope)).Post("/configs/{id}/issue", dynamicSecretHandler.IssueLease)
			r.With(customMiddleware.RequireScopedPermission(permSecretsRead, configScope)).Get("/configs/{id}/leases", dynamicSecretHandler.ListLeases)
			r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, configScope)).Post("/configs/{id}/revoke-all", dynamicSecretHandler.RevokeAllLeases)
			r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, leaseScope)).Post("/leases/{leaseID}/renew", dynamicSecretHandler.RenewLease)
			r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, leaseScope)).Post("/leases/{leaseID}/revoke", dynamicSecretHandler.RevokeLease)
		})

		// Users endpoints (RBAC)
		r.Route("/users", func(r chi.Router) {
			r.Use(customMiddleware.RequirePermission(permUsersRead))
			r.Get("/", handlers.ListUsers)
			// CreateUser mutates (and can grant roles via ADR-028 atomic provisioning),
			// so it needs users.write — not just the group-level users.read. Without
			// this gate a global read-only persona (system_auditor holds users.read)
			// could POST a user with role:"system_admin" and escalate to global admin.
			r.With(customMiddleware.RequirePermission(permUsersWrite)).Post("/", handlers.CreateUser)
			r.Get("/search", handlers.SearchUsers)
			// Stale-account warnings (ADR-025): static path before /{id}.
			r.Get("/stale", handlers.StaleAccounts)
			// By-email lookup, scoped by the group-wide users.read gate above — the
			// server-side counterpart RemoteStorage.GetUserByEmail (#503) needs, for a
			// caller with only a user's email (not their numeric ID). Deliberately the
			// SAME gate as GetUser-by-id (not a stricter one): users.read already lets a
			// caller enumerate every user (including email) via GET /users with no
			// filter, so this route grants no new capability at that permission level.
			// Static path, before /{id}.
			r.Get("/by-email", handlers.GetUserByEmail)
			// By-username and by-external-id lookups (#505), the server-side
			// counterparts RemoteStorage.GetUserByUsername/GetUserByExternalID need —
			// SAME gate (users.read) and NotFound shape as by-email above, for the
			// identical reason: a caller with users.read can already enumerate every
			// user's username/external_id via GET /users, so these routes grant no
			// new capability at that permission level. Static paths, before /{id}.
			r.Get("/by-username", handlers.GetUserByUsername)
			r.Get("/by-external-id", handlers.GetUserByExternalID)
			r.Get("/{id}", handlers.GetUser)
			// Mutations need users.write, not the group-wide users.read (which the
			// read-only system_auditor persona holds) — these were the missed
			// siblings of the suspend/reactivate transitions gated below.
			r.With(customMiddleware.RequirePermission(permUsersWrite)).Put("/{id}", handlers.UpdateUser)
			// users.delete, not users.write — matches the gRPC UserService.DeleteUser
			// gate (#141). A custom role granted users.write alone (update, not delete)
			// could otherwise delete users via HTTP while gRPC correctly refused it.
			r.With(customMiddleware.RequirePermission("users.delete")).Delete("/{id}", handlers.DeleteUser)
			r.With(customMiddleware.RequirePermission(permUsersWrite)).Post(pathIDRestore, handlers.RestoreUser)
			r.With(customMiddleware.RequirePermission(permUsersWrite)).Post("/{id}/unlock", handlers.UnlockUser)
			// Admin force-logout: revoke all of a user's sessions (no state change).
			r.With(customMiddleware.RequirePermission(permUsersWrite)).Post("/{id}/revoke-sessions", handlers.RevokeSessions)
			// Account state transitions (ADR-025).
			r.With(customMiddleware.RequirePermission(permUsersWrite)).Post("/{id}/suspend", handlers.SuspendUser)
			r.With(customMiddleware.RequirePermission(permUsersWrite)).Post("/{id}/reactivate", handlers.ReactivateUser)
			r.With(customMiddleware.RequirePermission(permUsersWrite)).Post("/{id}/require-password-reset", handlers.RequirePasswordReset)
			// Credential-delivery resend (ADR-028): reissue + redeliver a setup link.
			r.With(customMiddleware.RequirePermission(permUsersWrite)).Post("/{id}/resend-setup-link", handlers.ResendSetupLink)
			// roles.read, not the group-wide users.read (#141) — matches the gRPC
			// RoleService.GetUserRoles gate for the same data. users.read is held by
			// nearly every seeded role (project_viewer, editor, …), so gating a user's
			// full role-assignment list on it let any low-privilege project member
			// enumerate an arbitrary OTHER user's roles — reconnaissance for targeted
			// privilege-escalation attempts. roles.read is held by system_admin/
			// system_auditor/project_admin, the personas that actually manage access.
			r.With(customMiddleware.RequirePermission(permRolesRead)).Get(pathIDRoles, usersRolesHandler.GetUserRolesForUser)
			// Effective permission set (union across the user's roles) — a read, gated
			// by the group-wide users.read like the roles view used to be. Not part of
			// #141's scope; left as-is.
			r.Get(pathIDPermissions, usersRolesHandler.GetUserPermissionsForUser)
			// Replacing a user's roles is a privilege grant — gate on roles.assign,
			// not the group-wide users.read (which many non-admin roles hold).
			r.With(customMiddleware.RequirePermission(permRolesAssign)).Put(pathIDRoles, usersRolesHandler.UpdateUserRoles)
			// Per-user project assignments for the detail page (ADR-025).
			r.Get("/{id}/memberships", usersRolesHandler.GetUserMembershipsForUser)
			// Admin-scoped shared-secrets view (CLI-split inventory §6 secondary
			// gap): the SAME data as GET /api/v1/shared-secrets (the caller's own
			// shares) for an arbitrary target user. Gated on secrets.read (not
			// just the group-wide users.read above) since the disclosed data is
			// secret metadata (name, project, environment) — the same
			// sensitivity tier as the self-service route, which itself requires
			// secrets.read, not a user-account permission. A self-view (id ==
			// caller) needs only that; a cross-user view additionally goes
			// through the S1 admin-rank ceiling in-core
			// (ListSharedSecretsForUser), matching the roles.read precedent
			// above where a more specific, sensitive-data-appropriate
			// permission was chosen over the blanket group-level gate.
			r.With(customMiddleware.RequirePermission(permSecretsRead)).Get("/{id}/shared-secrets", shareHandler.ListSharedSecretsForUser)
		})

		// Admin impersonation — gated by users.impersonate, which only global
		// admins hold (admin-bypass). Issues a session for the target user.
		r.With(customMiddleware.RequirePermission("users.impersonate")).
			Post("/admin/impersonate", impersonationHandler.Start)

		// Groups endpoints
		r.Route(pathGroups, func(r chi.Router) {
			r.Use(customMiddleware.RequirePermission(permUsersRead))
			r.Get("/", groupHandler.ListGroups)
			// Group CRUD mutates identity/membership state — gate on users.write,
			// not the group-wide users.read (held by the read-only system_auditor).
			r.With(customMiddleware.RequirePermission(permUsersWrite)).Post("/", groupHandler.CreateGroup)
			r.Get("/{id}", groupHandler.GetGroup)
			r.With(customMiddleware.RequirePermission(permUsersWrite)).Put("/{id}", groupHandler.UpdateGroup)
			r.With(customMiddleware.RequirePermission(permUsersWrite)).Delete("/{id}", groupHandler.DeleteGroup)
			// Restore reinstates every role grant the group carried at deletion — the
			// same blast radius as a role grant — so gate on roles.assign (#147), not
			// users.write, mirroring the direct role-grant path below.
			r.With(customMiddleware.RequirePermission(permRolesAssign)).Post(pathIDRestore, groupHandler.RestoreGroup)
			r.Get("/{id}/members", groupHandler.GetGroupMembers)
			// Secrets a group can reach via shares — reveals secret names, so it needs
			// secrets.read on top of the group-level users.read above.
			r.With(customMiddleware.RequirePermission(permSecretsRead)).Get("/{id}/shared-secrets", shareHandler.ListGroupSharedSecrets)
			// Share grants made TO the group (owner/secret IDs, not resolved secret
			// content) — same sensitivity tier as shared-secrets above, same gate.
			r.With(customMiddleware.RequirePermission(permSecretsRead)).Get("/{id}/shares", shareHandler.ListGroupShares)
			// Adding/removing a group member confers (or revokes) every role the group
			// holds — the same blast radius as a role grant, so gate on roles.assign
			// (matching the group's role-grant routes below), not users.read.
			r.With(customMiddleware.RequirePermission(permRolesAssign)).Post("/{id}/members", groupHandler.AddGroupMember)
			r.With(customMiddleware.RequirePermission(permRolesAssign)).Delete("/{id}/members/{userId}", groupHandler.RemoveGroupMember)
			// Viewing a group's role grants discloses the same privilege-escalation
			// topology as a single user's role list, so gate on roles.read (#262) —
			// not the group-wide users.read (held by nearly every seeded role,
			// including the baseline viewer). This matches GetUserRolesForUser above
			// (#141) and the roles.read gate the /roles route group itself uses for
			// GetRolePermissions; the mutating siblings (AssignRoleToGroup,
			// RemoveRoleFromGroup) already require the more privileged roles.assign.
			r.With(customMiddleware.RequirePermission(permRolesRead)).Get(pathIDRoles, rbacHandler.GetGroupRoles)
			r.With(customMiddleware.RequirePermission(permRolesAssign)).Post(pathIDRoles, rbacHandler.AssignRoleToGroup)
			r.With(customMiddleware.RequirePermission(permRolesAssign)).Delete("/{id}/roles/{roleId}", rbacHandler.RemoveRoleFromGroup)
		})

		// Roles endpoints (RBAC)
		r.Route("/roles", func(r chi.Router) {
			r.Use(customMiddleware.RequirePermission(permRolesRead))
			r.Get("/", rbacHandler.ListRoles)
			r.With(customMiddleware.RequirePermission(permRolesWrite)).Post("/", rbacHandler.CreateRole)
			// By-name lookup, scoped by the group-wide roles.read gate above — the
			// server-side counterpart RemoteStorage.GetRoleByName (#512) needs, for a
			// caller (e.g. InviteToProject resolving an invited role by name) with
			// only a role's name, not its numeric ID. Deliberately the SAME gate as
			// GetRole-by-id (not a stricter one): roles.read already lets a caller
			// enumerate every role (including name) via GET /roles with no filter,
			// so this route grants no new capability at that permission level.
			// Static path, before /{id} — mirrors GetUserByEmail (#503) /
			// GetSecretByName (#497)'s query-param "by-X" convention.
			r.Get("/by-name", rbacHandler.GetRoleByName)
			r.Get("/{id}", rbacHandler.GetRole)
			r.With(customMiddleware.RequirePermission(permRolesWrite)).Put("/{id}", rbacHandler.UpdateRole)
			r.With(customMiddleware.RequirePermission(permRolesWrite)).Delete("/{id}", rbacHandler.DeleteRole)
			r.Get(pathIDPermissions, rbacHandler.GetRolePermissions)
			r.With(customMiddleware.RequirePermission(permRolesWrite)).Post(pathIDPermissions, rbacHandler.AssignPermissionToRole)
			r.With(customMiddleware.RequirePermission(permRolesWrite)).Delete("/{id}/permissions/{permissionId}", rbacHandler.RemovePermissionFromRole)
		})

		// #G79: relocated out of the /system group (a human admin, not a node, wants
		// this) when that group's gate became RequireNodeCredential — also fixes the
		// CLI's export-matrix consumer, which already requested this exact path
		// (/api/v1/rbac/permission-matrix, no /system prefix) and was 404ing.
		r.With(customMiddleware.RequirePermission(permRolesRead)).Get("/rbac/permission-matrix", rbacHandler.GetPermissionMatrix)

		// Permissions endpoints
		r.Route("/permissions", func(r chi.Router) {
			r.Use(customMiddleware.RequirePermission(permRolesRead))
			r.Get("/", rbacHandler.ListPermissions)
			// #526: RemoteStorage's storage.type: remote proxy for
			// AssignPermissionToRole's permissionID -> name lookup had no route
			// to call (ListPermissions and GetRolePermissions already had
			// routes to reuse; this was the one gap). Same roles.read gate as
			// the collection route above — no new capability, a caller who can
			// already list every permission can already see this one.
			r.Get("/{id}", rbacHandler.GetPermission)
		})

		// NOTE: the legacy admin-managed "service accounts" (APIClient/APIToken)
		// issuance/management routes were removed here (finding #131): the tokens
		// they minted were never accepted by any authentication path (validateToken
		// in server/middleware/auth.go has no branch for them), making them a dead,
		// unscannable credential type. Machine identities (ADR-030, kx_machine_
		// tokens) are the actual wired, RBAC-integrated non-human-identity
		// credential and are the intended replacement — see docs/adr-030 and
		// docs/adr-027 (which documents this exact gap). The models/DB tables and
		// KEK-rotation sweep code for APIClient/APIToken are left in place for any
		// legacy rows in already-deployed databases.

		// User roles endpoints
		r.Route("/user-roles", func(r chi.Router) {
			// Assign/remove are gated on roles.assign AT THE REQUEST BODY'S TARGET
			// scope (project_id/environment_id, 0 = global) — mirroring
			// RoleGRPCService.AssignRole/RemoveRole, which authorize at the target
			// scope rather than a flat global permission. Before this (#342), these
			// routes used the group-level RequirePermission(permRolesAssign), which
			// always checked the GLOBAL scope regardless of the body's actual
			// target, a parity gap with the gRPC path.
			r.With(customMiddleware.RequireScopedPermission(permRolesAssign, customMiddleware.ScopeFromRoleAssignmentBody)).Post("/", rbacHandler.AssignRole)
			r.With(customMiddleware.RequireScopedPermission(permRolesAssign, customMiddleware.ScopeFromRoleAssignmentBody)).Delete("/", rbacHandler.RemoveRole)
			r.With(customMiddleware.RequirePermission(permRolesAssign)).Get("/user/{userId}", rbacHandler.GetUserRoles)
		})

		// Audit logs endpoints
		r.Route("/audit", func(r chi.Router) {
			r.Use(customMiddleware.RequirePermission(permAuditRead))
			r.Get("/logs", auditHandler.GetAuditLogs)
			r.Get("/search", auditHandler.SearchAuditLogs)
			// FIX-1 sibling of ANOMALY-04 (#2733's bug class): both export routes
			// return AuditExportEntry's full-fidelity shape, including IPAddress and
			// the tamper-evidence hash chain -- deliberately never included in
			// /logs or /search's AuditLogEntry shape. A handler-file doc comment
			// (audit.go's toAuditLogEntries) already asserted these routes have
			// "their own gate" above bare audit.read, but no such elevation was
			// ever registered here -- raise the gate above the group's audit.read
			// with system.read, same bar as /anomalies, so the base viewer/
			// project_auditor tier cannot read other users' IP addresses via export.
			r.With(customMiddleware.RequirePermission(permSystemRead)).Get("/export", auditHandler.ExportAuditLogs)
			r.With(customMiddleware.RequirePermission(permSystemRead)).Get("/export.csv", auditHandler.ExportAuditLogsCSV)
			r.Get("/rbac-logs", auditHandler.GetRBACAuditLogs)
			r.Get("/retention", auditHandler.GetAuditRetention)
			r.Get("/verify", auditHandler.VerifyAuditChain)
			// Writing a checkpoint is a privileged integrity-control action — gate it
			// above the group's audit.read with system.write (admin-level).
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/checkpoint", auditHandler.WriteAuditCheckpoint)
			// A one-time, operator-triggered migration of the audit hash chain's
			// encoding (see internal/core/audit_chain_migrate.go) — same privilege
			// bar as /checkpoint: it rewrites the tamper-evidence dataset itself.
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/migrate-chain-encoding", auditHandler.MigrateAuditChainEncoding)
			// ANOMALY-04: anomaly alerts expose SecretName/AccessedBy/IPAddress — raise
			// the gate above the group's audit.read so the base viewer/system_viewer role
			// cannot enumerate them and check whether their own access patterns were flagged.
			r.With(customMiddleware.RequirePermission(permSystemRead)).Get("/anomalies", handlers.ListAnomalyAlerts)
			// Acknowledging (dismissing) an alert mutates a security-detection record, so
			// gate it above the group's audit.read with system.write — like /checkpoint —
			// rather than letting any read-only auditor silently bury alerts.
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/anomalies/{id}/acknowledge", handlers.AcknowledgeAnomalyAlert)
		})

		// Per-scheduler last-run/last-success timestamps (Prometheus exposition format),
		// deliberately kept off the public, unauthenticated /metrics endpoint — see
		// server/middleware/scheduler_metrics.go — since an exact tick timestamp would
		// let an anonymous caller predict a security-relevant job's next execution to
		// sub-second precision. #G79: relocated out of the /system group (a human admin,
		// not a node, wants this) when that group's gate became RequireNodeCredential.
		r.With(customMiddleware.RequirePermission(permSystemWrite)).Get("/admin/scheduler-metrics", customMiddleware.SchedulerMetricsHandler().ServeHTTP)

		// Offline-license status (ADR-065) — the locally-evaluated commercial entitlement.
		r.With(customMiddleware.RequirePermission(permSystemRead)).Get("/license/status", licenseHandler.GetLicenseStatus)

		// Personal-access-token hygiene — deployment-wide stale / expired-but-active
		// tokens an admin should revoke (token sprawl). Discloses every user's PAT
		// names/scopes/project-env-scope/AllowedCIDRs/owning user ID deployment-wide, so
		// gated on audit.read (global), NOT the universal system_viewer baseline
		// system.read — same disclosure-family calibration as /compliance/evidence.
		r.With(customMiddleware.RequirePermission(permAuditRead)).Get("/pat-hygiene", patHandler.PATHygiene)
		// Machine-token hygiene — deployment-wide stale / expired-but-active machine
		// credentials an admin should revoke (non-human token sprawl). Same calibration
		// as /pat-hygiene: audit.read, not the baseline.
		r.With(customMiddleware.RequirePermission(permAuditRead)).Get("/machine-token-hygiene", catalogHandler.MachineTokenHygiene)
		// Machine identity audit report — deployment-wide identity inventory with
		// credential counts, last-used timestamps, stale status, and revocation status.
		// Same disclosure family as /pat-hygiene and /machine-token-hygiene: audit.read.
		r.With(customMiddleware.RequirePermission(permAuditRead)).Get("/machine-identities/audit", machineAuditHandler.GetMachineAuditReport)
		r.With(customMiddleware.RequirePermission(permAuditRead)).Get("/machine-identities/audit.csv", machineAuditHandler.GetMachineAuditReportCSV)
		// Secret-hygiene rollup — deployment-wide totals of every project's posture
		// (orphaned / unused / expiring / stale-MI / rotation-overdue) + per-project
		// breakdown identified by project name. Same calibration: audit.read.
		r.With(customMiddleware.RequirePermission(permAuditRead)).Get("/hygiene", secretHandler.DeploymentHygiene)

		// Compliance posture — deployment-wide controls snapshot for auditors. Part of
		// the same disclosure family as /compliance/evidence (SoD-violation counts,
		// legal-hold reason, risk-register counts): gated on audit.read, not the
		// universal system_viewer baseline.
		// Credential hygiene trends — 30/60/90-day per-day counts of stale/expired PATs
		// and stale machine credentials. Same disclosure family as /compliance/evidence;
		// gated on audit.read.
		r.With(customMiddleware.RequirePermission(permAuditRead)).Get("/compliance/credential-trends", hygieneTrendsHandler.GetCredentialTrends)

		r.With(customMiddleware.RequirePermission(permAuditRead)).Get("/compliance/posture", dashboardHandler.GetCompliancePosture)
		// Rotation-overdue report grouped by backend: per-backend counts of overdue /
		// up-to-date / never-rotated secrets deployment-wide. Discloses backend labels
		// and secret counts across the whole deployment, so audit.read (not the
		// baseline) applies â same disclosure family as /compliance/evidence.
		r.With(customMiddleware.RequirePermission(permAuditRead)).Get("/compliance/rotation-by-backend", secretHandler.RotationByBackend)
		// Compliance control matrix — controls mapped to ISO/SOC2/NIS2/DORA + status.
		r.With(customMiddleware.RequirePermission(permAuditRead)).Get("/compliance/controls", dashboardHandler.GetComplianceControls)
		// Control matrix as CSV — the same matrix for an auditor's spreadsheet; same gate
		// as the JSON endpoint above (a lower-tier CSV export would just be a bypass).
		r.With(customMiddleware.RequirePermission(permAuditRead)).Get("/compliance/controls.csv", dashboardHandler.ExportComplianceControlsCSV)
		// Compliance digest — on-demand human-readable summary (the scheduled-broadcast
		// text); restates the same posture data, same gate.
		r.With(customMiddleware.RequirePermission(permAuditRead)).Get("/compliance/digest", dashboardHandler.GetComplianceDigest)
		// Compliance digest send — triggers an immediate broadcast to notification
		// channels (Slack/Teams/webhook/email) restating the SAME posture data as GET
		// /compliance/digest above — gate on audit.read to match that read sibling
		// (G16). system.write was the wrong tier: the broadcast discloses nothing beyond
		// what audit.read already permits reading, so it both let a caller lacking the
		// read view still trigger identical content being dispatched to a channel, and
		// blocked an audit.read holder (e.g. system_auditor) from an action no more
		// sensitive than the read they're already trusted with.
		r.With(customMiddleware.RequirePermission(permAuditRead)).Post("/compliance/digest/send", dashboardHandler.SendComplianceDigest)
		// Compliance snapshots — on-demand posture capture + history list. POST requires
		// system.write (triggers a full evaluation + persist); GET only reads stored rows.
		r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/compliance/snapshots", dashboardHandler.TakeComplianceSnapshot)
		r.With(customMiddleware.RequirePermission(permAuditRead)).Get("/compliance/snapshots", dashboardHandler.ListComplianceSnapshots)
		// Legal hold (ISO A.5.34): status discloses the free-text hold reason
		// deployment-wide, so reads need audit.read; place/lift stay system.write
		// (an admin action, not a read disclosure).
		r.With(customMiddleware.RequirePermission(permAuditRead)).Get(pathLegalHold, dashboardHandler.GetLegalHold)
		r.With(customMiddleware.RequirePermission(permSystemWrite)).Post(pathLegalHold, dashboardHandler.PlaceLegalHold)
		r.With(customMiddleware.RequirePermission(permSystemWrite)).Delete(pathLegalHold, dashboardHandler.LiftLegalHold)
		// Compliance evidence pack — posture + supporting records, for archival. Gated on
		// audit.read (global), NOT system.read: the deployment-wide pack enumerates
		// cross-project secret NAMES and break-glass JUSTIFICATIONS, which the minimal
		// system_viewer baseline (system.read only) must not be able to export. audit.read
		// is the compliance/auditor persona (system_auditor/system_admin) at global scope;
		// a project-scoped audit.read holder is correctly excluded from the org-wide pack.
		r.With(customMiddleware.RequirePermission(permAuditRead)).Get("/compliance/evidence", dashboardHandler.GetComplianceEvidence)
		// Verify a previously-exported evidence pack against its detached signature.
		r.With(customMiddleware.RequirePermission(permAuditRead)).Post("/compliance/evidence/verify", dashboardHandler.VerifyComplianceEvidence)
		// Permission baseline attestation — every user's effective permissions (through
		// roles + group membership) as JSON or CSV for auditor hand-off. Gated on
		// audit.read: it discloses the full role/permission topology deployment-wide,
		// same disclosure family as /compliance/evidence.
		r.With(customMiddleware.RequirePermission(permAuditRead)).Get("/compliance/permission-baseline", dashboardHandler.GetPermissionBaseline)
		r.With(customMiddleware.RequirePermission(permAuditRead)).Get("/compliance/permission-baseline.csv", dashboardHandler.GetPermissionBaselineCSV)
		// Permission change audit trail — structured before/after diff of role grants/
		// revokes from the existing audit event trail. Gated on audit.read: it
		// discloses the full role-assignment history deployment-wide, same disclosure
		// family as /compliance/evidence.
		r.With(customMiddleware.RequirePermission(permAuditRead)).Get("/compliance/permission-changes", dashboardHandler.GetPermissionChangeAudit)
		// Risk register (ISO A.5.8): list discloses free-text Reference/Justification
		// (which may itself name a secret) deployment-wide, so reads need audit.read;
		// create/revoke stay system.write.
		r.With(customMiddleware.RequirePermission(permAuditRead)).Get(pathRiskExceptions, dashboardHandler.ListRiskExceptions)
		r.With(customMiddleware.RequirePermission(permSystemWrite)).Post(pathRiskExceptions, dashboardHandler.CreateRiskException)
		r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/risk-exceptions/{id}/approve", dashboardHandler.ApproveRiskException)
		r.With(customMiddleware.RequirePermission(permSystemWrite)).Delete(pathRiskExceptionsID, dashboardHandler.RevokeRiskException)

		// Separation of duties (ISO A.5.3): policy definitions (name/permission pair, no
		// PII) stay at the baseline system.read; the violations list discloses
		// deployment-wide violator names/emails, so it needs audit.read; create/delete
		// policies need system.write.
		r.With(customMiddleware.RequirePermission(permSystemRead)).Get("/sod/policies", catalogHandler.ListSoDPolicies)
		r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/sod/policies", catalogHandler.CreateSoDPolicy)
		r.With(customMiddleware.RequirePermission(permSystemWrite)).Delete("/sod/policies/{id}", catalogHandler.DeleteSoDPolicy)
		r.With(customMiddleware.RequirePermission(permAuditRead)).Get("/sod/violations", catalogHandler.ListSoDViolations)

		// Usage report — per-project secret counts + read activity over a time window,
		// with no per-project ownership check anywhere in the call chain (any project_id
		// can be requested). Gated by audit.read, NOT system.read: system.read is the
		// universal system_viewer baseline auto-assigned to every user at creation
		// (CreateUser), every SSO/JIT-provisioned user, and every SCIM-provisioned user, so
		// gating a deployment-wide, cross-project disclosure report on it alone is
		// equivalent to no gate at all. Same disclosure family as CP-001/CP-008 (see
		// control_framework.go's package comment) — this is the 7th+ confirmed instance of
		// the identical mistake.
		r.With(customMiddleware.RequirePermission(permAuditRead)).Get("/admin/usage", adminUsageHandler.GetUsageReport)

		// Billing report — per-project FinOps usage breakdown for a date range, with no
		// per-project ownership check (project_id list is caller-supplied, unchecked
		// against any membership). Requires the "billing" license feature (gated in
		// core.GenerateBillingReport) as well, but a license feature flag is a deployment
		// capability check, not a per-caller authorization check — it does not substitute
		// for one. Gated by audit.read, NOT system.read, for the same reason as
		// /admin/usage immediately above (same disclosure family, same fix).
		r.With(customMiddleware.RequirePermission(permAuditRead)).Get("/admin/billing/report", adminBillingHandler.GetBillingReport)

		// On-demand triggers for the notification/alert jobs that otherwise run only on
		// their background schedulers — dispatch immediately after an incident or config
		// change. F1 (ADR-110 follow-up) split this group's single gate per-route:
		// every trigger that only ever emits/dispatches a notification AND carries no
		// anomaly/compliance-derived data moved to alerts.write; the rest — three that
		// mutate account/data state (suspend-inactive-users, purge-audit-logs,
		// record-hygiene-snapshot), plus anomaly-alerts, compliance-digest, and
		// run-alert-escalation — stayed on system.write. Those three are
		// notification-only but deliberately excluded from the split: an
		// alert_operator (no audit/compliance authority by design) could point a
		// notification channel they control at any of them and exfiltrate
		// anomaly-detection findings or compliance posture — an SSRF path from
		// air-gapped hosts too. (Note: if the scheduled anomaly/digest jobs already
		// send to every configured channel on their normal schedule, an operator-
		// controlled channel already receives that data regardless of this gate —
		// gating the on-demand trigger only removes the ability to force an
		// immediate send, not the underlying exposure. See
		// docs/adr-110-system-write-scope.md's Decision section for the per-route
		// classification.)
		r.Route("/admin/jobs", func(r chi.Router) {
			// Broadcasts anomaly-detection findings to configured notification
			// channels — kept on system.write, not alerts.write: see the group
			// comment above.
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/anomaly-alerts", adminJobsHandler.RunAnomalyAlerts)
			r.With(customMiddleware.RequirePermission(permAlertsWrite)).Post("/rotation-reminders", adminJobsHandler.RunRotationReminders)
			r.With(customMiddleware.RequirePermission(permAlertsWrite)).Post("/expiry-reminders", adminJobsHandler.RunExpiryReminders)
			// Broadcasts the compliance digest to configured notification channels —
			// kept on system.write, not alerts.write: see the group comment above.
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/compliance-digest", adminJobsHandler.RunComplianceDigest)
			// Persists a HygieneTrendSnapshot row (data persistence, not a
			// notification) — stays on system.write.
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/record-hygiene-snapshot", hygieneTrendsHandler.RecordHygieneSnapshot)
			// CheckRoleExpiry only emits Notification rows (no revocation — a
			// separate sweep removes expired grants); verified by reading
			// internal/core/role_expiry_notify.go.
			r.With(customMiddleware.RequirePermission(permAlertsWrite)).Post("/role-expiry-check", adminJobsHandler.RunRoleExpiryCheck)
			// CheckReadQuotas only emits Notification rows (no read-blocking/
			// enforcement here); verified by reading internal/core/read_quota_alerts.go.
			r.With(customMiddleware.RequirePermission(permAlertsWrite)).Post("/check-read-quotas", adminJobsHandler.RunReadQuotaCheck)
			// Dispatches unacknowledged anomaly alerts to configured notification
			// channels — same anomaly-detection-data exfiltration risk as
			// anomaly-alerts above, so kept on system.write, not alerts.write.
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/run-alert-escalation", alertEscalationHandler.RunEscalation)
			r.With(customMiddleware.RequirePermission(permAlertsWrite)).Post("/token-expiry-check", adminJobsHandler.RunTokenExpiryCheck)
			// Suspends user accounts — a real account-state mutation — stays on
			// system.write.
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/suspend-inactive-users", adminJobsHandler.SuspendInactiveUsers)
			// Deletes audit events — stays on system.write.
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/purge-audit-logs", adminJobsHandler.PurgeAuditLogsJob)
		})

		// Runtime anomaly detection configuration — read/write the DB-persisted
		// detection thresholds without restarting the server.
		r.Route("/admin/anomaly-config", func(r chi.Router) {
			r.With(customMiddleware.RequirePermission(permSystemRead)).Get("/", handlers.GetAnomalyConfig)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Put("/", handlers.UpdateAnomalyConfig)
		})
	})

	// Swagger UI and the raw OpenAPI spec (optional, based on config). #224: the
	// spec endpoint was previously registered unconditionally, so disabling
	// swagger_enabled still leaked the machine-readable API surface even though
	// the human-facing UI was correctly gated. Both routes must share the same
	// on/off behavior.
	if cfg.Server.HTTP.SwaggerEnabled {
		r.Mount("/swagger/", handlers.SwaggerHandler())
		r.Get("/openapi.yaml", handlers.OpenAPISpec)
	}

	// Serve the web dashboard. Prefer an on-disk build (mounted in the Docker
	// stack, or present in dev); otherwise fall back to the build embedded in the
	// binary, so a single keyorix-server can serve the UI with no web container
	// (the air-gap "one file" deployment).
	if webDir := getWebAssetsPath(cfg); webDir != "" {
		log.Printf("Serving web UI from %s", webDir)
		registerWebUI(r, http.Dir(webDir))
	} else if webui.HasRealBuild() {
		log.Printf("Serving embedded web UI (single-binary mode)")
		registerWebUI(r, webui.HTTPFS())
	} else {
		log.Printf("Web UI not bundled in this build; serving API only (placeholder page at /)")
		registerWebUI(r, webui.HTTPFS())
	}

	return r, nil
}

// backendRoutePrefixes lists every non-SPA route family registered on the router
// outside registerWebUI (see router.go's setup above /api/v1, plus /api/v1 itself).
// #214: NotFound previously only special-cased /api/, so a typo'd path under any
// other backend family (auth, health checks, SCIM, metrics, SAML/SSO endpoints
// under /auth, the OpenAPI/swagger docs) silently fell through to the SPA shell
// with a 200 instead of a 404 — not an auth bypass (same static public shell
// everyone gets at /), but noisy/incorrect status codes confuse health-check
// tooling and WAF rules that expect a clean 404 on an unknown path.
var backendRoutePrefixes = []string{
	"/api/", "/auth/", "/scim/", "/system/init", "/health", "/readyz", pathMetrics, pathStatus, "/swagger/", "/openapi.yaml",
}

func isBackendRoute(p string) bool {
	for _, prefix := range backendRoutePrefixes {
		if strings.HasPrefix(p, prefix) {
			return true
		}
		// A prefix ending in "/" (e.g. "/api/") also covers the bare path without
		// the trailing slash (e.g. "/api"), so GET /api or GET /auth returns 404
		// instead of falling through to the SPA and returning HTML.
		if strings.HasSuffix(prefix, "/") && p == prefix[:len(prefix)-1] {
			return true
		}
	}
	return false
}

// writeJSONNotFound sends a JSON 404, for a NotFound request whose Accept
// header indicates the caller is not a browser expecting the SPA shell.
func writeJSONNotFound(w http.ResponseWriter) {
	w.Header().Set(hdrContentType, "application/json")
	w.WriteHeader(http.StatusNotFound)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error": "NotFound", "message": "not found", "code": http.StatusNotFound,
	})
}

// noDirListing wraps a static file handler so a request that resolves to a
// directory (no index file inside it) returns 404 instead of falling through to
// Go's default http.FileServer directory listing (#213). dist/assets has no
// index.html, so a bare GET /assets/ would otherwise list every bundled filename
// including .js.map source-map names — low impact (already discoverable via the
// built JS's own sourceMappingURL comments and index.html's hashed bundle
// references) but unnecessary and inconsistent with serving no directory index.
func noDirListing(fsys http.FileSystem, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		upath := req.URL.Path
		if !strings.HasPrefix(upath, "/") {
			upath = "/" + upath
		}
		if f, err := fsys.Open(path.Clean(upath)); err == nil {
			fi, statErr := f.Stat()
			_ = f.Close()
			if statErr == nil && fi.IsDir() {
				http.NotFound(w, req)
				return
			}
		}
		h.ServeHTTP(w, req)
	})
}

// registerWebUI wires the SPA's static assets and the client-side-routing
// fallback against fsys, which is rooted at the dist directory (so request paths
// map directly: /assets/x -> dist/assets/x). fsys is either an on-disk build
// (http.Dir) or the embedded build (webui.HTTPFS()).
func registerWebUI(r chi.Router, fsys http.FileSystem) {
	fileServer := http.FileServer(fsys)
	assetServer := noDirListing(fsys, fileServer)

	// Static assets are read-only: register GET+HEAD only, so a mutating method
	// (DELETE/PUT/POST/PATCH) on an asset gets a 405 from chi rather than the file
	// served with a 200 (http.FileServer ignores the method). Cleaner semantics and a
	// smaller surface for a security product.
	serveStatic := func(pattern string, h http.Handler, mws ...func(http.Handler) http.Handler) {
		rr := r.With(mws...)
		rr.Method(http.MethodGet, pattern, h)
		rr.Method(http.MethodHead, pattern, h)
	}
	serveStatic("/assets/*", assetServer, setCacheHeaders)
	serveStatic("/static/*", assetServer, setCacheHeaders)
	serveStatic("/sw.js", fileServer)
	serveStatic("/manifest.json", fileServer)
	serveStatic("/favicon.ico", fileServer)

	// SPA fallback: serve index.html for any non-API route that didn't match a
	// registered handler, so client-side routes (e.g. /admin/users) resolve. Only for
	// GET/HEAD — a mutating method to an unmatched path is not a page load.
	r.NotFound(func(w http.ResponseWriter, req *http.Request) {
		// An unmatched path under any known backend route family is a 404
		// regardless of method — never the SPA shell.
		if isBackendRoute(req.URL.Path) {
			http.NotFound(w, req)
			return
		}
		// A mutating method to a non-backend, unmatched path is not a page load.
		if req.Method != http.MethodGet && req.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// A client asking for something other than HTML — an OpenAPI-driven
		// scanner or API client hitting a fuzzed/mistyped path, for example —
		// should get a JSON 404, not the SPA shell's text/html (ZAP/100001:
		// "Unexpected Content-Type"). Real browsers always include text/html
		// or */* in Accept; a client that names application/json and nothing
		// else never accepted an HTML response.
		if accept := req.Header.Get("Accept"); accept != "" && !strings.Contains(accept, contentTypeHTML) && !strings.Contains(accept, "*/*") {
			writeJSONNotFound(w)
			return
		}
		f, err := fsys.Open("index.html")
		if err != nil {
			http.NotFound(w, req)
			return
		}
		defer func() { _ = f.Close() }()
		fi, err := f.Stat()
		if err != nil {
			http.NotFound(w, req)
			return
		}
		w.Header().Set(hdrCacheControl, cacheNoCache)
		http.ServeContent(w, req, "index.html", fi.ModTime(), f)
	})
}

// getAllowedOrigins returns the allowed origins for CORS based on configuration
func getAllowedOrigins(cfg *config.Config) []string {
	// In development, allow localhost origins
	if cfg.Environment == "development" {
		return []string{
			"http://localhost:3000",
			"http://localhost:5173", // Vite dev server
			"http://127.0.0.1:3000",
			"http://127.0.0.1:5173",
		}
	}

	// In production, use configured origins or default to same origin
	if len(cfg.Server.HTTP.AllowedOrigins) > 0 {
		return cfg.Server.HTTP.AllowedOrigins
	}

	// Default to same origin only
	return []string{fmt.Sprintf("https://%s", cfg.Server.HTTP.Domain)}
}

// getWebAssetsPath returns the path to web assets based on configuration
func getWebAssetsPath(cfg *config.Config) string {
	// Check if web assets path is configured
	if cfg.Server.HTTP.WebAssetsPath != "" {
		if _, err := os.Stat(cfg.Server.HTTP.WebAssetsPath); err == nil {
			return cfg.Server.HTTP.WebAssetsPath
		}
	}

	// Default paths to check
	defaultPaths := []string{
		"./web/dist",
		"../web/dist",
		"/app/web/dist", // Docker container path
		"./dist",
	}

	for _, path := range defaultPaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}

// setCacheHeaders sets appropriate cache headers for static assets
func setCacheHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set cache headers for static assets
		if strings.Contains(r.URL.Path, ".") {
			ext := filepath.Ext(r.URL.Path)
			switch ext {
			case ".js", ".css", ".woff", ".woff2", ".ttf", ".eot":
				// Cache for 1 year
				w.Header().Set(hdrCacheControl, "public, max-age=31536000, immutable")
			case ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico":
				// Cache for 1 month
				w.Header().Set(hdrCacheControl, "public, max-age=2592000")
			default:
				// Cache for 1 day
				w.Header().Set(hdrCacheControl, "public, max-age=86400")
			}
		}
		next.ServeHTTP(w, r)
	})
}
