// sso.go — human single-sign-on via OIDC (authorization-code flow). A user clicks
// "Sign in with SSO", is redirected to their IdP, and on callback Keyorix verifies
// the id_token (signature via the issuer's JWKS, issuer, audience=client_id, expiry,
// and the nonce it issued), maps the identity to a Keyorix user (this provider's
// scoped externalId first, then a provider-gated email fallback), and mints the SAME
// session a password login would — so an
// IdP-provisioned (passwordless) user can actually sign in. SSO logins bypass
// Keyorix-local MFA: the IdP is the trusted authenticator.
//
// When a provider has auto_provision enabled, a first login whose verified identity
// matches no existing account JIT-creates one (active, passwordless, default_role
// baseline) instead of being refused — so an IdP that isn't wired for SCIM push can
// still onboard users on demand. Off by default: an unknown identity is refused.
package core

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"

	"github.com/keyorixhq/keyorix/internal/besteffort"
	"github.com/keyorixhq/keyorix/internal/core/ports"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const (
	ssoStateTTL          = 10 * time.Minute
	EventSSOLogin        = "auth.sso_login"
	EventSSOJITProvision = "auth.sso_jit_provisioned"
	EventSSOGroupsSynced = "auth.sso_groups_synced"
	EventSSORolesSynced  = "auth.sso_roles_synced"
	// EventSSOReconcileRefused is written whenever a group/role reconcile did not
	// fully apply and the login is refused over it (#2903): it names every step
	// that failed (which group or role, add or remove) and what had already been
	// applied before the refusal. Class C means the applied part is NOT rolled
	// back, so this event is the only record of it.
	EventSSOReconcileRefused = "auth.sso_reconcile_refused"
	// EventSSOReconcileLastAdminRefused replaces EventSSOReconcileRefused when one
	// of the failed steps is a removal the last-admin guard refused: the IdP
	// revoked the install's last administrator's admin-conferring group or role.
	// The login stays refused (the IdP's revocation wins -- Andrei, 2026-10-10);
	// this distinct type exists so an operator can alert on it, because the way
	// back is out of band (re-add the user at the IdP, or `keyorix-server admin
	// recover-admin`).
	EventSSOReconcileLastAdminRefused = "auth.sso_reconcile_last_admin_removal_refused"
	ssoClockSkew                      = 60 * time.Second
	ssoDefaultRole                    = "system_viewer"
	ssoDefaultGroupClaim              = "groups"
)

// ssoJITProvisionDetail is the structured payload stored in an
// auth.sso_jit_provisioned event's Diff field, carrying the role actually
// requested for the new account. ReconcileUserBaselineRoles
// (user_baseline_role_reconcile.go) reads NonDefaultRole to tell a user who
// never held system_viewer because the provider's own DefaultRole config
// gave them a different baseline apart from one simply missing it due to the
// pre-#2188 bootstrap-ordering bug — the free-text "role=%s" already in the
// event's Description is for a human reader, not a stable machine-parseable
// field.
type ssoJITProvisionDetail struct {
	Role           string `json:"role,omitempty"`
	NonDefaultRole bool   `json:"non_default_role,omitempty"`
}

// SAMLAuthn is the slice of a SAML Service Provider the SSO flow needs (satisfied by
// *saml.Provider). A type alias of ports.SAMLServiceProvider (ADR-109 step 1) — kept
// under its original name so existing callers/tests are unaffected, and so the SAML
// login path stays unit-testable without a live IdP or a signed response.
type SAMLAuthn = ports.SAMLServiceProvider

// SSOProvider is a resolved SSO provider. Type is "oidc" (the default) or "saml"; the
// type-specific fields (OAuth/JWKS for OIDC, SAML for SAML) are set accordingly, while
// the provisioning + group/role-mapping fields below are shared by both.
type SSOProvider struct {
	Name        string
	Type        string // "oidc" (default) | "saml"
	Issuer      string
	ClientID    string
	OAuth       *oauth2.Config // OIDC: ClientID/Secret + discovered Auth/Token endpoints + redirect
	CompleteURL string         // <redirect origin>/auth/sso/complete — where the browser lands
	SAML        SAMLAuthn      // SAML: the Service Provider (nil for OIDC providers)

	AutoProvision bool   // JIT-create an account on first login for an unknown identity
	DefaultRole   string // baseline role for JIT-provisioned users ("" → system_viewer)

	// TrustAssertedEmail opts a SAML provider into treating its asserted email as
	// verified for resolveSSOUser's email-fallback account linking. SAML carries no
	// per-assertion equivalent of OIDC's email_verified claim — the assertion being
	// IdP-signed only proves the IdP sent it, not that the IdP itself verified
	// ownership of that address (a self-service/low-trust IdP could let a user set
	// any email). Off by default: without it, CompleteSAML's email fallback can
	// still seed a brand-new JIT account (nothing to take over) but cannot claim an
	// EXISTING one — closing a SAML-specific account-takeover path (#89) that
	// OIDC's real email_verified claim already closes. Ignored for OIDC providers.
	TrustAssertedEmail bool

	GroupSync   bool   // reconcile native group memberships from the IdP groups claim on login
	GroupsClaim string // id_token claim carrying group names ("" → "groups")

	// GroupRoleMap maps an IdP group-claim value to a Keyorix (system) role name. When
	// non-empty, each login reconciles the user's grants of the MAPPED roles to match
	// their asserted groups — the IdP drives those role assignments. Roles outside the
	// map are never touched (so manual grants are safe).
	GroupRoleMap map[string]string
}

// SetSSOProviders wires the configured providers (built from config + discovery at
// startup) and the JWKS resolver used to verify id_tokens. nil/empty disables SSO.
func (c *KeyorixCore) SetSSOProviders(providers map[string]*SSOProvider, jwks JWKSResolver) {
	c.ssoProviders = providers
	c.ssoJWKS = jwks
}

// SSOEnabled reports whether any SSO provider is configured.
func (c *KeyorixCore) SSOEnabled() bool { return len(c.ssoProviders) > 0 }

// SSOProviderNames returns the configured provider names, sorted — for the login page.
func (c *KeyorixCore) SSOProviderNames() []string {
	names := make([]string, 0, len(c.ssoProviders))
	for n := range c.ssoProviders {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// SSOCompleteURL returns the browser-facing completion URL for a provider.
func (c *KeyorixCore) SSOCompleteURL(provider string) (string, bool) {
	if p, ok := c.ssoProviders[provider]; ok {
		return p.CompleteURL, true
	}
	return "", false
}

// oidcProvider resolves a configured OIDC provider by name. buildSSOProviders
// (server/main.go) never sets Type for an OIDC provider — it's left as the zero
// value, "" — so "not saml" is treated as OIDC here, mirroring samlProvider's
// reciprocal check. This guards the OIDC flow (which dereferences OAuth
// unconditionally) against being invoked for a provider configured with
// Type: "saml", whose OAuth field is always nil.
func (c *KeyorixCore) oidcProvider(name string) (*SSOProvider, error) {
	p, ok := c.ssoProviders[name]
	if !ok || p.Type == "saml" || p.OAuth == nil {
		return nil, fmt.Errorf("unknown SSO provider %q", name)
	}
	return p, nil
}

// BeginSSO creates and stores the CSRF state + nonce and returns the IdP
// authorization URL to redirect the browser to.
func (c *KeyorixCore) BeginSSO(ctx context.Context, providerName, returnTo string) (string, error) {
	p, err := c.oidcProvider(providerName)
	if err != nil {
		return "", err
	}
	state, err := randToken()
	if err != nil {
		return "", err
	}
	nonce, err := randToken()
	if err != nil {
		return "", err
	}
	// PKCE (RFC 7636): generate a code_verifier, persist it with the login state
	// (server-side only), and send just its S256 challenge to the IdP. CompleteSSO
	// replays the verifier on the token exchange, so an authorization code
	// intercepted between the IdP redirect and the callback cannot be redeemed
	// without the verifier this browser's login state holds. This is defence in
	// depth on top of the confidential-client secret and the single-use state row —
	// the OAuth 2.1 / OIDC baseline (F1, adversarial-review 2026-09-14).
	verifier := oauth2.GenerateVerifier()
	if err := c.storage.CreateSSOLoginState(ctx, &models.SSOLoginState{
		State:        state,
		Nonce:        nonce,
		Provider:     providerName,
		ReturnTo:     sanitizeReturnTo(returnTo),
		CodeVerifier: verifier,
		ExpiresAt:    c.now().Add(ssoStateTTL),
		CreatedAt:    c.now(),
	}); err != nil {
		return "", err
	}
	return p.OAuth.AuthCodeURL(state,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.S256ChallengeOption(verifier),
	), nil
}

// validateSSOLoginState consumes and validates the stored login state for a
// callback: checks provider match and expiry. Returns the state row on success.
func (c *KeyorixCore) validateSSOLoginState(ctx context.Context, providerName, state string) (*models.SSOLoginState, error) {
	st, err := c.storage.ConsumeSSOLoginState(ctx, state)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired login state")
	}
	if st.Provider != providerName {
		return nil, fmt.Errorf("login state does not match the callback provider")
	}
	if c.now().After(st.ExpiresAt) {
		return nil, fmt.Errorf("login state expired")
	}
	return st, nil
}

// CompleteSSO consumes the state, exchanges the code, verifies the id_token, maps it
// to a user, and mints a session. Returns the session, the user, and the in-app path
// to land on (ReturnTo, may be empty).
func (c *KeyorixCore) CompleteSSO(ctx context.Context, providerName, code, state, userAgent, ip string) (*models.Session, *models.User, string, error) {
	p, err := c.oidcProvider(providerName)
	if err != nil {
		return nil, nil, "", fmt.Errorf("unknown SSO provider")
	}
	st, err := c.validateSSOLoginState(ctx, providerName, state)
	if err != nil {
		return nil, nil, "", err
	}

	// Replay the PKCE code_verifier stored at BeginSSO so the IdP binds this
	// exchange to the challenge it saw on the auth request (RFC 7636). Only sent
	// when the state row carries a verifier: a row created before PKCE was added
	// (an in-flight login across an upgrade) has none, and sending an empty
	// verifier against an auth request that carried no challenge would needlessly
	// risk rejection — omitting it preserves the pre-PKCE flow for those.
	exchangeOpts := []oauth2.AuthCodeOption{}
	if st.CodeVerifier != "" {
		exchangeOpts = append(exchangeOpts, oauth2.VerifierOption(st.CodeVerifier))
	}
	tok, err := p.OAuth.Exchange(ctx, code, exchangeOpts...)
	if err != nil {
		return nil, nil, "", fmt.Errorf("authorization-code exchange failed: %w", err)
	}
	rawID, _ := tok.Extra("id_token").(string)
	if rawID == "" {
		return nil, nil, "", fmt.Errorf("the token response carried no id_token")
	}
	sub, email, name, emailVerified, err := c.verifyIDToken(ctx, p, st.Nonce, rawID)
	if err != nil {
		return nil, nil, "", err
	}

	resolved, err := c.resolveSSOUser(ctx, p.Name, sub, email, emailVerified)
	if err != nil {
		return nil, nil, "", err
	}
	user, err := c.ensureSSOUser(ctx, p, resolved, sub, email, emailVerified, name)
	if err != nil {
		return nil, nil, "", err
	}
	if !user.IsActive || AccountLoginBlocked(user.ID, user.AccountState) {
		return nil, nil, "", fmt.Errorf("account suspended")
	}
	// Enforce per-account brute-force lockout (distinct from deactivation/suspension)
	// BEFORE any IdP-driven state mutation below (group/role reconciliation). A locked
	// account must not receive a new session via SSO even though the IdP authenticated
	// it — the lockout signals an active attack and must be honoured on all login
	// paths, same as password/TOTP/WebAuthn (see auth.go) — and its native group/role
	// state must stay frozen while the lock is in effect, not silently resynced by a
	// login attempt that's about to be refused anyway.
	if c.loginLocked(user) {
		return nil, nil, "", fmt.Errorf("account temporarily locked due to repeated failed logins; try again later")
	}
	// TOCTOU re-check only; the clear happens after the session actually exists
	// (#2894). SSO never FEEDS this counter (an IdP-rejected assertion never
	// reaches here), so a post-mint fault simply leaves it untouched rather than
	// at 0 — there is no wrong-credential branch here for it to differ from.
	if err := c.recheckLoginLockFailClosed(ctx, user); err != nil {
		return nil, nil, "", err
	}

	// Reconcile native group memberships and/or mapped role grants from the IdP's
	// groups claim, and refuse the login if that did not fully apply -- the same
	// rule CompleteSAML follows (#2839 item 1, #2903; extended to OIDC by #2907).
	// This used to be best-effort ("a sync failure must not block an otherwise-
	// valid login"), so a failed REVOCATION -- the IdP dropped the user from its
	// admin group and the removal errored or was refused -- left the user holding
	// the privilege AND minted a session carrying it for its whole lifetime.
	// Not rolled back on refusal: class C, see CompleteSAML and
	// docs/atomicity-exempt.tsv (the JIT:(*KeyorixCore).CompleteSAML row, whose
	// reconcile conditions cover this path too since #2907).
	if p.GroupSync {
		if rerr := c.syncSSOGroups(ctx, p, user.ID, rawID); rerr != nil {
			log.Printf("CompleteSSO: refusing login for user %d: %v", user.ID, rerr)
			return nil, nil, "", ssoReconcileLoginRefusal(SSOMsgGroupReconcileRefused, rerr)
		}
	}
	if len(p.GroupRoleMap) > 0 {
		if rerr := c.syncSSORoles(ctx, p, user.ID, rawID); rerr != nil {
			log.Printf("CompleteSSO: refusing login for user %d: %v", user.ID, rerr)
			return nil, nil, "", ssoReconcileLoginRefusal(SSOMsgRoleReconcileRefused, rerr)
		}
	}

	if err := c.enforcePasswordExpiryGate(ctx, user); err != nil {
		return nil, nil, "", err
	}
	session, err := c.mintSession(ctx, user.ID, userAgent, ip)
	if err != nil {
		return nil, nil, "", err
	}
	// Lockout clear AFTER mintSession (#2894), and panic-safe for the same
	// reason as the last-login stamp below (#2920): it runs after the session
	// is committed, so a panic must not turn a completed login into a failure.
	besteffort.Run(ctx, "sso.CompleteSSO.clearLoginFailures", func() error { c.clearLoginFailures(ctx, user); return nil })
	// Best-effort last-login stamp, panic-safe (#2910 fault sweep): it runs
	// AFTER the session is minted, so a panic here used to unwind past a
	// committed session and turn a completed login into a reported failure
	// with an orphan session. Every other login path already runs it
	// panic-safe (goSafe in the handlers).
	besteffort.Run(ctx, "sso.CompleteSSO.RecordLogin", func() error { return c.RecordLogin(ctx, user.ID) })
	c.writeAuditEvent(ctx, EventSSOLogin, actorPtr(user.ID), nil,
		fmt.Sprintf("SSO login via %s (subject=%s)", providerName, sub))
	return session, user, st.ReturnTo, nil
}

// samlProvider resolves a configured SAML provider by name.
func (c *KeyorixCore) samlProvider(name string) (*SSOProvider, error) {
	p, ok := c.ssoProviders[name]
	if !ok || p.Type != "saml" || p.SAML == nil {
		return nil, fmt.Errorf("unknown SAML provider")
	}
	return p, nil
}

// SAMLMetadata returns the SP metadata XML for a provider (served at the metadata route).
func (c *KeyorixCore) SAMLMetadata(name string) ([]byte, error) {
	p, err := c.samlProvider(name)
	if err != nil {
		return nil, err
	}
	return p.SAML.Metadata()
}

// BeginSAML starts an SP-initiated login: it builds a signed-or-unsigned AuthnRequest,
// stores the login state (RelayState key + the request ID for InResponseTo matching),
// and returns the IdP redirect URL. Mirrors BeginSSO for OIDC.
func (c *KeyorixCore) BeginSAML(ctx context.Context, name, returnTo string) (string, error) {
	p, err := c.samlProvider(name)
	if err != nil {
		return "", err
	}
	relayState, err := randToken()
	if err != nil {
		return "", err
	}
	redirectURL, requestID, err := p.SAML.AuthnRequest(relayState)
	if err != nil {
		return "", fmt.Errorf("build SAML request: %w", err)
	}
	// Reuse the SSO login-state row: State is the RelayState lookup key, Nonce carries
	// the AuthnRequest ID (matched against InResponseTo at the ACS).
	if err := c.storage.CreateSSOLoginState(ctx, &models.SSOLoginState{
		State:     relayState,
		Nonce:     requestID,
		Provider:  name,
		ReturnTo:  sanitizeReturnTo(returnTo),
		ExpiresAt: c.now().Add(ssoStateTTL),
		CreatedAt: c.now(),
	}); err != nil {
		return "", err
	}
	return redirectURL, nil
}

// CompleteSAML consumes the RelayState, validates the SAMLResponse on r (signature,
// audience, recipient, time, InResponseTo — via the vetted library), maps the assertion
// to a user, reconciles groups/roles, and mints a session. Mirrors CompleteSSO.
func (c *KeyorixCore) CompleteSAML(ctx context.Context, name string, r *http.Request, relayState, userAgent, ip string) (*models.Session, *models.User, string, error) { // NOSONAR -- cognitive complexity 20, suppress go:S3776
	p, err := c.samlProvider(name)
	if err != nil {
		return nil, nil, "", err
	}
	st, err := c.storage.ConsumeSSOLoginState(ctx, relayState)
	if err != nil {
		return nil, nil, "", fmt.Errorf("invalid or expired login state")
	}
	if st.Provider != name {
		return nil, nil, "", fmt.Errorf("login state does not match the callback provider")
	}
	if c.now().After(st.ExpiresAt) {
		return nil, nil, "", fmt.Errorf("login state expired")
	}

	info, err := p.SAML.ParseResponse(r, []string{st.Nonce})
	if err != nil {
		return nil, nil, "", err
	}
	if strings.TrimSpace(info.Subject) == "" && strings.TrimSpace(info.Email) == "" {
		return nil, nil, "", fmt.Errorf("the assertion carried no subject or email")
	}

	// The assertion being IdP-signed proves the IdP sent this email, not that the
	// IdP verified the user OWNS it — SAML has no per-assertion equivalent of
	// OIDC's email_verified claim. Trusting it unconditionally let a self-service/
	// low-trust SAML IdP claim an EXISTING account (up to a native admin) merely
	// by asserting its address (#89). Gate on the provider's explicit opt-in
	// instead; see SSOProvider.TrustAssertedEmail.
	user, err := c.resolveSSOUser(ctx, p.Name, info.Subject, info.Email, p.TrustAssertedEmail)
	if err != nil {
		return nil, nil, "", err
	}
	if user == nil {
		if !p.AutoProvision {
			return nil, nil, "", fmt.Errorf("no Keyorix account matches this SSO identity")
		}
		// p.TrustAssertedEmail, not a hardcoded true — provisionSSOUser's own
		// race-guard re-runs resolveSSOUser with this exact value to decide
		// whether a just-materialised existing account may be claimed by email
		// match. Hardcoding true here let that internal re-check treat the
		// SAML-asserted email as verified regardless of the provider's own
		// TrustAssertedEmail setting, reopening the #89 SAML account-takeover
		// through the resolve-then-provision race window specifically.
		if user, err = c.provisionSSOUser(ctx, p, info.Subject, info.Email, p.TrustAssertedEmail, info.Name); err != nil {
			return nil, nil, "", err
		}
	}
	if !user.IsActive || AccountLoginBlocked(user.ID, user.AccountState) {
		return nil, nil, "", fmt.Errorf("account suspended")
	}
	// Enforce per-account brute-force lockout BEFORE any IdP-driven state mutation
	// below (group/role reconciliation) — see the identical guard in CompleteSSO for
	// the full rationale. A locked account's native group/role state must stay frozen
	// while the lock is in effect, not silently resynced by a login attempt that's
	// about to be refused anyway.
	if c.loginLocked(user) {
		return nil, nil, "", fmt.Errorf("account temporarily locked due to repeated failed logins; try again later")
	}
	// TOCTOU re-check only; the clear happens after the session actually exists
	// (#2894). SSO never FEEDS this counter (an IdP-rejected assertion never
	// reaches here), so a post-mint fault simply leaves it untouched rather than
	// at 0 — there is no wrong-credential branch here for it to differ from.
	if err := c.recheckLoginLockFailClosed(ctx, user); err != nil {
		return nil, nil, "", err
	}

	// Reconcile whenever the assertion carried the groups attribute, EVEN WITH NO
	// VALUES (#2903 finding 2). An IdP asserting an empty group set is saying the
	// user is in no groups, and must reconcile to zero -- removing every stale
	// membership and managed role. This used to gate on len(info.Groups) > 0,
	// which read "present but empty" as "absent": a user the IdP had removed from
	// every group (admin group included) kept them all and got a session.
	//
	// An ABSENT attribute is a no-op, by decision: it means "this assertion
	// carries no group information" (many IdPs release the groups attribute only
	// when configured to), not "no groups". Treating it as empty would strip
	// every membership on every login from such an IdP. That is acceptable only
	// because Keyorix has no setting that REQUIRES the attribute when group sync
	// is on; if one is added, absence under it must refuse the login instead.
	// Matches the OIDC path's absent-claim no-op (extractTokenStringList's
	// `present`).
	//
	// #2839 item 1, Andrei's condition 1: mintSession runs ONLY if reconciliation
	// fully applied. Both calls used to discard their result (they returned
	// nothing), so a failed REVOCATION — the IdP dropped a user from its admin
	// group, the removal errored or was refused — left the user holding the group
	// or role and still handed them a session, for the session's whole lifetime.
	// Refusing the login is the only outcome that does not do that.
	//
	// The reconciled state is derived solely from info.Groups, which came out of
	// p.SAML.ParseResponse — i.e. the signed, audience- and time-validated
	// assertion. Nothing here reads request parameters or any prior stored group
	// state as a source of desired state (condition 2).
	//
	// Not rolled back on refusal, by design: this is a class-C step set (#2839,
	// docs/atomicity-exempt.tsv). Each reconciliation is idempotent and converges
	// on the next successful login, and a half-applied reconcile only ever leaves
	// the user with FEWER or equal privileges than the assertion grants plus the
	// ones its removal failed to take away — which is precisely why the login must
	// be refused rather than compensated. The refusal's audit event records what
	// had already applied (finishSSOReconcile).
	if info.GroupsPresent || len(info.Groups) > 0 {
		if p.GroupSync {
			if rerr := c.reconcileSSOGroups(ctx, p, user.ID, info.Groups); rerr != nil {
				log.Printf("CompleteSAML: refusing login for user %d: %v", user.ID, rerr)
				return nil, nil, "", ssoReconcileLoginRefusal(SSOMsgGroupReconcileRefused, rerr)
			}
		}
		if len(p.GroupRoleMap) > 0 {
			if rerr := c.reconcileSSORoles(ctx, p, user.ID, info.Groups); rerr != nil {
				log.Printf("CompleteSAML: refusing login for user %d: %v", user.ID, rerr)
				return nil, nil, "", ssoReconcileLoginRefusal(SSOMsgRoleReconcileRefused, rerr)
			}
		}
	}

	if err := c.enforcePasswordExpiryGate(ctx, user); err != nil {
		return nil, nil, "", err
	}
	session, err := c.mintSession(ctx, user.ID, userAgent, ip)
	if err != nil {
		return nil, nil, "", err
	}
	// Lockout clear after mint (#2894); both steps best-effort and panic-safe
	// -- see the identical steps in CompleteSSO.
	besteffort.Run(ctx, "sso.CompleteSAML.clearLoginFailures", func() error { c.clearLoginFailures(ctx, user); return nil })
	besteffort.Run(ctx, "sso.CompleteSAML.RecordLogin", func() error { return c.RecordLogin(ctx, user.ID) })
	c.writeAuditEvent(ctx, EventSSOLogin, actorPtr(user.ID), nil,
		fmt.Sprintf("SAML login via %s (subject=%s)", name, info.Subject))
	return session, user, st.ReturnTo, nil
}

// ssoExternalIDScheme namespaces an SSO-provider-managed identity inside the shared
// external_id column. A scoped value "sso:<provider>:<subject>" binds the account to
// exactly ONE SSO provider, so a second IdP that asserts the same subject — or the same
// email — cannot claim it (see resolveSSOUser). Bare external_ids (SCIM externalId,
// RFC 7644) and empty values (local accounts) are deliberately left unscoped so they
// stay interoperable; only JIT-provisioned SSO accounts carry the scheme.
const ssoExternalIDScheme = "sso:"

// ssoExternalID builds the provider-scoped external_id for an SSO identity. Provider
// names are configuration keys (no ':'), so the scheme + provider form a stable prefix.
func ssoExternalID(provider, subject string) string {
	return ssoExternalIDScheme + provider + ":" + subject
}

// ssoBoundToOtherProvider reports whether externalID is an SSO-scoped identity owned by
// a provider OTHER than `provider`. An account in that state must never be linked to
// `provider`'s assertion — doing so is exactly the cross-provider account takeover this
// guards against. Bare/empty external_ids are not provider-bound and return false.
func ssoBoundToOtherProvider(externalID, provider string) bool {
	return strings.HasPrefix(externalID, ssoExternalIDScheme) &&
		!strings.HasPrefix(externalID, ssoExternalID(provider, ""))
}

// resolveSSOUser maps a verified IdP identity from `provider` to a Keyorix user: this
// provider's own scoped external_id first, then email. Returns (nil, nil) when neither
// matches — the caller decides whether to refuse the login or JIT-provision the account.
//
// The email fallback carries two guards that close a cross-provider account-takeover
// vector when more than one SSO provider is trusted (e.g. a corporate IdP plus a
// weaker/partner IdP). (1) The email must be EXPLICITLY verified: an IdP that lets a
// user self-assert an address — or merely omits email_verified — cannot use it to
// claim an EXISTING account (a brand-new JIT account is still provisionable, since
// there is nothing to take over). (2) The matched account must not already be bound to
// a scoped identity owned by a DIFFERENT provider (see ssoBoundToOtherProvider);
// otherwise a second IdP asserting the same email could take over an account owned by
// the first. A never-federated (native or SCIM-by-email) account is claimed for THIS
// provider on first link (scoped even when the assertion carries no subject — e.g. a
// SAML IdP that omits the Subject and relies solely on TrustAssertedEmail; see
// CompleteSAML), so a later provider can't re-link it by asserting the same address.
// The subject-less claim only marks provider ownership; it doesn't enable the
// fast-path externalID lookup above, so a later assertion from the SAME provider that
// does carry a subject still falls through to this email path and re-resolves here —
// that's fine, since ssoBoundToOtherProvider still passes for the owning provider.
func (c *KeyorixCore) resolveSSOUser(ctx context.Context, provider, sub, email string, emailVerified bool) (*models.User, error) {
	if sub != "" {
		if u, err := c.storage.GetUserByExternalID(ctx, ssoExternalID(provider, sub)); err == nil {
			return u, nil
		} else if !storage.IsUserNotFound(err) {
			return nil, err
		}
	}
	if email == "" || !emailVerified {
		return nil, nil
	}
	u, err := c.storage.GetUserByEmail(ctx, email)
	if err != nil {
		if storage.IsUserNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	if ssoBoundToOtherProvider(u.ExternalID, provider) {
		return nil, fmt.Errorf("the email %q is already linked to a different SSO provider", email)
	}
	if u.ExternalID == "" {
		// Claim this never-federated account for the verifying provider (scoped by
		// subject when the assertion carries one; ssoExternalID(provider, "") when it
		// doesn't — e.g. a SAML assertion with no Subject) so a later provider can't
		// re-link it by asserting the same email. A subject-less claim still fully
		// closes the cross-provider vector: ssoBoundToOtherProvider only cares which
		// provider owns the scoped id, not whether a subject is present. Best-effort:
		// a failed claim just means we re-link on the next login.
		//
		// #2699: a column-scoped write of external_id alone, onto a row that is
		// still live and still unfederated. It used to be the generic full-row
		// UpdateUser, whose GORM Save upsert-fallback RESURRECTED an account an
		// admin had deleted after the GetUserByEmail above — writing back
		// deleted_at=NULL, is_active=true, account_state=active — and the same
		// window also reverted a concurrent suspension, password change, MFA
		// enable or lockout. The user controls the timing: they fire the first
		// SSO login, and can fire several in parallel.
		// The claimed flag is deliberately discarded: claiming is best-effort
		// (that predates this change — "a failed claim just means we re-link on
		// the next login"), and either way what the caller must act on is the
		// re-read below, not this statement's own verdict. A no-match means
		// another replica federated the account first or the row is gone; the
		// re-read distinguishes those and handles both correctly.
		if _, cerr := c.storage.ClaimUserExternalIDIfUnset(ctx, u.ID, ssoExternalID(provider, sub), c.now()); cerr != nil {
			return nil, cerr
		}
		// Re-read regardless of whether the claim landed, and return the COMMITTED
		// row rather than the snapshot read before it. Fixing only the write would
		// leave the other half of #2699 open: CompleteSSO's login gate
		// (!user.IsActive || AccountLoginBlocked) evaluates whatever this function
		// returns, so handing back the stale struct — which still says active —
		// mints a session for a deleted or suspended account even once the row
		// itself is correctly left alone. A failed re-read means the account is
		// gone or unreadable: fail closed, and in particular do NOT fall through
		// to the caller's auto-provision branch, which would mint a brand-new
		// account for the deleted one's email.
		fresh, gerr := c.storage.GetUser(ctx, u.ID)
		if gerr != nil {
			return nil, fmt.Errorf("the account for this SSO identity is no longer available")
		}
		// The claim is conditional on external_id still being unset. If another
		// provider claimed this account between our read and our write, the
		// re-read shows ITS id: refuse instead of logging this provider's user in
		// to an account bound elsewhere (the cross-provider vector the claim exists
		// to close).
		if fresh.ExternalID != ssoExternalID(provider, sub) {
			return nil, fmt.Errorf("this account is already linked to a different sign-in provider")
		}
		u = fresh
	}
	return u, nil
}

// ensureSSOUser returns the resolved user if one exists; otherwise JIT-provisions one
// via provisionSSOUser when p.AutoProvision is enabled. Extracted from CompleteSSO to
// reduce its cognitive complexity.
func (c *KeyorixCore) ensureSSOUser(ctx context.Context, p *SSOProvider, existing *models.User, sub, email string, emailVerified bool, name string) (*models.User, error) {
	if existing != nil {
		return existing, nil
	}
	if !p.AutoProvision {
		return nil, fmt.Errorf("no Keyorix account matches this SSO identity")
	}
	return c.provisionSSOUser(ctx, p, sub, email, emailVerified, name)
}

// provisionSSOUser JIT-creates a Keyorix account for a verified SSO identity that
// matches no existing user (auto_provision must be enabled — the caller gates this).
// The identity has already passed full id_token verification (signature, issuer,
// audience, expiry, nonce), so the IdP subject is trusted as the externalId. The
// account is created ACTIVE — the IdP has authenticated it and the user signs in via
// SSO — with an unusable local password; it deliberately does NOT start in
// pending_first_login (which would trap an SSO user in a password-change-only
// restricted session they can never clear). The baseline role is the provider's
// default_role (system_viewer when unset); an unknown role grants nothing.
func (c *KeyorixCore) provisionSSOUser(ctx context.Context, p *SSOProvider, sub, email string, emailVerified bool, name string) (*models.User, error) {
	if strings.TrimSpace(email) == "" {
		return nil, fmt.Errorf("the IdP returned no email; cannot auto-provision an account")
	}
	// ADR-022: the domain allowlist is an install-wide boundary on who may hold an
	// account at all, not just an invite-flow check — an SSO login from an
	// unapproved domain (e.g. a misconfigured/multi-tenant IdP) must not silently
	// JIT-provision an account either.
	if !c.domainAllowed(email) {
		return nil, fmt.Errorf("email domain is not on the allowlist")
	}
	// Guard against a race / case where a user materialised between the resolve and here:
	// reuse it rather than create a duplicate. This MUST go through resolveSSOUser (not a
	// raw email lookup), so the same guards apply — an EXISTING account is reused via an
	// email match ONLY when the email is verified, and never when it is bound to a
	// different provider's federated identity. Re-running the SAME gated resolution
	// means the race path cannot bypass either check.
	if existing, ferr := c.resolveSSOUser(ctx, p.Name, sub, email, emailVerified); ferr != nil {
		return nil, ferr
	} else if existing != nil {
		return existing, nil
	}
	username, err := c.deriveSCIMUsername(ctx, email)
	if err != nil {
		return nil, err
	}
	hash, err := randomPasswordHash()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	displayName := strings.TrimSpace(name)
	if displayName == "" {
		displayName = email
	}
	now := c.now()
	// #1642: SSO JIT-provisioned usernames/emails come from the IdP's own
	// claims and bypass buildUserForCreate entirely -- fold here, mirroring
	// ProvisionSCIMUser's identical treatment (scim.go).
	foldedUsername, ferr := identity.NewFoldedName(username)
	if ferr != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), ferr)
	}
	foldedEmail, ferr := identity.NewFoldedName(email)
	if ferr != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), ferr)
	}
	roleName := strings.TrimSpace(p.DefaultRole)
	if roleName == "" {
		roleName = ssoDefaultRole
	}
	// The user row and its baseline role grant run in one transaction — identical
	// bootstrap shape to ProvisionSCIMUser (scim.go) and #2295's first-boot fix: a
	// role-assign failure after a best-effort create used to leave a JIT-provisioned
	// SSO user with zero roles, unable to do anything until an admin noticed.
	var created *models.User
	err = c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
		var cerr error
		created, cerr = tx.CreateUser(ctx, &models.User{
			Username: username, UsernameFolded: foldedUsername.Folded(),
			Email: email, EmailFolded: foldedEmail.Folded(), DisplayName: displayName,
			PasswordHash: hash, IsActive: true, AccountState: AccountActive, ExternalID: ssoExternalID(p.Name, sub),
			PasswordChangedAt: &now, CreatedAt: now, UpdatedAt: now,
		})
		if cerr != nil {
			return cerr
		}
		r, rerr := tx.GetRoleByName(ctx, roleName)
		if rerr != nil {
			return fmt.Errorf("failed to resolve default role %q: %w", roleName, rerr)
		}
		return tx.AssignRole(ctx, created.ID, r.ID, Scope{})
	})
	if err != nil {
		// #117: the FindSCIMUser reuse-check above races with a concurrent JIT-provision
		// (or any other create) for the identical email — both can pass it before either
		// commits. The DB-level partial unique index catches the loser here and CreateUser
		// wraps it in ErrDuplicateEmail; surface a clean error instead of a raw
		// constraint-violation message.
		if errors.Is(err, storage.ErrDuplicateEmail) {
			return nil, fmt.Errorf("a user with this email already exists")
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	role := roleName
	detail, _ := json.Marshal(ssoJITProvisionDetail{Role: role, NonDefaultRole: role != ssoDefaultRole})
	c.writeAuditEventDiff(ctx, EventSSOJITProvision, actorPtr(created.ID), nil, nil, "",
		fmt.Sprintf("SSO JIT-provisioned user %d via %s (externalId=%q, role=%s)", created.ID, p.Name, sub, role),
		string(detail))
	return created, nil
}

// syncSSOGroups reconciles the user's NATIVE group memberships to the groups the IdP
// asserts in the (already-verified) id_token's configured groups claim. The IdP is
// the source of truth: the user is added to native groups whose name matches an
// asserted group and removed from native groups it didn't assert — so revoking a
// group at the IdP deprovisions the corresponding Keyorix access on next login. It
// only ever touches MEMBERSHIPS of groups that already exist natively (provisioned by
// SCIM or an admin); it never creates or deletes groups, and an asserted group with
// no native counterpart is ignored.
//
// Crucially, if the groups claim is ABSENT from the token (vs present-but-empty), the
// sync is a no-op: many IdPs only emit groups in the userinfo endpoint or under a
// specific scope, and treating "absent" as "assert no groups" would strip every
// membership on login. A present-but-EMPTY claim is the IdP asserting no groups and
// reconciles to zero.
//
// Returns reconcileSSOGroups' error (wrapping ErrSSOReconcileIncomplete), and
// CompleteSSO refuses the login on it (#2907). It used to swallow every error so
// the login always proceeded -- see CompleteSSO for why that was the bug.
func (c *KeyorixCore) syncSSOGroups(ctx context.Context, p *SSOProvider, userID uint, rawID string) error {
	claim := strings.TrimSpace(p.GroupsClaim)
	if claim == "" {
		claim = ssoDefaultGroupClaim
	}
	asserted, present := extractTokenStringList(rawID, claim)
	if !present {
		return nil // IdP did not assert groups in the id_token — leave memberships untouched.
	}
	return c.reconcileSSOGroups(ctx, p, userID, asserted)
}

// ErrSSOReconcileIncomplete marks a group/role reconciliation that did not fully
// apply the IdP's assertion. CompleteSAML and CompleteSSO refuse the login on it (#2839 item 1,
// Andrei's condition 1): the dangerous direction is a REMOVAL that did not happen,
// which leaves the user holding a group or role the IdP has revoked, and minting a
// session then hands them that stale privilege for the whole session lifetime.
//
// Wrapped, not returned bare, so the underlying cause stays inspectable; the
// caller only needs errors.Is to decide.
var ErrSSOReconcileIncomplete = errors.New("SSO group/role reconciliation did not fully apply the asserted state")

// Client-safe texts of the login refusals a failed reconcile produces. They are
// the WHOLE of ssoLoginRefusedError.Error(), with no wrapped detail appended,
// which is what lets server/http/handlers' isSafeSSOError (a substring match)
// reflect them to the browser without also reflecting a storage error.
const (
	SSOMsgGroupReconcileRefused = "could not apply the identity provider's group assertion; login refused"
	SSOMsgRoleReconcileRefused  = "could not apply the identity provider's role mapping; login refused"
	// SSOMsgLastAdminRemovalRefused tells the person at the browser, who has just
	// authenticated at the IdP as this account, why the login failed and that it
	// needs an operator. It reveals that the account is the last administrator,
	// which its own owner may know.
	SSOMsgLastAdminRemovalRefused = "the identity provider no longer grants this account administrator access, " +
		"but it is the install's last administrator, so the access cannot be removed; login refused -- " +
		"ask an operator to restore the group at the identity provider or run keyorix-server admin recover-admin"
)

// ssoLoginRefusedError is a reconcile refusal as CompleteSAML/CompleteSSO return
// it: Error() is exactly one of the SSOMsg* texts above (safe to show), and
// Unwrap() keeps the full cause chain -- ErrSSOReconcileIncomplete and, for a
// last-admin refusal, storage.ErrWouldStrandLastAdmin -- for errors.Is.
type ssoLoginRefusedError struct {
	msg   string
	cause error
}

func (e *ssoLoginRefusedError) Error() string { return e.msg }
func (e *ssoLoginRefusedError) Unwrap() error { return e.cause }

// ssoReconcileLoginRefusal builds the error a login refused over a failed
// reconcile returns: msg, or SSOMsgLastAdminRemovalRefused when the cause is the
// install's last-admin guard, so the person at the browser learns that an
// operator is needed rather than retrying.
func ssoReconcileLoginRefusal(msg string, cause error) error {
	if errors.Is(cause, storage.ErrWouldStrandLastAdmin) {
		msg = SSOMsgLastAdminRemovalRefused
	}
	return &ssoLoginRefusedError{msg: msg, cause: cause}
}

// ssoReconcileReport accumulates what one reconcile pass applied and what it
// failed to apply. finishSSOReconcile turns it into exactly one audit event --
// a success event when everything applied, a refusal event naming every failed
// step AND the already-applied counts when anything did not (#2903 finding 1:
// the old code wrote the event only when something changed, so a lone failed
// removal left no record, and wrote a partial change as a plain success).
type ssoReconcileReport struct {
	added, removed, blocked int
	// failures names every step that did not apply, e.g.
	// `remove group 42 "idp-admins": <cause>`.
	failures []string
	// lastAdmin: one of the failed steps was a removal the install's last-admin
	// guard refused (storage.ErrWouldStrandLastAdmin).
	lastAdmin bool
	// The error to return, by precedence: a last-admin refusal (so the caller can
	// tell the user why), then any other removal (the privilege-RETAINING
	// direction), then anything else.
	lastAdminErr, removalErr, otherErr error
}

func (r *ssoReconcileReport) fail(step string, removal bool, cause error) {
	r.failures = append(r.failures, step+": "+cause.Error())
	err := fmt.Errorf("%w: %s: %w", ErrSSOReconcileIncomplete, step, cause)
	switch {
	case errors.Is(cause, storage.ErrWouldStrandLastAdmin):
		r.lastAdmin = true
		if r.lastAdminErr == nil {
			r.lastAdminErr = err
		}
	case removal:
		if r.removalErr == nil {
			r.removalErr = err
		}
	default:
		if r.otherErr == nil {
			r.otherErr = err
		}
	}
}

func (r *ssoReconcileReport) err() error {
	switch {
	case r.lastAdminErr != nil:
		return r.lastAdminErr
	case r.removalErr != nil:
		return r.removalErr
	default:
		return r.otherErr
	}
}

// ssoLastAdminWayBack is appended to the last-admin refusal's audit event and log
// line: the operator reading it needs the way back, not just the fact.
const ssoLastAdminWayBack = "the identity provider revoked admin access from the install's last administrator " +
	"and the last-admin guard refused the removal, so this user's SSO login will keep being refused " +
	"(the IdP's revocation wins). Two ways back: re-add the user to the admin group at the identity provider, " +
	"or run `keyorix-server admin recover-admin <user>` with the recovery key on the server host " +
	"(then create a second administrator, so the IdP's revocation can apply)"

// finishSSOReconcile writes the one audit event a reconcile pass produces and
// returns its error. kind names the pass ("group sync", "role mapping"),
// counts/blockedNote describe what applied.
//
// A refusal is written as a FAILED event (Success=false) of type
// EventSSOReconcileRefused, or EventSSOReconcileLastAdminRefused when the last-
// admin guard was one of the reasons, and the applied counts are stated as
// applied-and-not-rolled-back, because class C does not roll them back.
func (c *KeyorixCore) finishSSOReconcile(ctx context.Context, p *SSOProvider, userID uint, kind, okEvent, counts, blockedNote string, r *ssoReconcileReport) error {
	err := r.err()
	if err == nil {
		if r.added > 0 || r.removed > 0 || r.blocked > 0 {
			c.writeAuditEvent(ctx, okEvent, actorPtr(userID), nil,
				fmt.Sprintf("SSO %s via %s: user %d (%s)%s", kind, p.Name, userID, counts, blockedNote))
		}
		return nil
	}
	event := EventSSOReconcileRefused
	msg := fmt.Sprintf("SSO %s via %s refused the login for user %d. Failed: %s. Already applied before the refusal (not rolled back): %s%s",
		kind, p.Name, userID, strings.Join(r.failures, "; "), counts, blockedNote)
	if r.lastAdmin {
		event = EventSSOReconcileLastAdminRefused
		msg += ". " + ssoLastAdminWayBack
		log.Printf("SECURITY: %s", msg)
	}
	c.writeAuditEventFailed(ctx, event, actorPtr(userID), nil, "", msg)
	return err
}

// reconcileSSOGroups reconciles native group memberships to match the asserted group
// names — shared by the OIDC (id_token claim) and SAML (assertion attribute) paths.
//
// Returns ErrSSOReconcileIncomplete (wrapped) when any step did not apply. It used
// to return nothing and swallow every error, which is the bug #2839 item 1 names:
// a user removed from an IdP admin group whose removal then failed kept the group
// AND got a session. Whether the caller refuses the login on that is the caller's
// decision; both login paths refuse (CompleteSAML, and CompleteSSO via
// syncSSOGroups since #2907).
//
// Every step is attempted even after one fails, and the audit event written at
// the end (finishSSOReconcile) records both what failed and what applied.
func (c *KeyorixCore) reconcileSSOGroups(ctx context.Context, p *SSOProvider, userID uint, asserted []string) error {
	r := &ssoReconcileReport{}
	c.applySSOGroupReconcile(ctx, userID, asserted, r)
	blockedNote := ""
	if r.blocked > 0 {
		blockedNote = fmt.Sprintf("; %d admin-conferring group(s) refused (IdP assertion cannot grant admin)", r.blocked)
	}
	return c.finishSSOReconcile(ctx, p, userID, "group sync", EventSSOGroupsSynced,
		fmt.Sprintf("+%d/-%d native group memberships", r.added, r.removed), blockedNote, r)
}

func (c *KeyorixCore) applySSOGroupReconcile(ctx context.Context, userID uint, asserted []string, r *ssoReconcileReport) {
	assertedSet := make(map[string]bool, len(asserted))
	for _, g := range asserted {
		if g = strings.TrimSpace(g); g != "" {
			assertedSet[g] = true
		}
	}

	nativeGroups, err := c.storage.ListGroups(ctx)
	if err != nil {
		// Nothing was changed, but nothing was VERIFIED either: without the native
		// group list the desired set is unknown, so a revoked membership may still
		// be in place. Unknown is not the same as reconciled.
		r.fail("list native groups", false, err)
		return
	}
	// Desired native group IDs = native groups whose name the IdP asserted.
	desired := make(map[uint]bool)
	names := make(map[uint]string, len(nativeGroups))
	for _, g := range nativeGroups {
		names[g.ID] = g.Name
		if assertedSet[g.Name] {
			desired[g.ID] = true
		}
	}
	current, err := c.storage.GetUserGroups(ctx, userID)
	if err != nil {
		r.fail("read current group memberships", false, err)
		return
	}
	currentSet := make(map[uint]bool, len(current))
	for _, g := range current {
		currentSet[g.ID] = true
		if _, ok := names[g.ID]; !ok {
			names[g.ID] = g.Name
		}
	}

	c.reconcileSSOGroupAdditions(ctx, userID, desired, currentSet, names, r)
	c.reconcileSSOGroupRemovals(ctx, userID, desired, currentSet, names, r)
}

// reconcileSSOGroupAdditions records every ADD failure in r.
// A blocked escalation is NOT an error: refusing to add an admin-conferring group
// is the fail-closed direction and the privilege is not granted, so the login can
// proceed -- the refusal is recorded in the aggregate audit event instead.
//
// A guard that could not DECIDE is an error, though (#2910 fault sweep). When
// the escalation lookup fails, the group is still not added, but the failure is
// recorded as a failed step and the login is refused. It used to be counted as
// a blocked escalation: the session was minted short of a group the IdP
// asserted, and the audit claimed a refusal nobody had decided.
func (c *KeyorixCore) reconcileSSOGroupAdditions(ctx context.Context, userID uint, desired, currentSet map[uint]bool, names map[uint]string, r *ssoReconcileReport) {
	for id := range desired {
		if currentSet[id] {
			continue
		}
		// Refuse to ESCALATE into an admin-conferring group via an IdP group assertion —
		// the same guard SCIM applies (scimGroupConfersAdmin; the predicate is not
		// SCIM-specific). scimGroupConfersAdmin fails CLOSED on a lookup error.
		confers, gerr := c.idpGroupConfersAdminVerdict(ctx, id)
		if gerr != nil {
			r.fail(fmt.Sprintf("check whether group %d %q confers admin", id, names[id]), false, gerr)
			continue
		}
		if confers {
			r.blocked++
			continue
		}
		if aerr := c.storage.AddUserToGroup(ctx, userID, id, 0); aerr != nil {
			r.fail(fmt.Sprintf("add group %d %q", id, names[id]), false, aerr)
			continue
		}
		r.added++
	}
}

// FIX-2: this used to call c.storage.RemoveUserFromGroup directly, bypassing
// the core-layer RemoveUserFromGroup's last-admin guards entirely
// (guardLastGlobalAdminMembership, guardLastProjectAdminGroupMembership) — an
// IdP that stopped asserting a user's admin-conferring group membership (a
// misconfigured claim, a stale IdP-side group, or a malicious IdP) could
// silently strand the install or a project with no admin on the user's very
// next login, with no refusal and no error surfaced anywhere. Routed through
// RemoveUserFromGroupGlobal — the guarded wrapper this file's own doc comment
// already names as the one JIT/SSO de-provisioning callers should use — so
// this is exactly as safe as any other de-provisioning path.
// reconcileSSOGroupRemovals records every REMOVAL failure in r.
//
// Every removal failure is reported, including a refusal by
// RemoveUserFromGroupGlobal's last-admin guards. That is deliberate and is the
// case #2839 item 1 describes in so many words: the IdP has revoked an
// admin-conferring group and the removal did not happen, so minting a session
// hands the user the stale admin privilege for its whole lifetime. Refusing the
// login is the only outcome that does not do that.
//
// The trade-off is real, and Andrei decided it on 2026-10-10 (#2903): if the
// user is the install's LAST administrator and holds that admin role through
// this group, the guard keeps refusing and their SSO login keeps failing until
// either the IdP re-asserts the group or a second admin exists -- the IdP's
// revocation wins. That is recoverable out of band (`keyorix-server admin
// recover-admin`, proven for an SSO-only admin by
// TestPerformRecoverAdmin_SSOOnlyLastAdminWithNoPassword), whereas a session
// minted with revoked admin is not recoverable at all once issued. The refusal
// is written as EventSSOReconcileLastAdminRefused, naming both ways back.
func (c *KeyorixCore) reconcileSSOGroupRemovals(ctx context.Context, userID uint, desired, currentSet map[uint]bool, names map[uint]string, r *ssoReconcileReport) {
	// De-escalating removals are unconditional (dropping a group only reduces
	// privilege) EXCEPT when doing so would strand the install or a project
	// with no remaining admin — RemoveUserFromGroupGlobal refuses those. The
	// acting principal is the logging-in user themself, matching this file's
	// audit-logging convention (actorPtr(userID), reconcileSSOGroups above).
	for id := range currentSet {
		if desired[id] {
			continue
		}
		if rerr := c.RemoveUserFromGroupGlobal(ctx, userID, userID, id); rerr != nil {
			r.fail(fmt.Sprintf("remove group %d %q", id, names[id]), true, rerr)
			continue
		}
		r.removed++
	}
}

// syncSSORoles reconciles the user's grants of the MAPPED (system) roles to match the
// roles their asserted IdP groups map to via GroupRoleMap — so the IdP drives those
// role assignments. It is authoritative ONLY over the set of roles named in the map
// (the "managed" roles): a managed role is granted when an asserted group maps to it
// and removed when none do; a role NOT in the map is never touched, so manual grants
// survive. Like group sync, an ABSENT groups claim is a no-op (so an IdP that omits
// groups can't strip a user's roles). Its error refuses the login in CompleteSSO
// (#2907), exactly as syncSSOGroups'.
// Roles are bound at global scope (system roles); an unknown mapped role is skipped.
func (c *KeyorixCore) syncSSORoles(ctx context.Context, p *SSOProvider, userID uint, rawID string) error {
	claim := strings.TrimSpace(p.GroupsClaim)
	if claim == "" {
		claim = ssoDefaultGroupClaim
	}
	asserted, present := extractTokenStringList(rawID, claim)
	if !present {
		return nil // IdP did not assert groups in the id_token — leave roles untouched.
	}
	return c.reconcileSSORoles(ctx, p, userID, asserted)
}

// reconcileSSORoles reconciles the user's grants of the MAPPED roles to match the roles
// their asserted groups map to — shared by the OIDC and SAML paths. Authoritative only
// over roles named in GroupRoleMap (manual grants survive).
// Returns ErrSSOReconcileIncomplete (wrapped) when any grant or revocation did
// not apply -- see reconcileSSOGroups' doc for why the caller may want to refuse
// the login on it.
func (c *KeyorixCore) reconcileSSORoles(ctx context.Context, p *SSOProvider, userID uint, asserted []string) error {
	rep := &ssoReconcileReport{}
	c.applySSORoleReconcile(ctx, p, userID, asserted, rep)
	blockedNote := ""
	if rep.blocked > 0 {
		blockedNote = fmt.Sprintf("; %d admin-tier role grant(s) refused (IdP group mapping cannot grant admin)", rep.blocked)
	}
	return c.finishSSOReconcile(ctx, p, userID, "role mapping", EventSSORolesSynced,
		fmt.Sprintf("+%d/-%d mapped role grants", rep.added, rep.removed), blockedNote, rep)
}

func (c *KeyorixCore) applySSORoleReconcile(ctx context.Context, p *SSOProvider, userID uint, asserted []string, rep *ssoReconcileReport) {
	assertedSet := make(map[string]bool, len(asserted))
	for _, g := range asserted {
		if g = strings.TrimSpace(g); g != "" {
			assertedSet[g] = true
		}
	}

	// desiredRoles = role names an asserted group maps to; managedRoles = every role
	// name the map can grant (the authoritative scope).
	desiredRoles, managedRoles := buildSSORoleMaps(p, assertedSet)

	// The user's current global-scope role names.
	current, err := c.storage.GetUserRoles(ctx, userID)
	if err != nil {
		// Same reasoning as reconcileSSOGroups' read failures: without the
		// current set, a role the IdP has revoked may still be held.
		rep.fail("read current role grants", false, err)
		return
	}
	currentSet := make(map[string]bool, len(current))
	for _, r := range current {
		currentSet[r.Name] = true
	}

	// Route through the audited RBAC choke point (assignUserRoleSystemGrant/
	// RemoveUserRole) so each individual role change lands in the RBAC audit trail
	// with a structured RoleID, not just the coarse aggregate-count event below
	// (#297). The acting principal is the logging-in user themself — the same
	// attribution the aggregate auth.sso_roles_synced event below already used —
	// since the grant is driven by their own IdP-asserted groups against the
	// admin-configured map. The grant deliberately uses assignUserRoleSystemGrant,
	// not AssignUserRole: the #93/#107/#141 grant-ceiling check would require the
	// logging-in user to already hold every permission of the role they're being
	// auto-provisioned — impossible for their FIRST SSO-driven grant, and beside
	// the point, since authorization here is rooted in the admin-configured
	// GroupRoleMap and the verified IdP assertion, not in the user's own
	// roles.assign-derived authority.
	for role := range managedRoles {
		r, rerr := c.storage.GetRoleByName(ctx, role)
		if rerr != nil {
			// A role NAME that does not exist is a configuration fact about
			// GroupRoleMap, not a failure: skip it, exactly as before. Any OTHER
			// error means the lookup itself failed, so whether this managed role
			// should be granted or revoked is UNKNOWN -- and "unknown" on a
			// revocation is the dangerous direction. Distinguished by sentinel
			// (storage.ErrRoleNotFound, which GetRoleByName now wraps) rather than
			// by matching a translatable message.
			if storage.IsRoleNotFound(rerr) {
				continue
			}
			rep.fail(fmt.Sprintf("resolve managed role %q", role), currentSet[role] && !desiredRoles[role], rerr)
			continue
		}
		c.applySSOManagedRole(ctx, userID, r, role, desiredRoles, currentSet, rep)
	}
}

func buildSSORoleMaps(p *SSOProvider, assertedSet map[string]bool) (desiredRoles, managedRoles map[string]bool) {
	desiredRoles = make(map[string]bool)
	managedRoles = make(map[string]bool)
	for group, role := range p.GroupRoleMap {
		role = strings.TrimSpace(role)
		if role == "" {
			continue
		}
		managedRoles[role] = true
		if assertedSet[group] {
			desiredRoles[role] = true
		}
	}
	return desiredRoles, managedRoles
}

// applySSOManagedRole records in rep a grant or revocation that did not apply.
// A blocked escalation is not an error -- see reconcileSSOGroupAdditions for the
// same reasoning (the privilege is not granted, so the fail-closed direction).
func (c *KeyorixCore) applySSOManagedRole(ctx context.Context, userID uint, r *models.Role, role string, desired, current map[string]bool, rep *ssoReconcileReport) {
	switch {
	case desired[role] && !current[role]:
		// Refuse to auto-grant an escalation-conferring role from an IdP group mapping
		// (#96) — GroupRoleMap is configured once by an admin, but IdP group membership is
		// frequently self-service, so a mapping intended for a routine role must not double
		// as a path to admin (or to the role-granting primitive) for anyone who can join the
		// group. The predicate blocks the canonical admin roles, any admin-bypass role, AND
		// any role carrying roles.assign (a self-propagating privilege pump); it deliberately
		// permits ordinary privileged roles, which are the admin's legitimate intent. This is
		// the SAME backstop the SCIM group-membership path uses (scimGroupConfersAdmin) — the
		// two were inconsistent before (name vs bypass-flag) and both missed the roles.assign
		// case. See idpAutoGrantOfRoleIsEscalation (authz.go).
		// A lookup failure in the guard is a failed step, not a block -- see
		// reconcileSSOGroupAdditions (#2910).
		escalation, eerr := c.idpAutoGrantEscalationVerdict(ctx, r.ID, role)
		if eerr != nil {
			rep.fail(fmt.Sprintf("check whether role %q is an admin-tier grant", role), false, eerr)
			return
		}
		if escalation {
			rep.blocked++
			return
		}
		if err := c.assignUserRoleSystemGrant(ctx, userID, userID, r.ID, Scope{}); err != nil {
			rep.fail(fmt.Sprintf("grant role %q", role), false, err)
			return
		}
		rep.added++
	case !desired[role] && current[role]:
		// The privilege-RETAINING direction: the IdP no longer maps this user to
		// this role, so failing here leaves them holding it.
		// A last-admin-guard refusal lands here too (RemoveGlobalAdminRoleGuarded's
		// storage.ErrWouldStrandLastAdmin) and is reported as such -- see
		// reconcileSSOGroupRemovals for why the login stays refused.
		if err := c.RemoveUserRole(ctx, userID, userID, r.ID, Scope{}); err != nil {
			rep.fail(fmt.Sprintf("revoke role %q", role), true, err)
			return
		}
		rep.removed++
	}
}

// extractTokenStringList pulls a string-list claim from an ALREADY-VERIFIED id_token
// (verifyIDToken ran on the same raw token immediately before). The claim name is
// configurable, so it can't be a static struct tag; the verified payload is decoded
// into a map and the claim coerced from []string, []any (of strings), or a single
// string. Returns (values, present) — present distinguishes an absent claim from an
// empty list.
func extractTokenStringList(raw, claim string) ([]string, bool) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, false
	}
	raw2, ok := claims[claim]
	if !ok {
		return nil, false
	}
	// Try []string, then []any (coerce string elements), then a single string.
	var list []string
	if err := json.Unmarshal(raw2, &list); err == nil {
		return list, true
	}
	var anyList []any
	if err := json.Unmarshal(raw2, &anyList); err == nil {
		out := make([]string, 0, len(anyList))
		for _, v := range anyList {
			if s, isStr := v.(string); isStr {
				out = append(out, s)
			}
		}
		return out, true
	}
	var single string
	if err := json.Unmarshal(raw2, &single); err == nil {
		return []string{single}, true
	}
	return nil, true // claim present but an unrecognised shape — treat as empty assertion
}

// ssoBool unmarshals a JSON boolean OR the strings "true"/"false" — some IdPs send
// email_verified as a string rather than a bool, and a strict bool field would fail
// the whole token parse. A pointer to it distinguishes "absent" (nil) from "false".
type ssoBool bool

func (b *ssoBool) UnmarshalJSON(data []byte) error {
	*b = ssoBool(strings.Trim(string(data), `"`) == "true")
	return nil
}

// verifyIDToken validates the id_token's signature (asymmetric only), issuer,
// audience (= the provider's client_id), azp (when the token names more than one
// audience), expiry, and the nonce, returning the subject, email, (best-effort)
// name, and whether the email was EXPLICITLY verified. The email is dropped only
// when the IdP explicitly marks it unverified (email_verified: false). An absent
// email_verified claim is treated as trusted for JIT-provisioning — it is OPTIONAL
// in OIDC and common enterprise IdPs (e.g. Entra ID) omit it — but emailVerified is
// reported true only when the claim is present and true, so resolveSSOUser can
// refuse to MATCH AN EXISTING account on a merely-asserted email.
func (c *KeyorixCore) verifyIDToken(ctx context.Context, p *SSOProvider, expectedNonce, raw string) (sub, email, name string, emailVerified bool, err error) { // NOSONAR -- cognitive complexity 16, suppress go:S3776
	var claims struct {
		jwt.RegisteredClaims
		Email         string   `json:"email"`
		EmailVerified *ssoBool `json:"email_verified"`
		Name          string   `json:"name"`
		Nonce         string   `json:"nonce"`
		Azp           string   `json:"azp,omitempty"`
	}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}),
		jwt.WithLeeway(ssoClockSkew),
		jwt.WithExpirationRequired(),
		// WithIssuedAt rejects an iat more than ssoClockSkew into the future
		// (mirrors OIDCVerifier.Verify in oidc.go). It does NOT make iat
		// required and does NOT bound how far in the past iat may be — this
		// path still has no max-age ceiling at all, deliberately: the
		// single-use nonce (below) and the fact that this id_token is only
		// ever obtained via the server-side token-endpoint exchange (never
		// the front channel — see CompleteSSO in this file) already close
		// the long-lived-bearer-token replay surface a max-age check would
		// otherwise guard against (docs/findings/
		// 2026-09-23-FINDING-oidc-future-iat-and-crit.md).
		jwt.WithIssuedAt(),
		// Without this, golang-jwt reads the real wall clock directly for
		// exp/nbf/iat-future, independent of and unsynchronized with every
		// other auth-adjacent expiry check on KeyorixCore (session/PAT/
		// machine-token, all via authEffectiveNow) — reusing that same
		// watermarked clock here closes that gap and makes id_token
		// verification's clock testable/injectable like the rest (#1983).
		jwt.WithTimeFunc(c.authEffectiveNow),
	)
	keyfn := func(t *jwt.Token) (interface{}, error) {
		iss, ierr := t.Claims.GetIssuer()
		if ierr != nil || iss != p.Issuer {
			return nil, fmt.Errorf("issuer mismatch")
		}
		kid, _ := t.Header["kid"].(string)
		return c.ssoJWKS.Key(ctx, p.Issuer, kid)
	}
	token, err := parser.ParseWithClaims(raw, &claims, keyfn)
	if err != nil {
		return "", "", "", false, fmt.Errorf("id_token verification failed: %w", err)
	}
	if !token.Valid || claims.Issuer != p.Issuer {
		return "", "", "", false, fmt.Errorf("id_token invalid")
	}
	// RFC 7515 §4.1.11: a recipient MUST reject a JWS whose "crit" header
	// names an extension it doesn't understand. This verifier understands
	// none, so ANY crit header — regardless of what it names — is rejected.
	if _, hasCrit := token.Header["crit"]; hasCrit {
		return "", "", "", false, fmt.Errorf("id_token has an unrecognized crit header")
	}
	audOK := false
	for _, a := range claims.Audience {
		if a == p.ClientID {
			audOK = true
			break
		}
	}
	if !audOK {
		return "", "", "", false, fmt.Errorf("id_token audience does not match the client id")
	}
	// A token naming MORE THAN ONE audience is, per OIDC, ambiguous about which
	// party it was actually issued to — any one of the audiences matching our
	// client_id isn't enough, since a multi-tenant IdP could mint a token shared
	// across several relying parties and an attacker holding a copy issued to a
	// DIFFERENT (also-trusted) party could replay it here. azp (authorized party)
	// disambiguates the true recipient and must equal this provider's client_id.
	// Mirrors OIDCVerifier.Verify in oidc.go (the machine-federation path).
	if len(claims.Audience) > 1 {
		if claims.Azp == "" {
			return "", "", "", false, fmt.Errorf("id_token has multiple audiences but no azp claim")
		}
		if claims.Azp != p.ClientID {
			return "", "", "", false, fmt.Errorf("id_token azp does not match the client id")
		}
	}
	if expectedNonce == "" || claims.Nonce != expectedNonce {
		return "", "", "", false, fmt.Errorf("id_token nonce mismatch")
	}
	if strings.TrimSpace(claims.Subject) == "" {
		return "", "", "", false, fmt.Errorf("id_token has no subject")
	}
	email = claims.Email
	if email != "" && claims.EmailVerified != nil && !bool(*claims.EmailVerified) {
		// The IdP explicitly says this address is unverified — don't trust it for
		// identity. The subject (externalId) match still works; only the email
		// fallback / JIT-provisioning lose this untrusted address.
		email = ""
	}
	emailVerified = claims.EmailVerified != nil && bool(*claims.EmailVerified)
	return claims.Subject, email, claims.Name, emailVerified, nil
}

func randToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}
	return hex.EncodeToString(b), nil
}
