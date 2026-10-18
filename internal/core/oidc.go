// oidc.go — machine-identity federation via OIDC / Kubernetes JWTs (ADR-031).
//
// An external workload (e.g. a Kubernetes pod with a projected service-account
// token) presents a JWT instead of a Keyorix-issued secret. The verifier checks
// the signature against the issuer's JWKS and validates iss/aud/exp; the core
// then maps the (issuer, subject) to a machine identity and resolves its roles —
// reusing the ADR-030 machine principal, RBAC, and audit path unchanged.
package core

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// oidcClockSkew is the leeway allowed on exp/nbf to tolerate small clock drift.
const oidcClockSkew = 60 * time.Second

// defaultOIDCMaxTokenAge bounds how old (now - iat) a federated token may be when
// an issuer doesn't configure its own ceiling. exp alone doesn't bound this: a
// token minted with a far-future exp (misconfigured or malicious issuer/CI
// pipeline) would otherwise verify — and be replayable — for as long as that exp,
// regardless of how long ago it was actually issued.
const defaultOIDCMaxTokenAge = 24 * time.Hour

// oidcClaims extends the JWT registered claims with azp (authorized party) — an
// OIDC-specific claim not in the RFC 7519 registered set, needed to disambiguate
// a multi-audience token's intended recipient.
type oidcClaims struct {
	jwt.RegisteredClaims
	Azp string `json:"azp,omitempty"`
}

// JWKSResolver returns the public signing key for an (issuer, kid). The
// production implementation fetches and caches the issuer's JWKS; tests inject a
// static key.
type JWKSResolver interface {
	Key(ctx context.Context, issuer, kid string) (any, error)
}

// OIDCTrustedIssuer is one operator-configured issuer the verifier will accept.
// MaxTokenAge bounds (now - iat); zero uses defaultOIDCMaxTokenAge.
type OIDCTrustedIssuer struct {
	Issuer      string
	Audiences   []string
	MaxTokenAge time.Duration
}

type oidcIssuerTrust struct {
	audiences map[string]struct{}
	maxAge    time.Duration
}

// OIDCVerifier verifies federated JWTs against an operator-curated set of
// trusted issuers. It is pure token logic — no storage — so it is unit-testable
// with a generated key and no network.
type OIDCVerifier struct {
	issuers map[string]oidcIssuerTrust
	jwks    JWKSResolver
	leeway  time.Duration
	now     func() time.Time
	// clockWatermarkMu/clockWatermark back effectiveNow (#1653, follow-up to
	// #1632): an in-memory monotonic high-water mark of the latest now()
	// reading this verifier has legitimately observed. Verify's age check
	// (v.now().Sub(claims.IssuedAt.Time)) is NOT monotonic-safe — claims.IssuedAt
	// is parsed from the JWT (round-tripped, monotonic reading stripped), so a
	// backward-stepped host clock makes a stale token's computed age look
	// smaller, extending acceptance of it past its configured max-age. This
	// CLAMPS rather than refuses — Verify runs on every OIDC-authenticated
	// request (server/middleware/auth.go), a pervasive read path, not a single
	// discrete action — see rbacEffectiveNow's doc comment
	// (internal/storage/store/local_rbac.go) for why that shape calls for a
	// clamp, not a refuse.
	clockWatermarkMu sync.Mutex
	clockWatermark   time.Time
}

// effectiveNow returns v.now() clamped so it never regresses relative to a
// reading this verifier has already legitimately observed. See
// clockWatermark's doc comment above for what this defends against.
//
// .UTC() strips any monotonic clock reading v.now() carries — see
// KeyorixCore.authEffectiveNow's doc comment (auth.go) for why an unstripped
// comparison here would never actually detect a backward wall-clock step.
func (v *OIDCVerifier) effectiveNow() time.Time {
	v.clockWatermarkMu.Lock()
	defer v.clockWatermarkMu.Unlock()
	now := v.now().UTC()
	if now.Before(v.clockWatermark) {
		return v.clockWatermark
	}
	v.clockWatermark = now
	return now
}

// setClock overrides the clock Verify uses for every check (both golang-jwt's
// own exp/nbf/iat-future evaluation, wired via jwt.WithTimeFunc below, and the
// custom max-age check via effectiveNow) and resets the monotonic watermark to
// zero. The reset matters: without it, a caller that moves the clock backward
// after this verifier has already observed a later reading would find that
// reading still clamps effectiveNow, silently discarding the override. #1983.
func (v *OIDCVerifier) setClock(now func() time.Time) {
	v.clockWatermarkMu.Lock()
	defer v.clockWatermarkMu.Unlock()
	v.now = now
	v.clockWatermark = time.Time{}
}

// NewOIDCVerifier builds a verifier over the trusted issuers. An issuer with no
// configured audiences is rejected at build time — audience binding is required
// (fail closed), since an unaudienced token is replayable across services.
func NewOIDCVerifier(issuers []OIDCTrustedIssuer, jwks JWKSResolver) (*OIDCVerifier, error) {
	m := make(map[string]oidcIssuerTrust, len(issuers))
	for _, iss := range issuers {
		if strings.TrimSpace(iss.Issuer) == "" {
			return nil, fmt.Errorf("oidc: an issuer entry has an empty issuer URL")
		}
		if len(iss.Audiences) == 0 {
			return nil, fmt.Errorf("oidc: issuer %q has no audiences configured (required)", iss.Issuer)
		}
		auds := make(map[string]struct{}, len(iss.Audiences))
		for _, a := range iss.Audiences {
			if a != "" {
				auds[a] = struct{}{}
			}
		}
		if len(auds) == 0 {
			return nil, fmt.Errorf("oidc: issuer %q has no usable audiences after filtering empty values — configure at least one non-empty audience", iss.Issuer)
		}
		maxAge := iss.MaxTokenAge
		if maxAge <= 0 {
			maxAge = defaultOIDCMaxTokenAge
		}
		m[iss.Issuer] = oidcIssuerTrust{audiences: auds, maxAge: maxAge}
	}
	return &OIDCVerifier{issuers: m, jwks: jwks, leeway: oidcClockSkew, now: time.Now}, nil
}

// Verify checks the JWT's signature against the issuer's JWKS and validates
// iss (trusted), aud (intersects the issuer's allowlist), and exp/nbf. It
// returns the (issuer, subject) on success. Asymmetric algorithms only — HMAC
// is rejected so a leaked JWKS document can never be used to forge tokens.
func (v *OIDCVerifier) Verify(ctx context.Context, raw string) (issuer, subject string, err error) {
	issuer, subject, _, err = v.VerifyWithExpiry(ctx, raw)
	return issuer, subject, err
}

// VerifyWithExpiry is Verify that also returns the token's exp (UTC), so a caller
// that caches the verdict can bound the entry by the token's own lifetime
// (OIDC-EXPIRY-CAP-1). exp is required by the parser, so it is never zero on success.
func (v *OIDCVerifier) VerifyWithExpiry(ctx context.Context, raw string) (issuer, subject string, exp time.Time, err error) { // NOSONAR -- cognitive complexity 20, suppress go:S3776
	var claims oidcClaims
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}),
		jwt.WithLeeway(v.leeway),
		jwt.WithExpirationRequired(),
		// WithIssuedAt rejects an iat set more than v.leeway into the future
		// (golang-jwt's verifyIssuedAt: fails iff now < iat-leeway). It does
		// NOT touch the far-past direction or make iat required — the
		// existing manual iat-required + max-age check below still owns
		// that. Without this, a future-dated iat only ever makes the max-age
		// check's age computation negative, which can never exceed a
		// positive bound, so nothing rejected it (docs/findings/
		// 2026-09-23-FINDING-oidc-future-iat-and-crit.md).
		jwt.WithIssuedAt(),
		// Without this, golang-jwt's own exp/nbf/iat-future checks read the
		// real wall clock directly, while the max-age check below reads
		// v.effectiveNow() — two independent clocks inside one Verify call
		// that a test (or a fuzz harness) can't both freeze at once, and that
		// diverge under a clock-jump exactly when this verifier most needs to
		// agree with itself about what "now" is (#1983).
		jwt.WithTimeFunc(v.effectiveNow),
	)

	keyfunc := func(token *jwt.Token) (any, error) {
		iss, ierr := token.Claims.GetIssuer()
		if ierr != nil || iss == "" {
			return nil, fmt.Errorf("missing issuer")
		}
		if _, ok := v.issuers[iss]; !ok {
			return nil, fmt.Errorf("untrusted issuer")
		}
		kid, _ := token.Header["kid"].(string)
		return v.jwks.Key(ctx, iss, kid)
	}

	token, err := parser.ParseWithClaims(raw, &claims, keyfunc)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("oidc token verification failed: %w", err)
	}
	if !token.Valid {
		return "", "", time.Time{}, fmt.Errorf("oidc token invalid")
	}
	// RFC 7515 §4.1.11: a recipient MUST reject a JWS whose "crit" header
	// names an extension it doesn't understand. This verifier understands
	// none, so ANY crit header — regardless of what it names — is rejected.
	if _, hasCrit := token.Header["crit"]; hasCrit {
		return "", "", time.Time{}, fmt.Errorf("oidc token has an unrecognized crit header")
	}

	trust, ok := v.issuers[claims.Issuer]
	if !ok {
		return "", "", time.Time{}, fmt.Errorf("untrusted issuer")
	}
	audOK := false
	for _, a := range claims.Audience {
		if _, ok := trust.audiences[a]; ok {
			audOK = true
			break
		}
	}
	if !audOK {
		return "", "", time.Time{}, fmt.Errorf("oidc token audience not allowed")
	}
	// A token naming MORE THAN ONE audience is, per OIDC, ambiguous about which
	// party it was actually issued to — any one of the audiences matching our
	// allowlist isn't enough, since a multi-tenant IdP could mint a token shared
	// across several relying parties and an attacker holding a copy issued to a
	// DIFFERENT (also-trusted) party could replay it here. azp (authorized party)
	// disambiguates the true recipient and must itself be one of our trusted
	// audiences.
	if len(claims.Audience) > 1 {
		if claims.Azp == "" {
			return "", "", time.Time{}, fmt.Errorf("oidc token has multiple audiences but no azp claim")
		}
		if _, ok := trust.audiences[claims.Azp]; !ok {
			return "", "", time.Time{}, fmt.Errorf("oidc token azp not allowed")
		}
	}
	if strings.TrimSpace(claims.Subject) == "" {
		return "", "", time.Time{}, fmt.Errorf("oidc token has no subject")
	}
	// exp alone doesn't bound how long ago a token was minted — a far-future exp
	// (misconfigured or malicious issuer) would otherwise verify indefinitely.
	// Require iat and cap its age per-issuer.
	if claims.IssuedAt == nil {
		return "", "", time.Time{}, fmt.Errorf("oidc token has no iat claim")
	}
	if age := v.effectiveNow().Sub(claims.IssuedAt.Time); age > trust.maxAge+v.leeway {
		return "", "", time.Time{}, fmt.Errorf("oidc token exceeds max age (issued %s ago)", age.Round(time.Second))
	}
	if claims.ExpiresAt == nil {
		return "", "", time.Time{}, fmt.Errorf("oidc token has no exp claim")
	}
	return claims.Issuer, claims.Subject, claims.ExpiresAt.UTC(), nil
}

// TrustsIssuer reports whether the issuer is in the configured allowlist.
func (v *OIDCVerifier) TrustsIssuer(issuer string) bool {
	_, ok := v.issuers[issuer]
	return ok
}

// SetOIDCVerifier wires the federation verifier (built from config at startup).
// nil disables OIDC auth.
func (c *KeyorixCore) SetOIDCVerifier(v *OIDCVerifier) {
	c.oidcVerifier = v
}

// OIDCEnabled reports whether federated authentication is configured.
func (c *KeyorixCore) OIDCEnabled() bool {
	return c.oidcVerifier != nil
}

// ValidateOIDCToken verifies a federated JWT and resolves it to its bound
// machine identity + roles (ADR-031), mirroring ValidateMachineToken so the
// middleware builds the same machine principal. Rejects when OIDC is disabled,
// the token fails verification, no binding exists, or the machine is not active.
// A storage failure while reading the machine's roles returns
// ErrRoleResolutionUnavailable (#2748) — never an empty role list.
//
// The third return value is the token's own exp (UTC): a caller that caches the
// result must not keep it past that instant (OIDC-EXPIRY-CAP-1).
func (c *KeyorixCore) ValidateOIDCToken(ctx context.Context, raw string) (*models.MachineIdentity, []string, time.Time, error) {
	if c.oidcVerifier == nil {
		return nil, nil, time.Time{}, fmt.Errorf("oidc authentication is not enabled")
	}
	issuer, subject, exp, err := c.oidcVerifier.VerifyWithExpiry(ctx, raw)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	m, err := c.storage.GetMachineByOIDCSubject(ctx, issuer, subject)
	if err != nil {
		return nil, nil, time.Time{}, credentialLookupError(err, "no machine identity bound to this token")
	}
	if m.State != MachineActive {
		// #2518: the same typed sentinel the opaque-token paths return for this
		// identical condition (machine_token.go). This path has no positive
		// auth cache today, so nothing can mistake it for a transient failure —
		// kept in step so a future cached OIDC path cannot inherit the trap.
		return nil, nil, time.Time{}, fmt.Errorf("%w: %s", ErrMachineIdentityNotActive, m.State)
	}
	roles, err := c.storage.GetMachineRoles(ctx, m.ID)
	if err != nil {
		// #2748: same fix as ValidateMachineToken's own GetMachineRoles branch
		// (and #1944's for the two user-credential validators) — a storage
		// failure resolving roles is retryable, not a successful validation
		// with no grants. See ErrRoleResolutionUnavailable.
		return nil, nil, time.Time{}, ErrRoleResolutionUnavailable
	}
	roleNames := make([]string, len(roles))
	for i, r := range roles {
		roleNames[i] = r.Name
	}
	return m, roleNames, exp, nil
}

// --- Binding management (ADR-031) ---

// CreateOIDCBinding binds an external (issuer, subject) to a machine identity in
// the given project. Audited; the machine must belong to the project (the
// handler also gates roles.assign there).
//
// (issuer, subject) is a GLOBAL namespace — GetMachineByOIDCSubject / the token
// verify path resolve it with no project scoping — but until this check, only
// project-scoped authority (roles.assign within THAT project) was required to
// claim a slice of it (#127). A project-A admin could pre-claim another team's
// well-known, not-yet-bound subject (predictable per issuer, e.g. a Kubernetes
// service-account or CI workflow identity) for their own machine; the victim
// workload's genuine token would then authenticate as the attacker's machine
// identity instead. Creating a binding is therefore gated on GLOBAL admin
// authority, matching the scope of what it actually claims.
func (c *KeyorixCore) CreateOIDCBinding(ctx context.Context, projectID, machineID uint, issuer, subject string, actorID uint) (*models.MachineIdentityOIDCBinding, error) {
	if strings.TrimSpace(issuer) == "" || strings.TrimSpace(subject) == "" {
		return nil, fmt.Errorf("issuer and subject are required")
	}
	if err := c.requireAdminAuthorityAt(ctx, actorID, 0); err != nil {
		return nil, fmt.Errorf("binding an OIDC subject requires install-wide admin authority: %w", err)
	}
	// Surface operator typos early: a binding to an issuer Keyorix doesn't trust
	// would never authenticate (Verify rejects untrusted issuers independently),
	// so reject it at creation when OIDC is configured.
	if c.oidcVerifier != nil && !c.oidcVerifier.TrustsIssuer(strings.TrimSpace(issuer)) {
		return nil, fmt.Errorf("issuer %q is not a configured trusted OIDC issuer", issuer)
	}
	m, err := c.machineInProject(ctx, projectID, machineID)
	if err != nil {
		return nil, err
	}
	b, err := c.storage.CreateOIDCBinding(ctx, &models.MachineIdentityOIDCBinding{
		MachineIdentityID: machineID,
		Issuer:            strings.TrimSpace(issuer),
		Subject:           strings.TrimSpace(subject),
		CreatedBy:         actorID,
		CreatedAt:         c.now(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC binding (already bound?): %w", err)
	}
	c.logMachineEvent(ctx, "machine_identity.oidc_bound", m, actorID)
	return b, nil
}

// ListOIDCBindings returns a machine's OIDC bindings (after the project check).
func (c *KeyorixCore) ListOIDCBindings(ctx context.Context, projectID, machineID uint) ([]*models.MachineIdentityOIDCBinding, error) {
	if _, err := c.machineInProject(ctx, projectID, machineID); err != nil {
		return nil, err
	}
	return c.storage.ListOIDCBindings(ctx, machineID)
}

// DeleteOIDCBinding removes a binding after verifying it belongs to the machine
// and the machine belongs to the project.
func (c *KeyorixCore) DeleteOIDCBinding(ctx context.Context, projectID, machineID, bindingID, actorID uint) error {
	m, err := c.machineInProject(ctx, projectID, machineID)
	if err != nil {
		return err
	}
	b, err := c.storage.GetOIDCBindingByID(ctx, bindingID)
	if err != nil || b.MachineIdentityID != machineID {
		return fmt.Errorf("binding not found")
	}
	if err := c.storage.DeleteOIDCBinding(ctx, bindingID); err != nil {
		return err
	}
	c.logMachineEvent(ctx, "machine_identity.oidc_unbound", m, actorID)
	return nil
}
