package config

import (
	"fmt"
	"strings"
)

// SSOConfig configures human OIDC single-sign-on. Opt-in (default off). Each
// provider is an OIDC IdP; users are matched to a Keyorix account by the IdP
// subject (against the SCIM externalId) and, failing that, by email.
type SSOConfig struct {
	Enabled   bool                `yaml:"enabled"`
	Providers []SSOProviderConfig `yaml:"providers"`
}

// SSOProviderConfig is one configured OIDC provider. Endpoints are discovered from
// the issuer's /.well-known/openid-configuration at startup, so only the issuer +
// client credentials + redirect URL are required.
type SSOProviderConfig struct {
	Name string `yaml:"name"` // operator label + URL slug (e.g. "okta")
	// Type is "oidc" (default) or "saml"; it selects which block below is used.
	Type string `yaml:"type"`
	// SAML config (when type=saml). OIDC fields below are ignored for SAML providers.
	SAML *SAMLProviderConfig `yaml:"saml"`

	Issuer       string   `yaml:"issuer"`        // OIDC issuer URL
	ClientID     string   `yaml:"client_id"`     // the OAuth client id registered at the IdP
	ClientSecret string   `yaml:"client_secret"` // prefer KEYORIX_SSO_<NAME>_CLIENT_SECRET
	RedirectURL  string   `yaml:"redirect_url"`  // must equal <public-host>/auth/sso/<name>/callback
	Scopes       []string `yaml:"scopes"`        // default [openid, profile, email]

	// AutoProvision JIT-creates a Keyorix account on a first SSO login whose verified
	// identity matches no existing user — so an IdP that isn't wired for SCIM push can
	// still onboard users on demand. Opt-in (default off): when false, an unknown
	// identity is refused, exactly as before.
	AutoProvision bool `yaml:"auto_provision"`
	// DefaultRole is the install-wide baseline role granted to a JIT-provisioned user
	// (default "system_viewer"). A misconfigured/unknown role grants nothing —
	// least-privilege on misconfiguration.
	DefaultRole string `yaml:"default_role"`
	// TrustAssertedEmail opts a SAML provider (type: saml) into treating its
	// asserted email as verified for account-linking. SAML has no per-assertion
	// verified-email signal — the assertion being IdP-signed proves the IdP sent
	// it, not that the IdP verified the user owns it. Opt-in (default off):
	// without it, a SAML login can still JIT-provision a NEW account but cannot
	// claim an EXISTING one by asserting its email. Ignored for OIDC providers
	// (whose email_verified claim is checked per-login instead).
	TrustAssertedEmail bool `yaml:"insecure_trust_saml_asserted_email"`

	// GroupSync reconciles the user's NATIVE group memberships from the IdP's groups
	// claim on each login (the IdP becomes the source of truth — membership is added
	// for asserted groups and removed for non-asserted ones). Opt-in (default off).
	// Only existing native groups (provisioned by SCIM or an admin) are touched; an
	// asserted group with no native counterpart is ignored. If the groups claim is
	// absent from the id_token, the sync is a no-op.
	GroupSync bool `yaml:"group_sync"`
	// GroupsClaim is the id_token claim carrying the group names (default "groups";
	// some IdPs use "roles").
	GroupsClaim string `yaml:"groups_claim"`
	// GroupRoleMap maps an IdP group-claim value to a Keyorix (system) role name. When
	// set, each login reconciles the user's grants of the MAPPED roles to their
	// asserted groups (the IdP drives those assignments); roles outside the map are
	// untouched. Uses groups_claim as the source. e.g. {keyorix-admins: system_admin}.
	GroupRoleMap map[string]string `yaml:"group_role_map"`
}

// GetClientSecret returns the resolved client secret, preferring the per-provider
// env var KEYORIX_SSO_<NAME>_CLIENT_SECRET (name upper-cased).
func (p *SSOProviderConfig) GetClientSecret() string {
	return resolveSecret("KEYORIX_SSO_"+strings.ToUpper(p.Name)+"_CLIENT_SECRET", p.ClientSecret)
}

// SAMLProviderConfig is one configured SAML 2.0 IdP (when the provider's type=saml).
// The IdP metadata supplies the entityID, SSO URL, and signing certificate; provide it
// inline (idp_metadata_xml) or as a file path (idp_metadata_file).
type SAMLProviderConfig struct {
	IDPMetadataXML  string `yaml:"idp_metadata_xml"`
	IDPMetadataFile string `yaml:"idp_metadata_file"`
	SPEntityID      string `yaml:"sp_entity_id"` // our SP entity ID (conventionally the metadata URL)
	ACSURL          string `yaml:"acs_url"`      // <public-host>/auth/saml/<name>/acs
	// AllowIDPInitiated permits responses with no InResponseTo (loses CSRF/replay
	// protection). Off by default — enable only for IdPs that require it.
	AllowIDPInitiated bool `yaml:"insecure_allow_idp_initiated_saml"`
	// Attribute names to read from the assertion (empty → common Azure AD/ADFS defaults).
	EmailAttribute  string `yaml:"email_attribute"`
	NameAttribute   string `yaml:"name_attribute"`
	GroupsAttribute string `yaml:"groups_attribute"`
}

// validateSSOIDPInitiated (F3, adversarial-review 2026-09-14) refuses any SAML
// provider that sets allow_idp_initiated. keyorix's SAML replay protection rests
// entirely on the single-use RelayState row CompleteSAML consumes on the ACS;
// there is no assertion-ID / NotOnOrAfter replay cache. An IdP-initiated response
// carries no InResponseTo and no RelayState to bind, so it has no replay defence
// at all — CompleteSAML already fails such a response closed today, which makes
// the option DEAD, not merely risky. A dead security toggle an operator can set
// to "true" and believe is in effect is worse than no toggle: reject it loud at
// boot so the misconfiguration surfaces as a config error rather than a false
// sense of security (and a latent trap for whoever might one day wire IdP-initiated
// up without noticing the missing replay cache). If IdP-initiated is ever genuinely
// implemented, add the assertion-ID + NotOnOrAfter replay cache first, then lift
// this check. Aggregates every offending provider into one error, mirroring the
// connect validators.
func validateSSOIDPInitiated(sso SSOConfig) error {
	var offending []string
	for _, p := range sso.Providers {
		if p.SAML != nil && p.SAML.AllowIDPInitiated {
			offending = append(offending, p.Name)
		}
	}
	if len(offending) > 0 {
		return fmt.Errorf("sso: provider(s) set insecure_allow_idp_initiated_saml (or its deprecated alias allow_idp_initiated), which is not supported — keyorix has no SAML assertion-replay cache, so an IdP-initiated response (no InResponseTo / RelayState) has no replay protection and is refused at the ACS regardless; remove it: %s", strings.Join(offending, ", "))
	}
	return nil
}

// validateSSOAudienceIsolation (F4, adversarial-review 2026-09-14) closes a
// cross-seam token-confusion gap between the two independent OIDC trust seams:
// human SSO (cfg.SSO.Providers) and machine-identity federation (cfg.OIDC.Issuers).
// A human-SSO provider's client_id must not ALSO be a trusted machine-federation
// audience for the SAME issuer. If it were, one id_token minted by that issuer for
// the human SSO client would satisfy the machine seam too (identical iss, and aud
// contains the shared client_id) — a token issued for one trust boundary replaying
// into the other, authenticating a browser SSO login as a machine identity. The
// machine seam enforces an exact issuer match, so the confusion is only reachable
// when the issuers coincide; that is exactly the condition checked here (guard the
// condition, not the conclusion). Only OIDC-type SSO providers are considered
// (SAML providers mint no OIDC id_token). No-op when machine federation is disabled.
func validateSSOAudienceIsolation(c *Config) error {
	if !c.OIDC.Enabled {
		return nil
	}
	var collisions []string
	for _, p := range c.SSO.Providers {
		if p.Type == "saml" || p.Issuer == "" || p.ClientID == "" {
			continue
		}
		providerIssuer := strings.TrimRight(p.Issuer, "/")
		for _, iss := range c.OIDC.Issuers {
			if strings.TrimRight(iss.Issuer, "/") != providerIssuer {
				continue
			}
			for _, aud := range iss.Audiences {
				if aud == p.ClientID {
					collisions = append(collisions, fmt.Sprintf("sso provider %q client_id is also a machine-federation audience on oidc issuer %q (issuer %q)", p.Name, iss.Name, providerIssuer))
				}
			}
		}
	}
	if len(collisions) > 0 {
		return fmt.Errorf("cross-seam audience collision — a human-SSO id_token would also authenticate as a machine identity: %s; use a distinct client_id per trust seam and remove the sso client_id from the machine-federation issuer's audiences", strings.Join(collisions, "; "))
	}
	return nil
}

// validateSSOSection checks sso: IdP-initiated login and audience isolation (Validate step).
func validateSSOSection(c *Config) error {
	if err := validateSSOIDPInitiated(c.SSO); err != nil {
		return err
	}

	if err := validateSSOAudienceIsolation(c); err != nil {
		return err
	}
	return nil
}
