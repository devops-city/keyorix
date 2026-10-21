package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/netutil"
	samlpkg "github.com/keyorixhq/keyorix/internal/saml"
	"github.com/keyorixhq/keyorix/internal/secretenv"
	"golang.org/x/oauth2"
)

// oidcDiscovery is the subset of an OIDC discovery document we need.
type oidcDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// maxDiscoveryBytes caps the discovery document we read into memory.
const maxDiscoveryBytes = 1 << 20 // 1 MiB

// oidcDiscoveryTransport guards the SSO OIDC-discovery fetch the same way
// jwksEgressTransport guards the JWKS fetch (F2, adversarial-review 2026-09-14):
// clone http.DefaultTransport (preserving proxy-from-environment and pooling, the
// prior behaviour) and re-validate every direct-dial target against
// netutil.IsLinkLocal, so a misconfigured or compromised issuer whose
// /.well-known/openid-configuration resolves to the cloud instance-metadata
// endpoint (169.254.169.254) can never be dialed. Link-local-only by design:
// RFC-1918/on-prem and loopback issuers stay reachable (requireSecureOrLoopback
// already permits http on loopback for dev), which is keyorix's primary
// deployment shape. When an egress proxy is configured the dial targets the proxy
// rather than the issuer — accepted, same as the JWKS client.
var oidcDiscoveryTransport = func() *http.Transport {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = (&netutil.Dialer{Disallow: netutil.IsLinkLocal}).DialContext
	return tr
}()

// discoverOIDC fetches an issuer's /.well-known/openid-configuration and validates
// it. The issuer must use https (http only for loopback) so the document — which
// names the jwks_uri that ultimately supplies the token-signing keys — is not
// fetched over plaintext where a MITM could redirect key fetching to attacker keys.
// Per the OIDC spec the document's own issuer must equal the configured issuer, and
// the jwks_uri it advertises must live on the issuer's host, so a tampered/hostile
// discovery doc can't point key fetching at an unrelated host.
func discoverOIDC(issuer string) (*oidcDiscovery, error) {
	iss, err := url.Parse(strings.TrimRight(issuer, "/"))
	if err != nil || iss.Host == "" {
		return nil, fmt.Errorf("invalid issuer %q", issuer)
	}
	if err := requireSecureOrLoopback(iss, "issuer"); err != nil {
		return nil, err
	}

	u := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	client := &http.Client{
		Timeout:       10 * time.Second,
		Transport:     oidcDiscoveryTransport,
		CheckRedirect: noDiscoveryCrossOriginRedirect,
	}
	resp, err := client.Get(u) // #nosec G107 -- issuer is operator-configured and https-validated above
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery returned %s", resp.Status)
	}
	var d oidcDiscovery
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxDiscoveryBytes)).Decode(&d); err != nil {
		return nil, err
	}
	if d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" || d.JWKSURI == "" {
		return nil, fmt.Errorf("discovery document is missing required endpoints")
	}
	if d.Issuer != "" && strings.TrimRight(d.Issuer, "/") != strings.TrimRight(issuer, "/") {
		return nil, fmt.Errorf("discovery issuer %q does not match configured issuer %q", d.Issuer, issuer)
	}
	jwksURL, err := url.Parse(d.JWKSURI)
	if err != nil || jwksURL.Host == "" {
		return nil, fmt.Errorf("discovery jwks_uri %q is invalid", d.JWKSURI)
	}
	if !strings.EqualFold(jwksURL.Hostname(), iss.Hostname()) {
		return nil, fmt.Errorf("discovery jwks_uri host %q does not match issuer host %q", jwksURL.Hostname(), iss.Hostname())
	}
	return &d, nil
}

// requireSecureOrLoopback rejects a non-https URL unless its host is loopback.
func requireSecureOrLoopback(u *url.URL, label string) error {
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" && isLoopbackHostname(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("%s %q must use https (http is allowed only for localhost)", label, u.Redacted())
}

func isLoopbackHostname(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// noDiscoveryCrossOriginRedirect rejects a discovery redirect that changes host or
// downgrades the scheme, so a redirect can't pull the document from an unexpected host.
func noDiscoveryCrossOriginRedirect(req *http.Request, via []*http.Request) error {
	if len(via) == 0 {
		return nil
	}
	prev := via[len(via)-1].URL
	if !strings.EqualFold(req.URL.Hostname(), prev.Hostname()) {
		return fmt.Errorf("discovery: refusing cross-host redirect to %q", req.URL.Host)
	}
	if prev.Scheme == "https" && req.URL.Scheme != "https" {
		return fmt.Errorf("discovery: refusing scheme downgrade to %q", req.URL.Scheme)
	}
	return nil
}

// wireHumanSSO wires human SSO login (OIDC authorization-code flow, and SAML)
// when configured. Each provider's endpoints are discovered from its issuer; a
// provider whose discovery fails (or, for SAML, is misconfigured) is skipped
// with a warning rather than failing startup.
func wireHumanSSO(cfg *config.Config, coreService *core.KeyorixCore) {
	sso := cfg.SSO
	if !sso.Enabled || len(sso.Providers) == 0 {
		return
	}
	providers, jwks, n := buildSSOProviders(sso)
	if n > 0 {
		coreService.SetSSOProviders(providers, jwks)
		log.Printf("Human SSO enabled for %d provider(s)", n)
	}
}

// ssoCompleteURL derives the SPA completion URL (<redirect origin>/auth/sso/complete)
// from a provider's redirect_url.
func ssoCompleteURL(redirectURL string) (string, error) {
	u, err := url.Parse(redirectURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid redirect_url %q", redirectURL)
	}
	return u.Scheme + "://" + u.Host + "/auth/sso/complete", nil
}

// buildSSOProviders discovers each configured provider and builds the resolved
// providers + a JWKS resolver over their issuers. A provider that is misconfigured
// or whose discovery fails is skipped with a warning (it must not block startup).
func buildSSOProviders(sso config.SSOConfig) (map[string]*core.SSOProvider, core.JWKSResolver, int) { // NOSONAR -- cognitive complexity 23, suppress go:S3776
	providers := map[string]*core.SSOProvider{}
	jwksURIs := map[string]string{}
	for i := range sso.Providers {
		pc := sso.Providers[i]
		if pc.Name == "" {
			log.Printf("SSO provider with no name; skipping")
			continue
		}
		// SAML providers are built from their own block (no OIDC discovery).
		if strings.EqualFold(pc.Type, "saml") {
			sp, err := buildSAMLProvider(pc)
			if err != nil {
				log.Printf("SSO provider %q (saml) misconfigured: %v; skipping", pc.Name, err)
				continue
			}
			completeURL, err := ssoCompleteURL(pc.SAML.ACSURL)
			if err != nil {
				log.Printf("SSO provider %q (saml): %v; skipping", pc.Name, err)
				continue
			}
			providers[pc.Name] = &core.SSOProvider{
				Name: pc.Name, Type: "saml", SAML: sp, CompleteURL: completeURL,
				AutoProvision: pc.AutoProvision, DefaultRole: pc.DefaultRole,
				TrustAssertedEmail: pc.TrustAssertedEmail,
				GroupSync:          pc.GroupSync, GroupRoleMap: pc.GroupRoleMap,
			}
			continue
		}
		if pc.Issuer == "" || pc.ClientID == "" || pc.RedirectURL == "" {
			log.Printf("SSO provider %q misconfigured (issuer/client_id/redirect_url required); skipping", pc.Name)
			continue
		}
		disc, err := discoverOIDC(pc.Issuer)
		if err != nil {
			log.Printf("SSO provider %q discovery failed: %v; skipping", pc.Name, err)
			continue
		}
		completeURL, err := ssoCompleteURL(pc.RedirectURL)
		if err != nil {
			log.Printf("SSO provider %q: %v; skipping", pc.Name, err)
			continue
		}
		scopes := pc.Scopes
		if len(scopes) == 0 {
			scopes = []string{"openid", "profile", "email"}
		}
		providers[pc.Name] = &core.SSOProvider{
			Name:     pc.Name,
			Issuer:   pc.Issuer,
			ClientID: pc.ClientID,
			OAuth: &oauth2.Config{
				ClientID:     pc.ClientID,
				ClientSecret: pc.GetClientSecret(),
				Endpoint:     oauth2.Endpoint{AuthURL: disc.AuthorizationEndpoint, TokenURL: disc.TokenEndpoint},
				RedirectURL:  pc.RedirectURL,
				Scopes:       scopes,
			},
			CompleteURL:   completeURL,
			AutoProvision: pc.AutoProvision,
			DefaultRole:   pc.DefaultRole,
			GroupSync:     pc.GroupSync,
			GroupsClaim:   pc.GroupsClaim,
			GroupRoleMap:  pc.GroupRoleMap,
		}
		jwksURIs[pc.Issuer] = disc.JWKSURI
	}
	if len(providers) == 0 {
		return nil, nil, 0
	}
	// A JWKS resolver is only needed for OIDC providers; a SAML-only deployment has none.
	if len(jwksURIs) == 0 {
		return providers, nil, len(providers)
	}
	resolver, err := core.NewHTTPJWKSResolver(jwksURIs)
	if err != nil {
		log.Printf("SSO disabled: jwks resolver init failed: %v", err)
		return nil, nil, 0
	}
	return providers, resolver, len(providers)
}

// buildSAMLProvider constructs a SAML Service Provider from its config block, reading
// the IdP metadata inline or from a file.
func buildSAMLProvider(pc config.SSOProviderConfig) (*samlpkg.Provider, error) {
	if pc.SAML == nil {
		return nil, fmt.Errorf("missing saml config block")
	}
	metaXML := []byte(pc.SAML.IDPMetadataXML)
	if len(metaXML) == 0 && pc.SAML.IDPMetadataFile != "" {
		b, err := secretenv.ReadRegularFile("idp_metadata_file", pc.SAML.IDPMetadataFile) // operator-provided metadata path; a FIFO is refused, not waited on
		if err != nil {
			return nil, fmt.Errorf("read idp_metadata_file: %w", err)
		}
		metaXML = b
	}
	return samlpkg.NewProvider(samlpkg.Config{
		Name:              pc.Name,
		IDPMetadataXML:    metaXML,
		SPEntityID:        pc.SAML.SPEntityID,
		ACSURL:            pc.SAML.ACSURL,
		AllowIDPInitiated: pc.SAML.AllowIDPInitiated,
		EmailAttr:         pc.SAML.EmailAttribute,
		NameAttr:          pc.SAML.NameAttribute,
		GroupsAttr:        pc.SAML.GroupsAttribute,
	})
}
