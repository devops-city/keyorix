package main

import (
	"fmt"
	"log"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
)

// wireOIDCFederation is a core wiring step (coreWiringSteps in main.go).
func wireOIDCFederation(cw *coreWiring) error {
	cfg, coreService := cw.cfg, cw.core
	// Wire OIDC / Kubernetes-JWT federation (ADR-031) when configured. A bad
	// issuer config (e.g. missing audiences) fails loud rather than silently
	// disabling federation.
	if oidc := cfg.OIDC; oidc.Enabled && len(oidc.Issuers) > 0 {
		trusted := make([]core.OIDCTrustedIssuer, 0, len(oidc.Issuers))
		jwksURIs := make(map[string]string, len(oidc.Issuers))
		for _, iss := range oidc.Issuers {
			trusted = append(trusted, core.OIDCTrustedIssuer{
				Issuer: iss.Issuer, Audiences: iss.Audiences,
				MaxTokenAge: time.Duration(iss.MaxTokenAgeSeconds) * time.Second,
			})
			jwksURIs[iss.Issuer] = iss.JWKSURI
		}
		resolver, rerr := core.NewHTTPJWKSResolver(jwksURIs)
		if rerr != nil {
			return fmt.Errorf("invalid OIDC jwks_uri: %w", rerr)
		}
		verifier, verr := core.NewOIDCVerifier(trusted, resolver)
		if verr != nil {
			return fmt.Errorf("failed to init OIDC federation: %w", verr)
		}
		coreService.SetOIDCVerifier(verifier)
		log.Printf("OIDC federation enabled for %d issuer(s)", len(oidc.Issuers))
	}
	return nil
}
