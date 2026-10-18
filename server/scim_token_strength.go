// scim_token_strength.go -- #3397: refuse, at boot, a SCIM bearer token that is
// obviously not random. The token is operator-supplied (PATs and machine tokens
// are server-generated) and authorizes user provisioning and deprovisioning.
//
// Two layers, checked before any listener opens:
//   - the 20-byte floor (rules.ValidateSCIMTokenStrength): always refuses, as
//     it did before this check existed;
//   - the shape checks (rules.CheckSCIMTokenShape: repeated byte, too few
//     distinct bytes, placeholder or sample value, same value as another
//     configured secret): new, so they follow the ADR-112 upgrade grace like
//     the other secure-by-default refusals. A fresh install refuses; an
//     upgraded deployment (users, no adr112.scim_token_strength.enforced
//     marker) only warns, until a boot where the check did not have to be
//     softened writes the marker (recordADR112Markers). Any error deciding
//     the grace period fails closed.
//
// The router keeps its own floor check (server/http/router.go) for callers that
// build a router without this boot path.
package main

import (
	"log"
	"sync/atomic"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
)

// adr112SCIMTokenSoftened is set when enforceSCIMTokenStrength turned a refusal
// into a warning during this boot; recordADR112Markers then leaves the
// deployment in the grace period.
var adr112SCIMTokenSoftened atomic.Bool

// enforceSCIMTokenStrength applies the checks above to the configured SCIM
// token. Nothing is checked when SCIM is disabled or the token is unset (every
// SCIM request is then refused by the middleware).
func enforceSCIMTokenStrength(cfg *config.Config) error {
	if !cfg.SCIM.Enabled {
		return nil
	}
	token := cfg.SCIM.GetToken()
	if err := core.ValidateSCIMTokenStrength(token); err != nil {
		return err
	}
	others := cfg.ConfiguredSecretValues()
	delete(others, "KEYORIX_SCIM_TOKEN")
	err := core.CheckSCIMTokenShape(token, others)
	if err == nil {
		return nil
	}
	st := inspectADR112State(cfg)
	if grace, why := st.grace(st.scimMarker); grace {
		adr112SCIMTokenSoftened.Store(true)
		log.Printf("WARNING: %v. ADR-112 grace period: %s, so this only warns for now. Replace the token; the first start with a token that passes ends the grace period for good, and from then on a weak SCIM token refuses to start.", err, why)
		return nil
	}
	return err
}
