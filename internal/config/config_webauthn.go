package config

import (
	"fmt"
	"net/url"
	"strings"
)

// WebAuthnConfig configures the WebAuthn relying party (ADR-036). RPID is the
// effective domain (e.g. "keyorix.example.com", no scheme/port); RPOrigins are the
// full origins permitted to authenticate (e.g. "https://keyorix.example.com").
type WebAuthnConfig struct {
	Enabled       bool     `yaml:"enabled"`
	RPID          string   `yaml:"rp_id"`
	RPDisplayName string   `yaml:"rp_display_name"`
	RPOrigins     []string `yaml:"rp_origins"`
}

// validateWebAuthnRP (F5, adversarial-review 2026-09-14) is a fail-loud startup
// sanity check on the WebAuthn relying-party config. The go-webauthn library
// enforces the real origin/RP-ID match per ceremony at runtime; without this
// check a misconfigured rp_origins (plaintext http, or a host that is not rp_id
// nor a subdomain of it) makes EVERY passkey ceremony fail at runtime with an
// opaque library error, instead of a clear config error at boot. Rules follow
// WebAuthn L3 effective-domain semantics:
//   - each rp_origin must parse to a URL with a host;
//   - scheme must be https, except http is allowed only for a loopback host
//     (localhost / 127.0.0.1 / ::1) for local development;
//   - the origin host must equal rp_id or be a subdomain of rp_id — a passkey is
//     scoped to the rp_id registrable domain, so an origin outside it can never
//     satisfy the ceremony.
//
// This is config hygiene, not the security boundary itself (the library remains
// the authority per ceremony); it exists so the misconfiguration is caught once,
// at boot, rather than per failed login.
func validateWebAuthnRP(wc WebAuthnConfig) error {
	if !wc.Enabled {
		return nil
	}
	if wc.RPID == "" {
		return fmt.Errorf("webauthn is enabled but rp_id is not set")
	}
	if len(wc.RPOrigins) == 0 {
		return fmt.Errorf("webauthn is enabled but no rp_origins are configured")
	}
	rpID := strings.ToLower(wc.RPID)
	for _, o := range wc.RPOrigins {
		u, err := url.Parse(o)
		if err != nil || u.Host == "" {
			return fmt.Errorf("webauthn rp_origin %q is not a valid origin URL (expected scheme://host[:port], e.g. https://app.example.com)", o)
		}
		host := strings.ToLower(u.Hostname())
		loopback := isLoopbackConfigHost(host)
		switch u.Scheme {
		case "https":
			// ok
		case "http":
			if !loopback {
				return fmt.Errorf("webauthn rp_origin %q must use https (http is allowed only for a loopback host)", o)
			}
		default:
			return fmt.Errorf("webauthn rp_origin %q must use https (http is allowed only for a loopback host)", o)
		}
		if !loopback && host != rpID && !strings.HasSuffix(host, "."+rpID) {
			return fmt.Errorf("webauthn rp_origin %q host %q must equal rp_id %q or be a subdomain of it", o, host, rpID)
		}
	}
	return nil
}

// validateWebAuthnSection checks the webauthn relying-party settings (Validate step).
func validateWebAuthnSection(c *Config) error {
	if err := validateWebAuthnRP(c.WebAuthn); err != nil {
		return err
	}
	return nil
}
