package config

import (
	"time"

	"github.com/keyorixhq/keyorix/internal/delivery"
)

// CredentialDeliveryConfig configures the ADR-028 credential-delivery subsystem:
// how a brand-new principal receives their first-credential setup link.
type CredentialDeliveryConfig struct {
	// Mode selects the channel: auto | smtp | out_of_band | log ("" = auto).
	Mode string `yaml:"mode"`
	// SetupTokenTTL is the single-use setup/invite link lifetime (e.g. "24h").
	// Empty = DefaultSetupTokenTTLString.
	SetupTokenTTL string `yaml:"setup_token_ttl"`
	// BaseURL is required for any link-producing mode; used to build absolute setup
	// links (e.g. "https://keyorix.acme.internal"). A relative link is a
	// misconfiguration, not a fallback, so link minting refuses an empty BaseURL.
	BaseURL string               `yaml:"base_url"`
	SMTP    CredentialSMTPConfig `yaml:"smtp"`
}

// CredentialSMTPConfig is the operator's own mail relay. The password is resolved
// from KEYORIX_SMTP_PASSWORD when set, so it need not be written into the file
// (same convention as the DB password).
type CredentialSMTPConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"` // use KEYORIX_SMTP_PASSWORD env var instead
	From     string `yaml:"from"`
	TLS      string `yaml:"tls"` // starttls | implicit | none(dev-only)
}

// DefaultSetupTokenTTLString is the fallback link lifetime when none is configured.
const DefaultSetupTokenTTLString = "24h"

// GetSetupTokenTTL parses SetupTokenTTL, falling back to 24h when empty or invalid.
func (c *CredentialDeliveryConfig) GetSetupTokenTTL() time.Duration {
	raw := c.SetupTokenTTL
	if raw == "" {
		raw = DefaultSetupTokenTTLString
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		d, _ = time.ParseDuration(DefaultSetupTokenTTLString)
	}
	return d
}

// GetPassword returns the resolved SMTP password, preferring the environment variable.
func (s *CredentialSMTPConfig) GetPassword() string {
	return resolveSecret("KEYORIX_SMTP_PASSWORD", s.Password)
}

// DeliveryConfig maps the credential-delivery config block onto the delivery package's
// channel selector, resolving the SMTP password from the environment. Shared by the
// server and CLI wiring (ADR-028) so the mapping lives in exactly one place.
func (c *CredentialDeliveryConfig) DeliveryConfig() delivery.Config {
	return delivery.Config{
		Mode:    c.Mode,
		BaseURL: c.BaseURL,
		SMTP: delivery.SMTPSettings{
			Host:     c.SMTP.Host,
			Port:     c.SMTP.Port,
			Username: c.SMTP.Username,
			Password: c.SMTP.GetPassword(),
			From:     c.SMTP.From,
			TLS:      c.SMTP.TLS,
		},
	}
}
