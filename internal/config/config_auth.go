package config

type ClientConfig struct {
	Endpoint string     `yaml:"endpoint"`
	Auth     AuthConfig `yaml:"auth"`
	Timeout  string     `yaml:"timeout"`
}

type AuthConfig struct {
	Type   string `yaml:"type"`    // "none", "api_key"
	APIKey string `yaml:"api_key"` // use KEYORIX_API_KEY env var instead
}

// OIDCConfig is the trusted-issuer allowlist for machine-identity federation.
type OIDCConfig struct {
	Enabled bool               `yaml:"enabled"`
	Issuers []OIDCIssuerConfig `yaml:"issuers"`
}

// OIDCIssuerConfig describes one trusted token issuer.
type OIDCIssuerConfig struct {
	Name      string   `yaml:"name"`      // operator label
	Issuer    string   `yaml:"issuer"`    // must equal the JWT `iss` exactly
	JWKSURI   string   `yaml:"jwks_uri"`  // where the issuer's signing keys live
	Audiences []string `yaml:"audiences"` // the JWT `aud` must contain one of these
	// MaxTokenAgeSeconds bounds (now - iat) for a token from this issuer; unset/0
	// uses a 24h default. exp alone doesn't bound how long ago a token was
	// minted, so without this a far-future-exp token (misconfigured or
	// malicious issuer) would verify indefinitely.
	MaxTokenAgeSeconds int `yaml:"max_token_age_seconds"`
}

// GetAPIKey returns the resolved API key, preferring the environment variable.
func (a *AuthConfig) GetAPIKey() string {
	return resolveSecret("KEYORIX_API_KEY", a.APIKey)
}
