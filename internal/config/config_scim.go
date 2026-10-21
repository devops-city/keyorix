package config

// SCIMConfig configures SCIM 2.0 provisioning (RFC 7644). When Enabled, the
// /scim/v2 endpoints are served, authenticated by a static bearer token an IdP
// presents. Opt-in (default off).
type SCIMConfig struct {
	Enabled bool   `yaml:"enabled"`
	Token   string `yaml:"token"` // use KEYORIX_SCIM_TOKEN env var instead
}

// GetToken returns the resolved SCIM bearer token, preferring the env var.
func (s *SCIMConfig) GetToken() string {
	return resolveSecret("KEYORIX_SCIM_TOKEN", s.Token)
}
