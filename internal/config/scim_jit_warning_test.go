package config

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func scimJITCfg(scim, ssoEnabled bool, providers ...SSOProviderConfig) *Config {
	c := &Config{}
	c.SCIM.Enabled = scim
	c.SSO.Enabled = ssoEnabled
	c.SSO.Providers = providers
	return c
}

// SCIM is one install-wide switch, so "the same provider" is any SSO provider of
// this install: the warning fires when SCIM is on and at least one enabled SSO
// provider JIT-provisions accounts, and names exactly those providers.
func TestSCIMJITUnmanagedProviders(t *testing.T) {
	jit := func(n string) SSOProviderConfig { return SSOProviderConfig{Name: n, AutoProvision: true} }
	noJIT := func(n string) SSOProviderConfig { return SSOProviderConfig{Name: n} }

	cases := []struct {
		name string
		cfg  *Config
		want []string
	}{
		{"both", scimJITCfg(true, true, jit("okta")), []string{"okta"}},
		{"scim only", scimJITCfg(true, true, noJIT("okta")), nil},
		{"jit only", scimJITCfg(false, true, jit("okta")), nil},
		{"neither", scimJITCfg(false, false), nil},
		{"sso disabled globally", scimJITCfg(true, false, jit("okta")), nil},
		{"only the JIT providers are named", scimJITCfg(true, true, noJIT("a"), jit("b"), jit("c")), []string{"b", "c"}},
		{"scim, jit on none", scimJITCfg(true, true, noJIT("a"), noJIT("b")), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.cfg.SCIMJITUnmanagedProviders())
		})
	}
}

func TestSCIMJITUnmanagedWarning(t *testing.T) {
	assert.Empty(t, SCIMJITUnmanagedWarning(nil))

	w := SCIMJITUnmanagedWarning([]string{"okta", "entra"})
	for _, must := range []string{
		"SECURITY", "okta", "entra",
		"not deactivated by SCIM",
		"PATs and sessions",
		"scim_managed",
	} {
		assert.True(t, strings.Contains(w, must), "warning must mention %q: %s", must, w)
	}
}
