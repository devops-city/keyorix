package config

import "strings"

// SCIMJITUnmanagedProviders returns the names of the SSO providers whose
// JIT-created accounts SCIM cannot deactivate, or nil when there are none.
//
// SCIM is one install-wide switch (scim.enabled), so "the same provider" is any
// enabled SSO provider of this install: the combination is at risk when
// scim.enabled and sso.enabled are both on and a provider has auto_provision.
// An account JIT-created by SSO carries external_id sso:<provider>:<sub>, which
// SCIM treats as not SCIM-managed (#3493, docs/security/threat-models/
// scim-and-sso-accounts.md SCIM-7), so an IdP offboard over SCIM never reaches it.
func (c *Config) SCIMJITUnmanagedProviders() []string {
	if !c.SCIM.Enabled || !c.SSO.Enabled {
		return nil
	}
	var names []string
	for _, p := range c.SSO.Providers {
		if p.AutoProvision {
			names = append(names, p.Name)
		}
	}
	return names
}

// SCIMJITUnmanagedWarning is the startup, `admin validate` and /system/info line
// for the providers returned by SCIMJITUnmanagedProviders; empty for none.
func SCIMJITUnmanagedWarning(providers []string) string {
	if len(providers) == 0 {
		return ""
	}
	return "SECURITY: scim.enabled together with sso.providers[].auto_provision (" + strings.Join(providers, ", ") +
		"): accounts JIT-created by SSO are not SCIM-managed, so they are not deactivated by SCIM. " +
		"Offboard those users on the IdP/SSO session side; their PATs and sessions survive until expiry. " +
		"A scim_managed column (option B) is the planned fix if this combination is used -- " +
		"see docs/security/threat-models/scim-and-sso-accounts.md (SCIM-7)"
}
