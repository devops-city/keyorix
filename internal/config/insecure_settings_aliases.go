// insecure_settings_aliases.go -- ADR-112 opt-out rule (secure-by-default
// baseline, item 2): every security-weakening setting renamed to the
// insecure_ form keeps its old name working as a deprecated alias, with a
// start-up warning when the old name is used. See
// insecure_settings_registry.go for the full registry this complements.
//
// A plain post-decode presence check (the technique Load() already uses for
// the ADR-112 secure-by-default keys in SecurityConfig) cannot implement an
// alias for a RENAMED struct field: Load()'s decode runs with
// dec.KnownFields(true), which hard-rejects an old key outright as an
// unrecognized field before any Go code of ours ever runs -- exactly the
// "correctly-spelled field in the wrong place" protection KnownFields(true)
// exists for (see Load's own comment), now firing on a key this package
// itself renamed out from under an existing deployment. "Deprecated alias,
// warns when used" requires the old key to still decode successfully, so the
// rewrite has to happen BEFORE that strict decode, not after.
//
// resolveDeprecatedAliases rewrites the raw YAML tree -- translating each
// deprecated old key to its current name -- using a full yaml.Node parse (not
// a Config-typed one, so it can't itself trip KnownFields), then re-marshals
// the rewritten tree back to bytes for Load's existing strict decode to
// process unchanged. The config file on disk is never modified.
package config

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// deprecatedSettingAlias names one ADR-112 rename: a security-weakening
// setting's old dotted YAML path and its current insecure_-prefixed
// replacement. Every entry here is same-polarity (true still means the same
// weakened state under both names) -- a polarity-INVERTING rename (e.g. a
// hypothetical "require_x" -> "insecure_disable_x") is deliberately not
// supported by this simple rewrite-the-key-name mechanism, and none of the
// ADR-112 renames done so far need it; see docs/adr-112-secure-by-default-
// baseline.md and this PR's own NEEDS ANDREI list for the settings left out
// of this table because they would need exactly that (or a non-boolean
// restructuring this mechanism can't express at all).
//
// A segment ending in "[]" names a YAML sequence; the rewrite is applied to
// EVERY element (used for the two settings nested under sso.providers[]).
type deprecatedSettingAlias struct {
	OldPath string
	NewPath string
}

var deprecatedSettingAliases = []deprecatedSettingAlias{
	{"security.allow_unsafe_file_permissions", "security.insecure_allow_unsafe_file_permissions"},
	{"security.login_lockout.disabled", "security.login_lockout.insecure_disable_login_lockout"},
	{"security.recover_admin.keyless_mode", "security.recover_admin.insecure_keyless_admin_recovery"},
	{"audit.siem.allow_private_network_target", "audit.siem.insecure_allow_private_network_siem_target"},
	{"audit.siem.allow_insecure_transport", "audit.siem.insecure_allow_plaintext_siem_transport"},
	{"evidence_delivery.webhook.allow_private_network_target", "evidence_delivery.webhook.insecure_allow_private_network_evidence_target"},
	{"evidence_delivery.webhook.allow_insecure_transport", "evidence_delivery.webhook.insecure_allow_plaintext_evidence_transport"},
	{"notifications.webhook.allow_private_network_target", "notifications.webhook.insecure_allow_private_network_notify_target"},
	{"notifications.webhook.allow_insecure_transport", "notifications.webhook.insecure_allow_plaintext_notify_transport"},
	{"dynamic_secrets.allow_private_network_targets", "dynamic_secrets.insecure_allow_private_network_dynamic_secret_targets"},
	{"dynamic_secrets.allow_insecure_transport", "dynamic_secrets.insecure_allow_plaintext_dynamic_secret_transport"},
	{"storage.encryption.key_provider.kms_allow_context_fallback", "storage.encryption.key_provider.insecure_allow_kms_context_fallback"},
	{"storage.encryption.key_provider.allow_weaker_fallback", "storage.encryption.key_provider.insecure_allow_weaker_kek_fallback"},
	// The fallback chain's OWN copies of the two settings above. Both live on
	// KeyProviderConfig, so `fallbacks:` entries carry them too -- and without
	// these rows the old key under a fallback was never rewritten and then hit
	// Load's KnownFields(true) as an unrecognized field, i.e. a HARD boot
	// failure instead of the promised deprecation warning. Found by the
	// coordinator's review of #2454 (non-blocking finding, fixed here with the
	// rename it belongs to). One level only, matching keyProviderChain and
	// internal/keyfiles.Registry: a fallback's own nested `fallbacks` is never
	// read by buildSingleProvider, so it is not a live configuration shape.
	{"storage.encryption.key_provider.fallbacks[].kms_allow_context_fallback", "storage.encryption.key_provider.fallbacks[].insecure_allow_kms_context_fallback"},
	{"storage.encryption.key_provider.fallbacks[].allow_weaker_fallback", "storage.encryption.key_provider.fallbacks[].insecure_allow_weaker_kek_fallback"},
	{"sso.providers[].trust_asserted_email", "sso.providers[].insecure_trust_saml_asserted_email"},
	{"sso.providers[].saml.allow_idp_initiated", "sso.providers[].saml.insecure_allow_idp_initiated_saml"},
	{"audit_checkpoints.disabled", "audit_checkpoints.insecure_disable_audit_checkpoints"},
}

// mapGet returns the key and value nodes for key in mapping node m, or
// (nil, nil) if m isn't a mapping or has no such key.
func mapGet(m *yaml.Node, key string) (*yaml.Node, *yaml.Node) {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil, nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i], m.Content[i+1]
		}
	}
	return nil, nil
}

// mapDelete removes key (and its value) from mapping node m, if present.
func mapDelete(m *yaml.Node, key string) {
	if m == nil || m.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			return
		}
	}
}

// walkToParents calls fn once for every mapping node that directly contains
// path's final segment, descending through path's earlier segments from
// root. More than one call happens only when path crosses a "[]" (sequence)
// segment -- one call per sequence element. A missing intermediate key, or a
// node that isn't the kind path expects, simply yields zero calls (no error:
// resolveDeprecatedAliases treats "nothing to rewrite" and "malformed
// document" identically, since the real strict decode after it is the one
// place a malformed document is supposed to be reported).
func walkToParents(root *yaml.Node, path []string, fn func(parent *yaml.Node)) {
	cur := root
	for i, seg := range path {
		if i == len(path)-1 {
			fn(cur)
			return
		}
		if strings.HasSuffix(seg, "[]") {
			_, seq := mapGet(cur, strings.TrimSuffix(seg, "[]"))
			if seq == nil || seq.Kind != yaml.SequenceNode {
				return
			}
			for _, item := range seq.Content {
				walkToParents(item, path[i+1:], fn)
			}
			return
		}
		_, next := mapGet(cur, seg)
		if next == nil {
			return
		}
		cur = next
	}
}

// resolveDeprecatedAliases rewrites data's YAML tree so every deprecated key
// in deprecatedSettingAliases that's actually present is translated to its
// current name before Load's strict, KnownFields(true) decode ever sees it.
// Returns the rewritten bytes (data unchanged if nothing was rewritten) and
// one warning string per deprecated key found. A parse error here is NOT
// reported -- data is returned unchanged and the real strict decode
// immediately after this call reports the real parse error with its own
// (already well-tested) error message.
func resolveDeprecatedAliases(data []byte) ([]byte, []string) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil || len(root.Content) == 0 {
		return data, nil
	}
	doc := root.Content[0]
	var warnings []string
	changed := false
	for _, alias := range deprecatedSettingAliases {
		oldSegs := strings.Split(alias.OldPath, ".")
		newSegs := strings.Split(alias.NewPath, ".")
		oldLeaf := oldSegs[len(oldSegs)-1]
		newLeaf := newSegs[len(newSegs)-1]
		walkToParents(doc, oldSegs, func(parent *yaml.Node) {
			oldKeyNode, _ := mapGet(parent, oldLeaf)
			if oldKeyNode == nil {
				return
			}
			changed = true
			if newKeyNode, _ := mapGet(parent, newLeaf); newKeyNode != nil {
				warnings = append(warnings, fmt.Sprintf(
					"both the deprecated %q and its replacement %q are set; %q wins -- remove the deprecated key",
					alias.OldPath, alias.NewPath, alias.NewPath))
				mapDelete(parent, oldLeaf)
				return
			}
			warnings = append(warnings, fmt.Sprintf(
				"%q is deprecated, use %q instead (same meaning, no behavior change)",
				alias.OldPath, alias.NewPath))
			oldKeyNode.Value = newLeaf
		})
	}
	if !changed {
		return data, warnings
	}
	out, err := yaml.Marshal(&root)
	if err != nil {
		return data, warnings
	}
	return out, warnings
}
