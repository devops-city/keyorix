// insecure_settings_registry.go -- ADR-112 opt-out rule (secure-by-default
// baseline, item 2): the single registry of every security-weakening
// setting this codebase knows about. Three things read this registry:
//   - server/main.go logs a start-up warning for every entry currently
//     InEffect.
//   - server/main.go computes a SecurityPostureSnapshot and hands it to
//     internal/core's ReconcileSecurityPostureSnapshot, which diffs it
//     against the previous start's snapshot and audits any change.
//   - The future posture report (item 4) lists every InEffect entry as a
//     deviation.
//
// Each entry's Name is the setting's canonical insecure_-prefixed path. It is
// the IDENTIFIER the warning, the audit trail and the posture report use, and
// it is deliberately independent of what the YAML key is called today:
//
//   - Sixteen settings have been renamed to their insecure_ name (#2899), each
//     keeping the old key working as a warning-logging deprecated alias
//     (insecure_settings_aliases.go; DeprecatedAlias below names it). Every
//     other entry is derived-only: Name is the target name, SourcePaths is
//     what the config file actually says today.
//   - Thirteen of them cannot be renamed mechanically at all, and are recorded
//     here as KNOWN EXCEPTIONS rather than left out: each needs either a
//     polarity inversion of a load-bearing flag, or a non-boolean field (an
//     enum string, an empty-string sentinel, a negative-number sentinel)
//     restructured into a real boolean. Those are product decisions, not
//     mechanical edits. They are listed, with their current name, proposed
//     name and the shape change each needs, in #2895 (rows 1-13; its row 14,
//     sso.providers[].trust_asserted_email, was mechanically renameable and is
//     now sso.providers[].insecure_trust_saml_asserted_email) -- and they are fully
//     covered by the warning + audit + posture mechanisms under their CURRENT
//     names in the meantime, so none of this is invisible while it waits.
//
// SourcePaths is what makes the registry checkable against reality rather than
// self-referential: it ties each entry to the real config field(s) its InEffect
// reads, so insecure_settings_sweep_test.go can sweep Config's whole YAML
// surface and fail on a security-weakening setting that has no entry. Without
// it, a registry of synthetic insecure_ names would pass its own structural
// test no matter what the config struct grew next to it.
package config

// InsecureSetting is one entry in the ADR-112 opt-out-rule registry.
type InsecureSetting struct {
	// Name is this setting's canonical insecure_-prefixed dotted path --
	// used in the registry's own structural test, the start-up warning, and
	// the posture snapshot's keys. Stable across a future literal YAML
	// rename (DeprecatedAlias going from "" to a real old path never
	// changes Name), so the audit trail's setting identifiers never churn.
	Name string
	// SourcePaths are the REAL dotted YAML path(s) in Config that this
	// entry's InEffect/Value actually read -- the current names, not Name's
	// target name. Never empty.
	//
	// This is the registry's link to the config surface, and the thing
	// insecure_settings_sweep_test.go sweeps against: a weakening setting
	// present in Config but absent from every entry's SourcePaths fails that
	// test, and a SourcePaths entry naming a field that does not exist fails
	// it too (so the list cannot rot as fields are renamed or removed).
	//
	// More than one path when one logical weakening is spelled across
	// several fields -- e.g. insecure_allow_unauthenticated_metrics is in
	// effect if EITHER server.http.metrics_token or server.grpc.metrics_token
	// is empty, and both must be swept as covered.
	SourcePaths []string
	// DerivedInputs names the derived (yaml:"-") Config fields this entry's
	// InEffect/Value also read, as section.GoFieldName (e.g.
	// "security.EnableFilePermissionCheckUpgradeGrace"). They are set by
	// Load() or at boot, never by the config file, so the YAML sweep cannot
	// see them; insecure_settings_sweep_test.go's derived-field ratchet
	// requires every such field to be claimed here or exempted with a reason
	// (#2908: the grace-period state was invisible exactly because it lives in
	// one). Empty for an entry that reads only its SourcePaths.
	DerivedInputs []string
	// DeprecatedAlias is the old dotted YAML path this setting was renamed
	// from, or "" when it was already compliant (ships with an insecure_
	// name already) or has not been renamed (a derived-only entry, including
	// the thirteen known exceptions). Set for the sixteen renamed settings;
	// TestInsecureSettingsRegistry_DeprecatedAliasesMatchAliasTable keeps it in
	// step with deprecatedSettingAliases.
	DeprecatedAlias string
	// Describe is a one-line, human-readable explanation of what being in
	// effect actually weakens, for the start-up warning and (eventually)
	// the posture report.
	Describe string
	// InEffect reports whether the weak state is active right now.
	InEffect func(*Config) bool
	// Value returns a short string form of the setting's current value, for
	// the start-to-start settings diff. Boolean-shaped for every entry here
	// ("true"/"false") since this item is explicitly scoped to boolean
	// settings; a future numeric/enum entry would still fit this shape.
	Value func(*Config) string
}

// boolStr renders a bool the same way for every registry entry's Value, so
// the settings-diff snapshot's string values are consistent across entries.
func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// keyProviderChain returns enc's primary key provider followed by its
// Fallbacks, in try-order -- the same list buildKeyProvider (internal/
// encryption/service.go) actually constructs a provider for. Settings on
// KeyProviderConfig (insecure_allow_kms_context_fallback,
// insecure_allow_weaker_kek_fallback, the Shamir commitment check) can be
// set on ANY entry in this chain, not just the primary, so "in effect" must
// check all of them -- one level of Fallbacks only, matching
// internal/keyfiles.Registry's identical, already-established choice (that
// package's own doc comment: "Fallbacks' own nested Fallbacks field is never
// read by buildSingleProvider either, so it is not a live configuration
// shape").
func keyProviderChain(enc *EncryptionConfig) []KeyProviderConfig {
	chain := make([]KeyProviderConfig, 0, 1+len(enc.KeyProvider.Fallbacks))
	chain = append(chain, enc.KeyProvider)
	chain = append(chain, enc.KeyProvider.Fallbacks...)
	return chain
}

// anyKeyProviderInEffect reports whether pred holds for any provider in cfg's
// key-provider chain.
func anyKeyProviderInEffect(cfg *Config, pred func(KeyProviderConfig) bool) bool {
	for _, kp := range keyProviderChain(&cfg.Storage.Encryption) {
		if pred(kp) {
			return true
		}
	}
	return false
}

// anySSOProviderInEffect reports whether pred holds for any configured SSO
// provider -- "in effect" for a per-provider setting means at least one
// provider actually has the weak state active, the same way a single
// insecure listener among several makes checkTransportTLSPosture's overall
// cleartext warning fire.
func anySSOProviderInEffect(cfg *Config, pred func(SSOProviderConfig) bool) bool {
	for _, p := range cfg.SSO.Providers {
		if pred(p) {
			return true
		}
	}
	return false
}

// InsecureSettingsRegistry is the single, shared enumeration every ADR-112
// opt-out-rule consumer (start-up warnings, the settings-diff audit, the
// future posture report) reads instead of hand-rolling its own list.
var InsecureSettingsRegistry = []InsecureSetting{
	// -- Mechanically renameable: a straight key rename, no polarity flip and no
	//    shape change. NOT renamed here (Andrei's split puts renames in follow-up
	//    PRs); listed under their target Name, swept via their current SourcePaths. --
	{
		Name:            "security.insecure_allow_unsafe_file_permissions",
		SourcePaths:     []string{"security.insecure_allow_unsafe_file_permissions"},
		DeprecatedAlias: "security.allow_unsafe_file_permissions",
		Describe:        "lets group/other-readable key material pass enforceKeyFilePermissions/ValidateStartup instead of failing closed",
		InEffect:        func(c *Config) bool { return c.Security.AllowUnsafeFilePermissions },
		Value:           func(c *Config) string { return boolStr(c.Security.AllowUnsafeFilePermissions) },
	},
	{
		Name:            "security.login_lockout.insecure_disable_login_lockout",
		SourcePaths:     []string{"security.login_lockout.insecure_disable_login_lockout"},
		DeprecatedAlias: "security.login_lockout.disabled",
		Describe:        "removes per-account brute-force lockout protection",
		InEffect:        func(c *Config) bool { return c.Security.LoginLockout.Disabled },
		Value:           func(c *Config) string { return boolStr(c.Security.LoginLockout.Disabled) },
	},
	{
		Name:            "security.recover_admin.insecure_keyless_admin_recovery",
		SourcePaths:     []string{"security.recover_admin.insecure_keyless_admin_recovery"},
		DeprecatedAlias: "security.recover_admin.keyless_mode",
		Describe:        "lets `recover-admin` restore any admin on host access alone, with no recovery key",
		InEffect:        func(c *Config) bool { return c.Security.RecoverAdmin.KeylessMode },
		Value:           func(c *Config) string { return boolStr(c.Security.RecoverAdmin.KeylessMode) },
	},
	{
		Name:            "audit.siem.insecure_allow_private_network_siem_target",
		SourcePaths:     []string{"audit.siem.insecure_allow_private_network_siem_target"},
		DeprecatedAlias: "audit.siem.allow_private_network_target",
		Describe:        "disables the SSRF guard on the SIEM forwarder's endpoint",
		InEffect:        func(c *Config) bool { return c.Audit.SIEM.AllowPrivateNetworkTarget },
		Value:           func(c *Config) string { return boolStr(c.Audit.SIEM.AllowPrivateNetworkTarget) },
	},
	{
		Name:            "audit.siem.insecure_allow_plaintext_siem_transport",
		SourcePaths:     []string{"audit.siem.insecure_allow_plaintext_siem_transport"},
		DeprecatedAlias: "audit.siem.allow_insecure_transport",
		Describe:        "permits a plaintext (non-TLS) SIEM forwarder endpoint",
		InEffect:        func(c *Config) bool { return c.Audit.SIEM.AllowInsecureTransport },
		Value:           func(c *Config) string { return boolStr(c.Audit.SIEM.AllowInsecureTransport) },
	},
	{
		Name:            "evidence_delivery.webhook.insecure_allow_private_network_evidence_target",
		SourcePaths:     []string{"evidence_delivery.webhook.insecure_allow_private_network_evidence_target"},
		DeprecatedAlias: "evidence_delivery.webhook.allow_private_network_target",
		Describe:        "disables the SSRF guard on the evidence-delivery webhook's endpoint",
		InEffect:        func(c *Config) bool { return c.EvidenceDelivery.Webhook.AllowPrivateNetworkTarget },
		Value:           func(c *Config) string { return boolStr(c.EvidenceDelivery.Webhook.AllowPrivateNetworkTarget) },
	},
	{
		Name:            "evidence_delivery.webhook.insecure_allow_plaintext_evidence_transport",
		SourcePaths:     []string{"evidence_delivery.webhook.insecure_allow_plaintext_evidence_transport"},
		DeprecatedAlias: "evidence_delivery.webhook.allow_insecure_transport",
		Describe:        "permits a plaintext (non-TLS) evidence-delivery webhook endpoint",
		InEffect:        func(c *Config) bool { return c.EvidenceDelivery.Webhook.AllowInsecureTransport },
		Value:           func(c *Config) string { return boolStr(c.EvidenceDelivery.Webhook.AllowInsecureTransport) },
	},
	{
		Name:            "notifications.webhook.insecure_allow_private_network_notify_target",
		SourcePaths:     []string{"notifications.webhook.insecure_allow_private_network_notify_target"},
		DeprecatedAlias: "notifications.webhook.allow_private_network_target",
		Describe:        "disables the SSRF guard on the notification webhook's endpoint",
		InEffect:        func(c *Config) bool { return c.Notifications.Webhook.AllowPrivateNetworkTarget },
		Value:           func(c *Config) string { return boolStr(c.Notifications.Webhook.AllowPrivateNetworkTarget) },
	},
	{
		Name:            "notifications.webhook.insecure_allow_plaintext_notify_transport",
		SourcePaths:     []string{"notifications.webhook.insecure_allow_plaintext_notify_transport"},
		DeprecatedAlias: "notifications.webhook.allow_insecure_transport",
		Describe:        "permits a plaintext (non-TLS) notification webhook endpoint",
		InEffect:        func(c *Config) bool { return c.Notifications.Webhook.AllowInsecureTransport },
		Value:           func(c *Config) string { return boolStr(c.Notifications.Webhook.AllowInsecureTransport) },
	},
	{
		Name:            "dynamic_secrets.insecure_allow_private_network_dynamic_secret_targets",
		SourcePaths:     []string{"dynamic_secrets.insecure_allow_private_network_dynamic_secret_targets"},
		DeprecatedAlias: "dynamic_secrets.allow_private_network_targets",
		Describe:        "disables the SSRF guard on dynamic-secret backend DSNs (Postgres/MySQL/Mongo/Redis)",
		InEffect:        func(c *Config) bool { return c.DynamicSecrets.AllowPrivateNetworkTargets },
		Value:           func(c *Config) string { return boolStr(c.DynamicSecrets.AllowPrivateNetworkTargets) },
	},
	{
		Name:            "dynamic_secrets.insecure_allow_plaintext_dynamic_secret_transport",
		SourcePaths:     []string{"dynamic_secrets.insecure_allow_plaintext_dynamic_secret_transport"},
		DeprecatedAlias: "dynamic_secrets.allow_insecure_transport",
		Describe:        "disables the required-TLS guard for mongodb/redis dynamic-secret backends",
		InEffect:        func(c *Config) bool { return c.DynamicSecrets.AllowInsecureTransport },
		Value:           func(c *Config) string { return boolStr(c.DynamicSecrets.AllowInsecureTransport) },
	},
	{
		Name:            "storage.encryption.key_provider.insecure_allow_kms_context_fallback",
		SourcePaths:     []string{"storage.encryption.key_provider.insecure_allow_kms_context_fallback", "storage.encryption.key_provider.fallbacks.insecure_allow_kms_context_fallback"},
		DeprecatedAlias: "storage.encryption.key_provider.kms_allow_context_fallback",
		Describe:        "lets a context-bound KMS-wrapped KEK fall back to decrypting with no context",
		InEffect: func(c *Config) bool {
			return anyKeyProviderInEffect(c, func(kp KeyProviderConfig) bool { return kp.KMSAllowContextFallback })
		},
		Value: func(c *Config) string {
			return boolStr(anyKeyProviderInEffect(c, func(kp KeyProviderConfig) bool { return kp.KMSAllowContextFallback }))
		},
	},
	{
		Name:            "storage.encryption.key_provider.insecure_allow_weaker_kek_fallback",
		SourcePaths:     []string{"storage.encryption.key_provider.insecure_allow_weaker_kek_fallback", "storage.encryption.key_provider.fallbacks.insecure_allow_weaker_kek_fallback"},
		DeprecatedAlias: "storage.encryption.key_provider.allow_weaker_fallback",
		Describe:        "permits a key-provider fallback chain that silently downgrades KEK-sourcing strength",
		InEffect: func(c *Config) bool {
			return anyKeyProviderInEffect(c, func(kp KeyProviderConfig) bool { return kp.AllowWeakerFallback })
		},
		Value: func(c *Config) string {
			return boolStr(anyKeyProviderInEffect(c, func(kp KeyProviderConfig) bool { return kp.AllowWeakerFallback }))
		},
	},
	{
		Name:            "sso.providers.insecure_trust_saml_asserted_email",
		SourcePaths:     []string{"sso.providers.insecure_trust_saml_asserted_email"},
		DeprecatedAlias: "sso.providers[].trust_asserted_email",
		Describe:        "treats a SAML provider's self-asserted email as verified for account-linking (account-takeover risk)",
		InEffect: func(c *Config) bool {
			return anySSOProviderInEffect(c, func(p SSOProviderConfig) bool { return p.TrustAssertedEmail })
		},
		Value: func(c *Config) string {
			return boolStr(anySSOProviderInEffect(c, func(p SSOProviderConfig) bool { return p.TrustAssertedEmail }))
		},
	},
	{
		Name:            "sso.providers.saml.insecure_allow_idp_initiated_saml",
		SourcePaths:     []string{"sso.providers.saml.insecure_allow_idp_initiated_saml"},
		DeprecatedAlias: "sso.providers[].saml.allow_idp_initiated",
		Describe:        "accepts SAML responses with no InResponseTo, losing CSRF/replay protection (validateSSOIDPInitiated already refuses this at boot -- see its own doc comment)",
		InEffect: func(c *Config) bool {
			return anySSOProviderInEffect(c, func(p SSOProviderConfig) bool { return p.SAML != nil && p.SAML.AllowIDPInitiated })
		},
		Value: func(c *Config) string {
			return boolStr(anySSOProviderInEffect(c, func(p SSOProviderConfig) bool { return p.SAML != nil && p.SAML.AllowIDPInitiated }))
		},
	},
	{
		Name:            "audit_checkpoints.insecure_disable_audit_checkpoints",
		SourcePaths:     []string{"audit_checkpoints.insecure_disable_audit_checkpoints"},
		DeprecatedAlias: "audit_checkpoints.disabled",
		Describe:        "leaves the audit trail only tamper-evident, not forgery-resistant (no signed checkpoints)",
		InEffect:        func(c *Config) bool { return c.AuditCheckpoints.Disabled },
		Value:           func(c *Config) string { return boolStr(c.AuditCheckpoints.Disabled) },
	},

	// -- Already compliant: ships with an insecure_ name, nothing to rename --
	{
		Name:        "audit.siem.insecure_skip_verify",
		SourcePaths: []string{"audit.siem.insecure_skip_verify"},
		Describe:    "disables TLS certificate verification to the SIEM endpoint",
		InEffect:    func(c *Config) bool { return c.Audit.SIEM.InsecureSkipVerify },
		Value:       func(c *Config) string { return boolStr(c.Audit.SIEM.InsecureSkipVerify) },
	},
	{
		Name:        "evidence_delivery.webhook.insecure_skip_verify",
		SourcePaths: []string{"evidence_delivery.webhook.insecure_skip_verify"},
		Describe:    "disables TLS certificate verification to the evidence-delivery webhook endpoint",
		InEffect:    func(c *Config) bool { return c.EvidenceDelivery.Webhook.InsecureSkipVerify },
		Value:       func(c *Config) string { return boolStr(c.EvidenceDelivery.Webhook.InsecureSkipVerify) },
	},
	{
		Name:        "notifications.webhook.insecure_skip_verify",
		SourcePaths: []string{"notifications.webhook.insecure_skip_verify"},
		Describe:    "disables TLS certificate verification to the notification webhook endpoint",
		InEffect:    func(c *Config) bool { return c.Notifications.Webhook.InsecureSkipVerify },
		Value:       func(c *Config) string { return boolStr(c.Notifications.Webhook.InsecureSkipVerify) },
	},
	{
		// ADR-112 Amendment 1 (fast audit mode), landed on main after this
		// registry was written. Postgres-only; a SQLite backend refuses it.
		Name:        "storage.database.insecure_audit_skip_durable_sync",
		SourcePaths: []string{"storage.database.insecure_audit_skip_durable_sync"},
		Describe:    "audit writes no longer wait for the disk sync: an OS or database crash can lose a tail of audit entries (~600ms)",
		InEffect:    func(c *Config) bool { return c.Storage.Database.InsecureAuditSkipDurableSync },
		Value:       func(c *Config) string { return boolStr(c.Storage.Database.InsecureAuditSkipDurableSync) },
	},

	// -- The thirteen KNOWN EXCEPTIONS (#2895 rows 1-13; its row 14,
	//    trust_asserted_email, is renameable and registered above). Each
	//    needs a product decision, not a mechanical edit: a polarity
	//    inversion of a load-bearing flag, or a non-boolean field (enum
	//    string / empty-string sentinel / negative-number sentinel)
	//    restructured into a real boolean. Recorded here, not omitted, so
	//    each is covered by the start-up warning, the settings-diff audit and
	//    the posture report under its CURRENT name while it waits -- and so
	//    the sweep in insecure_settings_sweep_test.go counts them as covered
	//    rather than as unlisted gaps. Enumerated with their proposed names
	//    and shape changes in #2895. --
	{
		Name:        "security.insecure_allow_cleartext_transport",
		SourcePaths: []string{"security.require_transport_tls"},
		Describe:    "allows bearer tokens/secret values over cleartext HTTP/gRPC",
		InEffect:    func(c *Config) bool { return !c.Security.RequireTransportTLS },
		Value:       func(c *Config) string { return boolStr(!c.Security.RequireTransportTLS) },
	},
	// #2908: not a boolean. During the ADR-112 upgrade grace period the field
	// reads true while the server only WARNS about a failed startup check, so
	// InEffect/Value read StartupValidationState (off / grace-warn-only /
	// enforcing-implicit / enforcing-explicit) and both weak states count.
	// The grace state is decided from the database at boot
	// (EnableFilePermissionCheckUpgradeGrace), so every consumer must evaluate
	// this entry AFTER applyADR112UpgradeGrace (server) or the posture
	// report's own grace lookup (server/admin) -- DerivedInputs records that.
	{
		Name:          "security.insecure_skip_startup_validation",
		SourcePaths:   []string{"security.enable_file_permission_check"},
		DerivedInputs: []string{"security.EnableFilePermissionCheckImplicitDefault", "security.EnableFilePermissionCheckUpgradeGrace"},
		Describe:      "the file-permission/DEK-salt-size/database-reachability startup checks are skipped (off) or, in the ADR-112 upgrade grace period (grace-warn-only), only warn instead of refusing to start",
		InEffect:      func(c *Config) bool { return c.Security.StartupValidationState().Weakened() },
		Value:         func(c *Config) string { return string(c.Security.StartupValidationState()) },
	},
	// #2986: not a boolean. An explicit require_mfa: false is "off"; an
	// upgraded deployment that never set the key is "grace-not-enforced"
	// (applyADR112UpgradeGrace sets RequireMFA false for the boot). Both count.
	// The grace state is decided from the database, so every consumer must
	// evaluate this entry AFTER applyADR112UpgradeGrace (server) or
	// collectRequireMFAPosture (server/admin) -- DerivedInputs records that.
	{
		Name:          "security.insecure_disable_mfa_requirement",
		SourcePaths:   []string{"security.require_mfa"},
		DerivedInputs: []string{"security.RequireMFAImplicitDefault", "security.RequireMFAUpgradeGrace"},
		Describe:      "interactive logins do not require a second factor: off (require_mfa: false written in the config) or, in the ADR-112 upgrade grace period (grace-not-enforced), not enforced yet",
		InEffect:      func(c *Config) bool { return c.Security.RequireMFAState().Weakened() },
		Value:         func(c *Config) string { return string(c.Security.RequireMFAState()) },
	},
	{
		Name:        "storage.encryption.key_provider.insecure_omit_shamir_commitment_check",
		SourcePaths: []string{"storage.encryption.key_provider.shamir_commitment"},
		Describe:    "Shamir KEK reconstruction falls back to a forgeable magic-byte check only",
		InEffect: func(c *Config) bool {
			return anyKeyProviderInEffect(c, func(kp KeyProviderConfig) bool { return kp.Type == "shamir" && kp.ShamirCommitment == "" })
		},
		Value: func(c *Config) string {
			return boolStr(anyKeyProviderInEffect(c, func(kp KeyProviderConfig) bool { return kp.Type == "shamir" && kp.ShamirCommitment == "" }))
		},
	},
	{
		Name:        "storage.encryption.insecure_disable_encryption_at_rest",
		SourcePaths: []string{"storage.encryption.enabled"},
		Describe:    "secrets stored unencrypted at rest",
		InEffect:    func(c *Config) bool { return !c.Storage.Encryption.Enabled },
		Value:       func(c *Config) string { return boolStr(!c.Storage.Encryption.Enabled) },
	},
	{
		Name:        "membership.insecure_skip_membership_review",
		SourcePaths: []string{"membership.validation_mode"},
		Describe:    "new members become active immediately, skipping admin review",
		InEffect:    func(c *Config) bool { return c.Membership.ValidationMode == "open" },
		Value:       func(c *Config) string { return boolStr(c.Membership.ValidationMode == "open") },
	},
	{
		Name:        "sso.providers.insecure_auto_provision_sso_users",
		SourcePaths: []string{"sso.providers.auto_provision"},
		Describe:    "JIT-creates an SSO account with no admin step",
		InEffect: func(c *Config) bool {
			return anySSOProviderInEffect(c, func(p SSOProviderConfig) bool { return p.AutoProvision })
		},
		Value: func(c *Config) string {
			return boolStr(anySSOProviderInEffect(c, func(p SSOProviderConfig) bool { return p.AutoProvision }))
		},
	},
	{
		Name:        "sso.providers.insecure_auto_sync_sso_groups",
		SourcePaths: []string{"sso.providers.group_sync"},
		Describe:    "IdP group claims silently change native role membership every login",
		InEffect: func(c *Config) bool {
			return anySSOProviderInEffect(c, func(p SSOProviderConfig) bool { return p.GroupSync })
		},
		Value: func(c *Config) string {
			return boolStr(anySSOProviderInEffect(c, func(p SSOProviderConfig) bool { return p.GroupSync }))
		},
	},
	// metrics_token_file (SECURE-DEFAULT-1) is the same setting supplied from a
	// file; an unreadable file counts as no token (metricsTokenMissing).
	{
		Name:        "server.insecure_allow_unauthenticated_metrics",
		SourcePaths: []string{"server.http.metrics_token", "server.grpc.metrics_token", "server.http.metrics_token_file", "server.grpc.metrics_token_file"},
		Describe:    "/metrics served fully unauthenticated",
		InEffect:    func(c *Config) bool { return c.metricsTokenMissing() },
		Value:       func(c *Config) string { return boolStr(c.metricsTokenMissing()) },
	},
	{
		Name:        "server.insecure_disable_max_request_body_cap",
		SourcePaths: []string{"server.http.max_request_body_bytes", "server.grpc.max_request_body_bytes"},
		Describe:    "removes the request-body size cap entirely (DoS)",
		InEffect: func(c *Config) bool {
			return c.Server.HTTP.MaxRequestBodyBytes < 0 || c.Server.GRPC.MaxRequestBodyBytes < 0
		},
		Value: func(c *Config) string {
			return boolStr(c.Server.HTTP.MaxRequestBodyBytes < 0 || c.Server.GRPC.MaxRequestBodyBytes < 0)
		},
	},
	{
		Name:        "storage.database.insecure_disable_database_tls",
		SourcePaths: []string{"storage.database.ssl_mode"},
		Describe:    "Postgres connection unencrypted",
		InEffect:    func(c *Config) bool { return c.Storage.Database.SSLMode == "disable" },
		Value:       func(c *Config) string { return boolStr(c.Storage.Database.SSLMode == "disable") },
	},
	{
		Name:        "server.insecure_disable_api_ratelimit",
		SourcePaths: []string{"server.http.ratelimit.enabled", "server.grpc.ratelimit.enabled"},
		Describe:    "removes per-principal API rate limiting",
		InEffect:    func(c *Config) bool { return !c.Server.HTTP.RateLimit.Enabled || !c.Server.GRPC.RateLimit.Enabled },
		Value: func(c *Config) string {
			return boolStr(!c.Server.HTTP.RateLimit.Enabled || !c.Server.GRPC.RateLimit.Enabled)
		},
	},
	{
		Name:        "credential_delivery.insecure_allow_log_delivery",
		SourcePaths: []string{"credential_delivery.mode"},
		Describe:    "writes a usable account-setup link to the application log",
		InEffect:    func(c *Config) bool { return c.CredentialDelivery.Mode == "log" },
		Value:       func(c *Config) string { return boolStr(c.CredentialDelivery.Mode == "log") },
	},
	{
		Name:        "credential_delivery.insecure_allow_plaintext_smtp",
		SourcePaths: []string{"credential_delivery.smtp.tls", "notifications.email.tls"},
		Describe:    "sends setup/notification mail over cleartext SMTP",
		InEffect: func(c *Config) bool {
			return c.CredentialDelivery.SMTP.TLS == "none" || c.Notifications.Email.TLS == "none"
		},
		Value: func(c *Config) string {
			return boolStr(c.CredentialDelivery.SMTP.TLS == "none" || c.Notifications.Email.TLS == "none")
		},
	},
}
