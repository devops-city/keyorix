package main

import (
	"fmt"
	"log"
	"slices"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
)

// logWarnOnImplicitRequireMFADefault logs where security.require_mfa stands when the
// config file never set it (ADR-112 resolves an absent key to true;
// RequireMFAImplicitDefault is true only then).
//
// On a fresh install (or a deployment already enforced once) MFA is enforced and this is
// informational: server/middleware.EnforceAccountSetup confines a session-authenticated
// user without MFA to the enrolment endpoints (never locks the account out; PAT/machine
// credentials are exempt). On an upgraded deployment, applyADR112UpgradeGrace has put
// require_mfa in ADR-112's grace period (RequireMFAUpgradeGrace): MFA is NOT enforced yet,
// and this warns loudly on every boot, with the days left, until the grace period ends
// (first admin MFA enrolment or the 30-day deadline, #2923) or the key is set explicitly.
func logWarnOnImplicitRequireMFADefault(cfg *config.Config) {
	sec := cfg.Security
	switch {
	case sec.RequireMFAUpgradeGrace:
		deadline := adr112MFAWindow.Deadline
		days := int((deadline.Sub(adr112MFAWindow.Floor) + 24*time.Hour - 1) / (24 * time.Hour))
		log.Printf("WARNING: ADR-112 grace period: security.require_mfa now defaults to true, but %s and this config never set it, so MFA is NOT enforced yet: %d day(s) left. It is enforced at %s, or as soon as the first administrator enrols a second factor, whichever comes first; users without MFA are then sent to MFA enrolment when they sign in (they are not locked out). Have every interactive admin enrol now (keyorix mfa enroll / activate, or Profile -> Security in the web UI), or set security.require_mfa explicitly (true to enforce now, false to opt out visibly).", adr112MFAReason, days, deadline.UTC().Format(time.RFC3339))
	case sec.RequireMFA && sec.RequireMFAImplicitDefault:
		reason := adr112MFAReason
		if reason == "" {
			reason = "the key is not set in this config"
		}
		log.Printf("INFO: security.require_mfa is enforcing on its ADR-112 secure-by-default value (%s). Session-authenticated users without MFA are confined to MFA enrolment until they enrol (PAT/machine credentials are unaffected). Set security.require_mfa explicitly to silence this.", reason)
	}
}

// warnDeprecatedSettingAliases logs every ADR-112 deprecated-alias key (an old
// name config.Load translated to its current insecure_ form) found in this
// config file — "deprecated alias, warns when used" (opt-out rule item 2)
// means the old key still works exactly as before, but is never silent about it.
func warnDeprecatedSettingAliases(cfg *config.Config) {
	for _, w := range cfg.DeprecatedSettingWarnings {
		log.Printf("WARNING: deprecated config key: %s", w)
	}
}

// warnHTTPOnlySettingsUnderGRPC logs a start-up warning for every security setting
// written under server.grpc that only the HTTP server implements (the two
// listeners share one config struct). The gRPC server has no client-IP rewrite and
// sends no HSTS, so these keys would otherwise be accepted and silently do nothing.
// The loader does not reject other HTTP-only keys under grpc either, so this warns
// rather than failing the boot.
func warnHTTPOnlySettingsUnderGRPC(cfg *config.Config) {
	for _, w := range config.HTTPOnlySettingsSetUnderGRPC(cfg) {
		log.Printf("WARNING: %s", w)
	}
}

// warnInsecureSettingsInEffect logs a start-up warning for every ADR-112
// registry entry currently in effect — unconditionally, on every boot, so a
// security-weakening setting can never be silently in effect (opt-out rule
// item 2's "a start-up warning for every insecure_ setting in effect").
// Looping config.InsecureSettingsRegistry here is also half of what makes
// TestInsecureSettingsRegistry_EveryEntryHasThePrefixWarningAndAuditHook's
// guarantee hold: every entry with a non-nil InEffect is warned about by
// construction, with no per-entry call site that could forget to wire one in.
func warnInsecureSettingsInEffect(cfg *config.Config) {
	for _, s := range config.InsecureSettingsRegistry {
		if s.InEffect(cfg) {
			log.Print(insecureSettingWarning(s, cfg))
		}
	}
}

// insecureSettingWarning is the start-up line for one registry entry in effect.
// Name is a stable identifier, not always a key an operator can set today:
// when it is not one of SourcePaths, the line says so and names the key that
// actually controls the state (Cause, or the SourcePaths), so nobody writes
// the registry name into keyorix.yaml and gets an unknown-key error
// (BOOT-REFUSALS-1 item 3).
func insecureSettingWarning(s config.InsecureSetting, cfg *config.Config) string {
	if slices.Contains(s.SourcePaths, s.Name) {
		return fmt.Sprintf("WARNING: %s is in effect (%s; config: %s) — %s", s.Name, s.Value(cfg), strings.Join(s.SourcePaths, ", "), s.Describe)
	}
	cause := "it follows " + strings.Join(s.SourcePaths, ", ")
	if s.Cause != nil {
		cause = s.Cause(cfg)
	}
	return fmt.Sprintf("WARNING: %s is in effect (%s) — %s. That is the setting's registry name, not a config key: %s", s.Name, s.Value(cfg), s.Describe, cause)
}

// resolveADR112BootPosture applies the ADR-112 upgrade-grace decision and THEN
// warns about every registry entry in effect. The order is the point (#2908):
// security.insecure_skip_startup_validation's grace-warn-only state is read
// from EnableFilePermissionCheckUpgradeGrace, which only
// applyADR112UpgradeGrace sets. Warning first -- main's order before #2908 --
// evaluated that entry with the flag still false, so a grace-period
// deployment that only warns on a failed startup check got no opt-out warning.
func resolveADR112BootPosture(cfg *config.Config) {
	applyADR112UpgradeGrace(cfg)
	warnInsecureSettingsInEffect(cfg)
}

// securityPostureSnapshot computes this boot's value of every ADR-112
// registry entry, keyed by its Name — the input to
// coreService.ReconcileSecurityPostureSnapshot's start-to-start diff. Looping
// config.InsecureSettingsRegistry here is the other half of
// TestInsecureSettingsRegistry_EveryEntryHasThePrefixWarningAndAuditHook's
// guarantee: every entry with a non-nil Value is audited by construction.
//
// config.TrackedSettings (settings that are never a deviation, such as
// storage.database.audit_durability) are diffed the same way, so a change of
// one between two starts is audited with its old and new value.
func securityPostureSnapshot(cfg *config.Config) map[string]string {
	snapshot := make(map[string]string, len(config.InsecureSettingsRegistry)+len(config.TrackedSettings))
	for _, s := range config.InsecureSettingsRegistry {
		snapshot[s.Name] = s.Value(cfg)
	}
	for _, s := range config.TrackedSettings {
		snapshot[s.Name] = s.Value(cfg)
	}
	return snapshot
}

// logAuditDurability logs the start-up INFO line for the effective
// storage.database.audit_durability, e.g. "audit durability: standard
// (PostgreSQL default; committed before every disclosure; ...)".
func logAuditDurability(cfg *config.Config) {
	log.Printf("INFO: %s", cfg.Storage.Database.EffectiveAuditDurability(cfg.Storage.Type).StartupLine())
}
