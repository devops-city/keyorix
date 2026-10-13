package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// TestLicenseGrace_Default validates that an unset GraceHours defaults to 14 days.
func TestLicenseGrace_Default(t *testing.T) {
	c := &Config{}
	assert.Equal(t, 14*24*time.Hour, c.LicenseGrace())
}

// TestLicenseGrace_Zero validates that GraceHours=0 uses the 14d default.
func TestLicenseGrace_Zero(t *testing.T) {
	c := &Config{License: LicenseConfig{GraceHours: 0}}
	assert.Equal(t, 14*24*time.Hour, c.LicenseGrace())
}

// TestLicenseGrace_Negative validates that a negative GraceHours uses the 14d default.
func TestLicenseGrace_Negative(t *testing.T) {
	c := &Config{License: LicenseConfig{GraceHours: -1}}
	assert.Equal(t, 14*24*time.Hour, c.LicenseGrace())
}

// TestLicenseGrace_Positive validates that a positive GraceHours is used as-is.
func TestLicenseGrace_Positive(t *testing.T) {
	c := &Config{License: LicenseConfig{GraceHours: 48}}
	assert.Equal(t, 48*time.Hour, c.LicenseGrace())
}

// TestPasswordPolicyConfig_Resolve_AbsentBlockKeepsDefaults is the #G37 detection_idea:
// construct the struct with only required fields set and assert the SECURE default, not
// the permissive Go zero value — an entirely-absent password_policy block must resolve to
// 100% of the caller's defaults.
func TestPasswordPolicyConfig_Resolve_AbsentBlockKeepsDefaults(t *testing.T) {
	defaults := PasswordPolicyValues{
		MinLength: 16, RequireUppercase: true, RequireLowercase: true, RequireDigit: true,
		RequireSpecial: true, RejectPersonalInfo: true, RejectCommonPasswords: true, HistoryCount: 5,
	}
	assert.Equal(t, defaults, PasswordPolicyConfig{}.Resolve(defaults))
}

// TestPasswordPolicyConfig_Resolve_PartialBlockOverridesOnlyItsOwnFields is the #G37
// regression: a partial password_policy block naming only ONE rule must not silently
// zero out every other rule it didn't mention.
func TestPasswordPolicyConfig_Resolve_PartialBlockOverridesOnlyItsOwnFields(t *testing.T) {
	defaults := PasswordPolicyValues{
		MinLength: 16, RequireUppercase: true, RequireLowercase: true, RequireDigit: true,
		RequireSpecial: true, RejectPersonalInfo: true, RejectCommonPasswords: true, HistoryCount: 5,
	}
	partial := PasswordPolicyConfig{RejectCommonPasswords: BoolPtr(false)}
	resolved := partial.Resolve(defaults)

	assert.False(t, resolved.RejectCommonPasswords, "the explicitly-set field must be honored")
	assert.Equal(t, defaults.MinLength, resolved.MinLength, "an unset field must keep the default, not collapse to 0")
	assert.True(t, resolved.RequireUppercase, "an unset bool must keep the default, not collapse to false")
	assert.True(t, resolved.RequireLowercase)
	assert.True(t, resolved.RequireDigit)
	assert.True(t, resolved.RequireSpecial)
	assert.True(t, resolved.RejectPersonalInfo)
	assert.Equal(t, defaults.HistoryCount, resolved.HistoryCount, "an unset int must keep the default, not collapse to 0")
}

// TestPasswordPolicyConfig_Resolve_RealYAMLPartialBlock is the #G37 detection_idea run
// against actual YAML unmarshaling, not just hand-built structs: a real operator config
// naming only ONE rule must not zero out the rest once parsed and resolved.
func TestPasswordPolicyConfig_Resolve_RealYAMLPartialBlock(t *testing.T) {
	var pp PasswordPolicyConfig
	require.NoError(t, yaml.Unmarshal([]byte("reject_common_passwords: false\n"), &pp))

	defaults := PasswordPolicyValues{
		MinLength: 16, RequireUppercase: true, RequireLowercase: true, RequireDigit: true,
		RequireSpecial: true, RejectPersonalInfo: true, RejectCommonPasswords: true, HistoryCount: 5,
	}
	resolved := pp.Resolve(defaults)
	assert.False(t, resolved.RejectCommonPasswords, "the YAML-set field must be honored")
	assert.Equal(t, 16, resolved.MinLength, "min_length, never mentioned in the YAML, must keep the default")
	assert.True(t, resolved.RequireUppercase, "require_uppercase, never mentioned in the YAML, must keep the default")
	assert.Equal(t, 5, resolved.HistoryCount, "history_count, never mentioned in the YAML, must keep the default")
}

// TestPasswordPolicyConfig_Resolve_ExplicitFalseIsHonored proves the *bool fields still
// let an operator genuinely relax a rule (e.g. a lab install) by setting it to false —
// the fix must not make explicit opt-out impossible.
func TestPasswordPolicyConfig_Resolve_ExplicitFalseIsHonored(t *testing.T) {
	defaults := PasswordPolicyValues{RequireSpecial: true}
	explicit := PasswordPolicyConfig{RequireSpecial: BoolPtr(false)}
	assert.False(t, explicit.Resolve(defaults).RequireSpecial)
}

// TestResolvePostgresConnConfig_DSNPassthrough validates that an explicit DSN
// is used as pgx parses it.
func TestResolvePostgresConnConfig_DSNPassthrough(t *testing.T) {
	clearPGEnv(t)
	d := &DatabaseConfig{DSN: "host=pg user=kx dbname=keyorix sslmode=require"}
	cc, err := ResolvePostgresConnConfig(d)
	require.NoError(t, err)
	assertSameConnection(t, d.DSN, cc, "")
}

// TestBuildPostgresDSNFromFields_Defaults validates that missing host/port/sslmode
// are filled with their documented defaults.
func TestBuildPostgresDSNFromFields_Defaults(t *testing.T) {
	d := &DatabaseConfig{Name: "keyorix", User: "kx"}
	dsn := buildPostgresDSNFromFields(d)
	assert.Contains(t, dsn, "host='localhost'")
	assert.Contains(t, dsn, "port='5432'")
	assert.Contains(t, dsn, "sslmode='require'")
	assert.Contains(t, dsn, "dbname='keyorix'")
	assert.Contains(t, dsn, "user='kx'")
}

// TestBuildPostgresDSNFromFields_ExplicitFields validates that explicit host/port/sslmode
// are used when provided.
func TestBuildPostgresDSNFromFields_ExplicitFields(t *testing.T) {
	d := &DatabaseConfig{
		Host:    "pg.prod",
		Port:    "5433",
		Name:    "mydb",
		User:    "admin",
		SSLMode: "verify-full",
		// verify-full needs a named CA since PG-VERIFYFULL-1 (database_tls_test.go).
		SSLRootCert: SSLRootCertSystem,
	}
	dsn := buildPostgresDSNFromFields(d)
	assert.Contains(t, dsn, "host='pg.prod'")
	assert.Contains(t, dsn, "port='5433'")
	assert.Contains(t, dsn, "sslmode='verify-full'")
	assert.Contains(t, dsn, "sslrootcert='system'")
}

// TestResolvePostgresConnConfig_FieldsPassword validates that the configured
// password is set on the parsed config and is not part of the field DSN.
func TestResolvePostgresConnConfig_FieldsPassword(t *testing.T) {
	clearPGEnv(t)
	d := &DatabaseConfig{Name: "db", User: "u", Password: "s3cr3t"}
	assert.NotContains(t, buildPostgresDSNFromFields(d), "s3cr3t")
	cc, err := ResolvePostgresConnConfig(d)
	require.NoError(t, err)
	assert.Equal(t, "s3cr3t", cc.Password)
}

// TestDatabaseConfig_GetPassword_EnvVar validates the environment-variable
// override for the database password.
func TestDatabaseConfig_GetPassword_EnvVar(t *testing.T) {
	t.Setenv("KEYORIX_DB_PASSWORD", "from-env")
	d := &DatabaseConfig{Password: "from-file"}
	assert.Equal(t, "from-env", d.GetPassword())
}

// TestDatabaseConfig_GetPassword_Fallback validates that the config-file value
// is used when the env var is absent.
func TestDatabaseConfig_GetPassword_Fallback(t *testing.T) {
	t.Setenv("KEYORIX_DB_PASSWORD", "")
	d := &DatabaseConfig{Password: "from-file"}
	assert.Equal(t, "from-file", d.GetPassword())
}

// TestDatabaseConfig_GetAuditFlusherLingerWindow_DefaultIsZero validates the
// coordinator-review decision on #2420: an unset AuditFlusherLingerWindow
// must resolve to 0 (no deliberate linger wait), not a tuned nonzero value —
// see AuditFlusherLingerWindow's own doc comment for why.
func TestDatabaseConfig_GetAuditFlusherLingerWindow_DefaultIsZero(t *testing.T) {
	d := &DatabaseConfig{}
	assert.Equal(t, time.Duration(0), d.GetAuditFlusherLingerWindow())
}

// TestDatabaseConfig_GetAuditFlusherLingerWindow_Configurable validates that
// an operator can still set a nonzero window via config, per the
// coordinator's "keep it configurable (documented)" instruction.
func TestDatabaseConfig_GetAuditFlusherLingerWindow_Configurable(t *testing.T) {
	d := &DatabaseConfig{AuditFlusherLingerWindow: "2ms"}
	assert.Equal(t, 2*time.Millisecond, d.GetAuditFlusherLingerWindow())
}

// TestDatabaseConfig_GetAuditFlusherLingerWindow_InvalidFallsBackToZero
// validates that an unparseable or non-positive value falls back to the
// safe default (0) rather than erroring at startup or, worse, silently
// treating garbage as "wait forever".
func TestDatabaseConfig_GetAuditFlusherLingerWindow_InvalidFallsBackToZero(t *testing.T) {
	for _, raw := range []string{"not-a-duration", "-5ms", "0ms"} {
		d := &DatabaseConfig{AuditFlusherLingerWindow: raw}
		assert.Equal(t, time.Duration(0), d.GetAuditFlusherLingerWindow(), "raw=%q", raw)
	}
}

// TestBoolPtr validates that BoolPtr returns a pointer to the given value.
func TestBoolPtr(t *testing.T) {
	pTrue := BoolPtr(true)
	require.NotNil(t, pTrue)
	assert.True(t, *pTrue)

	pFalse := BoolPtr(false)
	require.NotNil(t, pFalse)
	assert.False(t, *pFalse)
}

// TestGetRequiredApprovals_Default validates that 0/1 both return 1.
func TestGetRequiredApprovals_Default(t *testing.T) {
	assert.Equal(t, 1, DualControlConfig{RequiredApprovals: 0}.GetRequiredApprovals())
	assert.Equal(t, 1, DualControlConfig{RequiredApprovals: 1}.GetRequiredApprovals())
}

// TestGetRequiredApprovals_Positive validates values above 1 are used as-is.
func TestGetRequiredApprovals_Positive(t *testing.T) {
	assert.Equal(t, 3, DualControlConfig{RequiredApprovals: 3}.GetRequiredApprovals())
}

// TestBreakGlassConfig_GetDefaultTTL validates default and explicit values.
func TestBreakGlassConfig_GetDefaultTTL(t *testing.T) {
	assert.Equal(t, 4*time.Hour, BreakGlassConfig{}.GetDefaultTTL())
	assert.Equal(t, 4*time.Hour, BreakGlassConfig{DefaultTTL: "bad"}.GetDefaultTTL())
	assert.Equal(t, 2*time.Hour, BreakGlassConfig{DefaultTTL: "2h"}.GetDefaultTTL())
}

// TestBreakGlassConfig_GetMaxTTL validates default and explicit values.
func TestBreakGlassConfig_GetMaxTTL(t *testing.T) {
	assert.Equal(t, 24*time.Hour, BreakGlassConfig{}.GetMaxTTL())
	assert.Equal(t, 24*time.Hour, BreakGlassConfig{MaxTTL: "invalid"}.GetMaxTTL())
	assert.Equal(t, 8*time.Hour, BreakGlassConfig{MaxTTL: "8h"}.GetMaxTTL())
}

// TestGetSweepInterval_Default validates default and edge cases.
func TestGetSweepInterval_Default(t *testing.T) {
	assert.Equal(t, time.Minute, DynamicSecretsConfig{}.GetSweepInterval())
	assert.Equal(t, time.Minute, DynamicSecretsConfig{SweepInterval: "garbage"}.GetSweepInterval())
	assert.Equal(t, time.Minute, DynamicSecretsConfig{SweepInterval: "0"}.GetSweepInterval())
	assert.Equal(t, 5*time.Minute, DynamicSecretsConfig{SweepInterval: "5m"}.GetSweepInterval())
}

// TestAutoRotationConfig_GetInterval validates the auto-rotation schedule.
func TestAutoRotationConfig_GetInterval(t *testing.T) {
	assert.Equal(t, time.Hour, AutoRotationConfig{}.GetInterval())
	assert.Equal(t, time.Hour, AutoRotationConfig{Schedule: "bad"}.GetInterval())
	assert.Equal(t, 30*time.Minute, AutoRotationConfig{Schedule: "30m"}.GetInterval())
}

// TestRotationRemindersConfig_GetInterval validates the rotation-reminder
// schedule.
func TestRotationRemindersConfig_GetInterval(t *testing.T) {
	assert.Equal(t, 24*time.Hour, RotationRemindersConfig{}.GetInterval())
	assert.Equal(t, 12*time.Hour, RotationRemindersConfig{Schedule: "12h"}.GetInterval())
}

// TestExpiryRemindersConfig_GetInterval validates the expiry-reminder schedule.
func TestExpiryRemindersConfig_GetInterval(t *testing.T) {
	assert.Equal(t, 24*time.Hour, ExpiryRemindersConfig{}.GetInterval())
	assert.Equal(t, 6*time.Hour, ExpiryRemindersConfig{Schedule: "6h"}.GetInterval())
}

// TestCertificateExpiryConfig_GetInterval validates the cert-expiry scan
// schedule.
func TestCertificateExpiryConfig_GetInterval(t *testing.T) {
	assert.Equal(t, 24*time.Hour, CertificateExpiryConfig{}.GetInterval())
	assert.Equal(t, 48*time.Hour, CertificateExpiryConfig{Schedule: "48h"}.GetInterval())
}

// TestAuditCheckpointsConfig_GetInterval validates the checkpoint schedule.
func TestAuditCheckpointsConfig_GetInterval(t *testing.T) {
	assert.Equal(t, 24*time.Hour, AuditCheckpointsConfig{}.GetInterval())
	assert.Equal(t, 12*time.Hour, AuditCheckpointsConfig{Schedule: "12h"}.GetInterval())
}

// TestJITAccessExpiryConfig_GetInterval validates the JIT expiry sweep schedule.
func TestJITAccessExpiryConfig_GetInterval(t *testing.T) {
	assert.Equal(t, time.Hour, JITAccessExpiryConfig{}.GetInterval())
	assert.Equal(t, 30*time.Minute, JITAccessExpiryConfig{Schedule: "30m"}.GetInterval())
}

// TestAnomalyAlertsConfig_GetInterval validates the anomaly alert schedule.
func TestAnomalyAlertsConfig_GetInterval(t *testing.T) {
	assert.Equal(t, time.Hour, AnomalyAlertsConfig{}.GetInterval())
	assert.Equal(t, 2*time.Hour, AnomalyAlertsConfig{Schedule: "2h"}.GetInterval())
}

// TestAnomalyAlertsConfig_GetBaselineQuarantine_Custom validates that values
// not covered by the dedicated anomaly_config_test.go are handled correctly.
func TestAnomalyAlertsConfig_GetBaselineQuarantine_Custom(t *testing.T) {
	// Valid non-zero duration beyond what the existing test covers.
	assert.Equal(t, 48*time.Hour, AnomalyAlertsConfig{BaselineQuarantine: "48h"}.GetBaselineQuarantine())
	assert.Equal(t, 72*time.Hour, AnomalyAlertsConfig{BaselineQuarantine: "72h"}.GetBaselineQuarantine())
}

// TestDataRetentionConfig_GetInterval validates the data-retention scheduler
// interval.
func TestDataRetentionConfig_GetInterval(t *testing.T) {
	assert.Equal(t, 24*time.Hour, DataRetentionConfig{}.GetInterval())
	assert.Equal(t, 24*time.Hour, DataRetentionConfig{Schedule: "bad"}.GetInterval())
	assert.Equal(t, 12*time.Hour, DataRetentionConfig{Schedule: "12h"}.GetInterval())
}

// TestRecertificationConfig_GetInterval validates the recertification scheduler
// interval.
func TestRecertificationConfig_GetInterval(t *testing.T) {
	assert.Equal(t, 24*time.Hour, RecertificationConfig{}.GetInterval())
	assert.Equal(t, 72*time.Hour, RecertificationConfig{Schedule: "72h"}.GetInterval())
}

// TestComplianceDigestConfig_GetInterval validates the compliance-digest
// scheduler interval.
func TestComplianceDigestConfig_GetInterval(t *testing.T) {
	assert.Equal(t, 24*time.Hour, ComplianceDigestConfig{}.GetInterval())
	assert.Equal(t, 168*time.Hour, ComplianceDigestConfig{Schedule: "168h"}.GetInterval())
}

// TestEvidenceDeliveryConfig_GetInterval validates the evidence-export
// scheduler interval.
func TestEvidenceDeliveryConfig_GetInterval(t *testing.T) {
	assert.Equal(t, 24*time.Hour, EvidenceDeliveryConfig{}.GetInterval())
	assert.Equal(t, 8*time.Hour, EvidenceDeliveryConfig{Schedule: "8h"}.GetInterval())
}

// TestEvidenceDeliveryConfig_HasTarget validates that at least one output must
// be configured.
func TestEvidenceDeliveryConfig_HasTarget(t *testing.T) {
	assert.False(t, EvidenceDeliveryConfig{}.HasTarget())
	assert.True(t, EvidenceDeliveryConfig{OutputDir: "/tmp/evidence"}.HasTarget())
	assert.True(t, EvidenceDeliveryConfig{Webhook: EvidenceWebhookConfig{Enabled: true}}.HasTarget())
	assert.True(t, EvidenceDeliveryConfig{ObjectStore: EvidenceObjectStoreConfig{Enabled: true}}.HasTarget())
}

// TestLicenseExpiryConfig_GetInterval validates the license-expiry reminder
// interval.
func TestLicenseExpiryConfig_GetInterval(t *testing.T) {
	assert.Equal(t, 24*time.Hour, LicenseExpiryConfig{}.GetInterval())
	assert.Equal(t, 12*time.Hour, LicenseExpiryConfig{Schedule: "12h"}.GetInterval())
}

// TestCredentialDeliveryConfig_GetSetupTokenTTL validates the setup-token TTL
// parsing.
func TestCredentialDeliveryConfig_GetSetupTokenTTL(t *testing.T) {
	// Default (empty = 24h).
	assert.Equal(t, 24*time.Hour, (&CredentialDeliveryConfig{}).GetSetupTokenTTL())
	// Explicit valid duration.
	assert.Equal(t, 48*time.Hour, (&CredentialDeliveryConfig{SetupTokenTTL: "48h"}).GetSetupTokenTTL())
	// Invalid falls back to 24h.
	assert.Equal(t, 24*time.Hour, (&CredentialDeliveryConfig{SetupTokenTTL: "bad"}).GetSetupTokenTTL())
	// Zero or negative falls back to 24h.
	assert.Equal(t, 24*time.Hour, (&CredentialDeliveryConfig{SetupTokenTTL: "0"}).GetSetupTokenTTL())
}

// TestValidate_HTTPServerEnabledNoPort validates that HTTP enabled without a
// port is rejected.
func TestValidate_HTTPServerEnabledNoPort(t *testing.T) {
	c := &Config{}
	c.Server.HTTP.Enabled = true
	c.Server.HTTP.Port = ""
	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "port")
}

// TestValidate_GRPCServerEnabledNoPort validates that gRPC enabled without a
// port is rejected.
func TestValidate_GRPCServerEnabledNoPort(t *testing.T) {
	c := &Config{}
	c.Server.GRPC.Enabled = true
	c.Server.GRPC.Port = ""
	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "port")
}

// TestValidate_HTTPTLSNoCertFile validates that HTTP TLS without cert/key is
// rejected.
func TestValidate_HTTPTLSNoCertFile(t *testing.T) {
	c := &Config{}
	c.Storage.Database.Path = "/tmp/db"
	c.Server.HTTP.TLS.Enabled = true
	c.Server.HTTP.TLS.AutoCert = false
	c.Server.HTTP.TLS.CertFile = ""
	c.Server.HTTP.TLS.KeyFile = ""
	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TLS")
}

// TestValidate_HTTPTLSAutoCertNoDomains validates that autocert without domains
// is rejected.
func TestValidate_HTTPTLSAutoCertNoDomains(t *testing.T) {
	c := &Config{}
	c.Server.HTTP.TLS.Enabled = true
	c.Server.HTTP.TLS.AutoCert = true
	c.Server.HTTP.TLS.Domains = nil
	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "domains")
}

// TestValidate_GRPCTLSNoCertFile validates that gRPC TLS without cert/key is
// rejected.
func TestValidate_GRPCTLSNoCertFile(t *testing.T) {
	c := &Config{}
	c.Storage.Database.Path = "/tmp/db"
	c.Server.GRPC.TLS.Enabled = true
	c.Server.GRPC.TLS.CertFile = ""
	c.Server.GRPC.TLS.KeyFile = ""
	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cert_file")
}

// TestValidate_PostgresRequiresDSNOrFields validates that postgres storage
// without DSN or host/name/user is rejected.
func TestValidate_PostgresRequiresDSNOrFields(t *testing.T) {
	c := &Config{}
	c.Storage.Type = "postgres"
	// DSN, host, name, user all empty.
	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dsn")
}

// TestValidate_PostgresAcceptsDSN validates that postgres storage with a DSN
// passes validation.
func TestValidate_PostgresAcceptsDSN(t *testing.T) {
	c := &Config{}
	c.Storage.Type = "postgres"
	c.Storage.Database.DSN = "host=pg user=kx dbname=keyorix sslmode=require"
	require.NoError(t, c.Validate())
}

// TestValidate_LocalStorageRequiresPath validates that local storage without a
// path is rejected.
func TestValidate_LocalStorageRequiresPath(t *testing.T) {
	c := &Config{}
	c.Storage.Type = "local"
	c.Storage.Database.Path = ""
	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "path")
}

// TestValidate_UnsupportedLanguage validates that an unknown locale.language is
// rejected.
func TestValidate_UnsupportedLanguage(t *testing.T) {
	c := &Config{}
	c.Storage.Type = "local"
	c.Storage.Database.Path = "/tmp/db"
	c.Locale.Language = "zh"
	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "language")
}

// TestValidate_UnsupportedFallbackLanguage validates that an unknown
// locale.fallback_language is rejected.
func TestValidate_UnsupportedFallbackLanguage(t *testing.T) {
	c := &Config{}
	c.Storage.Type = "local"
	c.Storage.Database.Path = "/tmp/db"
	c.Locale.Language = "en"
	c.Locale.FallbackLanguage = "zh"
	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fallback language")
}

// TestValidate_DefaultLocaleIsEn validates that an empty locale.language
// defaults to "en" and passes validation.
func TestValidate_DefaultLocaleIsEn(t *testing.T) {
	c := &Config{}
	c.Storage.Type = "local"
	c.Storage.Database.Path = "/tmp/db"
	// Language and FallbackLanguage left empty → should default to "en".
	require.NoError(t, c.Validate())
	assert.Equal(t, "en", c.Locale.Language)
	assert.Equal(t, "en", c.Locale.FallbackLanguage)
}

// TestResolvedPath_ExplicitArgWins validates that an explicit path argument
// takes precedence over the environment variable.
func TestResolvedPath_ExplicitArgWins(t *testing.T) {
	t.Setenv("KEYORIX_CONFIG_PATH", "/env/path.yaml")
	got := ResolvedPath("/explicit/path.yaml")
	assert.Equal(t, "/explicit/path.yaml", got)
}

// TestResolvedPath_EnvVarFallback validates that the env var is used when the
// explicit path is empty.
func TestResolvedPath_EnvVarFallback(t *testing.T) {
	t.Setenv("KEYORIX_CONFIG_PATH", "/env/keyorix.yaml")
	got := ResolvedPath("")
	assert.Equal(t, "/env/keyorix.yaml", got)
}

// TestResolvedPath_Default validates that the default file name is used when
// neither arg nor env var is set.
func TestResolvedPath_Default(t *testing.T) {
	t.Setenv("KEYORIX_CONFIG_PATH", "")
	got := ResolvedPath("")
	// filepath.Join(".", "keyorix.yaml") → "keyorix.yaml" on most OS.
	assert.Equal(t, "keyorix.yaml", got)
}

// TestReadQuotaAlertsConfig_GetInterval validates the read-quota alert scan
// interval; defaults to 24h and falls back for bad input.
func TestReadQuotaAlertsConfig_GetInterval(t *testing.T) {
	assert.Equal(t, 24*time.Hour, ReadQuotaAlertsConfig{}.GetInterval())
	assert.Equal(t, 24*time.Hour, ReadQuotaAlertsConfig{Schedule: "bad"}.GetInterval())
	assert.Equal(t, 24*time.Hour, ReadQuotaAlertsConfig{Schedule: "-1h"}.GetInterval())
	assert.Equal(t, 12*time.Hour, ReadQuotaAlertsConfig{Schedule: "12h"}.GetInterval())
	assert.Equal(t, 6*time.Hour, ReadQuotaAlertsConfig{Schedule: "6h"}.GetInterval())
}

// TestGRPCKeepaliveConfig_Defaults validates that missing/invalid values fall
// back to the documented defaults.
func TestGRPCKeepaliveConfig_Defaults(t *testing.T) {
	c := GRPCKeepaliveConfig{}
	assert.Equal(t, 5*time.Minute, c.GetTime())
	assert.Equal(t, 20*time.Second, c.GetTimeout())
	assert.Equal(t, 5*time.Minute, c.GetMinTime())
}

// TestGRPCKeepaliveConfig_ExplicitValues validates that explicit values are
// parsed.
func TestGRPCKeepaliveConfig_ExplicitValues(t *testing.T) {
	c := GRPCKeepaliveConfig{Time: "10m", Timeout: "30s", MinTime: "3m"}
	assert.Equal(t, 10*time.Minute, c.GetTime())
	assert.Equal(t, 30*time.Second, c.GetTimeout())
	assert.Equal(t, 3*time.Minute, c.GetMinTime())
}

// TestGRPCKeepaliveConfig_InvalidFallsBack validates that invalid values use
// their defaults.
func TestGRPCKeepaliveConfig_InvalidFallsBack(t *testing.T) {
	c := GRPCKeepaliveConfig{Time: "bad", Timeout: "bad", MinTime: "bad"}
	assert.Equal(t, 5*time.Minute, c.GetTime())
	assert.Equal(t, 20*time.Second, c.GetTimeout())
	assert.Equal(t, 5*time.Minute, c.GetMinTime())
}

// TestEffectiveMaxRequestBodyBytes_Default validates the 10 MiB default.
func TestEffectiveMaxRequestBodyBytes_Default(t *testing.T) {
	s := ServerInstanceConfig{}
	assert.Equal(t, int64(10<<20), s.EffectiveMaxRequestBodyBytes())
}

// TestEffectiveMaxRequestBodyBytes_Explicit validates that an explicit limit is
// returned as-is, including negative (disable cap).
func TestEffectiveMaxRequestBodyBytes_Explicit(t *testing.T) {
	s := ServerInstanceConfig{MaxRequestBodyBytes: 1024}
	assert.Equal(t, int64(1024), s.EffectiveMaxRequestBodyBytes())

	s2 := ServerInstanceConfig{MaxRequestBodyBytes: -1}
	assert.Equal(t, int64(-1), s2.EffectiveMaxRequestBodyBytes())
}

// TestSSOProviderConfig_GetClientSecret validates env-var override.
func TestSSOProviderConfig_GetClientSecret(t *testing.T) {
	p := &SSOProviderConfig{Name: "okta", ClientSecret: "file-secret"}
	t.Setenv("KEYORIX_SSO_OKTA_CLIENT_SECRET", "env-secret")
	assert.Equal(t, "env-secret", p.GetClientSecret())

	t.Setenv("KEYORIX_SSO_OKTA_CLIENT_SECRET", "")
	assert.Equal(t, "file-secret", p.GetClientSecret())
}

// TestRotationBackendConfig_GetDSN validates DSNEnv lookup.
func TestRotationBackendConfig_GetDSN(t *testing.T) {
	c := RotationBackendConfig{DSNEnv: "MY_ROTATION_DSN"}
	t.Setenv("MY_ROTATION_DSN", "postgres://admin:pw@host/db")
	assert.Equal(t, "postgres://admin:pw@host/db", c.GetDSN())

	c2 := RotationBackendConfig{} // DSNEnv empty
	assert.Equal(t, "", c2.GetDSN())
}

// TestSCIMConfig_GetToken validates SCIM token env-var override.
func TestSCIMConfig_GetToken(t *testing.T) {
	s := &SCIMConfig{Token: "file-token"}
	t.Setenv("KEYORIX_SCIM_TOKEN", "env-token")
	assert.Equal(t, "env-token", s.GetToken())

	t.Setenv("KEYORIX_SCIM_TOKEN", "")
	assert.Equal(t, "file-token", s.GetToken())
}

// TestNotificationWebhookConfig_GetToken validates webhook token env-var
// override.
func TestNotificationWebhookConfig_GetToken(t *testing.T) {
	w := &NotificationWebhookConfig{Token: "file-tok"}
	t.Setenv("KEYORIX_NOTIFY_WEBHOOK_TOKEN", "env-tok")
	assert.Equal(t, "env-tok", w.GetToken())

	t.Setenv("KEYORIX_NOTIFY_WEBHOOK_TOKEN", "")
	assert.Equal(t, "file-tok", w.GetToken())
}

// TestEvidenceWebhookConfig_GetToken validates evidence webhook token env-var
// override.
func TestEvidenceWebhookConfig_GetToken(t *testing.T) {
	w := &EvidenceWebhookConfig{Token: "file-tok"}
	t.Setenv("KEYORIX_EVIDENCE_WEBHOOK_TOKEN", "env-tok")
	assert.Equal(t, "env-tok", w.GetToken())

	t.Setenv("KEYORIX_EVIDENCE_WEBHOOK_TOKEN", "")
	assert.Equal(t, "file-tok", w.GetToken())
}

// TestValidateAllowedOrigins_TrailingSlash validates that a trailing slash on
// an origin is rejected.
func TestValidateAllowedOrigins_TrailingSlash(t *testing.T) {
	// "https://app.example.com/" — has a path "/"
	err := validateAllowedOrigins([]string{"https://app.example.com/"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "allowed_origins")
}

// TestPasswordPolicyConfig_Resolve_AllFieldsSetOverrideDefaults exercises the
// true branch of every *pointer field's nil-check in Resolve — the existing
// partial-block tests each set only one or two of MinLength/RequireUppercase/
// RequireLowercase/RequireDigit/RejectPersonalInfo/HistoryCount, leaving those
// individual "explicitly set" branches uncovered. Set every field explicitly to
// a value that DIFFERS from the defaults so each branch is both taken and
// verified to actually take effect.
func TestPasswordPolicyConfig_Resolve_AllFieldsSetOverrideDefaults(t *testing.T) {
	defaults := PasswordPolicyValues{
		MinLength: 16, RequireUppercase: true, RequireLowercase: true, RequireDigit: true,
		RequireSpecial: true, RejectPersonalInfo: true, RejectCommonPasswords: true, HistoryCount: 5,
		MaxAgeDays: 90,
	}
	full := PasswordPolicyConfig{
		MinLength:             IntPtr(24),
		RequireUppercase:      BoolPtr(false),
		RequireLowercase:      BoolPtr(false),
		RequireDigit:          BoolPtr(false),
		RequireSpecial:        BoolPtr(false),
		RejectPersonalInfo:    BoolPtr(false),
		RejectCommonPasswords: BoolPtr(false),
		HistoryCount:          IntPtr(10),
		MaxAgeDays:            30,
	}
	resolved := full.Resolve(defaults)

	assert.Equal(t, 24, resolved.MinLength)
	assert.False(t, resolved.RequireUppercase)
	assert.False(t, resolved.RequireLowercase)
	assert.False(t, resolved.RequireDigit)
	assert.False(t, resolved.RequireSpecial)
	assert.False(t, resolved.RejectPersonalInfo)
	assert.False(t, resolved.RejectCommonPasswords)
	assert.Equal(t, 10, resolved.HistoryCount)
	// MaxAgeDays is unconditional in Resolve (not gated on a pointer nil-check),
	// so it always takes the config's value, even 0 — verify that's still true here.
	assert.Equal(t, 30, resolved.MaxAgeDays)
}

// TestIntPtr validates that IntPtr returns a pointer to the given value.
func TestIntPtr(t *testing.T) {
	p := IntPtr(42)
	require.NotNil(t, p)
	assert.Equal(t, 42, *p)

	pZero := IntPtr(0)
	require.NotNil(t, pZero)
	assert.Equal(t, 0, *pZero)
}

// TestClassificationConfig_GetMFAStepUpGrantRetentionDays_Default validates
// that an unset (zero) retention defaults to 30 days.
func TestClassificationConfig_GetMFAStepUpGrantRetentionDays_Default(t *testing.T) {
	c := ClassificationConfig{}
	assert.Equal(t, 30, c.GetMFAStepUpGrantRetentionDays())
}

// TestClassificationConfig_GetMFAStepUpGrantRetentionDays_Negative validates
// that a negative retention also falls back to the 30 day default.
func TestClassificationConfig_GetMFAStepUpGrantRetentionDays_Negative(t *testing.T) {
	c := ClassificationConfig{MFAStepUpGrantRetentionDays: -5}
	assert.Equal(t, 30, c.GetMFAStepUpGrantRetentionDays())
}

// TestClassificationConfig_GetMFAStepUpGrantRetentionDays_Positive validates
// that a positive retention is used as-is.
func TestClassificationConfig_GetMFAStepUpGrantRetentionDays_Positive(t *testing.T) {
	c := ClassificationConfig{MFAStepUpGrantRetentionDays: 90}
	assert.Equal(t, 90, c.GetMFAStepUpGrantRetentionDays())
}

// TestValidateAllowedOrigins_Empty validates that an empty list is accepted.
func TestValidateAllowedOrigins_Empty(t *testing.T) {
	require.NoError(t, validateAllowedOrigins(nil))
	require.NoError(t, validateAllowedOrigins([]string{}))
}
