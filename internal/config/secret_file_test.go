package config

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// secretAccessorCase pairs a secret's env var with the accessor that resolves
// it. Every secret the server reads from the environment must be listed here
// AND in SecretEnvVars (see TestSecretEnvVars_CoversEveryResolveSecretCall).
type secretAccessorCase struct {
	env string
	get func() string
}

func secretAccessorCases() []secretAccessorCase {
	return []secretAccessorCase{
		{"KEYORIX_DB_PASSWORD", func() string { return (&DatabaseConfig{Password: "yaml-value"}).GetPassword() }},
		{"KEYORIX_API_KEY", func() string { return (&AuthConfig{APIKey: "yaml-value"}).GetAPIKey() }},
		{"KEYORIX_SIEM_TOKEN", func() string { return (&SIEMConfig{Token: "yaml-value"}).GetToken() }},
		{"KEYORIX_SMTP_PASSWORD", func() string { return (&CredentialSMTPConfig{Password: "yaml-value"}).GetPassword() }},
		{"KEYORIX_EVIDENCE_WEBHOOK_TOKEN", func() string { return (&EvidenceWebhookConfig{Token: "yaml-value"}).GetToken() }},
		{"KEYORIX_NOTIFY_SLACK_WEBHOOK", func() string {
			return (&NotificationsConfig{Slack: NotificationChatConfig{WebhookURL: "yaml-value"}}).GetSlackWebhookURL()
		}},
		{"KEYORIX_NOTIFY_TEAMS_WEBHOOK", func() string {
			return (&NotificationsConfig{Teams: NotificationChatConfig{WebhookURL: "yaml-value"}}).GetTeamsWebhookURL()
		}},
		{"KEYORIX_NOTIFY_SMTP_PASSWORD", func() string { return (&NotificationEmailConfig{Password: "yaml-value"}).GetPassword() }},
		{"KEYORIX_NOTIFY_WEBHOOK_TOKEN", func() string { return (&NotificationWebhookConfig{Token: "yaml-value"}).GetToken() }},
		{"KEYORIX_NOTIFY_WEBHOOK_SIGNING_SECRET", func() string {
			return (&NotificationWebhookConfig{SigningSecret: "yaml-value"}).GetSigningSecret()
		}},
		{"KEYORIX_SCIM_TOKEN", func() string { return (&SCIMConfig{Token: "yaml-value"}).GetToken() }},
		{"KEYORIX_SSO_OKTA_CLIENT_SECRET", func() string {
			return (&SSOProviderConfig{Name: "okta", ClientSecret: "yaml-value"}).GetClientSecret()
		}},
	}
}

func writeSecretFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	return p
}

func TestSecretAccessors_ReadFileVariant(t *testing.T) {
	for _, tc := range secretAccessorCases() {
		t.Run(tc.env, func(t *testing.T) {
			t.Setenv(tc.env+"_FILE", writeSecretFile(t, "from-file\n"))
			assert.Equal(t, "from-file", tc.get(), "%s_FILE must be honoured", tc.env)
		})
	}
}

func TestSecretAccessors_EnvStillWorks(t *testing.T) {
	for _, tc := range secretAccessorCases() {
		t.Run(tc.env, func(t *testing.T) {
			t.Setenv(tc.env, "from-env")
			assert.Equal(t, "from-env", tc.get())
		})
	}
}

func TestSecretAccessors_BothSetFailsClosed(t *testing.T) {
	for _, tc := range secretAccessorCases() {
		t.Run(tc.env, func(t *testing.T) {
			t.Setenv(tc.env, "from-env")
			t.Setenv(tc.env+"_FILE", writeSecretFile(t, "from-file\n"))
			assert.Empty(t, tc.get(), "no silent precedence: neither value, and not the yaml fallback either")
		})
	}
}

func TestSecretAccessors_UnreadableFileFailsClosed(t *testing.T) {
	for _, tc := range secretAccessorCases() {
		t.Run(tc.env, func(t *testing.T) {
			t.Setenv(tc.env+"_FILE", filepath.Join(t.TempDir(), "missing"))
			assert.Empty(t, tc.get(), "an unreadable file must not fall back to the yaml value")
		})
	}
}

func TestValidateSecretSources_OK(t *testing.T) {
	t.Setenv("KEYORIX_DB_PASSWORD_FILE", writeSecretFile(t, "pw\n"))
	require.NoError(t, validLocalConfig().ValidateSecretSources())
}

func TestValidateSecretSources_RefusesBothSet(t *testing.T) {
	t.Setenv("KEYORIX_DB_PASSWORD", "plain")
	t.Setenv("KEYORIX_DB_PASSWORD_FILE", writeSecretFile(t, "file\n"))
	err := validLocalConfig().ValidateSecretSources()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KEYORIX_DB_PASSWORD")
	assert.NotContains(t, err.Error(), "plain")
	assert.NotContains(t, err.Error(), "file\n")
}

func TestValidateSecretSources_RefusesUnreadable(t *testing.T) {
	t.Setenv("KEYORIX_SMTP_PASSWORD_FILE", filepath.Join(t.TempDir(), "missing"))
	err := validLocalConfig().ValidateSecretSources()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KEYORIX_SMTP_PASSWORD_FILE")
}

func TestValidate_RunsSecretSourceCheck(t *testing.T) {
	t.Setenv("KEYORIX_DB_PASSWORD", "plain")
	t.Setenv("KEYORIX_DB_PASSWORD_FILE", writeSecretFile(t, "file\n"))
	require.Error(t, validLocalConfig().Validate(), "Validate() is what both the server and startup validation call; it must refuse")
}

func TestValidateSecretSources_ReportsEveryProblem(t *testing.T) {
	t.Setenv("KEYORIX_DB_PASSWORD", "plain")
	t.Setenv("KEYORIX_DB_PASSWORD_FILE", writeSecretFile(t, "file\n"))
	t.Setenv("KEYORIX_SCIM_TOKEN_FILE", filepath.Join(t.TempDir(), "missing"))
	err := validLocalConfig().ValidateSecretSources()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KEYORIX_DB_PASSWORD")
	assert.Contains(t, err.Error(), "KEYORIX_SCIM_TOKEN_FILE")
}

func TestValidateSecretSources_DynamicNames(t *testing.T) {
	cfg := validLocalConfig()
	cfg.SSO.Providers = []SSOProviderConfig{{Name: "okta"}, {Name: "azure-ad"}}
	cfg.AutoRotation.Backends = []RotationBackendConfig{{Name: "pg", Type: "postgresql", DSNEnv: "MY_ROTATION_DSN"}}
	cfg.Connect.Connectors = []ConnectorConfig{{Name: "v", Type: "vault", TokenEnv: "MY_VAULT_TOKEN"}}
	cfg.Storage.Encryption.KeyProvider.EnvVar = "MY_KEK"
	cfg.Storage.Encryption.KeyProvider.ShamirShareEnv = []string{"MY_SHARE_1"}

	for _, name := range []string{"KEYORIX_SSO_OKTA_CLIENT_SECRET", "KEYORIX_SSO_AZURE-AD_CLIENT_SECRET", "MY_ROTATION_DSN", "MY_VAULT_TOKEN", "MY_KEK", "MY_SHARE_1"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "x")
			t.Setenv(name+"_FILE", writeSecretFile(t, "y\n"))
			err := cfg.ValidateSecretSources()
			require.Error(t, err)
			assert.Contains(t, err.Error(), name)
		})
	}
}

func TestSecretFilePaths_ListsConfiguredFiles(t *testing.T) {
	cfg := validLocalConfig()
	cfg.SSO.Providers = []SSOProviderConfig{{Name: "okta"}}
	a := writeSecretFile(t, "a\n")
	b := writeSecretFile(t, "b\n")
	t.Setenv("KEYORIX_DB_PASSWORD_FILE", a)
	t.Setenv("KEYORIX_SSO_OKTA_CLIENT_SECRET_FILE", b)
	assert.ElementsMatch(t, []string{a, b}, cfg.SecretFilePaths())
}

func TestRotationDSN_ReadsFileVariant(t *testing.T) {
	t.Setenv("MY_ROTATION_DSN_FILE", writeSecretFile(t, "postgres://u:p@h/db\n"))
	assert.Equal(t, "postgres://u:p@h/db", RotationBackendConfig{DSNEnv: "MY_ROTATION_DSN"}.GetDSN())
}

// TestSecretEnvVars_CoversEveryResolveSecretCall is the family guard: a new
// resolveSecret("KEYORIX_...") call that is not registered in SecretEnvVars
// would silently lack startup validation and the file-permission check. It reads
// every non-test file of this package: the accessors that call resolveSecret
// live with their section types in config_<domain>.go.
func TestSecretEnvVars_CoversEveryResolveSecretCall(t *testing.T) {
	paths, err := filepath.Glob("*.go")
	require.NoError(t, err)
	var src []byte
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		b, err := os.ReadFile(p) // #nosec G304 -- this package's own source files
		require.NoError(t, err)
		src = append(src, b...)
	}
	re := regexp.MustCompile(`resolveSecret\("([A-Z0-9_]+)",`)
	registered := map[string]bool{}
	for _, n := range SecretEnvVars {
		registered[n] = true
	}
	found := 0
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		if m[1] == "KEYORIX_CONFIG_PATH" { // a path, not a secret; no _FILE variant
			continue
		}
		found++
		assert.True(t, registered[m[1]], "%s is resolved via resolveSecret but missing from SecretEnvVars", m[1])
	}
	assert.GreaterOrEqual(t, found, 11, "regexp found too few resolveSecret calls; the guard is vacuous")
	for _, tc := range secretAccessorCases() {
		if strings.HasPrefix(tc.env, "KEYORIX_SSO_") {
			continue // dynamic name
		}
		assert.True(t, registered[tc.env], "%s missing from SecretEnvVars", tc.env)
	}
}

func TestConfigPathEnv_HasNoFileVariant(t *testing.T) {
	// KEYORIX_CONFIG_PATH is a path; KEYORIX_CONFIG_PATH_FILE must not be a thing.
	t.Setenv("KEYORIX_CONFIG_PATH_FILE", writeSecretFile(t, "/etc/other.yaml\n"))
	t.Setenv("KEYORIX_CONFIG_PATH", "/etc/keyorix.yaml")
	assert.Equal(t, "/etc/keyorix.yaml", ResolvedPath(""))
}
