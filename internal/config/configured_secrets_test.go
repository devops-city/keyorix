package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #3397: ConfiguredSecretValues feeds the "SCIM token equals another secret"
// refusal. Every fixed-name secret (SecretEnvVars) is collected from its env
// var or _FILE; family guard: a name added to SecretEnvVars is covered without
// touching this test.
func TestConfiguredSecretValues_EveryEnvSecret(t *testing.T) {
	for _, n := range SecretEnvVars {
		t.Setenv(n, "")
		require.NoError(t, os.Unsetenv(n))
	}
	cfg := &Config{}
	for _, n := range SecretEnvVars {
		t.Run(n, func(t *testing.T) {
			t.Setenv(n, "value-of-"+n)
			got := cfg.ConfiguredSecretValues()
			assert.Equal(t, "value-of-"+n, got[n])
		})
	}
	t.Run("_FILE form", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "db")
		require.NoError(t, os.WriteFile(p, []byte("from-file\n"), 0o600))
		t.Setenv("KEYORIX_DB_PASSWORD_FILE", p)
		assert.Equal(t, "from-file", cfg.ConfiguredSecretValues()["KEYORIX_DB_PASSWORD"])
	})
}

// Values written in the config file (no env var) are collected too, and so are
// operator-named variables and the metrics tokens.
func TestConfiguredSecretValues_ConfigFileAndOperatorNamed(t *testing.T) {
	for _, n := range SecretEnvVars {
		t.Setenv(n, "")
		require.NoError(t, os.Unsetenv(n))
	}
	t.Setenv("MY_KEK", "kek-env")
	cfg := &Config{
		Storage:            StorageConfig{Database: DatabaseConfig{Password: "db"}, Encryption: EncryptionConfig{KeyProvider: KeyProviderConfig{EnvVar: "MY_KEK"}}},
		Client:             &ClientConfig{Auth: AuthConfig{APIKey: "api"}},
		Audit:              AuditConfig{SIEM: SIEMConfig{Token: "siem"}},
		CredentialDelivery: CredentialDeliveryConfig{SMTP: CredentialSMTPConfig{Password: "smtp"}},
		EvidenceDelivery:   EvidenceDeliveryConfig{Webhook: EvidenceWebhookConfig{Token: "evidence"}},
		Notifications: NotificationsConfig{
			Webhook: NotificationWebhookConfig{Token: "nwh", SigningSecret: "nsig"},
			Email:   NotificationEmailConfig{Password: "nsmtp"},
			Slack:   NotificationChatConfig{WebhookURL: "slack"},
			Teams:   NotificationChatConfig{WebhookURL: "teams"},
		},
		SSO:    SSOConfig{Providers: []SSOProviderConfig{{Name: "okta", ClientSecret: "sso"}}},
		Server: ServerConfig{HTTP: ServerInstanceConfig{MetricsToken: "metrics-http"}, GRPC: ServerInstanceConfig{MetricsToken: "metrics-grpc"}},
		SCIM:   SCIMConfig{Token: "scim"},
	}
	got := cfg.ConfiguredSecretValues()
	values := map[string]bool{}
	for _, v := range got {
		values[v] = true
	}
	for _, want := range []string{"db", "api", "siem", "smtp", "evidence", "nwh", "nsig", "nsmtp", "slack", "teams", "sso", "metrics-http", "metrics-grpc", "scim", "kek-env"} {
		assert.True(t, values[want], "value %q not collected (got names %v)", want, secretNames(got))
	}
}

func secretNames(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
