package config

import (
	"strings"

	"github.com/keyorixhq/keyorix/internal/secretenv"
)

// ConfiguredSecretValues returns every secret this config resolves, keyed by a
// name an operator recognises (the env var, or the config key for values that
// have none), for checks that compare secrets with each other: the SCIM token
// must not equal another one (#3397). Empty and unresolvable values are left
// out (ValidateSecretSources reports the unresolvable ones). Callers print the
// names, never the values.
//
// Covered: every SecretEnvVars name and the operator-named variables
// (secretEnvNames), each from the variable or its _FILE; the config-file
// fallbacks of the resolveSecret accessors; the HTTP and gRPC metrics tokens.
// Not covered: a master passphrase given only on the command line
// (--passphrase-fd/-file/-stdin), which is read after this runs, and key
// material in files (the KEK file, Shamir share files).
func (c *Config) ConfiguredSecretValues() map[string]string {
	out := map[string]string{}
	add := func(name, v string) {
		if _, dup := out[name]; v != "" && !dup {
			out[name] = v
		}
	}
	for _, n := range c.secretEnvNames() {
		if v, found, err := secretenv.Lookup(n); err == nil && found {
			add(n, v)
		}
	}
	// The accessors return the env/_FILE value when set (already added above
	// under the same name), otherwise the config-file value.
	add("KEYORIX_DB_PASSWORD", c.Storage.Database.GetPassword())
	if c.Client != nil {
		add("KEYORIX_API_KEY", c.Client.Auth.GetAPIKey())
	}
	add("KEYORIX_SIEM_TOKEN", c.Audit.SIEM.GetToken())
	add("KEYORIX_SMTP_PASSWORD", c.CredentialDelivery.SMTP.GetPassword())
	add("KEYORIX_EVIDENCE_WEBHOOK_TOKEN", c.EvidenceDelivery.Webhook.GetToken())
	add("KEYORIX_NOTIFY_SLACK_WEBHOOK", c.Notifications.GetSlackWebhookURL())
	add("KEYORIX_NOTIFY_TEAMS_WEBHOOK", c.Notifications.GetTeamsWebhookURL())
	add("KEYORIX_NOTIFY_SMTP_PASSWORD", c.Notifications.Email.GetPassword())
	add("KEYORIX_NOTIFY_WEBHOOK_TOKEN", c.Notifications.Webhook.GetToken())
	add("KEYORIX_NOTIFY_WEBHOOK_SIGNING_SECRET", c.Notifications.Webhook.GetSigningSecret())
	add("KEYORIX_SCIM_TOKEN", c.SCIM.GetToken())
	for i := range c.SSO.Providers {
		p := &c.SSO.Providers[i]
		add("KEYORIX_SSO_"+strings.ToUpper(p.Name)+"_CLIENT_SECRET", p.GetClientSecret())
	}
	if tok, err := c.Server.HTTP.ResolveMetricsToken(); err == nil {
		add("server.http.metrics_token", tok)
	}
	if tok, err := c.Server.GRPC.ResolveMetricsToken(); err == nil {
		add("server.grpc.metrics_token", tok)
	}
	return out
}
