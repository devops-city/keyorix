package config

import (
	"time"
)

// NotificationsConfig configures external delivery channels for in-app
// notifications (ISO 27001 A.5.5 / SOC 2 operational alerting). Each channel is
// opt-in; with none enabled, notifications remain in-app only. When more than one
// is enabled, each notification is fanned out to all of them.
type NotificationsConfig struct {
	Webhook NotificationWebhookConfig `yaml:"webhook"`
	Email   NotificationEmailConfig   `yaml:"email"`
	Slack   NotificationChatConfig    `yaml:"slack"`
	Teams   NotificationChatConfig    `yaml:"teams"`
}

// NotificationChatConfig configures a Slack or Teams channel: an incoming-webhook
// URL (which carries the platform's secret token, so prefer the env var).
type NotificationChatConfig struct {
	Enabled    bool   `yaml:"enabled"`
	WebhookURL string `yaml:"webhook_url"`
}

// GetWebhookURL returns the resolved Slack incoming-webhook URL.
func (c *NotificationsConfig) GetSlackWebhookURL() string {
	return resolveSecret("KEYORIX_NOTIFY_SLACK_WEBHOOK", c.Slack.WebhookURL)
}

// GetTeamsWebhookURL returns the resolved Teams incoming-webhook URL.
func (c *NotificationsConfig) GetTeamsWebhookURL() string {
	return resolveSecret("KEYORIX_NOTIFY_TEAMS_WEBHOOK", c.Teams.WebhookURL)
}

// ComplianceDigestConfig configures the scheduled compliance digest (ISO 27001 /
// SOC 2 continuous monitoring): a periodic posture + control-matrix summary
// broadcast to the configured notification channels. Opt-in (default off); requires
// at least one notification channel to have somewhere to deliver.
type ComplianceDigestConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Schedule string `yaml:"schedule"`
}

// GetInterval returns the digest interval, parsing Schedule as a Go duration (e.g.
// "24h", "168h"); defaults to 24h when unset or unparseable.
func (c ComplianceDigestConfig) GetInterval() time.Duration {
	if c.Schedule != "" {
		if d, err := time.ParseDuration(c.Schedule); err == nil && d > 0 {
			return d
		}
	}
	return 24 * time.Hour
}

// NotificationEmailConfig configures the SMTP notification channel: each
// notification is emailed (plaintext) to the recipient via the operator's relay.
// Mirrors the credential-delivery SMTP settings (ADR-028).
type NotificationEmailConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"` // use KEYORIX_NOTIFY_SMTP_PASSWORD env var instead
	From     string `yaml:"from"`
	TLS      string `yaml:"tls"` // starttls | implicit | none(dev-only)
	// BroadcastTo is the destination address for BROADCAST notifications — the
	// scheduled compliance digest and auto-rotation-failure alerts (#221) — when
	// email is the channel carrying them. Unlike a per-user notification (whose
	// recipient is resolved from the user's account), a broadcast has no single
	// addressee, so without this the email channel has nowhere to route it and the
	// broadcast silently never sends. Optional: leave unset if Slack/Teams/webhook
	// already covers deployment-wide broadcasts, or if email-only broadcast alerting
	// isn't wanted.
	BroadcastTo string `yaml:"broadcast_to"`
}

// GetPassword returns the resolved SMTP password, preferring the environment variable.
func (c *NotificationEmailConfig) GetPassword() string {
	return resolveSecret("KEYORIX_NOTIFY_SMTP_PASSWORD", c.Password)
}

// NotificationWebhookConfig configures the webhook notification channel: each
// notification is POSTed as JSON to Endpoint, optionally bearer-authenticated.
type NotificationWebhookConfig struct {
	Enabled            bool   `yaml:"enabled"`
	Endpoint           string `yaml:"endpoint"`
	Token              string `yaml:"token"` // use KEYORIX_NOTIFY_WEBHOOK_TOKEN env var instead
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	// AllowPrivateNetworkTarget opts the endpoint out of the SSRF guard — a
	// SEPARATE decision from InsecureSkipVerify; see notifychan.WebhookConfig.
	AllowPrivateNetworkTarget bool `yaml:"insecure_allow_private_network_notify_target"`
	// AllowInsecureTransport permits a plaintext (http://) endpoint to a
	// non-loopback host. False by default: Endpoint must be https unless it
	// targets loopback. A SEPARATE decision from AllowPrivateNetworkTarget
	// (previously conflated: enabling AllowPrivateNetworkTarget alone used to
	// ALSO silently unlock cleartext HTTP to any public host, not just a
	// private one). Every use of this opt-out is logged; see
	// notifychan.WebhookConfig.
	AllowInsecureTransport bool `yaml:"insecure_allow_plaintext_notify_transport"`
	// SigningSecret HMAC-signs each payload (X-Keyorix-Signature) so the receiver can
	// verify authenticity. Use KEYORIX_NOTIFY_WEBHOOK_SIGNING_SECRET instead of the file.
	SigningSecret string `yaml:"signing_secret"`
}

// GetToken returns the resolved webhook token, preferring the environment variable.
func (c *NotificationWebhookConfig) GetToken() string {
	return resolveSecret("KEYORIX_NOTIFY_WEBHOOK_TOKEN", c.Token)
}

// GetSigningSecret returns the resolved webhook signing secret, preferring the env var.
func (c *NotificationWebhookConfig) GetSigningSecret() string {
	return resolveSecret("KEYORIX_NOTIFY_WEBHOOK_SIGNING_SECRET", c.SigningSecret)
}
