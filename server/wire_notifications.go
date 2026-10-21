package main

import (
	"context"
	"fmt"
	"log"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/ports"
	"github.com/keyorixhq/keyorix/internal/notifychan"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
)

// wireNotificationURLBackfill is a core wiring step (coreWiringSteps in main.go).
func wireNotificationURLBackfill(cw *coreWiring) error {
	store, encSvc := cw.store, cw.encSvc
	// #2433: bring every NotificationChannel row's webhook/Slack/Teams URL (the
	// bearer credential) into the encrypted, self-describing url_enc/url_meta
	// columns -- a real envelope when encSvc is wired and enabled, an
	// explicitly-tagged plaintext passthrough otherwise. Local-storage-only
	// (notification channels have no remote-storage implementation at all).
	//
	// #2468: this FAILS STARTUP rather than logging and continuing, and that
	// choice is deliberate over the "it is idempotent, a later restart will
	// retry" alternative. The migration now has a second, recurring job besides
	// the one-time legacy backfill: upgrading a plaintext-passthrough row the
	// first time encryption is enabled (see its own doc comment). A permanently
	// failing run of THAT job leaves webhook bearer credentials in plaintext at
	// rest on an install that has explicitly configured encryption -- and
	// leaves them readable and working, so nothing else ever surfaces it. That
	// is precisely the condition the SecretValueEncryptionActive check a few
	// lines above refuses to start on, for the same reason.
	if ls, ok := store.(*localstore.LocalStorage); ok {
		var encryptor ports.EncryptionProvider
		if encSvc != nil {
			encryptor = encSvc
		}
		n, merr := ls.MigrateNotificationChannelURLsToEncrypted(context.Background(), encryptor)
		if merr != nil {
			return fmt.Errorf("notification channel URL encryption backfill failed: %w -- refusing to start rather than leave a webhook credential unencrypted at rest", merr)
		}
		if n > 0 {
			log.Printf("notification channel URL encryption backfill: migrated %d channel(s)", n)
		}
	}
	return nil
}

// wireNotificationChannels is a core wiring step (coreWiringSteps in main.go).
func wireNotificationChannels(cw *coreWiring) error {
	cfg, coreService := cw.cfg, cw.core
	// Wire external notification channels if configured.
	//
	// #391: two distinct fan-out sets are built, not one. broadcastSinks (every
	// enabled channel) backs the deployment-wide, aggregate notifications
	// (compliance digest, auto-rotation-failure summary) — those are genuinely
	// relevant to the whole deployment's ops audience. recipientSinks (only
	// channels that can address a single user — currently email) backs every
	// per-user/per-project notification (secret shared, share revoked, ownership
	// transferred, access requested, anomaly alert, break-glass activation, …).
	// Slack/Teams/webhook are deliberately excluded from recipientSinks: they are
	// one fixed destination an operator configures, with no per-user chat-identity
	// mapping in this codebase to target a specific recipient, so routing a
	// per-user event there would broadcast it to everyone with channel visibility
	// regardless of project membership or secret access. See
	// internal/core/notifications.go and internal/core/service.go.
	var broadcastSinks []core.NotificationSink
	var recipientSinks []core.NotificationSink
	if wc := cfg.Notifications.Webhook; wc.Enabled {
		sink, werr := notifychan.NewWebhook(notifychan.WebhookConfig{
			Endpoint:                  wc.Endpoint,
			Token:                     wc.GetToken(),
			InsecureSkipVerify:        wc.InsecureSkipVerify,
			AllowPrivateNetworkTarget: wc.AllowPrivateNetworkTarget,
			AllowInsecureTransport:    wc.AllowInsecureTransport,
			SigningSecret:             wc.GetSigningSecret(),
		})
		if werr != nil {
			return fmt.Errorf("failed to init notification webhook channel: %w", werr)
		}
		broadcastSinks = append(broadcastSinks, sink)
		log.Printf("Notification webhook channel enabled (endpoint=%s)", wc.Endpoint)
	}
	if ec := cfg.Notifications.Email; ec.Enabled {
		sink, eerr := notifychan.NewEmail(notifychan.EmailConfig{
			Host:        ec.Host,
			Port:        ec.Port,
			Username:    ec.Username,
			Password:    ec.GetPassword(),
			From:        ec.From,
			TLS:         ec.TLS,
			BroadcastTo: ec.BroadcastTo,
		})
		if eerr != nil {
			return fmt.Errorf("failed to init notification email channel: %w", eerr)
		}
		broadcastSinks = append(broadcastSinks, sink)
		recipientSinks = append(recipientSinks, sink)
		log.Printf("Notification email channel enabled (host=%s)", ec.Host)
	}
	if cfg.Notifications.Slack.Enabled {
		sink, serr := notifychan.NewChat(notifychan.ChatConfig{Kind: notifychan.ChatSlack, WebhookURL: cfg.Notifications.GetSlackWebhookURL()})
		if serr != nil {
			return fmt.Errorf("failed to init Slack notification channel: %w", serr)
		}
		broadcastSinks = append(broadcastSinks, sink)
		log.Printf("Notification Slack channel enabled")
	}
	if cfg.Notifications.Teams.Enabled {
		sink, terr := notifychan.NewChat(notifychan.ChatConfig{Kind: notifychan.ChatTeams, WebhookURL: cfg.Notifications.GetTeamsWebhookURL()})
		if terr != nil {
			return fmt.Errorf("failed to init Teams notification channel: %w", terr)
		}
		broadcastSinks = append(broadcastSinks, sink)
		log.Printf("Notification Teams channel enabled")
	}
	// #221: email-only, with no email.broadcast_to configured, has no destination
	// for a deployment-wide broadcast (compliance digest, auto-rotation-failure
	// alert) to route to — it will keep no-op'ing every time one fires. Warn at
	// startup rather than let an operator discover it only from the (also newly
	// added, #221) dropped-delivery metric/log after the fact.
	if cfg.Notifications.Email.Enabled && cfg.Notifications.Email.BroadcastTo == "" &&
		!cfg.Notifications.Webhook.Enabled && !cfg.Notifications.Slack.Enabled && !cfg.Notifications.Teams.Enabled {
		log.Printf("WARNING: notifications.email is the only enabled notification channel and notifications.email.broadcast_to is not set — the compliance digest and auto-rotation-failure alerts have no destination to broadcast to and will silently no-op every time they fire; set notifications.email.broadcast_to to an admin/ops address to receive them")
	}
	if sink := notifychan.NewMulti(broadcastSinks...); sink != nil {
		coreService.SetNotificationSink(sink)
	}
	if sink := notifychan.NewMulti(recipientSinks...); sink != nil {
		coreService.SetRecipientNotificationSink(sink)
	}
	return nil
}
