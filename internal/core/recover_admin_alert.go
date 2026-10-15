// recover_admin_alert.go — Akeyless-style alerting on recover-admin use
// (F7). `recover-admin` is an offline/host-access CLI command that bypasses
// RBAC by design (docs/design-b2-recover-admin.md) and already writes an
// "admin.recover_admin" audit event (server/admin/recover_admin_logic.go).
// This closes the loop: since recover-admin runs while the server is
// typically stopped (or, in HA, may run against a live DB from a different
// process), nobody watching the server's own process sees it happen in real
// time. RunRecoverAdminAlerting finds every such event not yet notified and
// broadcasts a high-severity alert to every configured notification
// channel, then advances a system_metadata high-water mark so a restart (or
// the next scheduler tick) never re-notifies the same event.
package core

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// recoverAdminAuditEventType must match the literal EventType
// recordRecoveryAuditEvent (server/admin/recover_admin_logic.go) writes.
const recoverAdminAuditEventType = "admin.recover_admin"

// recoverAdminAlertHighWaterKey is the system_metadata key (ADR-029's
// key/value store) recording the highest AuditEvent.ID already notified.
// Unlike a one-time boolean marker (see userBaselineRoleBackfillMarkerKey),
// this advances on every run -- recover-admin can legitimately be used more
// than once over an install's lifetime, and each use must alert.
const recoverAdminAlertHighWaterKey = "recover_admin_alert_last_notified_id"

// recoverAdminAlertBatchSize bounds one alerting pass. recover-admin use is
// rare (a real account-lockout recovery); this only guards against an
// unbounded query if the high-water mark were ever reset or corrupted.
const recoverAdminAlertBatchSize = 200

// RunRecoverAdminAlerting finds every "admin.recover_admin" audit event
// with ID greater than the stored high-water mark, sends one high-severity
// alert per event to every enabled NotificationChannel, and advances the
// mark to the highest ID processed. Returns the number of events alerted
// on. Safe to call repeatedly (idempotent): a run with nothing new is a
// no-op, and the mark only advances after a batch is dispatched, so a crash
// mid-run at worst re-notifies that one in-flight batch on retry, never
// skips a real event.
func (c *KeyorixCore) RunRecoverAdminAlerting(ctx context.Context) (int, error) {
	highWater, err := c.recoverAdminAlertHighWater(ctx)
	if err != nil {
		return 0, err
	}

	action := recoverAdminAuditEventType
	events, _, err := c.storage.GetAuditLogs(ctx, &storage.AuditFilter{
		Action:    &action,
		AfterID:   &highWater,
		Ascending: true,
		Count:     storage.AuditCountNone,
		PageSize:  recoverAdminAlertBatchSize,
	})
	if err != nil {
		return 0, fmt.Errorf("recover-admin alerting: list events: %w", err)
	}
	if len(events) == 0 {
		return 0, nil
	}

	// ListNotificationChannels (the core-layer wrapper), not
	// c.storage.ListNotificationChannels directly (#2433): the raw storage
	// rows' URL is encrypted (URLEnc/URLMeta) -- only the wrapper decrypts it
	// into ch.URL, which the postJSONToURL call below needs to actually dial.
	channels, err := c.ListNotificationChannels(ctx)
	if err != nil {
		return 0, fmt.Errorf("recover-admin alerting: list channels: %w", err)
	}

	maxID := highWater
	for _, ev := range events {
		c.broadcastRecoverAdminAlert(ctx, ev, channels)
		if ev.ID > maxID {
			maxID = ev.ID
		}
	}
	// Advance the mark even if some channel deliveries above failed
	// (best-effort, logged) -- matches RunAlertEscalation's own delivery
	// semantics: a down webhook must not make this scheduler retry the same
	// event forever.
	if err := c.storage.SetSystemMetadata(ctx, recoverAdminAlertHighWaterKey, strconv.FormatUint(uint64(maxID), 10)); err != nil {
		return len(events), fmt.Errorf("recover-admin alerting: advance high-water mark: %w", err)
	}
	return len(events), nil
}

// recoverAdminAlertHighWater reads the stored high-water mark, defaulting
// to 0 (never notified) both when the key has never been set and when its
// value is unexpectedly not a valid integer -- fail safe toward alerting
// (a possible duplicate notification) rather than silently going quiet on a
// corrupted marker.
func (c *KeyorixCore) recoverAdminAlertHighWater(ctx context.Context) (uint, error) {
	val, found, err := c.storage.GetSystemMetadata(ctx, recoverAdminAlertHighWaterKey)
	if err != nil {
		return 0, fmt.Errorf("recover-admin alerting: read high-water mark: %w", err)
	}
	if !found {
		return 0, nil
	}
	n, perr := strconv.ParseUint(val, 10, strconv.IntSize)
	if perr != nil {
		log.Printf("recover-admin alerting: high-water mark %q is not a valid integer, treating as 0: %v", val, perr)
		return 0, nil
	}
	return uint(n), nil
}

// broadcastRecoverAdminAlert delivers one recover-admin-use alert to every
// enabled notification channel, regardless of any AlertEscalationPolicy --
// this is a mandatory security control, not a policy-routed anomaly alert.
// Reuses postJSONToURL (the same SSRF-guarded, redirect-refusing POST path
// alert escalation uses) for webhook/slack; other channel types log, same
// as dispatchToChannel's own convention pending full NotificationSink
// integration.
func (c *KeyorixCore) broadcastRecoverAdminAlert(ctx context.Context, ev *models.AuditEvent, channels []*models.NotificationChannel) {
	for _, ch := range channels {
		if !ch.Enabled {
			continue
		}
		switch ch.Type {
		case "webhook", "slack":
			err := c.postJSONToURL(ctx, ch.URL, map[string]any{
				"event":          "admin.recover_admin_used",
				"severity":       "high",
				"audit_event_id": ev.ID,
				"description":    ev.Description,
				"occurred_at":    ev.EventTime.Format(time.RFC3339),
				"channel":        ch.Name,
			})
			if err != nil {
				log.Printf("recover-admin alert: channel %q: dispatch failed: %v", ch.Name, err)
			}
		default:
			log.Printf("recover-admin alert: channel %q (type=%s): recover-admin use (audit event %d, %s) logged (full delivery via notification sink)",
				ch.Name, ch.Type, ev.ID, ev.EventTime.Format(time.RFC3339))
		}
	}
}
