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
// this advances on every run that sees new audit rows (to the highest audit id
// examined, whether or not an event matched) -- recover-admin can legitimately
// be used more than once over an install's lifetime, and each use must alert.
const recoverAdminAlertHighWaterKey = "recover_admin_alert_last_notified_id"

// recoverAdminAlertBatchSize bounds one alerting pass. recover-admin use is
// rare (a real account-lockout recovery); this only guards against a huge
// batch of alerts if the high-water mark were ever reset or corrupted.
const recoverAdminAlertBatchSize = 200

// recoverAdminAlertScanWindow is the id span one list query covers. Audit ids
// are dense, so it is about that many rows: a fraction of a second even for an
// unindexed filter walk on SQLite (SQLITE-PERF-1 measured ~2.6 s per million
// rows) -- short enough that no read snapshot is held long enough to hold back
// the WAL checkpoint.
const recoverAdminAlertScanWindow = 100_000

// RunRecoverAdminAlerting finds every "admin.recover_admin" audit event
// with ID greater than the stored high-water mark, sends one high-severity
// alert per event to every enabled NotificationChannel, and advances the
// mark. Returns the number of events alerted on.
//
// Cost: the mark is "the highest audit id examined", not "the highest id
// alerted". A run reads the current highest id once (an O(1) primary-key read),
// scans only the id range (mark, highest], in windows of recoverAdminAlertScanWindow,
// and stores highest, so the next run starts there: every run reads O(rows added
// since the previous run), also on an install that never used recover-admin. (Before, the mark moved only when an
// event matched, so such an install re-scanned the whole table, filtering the
// unindexed event_type, every 10 minutes and held a read snapshot all the while.)
//
// Why no row can be skipped: highest is read BEFORE the scan, and audit ids
// commit in order (nextval is taken under the audit advisory lock, held until
// commit, with the sequence cache pinned to 1 by CheckAuditIDSequenceCache; on
// SQLite writers are serialised). So every row with an id <= highest is already
// committed and visible to the scan; a row committing later has a larger id and
// is covered by the next run.
//
// Alert-once: every use alerts exactly once in normal operation. The mark
// advances only after the batch is dispatched, so a crash (or a lease handover to
// another replica) between dispatch and the mark write can re-notify that one
// in-flight batch, never skip an event: at-least-once, as before. Replicas do not
// double-alert in steady state because the scheduler runs this under the
// single-replica lease (lockedRun, ADR-039) and the mark lives in the shared
// database; the write below is also monotonic (never moves the mark back), so a
// slow replica that lost the lease cannot undo a newer replica's progress.
// A full batch (recoverAdminAlertBatchSize events) advances only to its last
// event, leaving the rest for the next run.
func (c *KeyorixCore) RunRecoverAdminAlerting(ctx context.Context) (int, error) {
	cursor, err := c.recoverAdminAlertHighWater(ctx)
	if err != nil {
		return 0, err
	}

	// Read the upper bound before the scan (see the ordering argument above).
	// An empty table or a mark at/after the end (nothing new) is a no-op.
	highest, err := c.storage.MaxAuditEventID(ctx)
	if err != nil {
		return 0, fmt.Errorf("recover-admin alerting: read highest audit id: %w", err)
	}

	action := recoverAdminAuditEventType
	var channels []*models.NotificationChannel
	alerted := 0
	// Walk (cursor, highest] in id windows: each window is its own short read
	// (not one transaction over the whole range), and the mark is persisted per
	// window, so even the one-off catch-up on an install with millions of existing
	// audit rows holds no long read snapshot and a restart resumes where it was.
	for cursor < highest {
		if err := ctx.Err(); err != nil {
			return alerted, err
		}
		upTo := highest
		if highest-cursor > recoverAdminAlertScanWindow {
			upTo = cursor + recoverAdminAlertScanWindow
		}
		after := cursor
		events, _, err := c.storage.GetAuditLogs(ctx, &storage.AuditFilter{
			Action:    &action,
			AfterID:   &after,
			UpToID:    &upTo,
			Ascending: true,
			Count:     storage.AuditCountNone,
			PageSize:  recoverAdminAlertBatchSize,
		})
		if err != nil {
			return alerted, fmt.Errorf("recover-admin alerting: list events: %w", err)
		}

		// Everything in (cursor, upTo] was examined unless the batch was full, in
		// which case more matches may remain beyond the last one returned.
		next := upTo
		if len(events) > 0 {
			if channels == nil {
				// ListNotificationChannels (the core-layer wrapper), not
				// c.storage.ListNotificationChannels directly (#2433): the raw storage
				// rows' URL is encrypted (URLEnc/URLMeta) -- only the wrapper decrypts it
				// into ch.URL, which the postJSONToURL call below needs to actually dial.
				channels, err = c.ListNotificationChannels(ctx)
				if err != nil {
					return alerted, fmt.Errorf("recover-admin alerting: list channels: %w", err)
				}
				if channels == nil {
					channels = []*models.NotificationChannel{}
				}
			}
			last := cursor
			for _, ev := range events {
				c.broadcastRecoverAdminAlert(ctx, ev, channels)
				if ev.ID > last {
					last = ev.ID
				}
			}
			alerted += len(events)
			if len(events) >= recoverAdminAlertBatchSize {
				next = last
			}
		}
		// Advance the mark even if some channel deliveries above failed
		// (best-effort, logged) -- matches RunAlertEscalation's own delivery
		// semantics: a down webhook must not make this scheduler retry the same
		// event forever. An empty window is recorded too, so the next run does
		// not read it again.
		if err := c.advanceRecoverAdminAlertMark(ctx, next); err != nil {
			return alerted, err
		}
		if next < upTo {
			// Full batch: the rest of this window is left for the next run.
			break
		}
		cursor = next
	}
	return alerted, nil
}

// advanceRecoverAdminAlertMark stores mark as the high-water mark unless the
// stored value is already at or past it (monotonic: the mark never moves back).
func (c *KeyorixCore) advanceRecoverAdminAlertMark(ctx context.Context, mark uint) error {
	current, err := c.recoverAdminAlertHighWater(ctx)
	if err != nil {
		return err
	}
	if current >= mark {
		return nil
	}
	if err := c.storage.SetSystemMetadata(ctx, recoverAdminAlertHighWaterKey, strconv.FormatUint(uint64(mark), 10)); err != nil {
		return fmt.Errorf("recover-admin alerting: advance high-water mark: %w", err)
	}
	return nil
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
