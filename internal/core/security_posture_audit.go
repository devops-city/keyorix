// security_posture_audit.go -- ADR-112 opt-out rule (secure-by-default
// baseline, item 2): the start-to-start settings diff. Config has no hot
// reload (it's re-read once at process start, per internal/config.Load), so
// the only way to notice a security-relevant setting changing between two
// starts is to compare THIS boot's values against a snapshot of the
// PREVIOUS boot's values. That comparison, and the audit event it writes for
// any difference, lives here; computing the snapshot itself (which settings,
// and their current values) lives in internal/config's InsecureSettingsRegistry
// -- this package deliberately does not import internal/config (core stays
// independent of the server's own config schema), so server/main.go computes
// the snapshot from the registry and passes it in as a plain map.
package core

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// EventSecurityPostureSettingChanged is the audit event type recorded when a
// security-relevant setting's effective value differs from what it was at
// the previous start (ADR-112 opt-out rule, item 2).
const EventSecurityPostureSettingChanged = "security.posture_setting_changed" // #nosec G101 -- audit event type, not a credential

// securityPostureSnapshotMetadataKey is the SystemMetadata key under which
// ReconcileSecurityPostureSnapshot persists the settings snapshot for the
// NEXT start to diff against.
const securityPostureSnapshotMetadataKey = "security_posture_settings_snapshot"

// securityPostureSettingChange is the structured payload stored in a
// security.posture_setting_changed event's Diff field.
type securityPostureSettingChange struct {
	Setting  string `json:"setting"`
	OldValue string `json:"old_value"`
	NewValue string `json:"new_value"`
}

// logSecurityPostureSettingChanged records that setting's effective value
// differs from what it was at the previous start. oldValue is "" for a
// setting that didn't exist in the previous snapshot at all (e.g. this
// process's binary is newer and the registry grew a new entry) — that is
// still reported as a change, not silently skipped, since "newly appeared at
// a non-default value" is exactly the kind of thing an operator reviewing
// the audit trail needs to see.
func (c *KeyorixCore) logSecurityPostureSettingChanged(ctx context.Context, change securityPostureSettingChange) {
	// The change was recorded, so the event succeeded: same convention as
	// AuditLicenseState. false would file every posture change under "failed
	// operations" in any success-filtered view of the trail.
	ok := true
	diff, _ := json.Marshal(change)
	c.emitAudit(ctx, &models.AuditEvent{
		EventType: EventSecurityPostureSettingChanged,
		Description: fmt.Sprintf(
			"security-relevant setting %q changed since the previous start: %q -> %q",
			change.Setting, change.OldValue, change.NewValue),
		Diff:      string(diff),
		Success:   &ok,
		ActorType: "system",
		EventTime: time.Now(),
	})
}

// EventSecurityPostureBaselineRecorded is the single audit event written on the
// first start, carrying every registry setting's initial value in its Diff.
const EventSecurityPostureBaselineRecorded = "security.posture_baseline_recorded" // #nosec G101 -- audit event type, not a credential

// logSecurityPostureBaseline records the first start's complete settings snapshot.
func (c *KeyorixCore) logSecurityPostureBaseline(ctx context.Context, snapshot map[string]string) {
	ok := true
	diff, _ := json.Marshal(snapshot)
	c.emitAudit(ctx, &models.AuditEvent{
		EventType:   EventSecurityPostureBaselineRecorded,
		Description: fmt.Sprintf("security posture baseline recorded at first start: %d security-relevant settings", len(snapshot)),
		Diff:        string(diff),
		Success:     &ok,
		ActorType:   "system",
		EventTime:   time.Now(),
	})
}

// ReconcileSecurityPostureSnapshot compares snapshot (this boot's security-
// relevant setting values, keyed by internal/config.InsecureSetting.Name) to
// the snapshot persisted at the end of the previous boot, writes a
// security.posture_setting_changed audit event for every setting whose value
// differs (added, removed, or changed), and persists snapshot as the new
// baseline for the NEXT boot to diff against.
//
// Best-effort, matching this codebase's established convention for a
// startup-only audit side effect (see AuditLicenseState): a read/write
// failure here is logged but never returned as an error, since the server
// has already finished booting everything this gates on by the time this
// runs (server/main.go calls it right after initializeCoreService succeeds,
// alongside AuditLicenseState) and a transient audit-metadata hiccup must
// not take an otherwise-healthy server back down.
func (c *KeyorixCore) ReconcileSecurityPostureSnapshot(ctx context.Context, snapshot map[string]string) {
	raw, found, err := c.storage.GetSystemMetadata(ctx, securityPostureSnapshotMetadataKey)
	// firstStart is only true when the read SUCCEEDED and found nothing: a failed
	// read must keep the old behaviour (every setting reported), never a quiet baseline.
	firstStart := err == nil && !found
	if err != nil {
		log.Printf("security posture snapshot: failed to read the previous start's snapshot (continuing without diffing): %v", err)
		found = false
	}
	previous := map[string]string{}
	if found {
		if err := json.Unmarshal([]byte(raw), &previous); err != nil {
			log.Printf("security posture snapshot: failed to parse the previous start's snapshot (continuing without diffing): %v", err)
			previous = map[string]string{}
		}
	}

	changedKeys := make(map[string]bool, len(snapshot)+len(previous))
	if firstStart {
		// First start ever (the read succeeded and no snapshot exists): there is
		// no previous start to differ from, so one baseline
		// event carries the whole snapshot instead of one "" -> "false" row per
		// setting at the head of the audit trail (#3155). Only a setting that does
		// not read as off ("false") still gets its own change event, so a deployment
		// that boots with a weakening already in effect (or a non-boolean mode) is as
		// visible as before.
		c.logSecurityPostureBaseline(ctx, snapshot)
		for k, newVal := range snapshot {
			if newVal != "false" {
				changedKeys[k] = true
			}
		}
	} else {
		for k, newVal := range snapshot {
			if oldVal, ok := previous[k]; !ok || oldVal != newVal {
				changedKeys[k] = true
			}
		}
	}
	for k := range previous {
		if _, ok := snapshot[k]; !ok {
			changedKeys[k] = true
		}
	}
	// Sorted iteration: deterministic audit-write order, so two otherwise-
	// identical boots produce byte-identical event sequences (easier to diff
	// in a test, and no reason not to).
	sortedKeys := make([]string, 0, len(changedKeys))
	for k := range changedKeys {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)
	for _, k := range sortedKeys {
		c.logSecurityPostureSettingChanged(ctx, securityPostureSettingChange{
			Setting:  k,
			OldValue: previous[k], // "" (Go zero value) when absent from the previous snapshot
			NewValue: snapshot[k], // "" when removed from the registry since the previous start
		})
	}

	out, err := json.Marshal(snapshot)
	if err != nil {
		log.Printf("security posture snapshot: failed to serialize this start's snapshot (NOT persisted -- the next start will diff against the OLDER one instead): %v", err)
		return
	}
	if err := c.storage.SetSystemMetadata(ctx, securityPostureSnapshotMetadataKey, string(out)); err != nil {
		log.Printf("security posture snapshot: failed to persist this start's snapshot: %v", err)
	}
}
