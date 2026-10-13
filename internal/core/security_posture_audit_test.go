package core

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// First boot (#3155): no previous snapshot exists, so there is no "change". One
// baseline event carries EVERY setting (nothing is dropped from the record), and
// a setting that does not read as off ("true", or a non-boolean mode) still gets
// its own change event, so a weakening in effect at first start stays visible.
// Settings that are simply off ("false") do not each get a "" -> "false" row.
func TestReconcileSecurityPostureSnapshot_FirstBootRecordsBaselineAndFlagsNonOffSettings(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetSystemMetadata", mock.Anything, securityPostureSnapshotMetadataKey).Return("", false, nil)

	var captured []*models.AuditEvent
	ms.On("LogAuditEvent", mock.Anything, mock.AnythingOfType("*models.AuditEvent")).
		Run(func(args mock.Arguments) {
			captured = append(captured, args.Get(1).(*models.AuditEvent))
		}).Return(nil)
	ms.On("SetSystemMetadata", mock.Anything, securityPostureSnapshotMetadataKey, mock.AnythingOfType("string")).Return(nil)

	snapshot := map[string]string{
		"security.insecure_allow_unsafe_file_permissions":      "false",
		"audit_checkpoints.insecure_disable_audit_checkpoints": "true",
		"security.insecure_startup_validation_mode":            "warn",
	}
	NewKeyorixCore(ms).ReconcileSecurityPostureSnapshot(context.Background(), snapshot)

	var baselines, changes int
	changedSettings := map[string]bool{}
	for _, e := range captured {
		assert.Equal(t, "system", e.ActorType)
		switch e.EventType {
		case EventSecurityPostureBaselineRecorded:
			baselines++
			var got map[string]string
			assert.NoError(t, json.Unmarshal([]byte(e.Diff), &got))
			assert.Equal(t, snapshot, got, "the baseline event must record every setting")
		case EventSecurityPostureSettingChanged:
			changes++
			var ch securityPostureSettingChange
			assert.NoError(t, json.Unmarshal([]byte(e.Diff), &ch))
			changedSettings[ch.Setting] = true
		}
	}
	assert.Equal(t, 1, baselines)
	assert.Equal(t, 2, changes, "only the two settings that do not read as off keep their own event")
	assert.True(t, changedSettings["audit_checkpoints.insecure_disable_audit_checkpoints"])
	assert.True(t, changedSettings["security.insecure_startup_validation_mode"])
}

// A FAILED read of the previous snapshot is not a first start: it keeps the
// per-setting reporting, so a flip is never hidden behind a quiet baseline.
func TestReconcileSecurityPostureSnapshot_FailedReadIsNotAQuietBaseline(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetSystemMetadata", mock.Anything, securityPostureSnapshotMetadataKey).Return("", false, assert.AnError)
	var captured []*models.AuditEvent
	ms.On("LogAuditEvent", mock.Anything, mock.AnythingOfType("*models.AuditEvent")).
		Run(func(args mock.Arguments) {
			captured = append(captured, args.Get(1).(*models.AuditEvent))
		}).Return(nil)
	ms.On("SetSystemMetadata", mock.Anything, securityPostureSnapshotMetadataKey, mock.AnythingOfType("string")).Return(nil)

	NewKeyorixCore(ms).ReconcileSecurityPostureSnapshot(context.Background(), map[string]string{
		"security.insecure_allow_unsafe_file_permissions": "false",
	})

	assert.Len(t, captured, 1)
	assert.Equal(t, EventSecurityPostureSettingChanged, captured[0].EventType)
}

// Kept from before #3155 for the persistence half: the snapshot is stored for the
// next boot to diff against.
func TestReconcileSecurityPostureSnapshot_FirstBootPersistsSnapshot(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetSystemMetadata", mock.Anything, securityPostureSnapshotMetadataKey).Return("", false, nil)

	var captured []*models.AuditEvent
	ms.On("LogAuditEvent", mock.Anything, mock.AnythingOfType("*models.AuditEvent")).
		Run(func(args mock.Arguments) {
			captured = append(captured, args.Get(1).(*models.AuditEvent))
		}).Return(nil)

	var persisted string
	ms.On("SetSystemMetadata", mock.Anything, securityPostureSnapshotMetadataKey, mock.AnythingOfType("string")).
		Run(func(args mock.Arguments) { persisted = args.Get(2).(string) }).Return(nil)

	c := NewKeyorixCore(ms)
	c.ReconcileSecurityPostureSnapshot(context.Background(), map[string]string{
		"security.insecure_allow_unsafe_file_permissions":      "false",
		"audit_checkpoints.insecure_disable_audit_checkpoints": "false",
	})

	assert.Len(t, captured, 1, "all-off first boot: just the baseline event")
	assert.Equal(t, EventSecurityPostureBaselineRecorded, captured[0].EventType)

	var snap map[string]string
	assert.NoError(t, json.Unmarshal([]byte(persisted), &snap))
	assert.Equal(t, "false", snap["security.insecure_allow_unsafe_file_permissions"])
}

// An unchanged setting between two boots must NOT produce an audit event —
// this is the whole point of diffing rather than auditing every setting on
// every boot unconditionally (which would make the audit trail useless
// noise, burying the one change an operator actually needs to see).
func TestReconcileSecurityPostureSnapshot_UnchangedSettingProducesNoEvent(t *testing.T) {
	ms := new(MockStorage)
	previous, _ := json.Marshal(map[string]string{"security.insecure_allow_unsafe_file_permissions": "false"})
	ms.On("GetSystemMetadata", mock.Anything, securityPostureSnapshotMetadataKey).Return(string(previous), true, nil)
	ms.On("SetSystemMetadata", mock.Anything, securityPostureSnapshotMetadataKey, mock.AnythingOfType("string")).Return(nil)

	c := NewKeyorixCore(ms)
	c.ReconcileSecurityPostureSnapshot(context.Background(), map[string]string{
		"security.insecure_allow_unsafe_file_permissions": "false",
	})

	ms.AssertNotCalled(t, "LogAuditEvent", mock.Anything, mock.Anything)
}

// A setting that flips value between two boots must produce exactly one
// audit event, carrying BOTH the old and the new value — this is the actual
// ADR-112 requirement ("write an audit event with the old and new values for
// any difference since the previous start"), not just "something changed."
func TestReconcileSecurityPostureSnapshot_ChangedSettingAuditsOldAndNewValue(t *testing.T) {
	ms := new(MockStorage)
	previous, _ := json.Marshal(map[string]string{"security.insecure_allow_unsafe_file_permissions": "false"})
	ms.On("GetSystemMetadata", mock.Anything, securityPostureSnapshotMetadataKey).Return(string(previous), true, nil)

	var captured *models.AuditEvent
	ms.On("LogAuditEvent", mock.Anything, mock.AnythingOfType("*models.AuditEvent")).
		Run(func(args mock.Arguments) { captured = args.Get(1).(*models.AuditEvent) }).Return(nil)
	ms.On("SetSystemMetadata", mock.Anything, securityPostureSnapshotMetadataKey, mock.AnythingOfType("string")).Return(nil)

	c := NewKeyorixCore(ms)
	c.ReconcileSecurityPostureSnapshot(context.Background(), map[string]string{
		"security.insecure_allow_unsafe_file_permissions": "true",
	})

	if assert.NotNil(t, captured) {
		assert.Contains(t, captured.Description, `"false" -> "true"`)
		assert.Contains(t, captured.Diff, `"old_value":"false"`)
		assert.Contains(t, captured.Diff, `"new_value":"true"`)
	}
}

// A setting present in the previous snapshot but absent from THIS boot's
// (e.g. the registry dropped an entry in a newer binary) still audits as a
// change, with NewValue "" — removal is itself a security-relevant event,
// not something to silently drop from the trail.
func TestReconcileSecurityPostureSnapshot_RemovedSettingStillAudits(t *testing.T) {
	ms := new(MockStorage)
	previous, _ := json.Marshal(map[string]string{"some.retired_setting": "true"})
	ms.On("GetSystemMetadata", mock.Anything, securityPostureSnapshotMetadataKey).Return(string(previous), true, nil)

	var captured *models.AuditEvent
	ms.On("LogAuditEvent", mock.Anything, mock.AnythingOfType("*models.AuditEvent")).
		Run(func(args mock.Arguments) { captured = args.Get(1).(*models.AuditEvent) }).Return(nil)
	ms.On("SetSystemMetadata", mock.Anything, securityPostureSnapshotMetadataKey, mock.AnythingOfType("string")).Return(nil)

	c := NewKeyorixCore(ms)
	c.ReconcileSecurityPostureSnapshot(context.Background(), map[string]string{})

	if assert.NotNil(t, captured) {
		assert.Contains(t, captured.Diff, `"setting":"some.retired_setting"`)
		assert.Contains(t, captured.Diff, `"new_value":""`)
	}
}

// A GetSystemMetadata failure must not panic or block persisting this
// boot's snapshot — it degrades to "can't diff this boot" (every setting
// reported as a first-boot-style addition), not "can't boot."
func TestReconcileSecurityPostureSnapshot_ReadFailureDegradesGracefully(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetSystemMetadata", mock.Anything, securityPostureSnapshotMetadataKey).
		Return("", false, assert.AnError)
	ms.On("LogAuditEvent", mock.Anything, mock.AnythingOfType("*models.AuditEvent")).Return(nil)
	ms.On("SetSystemMetadata", mock.Anything, securityPostureSnapshotMetadataKey, mock.AnythingOfType("string")).Return(nil)

	c := NewKeyorixCore(ms)
	assert.NotPanics(t, func() {
		c.ReconcileSecurityPostureSnapshot(context.Background(), map[string]string{"x": "true"})
	})
}

// A posture-setting change is an informational system event that was
// RECORDED successfully -- not a failed operation. It must carry
// Success == true, matching every other startup-time system audit event
// (AuditLicenseState's license.evaluated). Recording it as false made every
// genuine posture change look like a failed operation to an operator
// filtering the audit trail on success, i.e. it vanished from a "what
// changed" view and polluted a "what failed" one.
func TestReconcileSecurityPostureSnapshot_ChangeEventRecordsSuccessTrue(t *testing.T) {
	ms := new(MockStorage)
	previous, _ := json.Marshal(map[string]string{"security.insecure_allow_unsafe_file_permissions": "false"})
	ms.On("GetSystemMetadata", mock.Anything, securityPostureSnapshotMetadataKey).Return(string(previous), true, nil)

	var captured *models.AuditEvent
	ms.On("LogAuditEvent", mock.Anything, mock.AnythingOfType("*models.AuditEvent")).
		Run(func(args mock.Arguments) { captured = args.Get(1).(*models.AuditEvent) }).Return(nil)
	ms.On("SetSystemMetadata", mock.Anything, securityPostureSnapshotMetadataKey, mock.AnythingOfType("string")).Return(nil)

	c := NewKeyorixCore(ms)
	c.ReconcileSecurityPostureSnapshot(context.Background(), map[string]string{
		"security.insecure_allow_unsafe_file_permissions": "true",
	})

	if assert.NotNil(t, captured) && assert.NotNil(t, captured.Success, "Success must be set") {
		assert.True(t, *captured.Success,
			"a recorded posture-setting change is not a failed operation: Success must be true")
	}
}
