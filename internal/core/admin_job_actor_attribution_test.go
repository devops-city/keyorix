// admin_job_actor_attribution_test.go — coordinator-requested table test (PR
// #2249 review): every /admin/jobs on-demand-trigger core function must
// attribute its "job ran" summary audit event to the REAL triggering caller
// when WithAuditActor tagged one, and to no one (nil UserID) when it didn't
// (the background scheduler's own untagged runs) — never silently defaulting
// to nil regardless of caller, the bug this whole item exists to close.
// rotation_reminders.go's own MAIN (non-empty) path was the specific
// regression caught by this table's first run: its early-return (0 policies)
// branch had been fixed, but the unconditional summary write at the end of
// the function still hardcoded nil.
package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// captureLastAdminJobAuditEvent runs fn against a fresh MockStorage configured
// by setup, and returns the LAST audit_events row LogAuditEvent was called
// with (nil if never called).
func captureLastAdminJobAuditEvent(t *testing.T, setup func(store *MockStorage), fn func(c *KeyorixCore)) *models.AuditEvent {
	t.Helper()
	store := new(MockStorage)
	setup(store)
	var captured *models.AuditEvent
	store.On("LogAuditEvent", mock.Anything, mock.AnythingOfType("*models.AuditEvent")).
		Run(func(args mock.Arguments) { captured = args.Get(1).(*models.AuditEvent) }).
		Return(nil)
	c := NewKeyorixCore(store)
	fn(c)
	return captured
}

// adminJobActorCase is one /admin/jobs core function's empty-path fixture.
type adminJobActorCase struct {
	name      string
	eventType string
	setup     func(store *MockStorage)
	run       func(c *KeyorixCore, ctx context.Context) error
}

func adminJobActorCases() []adminJobActorCase {
	return []adminJobActorCase{
		{
			name:      "anomaly-alerts",
			eventType: "admin_job.anomaly_alerts_run",
			setup: func(store *MockStorage) {
				store.On("ListUnalertedAnomalyAlerts", mock.Anything).Return([]models.AnomalyAlert{}, nil)
			},
			run: func(c *KeyorixCore, ctx context.Context) error { _, err := c.AlertNewAnomalies(ctx); return err },
		},
		{
			name:      "rotation-reminders",
			eventType: "admin_job.rotation_reminders_run",
			setup: func(store *MockStorage) {
				store.On("ListRotationPolicies", mock.Anything, mock.Anything, mock.Anything).Return([]*models.RotationPolicy{}, nil)
			},
			run: func(c *KeyorixCore, ctx context.Context) error { _, err := c.SendRotationReminders(ctx); return err },
		},
		{
			name:      "expiry-reminders",
			eventType: "admin_job.expiry_reminders_run",
			setup: func(store *MockStorage) {
				store.On("ListSecrets", mock.Anything, mock.Anything).Return([]*models.SecretNode{}, int64(0), nil)
			},
			run: func(c *KeyorixCore, ctx context.Context) error { _, err := c.SendExpiryReminders(ctx, 14); return err },
		},
		{
			name:      "record-hygiene-snapshot",
			eventType: "admin_job.record_hygiene_snapshot_run",
			setup: func(store *MockStorage) {
				store.On("CountStalePATs", mock.Anything, mock.Anything).Return(0, nil)
				store.On("CountExpiredPATs", mock.Anything).Return(0, nil)
				store.On("CountStaleMachineCredentials", mock.Anything, mock.Anything).Return(0, nil)
				store.On("ListActivePersonalAccessTokens", mock.Anything).Return([]*models.PersonalAccessToken{}, nil)
				store.On("ListAllMachineIdentities", mock.Anything).Return([]*models.MachineIdentity{}, nil)
				store.On("SaveHygieneTrendSnapshot", mock.Anything, mock.AnythingOfType("*models.HygieneTrendSnapshot")).Return(nil)
			},
			run: func(c *KeyorixCore, ctx context.Context) error { _, err := c.RecordHygieneTrendPoint(ctx); return err },
		},
		{
			name:      "role-expiry-check",
			eventType: "admin_job.role_expiry_check_run",
			setup: func(store *MockStorage) {
				store.On("ListExpiringUserRoles", mock.Anything, mock.Anything).Return([]models.UserRole{}, nil)
			},
			run: func(c *KeyorixCore, ctx context.Context) error { _, err := c.CheckRoleExpiry(ctx); return err },
		},
		{
			name:      "check-read-quotas",
			eventType: "admin_job.check_read_quotas_run",
			setup: func(store *MockStorage) {
				store.On("ListSecretsWithQuota", mock.Anything).Return([]models.SecretNode{}, nil)
			},
			run: func(c *KeyorixCore, ctx context.Context) error { _, err := c.CheckReadQuotas(ctx); return err },
		},
		{
			name:      "token-expiry-check",
			eventType: "admin_job.token_expiry_check_run",
			setup: func(store *MockStorage) {
				store.On("ListExpiringPATs", mock.Anything, mock.Anything).Return([]models.PersonalAccessToken{}, nil)
				store.On("ListExpiringMachineCredentials", mock.Anything, mock.Anything).Return([]models.MachineIdentityCredential{}, nil)
			},
			run: func(c *KeyorixCore, ctx context.Context) error { _, err := c.CheckTokenExpiry(ctx); return err },
		},
		{
			name:      "suspend-inactive-users",
			eventType: "admin_job.suspend_inactive_users_run",
			setup: func(store *MockStorage) {
				store.On("ListInactiveUsers", mock.Anything, mock.Anything).Return([]*models.User{}, nil)
			},
			run: func(c *KeyorixCore, ctx context.Context) error {
				_, err := c.SuspendInactiveUsers(ctx, InactivitySuspendConfig{InactiveDays: 90})
				return err
			},
		},
		{
			name:      "run-alert-escalation",
			eventType: "admin_job.run_alert_escalation_run",
			setup: func(store *MockStorage) {
				store.On("ListAlertEscalationPolicies", mock.Anything).Return([]models.AlertEscalationPolicy{}, nil)
			},
			run: func(c *KeyorixCore, ctx context.Context) error { _, err := c.RunAlertEscalation(ctx); return err },
		},
	}
}

// TestAdminJobs_AttributeRealActor_EmptyPath is the coordinator-requested
// table: every /admin/jobs core function, tagged (WithAuditActor) vs
// untagged, on the empty-result path -- the shape common to all of them.
func TestAdminJobs_AttributeRealActor_EmptyPath(t *testing.T) {
	for _, tc := range adminJobActorCases() {
		t.Run(tc.name+"/tagged", func(t *testing.T) {
			const actorID = uint(4242)
			captured := captureLastAdminJobAuditEvent(t, tc.setup, func(c *KeyorixCore) {
				require.NoError(t, tc.run(c, WithAuditActor(context.Background(), actorID)))
			})
			require.NotNil(t, captured, "%s must leave an audit trail even on the empty path", tc.name)
			assert.Equal(t, tc.eventType, captured.EventType)
			require.NotNil(t, captured.UserID, "%s: a tagged (admin-triggered) run must attribute the real actor, not nil", tc.name)
			assert.Equal(t, actorID, *captured.UserID, "%s", tc.name)
		})
		t.Run(tc.name+"/untagged", func(t *testing.T) {
			captured := captureLastAdminJobAuditEvent(t, tc.setup, func(c *KeyorixCore) {
				require.NoError(t, tc.run(c, context.Background()))
			})
			require.NotNil(t, captured, "%s must leave an audit trail even on the empty path", tc.name)
			assert.Equal(t, tc.eventType, captured.EventType)
			assert.Nil(t, captured.UserID, "%s: an untagged (scheduler) run must not fabricate an actor", tc.name)
		})
	}
}

// TestSendRotationReminders_AttributesRealActor_NonEmptyPath is the specific
// regression this item's review caught: rotation_reminders.go's early-return
// (0 policies) branch was fixed first, but the unconditional summary write at
// the END of the function -- the one reached on the MAIN, non-empty path --
// still hardcoded nil. Uses the real-SQLite fixture (newRotationReminderCore)
// so at least one reminder is actually sent, exercising that exact line.
func TestSendRotationReminders_AttributesRealActor_NonEmptyPath(t *testing.T) {
	t.Run("tagged", func(t *testing.T) {
		c, db, _ := newRotationReminderCore(t)
		const actorID = uint(4242)
		sent, err := c.SendRotationReminders(WithAuditActor(context.Background(), actorID))
		require.NoError(t, err)
		require.Equal(t, 1, sent, "fixture must actually exercise the non-empty path")

		var events []models.AuditEvent
		require.NoError(t, db.Where("event_type = ?", "admin_job.rotation_reminders_run").Find(&events).Error)
		require.Len(t, events, 1)
		require.NotNil(t, events[0].UserID, "a tagged (admin-triggered) run must attribute the real actor, not nil")
		assert.Equal(t, actorID, *events[0].UserID)
	})
	t.Run("untagged", func(t *testing.T) {
		c, db, _ := newRotationReminderCore(t)
		sent, err := c.SendRotationReminders(context.Background())
		require.NoError(t, err)
		require.Equal(t, 1, sent, "fixture must actually exercise the non-empty path")

		var events []models.AuditEvent
		require.NoError(t, db.Where("event_type = ?", "admin_job.rotation_reminders_run").Find(&events).Error)
		require.Len(t, events, 1)
		assert.Nil(t, events[0].UserID, "an untagged (scheduler) run must not fabricate an actor")
	})
}
