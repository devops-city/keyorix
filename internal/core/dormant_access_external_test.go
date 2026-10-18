package core_test

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The access review annotates user grants with their last secret-access time (the
// most recent of several reads), and leaves it nil for a user with no recorded
// activity — the dormant-access signal.
func TestGenerateProjectAccessReview_AnnotatesLastUsed(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.AuditEvent{}))

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	h.CreateTestUser(t, "bob", 11)
	h.AssignUserRole(t, 10, 3, uptr(proj)) // alice editor — has activity
	h.AssignUserRole(t, 11, 4, uptr(proj)) // bob viewer — never used it

	pid := proj
	aid := uint(10)
	older := time.Now().Add(-72 * time.Hour)
	newer := time.Now().Add(-1 * time.Hour)
	require.NoError(t, h.DB.Create(&models.AuditEvent{EventType: "secret.read", UserID: &aid, ProjectID: &pid, EventTime: older}).Error)
	require.NoError(t, h.DB.Create(&models.AuditEvent{EventType: "secret.read", UserID: &aid, ProjectID: &pid, EventTime: newer}).Error)

	report, err := h.CoreService.GenerateProjectAccessReview(ctx, proj)
	require.NoError(t, err)
	require.False(t, report.Degraded, "audit_events is migrated with valid data — the lookup must not degrade")

	var alice, bob *core.AccessReviewEntry
	for _, e := range report.Entries {
		switch e.PrincipalName {
		case "alice":
			alice = e
		case "bob":
			bob = e
		}
	}
	require.NotNil(t, alice)
	require.NotNil(t, bob)
	require.NotNil(t, alice.LastUsedAt, "alice has recorded secret access")
	assert.WithinDuration(t, newer, *alice.LastUsedAt, time.Second, "the most recent access wins")
	assert.Nil(t, bob.LastUsedAt, "bob has no activity → dormant standing access")
}

// Activity in another project does not count toward this project's last-used.
func TestGenerateProjectAccessReview_LastUsedIsProjectScoped(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.AuditEvent{}))

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	h.AssignUserRole(t, 10, 3, uptr(proj))

	aid := uint(10)
	otherProj := uint(3)
	require.NoError(t, h.DB.Create(&models.AuditEvent{
		EventType: "secret.read", UserID: &aid, ProjectID: &otherProj, EventTime: time.Now(),
	}).Error)

	report, err := h.CoreService.GenerateProjectAccessReview(ctx, proj)
	require.NoError(t, err)
	require.Len(t, report.Entries, 1)
	assert.Nil(t, report.Entries[0].LastUsedAt, "activity in project 3 doesn't count for project 2")
}

// #453: on storage.type: remote, LastUserSecretActivity is unconditionally
// unimplemented (internal/storage/store/remote_access_activity.go), and the
// access-review report's caller previously silently swallowed that error —
// every entry's LastUsedAt read as nil with no signal, indistinguishable from
// "genuinely never used". Simulating the same failure mode locally (the
// audit_events table is unmigrated, so the underlying query errors) must now
// flip Degraded rather than silently produce a report that looks complete.
func TestGenerateProjectAccessReview_DegradedOnLastUsedQueryError(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	// audit_events deliberately absent → LastUserSecretActivity's raw
	// "audit_events" table query fails, mirroring
	// TestGetCompliancePosture_DegradedOnDormantRoleGrantsActivityQueryError
	// (compliance_posture_test.go). The helper migrates it since AUDIT-TX-2
	// (grants commit with their audit row), so drop it here.
	require.NoError(t, h.DB.Migrator().DropTable(&models.AuditEvent{}))

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	h.AssignUserRole(t, 10, 3, uptr(proj)) // editor → write

	report, err := h.CoreService.GenerateProjectAccessReview(ctx, proj)
	require.NoError(t, err)

	require.Len(t, report.Entries, 1)
	assert.Nil(t, report.Entries[0].LastUsedAt, "the field itself still reads as its zero value — no visible dormant/active signal")
	assert.True(t, report.Degraded, "an unqueryable last-used lookup must flip Degraded rather than silently read as no entry ever used")
	require.NotEmpty(t, report.DegradedReasons)
	assert.Contains(t, report.DegradedReasons[0], "last_used:project=2")
}
