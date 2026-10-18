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

func migrateCampaignTables(t *testing.T, h *testhelper.RBACTestHelper) {
	require.NoError(t, h.DB.AutoMigrate(&models.AccessReviewCampaign{}, &models.AccessReviewItem{}, &models.AuditEvent{}))
}

// Opening a campaign snapshots the current access review into pending items.
func TestOpenAccessReviewCampaign_SnapshotsEntries(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateCampaignTables(t, h)

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	h.AssignUserRole(t, 10, 3, uptr(proj)) // editor → one role entry

	res, err := h.CoreService.OpenAccessReviewCampaign(ctx, 1, 0, proj, "Q4 2026")
	require.NoError(t, err)
	assert.Equal(t, core.CampaignStateOpen, res.Campaign.State)
	assert.Equal(t, "Q4 2026", res.Campaign.Name)
	assert.Equal(t, 1, res.Progress.Total)
	assert.Equal(t, 1, res.Progress.Pending)

	detail, err := h.CoreService.GetAccessReviewCampaign(ctx, proj, res.Campaign.ID)
	require.NoError(t, err)
	require.Len(t, detail.Items, 1)
	assert.Equal(t, core.ReviewItemPending, detail.Items[0].Decision)
	assert.Equal(t, "alice", detail.Items[0].PrincipalName)
}

// #1573: a machine identity holding project-scoped roles.assign can open and
// close a campaign. actorID (0, ADR-030) alone loses which machine did it;
// the *MachineIdentityID companion fields must carry it through.
func TestAccessReviewCampaign_RecordsActingMachineIdentity(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateCampaignTables(t, h)

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	h.AssignUserRole(t, 10, 3, uptr(proj))

	res, err := h.CoreService.OpenAccessReviewCampaign(ctx, 0, 42, proj, "Machine-opened")
	require.NoError(t, err)
	assert.Zero(t, res.Campaign.CreatedBy)
	assert.Equal(t, uint(42), res.Campaign.CreatedByMachineIdentityID)

	closed, err := h.CoreService.CloseAccessReviewCampaign(ctx, 0, 77, proj, res.Campaign.ID, true)
	require.NoError(t, err)
	assert.Zero(t, closed.Campaign.ClosedBy)
	assert.Equal(t, uint(77), closed.Campaign.ClosedByMachineIdentityID)
}

// Attesting an item marks it kept; revoking removes the underlying grant.
func TestDecideAccessReviewItem_AttestAndRevoke(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateCampaignTables(t, h)

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	h.CreateTestUser(t, "bob", 11)
	h.AssignUserRole(t, 10, 3, uptr(proj)) // alice editor
	h.AssignUserRole(t, 11, 4, uptr(proj)) // bob viewer

	res, err := h.CoreService.OpenAccessReviewCampaign(ctx, 1, 0, proj, "review")
	require.NoError(t, err)
	detail, err := h.CoreService.GetAccessReviewCampaign(ctx, proj, res.Campaign.ID)
	require.NoError(t, err)
	require.Len(t, detail.Items, 2)

	// Identify alice's and bob's items.
	var aliceItem, bobItem uint
	for _, it := range detail.Items {
		if it.PrincipalID == 10 {
			aliceItem = it.ID
		} else if it.PrincipalID == 11 {
			bobItem = it.ID
		}
	}
	require.NotZero(t, aliceItem)
	require.NotZero(t, bobItem)

	// Attest alice (kept), revoke bob (removed).
	require.NoError(t, h.CoreService.DecideAccessReviewItem(ctx, 1, proj, res.Campaign.ID, aliceItem, "attest", ""))
	require.NoError(t, h.CoreService.DecideAccessReviewItem(ctx, 1, proj, res.Campaign.ID, bobItem, "revoke", "left team"))

	after, err := h.CoreService.GetAccessReviewCampaign(ctx, proj, res.Campaign.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, after.Progress.Attested)
	assert.Equal(t, 1, after.Progress.Revoked)
	assert.Equal(t, 0, after.Progress.Pending)

	// bob's editor/viewer grant is actually gone from the live review; alice's stays.
	report, err := h.CoreService.GenerateProjectAccessReview(ctx, proj)
	require.NoError(t, err)
	var names []string
	for _, e := range report.Entries {
		names = append(names, e.PrincipalName)
	}
	assert.Contains(t, names, "alice")
	assert.NotContains(t, names, "bob")
}

// A reviewer must not certify their OWN access (ISO 27001 A.5.18 independence).
func TestDecideAccessReviewItem_RejectsSelfCertification(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateCampaignTables(t, h)

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	h.AssignUserRole(t, 10, 3, uptr(proj))

	res, err := h.CoreService.OpenAccessReviewCampaign(ctx, 1, 0, proj, "review")
	require.NoError(t, err)
	detail, err := h.CoreService.GetAccessReviewCampaign(ctx, proj, res.Campaign.ID)
	require.NoError(t, err)
	require.Len(t, detail.Items, 1)
	item := detail.Items[0].ID

	// Alice (user 10) deciding her own item is rejected...
	err = h.CoreService.DecideAccessReviewItem(ctx, 10, proj, res.Campaign.ID, item, "attest", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "your own access")

	// ...but an independent reviewer can.
	require.NoError(t, h.CoreService.DecideAccessReviewItem(ctx, 1, proj, res.Campaign.ID, item, "attest", ""))
}

// A recertification decision requires an attributable HUMAN reviewer. A machine identity
// authenticates with UserID==0, so actorID==0 is refused — otherwise an automation token
// could rubber-stamp a campaign with the evidence recording reviewer "0"/nil, and the
// self-review independence check (keyed on actorID) would be inert for it.
func TestDecideAccessReviewItem_RejectsNonHumanReviewer(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateCampaignTables(t, h)

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	h.AssignUserRole(t, 10, 3, uptr(proj))

	res, err := h.CoreService.OpenAccessReviewCampaign(ctx, 1, 0, proj, "review")
	require.NoError(t, err)
	detail, err := h.CoreService.GetAccessReviewCampaign(ctx, proj, res.Campaign.ID)
	require.NoError(t, err)
	require.Len(t, detail.Items, 1)
	item := detail.Items[0].ID

	// actorID 0 (machine identity / unattributable) cannot decide.
	err = h.CoreService.DecideAccessReviewItem(ctx, 0, proj, res.Campaign.ID, item, "attest", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "attributable human reviewer")

	// The item is untouched — still pending, not silently attested.
	detail, err = h.CoreService.GetAccessReviewCampaign(ctx, proj, res.Campaign.ID)
	require.NoError(t, err)
	assert.Equal(t, core.ReviewItemPending, detail.Items[0].Decision)
}

// Independence extends to GROUP-conferred access: a reviewer who belongs to a group
// must not certify that group's review item (self-certification via a group grant).
func TestDecideAccessReviewItem_RejectsGroupSelfCertification(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateCampaignTables(t, h)

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "carol", 20)
	g := h.CreateTestGroup(t, "team", "", 5)
	h.AssignGroupRole(t, g.ID, 3, uptr(proj)) // the group holds a role in the project
	h.AssignUserToGroup(t, 20, g.ID)          // carol is a member

	res, err := h.CoreService.OpenAccessReviewCampaign(ctx, 1, 0, proj, "review")
	require.NoError(t, err)
	detail, err := h.CoreService.GetAccessReviewCampaign(ctx, proj, res.Campaign.ID)
	require.NoError(t, err)

	var groupItem uint
	for _, it := range detail.Items {
		if it.PrincipalType == "group" && it.PrincipalID == g.ID {
			groupItem = it.ID
		}
	}
	require.NotZero(t, groupItem, "expected a group-source review item")

	// Carol (a member of the group) cannot self-certify the group's access...
	err = h.CoreService.DecideAccessReviewItem(ctx, 20, proj, res.Campaign.ID, groupItem, "attest", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "group you belong to")

	// ...but an independent reviewer (not a member) can.
	require.NoError(t, h.CoreService.DecideAccessReviewItem(ctx, 1, proj, res.Campaign.ID, groupItem, "attest", ""))
}

// An item is decided once: a decided item can't be flipped, so the recorded decision
// can't drift from the real grant state (false certification evidence).
func TestDecideAccessReviewItem_RejectsDoubleDecision(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateCampaignTables(t, h)

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	h.AssignUserRole(t, 10, 3, uptr(proj))

	res, err := h.CoreService.OpenAccessReviewCampaign(ctx, 1, 0, proj, "review")
	require.NoError(t, err)
	detail, err := h.CoreService.GetAccessReviewCampaign(ctx, proj, res.Campaign.ID)
	require.NoError(t, err)
	item := detail.Items[0].ID

	require.NoError(t, h.CoreService.DecideAccessReviewItem(ctx, 1, proj, res.Campaign.ID, item, "attest", ""))
	// A second decision (flip to revoke) is rejected, and the original stands.
	err = h.CoreService.DecideAccessReviewItem(ctx, 1, proj, res.Campaign.ID, item, "revoke", "flip")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already been decided")

	after, err := h.CoreService.GetAccessReviewCampaign(ctx, proj, res.Campaign.ID)
	require.NoError(t, err)
	assert.Equal(t, core.ReviewItemAttested, after.Items[0].Decision, "the original decision is preserved")
}

// Closing refuses while items are pending unless forced; a closed campaign rejects
// further decisions.
func TestCloseAccessReviewCampaign_PendingGuardAndForce(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateCampaignTables(t, h)

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	h.AssignUserRole(t, 10, 3, uptr(proj))

	res, err := h.CoreService.OpenAccessReviewCampaign(ctx, 1, 0, proj, "review")
	require.NoError(t, err)

	// One pending item → close without force fails.
	_, err = h.CoreService.CloseAccessReviewCampaign(ctx, 1, 0, proj, res.Campaign.ID, false)
	require.Error(t, err)

	// Force-close succeeds and freezes the campaign.
	closed, err := h.CoreService.CloseAccessReviewCampaign(ctx, 1, 0, proj, res.Campaign.ID, true)
	require.NoError(t, err)
	assert.Equal(t, core.CampaignStateClosed, closed.Campaign.State)
	// #237: a force-close performed while items are still pending must be marked
	// ForcedIncomplete so the recertification cadence doesn't treat it as a
	// genuine, fully-decided review.
	assert.True(t, closed.Campaign.ForcedIncomplete, "a force-close with pending items must be flagged incomplete")

	// A closed campaign rejects further decisions.
	detail, err := h.CoreService.GetAccessReviewCampaign(ctx, proj, res.Campaign.ID)
	require.NoError(t, err)
	err = h.CoreService.DecideAccessReviewItem(ctx, 1, proj, res.Campaign.ID, detail.Items[0].ID, "attest", "")
	require.Error(t, err)

	// Re-closing is rejected.
	_, err = h.CoreService.CloseAccessReviewCampaign(ctx, 1, 0, proj, res.Campaign.ID, true)
	require.Error(t, err)
}

// #237: a close with every item already decided (no pending items left) is a
// genuine, fully-completed recertification — even when the caller happens to pass
// force=true, it must NOT be flagged ForcedIncomplete, so it isn't penalized by the
// recertification cadence the way a genuinely abandoned/rushed close is.
func TestCloseAccessReviewCampaign_FullyDecidedIsNotForcedIncomplete(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateCampaignTables(t, h)

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	h.AssignUserRole(t, 10, 3, uptr(proj))

	res, err := h.CoreService.OpenAccessReviewCampaign(ctx, 1, 0, proj, "review")
	require.NoError(t, err)
	detail, err := h.CoreService.GetAccessReviewCampaign(ctx, proj, res.Campaign.ID)
	require.NoError(t, err)
	require.Len(t, detail.Items, 1)
	require.NoError(t, h.CoreService.DecideAccessReviewItem(ctx, 1, proj, res.Campaign.ID, detail.Items[0].ID, "attest", ""))

	// Nothing pending, so this close (whether force is true or false) is a genuine
	// completed review.
	closed, err := h.CoreService.CloseAccessReviewCampaign(ctx, 1, 0, proj, res.Campaign.ID, true)
	require.NoError(t, err)
	assert.Equal(t, core.CampaignStateClosed, closed.Campaign.State)
	assert.False(t, closed.Campaign.ForcedIncomplete, "a fully-decided close must not be flagged incomplete")
}

// A campaign id from another project is not reachable through this project's scope.
func TestAccessReviewCampaign_CrossProjectGuard(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateCampaignTables(t, h)

	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	h.AssignUserRole(t, 10, 3, uptr(uint(2)))

	res, err := h.CoreService.OpenAccessReviewCampaign(ctx, 1, 0, 2, "p2")
	require.NoError(t, err)

	// Reaching campaign (project 2) through project 3 must fail.
	_, err = h.CoreService.GetAccessReviewCampaign(ctx, 3, res.Campaign.ID)
	require.Error(t, err)
	err = h.CoreService.DecideAccessReviewItem(ctx, 1, 3, res.Campaign.ID, 1, "attest", "")
	require.Error(t, err)
}

func TestOpenAccessReviewCampaign_RequiresProject(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateCampaignTables(t, h)
	_, err := h.CoreService.OpenAccessReviewCampaign(context.Background(), 1, 0, 0, "x")
	require.Error(t, err)
}

// #483: OpenAccessReviewCampaign previously took report.Entries and discarded
// report.Degraded/DegradedReasons entirely — the #453 degrade signal evaporated the
// instant a campaign was opened, even though models.AccessReviewCampaign had no field
// to carry it forward anyway. A degraded snapshot must now leave a DURABLE record on
// the campaign row itself, verified by reading the row back from storage (not just
// trusting the in-memory return value).
func TestOpenAccessReviewCampaign_PersistsDegradedFromReport(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	// Only the campaign tables are migrated — models.AuditEvent is deliberately NOT
	// migrated, so GenerateProjectAccessReview's LastUserSecretActivity lookup fails
	// and the report it returns comes back Degraded=true (same trick as
	// TestGenerateProjectAccessReview_DegradedOnLastUsedQueryError). The helper
	// migrates it since AUDIT-TX-2 (grants commit with their audit row), so drop it.
	require.NoError(t, h.DB.AutoMigrate(&models.AccessReviewCampaign{}, &models.AccessReviewItem{}))
	require.NoError(t, h.DB.Migrator().DropTable(&models.AuditEvent{}))

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	h.AssignUserRole(t, 10, 3, uptr(proj)) // editor → write

	report, err := h.CoreService.GenerateProjectAccessReview(ctx, proj)
	require.NoError(t, err)
	require.True(t, report.Degraded, "sanity: the report itself must be degraded for this test to be meaningful")

	res, err := h.CoreService.OpenAccessReviewCampaign(ctx, 1, 0, proj, "degraded review")
	require.NoError(t, err)
	assert.True(t, res.Campaign.Degraded, "the campaign returned by Open must carry the degraded signal")
	assert.NotEmpty(t, res.Campaign.DegradedReasons)

	// Read the row back from storage — not just the in-memory return value — to
	// confirm it's a durable record, not an ephemeral one.
	stored, err := h.Storage.GetAccessReviewCampaign(ctx, res.Campaign.ID)
	require.NoError(t, err)
	assert.True(t, stored.Degraded, "Degraded must be persisted on the campaign row")
	assert.Equal(t, res.Campaign.DegradedReasons, stored.DegradedReasons)
}

// RECERT-BOUND-1: an item's last_used_at is the principal's latest use within the
// recertification period only. Activity older than the period reads as "no use in
// the window" (not as an old timestamp), and the campaign records the window it was
// opened with.
func TestOpenAccessReviewCampaign_LastUsedLooksBackOverTheReviewPeriod(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		cadence  int
		wantDays int
		wantSeen bool // is the 100-day-old read inside the window?
	}{
		{"default 90 days", 0, 90, false},
		{"configured 180 days", 180, 180, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := testhelper.NewRBACTestHelper(t)
			defer h.Cleanup()
			migrateCampaignTables(t, h)
			h.CoreService.SetRecertificationCadence(tc.cadence)

			const proj = uint(2)
			ctx := context.Background()
			h.CreateTestUser(t, "alice", 10)
			h.AssignUserRole(t, 10, 3, uptr(proj))
			uid, pid, ok := uint(10), proj, true
			require.NoError(t, h.DB.Create(&models.AuditEvent{
				EventType: "secret.read", UserID: &uid, ProjectID: &pid, Success: &ok,
				EventTime: time.Now().AddDate(0, 0, -100),
			}).Error)

			res, err := h.CoreService.OpenAccessReviewCampaign(ctx, 1, 0, proj, "window")
			require.NoError(t, err)
			assert.Equal(t, tc.wantDays, res.Campaign.ActivityWindowDays)

			detail, err := h.CoreService.GetAccessReviewCampaign(ctx, proj, res.Campaign.ID)
			require.NoError(t, err)
			assert.Equal(t, tc.wantDays, detail.Campaign.ActivityWindowDays, "the window is persisted with the campaign")
			require.Len(t, detail.Items, 1)
			if tc.wantSeen {
				require.NotNil(t, detail.Items[0].LastUsedAt)
			} else {
				assert.Nil(t, detail.Items[0].LastUsedAt, "a read older than the period is 'no use within the last %d days'", tc.wantDays)
			}
		})
	}
}
