package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failOnceCreateAccessRequestApprovalStorage makes CreateAccessRequestApproval
// fail once, mirroring the failOnceStorage idiom from #2295.
func failOnceCreateAccessRequestApprovalStorage(inner storage.Storage, armed *bool) storage.Storage {
	return hooked(inner, &storeHooks{
		WrapTx: true,
		CreateAccessRequestApproval: func(next storage.Storage, ctx context.Context, a *models.AccessRequestApproval) error {
			if *armed {
				*armed = false
				return errors.New("injected fault: CreateAccessRequestApproval")
			}
			return next.CreateAccessRequestApproval(ctx, a)
		},
	})
}

// TestFinalizeAccessRequestApproval_ApprovalRecordFailureRevertsGrant is the
// red-proof for Session O's O3 access-request-approval fix: a failure
// recording the approval AFTER the role grant already landed must revert the
// grant too -- not the pre-fix behavior where the existing compensating
// revert only covered the LAST write's failure (UpdateAccessRequest's !ok
// race), leaving a CreateAccessRequestApproval failure with the role granted,
// zero approval record, and the request never flipping to approved.
//
// Extended (GH #2407, FuzzStorageFaultOperations REPLAY_HEX=4f002c3230303030):
// the ORIGINAL compensating-revert fix (#2306) got the STATE right (this test
// already proved that) but still left an extra "approval_race_reverted"
// AuditEvent behind -- the operation's only observable effect for a request
// that was told it failed, flagged by the fuzzer's oracle (a) as "reported an
// ERROR but logical state changed anyway." Wrapping the grant, the approval
// record, and the request update in one storage.WithTransaction (this PR)
// closes that too: a reported failure now leaves ZERO new audit rows, not
// just a consistent UserRole/AccessRequest/AccessRequestApproval state.
func TestFinalizeAccessRequestApproval_ApprovalRecordFailureRevertsGrant(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	proj, err := st.CreateProject(ctx, &models.Project{Name: "approval-proj", Description: "d"})
	require.NoError(t, err)
	requester, err := st.CreateUser(ctx, foldedTestUser(t, "requester", "requester@example.com"))
	require.NoError(t, err)

	req, err := st.CreateAccessRequest(ctx, &models.AccessRequest{
		ProjectID: proj.ID, UserID: requester.ID, SuggestedRole: "project_viewer", State: AccessRequestPending,
	})
	require.NoError(t, err)

	beforeLogs, beforeCount, berr := st.GetAuditLogs(ctx, &storage.AuditFilter{ProjectID: &proj.ID, PageSize: 1000})
	require.NoError(t, berr)
	_ = beforeLogs

	armed := true
	c.storage = failOnceCreateAccessRequestApprovalStorage(st, &armed)

	// actor 1 is the bootstrapped global admin (satisfies the grant-ceiling check).
	_, err = c.ApproveAccessRequestWithExpiry(ctx, proj.ID, req.ID, 1, 0, "project_viewer", time.Hour)
	require.Error(t, err)
	require.False(t, armed, "the injected fault must actually have fired")

	_, afterCount, aerr2 := st.GetAuditLogs(ctx, &storage.AuditFilter{ProjectID: &proj.ID, PageSize: 1000})
	require.NoError(t, aerr2)
	assert.Equal(t, beforeCount, afterCount,
		"a reported failure must leave ZERO new audit rows -- the atomic transaction rolls everything back, "+
			"including the former compensating-revert's own 'approval_race_reverted' audit write, instead of "+
			"leaving an extra row behind for an op that reported failure")

	roles, rerr := st.GetUserRoleIDsAt(ctx, requester.ID, storage.Scope{ProjectID: proj.ID})
	require.NoError(t, rerr)
	assert.Empty(t, roles, "a failed approval-record write must revert the role grant that already landed")

	reloaded, gerr := st.GetAccessRequest(ctx, req.ID)
	require.NoError(t, gerr)
	assert.Equal(t, AccessRequestPending, reloaded.State, "the request must stay pending, not silently approved with no approval record")

	approvals, aerr := st.ListAccessRequestApprovals(ctx, req.ID)
	require.NoError(t, aerr)
	assert.Empty(t, approvals)

	// Retry (fault disarmed) must fully succeed.
	_, err = c.ApproveAccessRequestWithExpiry(ctx, proj.ID, req.ID, 1, 0, "project_viewer", time.Hour)
	require.NoError(t, err)
	roles, rerr = st.GetUserRoleIDsAt(ctx, requester.ID, storage.Scope{ProjectID: proj.ID})
	require.NoError(t, rerr)
	assert.NotEmpty(t, roles, "a clean retry must grant the role")
}
