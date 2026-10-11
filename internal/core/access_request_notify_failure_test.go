package core

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #3075: every access-request transition notifies someone AFTER its own state
// change has committed. A CreateNotification that panics (the fuzz finding:
// PUT /projects/{id}/access-requests/{requestId}, CreateNotification#1/panic)
// or fails must not turn that committed transition into a reported error. The
// rule (#2880 shape): recover, log at SECURITY level with context, write a
// "notification.failed" audit event, return the success response.
//
// Family-wide on purpose: every core entry point that ends in an access-request
// notification is a row here (project request/approve/partial-approve/reject,
// secret request/approve/reject), under both fault kinds. Bulk approve/reject
// (server/http) go through ApproveAccessRequestWithExpiry/RejectAccessRequest,
// so these rows cover them too.

// accessRequestNotifyFixture is what each row's transition needs.
type accessRequestNotifyFixture struct {
	c         *KeyorixCore
	st        *store.LocalStorage
	projectID uint
	requester uint
	secretID  uint
	approver  uint // global admin from seedClassificationGateFixture
}

func newAccessRequestNotifyFixture(t *testing.T) *accessRequestNotifyFixture {
	t.Helper()
	c, st := newBootstrappedCore(t)
	secretID, requesterID, approverID, projectID := seedClassificationGateFixture(t, st, ClassificationRestricted)
	// A project-scoped approver so the "new request" fan-out has a recipient
	// beyond the install-wide admins.
	makeProjectApprover(t, st, approverID, projectID, "project_admin")
	return &accessRequestNotifyFixture{c: c, st: st, projectID: projectID, requester: requesterID, secretID: secretID, approver: approverID}
}

// callRecovering runs fn and turns an escaped panic into a returned error, so a
// pre-fix run reports the escape as a test failure instead of killing the binary.
func callRecovering(fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic escaped the committed transition: %v", r)
		}
	}()
	return fn()
}

func TestAccessRequestNotificationFailure_CommittedTransitionStillSucceeds(t *testing.T) {
	t.Parallel()
	type row struct {
		name string
		// setup runs unfaulted and returns the request the transition acts on (nil for a create).
		setup func(t *testing.T, f *accessRequestNotifyFixture) *models.AccessRequest
		// transition is the call under test; it runs with CreateNotification#1 faulted.
		transition func(ctx context.Context, f *accessRequestNotifyFixture, req *models.AccessRequest) (*models.AccessRequest, error)
		// committed checks the transition's own durable effect, read straight from storage.
		committed func(t *testing.T, f *accessRequestNotifyFixture, got *models.AccessRequest)
		// recipient is the user whose notification the fault swallowed.
		recipient func(f *accessRequestNotifyFixture) uint
	}
	pendingProjectRequest := func(t *testing.T, f *accessRequestNotifyFixture) *models.AccessRequest {
		req, err := f.c.RequestProjectAccess(context.Background(), f.projectID, f.requester, "project_developer", "need it")
		require.NoError(t, err)
		return req
	}
	pendingSecretRequest := func(t *testing.T, f *accessRequestNotifyFixture) *models.AccessRequest {
		req, err := f.c.RequestSecretAccess(context.Background(), f.secretID, f.requester, "need it")
		require.NoError(t, err)
		return req
	}
	stateIs := func(want string) func(t *testing.T, f *accessRequestNotifyFixture, got *models.AccessRequest) {
		return func(t *testing.T, f *accessRequestNotifyFixture, got *models.AccessRequest) {
			require.NotNil(t, got)
			stored, err := f.st.GetAccessRequest(context.Background(), got.ID)
			require.NoError(t, err)
			assert.Equal(t, want, stored.State)
		}
	}
	requester := func(f *accessRequestNotifyFixture) uint { return f.requester }

	rows := []row{
		{
			name:  "project request created",
			setup: func(*testing.T, *accessRequestNotifyFixture) *models.AccessRequest { return nil },
			transition: func(ctx context.Context, f *accessRequestNotifyFixture, _ *models.AccessRequest) (*models.AccessRequest, error) {
				return f.c.RequestProjectAccess(ctx, f.projectID, f.requester, "project_developer", "need it")
			},
			committed: stateIs(AccessRequestPending),
			recipient: nil, // fan-out: the first admin in id order took the fault
		},
		{
			name:  "project request approved (PUT /projects/{id}/access-requests/{requestId}, the fuzz tuple)",
			setup: pendingProjectRequest,
			transition: func(ctx context.Context, f *accessRequestNotifyFixture, req *models.AccessRequest) (*models.AccessRequest, error) {
				return f.c.ApproveAccessRequestWithExpiry(ctx, f.projectID, req.ID, f.approver, 0, "", time.Hour)
			},
			committed: func(t *testing.T, f *accessRequestNotifyFixture, got *models.AccessRequest) {
				stateIs(AccessRequestApproved)(t, f, got)
				roles, err := f.st.GetUserRoleIDsAt(context.Background(), f.requester, storage.Scope{ProjectID: f.projectID})
				require.NoError(t, err)
				assert.GreaterOrEqual(t, len(roles), 2, "the granted role must be committed alongside the requester's seeded viewer role")
			},
			recipient: requester,
		},
		{
			name: "project request partially approved (2-of-N)",
			setup: func(t *testing.T, f *accessRequestNotifyFixture) *models.AccessRequest {
				f.c.SetDualControlPolicy(2)
				return pendingProjectRequest(t, f)
			},
			transition: func(ctx context.Context, f *accessRequestNotifyFixture, req *models.AccessRequest) (*models.AccessRequest, error) {
				return f.c.ApproveAccessRequestWithExpiry(ctx, f.projectID, req.ID, f.approver, 0, "", 0)
			},
			committed: func(t *testing.T, f *accessRequestNotifyFixture, got *models.AccessRequest) {
				stateIs(AccessRequestPending)(t, f, got)
				approvals, err := f.st.ListAccessRequestApprovals(context.Background(), got.ID)
				require.NoError(t, err)
				assert.Len(t, approvals, 1, "the partial approval must be committed")
			},
			recipient: nil,
		},
		{
			name:  "project request rejected",
			setup: pendingProjectRequest,
			transition: func(ctx context.Context, f *accessRequestNotifyFixture, req *models.AccessRequest) (*models.AccessRequest, error) {
				return f.c.RejectAccessRequest(ctx, f.projectID, req.ID, f.approver, 0, "no")
			},
			committed: stateIs(AccessRequestRejected),
			recipient: requester,
		},
		{
			name:  "secret request created (POST /secret-access-requests)",
			setup: func(*testing.T, *accessRequestNotifyFixture) *models.AccessRequest { return nil },
			transition: func(ctx context.Context, f *accessRequestNotifyFixture, _ *models.AccessRequest) (*models.AccessRequest, error) {
				return f.c.RequestSecretAccess(ctx, f.secretID, f.requester, "need it")
			},
			committed: stateIs(AccessRequestPending),
			recipient: nil,
		},
		{
			name:  "secret request approved (PUT /secret-access-requests/{id})",
			setup: pendingSecretRequest,
			transition: func(ctx context.Context, f *accessRequestNotifyFixture, req *models.AccessRequest) (*models.AccessRequest, error) {
				return f.c.ApproveSecretAccessRequest(ctx, req.ID, f.approver)
			},
			committed: stateIs(AccessRequestApproved),
			recipient: requester,
		},
		{
			name:  "secret request rejected (PUT /secret-access-requests/{id})",
			setup: pendingSecretRequest,
			transition: func(ctx context.Context, f *accessRequestNotifyFixture, req *models.AccessRequest) (*models.AccessRequest, error) {
				return f.c.RejectSecretAccessRequest(ctx, req.ID, f.approver, 0, "no")
			},
			committed: stateIs(AccessRequestRejected),
			recipient: requester,
		},
	}

	for _, r := range rows {
		for _, kind := range []faultstorage.FaultKind{faultstorage.KindPanic, faultstorage.KindError} {
			t.Run(fmt.Sprintf("%s/CreateNotification#1/%s", r.name, kind), func(t *testing.T) {
				t.Parallel()
				f := newAccessRequestNotifyFixture(t)
				ctx := context.Background()
				req := r.setup(t, f)

				_, beforeFailed, err := f.st.GetAuditLogs(ctx, &storage.AuditFilter{ProjectID: &f.projectID, Action: strPtr(auditNotificationFailed), PageSize: 100})
				require.NoError(t, err)

				faulty := faultstorage.NewFaultyStorage(f.st, nil)
				f.c.storage = faulty
				faulty.Arm(&faultstorage.FaultSpec{Method: "CreateNotification", NthCall: 1, Kind: kind, Err: errors.New("injected CreateNotification fault")})

				var got *models.AccessRequest
				err = callRecovering(func() error {
					var terr error
					got, terr = r.transition(ctx, f, req)
					return terr
				})
				f.c.storage = f.st
				require.True(t, faulty.Fired(), "the CreateNotification fault must actually have fired, or this row proves nothing")

				require.NoError(t, err, "a notification failure after the transition committed must not be reported as the transition failing")
				r.committed(t, f, got)

				logs, afterFailed, err := f.st.GetAuditLogs(ctx, &storage.AuditFilter{ProjectID: &f.projectID, Action: strPtr(auditNotificationFailed), PageSize: 100})
				require.NoError(t, err)
				require.Equal(t, beforeFailed+1, afterFailed, "the swallowed notification failure must be recorded as exactly one %q audit event", auditNotificationFailed)
				assert.Contains(t, logs[0].Description, fmt.Sprintf("access request %d", got.ID), "the audit event must name the access request")

				if r.recipient != nil {
					notes, err := f.st.ListNotifications(ctx, r.recipient(f), false, 10)
					require.NoError(t, err)
					assert.Empty(t, notes, "the faulted notification must not have been persisted")
				}
			})
		}
	}
}
