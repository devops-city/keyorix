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

// failOnceCreateProjectMembershipStorage makes CreateProjectMembership fail
// once, mirroring the failOnceStorage idiom from #2295. This is the first
// storage write inviteMemberWithMode makes, so it forces
// applyInvitationGrants to fail for a project-scoped invite (the shape
// completeInvitationAccept uses when inv.SystemRole == "" && inv.AssignmentsJSON == "").
func failOnceCreateProjectMembershipStorage(inner storage.Storage, armed *bool) storage.Storage {
	return hooked(inner, &storeHooks{
		CreateProjectMembership: func(next storage.Storage, ctx context.Context, m *models.ProjectMembership) (*models.ProjectMembership, error) {
			if *armed {
				*armed = false
				return nil, errors.New("injected fault: CreateProjectMembership")
			}
			return next.CreateProjectMembership(ctx, m)
		},
	})
}

// inviteAcceptFixture builds a bootstrapped core with a pending project
// invitation and an active setup token for it, ready for completeInvitationAccept
// (reached via CompleteSetup) to consume.
func inviteAcceptFixture(t *testing.T, c *KeyorixCore, st interface {
	CreateProjectInvitation(ctx context.Context, inv *models.ProjectInvitation) (*models.ProjectInvitation, error)
	CreateSetupToken(ctx context.Context, tok *models.SetupToken) (*models.SetupToken, error)
}, projectID, adminID uint, email, rawToken string) *models.ProjectInvitation {
	t.Helper()
	ctx := context.Background()
	now := c.now()
	future := now.Add(24 * time.Hour)
	inv, err := st.CreateProjectInvitation(ctx, &models.ProjectInvitation{
		ProjectID: projectID, Email: email, Role: "project_developer", State: InvitationPending,
		InvitedBy: adminID, ValidationModeAtInvite: ValidationModeOpen, ExpiresAt: &future, CreatedAt: now,
	})
	require.NoError(t, err)
	_, err = st.CreateSetupToken(ctx, &models.SetupToken{
		TokenHash: sha256Hex(rawToken), Purpose: SetupPurposeInvitationAccept, SubjectEmail: email,
		InvitationID: &inv.ID, State: SetupTokenActive, ExpiresAt: future, CreatedBy: adminID,
	})
	require.NoError(t, err)
	return inv
}

// TestCompleteInvitationAccept_GrantFailureRecoverableViaResend is Session
// O's fix for the coordinator's hand-found class-A candidate (2026-09-29):
// completeInvitationAccept creates the account, consumes the (single-use)
// token, THEN applies grants -- proving via fault injection that this shape
// is class A, not S, because a retry of the SAME link is blocked by
// consumeInspectedToken having already burned it (single-use, by design; not
// itself a bug), and — before this fix — a completely FRESH attempt
// (simulating a resent invite link, a new token for the same still-pending
// invitation) was ALSO blocked, by the "account already exists" guard, with
// no documented recovery path for the invitee to finish on their own. The fix
// soft-deletes the orphaned, ungranted account on a grants failure so a
// resend starts clean.
func TestCompleteInvitationAccept_GrantFailureRecoverableViaResend(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	const email = "invitee@example.com"
	const rawToken = setupPrefix + "invite-accept-atomicity-1"

	proj, err := st.CreateProject(ctx, &models.Project{Name: "invite-proj", Description: "d"})
	require.NoError(t, err)
	inv := inviteAcceptFixture(t, c, st, proj.ID, 1, email, rawToken)

	armed := true
	c.storage = failOnceCreateProjectMembershipStorage(st, &armed)

	_, err = c.CompleteSetup(ctx, rawToken, strongPw, "ua", "1.2.3.4")
	require.Error(t, err, "grants failure must surface as an error, not a silent partial success")
	require.False(t, armed, "the injected fault must actually have fired")

	// (c) Token and invitation state after the failure: the token is consumed
	// (single-use, by design -- created BEFORE the grant step so a legitimate
	// race loser can't replay it), the invitation is still pending (never
	// flipped to accepted, matching the code's own stated intent).
	tokRow, terr := st.GetSetupTokenByHash(ctx, sha256Hex(rawToken))
	require.NoError(t, terr)
	assert.NotEqual(t, SetupTokenActive, tokRow.State, "the token must be consumed, not left replayable")
	reloadedInv, ierr := st.GetProjectInvitation(ctx, inv.ID)
	require.NoError(t, ierr)
	assert.Equal(t, InvitationPending, reloadedInv.State, "the invitation must stay pending, not falsely accepted")

	// (b) No grant was left half-applied. The orphaned account from the failed
	// attempt is gone (soft-deleted by the fix) -- GetUserByEmail (which
	// excludes soft-deleted rows) finds nothing.
	c.storage = st // remove the fault before further storage calls
	_, uerr := st.GetUserByEmail(ctx, email)
	require.Error(t, uerr, "the orphaned, ungranted account from the failed attempt must be cleaned up, not left behind")

	// (a) Recovery: the invitee CAN finish, just not via the same (spent) link.
	//  1. Retrying the SAME link still fails -- the token was already consumed
	//     above, correctly (single-use is by design, not the bug).
	_, retrySameErr := c.CompleteSetup(ctx, rawToken, strongPw, "ua", "1.2.3.4")
	require.Error(t, retrySameErr, "the SAME link must not be replayable")

	//  2. A FRESH attempt (simulating an admin resending the invite -- a new
	//     token for the SAME still-pending invitation) now succeeds cleanly:
	//     a new account is created and fully granted.
	const freshToken = setupPrefix + "invite-accept-atomicity-1-resend"
	_, err = st.CreateSetupToken(ctx, &models.SetupToken{
		TokenHash: sha256Hex(freshToken), Purpose: SetupPurposeInvitationAccept, SubjectEmail: email,
		InvitationID: &inv.ID, State: SetupTokenActive, ExpiresAt: c.now().Add(24 * time.Hour), CreatedBy: 1,
	})
	require.NoError(t, err)
	result, freshErr := c.CompleteSetup(ctx, freshToken, strongPw, "ua", "1.2.3.4")
	require.NoError(t, freshErr, "a resent-link retry must succeed once the orphaned account is cleaned up")
	require.NotNil(t, result.Session)

	newUser, uerr := st.GetUserByEmail(ctx, email)
	require.NoError(t, uerr)
	roles, rerr := st.GetUserRoleIDsExact(ctx, newUser.ID, storage.Scope{ProjectID: proj.ID})
	require.NoError(t, rerr)
	assert.NotEmpty(t, roles, "the resend-recovered account must actually hold the invited role")

	reloadedInv, ierr = st.GetProjectInvitation(ctx, inv.ID)
	require.NoError(t, ierr)
	assert.Equal(t, InvitationAccepted, reloadedInv.State, "the invitation must now read as accepted")
}
