// membership_revert_timestamps_test.go — #2800: a failed transition's revert
// must put the row's lifecycle timestamps back exactly as it found them.
package core

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

// newRevertTSCore is newBootstrappedCore's shape (real MigrateExisting, real
// BootstrapSystem, so roles and permissions are the production ones) but also
// hands back the *gorm.DB and the bootstrap admin's ID, both of which these
// tests need. sqlitetest gives it a process-unique database (the old
// clock-plus-letter name repeated after 26 calls in the same second).
func newRevertTSCore(t *testing.T) (*KeyorixCore, *gorm.DB, uint) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.OpenWithDialector(t, "kxcore_revertts_", sqlite.Open, &gorm.Config{})
	require.NoError(t, kxstorage.MigrateExisting(db))

	c := NewKeyorixCore(store.NewLocalStorage(db))
	c.SetBootstrapToken("revert-ts-token")
	boot, err := c.BootstrapSystem(context.Background(), &BootstrapRequest{
		Username: "admin", Email: "admin@example.com", Password: "BootstrapPass123!", DisplayName: "Admin",
		Token: "revert-ts-token",
	})
	require.NoError(t, err)
	c.SetBootstrapToken("")
	return c, db, boot.User.ID
}

// TestRevertFailedActivation_RestoresPreTransitionTimestamps drives the real
// revocation-failure path and asserts the row comes back as it was, rather than
// reconstructed from the target state.
//
// How the failure is driven, without a fault injector: RemoveProjectMember
// refuses to strip the project's LAST roles.assign holder
// (guardLastProjectAdmin, #236). So a project whose only admin is the member
// being revoked makes TransitionMembership's `case MembershipRevoked` side
// effect fail for a real, reachable, security-relevant reason — which is exactly
// the case #G54 added the revert for, and the one the timestamp branch got wrong.
//
// The defect (#2800): TransitionMembership stamps RevokedAt = now and commits
// state=revoked, then RemoveProjectMember refuses, then revertFailedActivation
// put the state back to `active` but DERIVED the timestamps from the TARGET
// state — taking the "not reverting to revoked" branch, which cleared
// ActivatedAt and left the failed revoke's RevokedAt standing. The row then read
// `active` / never-activated / revoked-at-T: three mutually contradictory facts,
// and a member who still holds their role while anything reading RevokedAt sees
// them as revoked.
func TestRevertFailedActivation_RestoresPreTransitionTimestamps(t *testing.T) {
	c, db, adminID := newRevertTSCore(t)
	ctx := context.Background()

	proj, err := c.CreateProject(ctx, "revert-ts-project", "")
	require.NoError(t, err)

	// The sole project admin — the member whose revocation must be refused.
	member, err := c.CreateUser(ctx, &CreateUserRequest{
		Username: "revert-member", Email: "revert-member@example.com", Password: "MemberPass123!xyz-long-enough",
	})
	require.NoError(t, err)
	projectAdmin, err := c.Storage().GetRoleByName(ctx, "project_admin")
	require.NoError(t, err)
	require.NoError(t, c.Storage().AssignRole(ctx, member.ID, projectAdmin.ID, Scope{ProjectID: proj.ID}))

	// An `active` membership with BOTH timestamps already populated, so the test
	// can distinguish "restored" from "cleared" and from "re-stamped to now".
	// The pre-existing RevokedAt is from an earlier revoke/re-invite cycle and
	// must survive untouched — a revert that re-derives `RevokedAt = now` fails
	// this too, not just one that clears ActivatedAt.
	invitedAt := time.Now().Add(-72 * time.Hour).UTC().Truncate(time.Second)
	earlierRevokedAt := time.Now().Add(-60 * time.Hour).UTC().Truncate(time.Second)
	activatedAt := time.Now().Add(-48 * time.Hour).UTC().Truncate(time.Second)
	m, err := c.Storage().CreateProjectMembership(ctx, &models.ProjectMembership{
		ProjectID: proj.ID, UserID: member.ID, Role: "project_admin", State: MembershipActive,
		InvitedBy: adminID, InvitedAt: invitedAt, UpdatedAt: invitedAt,
		ActivatedAt: &activatedAt, RevokedAt: &earlierRevokedAt,
	})
	require.NoError(t, err)

	before, err := c.Storage().GetProjectMembership(ctx, m.ID)
	require.NoError(t, err)
	require.Equal(t, MembershipActive, before.State)
	require.NotNil(t, before.ActivatedAt)
	require.NotNil(t, before.RevokedAt)

	// The revoke must fail: member is the project's only roles.assign holder.
	_, err = c.TransitionMembership(ctx, proj.ID, m.ID, MembershipRevoked, adminID, false)
	require.Error(t, err, "revoking the project's last admin must be refused by guardLastProjectAdmin")
	require.Contains(t, err.Error(), "failed to remove role grant on revocation",
		"the failure must come from the revoke's grant-removal side effect, not an earlier check — "+
			"otherwise this test never reaches revertFailedActivation and proves nothing")

	after, err := c.Storage().GetProjectMembership(ctx, m.ID)
	require.NoError(t, err)

	assert.Equal(t, MembershipActive, after.State, "the revert must put the state back to active")
	require.NotNil(t, after.ActivatedAt,
		"#2800: ActivatedAt was cleared — the row reads active but never-activated")
	assert.WithinDuration(t, *before.ActivatedAt, *after.ActivatedAt, time.Second,
		"ActivatedAt must be the pre-transition value, neither nil nor re-stamped")
	require.NotNil(t, after.RevokedAt, "the pre-existing RevokedAt must survive the revert")
	assert.WithinDuration(t, *before.RevokedAt, *after.RevokedAt, time.Second,
		"#2800: RevokedAt is the failed revoke's own stamp — the row reads active yet revoked-at-now")
	assert.WithinDuration(t, before.InvitedAt, after.InvitedAt, time.Second, "InvitedAt must not move")

	// UpdatedAt is the one timestamp that legitimately advances: the revert is a
	// real write, and an unchanged UpdatedAt would hide it from anything
	// reconciling on it.
	assert.False(t, after.UpdatedAt.Before(before.UpdatedAt), "UpdatedAt must not go backwards")

	// The point of the invariant: the member still holds the role, so nothing
	// reading this row may conclude they were revoked.
	stillMember, err := c.Storage().IsProjectMember(ctx, member.ID, proj.ID)
	require.NoError(t, err)
	assert.True(t, stillMember, "the refused revocation must leave the role grant in place")

	var raw models.ProjectMembership
	require.NoError(t, db.Where("id = ?", m.ID).First(&raw).Error)
	assert.False(t, raw.State == MembershipActive && raw.RevokedAt != nil && raw.RevokedAt.After(activatedAt),
		"row is active with a RevokedAt stamped after its activation — the self-contradictory state #2800 describes")
}

// TestRevertFailedActivation_InviteFailureStillRevokesTerminally pins the OTHER
// caller's intent so the #2800 change cannot silently alter it. When
// inviteMemberWithMode's own grant fails, the row it just created never had a
// working grant and has no earlier state to return to, so the revert is a
// genuine terminal revocation: revoked, stamped now, and NOT claiming to have
// been activated.
func TestRevertFailedActivation_InviteFailureStillRevokesTerminally(t *testing.T) {
	c, db, adminID := newRevertTSCore(t)
	ctx := context.Background()

	proj, err := c.CreateProject(ctx, "invite-revert-project", "")
	require.NoError(t, err)
	member, err := c.CreateUser(ctx, &CreateUserRequest{
		Username: "invite-revert-member", Email: "invite-revert-member@example.com", Password: "MemberPass123!xyz-long-enough",
	})
	require.NoError(t, err)

	// Make the open-mode invite's AssignRole fail the way revertFailedActivation's
	// own doc describes: the role is ALREADY held through an independent direct
	// grant, so AssignRole's composite primary key rejects the duplicate, while
	// uniq_project_memberships_active (which dedupes only membership rows) does
	// not stop the invite from creating its row first.
	viewer, err := c.Storage().GetRoleByName(ctx, "project_viewer")
	require.NoError(t, err)
	require.NoError(t, c.Storage().AssignRole(ctx, member.ID, viewer.ID, Scope{ProjectID: proj.ID}))

	c.SetMembershipValidationMode(ValidationModeOpen)
	created, inviteErr := c.InviteMember(ctx, proj.ID, member.ID, "project_viewer", adminID, 0, false)

	var raw models.ProjectMembership
	err = db.Where("project_id = ? AND user_id = ?", proj.ID, member.ID).First(&raw).Error
	if inviteErr == nil {
		// AssignRole tolerated the duplicate, so the grant did NOT fail and the
		// revert path was never entered. Assert the benign outcome rather than
		// skipping, so this test never silently stops covering anything.
		require.NoError(t, err)
		require.NotNil(t, created)
		assert.Equal(t, MembershipActive, raw.State,
			"a successful open-mode invite must leave an active row")
		assert.NotNil(t, raw.ActivatedAt, "an active row must carry ActivatedAt")
		return
	}

	require.NoError(t, err, "a failed invite must still have left its row for the revert to fix up")
	assert.Equal(t, MembershipRevoked, raw.State, "a failed open-mode invite must not leave a live active row")
	assert.Nil(t, raw.ActivatedAt, "the grant never landed, so the row must not claim it was activated")
	require.NotNil(t, raw.RevokedAt, "a terminal revert must stamp RevokedAt")
}
