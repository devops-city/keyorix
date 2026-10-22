package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestCompleteInvitationAccept(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	ctx := context.Background()
	raw := setupPrefix + "invite1"
	hash := sha256Hex(raw)
	iid := uint(11)

	pendingInvite := func(c *KeyorixCore, _ string) *models.SetupToken {
		return &models.SetupToken{
			ID: 3, State: SetupTokenActive, Purpose: SetupPurposeInvitationAccept,
			SubjectEmail: "bob@acme.io", InvitationID: &iid, ExpiresAt: c.now().Add(time.Hour),
		}
	}
	invite := func(state, mode string) *models.ProjectInvitation {
		exp := time.Now().Add(24 * time.Hour)
		return &models.ProjectInvitation{
			ID: iid, ProjectID: 5, Email: "bob@acme.io", Role: "developer", State: state,
			InvitedBy: 7, ValidationModeAtInvite: mode, ExpiresAt: &exp,
		}
	}

	t.Run("open mode: lazy-creates the account, activates membership, grants role, auto-logs in", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		anyAudit(ms)
		created := &models.User{ID: 20, Username: "bob", Email: "bob@acme.io"}

		ms.On("GetSetupTokenByHash", ctx, hash).Return(pendingInvite(c, ValidationModeOpen), nil)
		ms.On("GetProjectInvitation", ctx, iid).Return(invite(InvitationPending, ValidationModeOpen), nil)
		ms.On("GetUserByEmail", ctx, "bob@acme.io").Return(nil, assertNotFoundErr())
		ms.On("MarkSetupTokenConsumed", ctx, uint(3), mock.AnythingOfType("time.Time")).Return(true, nil)
		ms.On("GetUserByUsername", ctx, mock.AnythingOfType("string")).Return(nil, assertNotFoundErr())
		ms.On("CreateUser", ctx, mock.AnythingOfType("*models.User")).Return(created, nil)
		ms.On("AddPasswordHistory", ctx, uint(20), mock.AnythingOfType("string"), mock.Anything).Return(nil)
		// system_viewer auto-assign (CreateUser) + the invited "developer" grant on activation.
		ms.On("GetRoleByName", ctx, "system_viewer").Return(nil, assertNotFoundErr())
		ms.On("GetRoleByName", ctx, "developer").Return(&models.Role{ID: 9, Name: "developer"}, nil)
		// F6 sweep (2026-09-22): activation-on-accept now ALSO requires the
		// inviter (7) hold roles.assign as a baseline at the invitation's project.
		ms.On("GetUserRoleIDsAt", ctx, uint(7), Scope{ProjectID: 5}).Return([]uint{100}, nil)
		ms.On("GetUserGroupRoleIDsAt", ctx, uint(7), Scope{ProjectID: 5}).Return([]uint{}, nil)
		ms.On("RoleSetBypassesPermissionChecks", ctx, []uint{100}).Return(false, nil)
		ms.On("RoleSetHasPermission", ctx, []uint{100}, "roles.assign").Return(true, nil)
		ms.On("GetActiveProjectMembership", ctx, uint(5), uint(20)).Return(nil, assertNotFoundErr())
		ms.On("CreateProjectMembership", ctx, mock.AnythingOfType("*models.ProjectMembership")).
			Return(&models.ProjectMembership{ID: 1, ProjectID: 5, UserID: 20, Role: "developer", State: MembershipActive}, nil)
		ms.On("GetRole", mock.Anything, uint(9)).Return(&models.Role{ID: 9, Name: "test-role-9"}, nil).Maybe() // #3546 role-scope check
		ms.On("AssignRole", ctx, uint(20), uint(9), mock.Anything).Return(nil)
		ms.On("UpdateProjectInvitation", ctx, mock.AnythingOfType("*models.ProjectInvitation")).Return(true, nil)
		ms.On("CreateSession", ctx, mock.AnythingOfType("*models.Session")).
			Return(&models.Session{ID: 1, UserID: 20, SessionToken: "sess-bob"}, nil)

		res, err := c.CompleteSetup(ctx, raw, strongPw, "ua", "1.2.3.4")
		require.NoError(t, err)
		assert.Equal(t, "sess-bob", res.Session.SessionToken)
		assert.Equal(t, uint(20), res.User.ID)
		// Role was granted (open mode → active membership → AddProjectMember → AssignRole).
		ms.AssertCalled(t, "AssignRole", ctx, uint(20), uint(9), mock.Anything)
		// Invitation marked accepted.
		ms.AssertCalled(t, "UpdateProjectInvitation", ctx, mock.MatchedBy(func(i *models.ProjectInvitation) bool {
			return i.State == InvitationAccepted
		}))
	})

	t.Run("allowlist mode: membership starts in invited, role is NOT granted yet", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		anyAudit(ms)
		created := &models.User{ID: 21, Username: "bob", Email: "bob@acme.io"}

		ms.On("GetSetupTokenByHash", ctx, hash).Return(pendingInvite(c, ValidationModeAllowlist), nil)
		ms.On("GetProjectInvitation", ctx, iid).Return(invite(InvitationPending, ValidationModeAllowlist), nil)
		ms.On("GetUserByEmail", ctx, "bob@acme.io").Return(nil, assertNotFoundErr())
		ms.On("MarkSetupTokenConsumed", ctx, uint(3), mock.AnythingOfType("time.Time")).Return(true, nil)
		ms.On("GetUserByUsername", ctx, mock.AnythingOfType("string")).Return(nil, assertNotFoundErr())
		ms.On("CreateUser", ctx, mock.AnythingOfType("*models.User")).Return(created, nil)
		ms.On("AddPasswordHistory", ctx, uint(21), mock.AnythingOfType("string"), mock.Anything).Return(nil)
		ms.On("GetRoleByName", ctx, "system_viewer").Return(nil, assertNotFoundErr())
		ms.On("GetRoleByName", ctx, "developer").Return(&models.Role{ID: 9, Name: "developer"}, nil)
		// F6 sweep (2026-09-22): the invite-on-accept baseline check runs
		// regardless of validation mode -- see the "open mode" subtest above.
		ms.On("GetUserRoleIDsAt", ctx, uint(7), Scope{ProjectID: 5}).Return([]uint{100}, nil)
		ms.On("GetUserGroupRoleIDsAt", ctx, uint(7), Scope{ProjectID: 5}).Return([]uint{}, nil)
		ms.On("RoleSetBypassesPermissionChecks", ctx, []uint{100}).Return(false, nil)
		ms.On("RoleSetHasPermission", ctx, []uint{100}, "roles.assign").Return(true, nil)
		ms.On("GetActiveProjectMembership", ctx, uint(5), uint(21)).Return(nil, assertNotFoundErr())
		ms.On("CreateProjectMembership", ctx, mock.AnythingOfType("*models.ProjectMembership")).
			Return(&models.ProjectMembership{ID: 2, ProjectID: 5, UserID: 21, Role: "developer", State: MembershipInvited}, nil)
		ms.On("UpdateProjectInvitation", ctx, mock.AnythingOfType("*models.ProjectInvitation")).Return(true, nil)
		ms.On("CreateSession", ctx, mock.AnythingOfType("*models.Session")).
			Return(&models.Session{ID: 2, UserID: 21, SessionToken: "sess-bob2"}, nil)

		res, err := c.CompleteSetup(ctx, raw, strongPw, "ua", "1.2.3.4")
		require.NoError(t, err)
		assert.Equal(t, "sess-bob2", res.Session.SessionToken)
		// The membership landed in `invited`, so no project-role grant happened.
		ms.AssertNotCalled(t, "AssignRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		// The membership was created in the invited state (not active).
		ms.AssertCalled(t, "CreateProjectMembership", ctx, mock.MatchedBy(func(m *models.ProjectMembership) bool {
			return m.State == MembershipInvited
		}))
	})

	t.Run("rejects acceptance when an account already exists for the email (no auth bypass)", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		ms.On("GetSetupTokenByHash", ctx, hash).Return(pendingInvite(c, ValidationModeOpen), nil)
		ms.On("GetProjectInvitation", ctx, iid).Return(invite(InvitationPending, ValidationModeOpen), nil)
		ms.On("GetUserByEmail", ctx, "bob@acme.io").Return(&models.User{ID: 99}, nil)

		_, err := c.CompleteSetup(ctx, raw, strongPw, "ua", "1.2.3.4")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")
		ms.AssertNotCalled(t, "MarkSetupTokenConsumed", mock.Anything, mock.Anything, mock.Anything)
		ms.AssertNotCalled(t, "CreateUser", mock.Anything, mock.Anything)
	})

	t.Run("fails closed when the existing-account lookup errors (no silent bypass)", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		ms.On("GetSetupTokenByHash", ctx, hash).Return(pendingInvite(c, ValidationModeOpen), nil)
		ms.On("GetProjectInvitation", ctx, iid).Return(invite(InvitationPending, ValidationModeOpen), nil)
		// A non-"not found" storage error must abort, not be read as "no account".
		ms.On("GetUserByEmail", ctx, "bob@acme.io").Return(nil, assert.AnError)

		_, err := c.CompleteSetup(ctx, raw, strongPw, "ua", "1.2.3.4")
		require.Error(t, err)
		ms.AssertNotCalled(t, "MarkSetupTokenConsumed", mock.Anything, mock.Anything, mock.Anything)
		ms.AssertNotCalled(t, "CreateUser", mock.Anything, mock.Anything)
	})

	t.Run("rejects a non-pending invitation", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		ms.On("GetSetupTokenByHash", ctx, hash).Return(pendingInvite(c, ValidationModeOpen), nil)
		ms.On("GetProjectInvitation", ctx, iid).Return(invite(InvitationRevoked, ValidationModeOpen), nil)

		_, err := c.CompleteSetup(ctx, raw, strongPw, "ua", "1.2.3.4")
		require.Error(t, err)
		ms.AssertNotCalled(t, "MarkSetupTokenConsumed", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("a weak password is rejected without consuming the token", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		ms.On("GetSetupTokenByHash", ctx, hash).Return(pendingInvite(c, ValidationModeOpen), nil)
		ms.On("GetProjectInvitation", ctx, iid).Return(invite(InvitationPending, ValidationModeOpen), nil)
		ms.On("GetUserByEmail", ctx, "bob@acme.io").Return(nil, assertNotFoundErr())

		_, err := c.CompleteSetup(ctx, raw, "short", "ua", "1.2.3.4")
		require.Error(t, err)
		ms.AssertNotCalled(t, "MarkSetupTokenConsumed", mock.Anything, mock.Anything, mock.Anything)
		ms.AssertNotCalled(t, "CreateUser", mock.Anything, mock.Anything)
	})
}

func TestDeriveUsername(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	ctx := context.Background()

	t.Run("sanitizes the email local part and dedupes on collision", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		// "bob.smith" sanitizes to "bobsmith"; first candidate is taken, suffix wins.
		ms.On("GetUserByUsername", ctx, "bobsmith").Return(&models.User{ID: 1}, nil)
		ms.On("GetUserByUsername", ctx, "bobsmith1").Return(nil, assertNotFoundErr())

		got, err := c.deriveUsername(ctx, "Bob.Smith@acme.io")
		require.NoError(t, err)
		assert.Equal(t, "bobsmith1", got)
	})

	t.Run("pads a too-short local part", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		ms.On("GetUserByUsername", ctx, "abuser").Return(nil, assertNotFoundErr())
		got, err := c.deriveUsername(ctx, "ab@acme.io")
		require.NoError(t, err)
		assert.Equal(t, "abuser", got)
	})
}
