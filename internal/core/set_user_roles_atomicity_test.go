package core

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failOnceAssignRoleForRoleStorage makes AssignRole fail once for a specific
// roleID, mirroring the failOnceStorage idiom from #2295.
func failOnceAssignRoleForRoleStorage(inner storage.Storage, failRoleID uint, armed *bool) storage.Storage {
	return hooked(inner, &storeHooks{
		WrapTx: true,
		AssignRole: func(next storage.Storage, ctx context.Context, userID, roleID uint, scope storage.Scope) error {
			if *armed && roleID == failRoleID {
				*armed = false
				return errors.New("injected fault: AssignRole")
			}
			return next.AssignRole(ctx, userID, roleID, scope)
		},
	})
}

// WithTransaction keeps the fault on the transaction-scoped handle: a grant is
// written through tx since AUDIT-TX-2 (it commits with its audit row).
// TestSetUserRoles_PartialApplyFailureRevertsToOriginalSet is the red-proof
// for Session O's O3 SetUserRoles finding (a NEW finding, not in the
// coordinator's preliminary list): unlike AssignUserRole/RemoveUserRole's
// single-grant choke points, this is a full role-set replacement made of
// several of them with no underlying transaction available. Before this fix,
// a failure partway through returned immediately with NO compensation --
// completed removes stayed removed even though the operation as a whole
// failed. This asserts the compensating revert restores the ORIGINAL role
// set exactly, not some arbitrary in-between state.
func TestSetUserRoles_PartialApplyFailureRevertsToOriginalSet(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	proj, err := st.CreateProject(ctx, &models.Project{Name: "roles-proj", Description: "d"})
	require.NoError(t, err)
	u, err := st.CreateUser(ctx, foldedTestUser(t, "target", "target@example.com"))
	require.NoError(t, err)

	viewer, err := st.GetRoleByName(ctx, "project_viewer")
	require.NoError(t, err)
	developer, err := st.GetRoleByName(ctx, "project_developer")
	require.NoError(t, err)
	admin, err := st.GetRoleByName(ctx, "project_admin")
	require.NoError(t, err)

	scope := storage.Scope{ProjectID: proj.ID}
	require.NoError(t, st.AssignRole(ctx, u.ID, viewer.ID, scope))
	require.NoError(t, st.AssignRole(ctx, u.ID, developer.ID, scope))

	// New set: keep viewer, drop developer, add admin (which will fail).
	armed := true
	c.storage = failOnceAssignRoleForRoleStorage(st, admin.ID, &armed)

	const actor = uint(1) // bootstrapped global admin
	err = c.SetUserRoles(ctx, actor, u.ID, []uint{viewer.ID, admin.ID}, scope, false)
	require.Error(t, err)
	require.False(t, armed, "the injected fault must actually have fired")

	got, gerr := st.GetUserRoleIDsExact(ctx, u.ID, scope)
	require.NoError(t, gerr)
	assert.ElementsMatch(t, []uint{viewer.ID, developer.ID}, got,
		"a failed partial apply must revert to the EXACT original role set -- developer must be restored, admin must not be present")
}
