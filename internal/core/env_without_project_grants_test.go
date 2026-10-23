package core

// env_without_project_grants_test.go — ROLE-SHAPE-1 (#2857 follow-up): grants at
// {project_id: 0, environment_id: X} written before #3546 are reported, with the
// fix, and the access review of X's project says it is incomplete while one
// exists (it used to read as complete: the grant applies there but
// ListProjectRoleAssignments(P) never returns it).

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// seedEnvironmentWithoutProjectGrants writes the legacy shape straight into
// storage (as a release before #3546 could), plus valid grants that must not be
// reported: a user grant at {0, e1} of a system role, a group grant at {0, e2} of
// a project role, and the same principals at {p1, e1} and {0, 0}.
func seedEnvironmentWithoutProjectGrants(t *testing.T, w *roleScopeWorld) {
	t.Helper()
	ctx := context.Background()
	st := w.c.storage
	require.NoError(t, st.AssignRole(ctx, w.userID, w.systemViewer.ID, Scope{EnvironmentID: w.e1}))
	require.NoError(t, st.AssignRoleToGroup(ctx, w.groupID, w.projectDeveloper.ID, Scope{EnvironmentID: w.e2}))
	require.NoError(t, st.AssignRole(ctx, w.userID, w.projectDeveloper.ID, Scope{ProjectID: w.p1, EnvironmentID: w.e1}))
	require.NoError(t, st.AssignRoleToGroup(ctx, w.groupID, w.systemViewer.ID, Scope{}))
}

func TestListEnvironmentWithoutProjectGrants_ReportsLegacyRowsWithTheirProject(t *testing.T) {
	c, _ := newBootstrappedCore(t)
	ctx := context.Background()
	w := newRoleScopeWorld(t, c)

	got, err := c.ListEnvironmentWithoutProjectGrants(ctx)
	require.NoError(t, err)
	require.Empty(t, got, "a fresh install has none")

	seedEnvironmentWithoutProjectGrants(t, w)
	got, err = c.ListEnvironmentWithoutProjectGrants(ctx)
	require.NoError(t, err)
	require.Equal(t, []EnvironmentWithoutProjectGrant{
		{PrincipalType: "group", PrincipalID: w.groupID, RoleID: w.projectDeveloper.ID, RoleName: "project_developer", EnvironmentID: w.e2, ProjectID: w.p2},
		{PrincipalType: "user", PrincipalID: w.userID, RoleID: w.systemViewer.ID, RoleName: "system_viewer", EnvironmentID: w.e1, ProjectID: w.p1},
	}, got)
	require.Equal(t, fmt.Sprintf("user %d holds role system_viewer (id %d) at project_id=0, environment_id=%d; "+
		"it applies in environment %d of project %d but that project's access review does not list it: "+
		"re-create it with project_id=%d (POST /api/v1/user-roles {user_id: %d, role_id: %d, project_id: %d, environment_id: %d}), "+
		"then remove the old grant (DELETE /api/v1/user-roles {user_id: %d, role_id: %d, project_id: 0, environment_id: %d})",
		w.userID, w.systemViewer.ID, w.e1, w.e1, w.p1, w.p1, w.userID, w.systemViewer.ID, w.p1, w.e1, w.userID, w.systemViewer.ID, w.e1),
		got[1].Describe())
	require.Contains(t, got[0].Describe(), fmt.Sprintf("POST /api/v1/groups/%d/roles {role_id: %d, project_id: %d, environment_id: %d}",
		w.groupID, w.projectDeveloper.ID, w.p2, w.e2))
	require.Contains(t, got[0].Describe(), fmt.Sprintf("DELETE /api/v1/groups/%d/roles/%d?project_id=0&environment_id=%d",
		w.groupID, w.projectDeveloper.ID, w.e2))
}

func TestEnvironmentWithoutProjectGrant_DescribeGoneEnvironmentAndExpiry(t *testing.T) {
	exp := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	got := EnvironmentWithoutProjectGrant{PrincipalType: "user", PrincipalID: 3, RoleID: 4, RoleName: "auditor", EnvironmentID: 9, ExpiresAt: &exp}.Describe()
	require.Equal(t, "user 3 holds role auditor (id 4) at project_id=0, environment_id=9, expires 2026-11-01T00:00:00Z; "+
		"environment 9 no longer exists: remove the grant (DELETE /api/v1/user-roles {user_id: 3, role_id: 4, project_id: 0, environment_id: 9})", got)
}

// TestGenerateProjectAccessReview_FlagsEnvironmentWithoutProjectGrant: the
// review of the grant's project is degraded and names the grant with its fix,
// another project's review names only its own, a project with none stays
// complete, and a campaign opened on the project keeps the reasons as evidence.
// Red before ROLE-SHAPE-1: every report was complete.
func TestGenerateProjectAccessReview_FlagsEnvironmentWithoutProjectGrant(t *testing.T) {
	c, _ := newBootstrappedCore(t)
	ctx := context.Background()
	w := newRoleScopeWorld(t, c)
	clean, err := c.CreateProject(ctx, "rs-clean", "")
	require.NoError(t, err)
	seedEnvironmentWithoutProjectGrants(t, w)

	reasonsOf := func(projectID uint) (bool, []string) {
		r, rerr := c.GenerateProjectAccessReview(ctx, projectID)
		require.NoError(t, rerr)
		var flagged []string
		for _, reason := range r.DegradedReasons {
			if strings.HasPrefix(reason, accessReviewRoleScopeArea+": ") {
				flagged = append(flagged, reason)
			}
		}
		return r.Degraded, flagged
	}

	degraded, reasons := reasonsOf(w.p1)
	require.True(t, degraded)
	require.Len(t, reasons, 1)
	require.Contains(t, reasons[0], fmt.Sprintf("user %d holds role system_viewer", w.userID))
	require.Contains(t, reasons[0], fmt.Sprintf("re-create it with project_id=%d", w.p1))

	degraded, reasons = reasonsOf(w.p2)
	require.True(t, degraded)
	require.Len(t, reasons, 1)
	require.Contains(t, reasons[0], fmt.Sprintf("group %d holds role project_developer", w.groupID))

	degraded, reasons = reasonsOf(clean.ID)
	require.False(t, degraded, "a project with no such grant is not flagged")
	require.Empty(t, reasons)

	res, err := c.OpenAccessReviewCampaign(ctx, w.adminID, 0, w.p1, "Q4")
	require.NoError(t, err)
	require.True(t, res.Campaign.Degraded, "the campaign's evidence snapshot records that it was incomplete")
	require.Len(t, res.Campaign.DegradedReasons, 1)
	require.Contains(t, res.Campaign.DegradedReasons[0], fmt.Sprintf("environment_id=%d", w.e1))
}
