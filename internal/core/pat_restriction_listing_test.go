package core

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// The edges of pat_restriction_listing.go's filters that the HTTP sweep's fixture
// does not produce: a notification with no project, a nil row, and the no-op for an
// unrestricted request.
func TestPATRestrictionListingFilters_Edges(t *testing.T) {
	t.Parallel()
	pid := func(v uint) *uint { return &v }
	plain := context.Background()
	confined := WithPATRestriction(plain, &PATRestriction{ProjectID: 7})
	envConfined := WithPATRestriction(plain, &PATRestriction{ProjectID: 7, EnvironmentID: 70})
	noSecretsRead := WithPATRestriction(plain, &PATRestriction{Permissions: []string{"users.read"}})
	cidrOnly := WithPATRestriction(plain, &PATRestriction{AllowedCIDRs: []string{"10.0.0.0/8"}})

	t.Run("notifications", func(t *testing.T) {
		inProject := &models.Notification{ProjectID: pid(7)}
		otherProject := &models.Notification{ProjectID: pid(8)}
		noProject := &models.Notification{}

		for _, n := range []*models.Notification{inProject, otherProject, noProject} {
			assert.True(t, patAllowsNotification(plain, n), "no restriction: everything is visible")
		}
		assert.True(t, patAllowsNotification(confined, inProject))
		assert.False(t, patAllowsNotification(confined, otherProject))
		assert.False(t, patAllowsNotification(confined, noProject), "fail closed: no project to check against")
		assert.False(t, patAllowsNotification(envConfined, inProject), "a project-level row is outside an environment confinement, as in Allows")
		assert.False(t, patAllowsNotification(noSecretsRead, inProject))
		assert.False(t, patAllowsNotification(cidrOnly, noProject), "any restriction fails closed on a project-less row")
		assert.True(t, patAllowsNotification(cidrOnly, inProject), "a CIDR-only restriction narrows nothing by scope")
		assert.False(t, patAllowsNotification(confined, nil))
	})

	t.Run("secrets", func(t *testing.T) {
		in := &models.SecretWithSharingInfo{SecretNode: &models.SecretNode{ID: 1, ProjectID: 7, EnvironmentID: 70}}
		other := &models.SecretWithSharingInfo{SecretNode: &models.SecretNode{ID: 2, ProjectID: 8, EnvironmentID: 80}}
		otherEnv := &models.SecretWithSharingInfo{SecretNode: &models.SecretNode{ID: 3, ProjectID: 7, EnvironmentID: 71}}
		rows := []*models.SecretWithSharingInfo{in, other, otherEnv, nil, {}}

		assert.Equal(t, rows, filterSecretsByPATRestriction(plain, rows), "no restriction: input returned unchanged")
		assert.Equal(t, []*models.SecretWithSharingInfo{in, otherEnv}, filterSecretsByPATRestriction(confined, rows))
		assert.Equal(t, []*models.SecretWithSharingInfo{in}, filterSecretsByPATRestriction(envConfined, rows))
		assert.Empty(t, filterSecretsByPATRestriction(noSecretsRead, rows))
	})
}

// TestGetDashboardStats_HonoursPATRestriction pins the GET /dashboard/stats half of
// PAT-GUARD-1 that the HTTP sweep's fixture does not reach: the caller's OWN recent
// activity and the share tiles. A token restricted to system.read (the route's gate)
// or confined to another project must not see rows naming the other project's
// secrets, and a filtered-out row must not just shorten the list.
func TestGetDashboardStats_HonoursPATRestriction(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	userID := seedUserWithRole(t, st, "dashpat", "system_viewer", storage.Scope{})
	peerID := seedUserWithRole(t, st, "dashpeer", "system_viewer", storage.Scope{})

	mkProject := func(name string) (uint, uint) {
		p, err := c.CreateProject(ctx, name, "")
		require.NoError(t, err)
		envs, err := st.ListEnvironmentsByProject(ctx, p.ID)
		require.NoError(t, err)
		require.NotEmpty(t, envs)
		return p.ID, envs[0].ID
	}
	mkSecret := func(pid, eid uint, name string, owner uint) *models.SecretNode {
		s, err := st.CreateSecret(ctx, &models.SecretNode{ProjectID: pid, EnvironmentID: eid, Name: name, CreatedBy: "dashpeer", OwnerID: owner})
		require.NoError(t, err)
		return s
	}
	canaryPID, canaryEID := mkProject("dash-canary")
	decoyPID, decoyEID := mkProject("dash-decoy")
	canary := mkSecret(canaryPID, canaryEID, "dashcanary-secret", peerID)
	decoy := mkSecret(decoyPID, decoyEID, "decoy-secret", peerID)
	canaryMine := mkSecret(canaryPID, canaryEID, "dashcanary-mine", userID)
	decoyMine := mkSecret(decoyPID, decoyEID, "decoy-mine", userID)

	// Older: 5 events in the decoy project. Newer: 10 naming the canary secret, so
	// an unfiltered newest-5 page is all canary.
	ok := true
	logEvent := func(s *models.SecretNode) {
		require.NoError(t, st.LogAuditEvent(ctx, &models.AuditEvent{
			EventType: "secret.read", UserID: &userID, SecretNodeID: &s.ID, ProjectID: &s.ProjectID,
			Description: "User dashpat read secret " + s.Name, Success: &ok, EventTime: time.Now().UTC(),
		}))
	}
	for i := 0; i < 5; i++ {
		logEvent(decoy)
	}
	for i := 0; i < 10; i++ {
		logEvent(canary)
	}
	for _, s := range []*models.SecretNode{canary, decoy} {
		_, err := st.CreateShareRecord(ctx, &models.ShareRecord{SecretID: s.ID, OwnerID: peerID, RecipientID: userID, Permission: "read"})
		require.NoError(t, err)
	}
	for _, s := range []*models.SecretNode{canaryMine, decoyMine} {
		_, err := st.CreateShareRecord(ctx, &models.ShareRecord{SecretID: s.ID, OwnerID: userID, RecipientID: peerID, Permission: "read"})
		require.NoError(t, err)
	}

	names := func(stats *DashboardStats) []string {
		var out []string
		for _, it := range stats.RecentActivity {
			out = append(out, it.SecretName)
		}
		return out
	}

	control, err := c.GetDashboardStats(ctx, userID, "dashpat", userID)
	require.NoError(t, err)
	require.Len(t, control.RecentActivity, 5)
	assert.Contains(t, names(control), "dashcanary-secret", "control: unrestricted, the newest rows name the canary")
	assert.Equal(t, 2, control.SharedSecrets)
	assert.Equal(t, 2, control.SecretsSharedWithMe)

	for name, r := range map[string]*PATRestriction{
		"system_read_only": {Permissions: []string{"system.read"}},
		"decoy_project":    {ProjectID: decoyPID},
	} {
		t.Run(name, func(t *testing.T) {
			stats, err := c.GetDashboardStats(WithPATRestriction(ctx, r), userID, "dashpat", userID)
			require.NoError(t, err)
			assert.NotContains(t, names(stats), "dashcanary-secret")
			wantDecoy := 0
			if r.ProjectID != 0 {
				wantDecoy = 1
			}
			assert.Len(t, stats.RecentActivity, 5*wantDecoy, "the decoy rows behind the canary ones are found, not just dropped")
			assert.Equal(t, wantDecoy, stats.SharedSecrets)
			assert.Equal(t, wantDecoy, stats.SecretsSharedWithMe)
		})
	}
}

// seedNotifications creates n notifications for userID in projectID (nil: none),
// each newer than the last one seeded.
func seedNotifications(t *testing.T, st *store.LocalStorage, userID uint, projectID *uint, n int, clock *time.Time) []*models.Notification {
	t.Helper()
	out := make([]*models.Notification, 0, n)
	for i := 0; i < n; i++ {
		*clock = clock.Add(time.Second)
		row, err := st.CreateNotification(context.Background(), &models.Notification{
			UserID: userID, ProjectID: projectID, Type: "test", Title: "t", Message: "m", CreatedAt: *clock,
		})
		require.NoError(t, err)
		out = append(out, row)
	}
	return out
}

// TestNotifications_RestrictedPATSeesVisibleRowsBeyondNewestWindow pins the review
// finding on #3062: the restricted-PAT filter ran over storage's newest-N window
// (limit 0 -> 50), so rows the token may see were missing from the list, the unread
// count and read-all, and mark-read said not-found, whenever 50 newer rows it may
// not see existed.
func TestNotifications_RestrictedPATSeesVisibleRowsBeyondNewestWindow(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	userID := seedUserWithRole(t, st, "notifpat", "system_viewer", storage.Scope{})
	pa, pb := uint(101), uint(202)
	clock := time.Now().UTC().Add(-time.Hour)
	visible := seedNotifications(t, st, userID, &pa, 10, &clock)
	seedNotifications(t, st, userID, &pb, 210, &clock) // more than storage's 200 cap
	seedNotifications(t, st, userID, nil, 5, &clock)

	confined := WithPATRestriction(ctx, &PATRestriction{ProjectID: pa})

	rows, err := c.ListNotifications(confined, userID, false, 0)
	require.NoError(t, err)
	assert.Len(t, rows, 10, "every visible row, though 215 newer ones are not")
	for _, n := range rows {
		require.NotNil(t, n.ProjectID)
		assert.Equal(t, pa, *n.ProjectID)
	}
	limited, err := c.ListNotifications(confined, userID, false, 3)
	require.NoError(t, err)
	assert.Len(t, limited, 3, "limit counts visible rows")

	count, err := c.UnreadNotificationCount(confined, userID)
	require.NoError(t, err)
	assert.EqualValues(t, 10, count)

	require.NoError(t, c.MarkNotificationRead(confined, visible[0].ID, userID), "a visible row is not 'not found'")
	count, err = c.UnreadNotificationCount(confined, userID)
	require.NoError(t, err)
	assert.EqualValues(t, 9, count)

	require.NoError(t, c.MarkAllNotificationsRead(confined, userID))
	count, err = c.UnreadNotificationCount(confined, userID)
	require.NoError(t, err)
	assert.Zero(t, count, "read-all reached every visible row")
	all, err := c.UnreadNotificationCount(ctx, userID)
	require.NoError(t, err)
	assert.EqualValues(t, 215, all, "and none it cannot see")
}

// TestPATNotificationScope_MatchesPerRowCheck: patNotificationScope narrows in the
// query, patAllowsNotification decides per row. For every restriction shape the
// restricted feed must be exactly the rows the per-row check passes, so the query
// can neither hide a visible row nor (the defence-in-depth filter aside) return one
// that is not.
func TestPATNotificationScope_MatchesPerRowCheck(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	userID := seedUserWithRole(t, st, "notifscope", "system_viewer", storage.Scope{})
	pa, pb := uint(101), uint(202)
	clock := time.Now().UTC().Add(-time.Hour)
	var rows []*models.Notification
	for _, p := range []*uint{&pa, &pb, nil} {
		rows = append(rows, seedNotifications(t, st, userID, p, 3, &clock)...)
	}

	for name, r := range map[string]*PATRestriction{
		"project_a":            {ProjectID: pa},
		"project_a_env":        {ProjectID: pa, EnvironmentID: 9},
		"project_a_secrets":    {ProjectID: pa, Permissions: []string{"secrets.read"}},
		"project_a_users":      {ProjectID: pa, Permissions: []string{"users.read"}},
		"secrets_read":         {Permissions: []string{"secrets.read"}},
		"secrets_wildcard":     {Permissions: []string{"secrets.*"}},
		"star":                 {Permissions: []string{"*"}},
		"users_read":           {Permissions: []string{"users.read"}},
		"system_read":          {Permissions: []string{"system.read"}},
		"cidr_only":            {AllowedCIDRs: []string{"10.0.0.0/8"}},
		"unknown_project_only": {ProjectID: 999},
	} {
		t.Run(name, func(t *testing.T) {
			rctx := WithPATRestriction(ctx, r)
			var want []uint
			for _, n := range rows {
				if patAllowsNotification(rctx, n) {
					want = append(want, n.ID)
				}
			}
			got, err := c.ListNotifications(rctx, userID, false, 200)
			require.NoError(t, err)
			var gotIDs []uint
			for _, n := range got {
				gotIDs = append(gotIDs, n.ID)
			}
			assert.ElementsMatch(t, want, gotIDs)
			count, err := c.UnreadNotificationCount(rctx, userID)
			require.NoError(t, err)
			assert.EqualValues(t, len(want), count)
		})
	}
}
