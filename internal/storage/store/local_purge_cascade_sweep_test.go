// local_purge_cascade_sweep_test.go — partial-coverage sweep for
// local_purge.go: each retention-purge transaction's individual per-table
// delete-error branches, reached via partial migration (earlier steps'
// tables present, target step's table absent) or dropTableAfterDeletes /
// dropTableAfterQueries (shared helpers, local_secrets_cascade_sweep_test.go).
package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
)

func newPurgeUsersFixture(t *testing.T, extraModels ...any) *LocalStorage {
	t.Helper()
	ls := newPartialSecretsDB(t, append([]any{&models.User{}}, extraModels...)...)
	u := &models.User{Username: "purge-me", UsernameFolded: "purge-me", EmailFolded: "purge-me@example.com"}
	require.NoError(t, ls.db.Create(u).Error)
	require.NoError(t, ls.db.Exec("UPDATE users SET deleted_at = ? WHERE id = ?", time.Now().Add(-48*time.Hour), u.ID).Error)
	return ls
}

func TestPurgeDeletedUsersBefore_UserRoleDeleteFails(t *testing.T) {
	t.Parallel()
	ls := newPurgeUsersFixture(t)
	_, err := ls.PurgeDeletedUsersBefore(context.Background(), time.Now())
	require.Error(t, err)
}

func TestPurgeDeletedUsersBefore_UserGroupDeleteFails(t *testing.T) {
	t.Parallel()
	ls := newPurgeUsersFixture(t, &models.UserRole{})
	_, err := ls.PurgeDeletedUsersBefore(context.Background(), time.Now())
	require.Error(t, err)
}

func TestPurgeDeletedUsersBefore_ShareRecordDeleteFails(t *testing.T) {
	t.Parallel()
	ls := newPurgeUsersFixture(t, &models.UserRole{}, &models.UserGroup{})
	_, err := ls.PurgeDeletedUsersBefore(context.Background(), time.Now())
	require.Error(t, err)
}

func TestPurgeDeletedUsersBefore_PersonalAccessTokenDeleteFails(t *testing.T) {
	t.Parallel()
	ls := newPurgeUsersFixture(t, &models.UserRole{}, &models.UserGroup{}, &models.ShareRecord{})
	_, err := ls.PurgeDeletedUsersBefore(context.Background(), time.Now())
	require.Error(t, err)
}

func TestPurgeDeletedUsersBefore_SecretACLDeleteFails(t *testing.T) {
	t.Parallel()
	ls := newPurgeUsersFixture(t, &models.UserRole{}, &models.UserGroup{}, &models.ShareRecord{}, &models.PersonalAccessToken{})
	_, err := ls.PurgeDeletedUsersBefore(context.Background(), time.Now())
	require.Error(t, err)
}

func TestPurgeDeletedUsersBefore_SessionDeleteFails(t *testing.T) {
	t.Parallel()
	ls := newPurgeUsersFixture(t, &models.UserRole{}, &models.UserGroup{}, &models.ShareRecord{}, &models.PersonalAccessToken{}, &models.SecretACL{})
	_, err := ls.PurgeDeletedUsersBefore(context.Background(), time.Now())
	require.Error(t, err)
}

func TestPurgeDeletedUsersBefore_FinalUserDeleteFails(t *testing.T) {
	t.Parallel()
	ls := newPurgeUsersFixture(t, &models.UserRole{}, &models.UserGroup{}, &models.ShareRecord{},
		&models.PersonalAccessToken{}, &models.SecretACL{}, &models.Session{})

	// 6 delete-family statements precede the final User delete: UserRole,
	// UserGroup, ShareRecord, PersonalAccessToken, SecretACL, Session.
	dropTableAfterDeletes(t, ls.db, 6, "users")

	_, err := ls.PurgeDeletedUsersBefore(context.Background(), time.Now())
	require.Error(t, err)
}

func newPurgeProjectsFixture(t *testing.T, extraModels ...any) *LocalStorage {
	t.Helper()
	ls := newPartialSecretsDB(t, append([]any{&models.Project{}}, extraModels...)...)
	p := &models.Project{Name: "purge-me"}
	require.NoError(t, ls.db.Create(p).Error)
	require.NoError(t, ls.db.Exec("UPDATE projects SET deleted_at = ? WHERE id = ?", time.Now().Add(-48*time.Hour), p.ID).Error)
	return ls
}

func TestPurgeDeletedProjectsBefore_UserRoleDeleteFails(t *testing.T) {
	t.Parallel()
	ls := newPurgeProjectsFixture(t)
	_, err := ls.PurgeDeletedProjectsBefore(context.Background(), time.Now())
	require.Error(t, err)
}

func TestPurgeDeletedProjectsBefore_GroupRoleDeleteFails(t *testing.T) {
	t.Parallel()
	ls := newPurgeProjectsFixture(t, &models.UserRole{})
	_, err := ls.PurgeDeletedProjectsBefore(context.Background(), time.Now())
	require.Error(t, err)
}

func TestPurgeDeletedProjectsBefore_FinalProjectDeleteFails(t *testing.T) {
	t.Parallel()
	ls := newPurgeProjectsFixture(t, &models.UserRole{}, &models.GroupRole{})

	// 2 delete-family statements precede the final Project delete.
	dropTableAfterDeletes(t, ls.db, 2, "projects")

	_, err := ls.PurgeDeletedProjectsBefore(context.Background(), time.Now())
	require.Error(t, err)
}

func newPurgeSecretsFixture(t *testing.T, extraModels ...any) *LocalStorage {
	t.Helper()
	ls := newPartialSecretsDB(t, append([]any{&models.SecretNode{}}, extraModels...)...)
	s := &models.SecretNode{ProjectID: 1, EnvironmentID: 1, Name: "purge-me", IsSecret: true}
	require.NoError(t, ls.db.Create(s).Error)
	require.NoError(t, ls.db.Exec("UPDATE secret_nodes SET deleted_at = ? WHERE id = ?", time.Now().Add(-48*time.Hour), s.ID).Error)
	return ls
}

func TestPurgeDeletedSecretsBefore_SecretVersionDeleteFails(t *testing.T) {
	t.Parallel()
	// Every cascade table exists, so the cascade succeeds and the failure is the
	// secret_versions delete the test is named for, not a missing cascade table.
	ls := newPurgeSecretsFixture(t, secretPurgeCascadeModels()...)
	_, err := ls.PurgeDeletedSecretsBefore(context.Background(), time.Now())
	require.ErrorContains(t, err, "secret_versions")
}

func TestPurgeDeletedSecretsBefore_SecretDependencyDeleteFails(t *testing.T) {
	t.Parallel()
	ls := newPurgeSecretsFixture(t, append([]any{&models.SecretVersion{}}, secretPurgeCascadeModels()...)...)
	_, err := ls.PurgeDeletedSecretsBefore(context.Background(), time.Now())
	require.Error(t, err)
}

func TestPurgeDeletedSecretsBefore_SecretACLDeleteFails(t *testing.T) {
	t.Parallel()
	ls := newPurgeSecretsFixture(t, append([]any{&models.SecretVersion{}, &models.SecretDependency{}}, secretPurgeCascadeModels()...)...)
	_, err := ls.PurgeDeletedSecretsBefore(context.Background(), time.Now())
	require.Error(t, err)
}

func TestPurgeDeletedSecretsBefore_FinalSecretNodeDeleteFails(t *testing.T) {
	t.Parallel()
	ls := newPurgeSecretsFixture(t, append([]any{&models.SecretVersion{}, &models.SecretDependency{}, &models.SecretACL{}}, secretPurgeCascadeModels()...)...)

	// The reference cascade (#3085) plus 3 delete-family statements precede the
	// final SecretNode delete.
	dropTableAfterDeletes(t, ls.db, SecretPurgeStatementCount()+3, "secret_nodes")

	_, err := ls.PurgeDeletedSecretsBefore(context.Background(), time.Now())
	require.Error(t, err)
}

func TestDeleteClosedAccessReviewsBefore_CampaignDeleteFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.AccessReviewCampaign{}, &models.AccessReviewItem{})
	ctx := context.Background()
	closedAt := time.Now().Add(-48 * time.Hour)
	c := &models.AccessReviewCampaign{ProjectID: 1, Name: "campaign", State: "closed", ClosedAt: &closedAt}
	require.NoError(t, ls.db.Create(c).Error)

	// 1 delete-family statement (the item delete, 0 rows) precedes the
	// campaign delete.
	dropTableAfterDeletes(t, ls.db, 1, "access_review_campaigns")

	_, _, err := ls.DeleteClosedAccessReviewsBefore(ctx, time.Now())
	require.Error(t, err)
}

func TestDeleteResolvedAccessRequestsBefore_RequestDeleteFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.AccessRequest{}, &models.AccessRequestApproval{})
	ctx := context.Background()
	resolvedAt := time.Now().Add(-48 * time.Hour)
	r := &models.AccessRequest{ProjectID: 1, UserID: 1, State: "approved", ResolvedAt: &resolvedAt}
	require.NoError(t, ls.db.Create(r).Error)

	// 1 delete-family statement (the approval delete, 0 rows) precedes the
	// request delete.
	dropTableAfterDeletes(t, ls.db, 1, "access_requests")

	_, _, err := ls.DeleteResolvedAccessRequestsBefore(ctx, time.Now())
	require.Error(t, err)
}

func TestDeleteExpiredBreakGlassBefore_ReconcileUpdateFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.BreakGlassActivation{})
	ctx := context.Background()
	pastExpiry := time.Now().Add(-time.Hour)
	bg := &models.BreakGlassActivation{ProjectID: 1, UserID: 1, State: "active", ExpiresAt: &pastExpiry, CreatedAt: time.Now().Add(-48 * time.Hour)}
	require.NoError(t, ls.db.Create(bg).Error)

	// The Pluck (1 query-family call) finds this row (justReconciledIDs
	// non-empty); drop the table right after so the reconcile Update fails.
	dropTableAfterQueries(t, ls.db, 1, "break_glass_activations")

	_, err := ls.DeleteExpiredBreakGlassBefore(ctx, time.Now())
	require.Error(t, err)
}

func TestDeleteExpiredBreakGlassBefore_FinalDeleteFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.BreakGlassActivation{})
	ctx := context.Background()

	// No rows to reconcile (Pluck returns empty), so the Update step is
	// skipped entirely; drop the table right after the Pluck so the final
	// Delete fails instead.
	dropTableAfterQueries(t, ls.db, 1, "break_glass_activations")

	_, err := ls.DeleteExpiredBreakGlassBefore(ctx, time.Now())
	require.Error(t, err)
}
