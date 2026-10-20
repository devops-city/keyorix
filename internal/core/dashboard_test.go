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

// failingDashboardAuditStore wraps inner and fails every GetAuditLogs
// call, simulating an audit-log query outage while every other dashboard
// sub-check still runs for real.
func failingDashboardAuditStore(inner storage.Storage) storage.Storage {
	return hooked(inner, &storeHooks{
		GetAuditLogs: func(_ storage.Storage, _ context.Context, _ *storage.AuditFilter) ([]*models.AuditEvent, int64, error) {
			return nil, 0, errors.New("simulated audit log outage")
		},
	})
}

// failingDashboardStatsStore wraps inner and fails GetStats, simulating
// a DB error on the active-users rollup.
func failingDashboardStatsStore(inner storage.Storage) storage.Storage {
	return hooked(inner, &storeHooks{
		GetStats: func(_ storage.Storage, _ context.Context) (*storage.StorageStats, error) {
			return nil, errors.New("simulated stats query failure")
		},
	})
}

// failingDashboardUsersStore wraps inner and fails ListUsers, simulating
// a DB error on the inactive-users rollup.
func failingDashboardUsersStore(inner storage.Storage) storage.Storage {
	return hooked(inner, &storeHooks{
		ListUsers: func(_ storage.Storage, _ context.Context, _ *storage.UserFilter) ([]*models.User, int64, error) {
			return nil, 0, errors.New("simulated users query failure")
		},
	})
}

// failingExpiringSecretsStore wraps inner and fails ListSecrets only
// when called with the ExpiresBefore filter getExpiringSecrets uses, leaving
// the unrelated TotalSecrets ListSecrets call (no ExpiresBefore) untouched.
func failingExpiringSecretsStore(inner storage.Storage) storage.Storage {
	return hooked(inner, &storeHooks{
		ListSecrets: func(next storage.Storage, ctx context.Context, filter *storage.SecretFilter) ([]*models.SecretNode, int64, error) {
			if filter != nil && filter.ExpiresBefore != nil {
				return nil, 0, errors.New("simulated expiring-secrets query failure")
			}
			return next.ListSecrets(ctx, filter)
		},
	})
}

// failingDashboardTotalSecretsStore wraps inner and fails the query the
// TOTAL SECRETS rollup depends on, leaving the dashboard's other sub-checks —
// notably the expiring-secrets ListSecrets call — untouched.
//
// The hook moved with #2780. It used to intercept ListSecrets and key on
// `CreatedBy != nil && ExpiresBefore == nil`, which was the signature of the old
// authorship-based count (`SecretFilter{CreatedBy: &username}`). That count was the
// defect: it reported 0 to a caller who could read five secrets. The rollup now
// goes through CountReadableSecrets -> ListReadableSecrets, which sets no CreatedBy
// at all, so the old hook silently stopped firing and this test would have passed
// vacuously — asserting Degraded on a path where nothing failed.
//
// GetUserRoleScopes is the new hook: ListReadableSecrets calls it (via
// GetReadableScopes) to enumerate the caller's readable scopes and returns an error
// when it fails, which is what must flip Degraded. Nothing else in
// GetDashboardStats calls it — the audit.read gate goes through AuthorizePrincipal
// -> GetUserRoleIDsAt, and the expiring-secrets rollup through ListSecrets — so this
// fails exactly one sub-check, as before.
func failingDashboardTotalSecretsStore(inner storage.Storage) storage.Storage {
	return hooked(inner, &storeHooks{
		GetUserRoleScopes: func(_ storage.Storage, _ context.Context, _ uint) ([]storage.Scope, error) {
			return nil, errors.New("simulated total-secrets query failure")
		},
	})
}

// failingDashboardSharesByOwnerStore wraps inner and fails
// ListSharesByOwner, simulating a DB error on the shared-secrets rollup.
func failingDashboardSharesByOwnerStore(inner storage.Storage) storage.Storage {
	return hooked(inner, &storeHooks{
		ListSharesByOwner: func(_ storage.Storage, _ context.Context, _ uint, _ time.Time) ([]*models.ShareRecord, error) {
			return nil, errors.New("simulated shares-by-owner query failure")
		},
	})
}

// failingDashboardSharesByUserStore wraps inner and fails
// ListSharesByUser, simulating a DB error on the shared-with-me rollup.
func failingDashboardSharesByUserStore(inner storage.Storage) storage.Storage {
	return hooked(inner, &storeHooks{
		ListSharesByUser: func(_ storage.Storage, _ context.Context, _ uint, _ time.Time) ([]*models.ShareRecord, error) {
			return nil, errors.New("simulated shares-by-user query failure")
		},
	})
}

// failingDashboardRecentActivityStore wraps inner and fails only the
// recent-activity GetAuditLogs call (identified by having no StartTime set —
// the deployment-wide audit-count sub-checks below all set StartTime),
// leaving those sub-checks untouched.
func failingDashboardRecentActivityStore(inner storage.Storage) storage.Storage {
	return hooked(inner, &storeHooks{
		GetAuditLogs: func(next storage.Storage, ctx context.Context, filter *storage.AuditFilter) ([]*models.AuditEvent, int64, error) {
			if filter != nil && filter.StartTime == nil {
				return nil, 0, errors.New("simulated recent-activity query failure")
			}
			return next.GetAuditLogs(ctx, filter)
		},
	})
}

// #394: on a real deployment, a failed audit-log/user-count query left every
// deployment-wide dashboard stat at its zero value — byte-identical to
// "queried, genuinely zero" (e.g. FailedAuthAttempts24h=0 reads as a clean
// window even when the query that would report failed logins errored out).
// These tests prove the sub-checks now surface as Degraded instead.
func TestGetDashboardStats_DegradedOnAuditLogsQueryError(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	auditorID := seedUserWithRole(t, st, "auditor1", "system_auditor", storage.Scope{})
	c.storage = failingDashboardAuditStore(st)

	stats, err := c.GetDashboardStats(context.Background(), auditorID, "auditor1", auditorID)
	require.NoError(t, err, "a single failed sub-check must not abort the whole dashboard")

	assert.Zero(t, stats.AuditEvents30d, "the field itself still reads as its safe-default zero value")
	assert.Zero(t, stats.AuditLogins30d)
	assert.Zero(t, stats.AuditSecretReads30d)
	assert.Zero(t, stats.FailedAuthAttempts24h)
	assert.True(t, stats.Degraded, "a failed audit-log query must flip Degraded — the zero values above are UNKNOWN, not verified-clean")
	assert.True(t, containsSubstring(stats.DegradedReasons, "audit_count"), "expected an audit_count entry, got %v", stats.DegradedReasons)
	assert.True(t, containsSubstring(stats.DegradedReasons, "audit_logins"), "expected an audit_logins entry, got %v", stats.DegradedReasons)
	assert.True(t, containsSubstring(stats.DegradedReasons, "audit_secret_reads"), "expected an audit_secret_reads entry, got %v", stats.DegradedReasons)
	assert.Zero(t, stats.RefusedSecretReads24h)
	assert.True(t, containsSubstring(stats.DegradedReasons, "failed_logins_24h"), "expected a failed_logins_24h entry, got %v", stats.DegradedReasons)
	assert.True(t, containsSubstring(stats.DegradedReasons, "refused_secret_reads_24h"), "expected a refused_secret_reads_24h entry, got %v", stats.DegradedReasons)
	assert.Zero(t, stats.FailedSecondFactors24h)
	assert.True(t, containsSubstring(stats.DegradedReasons, "failed_second_factor_24h"), "expected a failed_second_factor_24h entry, got %v", stats.DegradedReasons)
}

// DASH-FAILED-AUTH-LABEL: the dashboard used to count every success=false audit event
// as a "failed auth attempt", so since #3274 a refused secret read inflated the
// brute-force signal. Failed logins and refused secret reads are now counted apart,
// and other failed events (here a failed export) count in neither.
func TestGetDashboardStats_FailedLoginsAndRefusedReadsCountedApart(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	auditorID := seedUserWithRole(t, st, "auditor-split", "system_auditor", storage.Scope{})

	for range 2 {
		c.writeAuditEventFailed(ctx, "auth.login_failed", nil, nil, "192.0.2.1", "bad password")
	}
	for range 3 {
		c.writeAuditEventFailed(ctx, "secret.read", &auditorID, nil, "192.0.2.2", "refused")
	}
	c.writeAuditEventFailed(ctx, "secret.export", &auditorID, nil, "192.0.2.3", "unrelated failure")
	// A successful read and a successful login must count in neither.
	c.writeAuditEvent(ctx, "secret.read", &auditorID, nil, "ok read")
	c.writeAuditEvent(ctx, "auth.login", &auditorID, nil, "ok login")

	stats, err := c.GetDashboardStats(ctx, auditorID, "auditor-split", auditorID)
	require.NoError(t, err)
	assert.False(t, stats.Degraded, "reasons: %v", stats.DegradedReasons)
	assert.Equal(t, int64(2), stats.FailedAuthAttempts24h, "failed logins only")
	assert.Equal(t, int64(3), stats.RefusedSecretReads24h, "refused secret reads only")
}

// DASH-FAILED-SPLIT-1: the three failure figures are separate and never summed. Seeded
// with distinct counts (2 / 3 / 1) so any merge of two buckets shows up as a wrong number.
// "Failed Logins" is auth.login_failed only; "Failed Second Factors" is mfa.failed +
// webauthn.failed (rows written before #3363 carry success=true and must still count);
// mfa.error (a fault, no verdict) counts in none of the three.
func TestGetDashboardStats_FailedLoginsSecondFactorsAndRefusedReadsAreSeparateFigures(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	auditorID := seedUserWithRole(t, st, "auditor-2fa", "system_auditor", storage.Scope{})

	for range 2 {
		c.writeAuditEventFailed(ctx, "auth.login_failed", nil, nil, "192.0.2.1", "bad password")
	}
	c.writeAuditEventFailed(ctx, "mfa.failed", &auditorID, nil, "192.0.2.2", "wrong code")
	// A pre-#3363 row: the same event stored by the success writer.
	c.writeAuditEvent(ctx, "mfa.failed", &auditorID, nil, "wrong code, historical row")
	c.writeAuditEventFailed(ctx, "webauthn.failed", &auditorID, nil, "192.0.2.3", "bad assertion")
	// Counted in neither bucket.
	c.writeAuditEventFailed(ctx, "mfa.error", &auditorID, nil, "192.0.2.4", "storage fault before a verdict")
	c.writeAuditEventFailed(ctx, "secret.read", &auditorID, nil, "192.0.2.5", "refused")
	c.writeAuditEvent(ctx, "auth.login", &auditorID, nil, "ok login")

	stats, err := c.GetDashboardStats(ctx, auditorID, "auditor-2fa", auditorID)
	require.NoError(t, err)
	assert.False(t, stats.Degraded, "reasons: %v", stats.DegradedReasons)
	assert.Equal(t, int64(2), stats.FailedAuthAttempts24h, "auth.login_failed only, no second factors")
	assert.Equal(t, int64(3), stats.FailedSecondFactors24h, "mfa.failed (both rows) + webauthn.failed")
	assert.Equal(t, int64(1), stats.RefusedSecretReads24h, "refused secret reads only")
}

func TestGetDashboardStats_DegradedOnActiveUsersQueryError(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	auditorID := seedUserWithRole(t, st, "auditor2", "system_auditor", storage.Scope{})
	c.storage = failingDashboardStatsStore(st)

	stats, err := c.GetDashboardStats(context.Background(), auditorID, "auditor2", auditorID)
	require.NoError(t, err)

	assert.Zero(t, stats.ActiveUsers, "the field itself still reads as its safe-default zero value")
	assert.True(t, stats.Degraded, "a failed active-users query must flip Degraded")
	assert.True(t, containsSubstring(stats.DegradedReasons, "active_users"), "expected an active_users entry, got %v", stats.DegradedReasons)
}

func TestGetDashboardStats_DegradedOnInactiveUsersQueryError(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	auditorID := seedUserWithRole(t, st, "auditor3", "system_auditor", storage.Scope{})
	c.storage = failingDashboardUsersStore(st)

	stats, err := c.GetDashboardStats(context.Background(), auditorID, "auditor3", auditorID)
	require.NoError(t, err)

	assert.Zero(t, stats.InactiveUsers, "the field itself still reads as its safe-default zero value")
	assert.True(t, stats.Degraded, "a failed inactive-users query must flip Degraded")
	assert.True(t, containsSubstring(stats.DegradedReasons, "inactive_users"), "expected an inactive_users entry, got %v", stats.DegradedReasons)
}

// #394: getExpiringSecrets paged through ListSecrets and silently discarded
// whatever it had accumulated so far on a page-load error — this proves the
// truncation is now surfaced via Degraded even for a baseline caller without
// audit.read (the expiring-secrets rollup is not gated by hasAuditRead).
func TestGetDashboardStats_DegradedOnExpiringSecretsQueryError(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	viewerID := seedUserWithRole(t, st, "viewer1", "system_viewer", storage.Scope{})
	c.storage = failingExpiringSecretsStore(st)

	stats, err := c.GetDashboardStats(context.Background(), viewerID, "viewer1", viewerID)
	require.NoError(t, err)

	assert.Empty(t, stats.ExpiringSecrets, "the field itself still reads as its safe-default empty value")
	assert.True(t, stats.Degraded, "a failed expiring-secrets query must flip Degraded")
	assert.True(t, containsSubstring(stats.DegradedReasons, "expiring_secrets"), "expected an expiring_secrets entry, got %v", stats.DegradedReasons)
	// A baseline caller (no audit.read) must not see the deployment-wide
	// aggregates degrade too — expiring_secrets is the only failure injected.
	assert.False(t, containsSubstring(stats.DegradedReasons, "active_users"))
}

// #485: round-101 regression audit found #394 only wired degrade() into 2 of
// the 6 error paths in GetDashboardStats — ListSecrets (TotalSecrets),
// ListSharesByOwner (SharedSecrets), ListSharesByUser (SecretsSharedWithMe),
// and GetAuditLogs (RecentActivity) all silently swallowed their errors and
// left the corresponding field at its zero/empty "genuinely clean" value. The
// zeroed TotalSecrets is also what gets persisted via SaveStatsSnapshot, so an
// unsurfaced ListSecrets failure here would corrupt the next day's trend
// computation too. These tests prove all 4 sub-checks now surface as Degraded.
func TestGetDashboardStats_DegradedOnTotalSecretsQueryError(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	viewerID := seedUserWithRole(t, st, "viewer2", "system_viewer", storage.Scope{})
	c.storage = failingDashboardTotalSecretsStore(st)

	stats, err := c.GetDashboardStats(context.Background(), viewerID, "viewer2", viewerID)
	require.NoError(t, err, "a single failed sub-check must not abort the whole dashboard")

	assert.Zero(t, stats.TotalSecrets, "the field itself still reads as its safe-default zero value")
	assert.True(t, stats.Degraded, "a failed total-secrets query must flip Degraded — 0 above is UNKNOWN, not verified-clean")
	assert.True(t, containsSubstring(stats.DegradedReasons, "total_secrets"), "expected a total_secrets entry, got %v", stats.DegradedReasons)
}

func TestGetDashboardStats_DegradedOnSharedSecretsQueryError(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	viewerID := seedUserWithRole(t, st, "viewer3", "system_viewer", storage.Scope{})
	c.storage = failingDashboardSharesByOwnerStore(st)

	stats, err := c.GetDashboardStats(context.Background(), viewerID, "viewer3", viewerID)
	require.NoError(t, err)

	assert.Zero(t, stats.SharedSecrets, "the field itself still reads as its safe-default zero value")
	assert.True(t, stats.Degraded, "a failed shares-by-owner query must flip Degraded")
	assert.True(t, containsSubstring(stats.DegradedReasons, "shared_secrets"), "expected a shared_secrets entry, got %v", stats.DegradedReasons)
}

func TestGetDashboardStats_DegradedOnSharedWithMeQueryError(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	viewerID := seedUserWithRole(t, st, "viewer4", "system_viewer", storage.Scope{})
	c.storage = failingDashboardSharesByUserStore(st)

	stats, err := c.GetDashboardStats(context.Background(), viewerID, "viewer4", viewerID)
	require.NoError(t, err)

	assert.Zero(t, stats.SecretsSharedWithMe, "the field itself still reads as its safe-default zero value")
	assert.True(t, stats.Degraded, "a failed shares-by-user query must flip Degraded")
	assert.True(t, containsSubstring(stats.DegradedReasons, "shared_with_me"), "expected a shared_with_me entry, got %v", stats.DegradedReasons)
}

func TestGetDashboardStats_DegradedOnRecentActivityQueryError(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	viewerID := seedUserWithRole(t, st, "viewer5", "system_viewer", storage.Scope{})
	c.storage = failingDashboardRecentActivityStore(st)

	stats, err := c.GetDashboardStats(context.Background(), viewerID, "viewer5", viewerID)
	require.NoError(t, err)

	assert.Empty(t, stats.RecentActivity, "the field itself still reads as its safe-default empty value")
	assert.True(t, stats.Degraded, "a failed recent-activity query must flip Degraded")
	assert.True(t, containsSubstring(stats.DegradedReasons, "recent_activity"), "expected a recent_activity entry, got %v", stats.DegradedReasons)
}

// TotalSecrets must mirror ActiveUsers/AuditEvents30d: a caller with audit.read
// sees the deployment-wide secret count, not just secrets they personally
// created. Before this fix, GetDashboardStats always filtered ListSecrets by
// CreatedBy regardless of the caller's RBAC role, so even a system_admin's
// dashboard undercounted every secret another user had created.
func TestGetDashboardStats_TotalSecretsIsDeploymentWideForAuditReadCaller(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	auditorID := seedUserWithRole(t, st, "auditor5", "system_auditor", storage.Scope{})

	project, err := c.CreateProject(ctx, "other-project", "")
	require.NoError(t, err)
	envs, err := st.ListEnvironmentsByProject(ctx, project.ID)
	require.NoError(t, err)
	require.NotEmpty(t, envs)

	// Created by a DIFFERENT user than the caller.
	_, err = st.CreateSecret(ctx, &models.SecretNode{
		ProjectID: project.ID, EnvironmentID: envs[0].ID,
		Name: "OTHER_USERS_SECRET", CreatedBy: "someone-else",
	})
	require.NoError(t, err)

	stats, err := c.GetDashboardStats(ctx, auditorID, "auditor5", auditorID)
	require.NoError(t, err)

	assert.EqualValues(t, 1, stats.TotalSecrets, "auditor5 personally created 0 secrets, but with audit.read the count must be deployment-wide")
}

// TestGetDashboardStats_TotalSecretsIsScopedForBaselineCaller replaces
// TestGetDashboardStats_TotalSecretsIsPersonalForBaselineCaller.
//
// #2780: a baseline caller's TOTAL SECRETS used to be the count of secrets they had
// AUTHORED, and the old test asserted 0 for a user who had created none. It passed —
// but a count of "secrets they can read" would have passed identically, because that
// user could read nothing either, so the assertion never actually distinguished the
// two definitions. Authorship was the wrong one: it reported 0 to a project member
// reading five secrets, which is what WEB-SWEEP-1 found in the UI.
//
// The property now asserted is the one the tile claims, in BOTH directions, which is
// what makes it discriminating: a baseline caller who can read nothing sees 0, and a
// caller granted read access to the project sees that project's secret WITHOUT having
// authored it. Privacy is preserved by the second half — they see their project's
// count, never the deployment-wide one, which stays audit.read-only (asserted by the
// sibling test above).
func TestGetDashboardStats_TotalSecretsIsScopedForBaselineCaller(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	viewerID := seedUserWithRole(t, st, "viewer6", "system_viewer", storage.Scope{})

	project, err := c.CreateProject(ctx, "other-project2", "")
	require.NoError(t, err)
	envs, err := st.ListEnvironmentsByProject(ctx, project.ID)
	require.NoError(t, err)
	require.NotEmpty(t, envs)

	_, err = st.CreateSecret(ctx, &models.SecretNode{
		ProjectID: project.ID, EnvironmentID: envs[0].ID,
		Name: "OTHER_USERS_SECRET", CreatedBy: "someone-else",
	})
	require.NoError(t, err)

	stats, err := c.GetDashboardStats(ctx, viewerID, "viewer6", viewerID)
	require.NoError(t, err)
	assert.Zero(t, stats.TotalSecrets,
		"the install baseline grants no read access to this project, so this caller can read nothing and is told 0")

	// A project reader, still the author of nothing. This is the half the old
	// assertion could not have caught.
	readerID := seedUserWithRole(t, st, "viewer6b", "project_viewer", storage.Scope{ProjectID: project.ID})
	readerStats, err := c.GetDashboardStats(ctx, readerID, "viewer6b", readerID)
	require.NoError(t, err)
	assert.EqualValues(t, 1, readerStats.TotalSecrets,
		"a project member who authored nothing must still be told they can read this project's one secret — "+
			"reporting 0 here is #2780, and the UI renders it as \"Create your first secret to get started\"")
	assert.False(t, readerStats.Degraded, "and that 1 must be a counted 1, not an unknown")
}

// A fully-healthy storage must never report Degraded.
func TestGetDashboardStats_NotDegradedOnSuccess(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	auditorID := seedUserWithRole(t, st, "auditor4", "system_auditor", storage.Scope{})

	stats, err := c.GetDashboardStats(context.Background(), auditorID, "auditor4", auditorID)
	require.NoError(t, err)

	assert.False(t, stats.Degraded)
	assert.Empty(t, stats.DegradedReasons)
}
