// store_s3_test.go — coverage sweep for uncovered local_* functions in the store package.
// Focus: local_auth (setup tokens, session cleanup, PATs), local_access_activity,
// local_access_review_campaigns, local_audit (secret access logs, RBAC, anomaly,
// checkpoint), local_dynamic, local_break_glass (get/list/revoke), local_legal_hold,
// local_login_attempts, classification_count.
package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// newStoreS3 returns a LocalStorage over a unique in-memory SQLite database,
// auto-migrated for a given set of GORM models.
func newStoreS3(t *testing.T, name string, migrateModels ...any) *LocalStorage {
	t.Helper()
	db := sqlitetest.OpenWithDialector(t, "stores3_", sqlite.Open, &gorm.Config{})
	if len(migrateModels) > 0 {
		require.NoError(t, db.AutoMigrate(migrateModels...))
	}
	return NewLocalStorage(db)
}

// ---------------------------------------------------------------------------
// local_auth — Setup Tokens (ADR-028)
// ---------------------------------------------------------------------------

func newSetupTokenStore(t *testing.T) *LocalStorage {
	t.Helper()
	return newStoreS3(t, "setup_tokens_"+t.Name(), &models.SetupToken{})
}

func TestSetupToken_Lifecycle(t *testing.T) {
	ctx := context.Background()
	ls := newSetupTokenStore(t)

	exp := time.Now().Add(time.Hour)
	tok, err := ls.CreateSetupToken(ctx, &models.SetupToken{
		TokenHash:    "h-abc123",
		Purpose:      "password_reset_link",
		SubjectEmail: "alice@example.com",
		State:        "active",
		ExpiresAt:    exp,
	})
	require.NoError(t, err)
	assert.NotZero(t, tok.ID)

	// GetSetupTokenByHash returns the row.
	got, err := ls.GetSetupTokenByHash(ctx, "h-abc123")
	require.NoError(t, err)
	assert.Equal(t, tok.ID, got.ID)

	// Unknown hash → error.
	_, err = ls.GetSetupTokenByHash(ctx, "nope")
	require.Error(t, err)
}

func TestSetupToken_SupersedeActiveTokens(t *testing.T) {
	ctx := context.Background()
	ls := newSetupTokenStore(t)

	exp := time.Now().Add(time.Hour)
	for i, hash := range []string{"h1", "h2"} {
		_, err := ls.CreateSetupToken(ctx, &models.SetupToken{
			TokenHash:    hash,
			Purpose:      "invitation_accept",
			SubjectEmail: "bob@example.com",
			State:        "active",
			ExpiresAt:    exp,
			CreatedBy:    uint(i + 1),
		})
		require.NoError(t, err)
	}

	// Supersede all active tokens for this (purpose, email) — unscoped (projectID nil),
	// the behavior account_setup/password_reset_link/global invites still rely on.
	require.NoError(t, ls.SupersedeActiveSetupTokens(ctx, "invitation_accept", "bob@example.com", nil))

	// Both tokens should now be superseded.
	for _, hash := range []string{"h1", "h2"} {
		got, err := ls.GetSetupTokenByHash(ctx, hash)
		require.NoError(t, err)
		assert.Equal(t, "superseded", got.State)
	}
}

// TestSetupToken_SupersedeActiveTokens_ProjectScoped is the CORE-INVITATIONS-003
// regression test: an admin issuing a project-scoped invitation_accept setup token
// for one project must NOT silently invalidate a different project's still-pending
// invite to the same email address, while a genuine re-invite/resend WITHIN the same
// project must still supersede the prior link (the SMTP-abuse throttle's underlying
// invariant — same-project reissue kills the old link — is preserved).
func TestSetupToken_SupersedeActiveTokens_ProjectScoped(t *testing.T) {
	ctx := context.Background()
	ls := newStoreS3(t, "setup_tokens_proj_"+t.Name(), &models.SetupToken{}, &models.ProjectInvitation{})
	exp := time.Now().Add(time.Hour)
	const email = "victim@example.com"

	// Project A's pending invitation + its accept-link token.
	invA, err := ls.CreateProjectInvitation(ctx, &models.ProjectInvitation{
		ProjectID: 1, Email: email, Role: "project_developer", State: "pending",
	})
	require.NoError(t, err)
	_, err = ls.CreateSetupToken(ctx, &models.SetupToken{
		TokenHash: "tok-a-1", Purpose: "invitation_accept", SubjectEmail: email,
		InvitationID: &invA.ID, State: "active", ExpiresAt: exp,
	})
	require.NoError(t, err)

	// Project B's admin — wholly unrelated to project A — invites the SAME email to
	// project B. Pre-fix, this unconditionally superseded project A's still-pending
	// link as an unintended side effect; the supersede call is now scoped to project B.
	invB, err := ls.CreateProjectInvitation(ctx, &models.ProjectInvitation{
		ProjectID: 2, Email: email, Role: "project_viewer", State: "pending",
	})
	require.NoError(t, err)
	projectB := uint(2)
	require.NoError(t, ls.SupersedeActiveSetupTokens(ctx, "invitation_accept", email, &projectB))
	_, err = ls.CreateSetupToken(ctx, &models.SetupToken{
		TokenHash: "tok-b-1", Purpose: "invitation_accept", SubjectEmail: email,
		InvitationID: &invB.ID, State: "active", ExpiresAt: exp,
	})
	require.NoError(t, err)

	// Both tokens remain active: project B's invite must not have touched project A's.
	reloadedA, err := ls.GetSetupTokenByHash(ctx, "tok-a-1")
	require.NoError(t, err)
	assert.Equal(t, "active", reloadedA.State, "an unrelated project's invite must not supersede this project's pending link")
	reloadedB, err := ls.GetSetupTokenByHash(ctx, "tok-b-1")
	require.NoError(t, err)
	assert.Equal(t, "active", reloadedB.State)

	// A THIRD invite to the SAME project (B) + SAME email — e.g. a resend — must still
	// supersede the prior link for that project: the per-project throttle invariant
	// holds even though the cross-project one no longer fires.
	require.NoError(t, ls.SupersedeActiveSetupTokens(ctx, "invitation_accept", email, &projectB))
	_, err = ls.CreateSetupToken(ctx, &models.SetupToken{
		TokenHash: "tok-b-2", Purpose: "invitation_accept", SubjectEmail: email,
		InvitationID: &invB.ID, State: "active", ExpiresAt: exp,
	})
	require.NoError(t, err)

	reloadedB1, err := ls.GetSetupTokenByHash(ctx, "tok-b-1")
	require.NoError(t, err)
	assert.Equal(t, "superseded", reloadedB1.State, "a same-project reissue must still supersede the project's own prior link")
	reloadedB2, err := ls.GetSetupTokenByHash(ctx, "tok-b-2")
	require.NoError(t, err)
	assert.Equal(t, "active", reloadedB2.State)
	// Project A's token is still untouched by project B's second (same-project) reissue.
	reloadedAFinal, err := ls.GetSetupTokenByHash(ctx, "tok-a-1")
	require.NoError(t, err)
	assert.Equal(t, "active", reloadedAFinal.State)
}

func TestSetupToken_MarkConsumed(t *testing.T) {
	ctx := context.Background()
	ls := newSetupTokenStore(t)

	exp := time.Now().Add(time.Hour)
	tok, err := ls.CreateSetupToken(ctx, &models.SetupToken{
		TokenHash:    "consume-me",
		Purpose:      "account_setup",
		SubjectEmail: "carol@example.com",
		State:        "active",
		ExpiresAt:    exp,
	})
	require.NoError(t, err)

	consumed, err := ls.MarkSetupTokenConsumed(ctx, tok.ID, time.Now())
	require.NoError(t, err)
	assert.True(t, consumed, "first consumption must succeed")

	// Second consumption (concurrent replay) is rejected.
	consumed2, err := ls.MarkSetupTokenConsumed(ctx, tok.ID, time.Now())
	require.NoError(t, err)
	assert.False(t, consumed2, "second consumption must fail (already consumed)")
}

func TestSetupToken_MarkExpired(t *testing.T) {
	ctx := context.Background()
	ls := newSetupTokenStore(t)

	exp := time.Now().Add(time.Hour)
	tok, err := ls.CreateSetupToken(ctx, &models.SetupToken{
		TokenHash:    "expire-me",
		Purpose:      "password_reset_link",
		SubjectEmail: "dave@example.com",
		State:        "active",
		ExpiresAt:    exp,
	})
	require.NoError(t, err)

	require.NoError(t, ls.MarkSetupTokenExpired(ctx, tok.ID))

	got, err := ls.GetSetupTokenByHash(ctx, "expire-me")
	require.NoError(t, err)
	assert.Equal(t, "expired", got.State)
}

func TestSetupToken_CountSince(t *testing.T) {
	ctx := context.Background()

	// Create 3 tokens on the same store and count them. CreatedAt is set
	// explicitly, mirroring every real caller (internal/core/setup_token.go's
	// `now := c.now()`): SetupToken.BeforeSave only gets a chance to
	// UTC-normalize a non-zero value — GORM's own blank-CreatedAt
	// auto-population runs AFTER BeforeSave and would silently overwrite a
	// hook-normalized zero value with local time.Now(), producing a row no
	// real caller can produce (#1619).
	ls2 := newStoreS3(t, "setup_token_count", &models.SetupToken{})
	since := time.Now().Add(-time.Minute)
	for _, hash := range []string{"x1", "x2", "x3"} {
		_, err := ls2.CreateSetupToken(ctx, &models.SetupToken{
			TokenHash:    hash,
			Purpose:      "invitation_accept",
			SubjectEmail: "frank@example.com",
			State:        "active",
			ExpiresAt:    time.Now().Add(time.Hour),
			CreatedAt:    time.Now(),
		})
		require.NoError(t, err)
	}

	n, err := ls2.CountSetupTokensSince(ctx, "invitation_accept", "frank@example.com", since)
	require.NoError(t, err)
	assert.Equal(t, int64(3), n)

	// Count for a different purpose returns 0.
	n2, err := ls2.CountSetupTokensSince(ctx, "password_reset_link", "frank@example.com", since)
	require.NoError(t, err)
	assert.Equal(t, int64(0), n2)
}

// ---------------------------------------------------------------------------
// local_auth — Session operations not yet covered
// ---------------------------------------------------------------------------

func TestDeleteSession(t *testing.T) {
	ctx := context.Background()
	ls := newStoreS3(t, "delete_session", &models.Session{})
	// #2701: a session/PAT insert now re-reads its owning user and rolls back if
	// it is not live, so this fixture needs the owners it references to exist.
	seedCredentialOwners(t, ls.db)
	future := time.Now().Add(time.Hour)

	s, err := ls.CreateSession(ctx, &models.Session{UserID: 1, SessionToken: "tok-delete", ExpiresAt: &future})
	require.NoError(t, err)

	require.NoError(t, ls.DeleteSession(ctx, s.ID))

	_, err = ls.GetSessionByID(ctx, s.ID)
	require.Error(t, err, "deleted session must not be found")
}

func TestCleanupExpiredSessions(t *testing.T) {
	ctx := context.Background()
	ls := newStoreS3(t, "cleanup_sessions", &models.Session{})
	// #2701: a session/PAT insert now re-reads its owning user and rolls back if
	// it is not live, so this fixture needs the owners it references to exist.
	seedCredentialOwners(t, ls.db)

	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)

	_, err := ls.CreateSession(ctx, &models.Session{UserID: 1, SessionToken: "live", ExpiresAt: &future})
	require.NoError(t, err)
	_, err = ls.CreateSession(ctx, &models.Session{UserID: 2, SessionToken: "expired", ExpiresAt: &past})
	require.NoError(t, err)

	require.NoError(t, ls.CleanupExpiredSessions(ctx))

	live, err := ls.ListSessionsByUser(ctx, 1)
	require.NoError(t, err)
	assert.Len(t, live, 1, "live session should remain")

	// Expired user's sessions should be gone (hard-deleted).
	var count int64
	ls.db.Model(&models.Session{}).Where("user_id = ?", 2).Count(&count)
	assert.Zero(t, count, "expired sessions should be hard-deleted")
}

func TestListSessionTokenHashesForUser(t *testing.T) {
	ctx := context.Background()
	ls := newStoreS3(t, "session_hashes_user", &models.Session{})
	// #2701: a session/PAT insert now re-reads its owning user and rolls back if
	// it is not live, so this fixture needs the owners it references to exist.
	seedCredentialOwners(t, ls.db)
	future := time.Now().Add(time.Hour)
	admin := uint(5)

	// User's own session.
	_, err := ls.CreateSession(ctx, &models.Session{UserID: 10, SessionToken: "own-tok", ExpiresAt: &future})
	require.NoError(t, err)
	// Impersonation session (started by admin=5 acting as user=10).
	_, err = ls.CreateSession(ctx, &models.Session{UserID: 10, SessionToken: "imp-tok", ImpersonatedBy: &admin, ExpiresAt: &future})
	require.NoError(t, err)
	// Unrelated session for another user.
	_, err = ls.CreateSession(ctx, &models.Session{UserID: 20, SessionToken: "other-tok", ExpiresAt: &future})
	require.NoError(t, err)

	hashes, err := ls.ListSessionTokenHashesForUser(ctx, 10)
	require.NoError(t, err)
	assert.Len(t, hashes, 2, "must include both own and impersonated session hashes")
}

func TestListActivePersonalAccessTokens(t *testing.T) {
	ctx := context.Background()
	ls := newStoreS3(t, "active_pats", &models.PersonalAccessToken{})
	// #2701: a session/PAT insert now re-reads its owning user and rolls back if
	// it is not live, so this fixture needs the owners it references to exist.
	seedCredentialOwners(t, ls.db)

	_, err := ls.CreatePersonalAccessToken(ctx, &models.PersonalAccessToken{
		UserID: 1, Name: "active", TokenHash: "h-active", TokenPrefix: "kx_pat_a",
	})
	require.NoError(t, err)
	tok2, err := ls.CreatePersonalAccessToken(ctx, &models.PersonalAccessToken{
		UserID: 2, Name: "revoked", TokenHash: "h-revoked", TokenPrefix: "kx_pat_b",
	})
	require.NoError(t, err)
	require.NoError(t, ls.RevokePersonalAccessToken(ctx, tok2.ID))

	active, err := ls.ListActivePersonalAccessTokens(ctx)
	require.NoError(t, err)
	assert.Len(t, active, 1)
	assert.Equal(t, "h-active", active[0].TokenHash)
}

func TestRevokeAllPersonalAccessTokensForUser(t *testing.T) {
	ctx := context.Background()
	ls := newStoreS3(t, "revoke_all_pats", &models.PersonalAccessToken{})
	// #2701: a session/PAT insert now re-reads its owning user and rolls back if
	// it is not live, so this fixture needs the owners it references to exist.
	seedCredentialOwners(t, ls.db)

	for i, hash := range []string{"h1", "h2", "h3"} {
		_, err := ls.CreatePersonalAccessToken(ctx, &models.PersonalAccessToken{
			UserID: 7, Name: fmt.Sprintf("tok%d", i), TokenHash: hash,
			TokenPrefix: fmt.Sprintf("kx_pat_%d", i),
		})
		require.NoError(t, err)
	}

	hashes, err := ls.RevokeAllPersonalAccessTokensForUser(ctx, 7)
	require.NoError(t, err)
	assert.Len(t, hashes, 3)

	// All are now revoked.
	active, err := ls.ListActivePersonalAccessTokens(ctx)
	require.NoError(t, err)
	assert.Empty(t, active)

	// Calling again on already-revoked returns empty slice (no-op).
	hashes2, err := ls.RevokeAllPersonalAccessTokensForUser(ctx, 7)
	require.NoError(t, err)
	assert.Nil(t, hashes2)
}

func TestTouchPersonalAccessToken(t *testing.T) {
	ctx := context.Background()
	ls := newStoreS3(t, "touch_pat", &models.PersonalAccessToken{})
	// #2701: a session/PAT insert now re-reads its owning user and rolls back if
	// it is not live, so this fixture needs the owners it references to exist.
	seedCredentialOwners(t, ls.db)

	tok, err := ls.CreatePersonalAccessToken(ctx, &models.PersonalAccessToken{
		UserID: 1, Name: "ci", TokenHash: "h-touch", TokenPrefix: "kx_pat_touch",
	})
	require.NoError(t, err)

	t1 := time.Now().UTC().Truncate(time.Second)
	require.NoError(t, ls.TouchPersonalAccessToken(ctx, tok.ID, t1, 30*time.Second))
	got, err := ls.GetPersonalAccessTokenByID(ctx, tok.ID)
	require.NoError(t, err)
	require.NotNil(t, got.LastUsedAt)
	assert.WithinDuration(t, t1, *got.LastUsedAt, time.Second)

	// Touch within staleness window is a no-op.
	t2 := t1.Add(5 * time.Second)
	require.NoError(t, ls.TouchPersonalAccessToken(ctx, tok.ID, t2, 30*time.Second))
	got2, _ := ls.GetPersonalAccessTokenByID(ctx, tok.ID)
	assert.WithinDuration(t, t1, *got2.LastUsedAt, time.Second, "within window → no write")

	// Touch past the staleness window writes through.
	t3 := t1.Add(time.Minute)
	require.NoError(t, ls.TouchPersonalAccessToken(ctx, tok.ID, t3, 30*time.Second))
	got3, _ := ls.GetPersonalAccessTokenByID(ctx, tok.ID)
	assert.WithinDuration(t, t3, *got3.LastUsedAt, time.Second, "past window → write")
}

// ---------------------------------------------------------------------------
// local_access_activity
// ---------------------------------------------------------------------------

func newAccessActivityStore(t *testing.T) *LocalStorage {
	t.Helper()
	ls := newStoreS3(t, "access_activity_"+t.Name(), &models.AuditEvent{})
	return ls
}

func insertAuditEvent(t *testing.T, ls *LocalStorage, userID uint, projectID uint, eventType string, at time.Time) {
	t.Helper()
	uid := userID
	pid := projectID
	require.NoError(t, ls.db.Create(&models.AuditEvent{
		EventType: eventType,
		UserID:    &uid,
		ProjectID: &pid,
		EventTime: at,
		Success:   boolPtr(true),
	}).Error)
}

func TestLastUserSecretActivity(t *testing.T) {
	ctx := context.Background()
	ls := newAccessActivityStore(t)

	now := time.Now()
	insertAuditEvent(t, ls, 1, 10, "secret.read", now.Add(-time.Hour))
	insertAuditEvent(t, ls, 1, 10, "secret.created", now.Add(-30*time.Minute))
	insertAuditEvent(t, ls, 2, 10, "secret.updated", now.Add(-2*time.Hour))
	// Event for a different project — should not appear.
	insertAuditEvent(t, ls, 1, 99, "secret.read", now)

	result, err := ls.LastUserSecretActivity(ctx, 10, time.Time{})
	require.NoError(t, err)
	assert.Contains(t, result, uint(1))
	assert.Contains(t, result, uint(2))
	// User 1's most recent is "created" at -30m, not "read" at -1h.
	assert.True(t, result[1].After(result[2]))
}

func TestLastUserRoleManagementActivity(t *testing.T) {
	ctx := context.Background()
	ls := newAccessActivityStore(t)

	now := time.Now()
	insertAuditEvent(t, ls, 3, 20, "role.assigned", now.Add(-time.Hour))
	insertAuditEvent(t, ls, 3, 20, "role.removed", now.Add(-30*time.Minute))
	// Non-role event — must not appear.
	insertAuditEvent(t, ls, 3, 20, "secret.read", now)

	result, err := ls.LastUserRoleManagementActivity(ctx, 20, time.Time{})
	require.NoError(t, err)
	require.Contains(t, result, uint(3))
	// Most recent role event was "removed" at -30m.
	assert.True(t, result[3].After(now.Add(-time.Hour)))
}

func TestLastUserSecretDeletionActivity(t *testing.T) {
	ctx := context.Background()
	ls := newAccessActivityStore(t)

	now := time.Now()
	insertAuditEvent(t, ls, 4, 30, "secret.deleted", now.Add(-time.Hour))
	insertAuditEvent(t, ls, 5, 30, "secret.read", now)

	result, err := ls.LastUserSecretDeletionActivity(ctx, 30, time.Time{})
	require.NoError(t, err)
	assert.Contains(t, result, uint(4), "user who deleted must appear")
	assert.NotContains(t, result, uint(5), "user who only read must not appear")
}

func TestLastUserSecretReadActivity(t *testing.T) {
	ctx := context.Background()
	ls := newAccessActivityStore(t)

	now := time.Now()
	insertAuditEvent(t, ls, 6, 40, "secret.read", now.Add(-time.Hour))
	insertAuditEvent(t, ls, 6, 40, "secret.created", now) // write, not read

	result, err := ls.LastUserSecretReadActivity(ctx, 40, time.Time{})
	require.NoError(t, err)
	require.Contains(t, result, uint(6))
	// Most recent read event is -1h, not now.
	assert.WithinDuration(t, now.Add(-time.Hour), result[6], 2*time.Second)
}

func TestLastUserSecretWriteActivity(t *testing.T) {
	ctx := context.Background()
	ls := newAccessActivityStore(t)

	now := time.Now()
	insertAuditEvent(t, ls, 7, 50, "secret.read", now.Add(-2*time.Hour)) // read, not write
	insertAuditEvent(t, ls, 7, 50, "secret.updated", now.Add(-time.Hour))
	insertAuditEvent(t, ls, 7, 50, "secret.rotated", now)

	result, err := ls.LastUserSecretWriteActivity(ctx, 50, time.Time{})
	require.NoError(t, err)
	require.Contains(t, result, uint(7))
	// Most recent write is "rotated" at now.
	assert.WithinDuration(t, now, result[7], 2*time.Second)
}

// ---------------------------------------------------------------------------
// local_access_review_campaigns
// ---------------------------------------------------------------------------

func newCampaignStore(t *testing.T) *LocalStorage {
	t.Helper()
	return newStoreS3(t, "campaigns_"+t.Name(), &models.AccessReviewCampaign{}, &models.AccessReviewItem{})
}

func TestAccessReviewCampaign_CRUD(t *testing.T) {
	ctx := context.Background()
	ls := newCampaignStore(t)

	// Create.
	c, err := ls.CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID: 1, Name: "Q4 2026", State: "open", CreatedBy: 99,
	})
	require.NoError(t, err)
	assert.NotZero(t, c.ID)

	// Get.
	got, err := ls.GetAccessReviewCampaign(ctx, c.ID)
	require.NoError(t, err)
	assert.Equal(t, "Q4 2026", got.Name)

	// Get — not found.
	_, err = ls.GetAccessReviewCampaign(ctx, 999)
	require.Error(t, err)

	// List.
	list, err := ls.ListAccessReviewCampaigns(ctx, 1)
	require.NoError(t, err)
	assert.Len(t, list, 1)

	// List empty project.
	empty, err := ls.ListAccessReviewCampaigns(ctx, 999)
	require.NoError(t, err)
	assert.Empty(t, empty)
}

func TestGetOpenAccessReviewCampaign(t *testing.T) {
	ctx := context.Background()
	ls := newCampaignStore(t)

	// No open campaign → nil.
	open, err := ls.GetOpenAccessReviewCampaign(ctx, 1)
	require.NoError(t, err)
	assert.Nil(t, open)

	// Create an open campaign.
	c, err := ls.CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID: 1, Name: "Open Q4", State: "open", CreatedBy: 1,
	})
	require.NoError(t, err)

	// Returns the open campaign.
	open, err = ls.GetOpenAccessReviewCampaign(ctx, 1)
	require.NoError(t, err)
	require.NotNil(t, open)
	assert.Equal(t, c.ID, open.ID)

	// Create a closed campaign for the same project.
	_, err = ls.CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID: 1, Name: "Closed Q3", State: "closed", CreatedBy: 1,
	})
	require.NoError(t, err)

	// Still only the open one is returned.
	open2, err := ls.GetOpenAccessReviewCampaign(ctx, 1)
	require.NoError(t, err)
	require.NotNil(t, open2)
	assert.Equal(t, c.ID, open2.ID)
}

func TestGetLatestClosedAccessReviewCampaign(t *testing.T) {
	ctx := context.Background()
	ls := newCampaignStore(t)

	// No closed campaign → nil.
	latest, err := ls.GetLatestClosedAccessReviewCampaign(ctx, 2)
	require.NoError(t, err)
	assert.Nil(t, latest)

	// Create two closed campaigns.
	c1, err := ls.CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID: 2, Name: "Closed Q1", State: "closed", CreatedBy: 1,
	})
	require.NoError(t, err)
	c2, err := ls.CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID: 2, Name: "Closed Q2", State: "closed", CreatedBy: 1,
	})
	require.NoError(t, err)
	_ = c1

	// Most recently created is returned.
	latest, err = ls.GetLatestClosedAccessReviewCampaign(ctx, 2)
	require.NoError(t, err)
	require.NotNil(t, latest)
	assert.Equal(t, c2.ID, latest.ID)
}

func TestAccessReviewItems_CRUD(t *testing.T) {
	ctx := context.Background()
	ls := newCampaignStore(t)

	// Create campaign.
	c, err := ls.CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID: 3, Name: "Items Test", State: "open", CreatedBy: 1,
	})
	require.NoError(t, err)

	// CreateAccessReviewItems — empty slice is a no-op.
	require.NoError(t, ls.CreateAccessReviewItems(ctx, nil))
	require.NoError(t, ls.CreateAccessReviewItems(ctx, []*models.AccessReviewItem{}))

	// Create actual items.
	items := []*models.AccessReviewItem{
		{CampaignID: c.ID, PrincipalType: "user", PrincipalID: 10, Decision: "pending", AccessLevel: "read"},
		{CampaignID: c.ID, PrincipalType: "user", PrincipalID: 11, Decision: "pending", AccessLevel: "write"},
	}
	require.NoError(t, ls.CreateAccessReviewItems(ctx, items))

	// List.
	listed, err := ls.ListAccessReviewItems(ctx, c.ID)
	require.NoError(t, err)
	assert.Len(t, listed, 2)

	// Count pending.
	n, err := ls.CountPendingAccessReviewItems(ctx, c.ID)
	require.NoError(t, err)
	assert.Equal(t, 2, n)

	// Get one item.
	got, err := ls.GetAccessReviewItem(ctx, items[0].ID)
	require.NoError(t, err)
	assert.Equal(t, uint(10), got.PrincipalID)

	// Get — not found.
	_, err = ls.GetAccessReviewItem(ctx, 99999)
	require.Error(t, err)

	// UpdateAccessReviewItem (conditional — must be pending+campaign open).
	items[0].Decision = "attested"
	items[0].DecidedBy = 99
	won, err := ls.UpdateAccessReviewItem(ctx, items[0])
	require.NoError(t, err)
	assert.True(t, won)

	// Re-deciding already-decided item fails (decision is no longer "pending").
	items[0].Decision = "revoked"
	won2, err := ls.UpdateAccessReviewItem(ctx, items[0])
	require.NoError(t, err)
	assert.False(t, won2, "cannot re-decide a non-pending item")

	// Count pending is now 1 (only the second item is still pending).
	n2, err := ls.CountPendingAccessReviewItems(ctx, c.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, n2)
}

func TestUpdateAccessReviewCampaign_ConditionalUpdate(t *testing.T) {
	ctx := context.Background()
	ls := newCampaignStore(t)

	c, err := ls.CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID: 4, Name: "Close Me", State: "open", CreatedBy: 1,
	})
	require.NoError(t, err)

	// Close the campaign.
	c.State = "closed"
	won, err := ls.UpdateAccessReviewCampaign(ctx, c)
	require.NoError(t, err)
	assert.True(t, won)

	// Trying to close again (state is no longer "open") must fail.
	won2, err := ls.UpdateAccessReviewCampaign(ctx, c)
	require.NoError(t, err)
	assert.False(t, won2)
}

// ---------------------------------------------------------------------------
// local_audit — uncovered paths
// ---------------------------------------------------------------------------

func newAuditStore(t *testing.T) *LocalStorage {
	t.Helper()
	return newStoreS3(t, "audit_"+t.Name(),
		&models.AuditEvent{}, &models.SecretAccessLog{}, &models.AnomalyAlert{})
}

func TestCreateSecretAccessLog(t *testing.T) {
	ctx := context.Background()
	ls := newAuditStore(t)

	now := time.Now()
	err := ls.CreateSecretAccessLog(ctx, &models.SecretAccessLog{
		SecretNodeID: 1, AccessedBy: "alice", Action: "read", IPAddress: "10.0.0.1", AccessTime: now,
	})
	require.NoError(t, err)

	logs, err := ls.ListSecretAccessLogs(ctx, 1, now.Add(-time.Hour))
	require.NoError(t, err)
	require.Len(t, logs, 1)
	assert.Equal(t, "alice", logs[0].AccessedBy)
}

func TestCountUnusedSecretsByProject(t *testing.T) {
	ctx := context.Background()
	ls := newAuditStore(t)
	// Also need secret_nodes table.
	require.NoError(t, ls.db.AutoMigrate(&models.SecretNode{}))

	// Create two projects with secrets.
	now := time.Now()

	// Project 1: 2 secrets, neither read.
	require.NoError(t, ls.db.Create(&models.SecretNode{ProjectID: 1, EnvironmentID: 1, Name: "s1", IsSecret: true}).Error)
	require.NoError(t, ls.db.Create(&models.SecretNode{ProjectID: 1, EnvironmentID: 1, Name: "s2", IsSecret: true}).Error)

	// Project 2: 1 secret, recently read.
	sn := models.SecretNode{ProjectID: 2, EnvironmentID: 2, Name: "s3", IsSecret: true}
	require.NoError(t, ls.db.Create(&sn).Error)
	require.NoError(t, ls.CreateSecretAccessLog(ctx, &models.SecretAccessLog{
		SecretNodeID: sn.ID, AccessedBy: "bob", Action: "read", IPAddress: "1.2.3.4", AccessTime: now,
	}))

	// Empty projectIDs → empty map.
	empty, err := ls.CountUnusedSecretsByProject(ctx, nil, now.Add(-30*24*time.Hour))
	require.NoError(t, err)
	assert.Empty(t, empty)

	counts, err := ls.CountUnusedSecretsByProject(ctx, []uint{1, 2}, now.Add(-24*time.Hour))
	require.NoError(t, err)
	// Project 1 has 2 unused secrets.
	assert.Equal(t, 2, counts[1])
	// Project 2's secret was read recently → not unused.
	assert.Equal(t, 0, counts[2])
}

func TestListUnalertedAnomalyAlerts(t *testing.T) {
	ctx := context.Background()
	ls := newStoreS3(t, "unalerted_alerts", &models.AnomalyAlert{})

	now := time.Now().UTC()
	require.NoError(t, ls.CreateAnomalyAlert(ctx, &models.AnomalyAlert{
		SecretNodeID: 1, AlertType: "new_ip", AccessedBy: "alice", IPAddress: "10.0.0.1", DetectedAt: now,
	}))

	rows, err := ls.ListUnalertedAnomalyAlerts(ctx)
	require.NoError(t, err)
	assert.Len(t, rows, 1)
	assert.False(t, rows[0].Alerted)
}

func TestMarkAnomalyAlertAlerted(t *testing.T) {
	ctx := context.Background()
	ls := newStoreS3(t, "mark_alerted", &models.AnomalyAlert{})

	now := time.Now().UTC()
	require.NoError(t, ls.CreateAnomalyAlert(ctx, &models.AnomalyAlert{
		SecretNodeID: 2, AlertType: "off_hours", AccessedBy: "bob", IPAddress: "10.0.0.2", DetectedAt: now,
	}))

	alerts, err := ls.ListUnalertedAnomalyAlerts(ctx)
	require.NoError(t, err)
	require.Len(t, alerts, 1)
	id := alerts[0].ID

	require.NoError(t, ls.MarkAnomalyAlertAlerted(ctx, id))

	// Now should be empty.
	rows, err := ls.ListUnalertedAnomalyAlerts(ctx)
	require.NoError(t, err)
	assert.Empty(t, rows)
}

func TestGetDistinctActiveUserIDs(t *testing.T) {
	ctx := context.Background()
	ls := newStoreS3(t, "distinct_active", &models.AuditEvent{})

	now := time.Now()
	uid1 := uint(101)
	uid2 := uint(102)

	// Two login events for user 101.
	require.NoError(t, ls.db.Create(&models.AuditEvent{
		EventType: "auth.login", UserID: &uid1, EventTime: now.Add(-time.Hour), Success: boolPtr(true),
	}).Error)
	require.NoError(t, ls.db.Create(&models.AuditEvent{
		EventType: "auth.login", UserID: &uid1, EventTime: now.Add(-30 * time.Minute), Success: boolPtr(true),
	}).Error)
	// One login for user 102.
	require.NoError(t, ls.db.Create(&models.AuditEvent{
		EventType: "auth.login", UserID: &uid2, EventTime: now.Add(-2 * time.Hour), Success: boolPtr(true),
	}).Error)
	// A non-login event for user 103 — must not appear.
	uid3 := uint(103)
	require.NoError(t, ls.db.Create(&models.AuditEvent{
		EventType: "secret.read", UserID: &uid3, EventTime: now, Success: boolPtr(true),
	}).Error)

	ids, err := ls.GetDistinctActiveUserIDs(ctx, now.Add(-3*time.Hour))
	require.NoError(t, err)
	assert.Contains(t, ids, uid1)
	assert.Contains(t, ids, uid2)
	assert.NotContains(t, ids, uid3)
	// Exactly 2 distinct users.
	assert.Len(t, ids, 2)
}

// ---------------------------------------------------------------------------
// local_audit_checkpoint
// ---------------------------------------------------------------------------

func newCheckpointStore(t *testing.T) *LocalStorage {
	t.Helper()
	return newStoreS3(t, "checkpoint_"+t.Name(), &models.AuditCheckpoint{}, &models.AuditEvent{})
}

func TestAuditCheckpoint_CRUD(t *testing.T) {
	ctx := context.Background()
	ls := newCheckpointStore(t)

	// LatestAuditCheckpoint on empty table → (nil, nil).
	latest, err := ls.LatestAuditCheckpoint(ctx)
	require.NoError(t, err)
	assert.Nil(t, latest)

	// Create a checkpoint.
	cp := &models.AuditCheckpoint{
		ChainedEvents: 100, HeadID: 50, HeadHash: "abc123", KeyVersion: "v1", Signature: "sig1",
	}
	require.NoError(t, ls.CreateAuditCheckpoint(ctx, cp))
	assert.NotZero(t, cp.ID)

	// LatestAuditCheckpoint returns the one we created.
	latest, err = ls.LatestAuditCheckpoint(ctx)
	require.NoError(t, err)
	require.NotNil(t, latest)
	assert.Equal(t, cp.ID, latest.ID)
	assert.Equal(t, "sig1", latest.Signature)

	// Create a second checkpoint — latest should return the newer one.
	cp2 := &models.AuditCheckpoint{
		ChainedEvents: 200, HeadID: 100, HeadHash: "def456", KeyVersion: "v1", Signature: "sig2",
	}
	require.NoError(t, ls.CreateAuditCheckpoint(ctx, cp2))

	latest2, err := ls.LatestAuditCheckpoint(ctx)
	require.NoError(t, err)
	require.NotNil(t, latest2)
	assert.Equal(t, cp2.ID, latest2.ID)

	// UpdateAuditCheckpointAnchor.
	anchorAt := time.Now()
	require.NoError(t, ls.UpdateAuditCheckpointAnchor(ctx, cp.ID, []byte("token-bytes"), anchorAt, "rfc3161:https://example.com"))
	var updated models.AuditCheckpoint
	require.NoError(t, ls.db.First(&updated, cp.ID).Error)
	assert.Equal(t, []byte("token-bytes"), updated.AnchorToken)
	assert.Equal(t, "rfc3161:https://example.com", updated.AnchorProvider)
}

func TestAuditEntryHashByID(t *testing.T) {
	ctx := context.Background()
	ls := newCheckpointStore(t)

	// Non-existent id → (empty, false, nil).
	hash, found, err := ls.AuditEntryHashByID(ctx, 99999)
	require.NoError(t, err)
	assert.False(t, found)
	assert.Empty(t, hash)

	// Insert an audit event with a known entry_hash.
	uid := uint(1)
	require.NoError(t, ls.db.Create(&models.AuditEvent{
		EventType: "secret.read", UserID: &uid, EventTime: time.Now(), EntryHash: "myhash", Success: boolPtr(true),
	}).Error)
	var ev models.AuditEvent
	require.NoError(t, ls.db.First(&ev).Error)

	hash, found, err = ls.AuditEntryHashByID(ctx, ev.ID)
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, "myhash", hash)
}

// ---------------------------------------------------------------------------
// local_dynamic — uncovered functions
// ---------------------------------------------------------------------------

func newDynamicFullStore(t *testing.T) *LocalStorage {
	t.Helper()
	ls := newStoreS3(t, "dynamic_full_"+t.Name(), &models.DynamicSecretConfig{}, &models.DynamicSecretLease{})
	seedDynamicConfigProjects(t, ls.db)
	return ls
}

func TestDynamicSecretConfig_GetListUpdate(t *testing.T) {
	ctx := context.Background()
	ls := newDynamicFullStore(t)

	// Create a config.
	c, err := ls.CreateDynamicSecretConfig(ctx, &models.DynamicSecretConfig{
		Name: "pg-admin", ProjectID: 1, EnvironmentID: 1, BackendType: "postgres",
	})
	require.NoError(t, err)

	// Get.
	got, err := ls.GetDynamicSecretConfig(ctx, c.ID)
	require.NoError(t, err)
	assert.Equal(t, "pg-admin", got.Name)

	// Get — not found.
	_, err = ls.GetDynamicSecretConfig(ctx, 99999)
	require.Error(t, err)

	// List by project.
	list, err := ls.ListDynamicSecretConfigs(ctx, 1, 0)
	require.NoError(t, err)
	assert.Len(t, list, 1)

	// List by project + environment.
	list2, err := ls.ListDynamicSecretConfigs(ctx, 1, 1)
	require.NoError(t, err)
	assert.Len(t, list2, 1)

	// List by project + different environment → empty.
	list3, err := ls.ListDynamicSecretConfigs(ctx, 1, 2)
	require.NoError(t, err)
	assert.Empty(t, list3)

	// Update.
	c.BackendType = "mysql"
	require.NoError(t, ls.UpdateDynamicSecretConfig(ctx, c))
	got2, err := ls.GetDynamicSecretConfig(ctx, c.ID)
	require.NoError(t, err)
	assert.Equal(t, "mysql", got2.BackendType)
}

// TestTransitionDynamicSecretConfigDisabled_ClosesRace proves the
// StateTransitionMissingCAS fix: two callers racing to flip the SAME config's
// Disabled field (both having read the SAME pre-transition value) can no
// longer both silently win. The first conditional write matches and persists;
// the second — still gated on the now-STALE fromDisabled value the first
// caller also observed — is rejected (matched=false), exactly mirroring
// TestTransitionMachineIdentityState's #388/#518 proof.
func TestTransitionDynamicSecretConfigDisabled_ClosesRace(t *testing.T) {
	ctx := context.Background()
	ls := newDynamicFullStore(t)

	cfg, err := ls.CreateDynamicSecretConfig(ctx, &models.DynamicSecretConfig{
		Name: "race-config", ProjectID: 1, EnvironmentID: 1, BackendType: "postgres",
		Disabled: false,
	})
	require.NoError(t, err)

	// Both racing callers observed Disabled=false via GetDynamicSecretConfig
	// before mutating their own in-memory copy to Disabled=true.
	first := *cfg
	first.Disabled = true
	second := *cfg
	second.Disabled = true

	// First writer wins: the row's persisted disabled value still matches the
	// fromDisabled it observed (false).
	matched1, err := ls.TransitionDynamicSecretConfigDisabled(ctx, &first, false)
	require.NoError(t, err)
	assert.True(t, matched1)

	// Second writer — racing off the SAME stale fromDisabled=false — must lose:
	// the row's persisted disabled value has already moved to true.
	matched2, err := ls.TransitionDynamicSecretConfigDisabled(ctx, &second, false)
	require.NoError(t, err)
	assert.False(t, matched2)

	// The persisted row reflects the FIRST writer's change only, and was not
	// clobbered by the second (rejected) write.
	got, err := ls.GetDynamicSecretConfig(ctx, cfg.ID)
	require.NoError(t, err)
	assert.True(t, got.Disabled)

	// A THIRD call gated on the now-current value (true) succeeds, proving the
	// conditional write isn't permanently stuck — it tracks whatever is
	// actually persisted.
	third := *cfg
	third.Disabled = false
	matched3, err := ls.TransitionDynamicSecretConfigDisabled(ctx, &third, true)
	require.NoError(t, err)
	assert.True(t, matched3)
}

// TestTransitionDynamicSecretConfigDisabled_DoesNotClobberConcurrentDSNRotation
// is #G42: the guard only checks `disabled`, so a concurrent DSN rotation
// (UpdateDynamicSecretConfig, an unconditional Save that never touches
// `disabled`) still matches this WHERE clause. The toggle itself must
// succeed, but must not revert the rotation using its own stale copy of
// AdminDSNEnc.
func TestTransitionDynamicSecretConfigDisabled_DoesNotClobberConcurrentDSNRotation(t *testing.T) {
	ctx := context.Background()
	ls := newDynamicFullStore(t)

	cfg, err := ls.CreateDynamicSecretConfig(ctx, &models.DynamicSecretConfig{
		Name: "rotate-config", ProjectID: 1, EnvironmentID: 1, BackendType: "postgres",
		Disabled: false, AdminDSNEnc: []byte("old-dsn"),
	})
	require.NoError(t, err)

	// An admin reads the config to disable it — this copy has NO knowledge of
	// the DSN rotation about to land.
	toggle := *cfg
	toggle.Disabled = true

	// A concurrent DSN rotation commits FIRST, via the plain (non-conditional)
	// update path — this is what a real rotation job uses.
	rotated := *cfg
	rotated.AdminDSNEnc = []byte("new-dsn")
	require.NoError(t, ls.UpdateDynamicSecretConfig(ctx, &rotated))

	// The disable toggle still legitimately matches (disabled was still false
	// when this call's WHERE clause evaluated) — it must succeed, but must NOT
	// revert the just-committed DSN rotation using its own stale copy.
	matched, err := ls.TransitionDynamicSecretConfigDisabled(ctx, &toggle, false)
	require.NoError(t, err)
	assert.True(t, matched, "disabling a config that was just rotated is legitimate")

	got, err := ls.GetDynamicSecretConfig(ctx, cfg.ID)
	require.NoError(t, err)
	assert.True(t, got.Disabled, "the toggle itself must have taken effect")
	assert.Equal(t, []byte("new-dsn"), got.AdminDSNEnc, "the concurrent DSN rotation must survive the toggle")
}

// TestTransitionDynamicSecretConfigDisabled_NotFound verifies the
// RowsAffected == 0 path when the config id doesn't exist at all.
func TestTransitionDynamicSecretConfigDisabled_NotFound(t *testing.T) {
	ctx := context.Background()
	ls := newDynamicFullStore(t)

	matched, err := ls.TransitionDynamicSecretConfigDisabled(ctx,
		&models.DynamicSecretConfig{ID: 9999, Disabled: true}, false)
	require.NoError(t, err)
	assert.False(t, matched)
}

func TestCountDynamicSecretConfigsByClassification(t *testing.T) {
	ctx := context.Background()
	ls := newDynamicFullStore(t)

	// Empty table → empty map.
	m, err := ls.CountDynamicSecretConfigsByClassification(ctx)
	require.NoError(t, err)
	assert.Empty(t, m)

	// Create some configs with different classifications.
	_, err = ls.CreateDynamicSecretConfig(ctx, &models.DynamicSecretConfig{
		Name: "a", ProjectID: 1, EnvironmentID: 1, BackendType: "postgres", Classification: "confidential",
	})
	require.NoError(t, err)
	_, err = ls.CreateDynamicSecretConfig(ctx, &models.DynamicSecretConfig{
		Name: "b", ProjectID: 1, EnvironmentID: 2, BackendType: "postgres", Classification: "confidential",
	})
	require.NoError(t, err)
	_, err = ls.CreateDynamicSecretConfig(ctx, &models.DynamicSecretConfig{
		Name: "c", ProjectID: 2, EnvironmentID: 1, BackendType: "mysql", Classification: "",
	})
	require.NoError(t, err)

	m2, err := ls.CountDynamicSecretConfigsByClassification(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, m2["confidential"])
	assert.Equal(t, 1, m2[""])
}

func TestDynamicSecretLease_CRUD(t *testing.T) {
	ctx := context.Background()
	ls := newDynamicFullStore(t)

	cfg, err := ls.CreateDynamicSecretConfig(ctx, &models.DynamicSecretConfig{
		Name: "lease-test", ProjectID: 1, EnvironmentID: 1, BackendType: "postgres",
	})
	require.NoError(t, err)

	now := time.Now()
	lease, err := ls.CreateDynamicSecretLease(ctx, &models.DynamicSecretLease{
		LeaseID:   "lease-001",
		ConfigID:  cfg.ID,
		Status:    "active",
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	})
	require.NoError(t, err)
	assert.NotZero(t, lease.ID)

	// Get.
	got, err := ls.GetDynamicSecretLease(ctx, "lease-001")
	require.NoError(t, err)
	assert.Equal(t, lease.ID, got.ID)

	// Get — not found.
	_, err = ls.GetDynamicSecretLease(ctx, "nope")
	require.Error(t, err)

	// List.
	list, err := ls.ListDynamicSecretLeases(ctx, cfg.ID)
	require.NoError(t, err)
	assert.Len(t, list, 1)

	// Update.
	lease.Status = "revoked"
	require.NoError(t, ls.UpdateDynamicSecretLease(ctx, lease))
	got2, err := ls.GetDynamicSecretLease(ctx, "lease-001")
	require.NoError(t, err)
	assert.Equal(t, "revoked", got2.Status)

	// CountActiveLeases — revoked lease doesn't count.
	n, err := ls.CountActiveLeases(ctx, cfg.ID)
	require.NoError(t, err)
	assert.Zero(t, n)

	// Create an active lease.
	_, err = ls.CreateDynamicSecretLease(ctx, &models.DynamicSecretLease{
		LeaseID:   "lease-002",
		ConfigID:  cfg.ID,
		Status:    "active",
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	})
	require.NoError(t, err)

	n2, err := ls.CountActiveLeases(ctx, cfg.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(1), n2)
}

func TestListExpiredActiveLeases(t *testing.T) {
	ctx := context.Background()
	ls := newDynamicFullStore(t)

	cfg, err := ls.CreateDynamicSecretConfig(ctx, &models.DynamicSecretConfig{
		Name: "exp-lease", ProjectID: 1, EnvironmentID: 1, BackendType: "postgres",
	})
	require.NoError(t, err)

	now := time.Now()
	past := now.Add(-time.Hour)

	// Expired active lease.
	_, err = ls.CreateDynamicSecretLease(ctx, &models.DynamicSecretLease{
		LeaseID:   "exp-active",
		ConfigID:  cfg.ID,
		Status:    "active",
		IssuedAt:  past,
		ExpiresAt: past,
	})
	require.NoError(t, err)

	// Expired revoke_failed lease.
	_, err = ls.CreateDynamicSecretLease(ctx, &models.DynamicSecretLease{
		LeaseID:   "exp-failed",
		ConfigID:  cfg.ID,
		Status:    "revoke_failed",
		IssuedAt:  past,
		ExpiresAt: past,
	})
	require.NoError(t, err)

	// Non-expired active lease.
	_, err = ls.CreateDynamicSecretLease(ctx, &models.DynamicSecretLease{
		LeaseID:   "live-active",
		ConfigID:  cfg.ID,
		Status:    "active",
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	})
	require.NoError(t, err)

	leases, err := ls.ListExpiredActiveLeases(ctx, now)
	require.NoError(t, err)
	assert.Len(t, leases, 2, "must return both the expired active and revoke_failed leases")

	leaseIDs := []string{leases[0].LeaseID, leases[1].LeaseID}
	assert.Contains(t, leaseIDs, "exp-active")
	assert.Contains(t, leaseIDs, "exp-failed")
}

// ---------------------------------------------------------------------------
// local_break_glass — Get, List, Revoke (not yet covered)
// ---------------------------------------------------------------------------

func newBGStore(t *testing.T) *LocalStorage {
	t.Helper()
	db := newStoreS3(t, "bg_"+t.Name(), &models.BreakGlassActivation{})
	// Partial unique index for active constraint.
	require.NoError(t, db.db.Exec(
		"CREATE UNIQUE INDEX IF NOT EXISTS uniq_bg_active_project_user ON break_glass_activations (project_id, user_id) WHERE state = 'active'",
	).Error)
	return db
}

func TestBreakGlass_GetListRevoke(t *testing.T) {
	ctx := context.Background()
	ls := newBGStore(t)

	// Create an activation.
	act, err := ls.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID: 5, UserID: 20, RoleID: 1, RoleName: "incident-responder", State: "active",
	})
	require.NoError(t, err)

	// Get.
	got, err := ls.GetBreakGlassActivation(ctx, act.ID)
	require.NoError(t, err)
	assert.Equal(t, "active", got.State)

	// Get — not found.
	_, err = ls.GetBreakGlassActivation(ctx, 99999)
	require.Error(t, err)

	// List.
	list, err := ls.ListBreakGlassActivations(ctx, 5)
	require.NoError(t, err)
	assert.Len(t, list, 1)

	// List — empty project.
	list2, err := ls.ListBreakGlassActivations(ctx, 99)
	require.NoError(t, err)
	assert.Empty(t, list2)

	// Revoke.
	revokedAt := time.Now()
	require.NoError(t, ls.RevokeBreakGlassActivation(ctx, act.ID, 1, 0, revokedAt))

	// Verify revoked.
	got2, err := ls.GetBreakGlassActivation(ctx, act.ID)
	require.NoError(t, err)
	assert.Equal(t, "revoked", got2.State)

	// Revoke again → ErrBreakGlassNotActive (wrapped).
	err = ls.RevokeBreakGlassActivation(ctx, act.ID, 1, 0, time.Now())
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrBreakGlassNotActive)
}

// ---------------------------------------------------------------------------
// local_legal_hold — GetActiveLegalHold (0% uncovered)
// ---------------------------------------------------------------------------

func TestGetActiveLegalHold(t *testing.T) {
	ctx := context.Background()
	ls := newStoreS3(t, "legal_hold", &models.LegalHold{})

	// No active hold → (nil, nil).
	hold, err := ls.GetActiveLegalHold(ctx)
	require.NoError(t, err)
	assert.Nil(t, hold)

	// Place a hold.
	h, err := ls.CreateLegalHold(ctx, &models.LegalHold{
		Reason: "litigation", PlacedBy: 1, PlacedAt: time.Now(), Released: false,
	})
	require.NoError(t, err)

	// GetActiveLegalHold returns it.
	hold2, err := ls.GetActiveLegalHold(ctx)
	require.NoError(t, err)
	require.NotNil(t, hold2)
	assert.Equal(t, h.ID, hold2.ID)

	// Release the hold.
	h.Released = true
	require.NoError(t, ls.UpdateLegalHold(ctx, h))

	// No longer active.
	hold3, err := ls.GetActiveLegalHold(ctx)
	require.NoError(t, err)
	assert.Nil(t, hold3)
}

// ---------------------------------------------------------------------------
// local_login_attempts — PruneLoginAttempts (0%)
// ---------------------------------------------------------------------------

func TestLoginAttempts_RecordCountPrune(t *testing.T) {
	ctx := context.Background()
	ls := newStoreS3(t, "login_attempts", &models.LoginAttempt{})

	now := time.Now()
	ip := "192.168.1.1"

	// Record 3 attempts.
	for _, at := range []time.Time{now.Add(-2 * time.Hour), now.Add(-time.Hour), now.Add(-time.Minute)} {
		require.NoError(t, ls.RecordLoginAttempt(ctx, ip, at))
	}

	// Count in last 90 minutes: only the last two.
	n, err := ls.CountRecentLoginAttempts(ctx, ip, now.Add(-90*time.Minute))
	require.NoError(t, err)
	assert.Equal(t, int64(2), n)

	// Prune attempts older than 90 minutes: removes the first.
	pruned, err := ls.PruneLoginAttempts(ctx, now.Add(-90*time.Minute))
	require.NoError(t, err)
	assert.Equal(t, int64(1), pruned)

	// Now only 2 remain.
	var cnt int64
	ls.db.Model(&models.LoginAttempt{}).Count(&cnt)
	assert.Equal(t, int64(2), cnt)
}

// ---------------------------------------------------------------------------
// classification_count — countByClassification (0%)
// ---------------------------------------------------------------------------

func TestCountByClassification(t *testing.T) {
	ctx := context.Background()
	// Use DynamicSecretConfig which has a Classification field.
	ls := newStoreS3(t, "classification", &models.DynamicSecretConfig{})

	// Empty.
	m, err := countByClassification(ctx, ls.db, &models.DynamicSecretConfig{})
	require.NoError(t, err)
	assert.Empty(t, m)

	// Insert items with various classifications.
	for _, c := range []struct {
		name, class string
	}{
		{"a", "public"}, {"b", "public"}, {"c", "confidential"}, {"d", ""},
	} {
		require.NoError(t, ls.db.Create(&models.DynamicSecretConfig{
			Name: c.name, ProjectID: 1, EnvironmentID: 1, BackendType: "pg", Classification: c.class,
		}).Error)
	}

	m2, err := countByClassification(ctx, ls.db, &models.DynamicSecretConfig{})
	require.NoError(t, err)
	assert.Equal(t, 2, m2["public"])
	assert.Equal(t, 1, m2["confidential"])
	assert.Equal(t, 1, m2[""])
}

// ---------------------------------------------------------------------------
// local_audit — scanTime Scan edge cases (increase coverage on Value/Scan/parse)
// ---------------------------------------------------------------------------

func TestScanTime_Scan(t *testing.T) {
	var st scanTime

	// nil → no-op.
	require.NoError(t, st.Scan(nil))
	assert.Nil(t, st.t)

	// time.Time value.
	now := time.Now()
	require.NoError(t, st.Scan(now))
	require.NotNil(t, st.t)
	assert.WithinDuration(t, now, *st.t, time.Second)

	// string value (RFC3339Nano format).
	var st2 scanTime
	require.NoError(t, st2.Scan(now.UTC().Format(time.RFC3339Nano)))
	require.NotNil(t, st2.t)

	// []byte value.
	var st3 scanTime
	require.NoError(t, st3.Scan([]byte(now.UTC().Format(time.RFC3339Nano))))
	require.NotNil(t, st3.t)

	// Unsupported type → error.
	var st4 scanTime
	err := st4.Scan(12345)
	require.Error(t, err)
}

func TestScanTime_Value(t *testing.T) {
	// nil t → (nil, nil).
	st := scanTime{t: nil}
	v, err := st.Value()
	require.NoError(t, err)
	assert.Nil(t, v)

	// non-nil t → the time.Time.
	now := time.Now()
	st2 := scanTime{t: &now}
	v2, err := st2.Value()
	require.NoError(t, err)
	assert.Equal(t, now, v2)
}

func TestScanTime_parse(t *testing.T) {
	var st scanTime

	// Various formats should parse.
	for _, s := range []string{
		"2026-07-10 15:04:05.999999999-07:00",
		"2026-07-10 15:04:05-07:00",
		"2026-07-10T15:04:05.999999999Z",
		"2026-07-10 15:04:05.123456789",
		"2026-07-10 15:04:05",
	} {
		st.t = nil
		err := st.parse(s)
		require.NoError(t, err, "format %q", s)
		assert.NotNil(t, st.t, "format %q", s)
	}

	// Unparseable string → error.
	err := st.parse("not-a-time")
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_audit — GetAuditLogs cursor/ascending mode
// ---------------------------------------------------------------------------

func TestGetAuditLogs_AscendingCursorMode(t *testing.T) {
	ctx := context.Background()
	ls := newStoreS3(t, "audit_logs_asc", &models.AuditEvent{})

	now := time.Now()
	for i := range 5 {
		uid := uint(i + 1)
		require.NoError(t, ls.db.Create(&models.AuditEvent{
			EventType: "secret.read", UserID: &uid,
			EventTime: now.Add(time.Duration(i) * time.Minute), Success: boolPtr(true),
		}).Error)
	}

	// Cursor mode (Ascending = true, AfterID filters).
	filter := &storage.AuditFilter{
		Ascending: true,
		PageSize:  3,
	}
	events, total, err := ls.GetAuditLogs(ctx, filter)
	require.NoError(t, err)
	assert.Equal(t, int64(5), total)
	assert.Len(t, events, 3)
	// First batch is ascending by ID.
	assert.True(t, events[0].ID < events[1].ID)
	assert.True(t, events[1].ID < events[2].ID)

	// Next page via AfterID.
	afterID := events[2].ID
	filter2 := &storage.AuditFilter{
		Ascending: true,
		PageSize:  3,
		AfterID:   &afterID,
	}
	events2, _, err := ls.GetAuditLogs(ctx, filter2)
	require.NoError(t, err)
	assert.Len(t, events2, 2, "only 2 events remain after the cursor")
}

func TestGetAuditLogs_AllFilters(t *testing.T) {
	ctx := context.Background()
	ls := newStoreS3(t, "audit_logs_filters", &models.AuditEvent{})

	now := time.Now()
	uid := uint(42)
	pid := uint(7)
	sid := uint(99)

	require.NoError(t, ls.db.Create(&models.AuditEvent{
		EventType: "secret.read", UserID: &uid, ProjectID: &pid, SecretNodeID: &sid,
		EventTime: now, Success: boolPtr(true), ActorType: "user",
	}).Error)
	require.NoError(t, ls.db.Create(&models.AuditEvent{
		EventType: "secret.write", UserID: &uid, ProjectID: &pid,
		EventTime: now.Add(time.Minute), Success: new(bool), ActorType: "machine_identity",
	}).Error)

	ptrU := uid
	ptrP := pid
	ptrS := sid
	ptrAct := "secret.read"
	ptrActorType := "user"
	bTrue := true
	bFalse := false

	// Filter by UserID.
	events, total, err := ls.GetAuditLogs(ctx, &storage.AuditFilter{UserID: &ptrU})
	require.NoError(t, err)
	assert.Equal(t, int64(2), total)
	assert.Len(t, events, 2)

	// Filter by ProjectID.
	events, total, err = ls.GetAuditLogs(ctx, &storage.AuditFilter{ProjectID: &ptrP})
	require.NoError(t, err)
	assert.Equal(t, int64(2), total)
	assert.Len(t, events, 2)

	// Filter by SecretID.
	events, _, err = ls.GetAuditLogs(ctx, &storage.AuditFilter{SecretID: &ptrS})
	require.NoError(t, err)
	assert.Len(t, events, 1)

	// Filter by Action.
	events, _, err = ls.GetAuditLogs(ctx, &storage.AuditFilter{Action: &ptrAct})
	require.NoError(t, err)
	assert.Len(t, events, 1)

	// Filter by Actions (slice).
	events, _, err = ls.GetAuditLogs(ctx, &storage.AuditFilter{Actions: []string{"secret.read", "secret.write"}})
	require.NoError(t, err)
	assert.Len(t, events, 2)

	// Filter by StartTime.
	st := now.Add(-time.Minute)
	events, _, err = ls.GetAuditLogs(ctx, &storage.AuditFilter{StartTime: &st})
	require.NoError(t, err)
	assert.Len(t, events, 2)

	// Filter by EndTime — only 1st event.
	et := now.Add(30 * time.Second)
	events, _, err = ls.GetAuditLogs(ctx, &storage.AuditFilter{EndTime: &et})
	require.NoError(t, err)
	assert.Len(t, events, 1)

	// Filter by Success=true.
	events, _, err = ls.GetAuditLogs(ctx, &storage.AuditFilter{Success: &bTrue})
	require.NoError(t, err)
	assert.Len(t, events, 1)

	// Filter by Success=false.
	events, _, err = ls.GetAuditLogs(ctx, &storage.AuditFilter{Success: &bFalse})
	require.NoError(t, err)
	assert.Len(t, events, 1)

	// Filter by ActorType.
	events, _, err = ls.GetAuditLogs(ctx, &storage.AuditFilter{ActorType: &ptrActorType})
	require.NoError(t, err)
	assert.Len(t, events, 1)

	// Pagination — page 2 of page_size 1.
	events, _, err = ls.GetAuditLogs(ctx, &storage.AuditFilter{Page: 2, PageSize: 1})
	require.NoError(t, err)
	assert.Len(t, events, 1)

	// nil filter (defaults).
	events, total, err = ls.GetAuditLogs(ctx, nil)
	require.NoError(t, err)
	assert.Equal(t, int64(2), total)
	assert.Len(t, events, 2)
}
