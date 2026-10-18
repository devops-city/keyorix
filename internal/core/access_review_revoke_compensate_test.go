package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// newAccessReviewRevokeCompensateWorld builds a minimal real-storage world for
// the revoke-compensation tests below: a reviewer, a target user holding a
// role at project scope, and an open campaign with one pending "revoke" item
// referencing that grant.
func newAccessReviewRevokeCompensateWorld(t *testing.T) (*KeyorixCore, *faultstorage.FaultyStorage, *gorm.DB, *models.AccessReviewItem) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{},
		&models.GroupRole{}, &models.Project{}, &models.AuditEvent{},
		&models.AccessReviewCampaign{}, &models.AccessReviewItem{},
	))
	const proj = uint(2)
	require.NoError(t, db.Create(&models.Role{ID: 3, Name: "editor"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "reviewer", IsActive: true}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "reviewer2", IsActive: true}).Error)
	require.NoError(t, db.Create(&models.User{ID: 10, Username: "alice", IsActive: true}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 10, RoleID: 3, ProjectID: proj}).Error)
	campaign := &models.AccessReviewCampaign{ProjectID: proj, Name: "q4", State: CampaignStateOpen, CreatedBy: 1}
	require.NoError(t, db.Create(campaign).Error)
	item := &models.AccessReviewItem{
		CampaignID: campaign.ID, PrincipalType: "user", PrincipalID: 10, PrincipalName: "alice",
		Source: "role", RoleID: 3, Decision: ReviewItemPending,
	}
	require.NoError(t, db.Create(item).Error)

	real := store.NewLocalStorage(db)
	faulty := faultstorage.NewFaultyStorage(real, nil)
	c := NewKeyorixCore(faulty)
	return c, faulty, db, item
}

// TestDecideAccessReviewItem_RevokeActionFailureRevertsClaim is the regression
// test for the compensating revert: DecideAccessReviewItem's revoke path
// claims the item (pending -> revoked) BEFORE running the real removal --
// claim-before-act is what closes the #1646 attest/revoke cross-replica race
// (see claimItemDecision's own doc comment) -- so a storage error during the
// real removal used to leave the item falsely stamped "revoked" with the
// underlying grant still intact (manual-reconciliation-only, per the original
// SECURITY log). Every RevokeAccessReviewGrant branch returns its error
// directly from the same call that would have performed the removal, never
// after a successful one (revokeRoleByPrincipalType's RemoveUserRole here),
// so revoke is idempotent on retry: nothing was actually removed when it
// errors. The fix compensates by reverting the claim back to pending so a
// retry can re-attempt the decision from scratch.
func TestDecideAccessReviewItem_RevokeActionFailureRevertsClaim(t *testing.T) {
	c, faulty, db, item := newAccessReviewRevokeCompensateWorld(t)
	ctx := context.Background()

	faulty.Arm(&faultstorage.FaultSpec{Method: "RemoveRole", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
	err := c.DecideAccessReviewItem(ctx, 1, 2, item.CampaignID, item.ID, "revoke", "no longer needed")
	require.Error(t, err, "a storage error during the real removal must be reported")
	require.True(t, faulty.Fired(), "the fault must actually have been reached")

	// Effect, not return value: the compensating revert must have put the item
	// back to pending, not left it stuck claimed as "revoked".
	var afterFault models.AccessReviewItem
	require.NoError(t, db.First(&afterFault, item.ID).Error)
	assert.Equal(t, ReviewItemPending, afterFault.Decision, "a failed revoke must leave the item pending again, not stuck claimed")
	assert.Zero(t, afterFault.DecidedBy)
	assert.Nil(t, afterFault.DecidedAt)

	// The grant itself must still be intact -- RemoveRole's own error means its
	// DELETE never ran.
	var roleCount int64
	require.NoError(t, db.Model(&models.UserRole{}).Where("user_id = ? AND role_id = ?", 10, 3).Count(&roleCount).Error)
	assert.Equal(t, int64(1), roleCount, "the role grant must still exist -- the faulted removal never ran")

	// No revoked audit event may be recorded for a failed, compensated decision.
	var revokedEvents int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", EventAccessReviewRevoked).Count(&revokedEvents).Error)
	assert.Zero(t, revokedEvents, "no revoke evidence may be recorded for a decision that was compensated away")

	// The fault clears: a retry by the SAME reviewer must succeed, actually
	// remove the grant, and record exactly one revoked audit event (not a
	// second/double one on top of anything the failed attempt might have left).
	faulty.Arm(nil)
	require.NoError(t, c.DecideAccessReviewItem(ctx, 1, 2, item.CampaignID, item.ID, "revoke", "retry"))

	var final models.AccessReviewItem
	require.NoError(t, db.First(&final, item.ID).Error)
	assert.Equal(t, ReviewItemRevoked, final.Decision)
	assert.Equal(t, uint(1), final.DecidedBy)

	require.NoError(t, db.Model(&models.UserRole{}).Where("user_id = ? AND role_id = ?", 10, 3).Count(&roleCount).Error)
	assert.Zero(t, roleCount, "the retry must have actually removed the grant")

	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", EventAccessReviewRevoked).Count(&revokedEvents).Error)
	assert.Equal(t, int64(1), revokedEvents, "exactly one revoked audit event -- no double from the earlier compensated attempt")
}

// TestDecideAccessReviewItem_RevokeActionFailure_AnotherReviewerCanRetry proves
// the compensation isn't scoped to "only the original reviewer can fix it":
// once reverted to pending, the item is a normal pending item again, decidable
// by any independent reviewer -- not wedged to the actor whose claim failed.
func TestDecideAccessReviewItem_RevokeActionFailure_AnotherReviewerCanRetry(t *testing.T) {
	c, faulty, db, item := newAccessReviewRevokeCompensateWorld(t)
	ctx := context.Background()

	faulty.Arm(&faultstorage.FaultSpec{Method: "RemoveRole", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
	require.Error(t, c.DecideAccessReviewItem(ctx, 1, 2, item.CampaignID, item.ID, "revoke", "no longer needed"))
	faulty.Arm(nil)

	// A DIFFERENT reviewer (actorID 2, not 1) retries -- must succeed.
	require.NoError(t, c.DecideAccessReviewItem(ctx, 2, 2, item.CampaignID, item.ID, "revoke", "retry by another reviewer"))

	var final models.AccessReviewItem
	require.NoError(t, db.First(&final, item.ID).Error)
	assert.Equal(t, ReviewItemRevoked, final.Decision)
	assert.Equal(t, uint(2), final.DecidedBy, "the successful retry's actor must be recorded, not the original failed claimant")
}
