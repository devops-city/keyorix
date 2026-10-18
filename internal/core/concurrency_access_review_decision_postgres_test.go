package core

import (
	"context"
	"sync"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// accessReviewCampaignModels is the AutoMigrate set for the access-review
// reproduction: bootstrap's RBAC seed plus the campaign tables
// access_review_campaign_external_test.go's migrateCampaignTables adds.
var accessReviewCampaignModels = []any{
	&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
	&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
	&models.Project{}, &models.Environment{}, &models.SystemMetadata{},
	&models.AccessReviewCampaign{}, &models.AccessReviewItem{}, &models.AuditEvent{},
	&models.MachineIdentity{}, &models.MachineIdentityRole{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{}, &models.SecretNode{},
}

// TestConcurrency_DecideAccessReviewItem_CrossReplicaPostgres_NoFalseCertification
// is #1646's access-review residual, reproduced (not just inspected) before deciding
// whether to fix it: accessReviewDecisionMu (service.go) is a KeyorixCore-level
// sync.Mutex, so it only serializes callers within ONE process/replica. This test
// gives two independent reviewers their OWN *gorm.DB connection (own LocalStorage,
// own KeyorixCore, own accessReviewDecisionMu) into the SAME real Postgres schema,
// then races an "attest" against a "revoke" on the identical pending item.
//
// AttestAccessReviewGrant changes no state -- it re-verifies the grant still exists
// and logs an audit event; the real mutation lives entirely on the revoke side
// (RemoveUserRole). So the concerning outcome isn't "both mutated conflicting data"
// -- it's a coherence violation: if BOTH replicas read Decision==Pending before
// either commits its stamp, revoke's real removal executes AND attest's "still
// needed, confirmed present" verification can ALSO pass (it ran before the removal,
// or races it) -- and persistItemDecision's conditional UPDATE picks a winner for
// the STAMP independent of which action's real effect landed. A persisted "attested"
// stamp on a grant that no longer exists is false compliance evidence: it certifies
// access that was, in fact, revoked in the same window.
func TestConcurrency_DecideAccessReviewItem_CrossReplicaPostgres_NoFalseCertification(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	base := pgTestDSN(t)
	dsn := pgIsolatedSchemaDSN(t, base)

	// Replica 0 sets up all the shared fixture data: bootstrap, two independent
	// reviewers, one target user holding the role grant under review, and an open
	// campaign with that grant as its one pending item.
	setupDB := pgOpen(t, dsn)
	require.NoError(t, setupDB.AutoMigrate(accessReviewCampaignModels...))
	setupStorage := localstore.NewLocalStorage(setupDB)
	setupCore := NewKeyorixCore(setupStorage)
	setupCore.SetBootstrapToken("access-review-race-token")
	ctx := context.Background()

	bootRes, err := setupCore.BootstrapSystem(ctx, &BootstrapRequest{
		Username: "admin", Email: "admin@example.com", Password: "BootstrapPass123!",
		DisplayName: "Admin", Token: "access-review-race-token",
	})
	require.NoError(t, err)
	projectID := bootRes.Project.ID

	reviewerB, err := setupCore.CreateUser(ctx, &CreateUserRequest{
		Username: "reviewer-b", Email: "reviewer-b@example.com", Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)

	target, err := setupCore.CreateUser(ctx, &CreateUserRequest{
		Username: "review-target", Email: "review-target@example.com", Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)
	viewerRole, err := setupCore.Storage().GetRoleByName(ctx, "project_viewer")
	require.NoError(t, err)
	require.NoError(t, setupCore.Storage().AssignRole(ctx, target.ID, viewerRole.ID, Scope{ProjectID: projectID}))

	openRes, err := setupCore.OpenAccessReviewCampaign(ctx, bootRes.User.ID, 0, projectID, "race test")
	require.NoError(t, err)
	require.Equal(t, 1, openRes.Progress.Total, "exactly the target's one role grant should be the campaign's only item")
	campaignID := openRes.Campaign.ID
	detail, err := setupCore.GetAccessReviewCampaign(ctx, projectID, campaignID)
	require.NoError(t, err)
	require.Len(t, detail.Items, 1)
	itemID := detail.Items[0].ID
	require.Equal(t, target.ID, detail.Items[0].PrincipalID)

	// Two independent replicas, own connections into the SAME schema -- own
	// accessReviewDecisionMu, unable to serialize against each other.
	dbA := pgOpen(t, dsn)
	coreA := NewKeyorixCore(localstore.NewLocalStorage(dbA))
	dbB := pgOpen(t, dsn)
	coreB := NewKeyorixCore(localstore.NewLocalStorage(dbB))

	var wg sync.WaitGroup
	start := make(chan struct{})
	var attestErr, revokeErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		attestErr = coreA.DecideAccessReviewItem(ctx, bootRes.User.ID, projectID, campaignID, itemID, "attest", "looks fine")
	}()
	go func() {
		defer wg.Done()
		<-start
		revokeErr = coreB.DecideAccessReviewItem(ctx, reviewerB.ID, projectID, campaignID, itemID, "revoke", "not needed")
	}()
	close(start)
	wg.Wait()

	t.Logf("attest result: %v", attestErr)
	t.Logf("revoke result: %v", revokeErr)

	// Verify from a fresh connection, independent of either racing replica.
	verifierDB := pgOpen(t, dsn)
	verifier := localstore.NewLocalStorage(verifierDB)

	item, err := verifier.GetAccessReviewItem(ctx, itemID)
	require.NoError(t, err)

	grants, err := verifier.GetUserRoleIDsAt(ctx, target.ID, storage.Scope{ProjectID: projectID})
	require.NoError(t, err)
	grantStillExists := false
	for _, rid := range grants {
		if rid == viewerRole.ID {
			grantStillExists = true
		}
	}

	t.Logf("persisted item decision: %s", item.Decision)
	t.Logf("underlying grant still exists: %v", grantStillExists)

	// Exactly one of the two racing decisions may win the claim -- the other must be
	// refused with "already decided" (or the campaign-closed variant), never both
	// succeeding and never both failing.
	succeeded := 0
	if attestErr == nil {
		succeeded++
	}
	if revokeErr == nil {
		succeeded++
	}
	assert.Equal(t, 1, succeeded, "exactly one of the racing attest/revoke calls may succeed, not zero and not both")

	// Whichever won, the persisted stamp must match reality: "attested" only if the
	// grant genuinely still exists, "revoked" only if it genuinely doesn't. A
	// mismatch in EITHER direction is false certification evidence.
	switch item.Decision {
	case ReviewItemAttested:
		assert.True(t, grantStillExists, "FALSE CERTIFICATION: item persisted as attested but the underlying grant is gone")
		assert.NoError(t, attestErr, "attest is the persisted winner, so the attest call itself must have succeeded")
	case ReviewItemRevoked:
		assert.False(t, grantStillExists, "FALSE CERTIFICATION: item persisted as revoked but the underlying grant still exists")
		assert.NoError(t, revokeErr, "revoke is the persisted winner, so the revoke call itself must have succeeded")
	default:
		t.Fatalf("item left in unexpected decision state %q -- neither racer's claim committed", item.Decision)
	}
}
