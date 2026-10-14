package core

import (
	"context"
	"sync"
	"testing"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

var dualControlModels = []any{
	&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
	&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
	&models.Project{}, &models.Environment{}, &models.SystemMetadata{},
	&models.AccessRequest{}, &models.AccessRequestApproval{}, &models.AuditEvent{},
	&models.SoDPolicy{},
}

// TestConcurrency_ApproveAccessRequestWithExpiry_CrossReplicaPostgres_ThresholdRace
// is #1646's dual-control residual, reproduced (not just inspected) before deciding
// whether to fix it -- per this campaign's own rule that a race which doesn't exist
// costs a database constraint for nothing. At the time, dualControlApprovalMu
// (service.go) was a KeyorixCore-level sync.Mutex, so it only serialized callers
// within ONE process/replica. This test gives two independent, distinct approvers
// their OWN *gorm.DB connection (own LocalStorage, own KeyorixCore) into the SAME
// real Postgres schema, then races them both submitting the
// THRESHOLD-CROSSING (2nd of a 2-of-N) approval on the identical request at the same
// instant.
//
// CONCLUSION (20/20 runs, varied timing): this race does NOT manifest as a defect.
// UserRole's primary key is the composite (UserID, RoleID, ProjectID, EnvironmentID)
// (models.go) -- a genuine, structural, DB-enforced uniqueness the dual-control
// threshold race always collides with, because resolveApprovalRole locks the granted
// role to the request's single SuggestedRole under K>1 (both racers necessarily
// target the identical tuple). The losing racer's AssignUserRole INSERT fails
// OUTRIGHT with a primary-key violation, before finalizeAccessRequestApproval ever
// reaches CreateAccessRequestApproval -- so neither approval-row inflation nor a live
// double-grant is possible, independent of any in-process mutex. No DB constraint
// was added for this residual; this test is kept as the permanent record of that
// conclusion, asserting the invariant it confirms rather than a defect it found.
//
// #G04-HA CORRECTION TO SCOPE: that conclusion is sound but does NOT generalize to
// dual control as a whole, and reading it as "the dual-control threshold needs no
// cross-replica serialization" is the mistake this note exists to prevent. It
// holds only for racers that BOTH cross the threshold — which is true here solely
// because the fixture below seeds one approval first. Racers that STRADDLE the
// K-th approval instead both take recordPartialApproval, grant no role (so
// UserRole's primary key is never consulted) and are distinct approvers (so
// ux_access_request_approver is never consulted), leaving a request stranded
// pending while holding K valid approvals. That variant is a real defect, is
// covered by concurrency_dual_control_subthreshold_postgres_test.go, and is why
// ApproveAccessRequestWithExpiry now runs under a per-request WithNamedLock.
//
// What that guard does NOT prevent is checked here anyway, as a durable regression
// check: (1) whether BOTH racers' CreateAccessRequestApproval calls land (recording
// MORE approval rows than the K threshold, since both reads happened before either
// commits), and (2) whether there is a live window where the target holds the granted
// role TWICE over (both AssignUserRole calls having landed before the loser's revert
// completes) rather than exactly once.
func TestConcurrency_ApproveAccessRequestWithExpiry_CrossReplicaPostgres_ThresholdRace(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	base := pgTestDSN(t)
	dsn := pgIsolatedSchemaDSN(t, base)

	setupDB := pgOpen(t, dsn)
	require.NoError(t, setupDB.AutoMigrate(dualControlModels...))
	setupStorage := localstore.NewLocalStorage(setupDB)
	setupCore := NewKeyorixCore(setupStorage)
	setupCore.SetBootstrapToken("dual-control-race-token")
	setupCore.SetDualControlPolicy(2)
	ctx := context.Background()

	bootRes, err := setupCore.BootstrapSystem(ctx, &BootstrapRequest{
		Username: "admin", Email: "admin@example.com", Password: "BootstrapPass123!",
		DisplayName: "Admin", Token: "dual-control-race-token",
	})
	require.NoError(t, err)
	projectID := bootRes.Project.ID

	target, err := setupCore.CreateUser(ctx, &CreateUserRequest{
		Username: "dc-target", Email: "dc-target@example.com", Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)
	approverC, err := setupCore.CreateUser(ctx, &CreateUserRequest{
		Username: "dc-approver-c", Email: "dc-approver-c@example.com", Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)
	approverA, err := setupCore.CreateUser(ctx, &CreateUserRequest{
		Username: "dc-approver-a", Email: "dc-approver-a@example.com", Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)
	approverB, err := setupCore.CreateUser(ctx, &CreateUserRequest{
		Username: "dc-approver-b", Email: "dc-approver-b@example.com", Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)

	// AssignUserRole refuses to let an approver grant a permission they don't hold
	// themselves (authz.go's grant ceiling) -- each approver needs project_viewer's
	// own secrets.read at this project before they're eligible to approve granting
	// project_viewer to someone else.
	viewerRoleForApprovers, err := setupCore.Storage().GetRoleByName(ctx, "project_viewer")
	require.NoError(t, err)
	for _, u := range []*models.User{approverC, approverA, approverB} {
		require.NoError(t, setupCore.Storage().AssignRole(ctx, u.ID, viewerRoleForApprovers.ID, Scope{ProjectID: projectID}))
	}
	grantRolesAssignAt(t, setupCore, setupDB, Scope{ProjectID: projectID}, approverC, approverA, approverB)

	req, err := setupCore.RequestProjectAccess(ctx, projectID, target.ID, "project_viewer", "need read access")
	require.NoError(t, err)

	// Seed ONE prior approval sequentially (not raced) so the request sits at
	// received=1, required=2 -- exactly one approval short of the threshold. A and B
	// racing next will each independently compute received=2==required.
	_, err = setupCore.ApproveAccessRequestWithExpiry(ctx, projectID, req.ID, approverC.ID, 0, "", 0)
	require.NoError(t, err)

	// Two independent replicas, own connections into the SAME schema -- sharing no
	// in-process state, so nothing but a DB-level guard can serialize them. Each
	// must also set the SAME dual-control policy (an in-memory KeyorixCore field,
	// not persisted) so both agree K=2.
	dbA := pgOpen(t, dsn)
	coreA := NewKeyorixCore(localstore.NewLocalStorage(dbA))
	coreA.SetDualControlPolicy(2)
	dbB := pgOpen(t, dsn)
	coreB := NewKeyorixCore(localstore.NewLocalStorage(dbB))
	coreB.SetDualControlPolicy(2)

	var wg sync.WaitGroup
	start := make(chan struct{})
	var errA, errB error
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		_, errA = coreA.ApproveAccessRequestWithExpiry(ctx, projectID, req.ID, approverA.ID, 0, "", 0)
	}()
	go func() {
		defer wg.Done()
		<-start
		_, errB = coreB.ApproveAccessRequestWithExpiry(ctx, projectID, req.ID, approverB.ID, 0, "", 0)
	}()
	close(start)
	wg.Wait()

	t.Logf("approver A result: %v", errA)
	t.Logf("approver B result: %v", errB)

	// Verify from a fresh connection, independent of either racing replica.
	verifierDB := pgOpen(t, dsn)
	verifier := localstore.NewLocalStorage(verifierDB)

	finalReq, err := verifier.GetAccessRequest(ctx, req.ID)
	require.NoError(t, err)
	t.Logf("final request state: %s", finalReq.State)

	approvals, err := verifier.ListAccessRequestApprovals(ctx, req.ID)
	require.NoError(t, err)
	t.Logf("total approval rows recorded: %d", len(approvals))

	viewerRole, err := verifier.GetRoleByName(ctx, "project_viewer")
	require.NoError(t, err)
	grantCount := countUserRoleGrants(t, verifierDB, target.ID, viewerRole.ID, projectID)
	t.Logf("live role-grant rows for target at project_viewer: %d", grantCount)

	// (1) Approval-row inflation: the dual-control evidence trail must not record
	// more sign-offs than were genuinely needed to cross the threshold once the
	// race resolves -- exactly 2 (C + whichever of A/B is the real, surviving
	// approval), not 3.
	assert.LessOrEqual(t, len(approvals), 2, "THRESHOLD RACE: more approval rows were recorded than the 2-of-N policy requires -- both racers' approvals landed independently of who ultimately won")

	// (2) Live double-grant: the target must hold the granted role AT MOST once,
	// never twice, once the race has fully resolved (including any compensating
	// revert).
	assert.LessOrEqual(t, grantCount, 1, "THRESHOLD RACE: the target holds the granted role more than once -- both racers' AssignUserRole calls landed live at the same time")
}

// countUserRoleGrants queries user_roles directly (bypassing GetUserRoleIDsAt's
// project|global union, which isn't needed here) for how many rows currently grant
// roleID to userID at projectID -- 0 or 1 in the correct case, 2 if both racers'
// grants are simultaneously live.
// grantRolesAssignAt gives each user a dedicated role holding ONLY
// roles.assign at scope. F6 sweep (2026-09-22): approving now also requires a
// roles.assign baseline, independent of the granted role's own bundle --
// mirrors the SQLite sibling's fixture (concurrency_g04_threshold_race_test.go)
// so these tests keep isolating the threshold race, their actual subject.
func grantRolesAssignAt(t *testing.T, c *KeyorixCore, db *gorm.DB, scope Scope, users ...*models.User) {
	t.Helper()
	ctx := context.Background()
	var perm models.Permission
	if err := db.Where("name = ?", "roles.assign").First(&perm).Error; err != nil {
		perm = models.Permission{Name: "roles.assign", Resource: "roles", Action: "assign"}
		require.NoError(t, db.Create(&perm).Error)
	}
	role := models.Role{Name: "dc-race-approver", NameFolded: "dc-race-approver"}
	require.NoError(t, db.Create(&role).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)
	for _, u := range users {
		require.NoError(t, c.Storage().AssignRole(ctx, u.ID, role.ID, scope))
	}
}

func countUserRoleGrants(t *testing.T, db *gorm.DB, userID, roleID, projectID uint) int {
	t.Helper()
	var count int64
	require.NoError(t, db.Table("user_roles").
		Where("user_id = ? AND role_id = ? AND project_id = ?", userID, roleID, projectID).
		Count(&count).Error)
	return int(count)
}
