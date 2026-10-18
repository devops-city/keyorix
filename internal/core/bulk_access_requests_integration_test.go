// bulk_access_requests_integration_test.go — SQLite-backed integration tests
// for the success paths of BulkApproveAccessRequests and BulkRejectAccessRequests
// that require the full RBAC chain to execute (role lookup, role grant, audit
// events). Uses the same in-memory SQLite setup as bulk_delete_test.go.
package core

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

// setupBulkAccessDB opens a uniquely-named in-memory SQLite DB, migrates all
// tables needed for access-request approval/rejection (roles, permissions,
// assignments, SoD, access schedules, audit), and seeds minimal RBAC fixtures.
// Returns the core, an approver user ID, a requester user ID, and the project ID.
func setupBulkAccessDB(t *testing.T) (k *KeyorixCore, db *gorm.DB, approverID, requesterID, projectID uint) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())

	db = sqlitetest.OpenWithDialector(t, "bulkaccess_", sqlite.Open, &gorm.Config{})

	require.NoError(t, db.AutoMigrate(
		&models.User{},
		&models.Role{},
		&models.UserRole{},
		&models.Permission{},
		&models.RolePermission{},
		&models.Group{},
		&models.UserGroup{},
		&models.GroupRole{},
		&models.Project{},
		&models.Environment{},
		&models.SecretNode{},
		&models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{},
		&models.Session{},
		&models.SystemMetadata{},
		&models.SoDPolicy{},
		&models.SecretAccessSchedule{},
		&models.AuditEvent{},
		&models.MachineIdentity{},
		&models.MachineIdentityRole{},
		&models.AccessRequest{},
		&models.AccessRequestApproval{},
		&models.RejectionReasonTemplate{},
	))

	ctx := context.Background()
	ls := store.NewLocalStorage(db)
	k = &KeyorixCore{storage: ls, now: time.Now}

	// Project
	p, err := ls.CreateProject(ctx, &models.Project{Name: "bulk-access-proj"})
	require.NoError(t, err)
	projectID = p.ID

	// Seed roles: admin (id=1) and editor (id=2). name_folded is NOT NULL
	// (#1642); both names are already pure-lowercase ASCII.
	require.NoError(t, db.Exec("INSERT INTO roles (id,name,name_folded,description) VALUES (1,'admin','admin','Admin')").Error)
	require.NoError(t, db.Exec("INSERT INTO roles (id,name,name_folded,description) VALUES (2,'editor','editor','Editor')").Error)

	// Permissions for admin so the ceiling check passes.
	perms := []struct {
		id   uint
		name string
	}{
		{1, "secrets.read"}, {2, "secrets.write"}, {3, "secrets.delete"},
		{4, "secrets.admin"}, {5, "users.read"}, {6, "users.write"},
		{7, "roles.read"}, {8, "roles.write"}, {9, "roles.assign"},
		{10, "system.read"}, {11, "system.write"}, {12, "audit.read"},
	}
	for _, perm := range perms {
		db.Exec("INSERT OR IGNORE INTO permissions (id,name,resource,action) VALUES (?,?,'resource','action')", perm.id, perm.name)
		db.Exec("INSERT OR IGNORE INTO role_permissions (role_id,permission_id) VALUES (1,?)", perm.id)
	}
	// editor gets the permissions it's defined with.
	db.Exec("INSERT OR IGNORE INTO role_permissions (role_id,permission_id) VALUES (2,1)") // secrets.read
	db.Exec("INSERT OR IGNORE INTO role_permissions (role_id,permission_id) VALUES (2,2)") // secrets.write
	db.Exec("INSERT OR IGNORE INTO role_permissions (role_id,permission_id) VALUES (2,5)") // users.read

	// Approver user (holds global admin role). username_folded/email_folded
	// are the columns GetUserByUsername/GetUserByEmail actually query (#1642);
	// both values here are already pure-lowercase ASCII.
	require.NoError(t, db.Exec("INSERT INTO users (id,username,username_folded,email,email_folded) VALUES (10,'approver','approver','approver@example.com','approver@example.com')").Error)
	approverID = 10
	// Grant approver the admin role at the project scope.
	require.NoError(t, db.Exec("INSERT INTO user_roles (user_id,role_id,project_id) VALUES (10,1,?)", projectID).Error)

	// Requester user (no role yet).
	require.NoError(t, db.Exec("INSERT INTO users (id,username,username_folded,email,email_folded) VALUES (11,'requester','requester','requester@example.com','requester@example.com')").Error)
	requesterID = 11

	return
}

// seedPendingRequest creates one pending AccessRequest and returns its ID.
func seedPendingRequest(t *testing.T, k *KeyorixCore, projectID, userID uint, role string) uint {
	t.Helper()
	req, err := k.storage.CreateAccessRequest(context.Background(), &models.AccessRequest{
		ProjectID:     projectID,
		UserID:        userID,
		SuggestedRole: role,
		State:         AccessRequestPending,
		CreatedAt:     time.Now(),
	})
	require.NoError(t, err)
	return req.ID
}

func TestBulkApproveAccessRequests_SuccessPath(t *testing.T) {
	t.Parallel()
	k, _, approverID, requesterID, projectID := setupBulkAccessDB(t)
	ctx := context.Background()

	reqID := seedPendingRequest(t, k, projectID, requesterID, "editor")

	result, err := k.BulkApproveAccessRequests(ctx, []uint{reqID}, approverID, 0)
	require.NoError(t, err)
	require.Contains(t, result.Approved, reqID, "request must be in the approved list")
	require.Empty(t, result.Failed, "no failures expected")
}

func TestBulkRejectAccessRequests_SuccessPath(t *testing.T) {
	t.Parallel()
	k, _, approverID, requesterID, projectID := setupBulkAccessDB(t)
	ctx := context.Background()

	reqID := seedPendingRequest(t, k, projectID, requesterID, "editor")

	result, err := k.BulkRejectAccessRequests(ctx, []uint{reqID}, approverID, 0, "you are not qualified")
	require.NoError(t, err)
	require.Contains(t, result.Rejected, reqID, "request must be in the rejected list")
	require.Empty(t, result.Failed, "no failures expected")
}

// TestBulkApproveAccessRequests_AtBatchLimit_RealApprovals proves the new
// maxBulkAccessRequestBatchSize cap is a pure size gate, not a regression on
// legitimate use: a batch of exactly the cap size goes through the FULL real
// approval chain (role lookup, role grant, audit) against a real SQLite-backed
// core and every single request succeeds, exactly as it did before the cap
// was added.
func TestBulkApproveAccessRequests_AtBatchLimit_RealApprovals(t *testing.T) {
	t.Parallel()
	k, db, approverID, _, projectID := setupBulkAccessDB(t)
	ctx := context.Background()

	// Each request needs a DISTINCT requester: granting the same role to the
	// same user twice fails with "Role already assigned" (correct, unrelated
	// pre-existing behavior), which would make every request after the first
	// fail here for a reason that has nothing to do with the batch-size cap.
	ids := make([]uint, maxBulkAccessRequestBatchSize)
	for i := range ids {
		userID := uint(1000 + i)
		username := fmt.Sprintf("requester%d", i)
		email := fmt.Sprintf("requester%d@example.com", i)
		require.NoError(t, db.Exec(
			"INSERT INTO users (id,username,username_folded,email,email_folded) VALUES (?,?,?,?,?)",
			userID, username, username, email, email,
		).Error)
		ids[i] = seedPendingRequest(t, k, projectID, userID, "editor")
	}

	result, err := k.BulkApproveAccessRequests(ctx, ids, approverID, 0)
	require.NoError(t, err)
	require.Empty(t, result.Failed, "no failures expected at exactly the cap")
	require.Len(t, result.Approved, maxBulkAccessRequestBatchSize)
}
