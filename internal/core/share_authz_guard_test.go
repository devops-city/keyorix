// share_authz_guard_test.go — #2941 guard, core half. The share term lives in exactly
// one function (sharePermissionFor, share_authz.go); both per-secret decision
// functions must call it, and the actor-aware entry points must route human users
// to AuthorizeSecret. The transport halves (every per-secret REST route, every
// per-secret gRPC RPC) are server/http/share_authz_route_guard_test.go and
// server/grpc/services/share_authz_rpc_guard_test.go.
//
// Behavioural counterparts with real storage (so the guard is also watched failing on
// the actual decision, not only on source shape): TestShareTerm_* below. Mutation
// check (drop the share term from AuthorizeSecret → red) is recorded in the PR.
package core

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestShareTerm_DecisionFunctionsConsultIt(t *testing.T) {
	bodies := map[string]*ast.BlockStmt{}
	for _, file := range []string{"authz.go", "permissions.go"} {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, file, nil, 0)
		require.NoError(t, err)
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil {
				bodies[fd.Name.Name] = fd.Body
			}
		}
	}
	for _, fn := range []string{"AuthorizeSecretAction", "checkSecretPermission"} {
		require.Contains(t, bodies, fn)
		assert.True(t, bodyCalls(bodies[fn], "sharePermissionFor"),
			"%s must consult the share term (sharePermissionFor) — #2941", fn)
	}
	// The action-less entry points delegate to the action-aware ones (so they get the
	// share term with no action: read elevation only).
	assert.True(t, bodyCalls(bodies["AuthorizeSecret"], "AuthorizeSecretAction"), "AuthorizeSecret must delegate to AuthorizeSecretAction")
	assert.True(t, bodyCalls(bodies["CheckSecretPermission"], "checkSecretPermission"), "CheckSecretPermission must delegate to checkSecretPermission")
	for _, fn := range []string{"AuthorizeSecretPrincipal", "AuthorizeSecretPrincipalForSecret", "AuthorizeSecretPrincipalForSecretAction"} {
		require.Contains(t, bodies, fn)
		assert.True(t, bodyCalls(bodies[fn], "AuthorizeSecret") || bodyCalls(bodies[fn], "AuthorizeSecretAction") ||
			bodyCalls(bodies[fn], "AuthorizeSecretPrincipalForSecret") || bodyCalls(bodies[fn], "AuthorizeSecretPrincipalForSecretAction"),
			"%s must route human users through AuthorizeSecret(Action)", fn)
	}
}

func bodyCalls(body *ast.BlockStmt, name string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == name {
				found = true
			}
		}
		return !found
	})
	return found
}

// shareTermRig: a real LocalStorage with one secret in project 1 owned by user 9,
// user 2 a member of project 1 via a role that carries NO permissions (so any access
// it gets comes from a share), and user 3 a non-member.
func shareTermRig(t *testing.T) (*KeyorixCore, *gorm.DB, uint) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.ShareRecord{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.UserRole{}, &models.Role{}, &models.Permission{}, &models.RolePermission{}, &models.SecretACL{},
		&models.AuditEvent{}, &models.User{}, &models.Project{}, &models.Environment{},
	))
	require.NoError(t, db.Create(&models.Role{ID: 50, Name: "member-no-perms"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 50, ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.SecretNode{ID: 1, Name: "s", IsSecret: true, ProjectID: 1, EnvironmentID: 1, OwnerID: 9}).Error)
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	return c, db, 1
}

func TestShareTerm_AuthorizeSecret_MaxOfRoleAndShare(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	c, db, secretID := shareTermRig(t)
	ctx := context.Background()

	allowed := func(user uint, perm string) bool {
		ok, err := c.AuthorizeSecret(ctx, user, secretID, perm)
		require.NoError(t, err)
		return ok
	}
	// A secrets.write decision a share can make names an allowlisted action and runs
	// under a request recorder (the transports always provide one).
	allowedWrite := func(user uint) bool {
		rctx, _ := WithShareElevationRecorder(ctx)
		d, err := c.AuthorizeSecretAction(rctx, user, secretID, permSecretsWrite, SecretActionUpdate)
		require.NoError(t, err)
		return d.Allowed
	}
	assert.False(t, allowed(2, permSecretsRead), "member with a no-permission role and no share: denied")

	share := &models.ShareRecord{SecretID: secretID, OwnerID: 9, RecipientID: 2, Permission: "write"}
	require.NoError(t, db.Create(share).Error)
	assert.True(t, allowed(2, permSecretsRead), "write share grants read")
	assert.True(t, allowedWrite(2), "write share grants an allowlisted write")
	assert.False(t, allowed(2, permSecretsWrite), "a write decision that names no action is not elevated (#3001 follow-up)")
	for _, perm := range []string{permSecretsDelete, permSecretsManage, permRolesAssign} {
		assert.False(t, allowed(2, perm), "a share never grants %s", perm)
	}

	// A non-member's share grants nothing.
	require.NoError(t, db.Create(&models.ShareRecord{SecretID: secretID, OwnerID: 9, RecipientID: 3, Permission: "write"}).Error)
	assert.False(t, allowed(3, permSecretsRead), "shares never apply to non-members")

	// Expired grants nothing.
	past := time.Now().Add(-time.Minute)
	// ExpiresAt goes through Save() so ShareRecord's BeforeSave hook runs (the
	// BeforeSave-bypass guard, g1619, rejects raw writes to hooked columns).
	share.ExpiresAt = &past
	require.NoError(t, db.Save(share).Error)
	assert.False(t, allowedWrite(2), "an expired share grants nothing")

	// A corrupt level grants nothing (never reads as owner).
	share.ExpiresAt = nil
	require.NoError(t, db.Save(share).Error)
	require.NoError(t, db.Model(share).Update("permission", "owner").Error)
	assert.False(t, allowed(2, permSecretsRead), "a share level outside read|write grants nothing")

	// Revoked (deleted) grants nothing.
	require.NoError(t, db.Model(share).Update("permission", "write").Error)
	require.True(t, allowedWrite(2))
	require.NoError(t, db.Delete(share).Error)
	assert.False(t, allowedWrite(2), "revoke removes exactly the elevation")
}

func TestShareTerm_CheckSecretPermission_NonMemberShareGrantsNothing(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	c, db, secretID := shareTermRig(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.ShareRecord{SecretID: secretID, OwnerID: 9, RecipientID: 3, Permission: "write"}).Error)
	require.NoError(t, db.Create(&models.ShareRecord{SecretID: secretID, OwnerID: 9, RecipientID: 2, Permission: "write"}).Error)

	_, err := c.CheckSecretPermission(ctx, secretID, 3, PermissionRead)
	assert.Error(t, err, "a non-member's share must not pass the core permission check either")
	pc, err := c.EnforceSecretActionPermission(ctx, secretID, 2, SecretActionUpdate)
	require.NoError(t, err)
	assert.Equal(t, "direct_share", pc.Source)
	require.NotNil(t, pc.ShareID)
	_, err = c.CheckSecretPermission(ctx, secretID, 2, PermissionWrite)
	assert.ErrorIs(t, err, ErrShareActionNotElevated, "an action-less write check is not elevated, and says why")
	_, err = c.CheckSecretPermission(ctx, secretID, 2, PermissionOwner)
	assert.Error(t, err, "a write share never grants owner")
}
