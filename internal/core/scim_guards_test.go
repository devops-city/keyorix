package core

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func newSCIMGuardCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Session{}, &models.AuditEvent{}, &models.Project{}, &models.Environment{},
		&models.PersonalAccessToken{},
	))
	return NewKeyorixCore(store.NewLocalStorage(db)), db
}

func TestUpdateSCIMUser_RejectsEmailCollision(t *testing.T) {
	t.Parallel()
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	// EmailFolded is what the collision check's GetUserByEmail actually
	// queries (#1642); both addresses are already their own folded form.
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "admin", UsernameFolded: "admin", Email: "admin@x.io", EmailFolded: "admin@x.io", IsActive: true, AccountState: AccountActive}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "bob", UsernameFolded: "bob", Email: "bob@x.io", EmailFolded: "bob@x.io", IsActive: true, AccountState: AccountActive, ExternalID: "okta|bob"}).Error)

	adminEmail := "admin@x.io"
	_, err := c.UpdateSCIMUser(ctx, 9, 2, nil, &adminEmail, nil)
	require.Error(t, err, "SCIM must not overwrite user 2's email to collide with the admin's")
	assert.Contains(t, err.Error(), "already in use")
}

// TestUpdateSCIMUser_OwnershipCheckedBeforeEmailCollision is the #G14
// regression: the SCIM-ownership check must run BEFORE checkSCIMEmailCollision
// — otherwise a SCIM token holder could supply a NATIVE (non-SCIM) account's id
// together with a probe email and learn, from "email already in use" vs
// proceeding further, whether that email is registered to a different account —
// without ever having rights to touch the target id at all.
func TestUpdateSCIMUser_OwnershipCheckedBeforeEmailCollision(t *testing.T) {
	t.Parallel()
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	// user 1 is a NATIVE account (no ExternalID) — never provisioned via SCIM.
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "native-admin", Email: "native@x.io", IsActive: true, AccountState: AccountActive}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "someone-else", Email: "taken@x.io", IsActive: true, AccountState: AccountActive}).Error)

	// Probing with an email that DOES collide must fail with the SAME ownership
	// error as probing with one that doesn't — never "email already in use".
	collidingEmail := "taken@x.io"
	_, err := c.UpdateSCIMUser(ctx, 9, 1, nil, &collidingEmail, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a SCIM-managed account")
	assert.NotContains(t, err.Error(), "already in use")

	freeEmail := "nobody-has-this@x.io"
	_, err2 := c.UpdateSCIMUser(ctx, 9, 1, nil, &freeEmail, nil)
	require.Error(t, err2)
	assert.Equal(t, err.Error(), err2.Error(), "a colliding and a free probe email must be indistinguishable for a non-SCIM-managed target")
}

func TestUpdateSCIMUser_RefusesLastAdminDeactivation(t *testing.T) {
	t.Parallel()
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "root", IsActive: true, AccountState: AccountActive, ExternalID: "okta|root"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 10}).Error) // global admin

	no := false
	_, err := c.UpdateSCIMUser(ctx, 9, 1, nil, nil, &no)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "last install administrator")
}

// TestUpdateSCIMUser_RefusesLastAdminDeactivation_ViaGroupMembership is the
// unmapped-critical regression: guardLastAdminDeactivation previously scanned
// role assignments and treated ANY group-type admin-conferring assignment as
// "another admin survives," without checking whether the target itself was
// that group's only member. A target whose sole route to admin authority was
// membership in a single-member admin group was never recognized as the last
// admin, so SCIM could deactivate them and leave the install with zero admins.
func TestUpdateSCIMUser_RefusesLastAdminDeactivation_ViaGroupMembership(t *testing.T) {
	t.Parallel()
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "root", IsActive: true, AccountState: AccountActive, ExternalID: "okta|root"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 5, Name: "Keyorix-Admins"}).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 5, RoleID: 10}).Error) // group confers admin, globally
	require.NoError(t, db.Create(&models.UserGroup{UserID: 1, GroupID: 5}).Error)  // user 1 is the group's ONLY member

	no := false
	_, err := c.UpdateSCIMUser(ctx, 9, 1, nil, nil, &no)
	require.Error(t, err, "must refuse to deactivate the install's last admin even when their authority is entirely group-derived")
	assert.Contains(t, err.Error(), "last install administrator")
}

// TestUpdateSCIMUser_AllowsGroupAdminDeactivationWhenAnotherGroupMemberExists
// is the positive control: a group with more than one member still has a
// surviving admin route after one member is deactivated.
func TestUpdateSCIMUser_AllowsGroupAdminDeactivationWhenAnotherGroupMemberExists(t *testing.T) {
	t.Parallel()
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "root", IsActive: true, AccountState: AccountActive, ExternalID: "okta|root"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "root2", IsActive: true, AccountState: AccountActive}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 5, Name: "Keyorix-Admins"}).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 5, RoleID: 10}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 1, GroupID: 5}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 2, GroupID: 5}).Error)

	no := false
	off, err := c.UpdateSCIMUser(ctx, 9, 1, nil, nil, &no)
	require.NoError(t, err, "deactivating one of two admin-group members is allowed")
	assert.False(t, off.IsActive)
}

func TestUpdateSCIMUser_AllowsAdminDeactivationWhenAnotherExists(t *testing.T) {
	t.Parallel()
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "root", IsActive: true, AccountState: AccountActive, ExternalID: "okta|root"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "root2", IsActive: true, AccountState: AccountActive}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 10}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 10}).Error)

	no := false
	off, err := c.UpdateSCIMUser(ctx, 9, 1, nil, nil, &no)
	require.NoError(t, err, "deactivating one of two admins is allowed")
	assert.False(t, off.IsActive)
}

func TestPatchSCIMGroup_RefusesAddingMemberToAdminGroup(t *testing.T) {
	t.Parallel()
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "bob", IsActive: true, AccountState: AccountActive, ExternalID: "okta|bob"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 5, Name: "Keyorix-Admins"}).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 5, RoleID: 10}).Error) // group confers admin

	_, err := c.PatchSCIMGroup(ctx, 9, 5, nil, []uint{2}, nil)
	require.Error(t, err, "SCIM must not add a member to an admin-bearing group")
	assert.Contains(t, err.Error(), "administrative roles")
}

// TestUpdateSCIMUser_FailsClosedOnTransientEmailLookupError is the (#336) regression:
// GetUserByEmail returns a non-nil error BOTH when the email is genuinely unused AND on
// a real DB failure. The previous `eerr == nil && existing != nil && ...` guard treated
// any error identically to "no collision", silently skipping the uniqueness check on a
// transient error — reintroducing the exact vulnerability the check exists to prevent,
// on the same failure mode the sibling create-path fix (FindSCIMUser) is deliberately
// hardened against. Simulates a genuine storage failure (not the "user not found"
// sentinel text) via MockStorage and asserts the update is refused, not silently applied.
func TestUpdateSCIMUser_FailsClosedOnTransientEmailLookupError(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	ctx := context.Background()

	target := &models.User{ID: 2, Username: "bob", Email: "bob@x.io", IsActive: true, AccountState: AccountActive}
	ms.On("GetUser", ctx, uint(2)).Return(target, nil)
	// A genuine transient failure — NOT the "user not found" sentinel text — must fail
	// the whole update closed, not be treated as "email is unused".
	ms.On("GetUserByEmail", ctx, "new@x.io").Return(nil, errors.New("connection refused"))

	newEmail := "new@x.io"
	_, err := c.UpdateSCIMUser(ctx, 9, 2, nil, &newEmail, nil)
	require.Error(t, err, "a transient email-lookup failure must refuse the update, not silently apply it")
	assert.NotContains(t, err.Error(), "already in use",
		"this is a lookup failure, not a collision — the error must say so, not misreport a collision")

	// The write must never have been attempted.
	ms.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything)
}

// TestUpdateSCIMUser_ProceedsWhenEmailGenuinelyUnused confirms the #336 fix didn't turn
// the guard into an unconditional refusal: the ordinary "email not found" case (the
// sentinel GetUserByEmail actually returns for a genuinely-unused email) must still let
// the update proceed.
func TestUpdateSCIMUser_ProceedsWhenEmailGenuinelyUnused(t *testing.T) {
	t.Parallel()
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "bob", Email: "bob@x.io", IsActive: true, AccountState: AccountActive, ExternalID: "okta|bob"}).Error)

	newEmail := "unused@x.io"
	updated, err := c.UpdateSCIMUser(ctx, 9, 2, nil, &newEmail, nil)
	require.NoError(t, err)
	assert.Equal(t, "unused@x.io", updated.Email)
}

// TestGuardLastAdminDeactivation_FailsClosedOnIsGlobalAdminError is the (#337)
// regression: guardLastAdminDeactivation previously treated an IsGlobalAdmin lookup
// error identically to "confirmed not an admin" (`if err != nil || !isAdmin { return
// nil }`), silently permitting a SCIM deactivate/deprovision of the sole install admin
// on exactly the failure mode (a DB hiccup during this one check) the guard exists to
// protect against. Simulates a genuine storage failure underneath IsGlobalAdmin via
// MockStorage and asserts both call sites — UpdateSCIMUser(active:false) and
// DeprovisionSCIMUser — now refuse the operation instead of silently permitting it.
func TestGuardLastAdminDeactivation_FailsClosedOnIsGlobalAdminError(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	dbErr := errors.New("connection pool exhausted")

	t.Run("UpdateSCIMUser deactivate", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		ctx := context.Background()
		target := &models.User{ID: 1, Username: "root", IsActive: true, AccountState: AccountActive}
		ms.On("GetUser", ctx, uint(1)).Return(target, nil)
		ms.On("GetUserRoleIDsAt", ctx, uint(1), Scope{}).Return(nil, dbErr)

		no := false
		_, err := c.UpdateSCIMUser(ctx, 9, 1, nil, nil, &no)
		require.Error(t, err, "an IsGlobalAdmin lookup failure must refuse the deactivation, not silently permit it")
		ms.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything)
	})

	t.Run("DeprovisionSCIMUser", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		ctx := context.Background()
		target := &models.User{ID: 1, Username: "root", IsActive: true, AccountState: AccountActive}
		ms.On("GetUser", ctx, uint(1)).Return(target, nil)
		ms.On("GetUserRoleIDsAt", ctx, uint(1), Scope{}).Return(nil, dbErr)

		err := c.DeprovisionSCIMUser(ctx, 9, 1)
		require.Error(t, err, "an IsGlobalAdmin lookup failure must refuse the deprovision, not silently permit it")
		ms.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything)
		ms.AssertNotCalled(t, "WithTransaction", mock.Anything, mock.Anything)
	})
}

// TestLocalStorage_UpdateUser_DuplicateEmailWrapsSentinel is the storage-layer half of the
// (#120/#218) regression: UpdateUser must translate a DB-level email-uniqueness violation
// into the clean ErrDuplicateEmail sentinel (mirroring CreateUser), not a raw
// constraint-violation error. See concurrency_scim_update_email_test.go for the full
// concurrent-UpdateSCIMUser race regression.
func TestLocalStorage_UpdateUser_DuplicateEmailWrapsSentinel(t *testing.T) {
	t.Parallel()
	c, db := newSCIMGuardCore(t)
	_ = c
	// Install the same partial unique index production installs get (mirrors
	// factory.go's ensureUserEmailIndex — #1642: on email_folded, not a
	// SQL-side LOWER(email) expression), since newSCIMGuardCore's in-memory
	// AutoMigrate doesn't run the storage-factory migration path that creates it.
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_users_email_folded_active "+
		"ON users (email_folded) WHERE deleted_at IS NULL AND email <> ''").Error)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", UsernameFolded: "alice", Email: "alice@x.io", EmailFolded: "alice@x.io", IsActive: true, AccountState: AccountActive}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "bob", UsernameFolded: "bob", Email: "bob@x.io", EmailFolded: "bob@x.io", IsActive: true, AccountState: AccountActive}).Error)

	ls := store.NewLocalStorage(db)
	u2, err := ls.GetUser(ctx, 2)
	require.NoError(t, err)
	u2.Email = "alice@x.io" // collides with user 1
	u2.EmailFolded = "alice@x.io"
	_, err = ls.UpdateUser(ctx, u2)
	require.Error(t, err)
	assert.True(t, errors.Is(err, corestorage.ErrDuplicateEmail),
		"a DB-level email collision on UpdateUser must be wrapped in the ErrDuplicateEmail sentinel")
}

// --- #167: SCIM group membership mutations must refuse non-SCIM-managed targets ---
//
// None of ProvisionSCIMGroup/ReplaceSCIMGroup/PatchSCIMGroup checked the target
// member's ExternalID before AddUserToGroup, so a valid SCIM group-provisioning
// token could add ANY native user — including one the attacker already controls —
// into a group. If that group carries an admin-conferring role, membership alone
// grants the role immediately. Each function below is exercised with both a
// SCIM-managed target (positive control — must succeed) and a non-SCIM-managed
// native target (negative control — must be refused, and membership must not
// take effect).

func TestProvisionSCIMGroup_AllowsSCIMManagedMember(t *testing.T) {
	t.Parallel()
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", IsActive: true, AccountState: AccountActive, ExternalID: "okta|alice"}).Error)

	group, err := c.ProvisionSCIMGroup(ctx, 9, "Engineering", []uint{1})
	require.NoError(t, err)
	members, err := c.storage.ListGroupMembers(ctx, group.ID)
	require.NoError(t, err)
	require.Len(t, members, 1)
	assert.Equal(t, uint(1), members[0].ID)
}

func TestProvisionSCIMGroup_RefusesNonSCIMManagedMember(t *testing.T) {
	t.Parallel()
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	// Native user: no ExternalID — never SCIM-provisioned.
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "native", IsActive: true, AccountState: AccountActive}).Error)

	group, err := c.ProvisionSCIMGroup(ctx, 9, "Engineering", []uint{1})
	require.Error(t, err, "SCIM must not add a non-SCIM-managed native user at group creation")
	assert.Contains(t, err.Error(), "SCIM-managed")
	assert.Nil(t, group)

	// No group should have been left dangling with the rejected membership.
	var count int64
	require.NoError(t, db.Model(&models.Group{}).Where("name = ?", "Engineering").Count(&count).Error)
	assert.Zero(t, count, "the group must not be created when the member set is refused")
}

func TestReplaceSCIMGroup_AllowsSCIMManagedMember(t *testing.T) {
	t.Parallel()
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", IsActive: true, AccountState: AccountActive, ExternalID: "okta|alice"}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 5, Name: "Engineering"}).Error)

	_, err := c.ReplaceSCIMGroup(ctx, 9, 5, "", []uint{1})
	require.NoError(t, err)
	members, err := c.storage.ListGroupMembers(ctx, 5)
	require.NoError(t, err)
	require.Len(t, members, 1)
	assert.Equal(t, uint(1), members[0].ID)
}

func TestReplaceSCIMGroup_RefusesNonSCIMManagedMember(t *testing.T) {
	t.Parallel()
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "native", IsActive: true, AccountState: AccountActive}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 5, Name: "Engineering"}).Error)

	_, err := c.ReplaceSCIMGroup(ctx, 9, 5, "", []uint{1})
	require.Error(t, err, "SCIM must not add a non-SCIM-managed native user via PUT")
	assert.Contains(t, err.Error(), "SCIM-managed")

	members, err := c.storage.ListGroupMembers(ctx, 5)
	require.NoError(t, err)
	assert.Empty(t, members, "the refused member must not have been added")
}

func TestPatchSCIMGroup_AllowsSCIMManagedMember(t *testing.T) {
	t.Parallel()
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", IsActive: true, AccountState: AccountActive, ExternalID: "okta|alice"}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 5, Name: "Engineering"}).Error)

	_, err := c.PatchSCIMGroup(ctx, 9, 5, nil, []uint{1}, nil)
	require.NoError(t, err)
	members, err := c.storage.ListGroupMembers(ctx, 5)
	require.NoError(t, err)
	require.Len(t, members, 1)
	assert.Equal(t, uint(1), members[0].ID)
}

func TestPatchSCIMGroup_RefusesNonSCIMManagedMember(t *testing.T) {
	t.Parallel()
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "native", IsActive: true, AccountState: AccountActive}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 5, Name: "Engineering"}).Error)

	_, err := c.PatchSCIMGroup(ctx, 9, 5, nil, []uint{1}, nil)
	require.Error(t, err, "SCIM must not add a non-SCIM-managed native user via PATCH")
	assert.Contains(t, err.Error(), "SCIM-managed")

	members, err := c.storage.ListGroupMembers(ctx, 5)
	require.NoError(t, err)
	assert.Empty(t, members, "the refused member must not have been added")
}
