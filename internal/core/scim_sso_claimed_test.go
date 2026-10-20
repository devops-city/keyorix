package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// #3418: SCIM ownership must not be shared with the SSO scheme. resolveSSOUser
// writes external_id = sso:<provider>:<sub> onto a NATIVE account the first time it
// signs in through SSO, which used to make it pass every SCIM ownership guard
// (ExternalID != ""). The family below drives every SCIM entry point with an
// SSO-claimed native admin AND an SSO-claimed non-admin, and with a SCIM-created
// account as the positive control (its behavior must not change).
const (
	ssoClaimedAdminID = uint(2)
	ssoClaimedUserID  = uint(3)
	scimCreatedID     = uint(4)
)

func seedSSOClaimedFixture(t *testing.T, db *gorm.DB) {
	t.Helper()
	mk := func(id uint, name, ext string) {
		require.NoError(t, db.Create(&models.User{
			ID: id, Username: name, UsernameFolded: name, Email: name + "@x.io", EmailFolded: name + "@x.io",
			DisplayName: name, IsActive: true, AccountState: AccountActive, ExternalID: ext,
		}).Error)
	}
	mk(1, "root", "") // second native admin so the last-admin guard is not what refuses
	mk(ssoClaimedAdminID, "alice", ssoExternalID("corp", "sub-alice"))
	mk(ssoClaimedUserID, "bob", ssoExternalID("corp", "sub-bob"))
	mk(scimCreatedID, "carol", "okta|carol")
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 10}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: ssoClaimedAdminID, RoleID: 10}).Error)
}

func TestSCIMEntryPoints_SSOClaimedAccountIsNotSCIMManaged(t *testing.T) {
	t.Parallel()
	const notManaged = "not a SCIM-managed account"
	for _, tc := range []struct {
		name string
		id   uint
	}{{"sso-claimed native admin", ssoClaimedAdminID}, {"sso-claimed non-admin", ssoClaimedUserID}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, db := newSCIMGuardCore(t)
			ctx := context.Background()
			seedSSOClaimedFixture(t, db)
			before := loadUser(t, db, tc.id)

			_, err := c.GetSCIMUser(ctx, tc.id)
			require.ErrorContains(t, err, notManaged, "GetSCIMUser")

			off, newEmail, newName := false, "rewritten@evil.test", "Mallory"
			_, err = c.UpdateSCIMUser(ctx, 9, tc.id, nil, nil, &off)
			require.ErrorContains(t, err, notManaged, "UpdateSCIMUser active=false")
			_, err = c.UpdateSCIMUser(ctx, 9, tc.id, nil, &newEmail, nil)
			require.ErrorContains(t, err, notManaged, "UpdateSCIMUser email rewrite")
			_, err = c.UpdateSCIMUser(ctx, 9, tc.id, &newName, nil, nil)
			require.ErrorContains(t, err, notManaged, "UpdateSCIMUser displayName")

			err = c.DeprovisionSCIMUser(ctx, 9, tc.id)
			require.ErrorContains(t, err, notManaged, "DeprovisionSCIMUser")

			after := loadUser(t, db, tc.id)
			require.Equal(t, before.Email, after.Email)
			require.Equal(t, before.DisplayName, after.DisplayName)
			require.Equal(t, before.ExternalID, after.ExternalID)
			require.True(t, after.IsActive)
			require.Equal(t, AccountActive, after.AccountState)
			require.False(t, after.DeletedAt.Valid, "must not be soft-deleted")

			// Group membership: every SCIM group entry point refuses the id.
			_, err = c.ProvisionSCIMGroup(ctx, 9, "Eng", []uint{tc.id})
			require.Error(t, err, "ProvisionSCIMGroup")
			g, err := c.ProvisionSCIMGroup(ctx, 9, "Eng2", []uint{scimCreatedID})
			require.NoError(t, err, "control: a SCIM-created member is still accepted")
			_, err = c.ReplaceSCIMGroup(ctx, 9, g.ID, "Eng2", []uint{tc.id})
			require.Error(t, err, "ReplaceSCIMGroup")
			_, err = c.PatchSCIMGroup(ctx, 9, g.ID, nil, []uint{tc.id}, nil)
			require.Error(t, err, "PatchSCIMGroup add")
			var n int64
			require.NoError(t, db.Model(&models.UserGroup{}).Where("user_id = ?", tc.id).Count(&n).Error)
			require.Zero(t, n, "no SCIM group membership may be written for the SSO-claimed account")
		})
	}
}

func TestSCIMListAndFind_ExcludeSSOClaimedAccounts(t *testing.T) {
	t.Parallel()
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	seedSSOClaimedFixture(t, db)

	users, total, err := c.ListSCIMUsersPage(ctx, 1, 100)
	require.NoError(t, err)
	require.Equal(t, 1, total, "only the SCIM-created account is listed")
	require.Len(t, users, 1)
	require.Equal(t, scimCreatedID, users[0].ID)

	// The SCIM-created account still resolves and is still manageable (no change).
	got, err := c.GetSCIMUser(ctx, scimCreatedID)
	require.NoError(t, err)
	require.Equal(t, scimCreatedID, got.ID)
	off := false
	_, err = c.UpdateSCIMUser(ctx, 9, scimCreatedID, nil, nil, &off)
	require.NoError(t, err)

	// The handler's userName-filter path decides with the exported predicate.
	alice, err := c.FindSCIMUser(ctx, "", "alice@x.io")
	require.NoError(t, err)
	require.NotNil(t, alice)
	require.False(t, IsSCIMManaged(alice))
	carol, err := c.FindSCIMUser(ctx, "", "carol@x.io")
	require.NoError(t, err)
	require.True(t, IsSCIMManaged(carol))
}

func TestIsSCIMManaged(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		ext  string
		want bool
	}{
		{"", false},
		{"okta|carol", true},
		{"00u1abcd", true},
		{ssoExternalID("corp", "sub"), false},
		{ssoExternalID("corp", ""), false}, // claimed before the assertion carried a subject
	} {
		require.Equal(t, tc.want, IsSCIMManaged(&models.User{ExternalID: tc.ext}), "external_id %q", tc.ext)
	}
}

func loadUser(t *testing.T, db *gorm.DB, id uint) models.User {
	t.Helper()
	var u models.User
	require.NoError(t, db.Unscoped().First(&u, id).Error)
	return u
}
