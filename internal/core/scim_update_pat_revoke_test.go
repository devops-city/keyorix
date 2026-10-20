package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func newSCIMUpdatePATFixture(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.Session{}, &models.PersonalAccessToken{}, &models.AuditEvent{},
		&models.Role{}, &models.UserRole{}, &models.Project{}, &models.Environment{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{}))
	return NewKeyorixCore(store.NewLocalStorage(db)), db
}

// #3419: a SCIM active=false (PUT or PATCH both reach UpdateSCIMUser) must revoke the
// user's PATs, as DeprovisionSCIMUser does (#2855); otherwise an IdP re-enable hands
// them back. Asserts the rows, not only inertness, and then the consequence.
func TestUpdateSCIMUser_DeactivateRevokesPATs(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"put", "patch"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c, db := newSCIMUpdatePATFixture(t)
			ctx := context.Background()
			require.NoError(t, db.Create(&models.User{ID: 1, Username: "carol", IsActive: true, AccountState: AccountActive, ExternalID: "okta|carol"}).Error)
			raw := patPrefix + "scim-update-regression-token-" + name
			require.NoError(t, db.Create(&models.PersonalAccessToken{ID: 1, UserID: 1, Name: "ci", TokenHash: sha256Hex(raw)}).Error)
			_, _, _, _, err := c.ValidatePATToken(ctx, raw)
			require.NoError(t, err, "precondition: PAT valid while the account is live")

			off, on := false, true
			var dn, em *string // PUT carries profile fields, PATCH only active
			if name == "put" {
				d, e := "Carol", "carol@example.test"
				dn, em = &d, &e
			}
			_, err = c.UpdateSCIMUser(ctx, 2, 1, dn, em, &off)
			require.NoError(t, err)

			var unrevoked int64
			require.NoError(t, db.Model(&models.PersonalAccessToken{}).
				Where("user_id = ? AND revoked = ?", 1, false).Count(&unrevoked).Error)
			require.Zero(t, unrevoked, "deactivation must REVOKE the PAT rows, not merely leave them inert")

			_, err = c.UpdateSCIMUser(ctx, 2, 1, nil, nil, &on)
			require.NoError(t, err)
			_, _, _, _, err = c.ValidatePATToken(ctx, raw)
			require.ErrorIs(t, err, ErrPATRevoked, "re-enable must not hand the PAT back")
		})
	}
}

// A profile-only update, or active=true on a live user, must not touch PATs.
func TestUpdateSCIMUser_NonDeactivatingUpdateKeepsPATs(t *testing.T) {
	t.Parallel()
	c, db := newSCIMUpdatePATFixture(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "dan", IsActive: true, AccountState: AccountActive, ExternalID: "okta|dan"}).Error)
	raw := patPrefix + "scim-update-keeps-token"
	require.NoError(t, db.Create(&models.PersonalAccessToken{ID: 1, UserID: 1, Name: "ci", TokenHash: sha256Hex(raw)}).Error)

	dn, on := "Dan D", true
	_, err := c.UpdateSCIMUser(ctx, 2, 1, &dn, nil, &on)
	require.NoError(t, err)
	_, _, _, _, err = c.ValidatePATToken(ctx, raw)
	require.NoError(t, err, "a non-deactivating SCIM update must leave PATs alone")
}

// A user with no PATs deactivates and reactivates without error.
func TestUpdateSCIMUser_DeactivateWithoutPATs(t *testing.T) {
	t.Parallel()
	c, db := newSCIMUpdatePATFixture(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "erin", IsActive: true, AccountState: AccountActive, ExternalID: "okta|erin"}).Error)
	off, on := false, true
	_, err := c.UpdateSCIMUser(ctx, 2, 1, nil, nil, &off)
	require.NoError(t, err)
	_, err = c.UpdateSCIMUser(ctx, 2, 1, nil, nil, &on)
	require.NoError(t, err)
}
