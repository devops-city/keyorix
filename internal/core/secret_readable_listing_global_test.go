// secret_readable_listing_global_test.go — follow-up item 1: a GLOBAL secrets.read
// holder's listing and count must equal everything they can read.
//
// Tier 1 of ListReadableSecrets delegated to ListSecretsWithSharingInfo, which is
// owned ∪ shared ∪ ACL-granted — NOT "everything the grant authorizes". So a caller
// holding global secrets.read who owns nothing and holds no share/ACL saw an empty
// list, while being authorized to read every secret in the deployment and able to GET
// any of them individually. #2780 is the same defect one tier over, and preserving
// tier 1 verbatim as "unchanged original behaviour" carried it forward.
//
// Found by Andrei's review of #2859, not by a test — and worth recording why no test
// caught it: #2859's own e2e equality assertion for the admin persona
// (dashboard.totalSecrets == GET /secrets total) PASSED, because that fixture's admin
// had created every secret and therefore owned them all. Both sides were wrong by the
// same amount. The fixture below deliberately gives the global reader ownership of
// NOTHING, which is the only shape that can tell the two definitions apart.
package core

import (
	"context"
	"fmt"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// globalReaderFixture seeds two projects with secrets owned by SOMEONE ELSE, and a
// reader (user 1) whose only grant is supplied by the caller.
func globalReaderFixture(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{},
		&models.Permission{}, &models.RolePermission{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.SecretNode{},
		&models.SecretACL{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.AuditEvent{},
	))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "reader", Email: "reader@example.com"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "author", Email: "author@example.com"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "secrets.read", Resource: "secrets", Action: "read"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "global-reader-fixture-reader"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 1, PermissionID: 1}).Error)

	for pid, name := range map[uint]string{1: "alpha", 2: "beta"} {
		require.NoError(t, db.Create(&models.Project{ID: pid, Name: name}).Error)
		require.NoError(t, db.Create(&models.Environment{ID: pid * 100, ProjectID: pid, Name: "prod"}).Error)
		for i := range 3 {
			require.NoError(t, db.Create(&models.SecretNode{
				Name: fmt.Sprintf("%s-%02d", name, i), ProjectID: pid, EnvironmentID: pid * 100,
				// Owned and authored by user 2, NOT the reader. No share, no ACL.
				IsSecret: true, CreatedBy: "author", OwnerID: 2,
			}).Error)
		}
	}
	return NewKeyorixCore(store.NewLocalStorage(db)), db
}

// TestListReadableSecrets_GlobalReaderSeesEverythingTheyCanRead is the item-1
// regression. Red before the fix: tier 1 returned 0 for a global reader who owns
// nothing. Green after: 6, every secret the grant authorizes.
func TestListReadableSecrets_GlobalReaderSeesEverythingTheyCanRead(t *testing.T) {
	t.Parallel()
	c, db := globalReaderFixture(t)
	ctx := context.Background()
	// The global grant: project_id = 0, environment_id = 0.
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 0}).Error)

	// Precondition: the reader really is authorized at global scope, so the assertion
	// below is about the LISTING disagreeing with the grant, not about a missing grant.
	allowed, err := c.AuthorizePrincipal(ctx, ActorTypeUser, 1, "secrets.read", Scope{})
	require.NoError(t, err)
	require.True(t, allowed, "fixture precondition: the reader holds global secrets.read")

	resp, err := c.ListReadableSecrets(ctx, 1, 1, &models.SecretListFilter{Page: 1, PageSize: 50})
	require.NoError(t, err)
	assert.Equal(t, int64(6), resp.Total,
		"a global secrets.read holder can read every secret, so the listing must show every secret — "+
			"owned ∪ shared ∪ ACL-granted is a DIFFERENT set, and it is empty for a reader who owns nothing")
	assert.Len(t, resp.Secrets, 6)

	counted, exact, err := c.CountReadableSecrets(ctx, 1, 1)
	require.NoError(t, err)
	assert.True(t, exact, "nothing is bounded here, so the count is exact")
	assert.Equal(t, resp.Total, counted, "the count is the listing's total, as always")
}

// TestListReadableSecrets_NoGrantGlobalReaderStillSeesNothing is the invariant that
// must hold before and after: widening tier 1 must not make the listing generous to a
// caller who holds no grant at all. The world is non-empty, so this is not vacuous.
func TestListReadableSecrets_NoGrantGlobalReaderStillSeesNothing(t *testing.T) {
	t.Parallel()
	c, _ := globalReaderFixture(t)
	ctx := context.Background()
	// No UserRole row at all for user 1.

	resp, err := c.ListReadableSecrets(ctx, 1, 1, &models.SecretListFilter{Page: 1, PageSize: 50})
	require.NoError(t, err)
	assert.Equal(t, int64(0), resp.Total,
		"six secrets exist and this caller is authorized for none of them")
}

// TestListReadableSecrets_ACLOnlyReaderStillSeesOnlyTheirGrant pins tier 3, which
// must NOT be widened: a caller with no role-granted scope sees exactly the secrets
// they own or hold a per-secret ACL/share grant for. Changing tier 1 must not leak
// into this path — if it did, an ACL-only caller would start seeing everything.
func TestListReadableSecrets_ACLOnlyReaderStillSeesOnlyTheirGrant(t *testing.T) {
	t.Parallel()
	c, db := globalReaderFixture(t)
	ctx := context.Background()
	// No role grant anywhere; one per-secret ACL grant on a single secret.
	var one models.SecretNode
	require.NoError(t, db.Where("name = ?", "alpha-00").First(&one).Error)
	require.NoError(t, db.Create(&models.SecretACL{
		SecretID: one.ID, UserID: 1, Permissions: `["secrets.read"]`, GrantedBy: 2,
	}).Error)

	resp, err := c.ListReadableSecrets(ctx, 1, 1, &models.SecretListFilter{Page: 1, PageSize: 50})
	require.NoError(t, err)
	assert.Equal(t, int64(1), resp.Total,
		"tier 3 is owned ∪ shared ∪ ACL-granted and must stay that way — exactly the one granted secret")
	if len(resp.Secrets) == 1 {
		assert.Equal(t, "alpha-00", resp.Secrets[0].Name)
	}
}

// TestListReadableSecrets_GlobalReaderStillGetsSharingMetadata checks the half that
// made tier 1 tempting to leave alone: the response must still carry per-secret
// sharing/ownership metadata, which is why the fix uses
// ListSecretsInScopeWithSharingInfo rather than the plain in-scope listing.
func TestListReadableSecrets_GlobalReaderStillGetsSharingMetadata(t *testing.T) {
	t.Parallel()
	c, db := globalReaderFixture(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 0}).Error)
	// Make the reader the owner of one secret, so an ownership flag has something to
	// be true about.
	require.NoError(t, db.Model(&models.SecretNode{}).Where("name = ?", "beta-00").
		Update("owner_id", 1).Error)

	resp, err := c.ListReadableSecrets(ctx, 1, 1, &models.SecretListFilter{Page: 1, PageSize: 50})
	require.NoError(t, err)
	require.Equal(t, int64(6), resp.Total)

	var ownedSeen bool
	for _, s := range resp.Secrets {
		require.NotNil(t, s.SecretNode, "every row carries its secret node")
		if s.Name == "beta-00" && s.IsOwnedByUser {
			ownedSeen = true
		}
	}
	assert.True(t, ownedSeen,
		"the global reader's own secret must still be flagged as owned — widening tier 1 must not drop "+
			"the sharing metadata the UI renders")
}
