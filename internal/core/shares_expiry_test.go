package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// newSharesExpiryFixture spins up an in-memory core with an owner (1) and two recipients
// (2, 3), one owned secret, and a controllable clock seeded to the real wall clock.
// Since #1983, the storage listing/permission queries (internal/storage/store/
// local_sharing.go) take an explicit now parameter sourced from the SAME
// c.shareEffectiveNow() core-level enforcement (CheckSecretPermission) uses — the two
// can no longer disagree regardless of what c.now is overridden to after fixture setup
// (see share_listing_split_clock_regression_test.go). The base is still seeded to the
// real wall clock here only because most of this file's sub-tests don't override it at
// all. Returns the core, secret ID, base now, db.
func newSharesExpiryFixture(t *testing.T) (*KeyorixCore, uint, time.Time, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())

	// Private in-memory DB (no shared cache) so each fixture is fully isolated; a
	// single connection keeps the one :memory: database alive for the test's duration.
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)

	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.SecretVersion{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{},
		&models.AuditEvent{}, &models.User{}, &models.Group{}, &models.UserGroup{},
		&models.UserRole{}, &models.GroupRole{},
	))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "owner@test.com"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "recip2", Email: "recip2@test.com"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 3, Username: "recip3", Email: "recip3@test.com"}).Error)
	// ShareSecret checks IsProjectMember before creating the share record; seed
	// project membership for both recipients so that check passes. The owner (1)
	// also needs live project membership — requireLiveOwnerAuthority now re-checks
	// it on every owner-gated sharing call (RBAC-001), mirroring CheckSecretPermission.
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 1, ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 3, RoleID: 1, ProjectID: 1}).Error)

	now := time.Now()
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }}

	secret, err := c.storage.CreateSecret(context.Background(), &models.SecretNode{
		Name: "s", ProjectID: 1, EnvironmentID: 1, Type: "password", OwnerID: 1, IsSecret: true,
		CreatedAt: now, UpdatedAt: now,
	})
	require.NoError(t, err)
	return c, secret.ID, now, db
}

func TestShareExpiry_Enforcement(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("active future-dated share authorizes and lists", func(t *testing.T) {
		c, secretID, now, _ := newSharesExpiryFixture(t)
		future := now.Add(time.Hour)
		_, err := c.ShareSecret(ctx, &ShareSecretRequest{
			SecretID: secretID, RecipientID: 2, Permission: "read", SharedBy: 1, ExpiresAt: &future,
		})
		require.NoError(t, err)

		_, err = c.CheckSecretPermission(ctx, secretID, 2, PermissionRead)
		require.NoError(t, err, "an unexpired share must grant read")

		shared, err := c.ListSharedSecrets(ctx, 2)
		require.NoError(t, err)
		assert.Len(t, shared, 1)
	})

	t.Run("expired share denies (core enforcement via clock)", func(t *testing.T) {
		c, secretID, now := mustShare(t)
		// Create with a future expiry (passes validation), then advance the clock past it.
		exp := now.Add(time.Minute)
		_, err := c.ShareSecret(ctx, &ShareSecretRequest{
			SecretID: secretID, RecipientID: 2, Permission: "read", SharedBy: 1, ExpiresAt: &exp,
		})
		require.NoError(t, err)

		c.now = func() time.Time { return now.Add(time.Hour) }
		_, err = c.CheckSecretPermission(ctx, secretID, 2, PermissionRead)
		require.Error(t, err, "an expired share must NOT grant access")
	})

	t.Run("expired share is hidden from the shared-with-me listing", func(t *testing.T) {
		c, secretID, now, db := newSharesExpiryFixture(t)
		// Insert an already-expired row directly (ShareSecret would reject a past expiry).
		past := now.Add(-time.Minute)
		require.NoError(t, db.Create(&models.ShareRecord{
			SecretID: secretID, OwnerID: 1, RecipientID: 2, Permission: "read", ExpiresAt: &past,
		}).Error)

		shared, err := c.ListSharedSecrets(ctx, 2)
		require.NoError(t, err)
		assert.Empty(t, shared, "an expired share must not surface in the shared-with-me list")

		_, err = c.CheckSecretPermission(ctx, secretID, 2, PermissionRead)
		require.Error(t, err, "an expired share must not authorize")
	})

	t.Run("share with a past expiry is rejected at creation", func(t *testing.T) {
		c, secretID, now, _ := newSharesExpiryFixture(t)
		past := now.Add(-time.Minute)
		_, err := c.ShareSecret(ctx, &ShareSecretRequest{
			SecretID: secretID, RecipientID: 2, Permission: "read", SharedBy: 1, ExpiresAt: &past,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "future")
	})

	t.Run("permanent share (nil expiry) keeps authorizing", func(t *testing.T) {
		c, secretID, now, _ := newSharesExpiryFixture(t)
		_, err := c.ShareSecret(ctx, &ShareSecretRequest{
			SecretID: secretID, RecipientID: 2, Permission: "read", SharedBy: 1,
		})
		require.NoError(t, err)
		c.now = func() time.Time { return now.Add(1000 * time.Hour) }
		_, err = c.CheckSecretPermission(ctx, secretID, 2, PermissionRead)
		require.NoError(t, err)
	})
}

func TestUpdateShareExpiry(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// share creates a permanent read share of the fixture secret to recipient 2 and
	// returns the core, the share, and the base clock.
	share := func(t *testing.T) (*KeyorixCore, *models.ShareRecord, time.Time) {
		c, secretID, now, _ := newSharesExpiryFixture(t)
		rec, err := c.ShareSecret(ctx, &ShareSecretRequest{
			SecretID: secretID, RecipientID: 2, Permission: "read", SharedBy: 1,
		})
		require.NoError(t, err)
		return c, rec, now
	}

	t.Run("sets an expiry on a permanent share", func(t *testing.T) {
		c, rec, now := share(t)
		require.Nil(t, rec.ExpiresAt)
		exp := now.Add(time.Hour)
		updated, err := c.UpdateSharePermission(ctx, &UpdateShareRequest{
			ShareID: rec.ID, Permission: "read", UpdatedBy: 1, ExpiresAt: &exp,
		})
		require.NoError(t, err)
		require.NotNil(t, updated.ExpiresAt)
		assert.True(t, updated.ExpiresAt.Equal(exp))
	})

	t.Run("clears an expiry (back to permanent)", func(t *testing.T) {
		c, rec, now := share(t)
		exp := now.Add(time.Hour)
		_, err := c.UpdateSharePermission(ctx, &UpdateShareRequest{
			ShareID: rec.ID, Permission: "read", UpdatedBy: 1, ExpiresAt: &exp,
		})
		require.NoError(t, err)
		updated, err := c.UpdateSharePermission(ctx, &UpdateShareRequest{
			ShareID: rec.ID, Permission: "read", UpdatedBy: 1, ClearExpiry: true,
		})
		require.NoError(t, err)
		assert.Nil(t, updated.ExpiresAt, "clear_expiry should make the share permanent")
	})

	t.Run("preserves expiry when the request changes only the permission", func(t *testing.T) {
		c, rec, now := share(t)
		exp := now.Add(time.Hour)
		_, err := c.UpdateSharePermission(ctx, &UpdateShareRequest{
			ShareID: rec.ID, Permission: "read", UpdatedBy: 1, ExpiresAt: &exp,
		})
		require.NoError(t, err)
		// A permission-only update must not silently drop the expiry.
		updated, err := c.UpdateSharePermission(ctx, &UpdateShareRequest{
			ShareID: rec.ID, Permission: "write", UpdatedBy: 1,
		})
		require.NoError(t, err)
		assert.Equal(t, "write", updated.Permission)
		require.NotNil(t, updated.ExpiresAt, "permission-only update must preserve the expiry")
		assert.True(t, updated.ExpiresAt.Equal(exp))
	})

	t.Run("rejects a past expiry", func(t *testing.T) {
		c, rec, now := share(t)
		past := now.Add(-time.Minute)
		_, err := c.UpdateSharePermission(ctx, &UpdateShareRequest{
			ShareID: rec.ID, Permission: "read", UpdatedBy: 1, ExpiresAt: &past,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "future")
	})
}

// TestReShareTightensExpiry is the regression test for #282: re-sharing an
// already-shared secret (the CreateShareRecord upsert path, reached from both
// ShareSecret and ShareSecretWithGroup) must persist a newly-requested ExpiresAt
// onto the existing row — not silently drop it — so an owner can time-bound or
// shorten an existing indefinite grant. Uses the real sqlite-backed LocalStorage
// fixture (no mocks) so the assertions exercise the actual upsert SQL, not a
// hand-rolled double.
func TestReShareTightensExpiry(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("direct share: re-sharing a permanent grant with an expiry persists it", func(t *testing.T) {
		c, secretID, now, _ := newSharesExpiryFixture(t)
		rec, err := c.ShareSecret(ctx, &ShareSecretRequest{
			SecretID: secretID, RecipientID: 2, Permission: "read", SharedBy: 1,
		})
		require.NoError(t, err)
		require.Nil(t, rec.ExpiresAt, "initial share must be permanent")

		exp := now.Add(time.Hour)
		reshared, err := c.ShareSecret(ctx, &ShareSecretRequest{
			SecretID: secretID, RecipientID: 2, Permission: "read", SharedBy: 1, ExpiresAt: &exp,
		})
		require.NoError(t, err)
		require.Equal(t, rec.ID, reshared.ID, "re-share must upsert onto the same row, not create a duplicate")
		require.NotNil(t, reshared.ExpiresAt, "re-share must tighten the returned record's expiry")
		assert.True(t, reshared.ExpiresAt.Equal(exp))

		// Re-fetch independently from storage to prove the tightened expiry was
		// actually persisted, not just reflected on the in-memory return value.
		persisted, err := c.storage.GetShareRecord(ctx, rec.ID)
		require.NoError(t, err)
		require.NotNil(t, persisted.ExpiresAt, "persisted row must carry the tightened expiry")
		assert.True(t, persisted.ExpiresAt.Equal(exp))
	})

	t.Run("direct share: re-sharing without an expiry clears a prior one back to permanent", func(t *testing.T) {
		c, secretID, now, _ := newSharesExpiryFixture(t)
		exp := now.Add(time.Hour)
		rec, err := c.ShareSecret(ctx, &ShareSecretRequest{
			SecretID: secretID, RecipientID: 2, Permission: "read", SharedBy: 1, ExpiresAt: &exp,
		})
		require.NoError(t, err)
		require.NotNil(t, rec.ExpiresAt)

		reshared, err := c.ShareSecret(ctx, &ShareSecretRequest{
			SecretID: secretID, RecipientID: 2, Permission: "read", SharedBy: 1,
		})
		require.NoError(t, err)
		assert.Nil(t, reshared.ExpiresAt, "re-share with no ExpiresAt must clear it back to permanent")

		persisted, err := c.storage.GetShareRecord(ctx, rec.ID)
		require.NoError(t, err)
		assert.Nil(t, persisted.ExpiresAt, "persisted row must reflect the cleared expiry")
	})

	t.Run("group share: re-sharing a permanent grant with an expiry persists it", func(t *testing.T) {
		c, secretID, now, db := newSharesExpiryFixture(t)
		require.NoError(t, db.Create(&models.Group{ID: 10, Name: "eng"}).Error)
		// ShareSecretWithGroup verifies the group is scoped to the secret's project
		// (project 1, per newSharesExpiryFixture); seed that grant so the share succeeds.
		require.NoError(t, db.Create(&models.GroupRole{GroupID: 10, RoleID: 1, ProjectID: 1}).Error)

		rec, err := c.ShareSecretWithGroup(ctx, &GroupShareSecretRequest{
			SecretID: secretID, GroupID: 10, Permission: "read", SharedBy: 1,
		})
		require.NoError(t, err)
		require.Nil(t, rec.ExpiresAt, "initial group share must be permanent")

		exp := now.Add(time.Hour)
		reshared, err := c.ShareSecretWithGroup(ctx, &GroupShareSecretRequest{
			SecretID: secretID, GroupID: 10, Permission: "read", SharedBy: 1, ExpiresAt: &exp,
		})
		require.NoError(t, err)
		require.Equal(t, rec.ID, reshared.ID, "re-share must upsert onto the same row, not create a duplicate")
		require.NotNil(t, reshared.ExpiresAt, "re-share must tighten the returned record's expiry")
		assert.True(t, reshared.ExpiresAt.Equal(exp))

		persisted, err := c.storage.GetShareRecord(ctx, rec.ID)
		require.NoError(t, err)
		require.NotNil(t, persisted.ExpiresAt, "persisted row must carry the tightened expiry")
		assert.True(t, persisted.ExpiresAt.Equal(exp))
	})
}

func TestListUserShareViews(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, secretID, now, _ := newSharesExpiryFixture(t)

	exp := now.Add(time.Hour)
	_, err := c.ShareSecret(ctx, &ShareSecretRequest{
		SecretID: secretID, RecipientID: 2, Permission: "read", SharedBy: 1, ExpiresAt: &exp,
	})
	require.NoError(t, err)

	// The owner's view list resolves recipient + creator names and carries the expiry.
	views, err := c.ListUserShareViews(ctx, 1)
	require.NoError(t, err)
	require.Len(t, views, 1)
	v := views[0]
	assert.Equal(t, secretID, v.SecretID)
	assert.Equal(t, "user", v.RecipientType)
	assert.Equal(t, "recip2", v.RecipientName, "recipient id should resolve to a username")
	assert.Equal(t, "owner", v.CreatedBy, "owner id should resolve to a username")
	assert.Equal(t, "read", v.Permission)
	require.NotNil(t, v.ExpiresAt)
	assert.True(t, v.ExpiresAt.Equal(exp))
}

// mustShare is a thin wrapper returning just the core, secret, and base now for the
// subtests that don't need the db handle.
func mustShare(t *testing.T) (*KeyorixCore, uint, time.Time) {
	t.Helper()
	c, secretID, now, _ := newSharesExpiryFixture(t)
	return c, secretID, now
}

func TestRemoveExpiredShares(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, secretID, now, db := newSharesExpiryFixture(t)

	// A soon-to-expire share for recipient 2.
	exp := now.Add(time.Minute)
	expiring, err := c.ShareSecret(ctx, &ShareSecretRequest{
		SecretID: secretID, RecipientID: 2, Permission: "read", SharedBy: 1, ExpiresAt: &exp,
	})
	require.NoError(t, err)
	// A permanent share for a different recipient (3) so it isn't upserted onto the first.
	permanent, err := c.ShareSecret(ctx, &ShareSecretRequest{
		SecretID: secretID, RecipientID: 3, Permission: "read", SharedBy: 1,
	})
	require.NoError(t, err)

	// Sweeping before the expiry removes nothing (no-op tick is idempotent).
	n, err := c.RemoveExpiredShares(ctx, now)
	require.NoError(t, err)
	assert.Equal(t, 0, n)

	// Sweeping after the expiry removes exactly the expired share.
	n, err = c.RemoveExpiredShares(ctx, now.Add(time.Hour))
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	// The permanent share survives; the expired one is gone.
	shares, err := c.storage.ListSharesBySecret(ctx, secretID, time.Now())
	require.NoError(t, err)
	require.Len(t, shares, 1)
	assert.Equal(t, permanent.ID, shares[0].ID)
	assert.NotEqual(t, expiring.ID, shares[0].ID)

	// A second sweep is a no-op.
	n, err = c.RemoveExpiredShares(ctx, now.Add(2*time.Hour))
	require.NoError(t, err)
	assert.Equal(t, 0, n)

	// The expiry was audited as share.expired.
	var count int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", EventShareExpired).Count(&count).Error)
	assert.EqualValues(t, 1, count)
}
