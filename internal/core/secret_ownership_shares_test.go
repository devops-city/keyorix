package core

// FIX-3102: TransferSecretOwnership must re-own the secret's ShareRecord rows.
//
// ShareRecord.OwnerID is the owner-scoped list's key (ListSharesByOwner, behind
// GET /api/v1/shares/owned and ListSharesByUser's owned half) while revoke/update are
// gated on live ownership of the SECRET (requireShareAuthority). Before the fix a
// transfer moved only the secret, so the previous owner kept LISTING shares they could
// no longer revoke or update and the new owner could revoke/update shares they could
// not list.
//
// The scenario runs on SQLite and, when KEYORIX_TEST_PG_DSN is set, on Postgres, through
// the same fixture (newCTAReviewOn), so the two backends cannot drift.

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// reownAccess is one recipient's effective access to the secret, as the permission
// check reports it. Compared before/after the transfer: recipients must keep EXACTLY
// the access they had.
type reownAccess struct{ read, write, owner bool }

func (f *ctaReview) accessOf(secretID, userID uint) reownAccess {
	f.t.Helper()
	can := func(l PermissionLevel) bool {
		_, err := f.coreA.CheckSecretPermission(f.ctx, secretID, userID, l)
		return err == nil
	}
	return reownAccess{read: can(PermissionRead), write: can(PermissionWrite), owner: can(PermissionOwner)}
}

func shareIDSet(shares []*models.ShareRecord) map[uint]bool {
	out := map[uint]bool{}
	for _, s := range shares {
		out[s.ID] = true
	}
	return out
}

func TestTransferSecretOwnership_ReownsShares(t *testing.T) {
	backends := []struct {
		name string
		new  func(*testing.T) *ctaReview
	}{
		{"sqlite", newCTAReviewSQLite},
		{"postgres", newCTAReview},
	}
	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			runReownSharesScenario(t, b.new(t))
		})
	}
}

func runReownSharesScenario(t *testing.T, f *ctaReview) {
	oldOwner := f.user("reown-old", "project_admin")
	newOwner := f.user("reown-new", "project_admin")
	live := f.user("reown-live", "project_viewer")
	toRevoke := f.user("reown-revoked", "project_viewer")
	expired := f.user("reown-expired", "project_viewer")
	s := f.secret("reown-secret", oldOwner.ID)

	liveShare, err := f.coreA.ShareSecret(f.ctx, &ShareSecretRequest{
		SecretID: s.ID, RecipientID: live.ID, Permission: "write", SharedBy: oldOwner.ID,
	})
	require.NoError(t, err)
	revokedShare, err := f.coreA.ShareSecret(f.ctx, &ShareSecretRequest{
		SecretID: s.ID, RecipientID: toRevoke.ID, Permission: "read", SharedBy: oldOwner.ID,
	})
	require.NoError(t, err)
	require.NoError(t, f.coreA.RevokeShare(f.ctx, revokedShare.ID, oldOwner.ID))
	// An expired-but-unswept row: ShareSecret refuses a past expiry, so seed it directly.
	past := time.Now().Add(-time.Hour)
	expiredShare := &models.ShareRecord{
		SecretID: s.ID, OwnerID: oldOwner.ID, RecipientID: expired.ID, Permission: "read", ExpiresAt: &past,
	}
	require.NoError(t, f.setupDB.Create(expiredShare).Error)

	// Baseline: the previous owner lists the live share; recipients' access recorded.
	owned, err := f.coreA.Storage().ListSharesByOwner(f.ctx, oldOwner.ID, time.Now())
	require.NoError(t, err)
	require.Equal(t, map[uint]bool{liveShare.ID: true}, shareIDSet(owned), "baseline: old owner lists the live share")
	recipients := []uint{live.ID, toRevoke.ID, expired.ID}
	before := map[uint]reownAccess{}
	for _, id := range recipients {
		before[id] = f.accessOf(s.ID, id)
	}
	type grant struct {
		recipient  uint
		permission string
	}
	grantsOf := func() map[uint]grant {
		shares, lerr := f.coreA.ListSecretShares(f.ctx, s.ID)
		require.NoError(t, lerr)
		out := map[uint]grant{}
		for _, sh := range shares {
			out[sh.ID] = grant{sh.RecipientID, sh.Permission}
		}
		return out
	}
	grantsBefore := grantsOf()
	require.Equal(t, map[uint]grant{liveShare.ID: {live.ID, "write"}}, grantsBefore)

	// --- the transfer ---
	_, err = f.coreA.TransferSecretOwnership(f.ctx, s.ID, newOwner.ID, oldOwner.ID, ActorTypeUser)
	require.NoError(t, err)

	// Every row of the secret, live, revoked and expired alike, is now stamped with the new owner.
	var rows []models.ShareRecord
	require.NoError(t, f.setupDB.Unscoped().Where("secret_id = ?", s.ID).Find(&rows).Error)
	require.Len(t, rows, 3)
	for _, r := range rows {
		assert.Equal(t, newOwner.ID, r.OwnerID, "share %d (deleted=%v expires=%v) kept the previous owner", r.ID, r.DeletedAt.Valid, r.ExpiresAt != nil)
	}
	// The revoked row stays revoked.
	var revokedRow models.ShareRecord
	require.NoError(t, f.setupDB.Unscoped().First(&revokedRow, revokedShare.ID).Error)
	assert.True(t, revokedRow.DeletedAt.Valid, "the transfer must not resurrect a revoked share")

	// List: the previous owner no longer lists it, the new owner does (both list paths).
	oldList, err := f.coreA.ListSharesByUser(f.ctx, oldOwner.ID)
	require.NoError(t, err)
	assert.Empty(t, oldList, "previous owner still lists the secret's shares")
	newList, err := f.coreA.ListSharesByUser(f.ctx, newOwner.ID)
	require.NoError(t, err)
	assert.Equal(t, map[uint]bool{liveShare.ID: true}, shareIDSet(newList), "new owner must list the secret's live share")
	newViews, err := f.coreA.ListOwnedShareViews(f.ctx, ActorTypeUser, newOwner.ID)
	require.NoError(t, err)
	require.Len(t, newViews, 1)
	assert.Equal(t, liveShare.ID, newViews[0].ID)
	oldViews, err := f.coreA.ListOwnedShareViews(f.ctx, ActorTypeUser, oldOwner.ID)
	require.NoError(t, err)
	assert.Empty(t, oldViews)

	// Update / revoke: the previous owner is refused and nothing changes; the new owner may.
	_, err = f.coreA.UpdateSharePermission(f.ctx, &UpdateShareRequest{ShareID: liveShare.ID, Permission: "read", UpdatedBy: oldOwner.ID})
	require.Error(t, err, "previous owner must not update the share")
	require.Error(t, f.coreA.RevokeShare(f.ctx, liveShare.ID, oldOwner.ID), "previous owner must not revoke the share")
	got, err := f.coreA.Storage().GetShareRecord(f.ctx, liveShare.ID)
	require.NoError(t, err)
	assert.Equal(t, "write", got.Permission, "a refused update must not change the share")

	// Recipients keep exactly the access they had.
	assert.Equal(t, grantsBefore, grantsOf(), "the set of grants (recipient, permission) changed by the transfer")
	for _, id := range recipients {
		assert.Equal(t, before[id], f.accessOf(s.ID, id), "recipient %d's access changed by the transfer", id)
	}

	updated, err := f.coreA.UpdateSharePermission(f.ctx, &UpdateShareRequest{ShareID: liveShare.ID, Permission: "read", UpdatedBy: newOwner.ID})
	require.NoError(t, err, "new owner must be able to update the share")
	assert.Equal(t, "read", updated.Permission)
	require.NoError(t, f.coreA.RevokeShare(f.ctx, liveShare.ID, newOwner.ID), "new owner must be able to revoke the share")
	newList, err = f.coreA.ListSharesByUser(f.ctx, newOwner.ID)
	require.NoError(t, err)
	assert.Empty(t, newList)

	// Audit: still the one secret.owner_transferred event; its structured detail now
	// also says how many share rows were re-owned.
	var ev models.AuditEvent
	require.NoError(t, f.setupDB.Where("event_type = ? AND secret_node_id = ?", EventSecretOwnerTransferred, s.ID).First(&ev).Error)
	assert.True(t, strings.Contains(ev.Diff, `"shares_reassigned":3`), "audit diff %q must carry the re-owned row count", ev.Diff)
	var n int64
	require.NoError(t, f.setupDB.Model(&models.AuditEvent{}).
		Where("event_type = ? AND secret_node_id = ?", EventSecretOwnerTransferred, s.ID).Count(&n).Error)
	assert.EqualValues(t, 1, n, "the transfer is still audited as exactly one event")
}
