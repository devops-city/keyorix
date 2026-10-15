package core

// Failure-path tests for the batched list lookups (LIST-ENDPOINTS-1, review of #3253):
// a failed batch lookup must fail closed (error / row excluded), and the best-effort
// name lookups must degrade to empty names without failing the list.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

var errBatchLookup = errors.New("transient batch lookup failure")

// aclListWorld wires a user with no owned secrets, no shares and one ACL grant on
// secret 5, so the only lookups the list issues are the ACL path's.
func aclListWorld(t *testing.T) (*KeyorixCore, *MockStorage, context.Context) {
	t.Helper()
	ms := new(MockStorage)
	c := &KeyorixCore{storage: ms, now: time.Now}
	ctx := context.Background()
	userID := uint(1)
	ms.On("GetUser", ctx, userID).Return(&models.User{ID: userID, Username: "u"}, nil)
	ms.On("ListSecrets", ctx, mock.AnythingOfType("*storage.SecretFilter")).Return([]*models.SecretNode(nil), int64(0), nil)
	ms.On("ListSharesByUser", ctx, userID).Return([]*models.ShareRecord(nil), nil)
	ms.On("ListSecretACLsByUser", ctx, userID).Return([]*models.SecretACL{
		{SecretID: 5, UserID: userID, Permissions: `["secrets.read"]`},
	}, nil)
	return c, ms, ctx
}

// A failed GetSecretsByIDs on the ACL path used to return (nil, nil): every ACL-granted
// secret vanished and the caller saw a 200. It must fail the list like the owned and
// shared paths do.
func TestListSecretsWithSharingInfo_ACLBatchLookupFailureFailsTheList(t *testing.T) {
	t.Parallel()
	c, ms, ctx := aclListWorld(t)
	ms.On("GetSecretsByIDs", ctx, []uint{5}).Return(nil, errBatchLookup)

	res, err := c.ListSecretsWithSharingInfo(ctx, 1, &models.SecretListFilter{Page: 1, PageSize: 10})
	require.Error(t, err)
	require.ErrorIs(t, err, errBatchLookup)
	require.Nil(t, res)
}

// Control for the test above: the same world with a working lookup lists the grant, so
// the error assertion cannot be satisfied by a world that never reaches the ACL path.
func TestListSecretsWithSharingInfo_ACLBatchLookupSuccessListsTheGrant(t *testing.T) {
	t.Parallel()
	c, ms, ctx := aclListWorld(t)
	ms.On("GetSecretsByIDs", ctx, []uint{5}).Return([]*models.SecretNode{
		{ID: 5, Name: "granted", OwnerID: 9, IsSecret: true, CreatedAt: time.Now()},
	}, nil)

	res, err := c.ListSecretsWithSharingInfo(ctx, 1, &models.SecretListFilter{Page: 1, PageSize: 10})
	require.NoError(t, err)
	require.Len(t, res.Secrets, 1)
	require.Equal(t, "granted", res.Secrets[0].Name)
}

// The scope-granted listing route calls the same ACL helper and must fail the same way.
func TestGetACLGrantedSecrets_BatchLookupFailureReturnsError(t *testing.T) {
	t.Parallel()
	c, ms, ctx := aclListWorld(t)
	ms.On("GetSecretsByIDs", ctx, []uint{5}).Return(nil, errBatchLookup)

	got, err := c.getACLGrantedSecretsWithSharingInfo(ctx, 1, &models.SecretListFilter{})
	require.ErrorIs(t, err, errBatchLookup)
	require.Nil(t, got)
}

func tagFilterRows() []*models.SecretWithSharingInfo {
	return []*models.SecretWithSharingInfo{
		{SecretNode: &models.SecretNode{ID: 1, Name: "alpha"}},
		{SecretNode: &models.SecretNode{ID: 2, Name: "beta"}},
	}
}

// A failed tag batch with a tag filter must exclude every affected row: a row whose tags
// could not be read is not known to carry the tag.
func TestApplySecretFilters_TagLookupFailureExcludesRowsWithTagFilter(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := &KeyorixCore{storage: ms, now: time.Now}
	ctx := context.Background()
	ms.On("GetSecretTagsBySecretIDs", ctx, []uint{1, 2}).Return(nil, errBatchLookup)

	got := c.applySecretFilters(ctx, tagFilterRows(), &models.SecretListFilter{Tags: []string{"prod"}})
	require.Empty(t, got)
	ms.AssertExpectations(t)
}

// Control: the same rows with a working tag lookup keep the tagged row only.
func TestApplySecretFilters_TagLookupSuccessKeepsTaggedRow(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := &KeyorixCore{storage: ms, now: time.Now}
	ctx := context.Background()
	ms.On("GetSecretTagsBySecretIDs", ctx, []uint{1, 2}).Return(map[uint][]string{1: {"prod"}}, nil)

	got := c.applySecretFilters(ctx, tagFilterRows(), &models.SecretListFilter{Tags: []string{"prod"}})
	require.Len(t, got, 1)
	require.Equal(t, uint(1), got[0].ID)
}

// Search: a failed tag lookup only removes the tag contribution. Name hits still match
// (and cost no lookup); a row that matched only by tag is dropped.
func TestApplySecretFilters_TagLookupFailureSearchKeepsNameMatchesOnly(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := &KeyorixCore{storage: ms, now: time.Now}
	ctx := context.Background()
	// "alpha" matches by name, so only "beta" (id 2) needs its tags resolved.
	ms.On("GetSecretTagsBySecretIDs", ctx, []uint{2}).Return(nil, errBatchLookup)
	ms.On("GetSecretTagsBySecretIDs", ctx, []uint{1, 2}).Return(nil, errBatchLookup)

	search := "alpha"
	got := c.applySecretFilters(ctx, tagFilterRows(), &models.SecretListFilter{Search: &search})
	require.Len(t, got, 1)
	require.Equal(t, uint(1), got[0].ID)

	tagSearch := "prod"
	got = c.applySecretFilters(ctx, tagFilterRows(), &models.SecretListFilter{Search: &tagSearch})
	require.Empty(t, got, "tag-only matches are dropped when the tag lookup failed")
}

// The recipient / owner name lookups are best effort: the list still succeeds, with
// empty names, when GetUsernamesByIDs fails.
func TestGetSharedSecrets_OwnerNameLookupFailureLeavesNameEmpty(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := &KeyorixCore{storage: ms, now: time.Now}
	ctx := context.Background()
	ms.On("ListSharesByUser", ctx, uint(1)).Return([]*models.ShareRecord{
		{ID: 1, SecretID: 2, OwnerID: 7, RecipientID: 1, Permission: "read"},
	}, nil)
	ms.On("GetSecretsByIDs", ctx, []uint{2}).Return([]*models.SecretNode{{ID: 2, Name: "s", OwnerID: 7}}, nil)
	ms.On("GetUsernamesByIDs", ctx, []uint{7}).Return(nil, errBatchLookup)

	got, err := c.getSharedSecretsWithSharingInfo(ctx, 1, &models.SecretListFilter{})
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "s", got[0].Name)
	require.Empty(t, got[0].OwnerUsername)
	require.Equal(t, "read", got[0].UserPermission)
}

// A shared secret that GetSecretsByIDs does not return (deleted) is skipped, as before.
func TestGetSharedSecrets_MissingSecretIsSkipped(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := &KeyorixCore{storage: ms, now: time.Now}
	ctx := context.Background()
	ms.On("ListSharesByUser", ctx, uint(1)).Return([]*models.ShareRecord{
		{ID: 1, SecretID: 2, OwnerID: 7, RecipientID: 1, Permission: "read"},
	}, nil)
	ms.On("GetSecretsByIDs", ctx, []uint{2}).Return([]*models.SecretNode{}, nil)

	got, err := c.getSharedSecretsWithSharingInfo(ctx, 1, &models.SecretListFilter{})
	require.NoError(t, err)
	require.Empty(t, got)
}

// Owned path: a failed recipient-name lookup leaves the share indicators unnamed but
// still lists the secret and its share count.
func TestGetOwnedSecrets_RecipientNameLookupFailureStillListsShares(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := &KeyorixCore{storage: ms, now: time.Now}
	ctx := context.Background()
	ms.On("GetUser", ctx, uint(1)).Return(&models.User{ID: 1, Username: "u"}, nil)
	ms.On("ListSecrets", ctx, mock.AnythingOfType("*storage.SecretFilter")).Return([]*models.SecretNode{{ID: 1, Name: "mine", OwnerID: 1}}, int64(1), nil)
	ms.On("ListSharesBySecretIDs", ctx, []uint{1}, mock.Anything).Return([]*models.ShareRecord{
		{ID: 1, SecretID: 1, OwnerID: 1, RecipientID: 3, Permission: "read"},
	}, nil)
	ms.On("GetUsernamesByIDs", ctx, []uint{3}).Return(nil, errBatchLookup)

	got, err := c.getOwnedSecretsWithSharingInfo(ctx, 1, &models.SecretListFilter{})
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, 1, got[0].ShareCount)
	require.True(t, got[0].IsShared)
}
