package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var machineAuditFixed = time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)

func newMachineAuditCore(store *MockStorage) *KeyorixCore {
	return &KeyorixCore{storage: store, now: func() time.Time { return machineAuditFixed }}
}

func TestGetMachineAuditReport_Empty(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newMachineAuditCore(store)
	ctx := context.Background()

	store.On("ListAllMachineIdentities", ctx).Return([]*models.MachineIdentity{}, nil)

	report, err := c.GetMachineAuditReport(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, report.TotalCount)
	assert.Equal(t, 0, report.StaleCount)
	assert.Equal(t, 0, report.RevokedCount)
	assert.Empty(t, report.Machines)
	assert.Equal(t, machineAuditFixed, report.GeneratedAt)
}

func TestGetMachineAuditReport_StaleWhenNeverUsed(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newMachineAuditCore(store)
	ctx := context.Background()

	m := &models.MachineIdentity{ID: 1, Name: "ci-bot", State: MachineActive}
	store.On("ListAllMachineIdentities", ctx).Return([]*models.MachineIdentity{m}, nil)
	// No credential has ever been used — all LastUsedAt are nil.
	store.On("ListMachineCredentialUsageByMachineIDs", ctx, []uint{1}).
		Return(map[uint][]*models.MachineIdentityCredential{1: []*models.MachineIdentityCredential{{ID: 10, LastUsedAt: nil}}}, nil)

	report, err := c.GetMachineAuditReport(ctx)
	require.NoError(t, err)
	require.Len(t, report.Machines, 1)
	row := report.Machines[0]
	assert.True(t, row.IsStale)
	assert.Nil(t, row.LastUsedAt)
	assert.Equal(t, 1, report.StaleCount)
}

func TestGetMachineAuditReport_StaleWhenLastUsedTooLongAgo(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newMachineAuditCore(store)
	ctx := context.Background()

	old := machineAuditFixed.Add(-40 * 24 * time.Hour) // 40 days ago > 30-day threshold
	m := &models.MachineIdentity{ID: 2, Name: "deploy-bot", State: MachineActive}
	store.On("ListAllMachineIdentities", ctx).Return([]*models.MachineIdentity{m}, nil)
	store.On("ListMachineCredentialUsageByMachineIDs", ctx, []uint{2}).
		Return(map[uint][]*models.MachineIdentityCredential{2: []*models.MachineIdentityCredential{{ID: 11, LastUsedAt: &old}}}, nil)

	report, err := c.GetMachineAuditReport(ctx)
	require.NoError(t, err)
	assert.True(t, report.Machines[0].IsStale)
	assert.Equal(t, 1, report.StaleCount)
}

func TestGetMachineAuditReport_NotStaleWhenRecentlyUsed(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newMachineAuditCore(store)
	ctx := context.Background()

	recent := machineAuditFixed.Add(-5 * 24 * time.Hour) // 5 days ago — within 30-day window
	m := &models.MachineIdentity{ID: 3, Name: "api-bot", State: MachineActive}
	store.On("ListAllMachineIdentities", ctx).Return([]*models.MachineIdentity{m}, nil)
	store.On("ListMachineCredentialUsageByMachineIDs", ctx, []uint{3}).
		Return(map[uint][]*models.MachineIdentityCredential{3: []*models.MachineIdentityCredential{{ID: 12, LastUsedAt: &recent}}}, nil)

	report, err := c.GetMachineAuditReport(ctx)
	require.NoError(t, err)
	assert.False(t, report.Machines[0].IsStale)
	assert.Equal(t, 0, report.StaleCount)
}

func TestGetMachineAuditReport_LastUsedPicksMostRecent(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newMachineAuditCore(store)
	ctx := context.Background()

	older := machineAuditFixed.Add(-10 * 24 * time.Hour)
	newer := machineAuditFixed.Add(-2 * 24 * time.Hour)
	m := &models.MachineIdentity{ID: 4, Name: "multi-cred", State: MachineActive}
	store.On("ListAllMachineIdentities", ctx).Return([]*models.MachineIdentity{m}, nil)
	store.On("ListMachineCredentialUsageByMachineIDs", ctx, []uint{4}).
		Return(map[uint][]*models.MachineIdentityCredential{4: []*models.MachineIdentityCredential{
			{ID: 13, LastUsedAt: &older},
			{ID: 14, LastUsedAt: &newer},
		}}, nil)

	report, err := c.GetMachineAuditReport(ctx)
	require.NoError(t, err)
	require.NotNil(t, report.Machines[0].LastUsedAt)
	assert.Equal(t, newer.UTC(), report.Machines[0].LastUsedAt.UTC())
}

func TestGetMachineAuditReport_RevokedCounted(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newMachineAuditCore(store)
	ctx := context.Background()

	recent := machineAuditFixed.Add(-1 * time.Hour)
	m := &models.MachineIdentity{ID: 5, Name: "old-bot", State: MachineRevoked}
	store.On("ListAllMachineIdentities", ctx).Return([]*models.MachineIdentity{m}, nil)
	store.On("ListMachineCredentialUsageByMachineIDs", ctx, []uint{5}).
		Return(map[uint][]*models.MachineIdentityCredential{5: []*models.MachineIdentityCredential{{ID: 15, LastUsedAt: &recent}}}, nil)

	report, err := c.GetMachineAuditReport(ctx)
	require.NoError(t, err)
	assert.True(t, report.Machines[0].IsRevoked)
	assert.Equal(t, 1, report.RevokedCount)
}

func TestGetMachineAuditReport_CredentialCountIncludesAll(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newMachineAuditCore(store)
	ctx := context.Background()

	recent := machineAuditFixed.Add(-1 * time.Hour)
	m := &models.MachineIdentity{ID: 6, Name: "many-keys", State: MachineActive}
	store.On("ListAllMachineIdentities", ctx).Return([]*models.MachineIdentity{m}, nil)
	store.On("ListMachineCredentialUsageByMachineIDs", ctx, []uint{6}).
		Return(map[uint][]*models.MachineIdentityCredential{6: []*models.MachineIdentityCredential{
			{ID: 20, LastUsedAt: &recent},
			{ID: 21, LastUsedAt: nil},
			{ID: 22, LastUsedAt: nil},
		}}, nil)

	report, err := c.GetMachineAuditReport(ctx)
	require.NoError(t, err)
	assert.Equal(t, 3, report.Machines[0].CredentialCount)
}

func TestGetMachineAuditReport_ListIdentitiesError(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newMachineAuditCore(store)
	ctx := context.Background()

	store.On("ListAllMachineIdentities", ctx).Return(nil, errors.New("db error"))

	_, err := c.GetMachineAuditReport(ctx)
	require.Error(t, err)
}

func TestGetMachineAuditReport_ListCredentialsError(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newMachineAuditCore(store)
	ctx := context.Background()

	m := &models.MachineIdentity{ID: 7, Name: "broken", State: MachineActive}
	store.On("ListAllMachineIdentities", ctx).Return([]*models.MachineIdentity{m}, nil)
	store.On("ListMachineCredentialUsageByMachineIDs", ctx, []uint{7}).Return(nil, errors.New("cred error"))

	_, err := c.GetMachineAuditReport(ctx)
	require.Error(t, err)
}

func TestGetMachineAuditReport_RowFieldsPopulated(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newMachineAuditCore(store)
	ctx := context.Background()

	created := machineAuditFixed.Add(-90 * 24 * time.Hour)
	m := &models.MachineIdentity{
		ID:          8,
		Name:        "svc-account",
		Description: "production service account",
		State:       MachineActive,
		CreatedAt:   created,
	}
	store.On("ListAllMachineIdentities", ctx).Return([]*models.MachineIdentity{m}, nil)
	store.On("ListMachineCredentialUsageByMachineIDs", ctx, []uint{8}).
		Return(map[uint][]*models.MachineIdentityCredential{8: []*models.MachineIdentityCredential{}}, nil)

	report, err := c.GetMachineAuditReport(ctx)
	require.NoError(t, err)
	row := report.Machines[0]
	assert.Equal(t, uint(8), row.MachineID)
	assert.Equal(t, "svc-account", row.Name)
	assert.Equal(t, "production service account", row.Description)
	assert.Equal(t, created.UTC(), row.CreatedAt.UTC())
}
