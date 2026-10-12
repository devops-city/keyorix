package core

import (
	"context"
	"errors"
	"testing"
	"time"

	stg "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func newOwnershipCore(store *MockStorage) *KeyorixCore {
	fixed := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)
	return &KeyorixCore{storage: store, now: func() time.Time { return fixed }}
}

// setupOwnerPermission makes secretID owned by actorID so EnforceSecretReadPermission passes.
func setupOwnerPermission(store *MockStorage, ctx context.Context, secretID, actorID uint) {
	store.On("GetSecret", ctx, secretID).
		Return(&models.SecretNode{ID: secretID, OwnerID: actorID}, nil)
	// CheckSecretPermission gates the owner fast-path on IsProjectMember (RBAC-001).
	store.On("IsProjectMember", mock.Anything, actorID, uint(0)).Return(true, nil)
}

func TestGetSecretOwnershipHistory_Empty(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newOwnershipCore(store)
	ctx := context.Background()

	setupOwnerPermission(store, ctx, 100, 42)
	store.On("GetAuditLogs", ctx, mock.AnythingOfType("*storage.AuditFilter")).
		Return([]*models.AuditEvent{}, int64(0), nil)

	records, err := c.GetSecretOwnershipHistory(ctx, 100, 42)
	require.NoError(t, err)
	assert.Empty(t, records)
}

func TestGetSecretOwnershipHistory_ParsesOwnershipDescription(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newOwnershipCore(store)
	ctx := context.Background()

	actor := uint(42)
	ts := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)

	setupOwnerPermission(store, ctx, 100, actor)
	store.On("GetAuditLogs", ctx, mock.AnythingOfType("*storage.AuditFilter")).
		Return([]*models.AuditEvent{
			{
				ID:          7,
				EventTime:   ts,
				UserID:      &actor,
				Description: `transferred ownership of secret "alpha" from user 5 to user 10`,
			},
		}, int64(1), nil)

	records, err := c.GetSecretOwnershipHistory(ctx, 100, actor)
	require.NoError(t, err)
	require.Len(t, records, 1)
	rec := records[0]
	assert.Equal(t, uint(7), rec.EventID)
	assert.Equal(t, ts, rec.ChangedAt)
	assert.Equal(t, actor, rec.ChangedBy)
	assert.Equal(t, uint(5), rec.FromID)
	assert.Equal(t, uint(10), rec.ToID)
}

func TestGetSecretOwnershipHistory_InvalidDescriptionKeepsZeroIDs(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newOwnershipCore(store)
	ctx := context.Background()

	actor := uint(42)
	setupOwnerPermission(store, ctx, 100, actor)
	store.On("GetAuditLogs", ctx, mock.AnythingOfType("*storage.AuditFilter")).
		Return([]*models.AuditEvent{
			{
				ID:          8,
				EventTime:   time.Now(),
				Description: "some legacy event without from/to pattern",
			},
		}, int64(1), nil)

	records, err := c.GetSecretOwnershipHistory(ctx, 100, actor)
	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Equal(t, uint(0), records[0].FromID)
	assert.Equal(t, uint(0), records[0].ToID)
}

func TestGetSecretOwnershipHistory_MultipleRecordsPreserveOrder(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newOwnershipCore(store)
	ctx := context.Background()

	actor := uint(42)
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)

	setupOwnerPermission(store, ctx, 100, actor)
	store.On("GetAuditLogs", ctx, mock.AnythingOfType("*storage.AuditFilter")).
		Return([]*models.AuditEvent{
			{ID: 1, EventTime: t1, Description: `transferred ownership of secret "x" from user 1 to user 2`},
			{ID: 2, EventTime: t2, Description: `transferred ownership of secret "x" from user 2 to user 3`},
		}, int64(2), nil)

	records, err := c.GetSecretOwnershipHistory(ctx, 100, actor)
	require.NoError(t, err)
	require.Len(t, records, 2)
	assert.Equal(t, uint(1), records[0].EventID)
	assert.Equal(t, uint(2), records[1].EventID)
}

func TestGetSecretOwnershipHistory_PermissionDenied(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newOwnershipCore(store)
	ctx := context.Background()

	// GetSecret returns secret owned by user 99, not actorID 42.
	store.On("GetSecret", ctx, uint(100)).
		Return(&models.SecretNode{ID: 100, OwnerID: 99}, nil)
	// CheckSecretPermission also checks shares when not the owner.
	store.On("ListSharesBySecret", ctx, uint(100)).
		Return([]*models.ShareRecord{}, nil)
	// CheckGroupPermissions → GetUserGroupsAt needed.
	store.On("GetUserGroupsAt", ctx, uint(42), mock.Anything).Return([]*models.Group{}, nil)
	// ACL fallback (r140): no direct grant, and no ancestor folder grant either → deny.
	store.On("GetSecretACL", mock.Anything, uint(100), uint(42)).Return(nil, errors.New("record not found"))
	store.On("GetSecretAncestors", mock.Anything, uint(100)).Return([]uint{}, nil)
	// RBAC fallback (r124): no roles → deny.
	store.On("GetUserRoleIDsAt", mock.Anything, uint(42), mock.Anything).Return([]uint{}, nil)
	store.On("GetUserGroupRoleIDsAt", mock.Anything, uint(42), mock.Anything).Return([]uint{}, nil)

	_, err := c.GetSecretOwnershipHistory(ctx, 100, 42)
	require.Error(t, err)
}

func TestGetSecretOwnershipHistory_AuditLogsError(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newOwnershipCore(store)
	ctx := context.Background()

	setupOwnerPermission(store, ctx, 100, 42)
	store.On("GetAuditLogs", ctx, mock.AnythingOfType("*storage.AuditFilter")).
		Return(nil, int64(0), errors.New("db error"))

	_, err := c.GetSecretOwnershipHistory(ctx, 100, 42)
	require.Error(t, err)
}

// newOwnershipHistoryFixture builds a real in-memory-SQLite-backed core (not a
// mock) with users 1 (owner) and 2 (eligible new owner), and a secret owned by
// user 1 — the same shape as newOwnershipFixture (secret_ownership_test.go) but
// additionally migrating models.AuditEvent, since this fixture exercises the real
// TransferSecretOwnership -> writeAuditEventDiff -> GetSecretOwnershipHistory
// round trip instead of mocking storage.
func newOwnershipHistoryFixture(t *testing.T) (*KeyorixCore, uint) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.User{}, &models.ShareRecord{},
		&models.Role{}, &models.Permission{}, &models.RolePermission{}, &models.UserRole{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.AuditEvent{}))
	for _, u := range []models.User{
		{ID: 1, Username: "owner", Email: "o@test.com"},
		{ID: 2, Username: "alice", Email: "a@test.com"},
	} {
		require.NoError(t, db.Create(&u).Error)
	}
	// User 2 needs secrets.write (not merely secrets.read) to be an eligible
	// transfer target under the write-tier ownership ceiling.
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "writer"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "secrets.write", Resource: "secrets", Action: "write"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 1, PermissionID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 1, ProjectID: 1}).Error)
	st := store.NewLocalStorage(db)
	c := &KeyorixCore{storage: st, now: time.Now}
	secret, err := st.CreateSecret(context.Background(), &models.SecretNode{
		Name: "db", ProjectID: 1, EnvironmentID: 1, Type: "password", OwnerID: 1, IsSecret: true,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)
	return c, secret.ID
}

// TestGetSecretOwnershipHistory_MaliciousSecretNameCannotForgeTransferIDs is the
// regression test for the description-regex forgery: a secret renamed to text
// that LOOKS like a fake "from user X to user Y" clause must not be able to make
// GetSecretOwnershipHistory report those forged IDs for a REAL transfer. Before
// the fix, GetSecretOwnershipHistory parsed FromID/ToID with a leftmost regex
// match over the free-text Description — which also embeds the secret's
// (attacker-controllable, via rename) NAME ahead of the real IDs — so a
// maliciously-named secret could hijack the leftmost match. After the fix, the
// real IDs are read from a structured Diff field the malicious name can never
// reach.
func TestGetSecretOwnershipHistory_MaliciousSecretNameCannotForgeTransferIDs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, secretID := newOwnershipHistoryFixture(t)

	// Attacker (the current owner, user 1, who has rename rights on their own
	// secret) renames it to a name containing a fake ownership-transfer clause
	// naming completely different users (1 -> 999) than the real transfer below
	// (1 -> 2) will use.
	secret, err := c.storage.GetSecret(ctx, secretID)
	require.NoError(t, err)
	secret.Name = `evil" from user 1 to user 999 fake`
	_, err = c.storage.UpdateSecret(ctx, secret)
	require.NoError(t, err)

	// A REAL transfer now happens: user 1 (current owner) hands the secret to
	// user 2.
	_, err = c.TransferSecretOwnership(ctx, secretID, 2, 1, ActorTypeUser)
	require.NoError(t, err)

	records, err := c.GetSecretOwnershipHistory(ctx, secretID, 2)
	require.NoError(t, err)
	require.Len(t, records, 1)

	rec := records[0]
	// The real transfer was 1 -> 2. If the parser were still regex-scanning the
	// description leftmost-first, it would report 1 -> 999 (from the forged
	// clause embedded in the name) instead.
	assert.Equal(t, uint(1), rec.FromID, "must report the REAL previous owner, not the forged ID from the secret name")
	assert.Equal(t, uint(2), rec.ToID, "must report the REAL new owner, not the forged ID from the secret name")
	assert.NotEqual(t, uint(999), rec.ToID, "must not be fooled by the fake 'to user 999' clause embedded in the malicious secret name")
}

// Ensure the filter produced by GetSecretOwnershipHistory uses the correct action type.
func TestGetSecretOwnershipHistory_FilterUsesOwnerTransferredAction(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newOwnershipCore(store)
	ctx := context.Background()

	setupOwnerPermission(store, ctx, 100, 42)

	capturedAction := ""
	store.On("GetAuditLogs", ctx, mock.MatchedBy(func(f *stg.AuditFilter) bool {
		if f != nil && f.Action != nil {
			capturedAction = *f.Action
		}
		return true
	})).Return([]*models.AuditEvent{}, int64(0), nil)

	_, err := c.GetSecretOwnershipHistory(ctx, 100, 42)
	require.NoError(t, err)
	assert.Equal(t, EventSecretOwnerTransferred, capturedAction)
}
