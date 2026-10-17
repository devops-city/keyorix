package core

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// bulkDeleteDBSeq makes each in-memory DB unique within the process.
var bulkDeleteDBSeq atomic.Int64

// setupBulkDeleteDB opens an in-memory SQLite DB, migrates the necessary models,
// and returns a core instance plus a factory for creating test secrets.
func setupBulkDeleteDB(t *testing.T) (*KeyorixCore, func(name string) uint, uint) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())

	// Use a unique in-memory DSN per invocation to avoid shared state across tests
	// and across repeated invocations of the same test (e.g. go test -count=N).
	dsn := fmt.Sprintf("file:bulkdelete_%d?mode=memory&cache=shared&_busy_timeout=5000", bulkDeleteDBSeq.Add(1))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)

	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{},
		&models.SecretVersion{},
		&models.Project{},
		&models.Environment{},
		&models.AuditEvent{},
		&models.SecretAccessLog{},
		&models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{},
		&models.SecretACL{},
		&models.SecretAccessSchedule{},
		// #G31: BulkDeleteSecrets now goes through GetSecretWithPermissionCheck /
		// DeleteSecretWithPermissionCheck (the same per-secret authorization the
		// singular delete endpoint enforces), which needs the RBAC tables and a
		// live project-membership row for the owner-access short-circuit
		// (CheckSecretPermission) to resolve.
		&models.User{}, &models.Role{}, &models.UserRole{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{},
	))

	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	ctx := context.Background()

	p, err := c.storage.CreateProject(ctx, &models.Project{Name: "proj-bulk-delete"})
	require.NoError(t, err)
	env, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "test", ProjectID: p.ID})
	require.NoError(t, err)

	projectID := p.ID
	envID := env.ID

	// The bulk-delete tests below authenticate as user 1, the OwnerID every mk()
	// secret is created with; grant user 1 project membership so
	// CheckSecretPermission's owner short-circuit resolves.
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "tester", AccountState: "active"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "member"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: projectID}).Error)

	mk := func(name string) uint {
		s, e := c.storage.CreateSecret(ctx, &models.SecretNode{
			Name:          name,
			ProjectID:     projectID,
			EnvironmentID: envID,
			Type:          "password",
			OwnerID:       1,
			IsSecret:      true,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		})
		require.NoError(t, e)
		return s.ID
	}

	return c, mk, projectID
}

func TestBulkDeleteSecrets_Success(t *testing.T) {
	t.Parallel()
	c, mk, projectID := setupBulkDeleteDB(t)
	ctx := context.Background()

	id1 := mk("secret-a")
	id2 := mk("secret-b")
	id3 := mk("secret-c")

	req := BulkDeleteRequest{SecretIDs: []uint{id1, id2, id3}}
	result, err := c.BulkDeleteSecrets(ctx, req, projectID, "tester", 1, "", "")
	require.NoError(t, err)
	assert.Len(t, result.Deleted, 3)
	assert.Empty(t, result.Failed)
	assert.Equal(t, 3, result.Total)
}

func TestBulkDeleteSecrets_PartialFailure(t *testing.T) {
	t.Parallel()
	c, mk, projectID := setupBulkDeleteDB(t)
	ctx := context.Background()

	id1 := mk("partial-a")
	id2 := mk("partial-b")
	missingID := uint(99999)

	req := BulkDeleteRequest{SecretIDs: []uint{id1, missingID, id2}}
	result, err := c.BulkDeleteSecrets(ctx, req, projectID, "tester", 1, "", "")
	require.NoError(t, err)

	// Two should succeed, one should fail.
	assert.Len(t, result.Deleted, 2)
	require.Len(t, result.Failed, 1)
	assert.Equal(t, missingID, result.Failed[0].SecretID)
	assert.Contains(t, result.Failed[0].Error, "not found")
	assert.Equal(t, 3, result.Total)
}

func TestBulkDeleteSecrets_EmptyRequest(t *testing.T) {
	t.Parallel()
	c, _, projectID := setupBulkDeleteDB(t)
	ctx := context.Background()

	req := BulkDeleteRequest{SecretIDs: nil}
	_, err := c.BulkDeleteSecrets(ctx, req, projectID, "tester", 1, "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

// TestBulkDeleteSecrets_ExceedsMaxBatchSize is the #G44 regression: before the
// fix, req.SecretIDs had no upper bound, and each ID drives a per-item
// GetSecret+DeleteSecret storage round trip — an unbounded list is a per-request
// resource-exhaustion vector, the same class of bug maxBulkAccessRequestBatchSize
// already guards against elsewhere in this package.
func TestBulkDeleteSecrets_ExceedsMaxBatchSize(t *testing.T) {
	t.Parallel()
	c, _, projectID := setupBulkDeleteDB(t)
	ctx := context.Background()

	ids := make([]uint, maxBulkDeleteBatchSize+1)
	for i := range ids {
		ids[i] = uint(i + 1)
	}
	req := BulkDeleteRequest{SecretIDs: ids}
	_, err := c.BulkDeleteSecrets(ctx, req, projectID, "tester", 1, "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds the maximum batch size")
}

func TestBulkDeleteSecrets_AlreadyDeleted(t *testing.T) {
	t.Parallel()
	c, mk, projectID := setupBulkDeleteDB(t)
	ctx := context.Background()

	id := mk("to-delete-twice")

	// First deletion should succeed.
	req := BulkDeleteRequest{SecretIDs: []uint{id}}
	result, err := c.BulkDeleteSecrets(ctx, req, projectID, "tester", 1, "", "")
	require.NoError(t, err)
	assert.Len(t, result.Deleted, 1)
	assert.Empty(t, result.Failed)

	// Second attempt on the same (now-deleted) ID must not panic; it should fail gracefully.
	result2, err := c.BulkDeleteSecrets(ctx, req, projectID, "tester", 1, "", "")
	require.NoError(t, err)
	assert.Empty(t, result2.Deleted)
	require.Len(t, result2.Failed, 1)
	assert.Equal(t, id, result2.Failed[0].SecretID)
}

func TestBulkDeleteSecrets_VerifyCleanup(t *testing.T) {
	t.Parallel()
	c, mk, projectID := setupBulkDeleteDB(t)
	ctx := context.Background()

	id1 := mk("cleanup-a")
	id2 := mk("cleanup-b")
	id3 := mk("cleanup-c-keep") // this one stays

	req := BulkDeleteRequest{SecretIDs: []uint{id1, id2}}
	result, err := c.BulkDeleteSecrets(ctx, req, projectID, "tester", 1, "", "")
	require.NoError(t, err)
	assert.Len(t, result.Deleted, 2)

	// After bulk delete, deleted secrets must no longer appear in ListSecrets.
	secrets, _, err := c.ListSecrets(ctx, &coreStorage.SecretFilter{PageSize: 100})
	require.NoError(t, err)

	liveIDs := make(map[uint]bool)
	for _, s := range secrets {
		liveIDs[s.ID] = true
	}
	assert.False(t, liveIDs[id1], "id1 should not appear in ListSecrets after delete")
	assert.False(t, liveIDs[id2], "id2 should not appear in ListSecrets after delete")
	assert.True(t, liveIDs[id3], "id3 should still appear in ListSecrets")
}

func TestBulkDeleteSecrets_ZeroID(t *testing.T) {
	t.Parallel()
	c, _, projectID := setupBulkDeleteDB(t)
	ctx := context.Background()

	// SecretID=0 is explicitly rejected before any storage call.
	req := BulkDeleteRequest{SecretIDs: []uint{0, 1}}
	result, err := c.BulkDeleteSecrets(ctx, req, projectID, "tester", 1, "", "")
	require.NoError(t, err)

	// ID 0 must appear in Failed; ID 1 is not found.
	zeroFailed := false
	for _, f := range result.Failed {
		if f.SecretID == 0 {
			zeroFailed = true
			assert.Contains(t, f.Error, "non-zero")
		}
	}
	assert.True(t, zeroFailed, "ID 0 must be in the failed list")
}

// TestBulkDeleteSecrets_CrossProjectGuard is the #G31 detection_idea: bulk-delete a
// list mixing an in-scope secret ID with another tenant's; the call must never
// disclose the other tenant's secret name, and the cross-project secret must be
// refused identically to a nonexistent one (not a distinguishing "does not belong
// to this project" message revealing that SOMETHING exists at that ID).
func TestBulkDeleteSecrets_CrossProjectGuard(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	ctx := context.Background()

	dsn := fmt.Sprintf("file:bulkdelete_crossproject_%d?mode=memory&cache=shared&_busy_timeout=5000", bulkDeleteDBSeq.Add(1))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)

	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{},
		&models.SecretVersion{},
		&models.Project{},
		&models.Environment{},
		&models.AuditEvent{},
		&models.SecretAccessLog{},
		&models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{},
		&models.SecretACL{},
		&models.SecretAccessSchedule{},
		&models.User{}, &models.Role{}, &models.UserRole{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{},
	))

	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}

	// Create two distinct projects/tenants.
	proj1, err := c.storage.CreateProject(ctx, &models.Project{Name: "project-one"})
	require.NoError(t, err)
	proj2, err := c.storage.CreateProject(ctx, &models.Project{Name: "project-two"})
	require.NoError(t, err)

	env1, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "env1", ProjectID: proj1.ID})
	require.NoError(t, err)
	env2, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "env2", ProjectID: proj2.ID})
	require.NoError(t, err)

	// The caller (user 1) is a member of project 1 only — NOT project 2, mirroring
	// a real cross-tenant caller who has no relationship to the other project at all.
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "tester", AccountState: "active"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "member"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: proj1.ID}).Error)

	// Create a secret in project 1 and a secret in project 2 — both owned by user
	// 1's ID, since a REAL cross-tenant attack scenario is a caller guessing IDs
	// that happen to belong to another tenant's data, not literal ownership.
	secretInProj1, err := c.storage.CreateSecret(ctx, &models.SecretNode{
		Name: "secret-p1", ProjectID: proj1.ID, EnvironmentID: env1.ID,
		Type: "password", OwnerID: 1, IsSecret: true,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)

	secretInProj2, err := c.storage.CreateSecret(ctx, &models.SecretNode{
		Name: "SENSITIVE-OTHER-TENANT-NAME", ProjectID: proj2.ID, EnvironmentID: env2.ID,
		Type: "password", OwnerID: 1, IsSecret: true,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)

	// Attempt to bulk-delete both secrets while scoped to project 1.
	// secret-p1 should succeed; secretInProj2 must be refused, its name never disclosed.
	req := BulkDeleteRequest{SecretIDs: []uint{secretInProj1.ID, secretInProj2.ID}}
	result, err := c.BulkDeleteSecrets(ctx, req, proj1.ID, "tester", 1, "127.0.0.1", "test-agent")
	require.NoError(t, err)

	// Exactly one deleted (the one in project 1).
	require.Len(t, result.Deleted, 1, "only the in-scope secret should be deleted")
	assert.Equal(t, secretInProj1.ID, result.Deleted[0])

	// Exactly one failure: the cross-project secret, reported WITHOUT its name and
	// with the SAME generic message a nonexistent ID gets — no signal that
	// something exists at that ID, let alone what it's called.
	require.Len(t, result.Failed, 1, "the out-of-scope secret must appear in Failed")
	assert.Equal(t, secretInProj2.ID, result.Failed[0].SecretID)
	assert.Empty(t, result.Failed[0].Name, "the other tenant's secret name must never be disclosed")
	assert.Equal(t, "secret not found", result.Failed[0].Error, "a cross-tenant secret must be refused identically to a nonexistent one")
	assert.Equal(t, 2, result.Total)

	// The other tenant's secret must survive untouched.
	stillThere, err := c.storage.GetSecret(ctx, secretInProj2.ID)
	require.NoError(t, err)
	assert.Equal(t, "SENSITIVE-OTHER-TENANT-NAME", stillThere.Name)
}

// TestBulkDeleteSecrets_RefusesProjectIDZero is the other half of the #G31 fix:
// projectID == 0 used to disable the cross-project guard entirely (every ID was
// accepted regardless of which project it belonged to); it must now be refused
// outright before any secret is even looked up.
func TestBulkDeleteSecrets_RefusesProjectIDZero(t *testing.T) {
	t.Parallel()
	c, mk, _ := setupBulkDeleteDB(t)
	ctx := context.Background()
	id := mk("some-secret")

	req := BulkDeleteRequest{SecretIDs: []uint{id}}
	_, err := c.BulkDeleteSecrets(ctx, req, 0, "tester", 1, "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "project ID is required")

	// The secret must be untouched — the call must have refused before reaching it.
	still, err := c.storage.GetSecret(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, "some-secret", still.Name)
}

// A per-secret runtime failure mid-batch (as opposed to a not-found/cross-project
// refusal) not aborting the whole batch is already covered by
// TestBulkDeleteSecrets_PartialFailure and TestBulkDeleteSecrets_AlreadyDeleted —
// both exercise a per-ID failure appearing in Failed without a top-level error.

// slowAuditLogStorage wraps a real storage.Storage and makes CreateSecretAccessLog
// take a measurable, deliberate amount of time before returning. Used to prove
// BulkDeleteSecrets' per-secret audit-log write is awaited synchronously rather
// than fired into a detached, un-awaited goroutine (the #1600 regression: a
// detached goroutine would let BulkDeleteSecrets return almost immediately
// regardless of how long CreateSecretAccessLog takes, since nothing waits on it).
type slowAuditLogStorage struct {
	coreStorage.Storage
	delay time.Duration
	calls atomic.Int32
}

func (s *slowAuditLogStorage) CreateSecretAccessLog(ctx context.Context, entry *models.SecretAccessLog) error {
	time.Sleep(s.delay)
	s.calls.Add(1)
	return s.Storage.CreateSecretAccessLog(ctx, entry)
}

// TestBulkDeleteSecrets_AuditLogWriteIsSynchronous is the #1600 regression.
// BulkDeleteSecrets used to fire its per-secret audit-log write
// (LogSecretDeletedWithProject -> writeAccessLog -> CreateSecretAccessLog) in a
// detached goroutine it never waited on. That's safe in a long-lived HTTP server
// process, but the SAME core method is also called directly by the CLI's
// short-lived embedded-mode `secret bulk-delete` (runBulkDeleteEmbedded,
// internal/cli/secret/bulk_delete.go) — a goroutine spawned there can be silently
// killed by the process exiting before it ever runs, losing the audit trail (and
// its loud "SECURITY: failed to persist secret access log" fallback log line, see
// audit.go) with no trace, independent of storage backend. This test proves the
// write now happens synchronously: with an artificially slow CreateSecretAccessLog,
// BulkDeleteSecrets' wall-clock time must scale with the number of deletions
// (each one's audit write is awaited before the loop continues), and the call
// count must already be complete the instant BulkDeleteSecrets returns — a
// detached goroutine would let both of those go to zero instead.
func TestBulkDeleteSecrets_AuditLogWriteIsSynchronous(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	dsn := fmt.Sprintf("file:bulkdelete_sync_%d?mode=memory&cache=shared&_busy_timeout=5000", bulkDeleteDBSeq.Add(1))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.SecretVersion{}, &models.Project{}, &models.Environment{},
		&models.AuditEvent{}, &models.SecretAccessLog{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{},
		&models.SecretAccessSchedule{}, &models.User{}, &models.Role{}, &models.UserRole{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{},
	))

	real := store.NewLocalStorage(db)
	const delay = 40 * time.Millisecond
	slow := &slowAuditLogStorage{Storage: real, delay: delay}
	c := &KeyorixCore{storage: slow, now: time.Now}
	ctx := context.Background()

	p, err := real.CreateProject(ctx, &models.Project{Name: "proj-sync"})
	require.NoError(t, err)
	env, err := real.CreateEnvironment(ctx, &models.Environment{Name: "test", ProjectID: p.ID})
	require.NoError(t, err)

	const n = 3
	ids := make([]uint, 0, n)
	for i := range n {
		s, err := real.CreateSecret(ctx, &models.SecretNode{
			Name: fmt.Sprintf("sync-secret-%d", i), ProjectID: p.ID, EnvironmentID: env.ID,
			Type: "password", OwnerID: 1, IsSecret: true, CreatedAt: time.Now(), UpdatedAt: time.Now(),
		})
		require.NoError(t, err)
		ids = append(ids, s.ID)
	}

	start := time.Now()
	req := BulkDeleteRequest{SecretIDs: ids}
	result, err := c.BulkDeleteSecrets(ctx, req, p.ID, "tester", 0, "", "")
	elapsed := time.Since(start)
	require.NoError(t, err)
	require.Len(t, result.Deleted, n)

	// If the audit write were still detached/async, BulkDeleteSecrets would return
	// almost immediately (the delay lives entirely in a goroutine nothing waits
	// on) and slow.calls would very likely still read less than n right after
	// return. Synchronous per-item writes force elapsed to scale with n*delay and
	// guarantee every call has already landed.
	assert.GreaterOrEqual(t, elapsed, time.Duration(n)*delay,
		"BulkDeleteSecrets must block on each per-secret audit-log write, not detach it into an unawaited goroutine")
	assert.EqualValues(t, n, slow.calls.Load(),
		"every audit-log write must have completed by the time BulkDeleteSecrets returns")
}
