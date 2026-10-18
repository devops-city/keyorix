// local_secrets_error_sweep_test.go — partial-coverage sweep for local_secrets.go:
// DB-error branches deep inside deleteProjectCascade/RestoreProject/RestoreSecret/
// ListSecrets/SetSecretTags that a fully-broken DB (newBrokenDB) can't reach on its
// own, because an earlier statement in the same function/transaction would fail
// first. Two techniques are used beyond newBrokenDB:
//
//  1. Partial migration: migrate only the tables an earlier step needs, leaving a
//     later step's table absent so IT fails instead.
//  2. dropTableAfterQueries / dropTableAfterUpdates: register a one-shot GORM
//     callback that drops a table after the Nth query/update statement succeeds,
//     so the (N+1)th statement against that same table fails — used when two
//     steps hit the SAME table (so partial migration can't separate them) or a
//     later step in the same transaction must fail only after earlier steps in
//     that same transaction already committed their effect.
package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// dropTableBothHandles drops tableName via BOTH the callback's own tx handle
// and the outer db handle. Which one actually shares the live connection that
// matters depends on context in ways that aren't safe to assume either way:
//   - Inside an active ls.db.Transaction(...), the transaction holds the
//     pool's only real connection to this :memory: DB, so db.Exec from
//     outside would silently operate on a different (separate, empty)
//     connection — only tx.Exec reaches the real table.
//   - Immediately after a not-found First() on the SAME session chain,
//     re-using that tx handle for a later Exec can inherit/reuse the prior
//     statement's state and silently no-op — only db.Exec reaches the real
//     table there.
//
// IF EXISTS makes firing both unconditionally safe: whichever handle doesn't
// share the live connection just no-ops on an empty/already-gone table.
//
// db's own call is bounded by a short timeout, not run unbounded: every
// :memory: DB constructor in this package (including this file's own
// newPartialSecretsDB) now calls sqlDB.SetMaxOpenConns(1), closing the
// separate defect where an anonymous ":memory:" DSN's UNLIMITED pool could
// silently open a second, never-migrated phantom connection under
// concurrent access (see TestMemDBConnectionPool_* in
// local_memdb_pool_isolation_test.go for the mechanism and #1835/#1836's
// real CI failures this closes). With the pool capped at 1, if tx is
// genuinely holding the only connection when this callback fires (the
// normal case: fires mid-transaction), a plain, unbounded db.Exec would
// block forever waiting for a connection tx will never release from inside
// its own callback chain — a real, first-run-observed deadlock (10 tests
// stuck 25m: TestRestoreProject_FinalProjectUpdateFails and 9 others using
// this same helper family), not a theoretical one. The timeout preserves
// this call's original purpose exactly: if db shares tx's connection, the
// deadline fires and this is a correct no-op (tx.Exec above already did the
// real drop); if db really is a distinct, already-free connection, the drop
// still completes immediately, well inside the timeout.
//
// The tx-side drop goes straight to tx's connection (Statement.ConnPool: the
// *sql.Tx inside a transaction, the pool otherwise), not through tx.Exec: tx is
// the hooked statement's own *gorm.DB and carries its Error, so after a
// First() that found nothing ("record not found") tx.Exec silently did
// nothing, and only the second-handle drop below did the work, which it can
// only do when no transaction holds the single connection.
func dropTableBothHandles(tx, db *gorm.DB, tableName string) {
	_, _ = tx.Statement.ConnPool.ExecContext(context.Background(), "DROP TABLE IF EXISTS "+tableName)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	db.WithContext(ctx).Exec("DROP TABLE IF EXISTS " + tableName)
}

// dropTableAfterQueries registers a one-shot callback on db that drops
// tableName immediately after the Nth statement passing through GORM's
// "gorm:query" callback family (First/Find/Count) completes, causing the
// (N+1)th such statement to fail with "no such table". NOTE: a `.Table(...).
// Scan(...)`-style raw query (used throughout local_billing.go and similar
// aggregation helpers) does NOT go through this family — it calls Rows()
// internally, which runs the separate "gorm:row" family; use
// dropTableAfterRows for those.
func dropTableAfterQueries(t *testing.T, db *gorm.DB, n int, tableName string) {
	t.Helper()
	calls := 0
	err := db.Callback().Query().After("gorm:query").Register("drop-"+tableName+"-after-query", func(tx *gorm.DB) {
		calls++
		if calls == n {
			dropTableBothHandles(tx, db, tableName)
		}
	})
	require.NoError(t, err)
}

// dropTableAfterUpdates is dropTableAfterQueries' twin for GORM's "gorm:update"
// callback family (Update/Updates/UpdateColumn), used to fail a later UPDATE in
// the same transaction after N earlier UPDATEs already succeeded.
func dropTableAfterUpdates(t *testing.T, db *gorm.DB, n int, tableName string) {
	t.Helper()
	calls := 0
	err := db.Callback().Update().After("gorm:update").Register("drop-"+tableName+"-after-update", func(tx *gorm.DB) {
		calls++
		if calls == n {
			dropTableBothHandles(tx, db, tableName)
		}
	})
	require.NoError(t, err)
}

// dropTableAfterDeletes is dropTableAfterQueries' twin for GORM's "gorm:delete"
// callback family, used to fail a later DELETE in the same transaction after N
// earlier DELETEs already succeeded.
func dropTableAfterDeletes(t *testing.T, db *gorm.DB, n int, tableName string) {
	t.Helper()
	calls := 0
	err := db.Callback().Delete().After("gorm:delete").Register("drop-"+tableName+"-after-delete", func(tx *gorm.DB) {
		calls++
		if calls == n {
			dropTableBothHandles(tx, db, tableName)
		}
	})
	require.NoError(t, err)
}

// dropTableAfterRows is dropTableAfterQueries' twin for GORM's "gorm:row"
// callback family (Rows/Scan on a raw .Table(...)-based builder — see
// dropTableAfterQueries' note).
// dropTableAfterRows uses a Before-hook (unlike its Query/Update/Delete
// siblings, which use After): a Row-family call (Rows/Scan) leaves its
// *sql.Rows cursor open across the After hook, holding the pool's real
// connection hostage, so a drop issued there silently lands on a different,
// separate :memory: connection instead. By the time the (n+1)th call's
// Before-hook fires, the Nth call's cursor has already been closed and the
// real connection is free again.
func dropTableAfterRows(t *testing.T, db *gorm.DB, n int, tableName string) {
	t.Helper()
	calls := 0
	err := db.Callback().Row().Before("gorm:row").Register("drop-"+tableName+"-before-row", func(tx *gorm.DB) {
		calls++
		if calls == n+1 {
			dropTableBothHandles(tx, db, tableName)
		}
	})
	require.NoError(t, err)
}

// newPartialSecretsDB returns a LocalStorage with only the given models
// migrated onto a fresh in-memory SQLite DB, for tests that need a specific
// subset of tables present/absent to isolate one step of a multi-step
// operation.
func newPartialSecretsDB(t *testing.T, models ...any) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	if len(models) > 0 {
		require.NoError(t, db.AutoMigrate(models...))
	}
	return NewLocalStorage(db)
}

// ---------------------------------------------------------------------------
// ListProjectsWithCounts / GetProjectByName — DB error paths
// ---------------------------------------------------------------------------

func TestListProjectsWithCounts_BrokenDB(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.ListProjectsWithCounts(context.Background(), false)
	require.Error(t, err)
}

func TestGetProjectByName_BrokenDB(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.GetProjectByName(context.Background(), "anything")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "project not found")
}

// ---------------------------------------------------------------------------
// deleteProjectCascade (via DeleteProject) — mid-cascade DB error paths
// ---------------------------------------------------------------------------

func TestDeleteProjectCascade_EnvironmentUpdateFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.Project{}, &models.SecretNode{}, &models.ShareRecord{}, &models.SecretACL{}, &models.AccessRequest{})
	ctx := context.Background()
	p, err := ls.CreateProject(ctx, &models.Project{Name: "casc-env"})
	require.NoError(t, err)

	err = ls.DeleteProject(ctx, p.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "soft-delete project environments")
}

func TestDeleteProjectCascade_DynamicConfigUpdateFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.Project{}, &models.SecretNode{}, &models.ShareRecord{}, &models.SecretACL{}, &models.AccessRequest{}, &models.Environment{})
	ctx := context.Background()
	p, err := ls.CreateProject(ctx, &models.Project{Name: "casc-dyn"})
	require.NoError(t, err)

	err = ls.DeleteProject(ctx, p.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "disable project dynamic-secret configs")
}

func TestDeleteProjectCascade_ProjectUpdateFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.Project{}, &models.SecretNode{}, &models.ShareRecord{}, &models.SecretACL{}, &models.AccessRequest{},
		&models.Environment{}, &models.DynamicSecretConfig{})
	ctx := context.Background()
	p, err := ls.CreateProject(ctx, &models.Project{Name: "casc-proj"})
	require.NoError(t, err)

	// Cascade update order inside a single transaction: SecretNode(1),
	// Environment(2), DynamicSecretConfig(3), Project(4). Drop `projects`
	// right after the 3rd update so the 4th (the project's own row) fails.
	dropTableAfterUpdates(t, ls.db, 3, "projects")

	err = ls.DeleteProject(ctx, p.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete project")
}

// ---------------------------------------------------------------------------
// DeleteProjectIfEmpty — DB error + outer propagation
// ---------------------------------------------------------------------------

func TestDeleteProjectIfEmpty_BrokenDB(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.DeleteProjectIfEmpty(context.Background(), 1)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// RestoreProject — mid-transaction DB error paths
// ---------------------------------------------------------------------------

func newSoftDeletedProject(t *testing.T, ls *LocalStorage, name string) uint {
	t.Helper()
	p := &models.Project{Name: name}
	require.NoError(t, ls.db.Create(p).Error)
	require.NoError(t, ls.db.Exec("UPDATE projects SET deleted_at = ? WHERE id = ?", time.Now().Add(-time.Hour), p.ID).Error)
	return p.ID
}

func TestRestoreProject_EnvironmentUpdateFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.Project{})
	id := newSoftDeletedProject(t, ls, "restore-env-fail")

	_, _, err := ls.RestoreProject(context.Background(), id)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "restore project environments")
}

func TestRestoreProject_SecretUpdateFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.Project{}, &models.Environment{})
	id := newSoftDeletedProject(t, ls, "restore-sec-fail")

	_, _, err := ls.RestoreProject(context.Background(), id)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "restore project secrets")
}

func TestRestoreProject_FinalProjectUpdateFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.Project{}, &models.Environment{}, &models.SecretNode{})
	id := newSoftDeletedProject(t, ls, "restore-proj-fail")

	// envResult(1), secResult(2) succeed; drop `projects` before the final update(3).
	dropTableAfterUpdates(t, ls.db, 2, "projects")

	_, _, err := ls.RestoreProject(context.Background(), id)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to restore project:")
}

// ---------------------------------------------------------------------------
// GetEnvironment / DeleteEnvironment / RestoreEnvironment — DB error paths
// ---------------------------------------------------------------------------

func TestGetEnvironment_BrokenDB(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.GetEnvironment(context.Background(), 1)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "environment not found")
}

func TestDeleteEnvironment_DeleteFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.SecretNode{})
	err := ls.DeleteEnvironment(context.Background(), 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete environment")
}

func TestRestoreEnvironment_UpdateFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.Project{})
	ctx := context.Background()
	p, err := ls.CreateProject(ctx, &models.Project{Name: "env-restore-fail"})
	require.NoError(t, err)

	err = ls.RestoreEnvironment(ctx, p.ID, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to restore environment")
}

// ---------------------------------------------------------------------------
// GetSecretByName — invalid-name early return (real logic, no DB access)
// ---------------------------------------------------------------------------

func TestGetSecretByName_InvalidNameRejectedBeforeQuery(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.GetSecretByName(context.Background(), "bad\x00name", 1, 1)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// DeleteSecret — SecretACL revoke error path
// ---------------------------------------------------------------------------

func TestDeleteSecret_ACLRevokeFails(t *testing.T) {
	t.Parallel()
	// newSecretsFullStore (store_s3_local3_test.go) migrates SecretNode/
	// ShareRecord but not SecretACL, so the cascade's ACL-revoke step fails.
	ls := newSecretsFullStore(t)
	ctx := context.Background()
	p, err := ls.CreateProject(ctx, &models.Project{Name: "acl-revoke-fail"})
	require.NoError(t, err)
	env, err := ls.CreateEnvironment(ctx, &models.Environment{ProjectID: p.ID, Name: "prod"})
	require.NoError(t, err)
	secret, err := ls.CreateSecret(ctx, &models.SecretNode{
		ProjectID: p.ID, EnvironmentID: env.ID, Name: "acl-secret", IsSecret: true,
	})
	require.NoError(t, err)

	err = ls.DeleteSecret(ctx, secret.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "revoke secret ACLs")
}

// ---------------------------------------------------------------------------
// RestoreSecret — every DB error / not-found branch
// ---------------------------------------------------------------------------

func TestRestoreSecret_NotActuallyDeleted(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.Project{}, &models.Environment{}, &models.SecretNode{})
	ctx := context.Background()
	p, err := ls.CreateProject(ctx, &models.Project{Name: "restore-secret-live"})
	require.NoError(t, err)
	env, err := ls.CreateEnvironment(ctx, &models.Environment{ProjectID: p.ID, Name: "prod"})
	require.NoError(t, err)
	secret, err := ls.CreateSecret(ctx, &models.SecretNode{
		ProjectID: p.ID, EnvironmentID: env.ID, Name: "live-secret", IsSecret: true,
	})
	require.NoError(t, err)

	err = ls.RestoreSecret(ctx, secret.ID)
	require.Error(t, err)
}

func TestRestoreSecret_RequireLiveProjectFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.SecretNode{})
	ctx := context.Background()
	secret := &models.SecretNode{ProjectID: 1, EnvironmentID: 0, Name: "orphan-secret", IsSecret: true}
	require.NoError(t, ls.db.Create(secret).Error)

	err := ls.RestoreSecret(ctx, secret.ID)
	require.Error(t, err)
}

func TestRestoreSecret_RequireLiveEnvironmentFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.Project{}, &models.SecretNode{})
	ctx := context.Background()
	p, err := ls.CreateProject(context.Background(), &models.Project{Name: "restore-env-check"})
	require.NoError(t, err)
	secret := &models.SecretNode{ProjectID: p.ID, EnvironmentID: 7, Name: "env-check-secret", IsSecret: true}
	require.NoError(t, ls.db.Create(secret).Error)

	err = ls.RestoreSecret(ctx, secret.ID)
	require.Error(t, err)
}

func TestRestoreSecret_FinalUpdateFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.Project{}, &models.SecretNode{})
	ctx := context.Background()
	p, err := ls.CreateProject(ctx, &models.Project{Name: "restore-final-fail"})
	require.NoError(t, err)
	secret := &models.SecretNode{ProjectID: p.ID, EnvironmentID: 0, Name: "final-fail-secret", IsSecret: true}
	require.NoError(t, ls.db.Create(secret).Error)
	require.NoError(t, ls.db.Exec("UPDATE secret_nodes SET deleted_at = ? WHERE id = ?", time.Now().Add(-time.Hour), secret.ID).Error)

	// query#1 = the initial secret lookup, query#2 = requireLiveProject's
	// Count. Drop secret_nodes right after so the final Update fails.
	dropTableAfterQueries(t, ls.db, 2, "secret_nodes")

	err = ls.RestoreSecret(ctx, secret.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Storage operation failed")
}

// ---------------------------------------------------------------------------
// ClearProjectSecretOwnership — DB error path
// ---------------------------------------------------------------------------

func TestClearProjectSecretOwnership_BrokenDB(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	err := ls.ClearProjectSecretOwnership(context.Background(), 1, 1)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// ListSecrets — Count error, Find error, and combined optional filters
// ---------------------------------------------------------------------------

func TestListSecrets_CountError(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, _, err := ls.ListSecrets(context.Background(), &storage.SecretFilter{})
	require.Error(t, err)
}

func TestListSecrets_FindErrorAfterCountSucceeds(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.SecretNode{})
	dropTableAfterQueries(t, ls.db, 1, "secret_nodes")

	_, _, err := ls.ListSecrets(context.Background(), &storage.SecretFilter{})
	require.Error(t, err)
}

func TestListSecrets_AllOptionalFilterBranches(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.SecretNode{}, &models.Environment{})

	typ := "api_key"
	createdBy := "bot"
	createdAfter := time.Now().Add(-time.Hour)
	createdBefore := time.Now().Add(time.Hour)
	isSecret := true
	parentID := uint(1)

	secrets, total, err := ls.ListSecrets(context.Background(), &storage.SecretFilter{
		Type:          &typ,
		CreatedBy:     &createdBy,
		CreatedAfter:  &createdAfter,
		CreatedBefore: &createdBefore,
		IsSecret:      &isSecret,
		ParentID:      &parentID,
		FolderOnly:    true,
	})
	require.NoError(t, err)
	assert.Zero(t, total)
	assert.Empty(t, secrets)
}

// ---------------------------------------------------------------------------
// CountOrphanedSecretsByProject / CountExpiringSecretsByProject — DB errors
// ---------------------------------------------------------------------------

func TestCountOrphanedSecretsByProject_BrokenDB(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.CountOrphanedSecretsByProject(context.Background(), []uint{1})
	require.Error(t, err)
}

func TestCountExpiringSecretsByProject_BrokenDB(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.CountExpiringSecretsByProject(context.Background(), []uint{1}, time.Now())
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// ListLiveSecretNamesByProject — truncation branch (real logic)
// ---------------------------------------------------------------------------

func TestListLiveSecretNamesByProject_Truncated(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.Project{}, &models.Environment{}, &models.SecretNode{})
	ctx := context.Background()

	p, err := ls.CreateProject(ctx, &models.Project{Name: "trunc-proj"})
	require.NoError(t, err)
	env, err := ls.CreateEnvironment(ctx, &models.Environment{ProjectID: p.ID, Name: "prod"})
	require.NoError(t, err)

	for i := range 3 {
		_, err := ls.CreateSecret(ctx, &models.SecretNode{
			ProjectID: p.ID, EnvironmentID: env.ID,
			Name: "secret-" + string(rune('a'+i)), IsSecret: true,
		})
		require.NoError(t, err)
	}

	rows, truncated, err := ls.ListLiveSecretNamesByProject(ctx, []uint{p.ID}, 2)
	require.NoError(t, err)
	assert.True(t, truncated)
	assert.Len(t, rows, 2)

	rows, truncated, err = ls.ListLiveSecretNamesByProject(ctx, []uint{p.ID}, 10)
	require.NoError(t, err)
	assert.False(t, truncated)
	assert.Len(t, rows, 3)
}

// ---------------------------------------------------------------------------
// SetSecretTags — DB error paths at each of the 3 statements
// ---------------------------------------------------------------------------

func TestSetSecretTags_DeleteFails(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	err := ls.SetSecretTags(context.Background(), 1, []string{"prod"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "clear tags")
}

func TestSetSecretTags_UpsertTagFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.SecretTag{})
	err := ls.SetSecretTags(context.Background(), 1, []string{"prod"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "upsert tag")
}

func TestSetSecretTags_LinkTagFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.SecretTag{}, &models.Tag{})
	// Same tag name twice: the 2nd iteration's FirstOrCreate resolves to the
	// SAME tag row, so the 2nd SecretTag Create collides with the 1st on the
	// composite primary key (secret_node_id, tag_id).
	err := ls.SetSecretTags(context.Background(), 1, []string{"dup", "dup"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "link tag")
}

// ---------------------------------------------------------------------------
// GetSecretAncestors — DB error path
// ---------------------------------------------------------------------------

func TestGetSecretAncestors_BrokenDB(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.GetSecretAncestors(context.Background(), 1)
	require.Error(t, err)
}
