// local_secrets.go — Secret node and version operations for LocalStorage.
//
// Covers: CreateSecret, GetSecret, GetSecretByName, UpdateSecret, DeleteSecret,
//
//	ListSecrets, CreateSecretVersion, GetSecretVersion (via GORM),
//	GetSecretVersions, GetLatestSecretVersion, IncrementSecretReadCount,
//	Project/Environment CRUD.
//
// All operations use direct GORM queries; no network calls.
// For the remote (HTTP) equivalent see remote_secrets.go.
package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// --- Project / Environment ---

// maxEnvironmentListing caps how many environments a single ListEnvironmentsByProject
// (or ...IncludingDeleted) call returns (#386). This is defense-in-depth behind the
// creation-time cap on CreateProjectWithEnvs (#383, maxEnvNamesPerCreate in
// internal/core/catalog.go): that cap bounds a single fan-out create, but a project
// can still accrete environments one at a time via repeated single-environment-create
// calls, and this backstop keeps the listing query/response bounded independent of
// that limit — including for any pre-existing data created before #383 shipped. Set
// well above the create-time cap so it never trips under normal use.
const maxEnvironmentListing = 1000

// isDuplicateProjectNameViolation reports whether err is a unique-constraint violation
// on specifically the partial projects-name index (uniq_projects_name_active, #385), as
// distinct from any other unique constraint. Both SQLite and Postgres include the
// violated index name in the driver-native error text for an expression index like this
// one, mirroring isDuplicateEmailViolation's treatment of users.email (#117).
func isDuplicateProjectNameViolation(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "uniq_projects_name_active")
}

func (ls *LocalStorage) CreateProject(ctx context.Context, project *models.Project) (*models.Project, error) {
	if err := ls.db.WithContext(ctx).Create(project).Error; err != nil {
		if isDuplicateProjectNameViolation(err) {
			// The partial unique index uniq_projects_name_active (#385) caught a
			// case-insensitive duplicate: another project already holds this name (in any
			// case). Translate to the sentinel so callers can surface a clean "project name
			// already in use" error instead of a raw constraint-violation message.
			return nil, fmt.Errorf("%w: %v", storage.ErrDuplicateProjectName, err)
		}
		return nil, err
	}
	return project, nil
}

func (ls *LocalStorage) CreateEnvironment(ctx context.Context, env *models.Environment) (*models.Environment, error) {
	return env, ls.db.WithContext(ctx).Create(env).Error
}

func (ls *LocalStorage) ListProjects(ctx context.Context) ([]*models.Project, error) {
	var projects []*models.Project
	return projects, ls.db.WithContext(ctx).Find(&projects).Error
}

// ListProjectsWithCounts returns projects with aggregated secret and environment
// counts. Soft-deleted projects (and their secrets/environments in the counts)
// are excluded unless includeDeleted is true — this query uses raw SQL, which
// bypasses GORM's soft-delete scope, so the deleted_at filters are explicit.
func (ls *LocalStorage) ListProjectsWithCounts(ctx context.Context, includeDeleted bool) ([]storage.ProjectWithCounts, error) {
	type row struct {
		ID                 uint
		Name               string
		Description        string
		SecretCount        int64
		EnvironmentCount   int64
		DeletedAt          *string
		CreatedAt          string
		UpdatedAt          string
		LastSecretActivity *string
	}
	// Both where values are compile-time string constants — no user input is
	// interpolated. Do NOT add user-controlled filter terms to this query without
	// switching to parameterised bindings.
	where := "WHERE p.deleted_at IS NULL"
	if includeDeleted {
		where = ""
	}
	var rows []row
	err := ls.db.WithContext(ctx).Raw(`
		SELECT p.id, p.name, p.description, p.created_at, p.updated_at, p.deleted_at,
		       COUNT(DISTINCT s.id) AS secret_count,
		       COUNT(DISTINCT e.id) AS environment_count,
		       MAX(s.updated_at) AS last_secret_activity
		FROM projects p
		LEFT JOIN secret_nodes s ON s.project_id = p.id AND s.deleted_at IS NULL
		LEFT JOIN environments e ON e.project_id = p.id AND e.deleted_at IS NULL
		` + where + `
		GROUP BY p.id
		ORDER BY p.id
	`).Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("failed to list projects with counts: %w", err)
	}
	result := make([]storage.ProjectWithCounts, 0, len(rows))
	for _, r := range rows {
		pc := storage.ProjectWithCounts{
			ID:               r.ID,
			Name:             r.Name,
			Description:      r.Description,
			SecretCount:      r.SecretCount,
			EnvironmentCount: r.EnvironmentCount,
		}
		// Last activity = most recent of the project's own update or any of its
		// secrets' updates, compared as instants (the columns can carry different
		// offsets, so a lexical compare is not a time compare) and reported as UTC
		// RFC 3339. Computed in Go (not SQL GREATEST) so the query works on both
		// Postgres and the SQLite-backed tests.
		pc.LastActivity = latestUTC(r.UpdatedAt, r.LastSecretActivity)
		if r.DeletedAt != nil {
			pc.Deleted = true
			pc.DeletedAt = utcRFC3339(*r.DeletedAt)
		}
		result = append(result, pc)
	}
	return result, nil
}

func (ls *LocalStorage) GetProject(ctx context.Context, id uint) (*models.Project, error) {
	var project models.Project
	if err := ls.db.WithContext(ctx).First(&project, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("project not found")
		}
		return nil, fmt.Errorf("failed to get project: %w", err)
	}
	return &project, nil
}

// GetProjectByName resolves a project by name, case-insensitively — matching
// ensureProjectNameIndex's LOWER(name) partial unique index exactly, so this can
// never resolve two different rows for names differing only in case. GORM's
// soft-delete scoping (Project.DeletedAt) already excludes a soft-deleted project
// from this query without an explicit deleted_at clause, consistent with a deleted
// project's name being freed for reuse (see Project.Name's own doc comment) — this
// must never resolve a name to a row that no longer legitimately holds it.
func (ls *LocalStorage) GetProjectByName(ctx context.Context, name string) (*models.Project, error) {
	var project models.Project
	if err := ls.db.WithContext(ctx).Where("LOWER(name) = LOWER(?)", name).First(&project).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("project not found")
		}
		return nil, fmt.Errorf("failed to get project by name: %w", err)
	}
	return &project, nil
}

// UpdateProjectFields persists name, description and updated_at — plus
// require_mfa only when requireMFA is non-nil — onto a live project row. See
// the storage.Storage interface doc for the two things the full-row
// UpdateProject this replaced (a bare Save) got wrong: resurrecting a
// concurrently deleted project, and reverting a concurrently enabled ADR-037
// require_mfa the caller never asked to touch (#2697).
//
// GORM adds `deleted_at IS NULL` for this soft-delete model, which is the clause
// that stops the resurrection.
func (ls *LocalStorage) UpdateProjectFields(ctx context.Context, id uint, name, description string, requireMFA *bool, updatedAt time.Time) (bool, error) {
	cols := map[string]any{
		"name":        name,
		"description": description,
		"updated_at":  updatedAt,
	}
	if requireMFA != nil {
		cols["require_mfa"] = *requireMFA
	}
	res := ls.db.WithContext(ctx).Model(&models.Project{}).Where("id = ?", id).Updates(cols)
	if res.Error != nil {
		if isDuplicateProjectNameViolation(res.Error) {
			// See CreateProject's comment: a rename collided with the partial
			// case-insensitive unique index (#385).
			return false, fmt.Errorf("%w: %v", storage.ErrDuplicateProjectName, res.Error)
		}
		return false, fmt.Errorf("failed to update project: %w", res.Error)
	}
	return res.RowsAffected == 1, nil
}

// deleteProjectCascade performs DeleteProject's soft-delete cascade (secrets, their
// shares, environments, dynamic-secret configs, then the project itself) against tx —
// the transaction-scoped *gorm.DB the caller (DeleteProject or DeleteProjectIfEmpty,
// #528) is already running inside. Factored out of DeleteProject so
// DeleteProjectIfEmpty can run the exact SAME cascade, inside its own transaction,
// immediately after its own empty-project check, without duplicating this logic or
// splitting the check and the cascade across two top-level storage calls.
func deleteProjectCascade(tx *gorm.DB, id uint, softDeleteDays int) error {
	// Stamp the project and the rows the cascade soft-deletes with ONE uniform
	// deleted_at, so RestoreProject can bring back exactly this cascade's rows and not
	// resurrect secrets/environments that were retired independently earlier (which
	// carry a different, earlier deleted_at). GORM auto-scopes Update on a soft-delete
	// model to deleted_at IS NULL, so already-deleted children are left untouched and
	// keep their original timestamp.
	deletedAt := time.Now()
	// Row-lock the project FIRST, unscoped (#2656 INV-STORE-21, #2723/#2724):
	// see lockProjectRowForCascade.
	if err := lockProjectRowForCascade(tx, id); err != nil {
		return err
	}
	// Soft-delete all currently-live secrets in the project.
	var liveSecretIDs []uint
	if err := tx.Model(&models.SecretNode{}).
		Where(sqlWhereProjectID, id).Pluck("id", &liveSecretIDs).Error; err != nil {
		return fmt.Errorf("failed to list project secrets: %w", err)
	}
	if err := tx.Model(&models.SecretNode{}).
		Where(sqlWhereProjectID, id).Update("deleted_at", deletedAt).Error; err != nil {
		return fmt.Errorf("failed to soft-delete project secrets: %w", err)
	}
	if err := stampSecretPurgeAt(tx, liveSecretIDs, softDeleteDays); err != nil {
		return err
	}
	// Revoke every still-active share for every secret in this project (#119
	// residual): the bulk update above is a raw UPDATE on secret_nodes, unlike
	// DeleteSecret's per-secret path, which also revokes that secret's ShareRecord
	// rows (#370) — so a project-cascade delete used to skip that step entirely,
	// leaving shares for the project's secrets live. Left alone, a share would
	// silently reactivate (via CheckSharePermission) the instant the project (and
	// its secrets) is later restored, with zero re-authorization — exactly the
	// hazard #370 closed for a single secret delete. The subquery is raw SQL,
	// deliberately bypassing GORM's default deleted_at IS NULL scope on
	// SecretNode, so it also reaches the secrets just soft-deleted above. Mirrors
	// #370: like RestoreSecret, RestoreProject does NOT bring these shares back —
	// "delete means gone" for sharing, whether the secret was deleted directly or
	// via a project cascade.
	if err := tx.Where("secret_id IN (SELECT id FROM secret_nodes WHERE project_id = ?) AND deleted_at IS NULL", id).
		Delete(&models.ShareRecord{}).Error; err != nil {
		return fmt.Errorf("failed to revoke project secret shares: %w", err)
	}
	// UserRole/GroupRole grants scoped to this project are deliberately left
	// untouched here, unlike ShareRecord above. Both are plain composite-primary-key
	// join rows (UserID/GroupID, RoleID, ProjectID, EnvironmentID) with no DeletedAt
	// column of their own — soft-deleting them isn't possible without a schema
	// migration that also reworks their primary key (a soft-deleted grant would
	// collide with a later re-grant of the identical scope under today's PK), and
	// RestoreProject's design (see requireAuthorityToReinstateProjectRoles / #161)
	// depends on these rows surviving the soft-delete window unchanged so a restore
	// fully reinstates the project's prior grants, gated by the actor's own
	// authority. PurgeDeletedProjectsBefore already hard-deletes them once the
	// project passes its retention window and can no longer be restored — the same
	// cascade, just necessarily deferred until undo is off the table.
	//
	// Soft-delete all currently-live environments in the project.
	if err := tx.Model(&models.Environment{}).
		Where(sqlWhereProjectID, id).Update("deleted_at", deletedAt).Error; err != nil {
		return fmt.Errorf("failed to soft-delete project environments: %w", err)
	}
	// Disable every dynamic-secret config scoped to the project (#369): a
	// disabled project must not go on minting live database credentials.
	// IssueLease/RenewLease refuse against a Disabled config; the caller
	// (core.DeleteProject) revokes the configs' outstanding active leases
	// against their real targets AFTER this transaction commits — that's
	// network I/O to arbitrary external systems and must not hold this DB
	// transaction open. Unlike secrets/environments, Disabled is a plain
	// boolean with no cascade timestamp: RestoreProject deliberately does
	// NOT clear it (see the Disabled field doc on DynamicSecretConfig).
	if err := tx.Model(&models.DynamicSecretConfig{}).
		Where("project_id = ? AND disabled = ?", id, false).Update("disabled", true).Error; err != nil {
		return fmt.Errorf("failed to disable project dynamic-secret configs: %w", err)
	}
	// Soft-delete the project itself with the same timestamp.
	result := tx.Model(&models.Project{}).
		Where(sqlWhereID, id).Update("deleted_at", deletedAt)
	if result.Error != nil {
		return fmt.Errorf("failed to delete project: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("project not found")
	}
	return nil
}

// lockProjectRowForCascade row-locks project id REGARDLESS of its deleted_at
// (FOR UPDATE on Postgres; SQLite's single writer serializes instead), then
// reports "project not found" if the locked row is already soft-deleted or
// missing.
//
// It is taken FIRST (#2656, INV-STORE-21), by deleteProjectCascade and, before
// its emptiness count, by DeleteProjectIfEmpty (#2887). Every child writer that
// must not commit under a deleted project (RestoreEnvironment, RestoreSecret,
// CreateSecret via tx.LockLiveProject) writes its child row, then re-reads the
// project FOR SHARE in the same transaction. Taking this lock before any count
// or sweep that decides whether to delete the project is what makes that sound:
// either the child writer's FOR SHARE came first and this caller waits for it to
// commit, so whatever runs next sees its row, or this lock came first and the
// child's FOR SHARE waits, then sees the project gone and rolls back. Locking
// only at the project's own final UPDATE (or not at all before a preceding
// count) leaves a window where a child's write and re-check lands AFTER a
// decision was made on stale information but BEFORE this lock.
//
// Under READ COMMITTED, a `deleted_at IS NULL`-scoped lock also let a
// RestoreProject committing mid-cascade produce a state no serial order can:
// the sweeps skip (their snapshots see deleted children), the restore commits,
// then the final project UPDATE takes a fresh snapshot, sees the project live
// and deletes it, leaving every restored environment and secret LIVE under a
// deleted project.
//
// Unscoped deliberately (#2723/#2724): a `deleted_at IS NULL`-scoped lock takes
// nothing on an already-deleted project, which is precisely the case where a
// concurrent RestoreProject must be excluded. The liveness verdict is then read
// off the row the lock is actually held on, rather than being folded into the
// locking query's WHERE — that folding is what made the original lock vacuous.
//
// Returning early here, rather than letting the cascade's final
// `UPDATE projects ... WHERE deleted_at IS NULL` report RowsAffected == 0, is the
// same outcome with the same error text, reached before the child sweeps run
// instead of after them (they would have been rolled back anyway).
func lockProjectRowForCascade(tx *gorm.DB, id uint) error {
	q := tx.Unscoped().Model(&models.Project{})
	if tx.Dialector.Name() == "postgres" {
		q = q.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var deletedAt []gorm.DeletedAt
	if err := q.Where(sqlWhereID, id).Limit(1).Pluck("deleted_at", &deletedAt).Error; err != nil {
		return fmt.Errorf("failed to lock project: %w", err)
	}
	if len(deletedAt) == 0 || deletedAt[0].Valid {
		return fmt.Errorf("project not found")
	}
	return nil
}

func (ls *LocalStorage) DeleteProject(ctx context.Context, id uint) error {
	return ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return deleteProjectCascade(tx, id, ls.softDeleteRetentionDays())
	})
}

// DeleteProjectIfEmpty is the atomic form of DeleteProject(force=false)'s guard+cascade
// pair (#528 — see the storage.Storage interface doc comment on this method for why).
// Counts the project's live secrets and, only if zero, runs the exact same cascade
// DeleteProject does — all inside ONE transaction, so the count the guard rejects on
// is read from, and committed alongside, the same transaction as the delete (mirrors
// #313's original guarantee, just via a single storage-layer call instead of a
// core-layer WithTransaction wrapper).
//
// #2887: the project row is locked FIRST, BEFORE the count -- not merely before the
// cascade (deleteProjectCascade already did that, one call too late for this
// function's own count). CreateSecret's own commit path writes its new secret row,
// then re-reads the project FOR SHARE in the same transaction (tx.LockLiveProject) --
// the same protocol lockProjectRowForCascade's doc comment describes. Counting
// before taking this lock let the legitimate interleaving "CreateSecret inserts,
// takes FOR SHARE (uncontended because this function hasn't locked yet), commits,
// reporting success" land AFTER this function's own stale zero-count decision but
// BEFORE its (deferred, cascade-only) lock -- so the cascade's own fresh sweep
// still swept the just-committed secret, deleting a project that, at the moment its
// caller was told "created", held a live secret forever. Locking first instead
// forces CreateSecret's FOR SHARE to wait for THIS transaction to finish: either it
// sees the project gone and rolls its own insert back (a clear, honest error to its
// caller), or this count runs after CreateSecret's insert is visible and correctly
// finds a blocking secret. Either outcome beats "reported created, silently swept".
func (ls *LocalStorage) DeleteProjectIfEmpty(ctx context.Context, id uint) (int, error) {
	var blockingSecretCount int
	err := ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := lockProjectRowForCascade(tx, id); err != nil {
			return err
		}
		var secretCount int64
		if err := tx.Model(&models.SecretNode{}).
			Where(sqlWhereProjectID, id).Count(&secretCount).Error; err != nil {
			return fmt.Errorf("failed to count project secrets: %w", err)
		}
		if secretCount > 0 {
			blockingSecretCount = int(secretCount)
			return nil
		}
		return deleteProjectCascade(tx, id, ls.softDeleteRetentionDays())
	})
	if err != nil {
		return 0, err
	}
	return blockingSecretCount, nil
}

// RestoreProject reverses a project soft-delete: it clears deleted_at on the project
// and on ONLY the environments and secrets that were soft-deleted by the same
// DeleteProject cascade (matched by the uniform deletion timestamp). Secrets or
// environments a user had retired independently earlier carry a different deleted_at
// and are deliberately left in the recycle bin — restoring the project must not
// silently resurrect a deliberately-deleted secret (and re-grant its retained shares).
//
// Returns the number of environments and secrets the cascade actually brought back, so
// the caller can emit a per-type-count audit entry alongside the single project.restored
// event (#311) — otherwise a DR-test or accidental delete-then-undo of a whole project
// resurrects an unknown number of children with no forensic record of what came back.
func (ls *LocalStorage) RestoreProject(ctx context.Context, id uint) (restoredEnvironments, restoredSecrets int, err error) {
	txErr := ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// #2723/#2724: row-lock the project FIRST, before any child UPDATE, and
		// unscoped — the project is soft-deleted by definition here, so a
		// default-scoped lock would match nothing. This read is where the lock is
		// taken: it is already the first statement in the transaction and already
		// Unscoped, so it only needed the FOR UPDATE clause.
		//
		// Without it, this transaction's child UPDATEs could commit in the middle of
		// a concurrent deleteProjectCascade — whose own lock, before this change,
		// also took nothing on a deleted project — and the cascade's final project
		// UPDATE would then see the freshly-restored project and delete it, stranding
		// every restored environment and secret live under it.
		//
		// On Postgres FOR UPDATE on this row is what makes the two mutually
		// exclusive. SQLite has no row lock and is single-writer, so the transaction
		// alone serializes them — same split as lockLiveParent.
		var project models.Project
		q := tx.Unscoped()
		if tx.Dialector.Name() == "postgres" {
			q = q.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		if err := q.Where("id = ? AND deleted_at IS NOT NULL", id).First(&project).Error; err != nil {
			return fmt.Errorf("project not found or not deleted")
		}
		cascadeTS := project.DeletedAt.Time

		// Restore only the children whose deleted_at is at or after the cascade timestamp
		// (those removed by this DeleteProject); earlier, independently-retired rows are
		// strictly before it and stay deleted.
		envResult := tx.Unscoped().Model(&models.Environment{}).
			Where("project_id = ? AND deleted_at >= ?", id, cascadeTS).Update("deleted_at", nil)
		if envResult.Error != nil {
			return fmt.Errorf("failed to restore project environments: %w", envResult.Error)
		}
		restoredEnvironments = int(envResult.RowsAffected)

		// The frozen purge date goes first, while deleted_at still selects these rows. It is
		// its own statement rather than a map-form Updates alongside deleted_at so the
		// un-delete below keeps the exact .Update("deleted_at", nil) shape that
		// TestChildParentLiveness's site scanner recognises (a map-form update would
		// silently hide this site from that guard).
		if err := tx.Exec("UPDATE secret_nodes SET purge_at = NULL WHERE secret_nodes.project_id = ? AND secret_nodes.deleted_at >= ?", id, cascadeTS).Error; err != nil {
			return fmt.Errorf("failed to restore project secrets: clearing purge dates: %w", err)
		}
		secResult := tx.Unscoped().Model(&models.SecretNode{}).
			Where("project_id = ? AND deleted_at >= ?", id, cascadeTS).Update("deleted_at", nil)
		if secResult.Error != nil {
			return fmt.Errorf("failed to restore project secrets: %w", secResult.Error)
		}
		restoredSecrets = int(secResult.RowsAffected)

		// Clear the project last.
		if err := tx.Unscoped().Model(&models.Project{}).
			Where(sqlWhereID, id).Update("deleted_at", nil).Error; err != nil {
			return fmt.Errorf("failed to restore project: %w", err)
		}
		return nil
	})
	if txErr != nil {
		return 0, 0, txErr
	}
	return restoredEnvironments, restoredSecrets, nil
}

func (ls *LocalStorage) ListEnvironments(ctx context.Context) ([]*models.Environment, error) {
	var environments []*models.Environment
	return environments, ls.db.WithContext(ctx).Find(&environments).Error
}

func (ls *LocalStorage) ListEnvironmentsByProject(ctx context.Context, projectID uint) ([]*models.Environment, error) {
	var environments []*models.Environment
	return environments, ls.db.WithContext(ctx).Where(sqlWhereProjectID, projectID).
		Limit(maxEnvironmentListing).Find(&environments).Error
}

// ListEnvironmentsByProjectIncludingDeleted is like ListEnvironmentsByProject but
// also returns soft-deleted environments (DeletedAt populated), for the restore UI.
func (ls *LocalStorage) ListEnvironmentsByProjectIncludingDeleted(ctx context.Context, projectID uint) ([]*models.Environment, error) {
	var environments []*models.Environment
	return environments, ls.db.WithContext(ctx).Unscoped().Where(sqlWhereProjectID, projectID).
		Limit(maxEnvironmentListing).Find(&environments).Error
}

func (ls *LocalStorage) GetEnvironment(ctx context.Context, id uint) (*models.Environment, error) {
	var env models.Environment
	if err := ls.db.WithContext(ctx).First(&env, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("environment not found")
		}
		return nil, fmt.Errorf("failed to get environment: %w", err)
	}
	return &env, nil
}

// DeleteEnvironment refuses to delete an environment holding active secrets.
// Serialized against every operation that creates or re-activates a
// secret_nodes row for this environment (CreateSecret, CreateFolder,
// RestoreSecret) via storage.EnvironmentSecretGuardLockKey, a single named
// lock per environment (SESSION-AT AT1/AT3) -- see that function's doc
// comment (internal/core/storage/environment_secret_guard.go) for why both a
// lock AND a re-check inside it are required; a plain db.Transaction alone
// was NOT sufficient (confirmed empirically: up to 7/100 trials still
// orphaned a secret with a transaction-only fix, regardless of statement
// order, since SQLite doesn't take a write lock until the transaction's
// first actual write).
//
// MUST NEVER be called from inside an already-open WithTransaction/write
// transaction: WithNamedLock on SQLite is an in-process mutex held for the
// lock's full duration, and a CreateSecret/CreateFolder/RestoreSecret on a
// DIFFERENT goroutine already holding that same mutex while THIS call's own
// enclosing transaction holds a DB write lock would deadlock the two
// goroutines against each other until busy_timeout expires. No caller does
// this today (checked: only the core.DeleteEnvironment wrapper and the HTTP
// handler call this, neither inside a transaction) -- flagging the
// constraint explicitly so it stays true.
func (ls *LocalStorage) DeleteEnvironment(ctx context.Context, id uint) error {
	return ls.WithNamedLock(ctx, storage.EnvironmentSecretGuardLockKey(id), func(ctx context.Context) error {
		var secretCount int64
		if err := ls.db.WithContext(ctx).Model(&models.SecretNode{}).
			Where("environment_id = ? AND status = 'active'", id).
			Count(&secretCount).Error; err != nil {
			return fmt.Errorf("failed to count secrets in environment: %w", err)
		}
		if secretCount > 0 {
			return fmt.Errorf("environment has %d active secret(s); move or delete them before removing this environment", secretCount)
		}

		result := ls.db.WithContext(ctx).Delete(&models.Environment{}, id)
		if result.Error != nil {
			return fmt.Errorf("failed to delete environment: %w", result.Error)
		}
		if result.RowsAffected == 0 {
			return fmt.Errorf("environment not found")
		}
		return nil
	})
}

// RestoreEnvironment clears deleted_at on a soft-deleted environment, but refuses to
// restore one whose parent project is still soft-deleted — otherwise a holder of a
// still-extant project-scoped grant (a soft-deleted project does NOT revoke its role
// grants) could resurrect a usable, readable scope under a project an admin deleted to
// revoke access. Mirrors the parent-liveness guard on CreateProjectEnvironment.
//
// #2656: the up-front requireLiveProject is only the friendly fast path. The restore
// itself runs in one transaction that un-deletes the environment and then re-reads the
// project with lockLiveParent (FOR SHARE on Postgres), rolling back if the project is
// gone. deleteProjectCascade row-locks the project before it sweeps environments, so a
// racing DeleteProject either sweeps this restored environment or makes this restore
// fail (INV-STORE-21).
func (ls *LocalStorage) RestoreEnvironment(ctx context.Context, projectID, id uint) error {
	if err := ls.requireLiveProject(ctx, projectID); err != nil {
		return err
	}
	return ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		result := tx.Unscoped().Model(&models.Environment{}).
			Where("id = ? AND project_id = ? AND deleted_at IS NOT NULL", id, projectID).Update("deleted_at", nil)
		if result.Error != nil {
			return fmt.Errorf("failed to restore environment: %w", result.Error)
		}
		if result.RowsAffected == 0 {
			return fmt.Errorf("environment not found or not deleted")
		}
		live, err := lockLiveParent(tx, &models.Project{}, sqlWhereID, projectID)
		if err != nil {
			return err
		}
		if !live {
			return fmt.Errorf("cannot restore: the parent project is deleted — restore the project first")
		}
		return nil
	})
}

// --- Secrets ---

// CreateSecret inserts a new secret node. Ignores the optional
// plaintextValue variadic (#499): the value continues to flow through the
// existing, unchanged CreateSecretVersion path -- this is a no-op parameter
// here, never read, never persisted. secret.ValueStored is deliberately left
// false (the zero value): the caller (core.CreateSecret) must still make its
// own CreateSecretVersion call for LocalStorage.
//
// Deliberately a raw, unchecked Create -- no environment-existence check, no
// lock -- matching this store's established "thin, unchecked" layering
// (validation belongs at the core layer, e.g. core.CreateSecret's own
// GetEnvironment check; see
// TestMigrateDatabase_ConcurrentCreateSecret_SameNameOnFirstBoot_ExactlyOneSurvives's
// own doc comment, which exercises this exact contract directly). An earlier
// version of this SESSION-AT fix added the existence check and a
// WithNamedLock HERE instead of at the core layer -- reverted after it broke
// that first-boot test (which intentionally creates a secret against an
// environment ID that was never seeded, to prove the DB unique index alone
// is the backstop at this layer). The environment-liveness guard against a
// concurrent DeleteEnvironment lives in core.CreateSecret and core.CreateFolder
// instead -- see their own doc comments.
func (ls *LocalStorage) CreateSecret(ctx context.Context, secret *models.SecretNode, _ ...string) (*models.SecretNode, error) {
	if err := ls.db.WithContext(ctx).Create(secret).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return secret, nil
}

// GetSecret retrieves a secret by ID. Served from the read-path metadata
// cache (PERF-3, docs/specs/read-path-caching.md) when a live, indexed
// generation-check confirms the cached row is still current; any miss
// (cold cache, stale generation, not-found, or a generation-check error
// itself) falls through to the exact live read this method always did. A
// generation-check error is always treated as a miss, never as "assume
// unchanged" — see secret_node_cache_epoch.go's readLiveNodeStamp doc comment.
func (ls *LocalStorage) GetSecret(ctx context.Context, id uint) (*models.SecretNode, error) {
	if secret, ok := ls.getCachedSecret(ctx, id); ok {
		return secret, nil
	}
	var secret models.SecretNode
	if err := ls.db.WithContext(ctx).First(&secret, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Nil-safe by construction: a tx-derived store (&LocalStorage{db: tx})
			// has no cache, and eviction on one is a no-op, not a panic.
			ls.secretMetaCache.evictNode(id)
			return nil, fmt.Errorf("%s", i18n.T("ErrorSecretNotFound", nil))
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	// The stamp is this row's own cache_epoch, selected by the SAME query that
	// returned the row — the same-row case, so there is no window between
	// reading the data and reading the stamp for a write to commit into.
	// Reading the stamp in a SEPARATE query is the bug class GUARD-6 exists
	// for: it would cache this pre-change row under a post-change stamp.
	//
	// Never publish a row read inside a transaction: it is UNCOMMITTED, and the
	// shared cache outlives the transaction (see cacheEnabled's doc comment).
	if ls.cacheEnabled && ls.nodeStampTrusted() {
		cp := secret
		ls.secretMetaCache.setNode(id, nodeGeneration{cacheEpoch: secret.CacheEpoch}, &cp)
	}
	cp2 := secret
	return &cp2, nil
}

// getCachedSecret returns (a defensive copy of the cached row, true) on a
// confirmed-current cache hit with a populated node, or (nil, false) on any
// miss. Callers must treat false exactly like a cold cache — do the full live
// read.
func (ls *LocalStorage) getCachedSecret(ctx context.Context, id uint) (*models.SecretNode, bool) {
	if !ls.cacheEnabled {
		return nil, false
	}
	cached, ok := ls.secretMetaCache.getNode(id)
	if !ok || cached.node == nil {
		return nil, false
	}
	// stamp.trusted is the fail-closed half, and it is read in the SAME query as
	// the epoch: if the cache_epoch trigger has gone away since this entry was
	// stored, the epoch is a frozen constant and would compare equal forever, so
	// an untrusted read is a miss no matter what the numbers say. Deliberately
	// NOT ls.nodeStampTrusted() here — that answer is per-store and
	// time-bounded, which is fine for deciding whether to STORE but would leave
	// a window on the serving path.
	//
	// A request that declared its follow-up reads (storage.ReadPathPrefetch)
	// gets them answered by this same statement; see local_readpath_prefetch.go.
	// They are parked only once the hit below is confirmed.
	var (
		stamp nodeStampRead
		err   error
		perm  *storage.PrefetchedPermission
		sched *storage.PrefetchedScheduleVersion
	)
	pf := storage.ReadPathPrefetchFrom(ctx)
	if pf != nil && takeFoldedNodeHit(pf, id, cached) {
		// Confirmed by the node read the credential statement made for this
		// secret and machine (local_folded_credential.go).
		cp := *cached.node
		return &cp, true
	}
	if pf != nil {
		var ok bool
		stamp, perm, sched, ok = ls.readNodeStampPrefetching(ctx, pf, id, cached.node)
		if !ok {
			pf, perm, sched = nil, nil, nil
			stamp, err = readLiveNodeStamp(ctx, ls.db, id)
		}
	} else {
		stamp, err = readLiveNodeStamp(ctx, ls.db, id)
	}
	if err != nil || !stamp.found || !stamp.trusted || stamp.generation != cached.generation {
		return nil, false
	}
	if pf != nil {
		pf.Park(perm, sched)
	}
	cp := *cached.node
	return &cp, true
}

// GetSecretsByIDs batch-fetches secrets by ID in one query — the batch form of
// GetSecret. IDs with no matching (non-deleted) row are simply absent from the
// result, in whatever order GORM returns them (callers needing a specific order
// must sort/index by ID themselves). Used by the rotation planner's risk-scoring
// batch (#409) so scoring N candidate secrets costs one query, not N.
func (ls *LocalStorage) GetSecretsByIDs(ctx context.Context, ids []uint) ([]*models.SecretNode, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	var secrets []*models.SecretNode
	if err := ls.db.WithContext(ctx).Where("id IN ?", ids).Find(&secrets).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return secrets, nil
}

// GetSecretByName retrieves a secret by name and scope. The lookup name is
// NFC-normalized (#1642) via identity.NewAddressName before comparison, the
// same way CreateSecret normalizes before writing — not case-folded, since a
// secret name is an address, not human-verified identity (PROD_KEY and
// prod_key must remain distinct).
func (ls *LocalStorage) GetSecretByName(ctx context.Context, name string, projectID, environmentID uint) (*models.SecretNode, error) {
	normalized, nerr := identity.NewAddressName(name)
	if nerr != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), storage.ErrSecretNotFound)
	}
	var secret models.SecretNode
	err := ls.db.WithContext(ctx).Where(
		"name = ? AND project_id = ? AND environment_id = ?",
		normalized.String(), projectID, environmentID,
	).First(&secret).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), storage.ErrSecretNotFound)
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &secret, nil
}

// ClearProjectSecretOwnership sets owner_id = 0 for every live secret in
// projectID owned by userID, removing the stale ownership tag left behind after
// a project member is offboarded (RBAC-002). A zero owner_id signals "no human
// owner" (the invariant enforced by secretOwnedBy), so CheckSecretPermission's
// owner short-circuit no longer fires for the removed user.
func (ls *LocalStorage) ClearProjectSecretOwnership(ctx context.Context, userID, projectID uint) error {
	err := ls.db.WithContext(ctx).Model(&models.SecretNode{}).
		Where("owner_id = ? AND project_id = ? AND deleted_at IS NULL", userID, projectID).
		Update("owner_id", 0).Error
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// secretNodeSQLOwnedColumns are the secret_nodes columns whose value is owned by
// the DATABASE, not by any in-memory *models.SecretNode, so a full-struct write
// must never carry them.
//
// # Why this exists (#2843)
//
// read_count is the lifetime counter behind MaxReads — a burn-after-N-reads
// budget (#133). It is only ever advanced by a conditional SQL expression
// (TryIncrementSecretNodeReadCount: `read_count = read_count + 1` guarded by
// `read_count < max_reads`), precisely so that concurrent readers cannot
// overshoot the cap. Any full-struct write of a SecretNode re-sends the
// read_count the caller happened to load, which means:
//
//	reader A: TryIncrementSecretNodeReadCount  -> read_count 4 -> 5 (cap 5, done)
//	editor B: GetSecret (read_count 4) ... UpdateSecret(description) -> read_count 4
//	reader C: TryIncrementSecretNodeReadCount  -> 4 < 5, granted
//
// i.e. an UNRELATED metadata edit silently REFUNDS reads against the cap, and
// the editor needs no permission over the cap to do it. Every UpdateSecret
// caller in internal/core has this shape (load, mutate one field, save):
// secret_description, classification, secret_move, secret_ownership,
// secret_bulk_rename, secret_extend_expiring, rotation_executor, and
// secrets.go's own update path. It is not one site's bug.
//
// Omitting the column is the whole fix: GORM leaves it out of the UPDATE's SET
// list, so the database's value stands and the conditional increment remains the
// only writer. Note this is NOT the same defect as the stale-cache one
// cache_epoch addresses — that was a stale READ of this column; this is a stale
// WRITE of it. Both had to be fixed, and neither fixes the other.
var secretNodeSQLOwnedColumns = []string{"read_count"}

// UpdateSecret updates an existing secret.
//
// read_count is omitted deliberately — see secretNodeSQLOwnedColumns. A caller
// that genuinely needs to change the counter must go through the dedicated
// conditional path, not through a full-struct save.
// UpdateSecret is the full-row Save that UpdateSecretFields replaces — see the
// storage.Storage interface doc for why exactly one caller still reaches it and
// which open PR removes that caller (#2695 / #2668).
func (ls *LocalStorage) UpdateSecret(ctx context.Context, secret *models.SecretNode) (*models.SecretNode, error) {
	if err := ls.db.WithContext(ctx).Omit(secretNodeSQLOwnedColumns...).Save(secret).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	// Save() wrote every other column but left read_count alone, so the struct we
	// hand back still carries the caller's stale value. Re-read it rather than
	// returning a row that disagrees with the database about a security counter.
	//
	// The error is deliberately swallowed, and that is safe rather than merely
	// convenient: the write above has already COMMITTED, so returning an error
	// here would tell the caller its update failed when it did not. What a failed
	// re-read costs is a stale ReadCount on the returned struct and nothing more
	// — enforcement never consults this field (TryIncrementSecretNodeReadCount
	// evaluates `read_count < max_reads` inside the UPDATE itself, against the
	// stored value), and the Omit above means the stale number can never be
	// written back. So the failure mode is a cosmetically stale number in one
	// response, not a refunded read.
	var fresh models.SecretNode
	if err := ls.db.WithContext(ctx).Model(&models.SecretNode{}).
		Select("read_count").Where(sqlWhereID, secret.ID).Take(&fresh).Error; err == nil {
		secret.ReadCount = fresh.ReadCount
	}
	return secret, nil
}

// UpdateSecretFields persists ONLY the fields f names, onto a LIVE secret row:
// "UPDATE secret_nodes SET <named columns> WHERE id = ? AND deleted_at IS NULL".
// See the storage.Storage interface doc and SecretFieldUpdate's own comment for
// why the full-row UpdateSecret this replaced (a bare GORM Save) was unsafe for
// every one of its callers (#2695).
//
// `expiration` is normalised to UTC here because this raw UPDATE bypasses
// SecretNode.BeforeSave, which exists precisely to keep that column canonical
// (G81, INV-STORE-19) for the read paths that range-query it in SQL.
func (ls *LocalStorage) UpdateSecretFields(ctx context.Context, id uint, f storage.SecretFieldUpdate) (bool, error) {
	cols := map[string]any{}
	if f.Name != nil {
		cols["name"] = *f.Name
	}
	if f.Description != nil {
		cols["description"] = *f.Description
	}
	if f.Classification != nil {
		cols["classification"] = *f.Classification
	}
	if f.Type != nil {
		cols["type"] = *f.Type
	}
	if f.OwnerID != nil {
		cols["owner_id"] = *f.OwnerID
	}
	if f.Metadata != nil {
		cols["metadata"] = *f.Metadata
	}
	if f.UpdatedAt != nil {
		cols["updated_at"] = *f.UpdatedAt
	}
	// The four nullable columns carry an explicit Set* flag, so "write NULL" is a
	// deliberate act rather than indistinguishable from "leave this alone".
	if f.SetParentID {
		cols["parent_id"] = f.ParentID
	}
	if f.SetExpiration {
		if f.Expiration != nil {
			utc := f.Expiration.UTC()
			cols["expiration"] = &utc
		} else {
			cols["expiration"] = nil
		}
	}
	if f.SetMaxReads {
		cols["max_reads"] = f.MaxReads
	}
	if f.SetLastRotatedAt {
		cols["last_rotated_at"] = f.LastRotatedAt
	}
	if len(cols) == 0 {
		// A caller that asked for nothing has a bug; it must not read the result
		// as "the row is there". GORM also rejects an empty Updates outright.
		return false, fmt.Errorf("%s: no secret fields to update", i18n.T("ErrorValidation", nil))
	}
	res := ls.db.WithContext(ctx).Model(&models.SecretNode{}).Where(sqlWhereID, id).Updates(cols)
	if res.Error != nil {
		return false, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), res.Error)
	}
	return res.RowsAffected == 1, nil
}

// TransitionSecretStatus persists secret's full row via a conditional UPDATE
// gated on the row's CURRENT status still being fromStatus (see the interface
// doc in internal/core/storage/interface.go for why this exists alongside —
// not instead of — UpdateSecretFields).
//
// #2695: this CAS used to be paired with Select("*"), copied from
// TransitionMachineIdentityState. The CAS means it can never resurrect a
// soft-deleted row, but a full-row write still REVERTED every column a narrower
// concurrent writer had changed since the caller's read — read_count (and with
// it a MaxReads budget), owner_id, classification, the rotation columns. Both
// callers (SuspendSecret, ResumeSecret) set exactly Status and UpdatedAt, so
// those are the only two columns this may write. Same whitelisting #G42 applied
// to TransitionDynamicSecretConfigDisabled, for the same reason.
func (ls *LocalStorage) TransitionSecretStatus(ctx context.Context, secret *models.SecretNode, fromStatus string) (bool, error) {
	res := ls.db.WithContext(ctx).Model(&models.SecretNode{}).
		Where("id = ? AND status = ?", secret.ID, fromStatus).
		Select("*").
		// Same reason as UpdateSecret: Select("*") would otherwise re-send the
		// caller's stale read_count and refund reads against MaxReads. A status
		// transition has no business moving a read counter.
		Omit(secretNodeSQLOwnedColumns...).
		Select("Status", "SuspendClearSyncedCopies", "UpdatedAt").
		Updates(secret)
	if res.Error != nil {
		return false, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), res.Error)
	}
	return res.RowsAffected == 1, nil
}

// UpdateSecretRotationConfig writes only the auto-rotation columns of secret,
// conditional on the row still being live (GORM scopes the soft-delete model to
// deleted_at IS NULL), in secret.ProjectID, and bound to fromBackend — see the
// interface doc in internal/core/storage/interface.go.
//
// Bug origin (#2650):
//
//	Introduced-by: core.SetSecretAutoRotate persisting its pre-read snapshot
//	               through UpdateSecret's full-row Save
//	Detected-by:   C-GUARD2-EXEMPT-REVIEW #2662
//	Class:         cross-replica check-then-act (stale Save upsert)
//	Severity:      high (a deleted secret is live again with no RestoreSecret,
//	               no secret.restored audit event; an admin backend binding or a
//	               cleared ownership is silently reverted)
//	Guard:         TestCTAReview_SetSecretAutoRotate_vs_DeleteSecret_CrossReplicaPostgres,
//	               TestSetSecretAutoRotate_IsColumnScoped
func (ls *LocalStorage) UpdateSecretRotationConfig(ctx context.Context, secret *models.SecretNode, fromBackend string) (bool, error) {
	res := ls.db.WithContext(ctx).Model(&models.SecretNode{}).
		Where("id = ? AND project_id = ? AND rotation_backend = ?", secret.ID, secret.ProjectID, fromBackend).
		Updates(map[string]any{
			"auto_rotate":      secret.AutoRotate,
			"rotation_length":  secret.RotationLength,
			"rotation_charset": secret.RotationCharset,
			"rotation_backend": secret.RotationBackend,
			"rotation_ref":     secret.RotationRef,
			"updated_at":       secret.UpdatedAt,
		})
	if res.Error != nil {
		return false, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), res.Error)
	}
	return res.RowsAffected == 1, nil
}

// SetSecretCertNotAfter caches a certificate-typed secret's parsed leaf expiry — a
// targeted single-column update that touches nothing else (ADR-056).
func (ls *LocalStorage) SetSecretCertNotAfter(ctx context.Context, secretID uint, notAfter *time.Time) error {
	if err := ls.db.WithContext(ctx).Model(&models.SecretNode{}).
		Where(sqlWhereID, secretID).Update("cert_not_after", notAfter).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// SetRetentionOverride sets the per-secret retention override. days = 0 clears
// the override (reverts to the global policy). The caller is responsible for
// validating the minimum floor before invoking this method.
func (ls *LocalStorage) SetRetentionOverride(ctx context.Context, secretID uint, days int) error {
	if err := ls.db.WithContext(ctx).Model(&models.SecretNode{}).
		Where(sqlWhereID, secretID).Update("retention_override_days", days).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// stampSecretPurgeAt freezes secret_nodes.purge_at for secrets this transaction has just
// soft-deleted: deleted_at + the secret's own retention override, else globalDays
// (models.PurgeAtFor, the same formula the displayed date and the purge job use). It
// runs inside the delete's transaction so a secret is never visible as deleted without
// its purge date. globalDays <= 0 means the store was never told the window; nothing is
// stamped and the purge falls back to the legacy cutoff rule for those rows. Each row's
// own deleted_at is read back rather than assumed, so it stays correct whichever
// timestamp the delete path used.
func stampSecretPurgeAt(tx *gorm.DB, ids []uint, globalDays int) error {
	if globalDays <= 0 || len(ids) == 0 {
		return nil
	}
	var rows []struct {
		ID                    uint
		DeletedAt             gorm.DeletedAt
		RetentionOverrideDays int
	}
	if err := tx.Unscoped().Model(&models.SecretNode{}).
		Select("id, deleted_at, retention_override_days").
		Where("id IN ? AND deleted_at IS NOT NULL", ids).
		Find(&rows).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	for _, row := range rows {
		days := globalDays
		if row.RetentionOverrideDays > 0 {
			days = row.RetentionOverrideDays
		}
		purgeAt := models.PurgeAtFor(row.DeletedAt.Time, days)
		if err := tx.Unscoped().Model(&models.SecretNode{}).
			Where("id = ?", row.ID).
			UpdateColumn("purge_at", purgeAt).Error; err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
	}
	return nil
}

// DeleteSecret deletes a secret by ID. #370: ShareRecord rows are a fully
// independent lifecycle from SecretNode's — left untouched, a share grant would
// silently reactivate (via CheckSharePermission) the instant the secret is later
// restored from the recycle bin, with zero re-authorization step, even when the
// secret was deleted specifically to sever a former grantee's access. "Delete
// means gone" for sharing too, so revoke every active share for this secret in
// the same transaction as the secret's own soft-delete.
func (ls *LocalStorage) DeleteSecret(ctx context.Context, id uint) error {
	return ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		result := tx.Delete(&models.SecretNode{}, id)
		if result.Error != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
		}
		if result.RowsAffected == 0 {
			return fmt.Errorf("%s", i18n.T("ErrorSecretNotFound", nil))
		}
		if err := stampSecretPurgeAt(tx, []uint{id}, ls.softDeleteRetentionDays()); err != nil {
			return err
		}
		if err := tx.Where("secret_id = ? AND deleted_at IS NULL", id).
			Delete(&models.ShareRecord{}).Error; err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
		// CWE-284: revoke SecretACL grants in the same transaction so that
		// ACL-based access cannot silently reactivate on restore (same class of
		// bug fixed for ShareRecord in #370).
		if err := tx.Where("secret_id = ?", id).Delete(&models.SecretACL{}).Error; err != nil {
			return fmt.Errorf("failed to revoke secret ACLs: %w", err)
		}
		return nil
	})
}

// GetSecretIncludingDeleted loads a secret even when soft-deleted (Unscoped).
func (ls *LocalStorage) GetSecretIncludingDeleted(ctx context.Context, id uint) (*models.SecretNode, error) {
	var secret models.SecretNode
	if err := ls.db.WithContext(ctx).Unscoped().First(&secret, id).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}
	return &secret, nil
}

// RestoreSecret clears a soft-deleted secret's deleted_at (ADR-033). Uses Unscoped to
// reach the soft-deleted row, which GORM hides by default. It refuses to restore a
// secret whose parent project or environment is still soft-deleted — otherwise a holder
// of a still-extant project-scoped grant could resurrect a live, readable secret inside
// a project an admin deleted to revoke access (the project delete does not revoke role
// grants). To bring such a secret back, restore the parent project first (which
// cascade-restores its children).
//
// SESSION-AT AT1/AT3 (coordinator review on PR #2353): un-deleting a secret
// re-activates a secret_nodes row exactly like CreateSecret/CreateFolder do,
// so it races DeleteEnvironment the identical way -- a secret restored into
// an environment that gets deleted in the same window would be silently
// orphaned. The initial lookup (which environment does this secret belong
// to) has to happen before the lock, since the lock key needs that answer;
// requireLiveEnvironment is then re-run INSIDE the lock, immediately before
// the actual restore, closing the same two gaps DeleteEnvironment's own doc
// comment describes (interleaving, and "delete legitimately wins the lock
// first, then restore blindly proceeds against a target already gone").
func (ls *LocalStorage) RestoreSecret(ctx context.Context, id uint) error {
	var secret models.SecretNode
	if err := ls.db.WithContext(ctx).Unscoped().Select("id", "project_id", "environment_id").First(&secret, id).Error; err != nil {
		return fmt.Errorf("%s", i18n.T("ErrorSecretNotFound", nil))
	}
	if err := ls.requireLiveProject(ctx, secret.ProjectID); err != nil {
		return err
	}

	// #2702/#2712: the restore and the project re-check share one transaction,
	// write-then-check, exactly as RestoreEnvironment does (#2656). The
	// requireLiveProject call above runs BEFORE this and outside any transaction,
	// so DeleteProject's cascade could commit in the window between it and the
	// UPDATE — and the cascade skips an already-deleted secret (GORM scopes its
	// sweep to deleted_at IS NULL), so nothing swept this row and the restore then
	// cleared deleted_at underneath a deleted project. That is precisely the end
	// state RestoreSecret's own error message says it prevents. The named
	// environment lock does not help: deleteProjectCascade never takes it.
	//
	// requireLiveProject is kept as a cheap early rejection with a better message;
	// it is no longer what makes this safe.
	restore := func(ctx context.Context) error {
		return ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			// Clear the frozen purge date first (see RestoreProject for why this is its own
			// statement and not a map-form Updates).
			if err := tx.Exec("UPDATE secret_nodes SET purge_at = NULL WHERE secret_nodes.id = ? AND secret_nodes.deleted_at IS NOT NULL", id).Error; err != nil {
				return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
			}
			result := tx.Unscoped().Model(&models.SecretNode{}).
				Where("id = ? AND deleted_at IS NOT NULL", id).Update("deleted_at", nil)
			if result.Error != nil {
				return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
			}
			if result.RowsAffected == 0 {
				return fmt.Errorf("%s", i18n.T("ErrorSecretNotFound", nil))
			}
			live, lerr := lockLiveParent(tx, &models.Project{}, sqlWhereID, secret.ProjectID)
			if lerr != nil {
				return lerr
			}
			if !live {
				return fmt.Errorf("cannot restore: the parent project is deleted — restore the project first")
			}
			return nil
		})
	}

	if secret.EnvironmentID == 0 {
		return restore(ctx)
	}
	return ls.WithNamedLock(ctx, storage.EnvironmentSecretGuardLockKey(secret.EnvironmentID), func(ctx context.Context) error {
		if err := ls.requireLiveEnvironment(ctx, secret.EnvironmentID); err != nil {
			return err
		}
		return restore(ctx)
	})
}

// requireLiveProject returns an error when the project is missing or soft-deleted.
func (ls *LocalStorage) requireLiveProject(ctx context.Context, projectID uint) error {
	var n int64
	if err := ls.db.WithContext(ctx).Model(&models.Project{}).
		Where("id = ? AND deleted_at IS NULL", projectID).Count(&n).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	if n == 0 {
		return fmt.Errorf("cannot restore: the parent project is deleted — restore the project first")
	}
	return nil
}

// requireLiveEnvironment returns an error when the environment is missing or soft-deleted.
func (ls *LocalStorage) requireLiveEnvironment(ctx context.Context, environmentID uint) error {
	var n int64
	if err := ls.db.WithContext(ctx).Model(&models.Environment{}).
		Where("id = ? AND deleted_at IS NULL", environmentID).Count(&n).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	if n == 0 {
		return fmt.Errorf("cannot restore: the parent environment is deleted — restore the environment first")
	}
	return nil
}

// ListSecrets lists secrets with filtering and pagination.
// When project_id is provided, results are always scoped to that project via
// a JOIN through environments — prevents cross-project leakage if a caller
// passes a mismatched environment_id.
func (ls *LocalStorage) ListSecrets(ctx context.Context, filter *storage.SecretFilter) ([]*models.SecretNode, int64, error) { // NOSONAR -- cognitive complexity 16, suppress go:S3776
	query := ls.db.WithContext(ctx).Model(&models.SecretNode{})
	if filter.DeletedOnly {
		// Recycle bin: only soft-deleted rows, newest-deleted first (ordered in SQL
		// so it survives the LIMIT). Unscoped reaches past GORM's deleted_at IS NULL
		// scope; the explicit predicate then keeps just the trashed secrets.
		query = query.Unscoped().
			Where("secret_nodes.deleted_at IS NOT NULL").
			Order("secret_nodes.deleted_at DESC")
	} else if filter.IncludeDeleted {
		// Reach soft-deleted rows too (restore UI); GORM hides them by default.
		query = query.Unscoped()
	}

	if filter.ProjectID != nil {
		// JOIN ensures environment_id is always verified against the project,
		// preventing cross-project leakage.
		query = query.Joins("JOIN environments ON environments.id = secret_nodes.environment_id").
			Where("secret_nodes.project_id = ?", *filter.ProjectID).
			Where("environments.project_id = ?", *filter.ProjectID)
	}
	if filter.EnvironmentID != nil {
		query = query.Where("secret_nodes.environment_id = ?", *filter.EnvironmentID)
	}
	if filter.Type != nil {
		query = query.Where("secret_nodes.type = ?", *filter.Type)
	}
	if filter.CreatedBy != nil {
		query = query.Where("secret_nodes.created_by = ?", *filter.CreatedBy)
	}
	if filter.OwnerID != nil {
		query = query.Where("secret_nodes.owner_id = ?", *filter.OwnerID)
	}
	if filter.ExpiresBefore != nil {
		// G81 (SecretNode.Expiration): normalize internally — see GetAuditLogs.
		query = query.Where("secret_nodes.expiration IS NOT NULL AND secret_nodes.expiration < ?", filter.ExpiresBefore.UTC())
		// #G24: order soonest-expiring first so a capped PageSize returns the
		// TRUE most-urgent rows, not an arbitrary unordered slice truncated to
		// whatever page happened to be returned — callers filtering by expiry
		// (ListExpiringSecrets) need the returned page to be exactly "the N
		// secrets closest to expiring", not "N secrets that happen to expire
		// before the cutoff" in no particular order.
		query = query.Order("secret_nodes.expiration ASC")
	}
	if filter.Classification != nil {
		if *filter.Classification == "unclassified" {
			query = query.Where("secret_nodes.classification = '' OR secret_nodes.classification IS NULL")
		} else {
			query = query.Where("secret_nodes.classification = ?", *filter.Classification)
		}
	}
	if filter.CreatedAfter != nil {
		query = query.Where("secret_nodes.created_at > ?", *filter.CreatedAfter)
	}
	if filter.CreatedBefore != nil {
		query = query.Where("secret_nodes.created_at < ?", *filter.CreatedBefore)
	}
	if filter.IsSecret != nil {
		query = query.Where("secret_nodes.is_secret = ?", *filter.IsSecret)
	}
	if filter.ParentID != nil {
		query = query.Where("secret_nodes.parent_id = ?", *filter.ParentID)
	}
	if filter.FolderOnly {
		query = query.Where("secret_nodes.is_secret = ?", false)
	}
	if filter.Search != nil && *filter.Search != "" {
		// escapeLIKE sanitises % and _ so a caller-supplied search term cannot
		// widen the match beyond the intended prefix/suffix anchors (#r124 LIKE injection).
		query = query.Where(`LOWER(secret_nodes.name) LIKE LOWER(?) ESCAPE '\'`, "%"+escapeLIKE(*filter.Search)+"%")
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	pageSize := clampPageSize(filter.PageSize)
	page := clampPage(filter.Page)
	offset := (page - 1) * pageSize
	query = query.Offset(offset).Limit(pageSize)

	var secrets []*models.SecretNode
	if err := query.Find(&secrets).Error; err != nil {
		return nil, 0, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return secrets, total, nil
}

// ListOrphanedSecrets returns the project's live secrets whose owner is no longer a
// live user (deleted or soft-deleted) — offboarding hygiene. The environment JOIN
// scopes to the project (anti-leak, consistent with ListSecrets); the LEFT JOIN to a
// non-soft-deleted user with no match (users.id IS NULL) is the "owner gone" test.
// GORM auto-applies secret_nodes.deleted_at IS NULL, so only live secrets are listed.
func (ls *LocalStorage) ListOrphanedSecrets(ctx context.Context, projectID uint) ([]*models.SecretNode, error) {
	var secrets []*models.SecretNode
	err := ls.db.WithContext(ctx).Model(&models.SecretNode{}).
		Joins("JOIN environments ON environments.id = secret_nodes.environment_id AND environments.project_id = ?", projectID).
		Joins("LEFT JOIN users ON users.id = secret_nodes.owner_id AND users.deleted_at IS NULL").
		Where("secret_nodes.project_id = ?", projectID).
		Where("users.id IS NULL").
		Order("secret_nodes.name ASC").
		Limit(maxUnboundedListRows).
		Find(&secrets).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return secrets, nil
}

// CountOrphanedSecretsByProject returns the same "owner no longer live" count as
// ListOrphanedSecrets, for every project in projectIDs, via a single
// `GROUP BY secret_nodes.project_id` query — the deployment-wide counterpart used
// by the hygiene rollup (#393) instead of calling ListOrphanedSecrets once per
// project (which turned "every project" into a per-project round trip). A project
// with no orphaned secrets is simply absent from the returned map.
func (ls *LocalStorage) CountOrphanedSecretsByProject(ctx context.Context, projectIDs []uint) (map[uint]int, error) {
	counts := make(map[uint]int)
	if len(projectIDs) == 0 {
		return counts, nil
	}
	type row struct {
		ProjectID uint
		N         int64
	}
	var rows []row
	err := ls.db.WithContext(ctx).Model(&models.SecretNode{}).
		Select("secret_nodes.project_id AS project_id, COUNT(*) AS n").
		Joins("JOIN environments ON environments.id = secret_nodes.environment_id AND environments.project_id = secret_nodes.project_id").
		Joins("LEFT JOIN users ON users.id = secret_nodes.owner_id AND users.deleted_at IS NULL").
		Where("secret_nodes.project_id IN ?", projectIDs).
		Where("users.id IS NULL").
		Group("secret_nodes.project_id").
		Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	for _, r := range rows {
		counts[r.ProjectID] = int(r.N)
	}
	return counts, nil
}

// CountSecretsByEnvironment returns the live-secret count (is_secret, not
// soft-deleted) for every environment in envIDs via a single
// `GROUP BY environment_id` query, so the environment list needs no per-environment
// round trip. An environment with no secrets is simply absent from the map.
func (ls *LocalStorage) CountSecretsByEnvironment(ctx context.Context, envIDs []uint) (map[uint]int64, error) {
	counts := make(map[uint]int64)
	if len(envIDs) == 0 {
		return counts, nil
	}
	type row struct {
		EnvironmentID uint
		N             int64
	}
	var rows []row
	// Model() applies GORM's soft-delete scope (secret_nodes.deleted_at IS NULL).
	err := ls.db.WithContext(ctx).Model(&models.SecretNode{}).
		Select("secret_nodes.environment_id AS environment_id, COUNT(*) AS n").
		Where("secret_nodes.environment_id IN ?", envIDs).
		Where("secret_nodes.is_secret = ?", true).
		Group("secret_nodes.environment_id").
		Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	for _, r := range rows {
		counts[r.EnvironmentID] = r.N
	}
	return counts, nil
}

// CountExpiringSecretsByProject returns, for every project in projectIDs, the
// count of live secrets with a non-null expiration before expiresBefore — the
// same definition ListSecrets(ExpiresBefore) uses per-project, but grouped into a
// single deployment-wide query for the hygiene rollup (#393). A project with no
// expiring secrets is simply absent from the returned map.
func (ls *LocalStorage) CountExpiringSecretsByProject(ctx context.Context, projectIDs []uint, expiresBefore time.Time) (map[uint]int, error) {
	// G81 (SecretNode.Expiration): normalize internally — see GetAuditLogs.
	expiresBefore = expiresBefore.UTC()
	counts := make(map[uint]int)
	if len(projectIDs) == 0 {
		return counts, nil
	}
	type row struct {
		ProjectID uint
		N         int64
	}
	var rows []row
	err := ls.db.WithContext(ctx).Model(&models.SecretNode{}).
		Select("project_id, COUNT(*) AS n").
		Where("project_id IN ?", projectIDs).
		Where("expiration IS NOT NULL AND expiration < ?", expiresBefore).
		Group("project_id").
		Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	for _, r := range rows {
		counts[r.ProjectID] = int(r.N)
	}
	return counts, nil
}

// ListLiveSecretNamesByProject returns every live secret (folders excluded) across
// every project in projectIDs — id/name/type/classification/environment plus its
// project ID — in a SINGLE query ordered by project then name, instead of one
// ListSecrets call per project (#416, the deployment-wide name-conformance scan's
// N+1 fix). Fetches one row beyond limit so truncation can be reported without a
// separate COUNT query.
func (ls *LocalStorage) ListLiveSecretNamesByProject(ctx context.Context, projectIDs []uint, limit int) ([]storage.SecretNameRow, bool, error) {
	if len(projectIDs) == 0 {
		return nil, false, nil
	}
	var rows []storage.SecretNameRow
	err := ls.db.WithContext(ctx).Model(&models.SecretNode{}).
		Select("project_id, id, name, type, classification, environment_id").
		Where("project_id IN ?", projectIDs).
		Where("is_secret = ?", true).
		Order("project_id ASC, name ASC").
		Limit(limit + 1).
		Scan(&rows).Error
	if err != nil {
		return nil, false, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	truncated := false
	if len(rows) > limit {
		truncated = true
		rows = rows[:limit]
	}
	return rows, truncated, nil
}

// GetSecretTags returns the secret's tag names, sorted.
func (ls *LocalStorage) GetSecretTags(ctx context.Context, secretID uint) ([]string, error) {
	var names []string
	err := ls.db.WithContext(ctx).
		Model(&models.Tag{}).
		Joins("JOIN secret_tags ON secret_tags.tag_id = tags.id").
		Where("secret_tags.secret_node_id = ?", secretID).
		Order("tags.name ASC").
		Pluck("tags.name", &names).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return names, nil
}

// SetSecretTags replaces the secret's tag associations with exactly tagNames,
// upserting any new Tag rows by name. Runs in a transaction so the secret never
// observes a partial tag set.
func (ls *LocalStorage) SetSecretTags(ctx context.Context, secretID uint, tagNames []string) error {
	return ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where(sqlWhereSecretNodeID, secretID).Delete(&models.SecretTag{}).Error; err != nil {
			return fmt.Errorf("clear tags: %w", err)
		}
		for _, name := range tagNames {
			var tag models.Tag
			if err := tx.Where(models.Tag{Name: name}).FirstOrCreate(&tag).Error; err != nil {
				return fmt.Errorf("upsert tag %q: %w", name, err)
			}
			if err := tx.Create(&models.SecretTag{SecretNodeID: secretID, TagID: tag.ID}).Error; err != nil {
				return fmt.Errorf("link tag %q: %w", name, err)
			}
		}
		return nil
	})
}

// --- Versions ---

// maxSecretVersionValueSize is the storage layer's own, unconditional backstop on
// a secret version's stored (encrypted) value size — see
// storage.ErrSecretValueTooLarge's doc comment for why this exists as defense in
// depth behind internal/core.checkSecretSize's operator-configured, potentially
// smaller limit, rather than duplicating that configured value here.
// internal/storage/store deliberately does not import internal/config (this
// package sits below it in the dependency layering), so this is independently
// defined rather than shared — kept in sync with config.MaxSecretSizeHardCeiling
// by TestMaxSecretVersionValueSize_MatchesConfigHardCeiling.
const maxSecretVersionValueSize = 1 << 20 // 1 MiB, mirrors config.MaxSecretSizeHardCeiling

// CreateSecretVersion creates a new version of a secret.
func (ls *LocalStorage) CreateSecretVersion(ctx context.Context, version *models.SecretVersion) (*models.SecretVersion, error) {
	if len(version.EncryptedValue) > maxSecretVersionValueSize {
		return nil, fmt.Errorf("%w: %d bytes exceeds the %d-byte hard ceiling",
			storage.ErrSecretValueTooLarge, len(version.EncryptedValue), maxSecretVersionValueSize)
	}
	if err := ls.db.WithContext(ctx).Create(version).Error; err != nil {
		if isUniqueViolation(err) {
			// The unique index on (secret_node_id, version_number) (#121) caught a
			// concurrent rotation that already claimed this version number. Translate to
			// the sentinel so RotateSecret can retry with a freshly re-read latest version
			// instead of failing the rotation outright on ordinary contention.
			return nil, fmt.Errorf("%w: %v", storage.ErrDuplicateSecretVersion, err)
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	// No secret_nodes touch here, deliberately. An earlier revision bumped the
	// node's updated_at from this method so the latest-version cache would be
	// invalidated by a new version; that is now unnecessary (the version cache's
	// generation is derived from the version rows themselves — see
	// secret_metadata_cache.go's liveVersionsGeneration) and was actively
	// harmful: it put a second UPDATE on one shared secret_nodes row inside
	// rotation's transaction, and made invalidation depend on the stored
	// timestamp's RESOLUTION, which storeNextSecretVersion's retry loop
	// re-entered fast enough to tie
	// (TestConcurrency_RotateSecret_NoDuplicateVersionNumbers, red in CI on
	// 86dea1220).
	return version, nil
}

// GetSecretVersions retrieves all versions of a secret ordered newest-first.
func (ls *LocalStorage) GetSecretVersions(ctx context.Context, secretID uint) ([]*models.SecretVersion, error) {
	var versions []*models.SecretVersion
	if err := ls.db.WithContext(ctx).Where(sqlWhereSecretNodeID, secretID).Order("version_number DESC").Find(&versions).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return versions, nil
}

// GetLatestSecretVersion retrieves the most recent version of a secret.
func (ls *LocalStorage) GetLatestSecretVersion(ctx context.Context, secretID uint) (*models.SecretVersion, error) {
	if version, hit := ls.getCachedLatestVersion(ctx, secretID); hit {
		if version == nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorVersionNotFound", nil), storage.ErrSecretVersionNotFound)
		}
		cp := *version
		return &cp, nil
	}
	// Read the generation BEFORE the version query (coordinator review of
	// #2764): a rotation committing between the two would otherwise cache the
	// pre-rotation version under the post-rotation generation, and the old value
	// would keep being served. Read first, a race can only produce an entry under
	// an already-stale generation, which never hits.
	liveGen, genErr := liveVersionsGeneration(ctx, ls.db, secretID)
	return ls.readLatestSecretVersionRow(ctx, secretID, liveGen, genErr)
}

// readLatestSecretVersionRow is GetLatestSecretVersion's cache-miss tail: the
// version row query, and the publish under liveGen. liveGen/genErr MUST have
// been read BEFORE this is called (see GetLatestSecretVersion); shared with
// GetSecretScheduleAndLatestVersion, which reads the generation in its combined
// statement.
func (ls *LocalStorage) readLatestSecretVersionRow(ctx context.Context, secretID uint, liveGen versionsGeneration, genErr error) (*models.SecretVersion, error) {
	var version models.SecretVersion
	err := ls.db.WithContext(ctx).Where(sqlWhereSecretNodeID, secretID).Order("version_number DESC").First(&version).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			if genErr == nil && ls.cacheEnabled {
				ls.secretMetaCache.setVersion(secretID, liveGen, nil)
			}
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorVersionNotFound", nil), storage.ErrSecretVersionNotFound)
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	// Only cache when the generation read itself succeeded — never cache
	// against a generation-check error (fail closed: an uncached version is
	// simply a future cache miss, never a correctness problem) — and never from
	// inside a transaction, where both the generation and the version row are
	// UNCOMMITTED and a rollback would leave this entry to be validated by the
	// next committed write that reproduces the same aggregate (see
	// cacheEnabled's doc comment on LocalStorage).
	if genErr == nil && ls.cacheEnabled {
		cp := version
		ls.secretMetaCache.setVersion(secretID, liveGen, &cp)
	}
	return &version, nil
}

// getCachedLatestVersion returns (version, true) on a confirmed-current hit
// — version is nil when the cache has already confirmed "no version exists"
// for the current generation. Returns (nil, false) on any miss.
func (ls *LocalStorage) getCachedLatestVersion(ctx context.Context, secretID uint) (*models.SecretVersion, bool) {
	if !ls.cacheEnabled {
		return nil, false
	}
	cached, ok := ls.secretMetaCache.getVersion(secretID)
	if !ok || !cached.hasVersion {
		return nil, false
	}
	liveGen, err := liveVersionsGeneration(ctx, ls.db, secretID)
	if err != nil || liveGen != cached.generation {
		return nil, false
	}
	return cached.latestVersion, true
}

// IncrementSecretReadCount atomically increments the read counter for a secret version.
func (ls *LocalStorage) IncrementSecretReadCount(ctx context.Context, versionID uint) error {
	if err := ls.db.WithContext(ctx).Model(&models.SecretVersion{}).
		Where(sqlWhereID, versionID).
		UpdateColumn("read_count", gorm.Expr(sqlIncrReadCount)).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// TryIncrementSecretReadCount atomically increments read_count only while it is
// still below maxReads. The conditional WHERE makes check-and-increment a single
// row-level-serialized UPDATE, so concurrent reads of a max-reads secret can never
// collectively exceed the cap. RowsAffected==1 means this read is within the cap.
func (ls *LocalStorage) TryIncrementSecretReadCount(ctx context.Context, versionID uint, maxReads int) (bool, error) {
	res := ls.db.WithContext(ctx).Model(&models.SecretVersion{}).
		Where("id = ? AND read_count < ?", versionID, maxReads).
		UpdateColumn("read_count", gorm.Expr(sqlIncrReadCount))
	if res.Error != nil {
		return false, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), res.Error)
	}
	return res.RowsAffected == 1, nil
}

// TryIncrementSecretNodeReadCount is TryIncrementSecretReadCount's secret-level
// twin (#133): the same atomic conditional-UPDATE pattern, keyed on the secret
// (secret_nodes.read_count) instead of a version, so the cap survives rotate/
// rollback creating a new version.
func (ls *LocalStorage) TryIncrementSecretNodeReadCount(ctx context.Context, secretID uint, maxReads int) (bool, error) {
	res := ls.db.WithContext(ctx).Model(&models.SecretNode{}).
		Where("id = ? AND read_count < ?", secretID, maxReads).
		UpdateColumn("read_count", gorm.Expr(sqlIncrReadCount))
	if res.Error != nil {
		return false, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), res.Error)
	}
	return res.RowsAffected == 1, nil
}

// maxAncestorDepth caps the ParentID chain walk to prevent infinite loops
// from accidental circular references in secret_nodes.parent_id.
const maxAncestorDepth = 20

// GetSecretAncestors walks the ParentID chain for nodeID and returns the
// ancestor IDs ordered from immediate parent to root. Capped at
// maxAncestorDepth levels. Stopping early (cycle / depth limit) never
// returns an error — missing ancestors are simply absent, the caller walks
// as far as the chain allows.
func (ls *LocalStorage) GetSecretAncestors(ctx context.Context, nodeID uint) ([]uint, error) {
	var ancestors []uint
	visited := make(map[uint]struct{})
	currentID := nodeID
	for range maxAncestorDepth {
		var node models.SecretNode
		err := ls.db.WithContext(ctx).
			Select("id", "parent_id").
			First(&node, currentID).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			break // node not found — stop walk
		}
		if err != nil {
			return nil, fmt.Errorf("get secret ancestors (node %d): %w", currentID, err)
		}
		if node.ParentID == nil {
			break // reached the root
		}
		parentID := *node.ParentID
		if _, seen := visited[parentID]; seen {
			break // cycle guard
		}
		visited[parentID] = struct{}{}
		ancestors = append(ancestors, parentID)
		currentID = parentID
	}
	return ancestors, nil
}

// latestUTC returns the later of a project's own updated_at and its newest
// secret's updated_at as UTC RFC 3339. If either value does not parse it falls
// back to the previous lexical choice rather than dropping the field.
func latestUTC(projectUpdated string, secretUpdated *string) string {
	if secretUpdated == nil {
		return utcRFC3339(projectUpdated)
	}
	pt, pok := parseDBTimestamp(projectUpdated)
	st, sok := parseDBTimestamp(*secretUpdated)
	if pok && sok {
		if st.After(pt) {
			return st.UTC().Format(time.RFC3339Nano)
		}
		return pt.UTC().Format(time.RFC3339Nano)
	}
	if *secretUpdated > projectUpdated {
		return utcRFC3339(*secretUpdated)
	}
	return utcRFC3339(projectUpdated)
}
