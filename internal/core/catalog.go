package core

import (
	"context"
	"errors"
	"fmt"
	"log"
	"regexp"
	"runtime/debug"
	"strings"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// #383: bounds on the project/environment catalog so a single request can't blow
// past a reasonable working set. maxEnvNamesPerCreate is generous relative to
// defaultEnvironmentNames' 3-entry convention — a few dozen covers realistic
// per-region/per-service environment fan-out — while still keeping
// CreateProjectWithEnvs's loop bounded instead of open to a ~10 MiB request body
// (a JSON array entry as short as `"a",` fits roughly 1-2 million times in that
// budget) requesting on the order of a million environments in one call.
// maxProjectNameLen/maxEnvironmentNameLen cap the unbounded `Name` text columns
// (Project.Name/Environment.Name) so an oversized name can't compound the same
// row/index bloat; a few hundred characters is generous for a name field.
const (
	maxEnvNamesPerCreate  = 50
	maxProjectNameLen     = 200
	maxEnvironmentNameLen = 200
)

// EventProjectCreated/EventProjectUpdated/EventProjectDeleted are audited on
// every project create/update/delete, REST and gRPC alike (F2, audit-
// completeness campaign) — previously CreateProject/CreateProjectWithEnvs/
// UpdateProject/DeleteProject wrote no audit event of their own at all,
// despite RestoreProject/environment.restored (both in this same file)
// already following this exact convention.
//
// Like EventUserCreated/EventUserUpdated (users.go), these are written via
// standalone LogProjectCreated/LogProjectUpdated/LogProjectDeleted methods
// rather than parameters baked into CreateProject/CreateProjectWithEnvs/
// UpdateProject/DeleteProject's own signatures — same reasoning as
// LogRoleCreated/LogRoleUpdated/LogRoleDeleted (audit.go): those four
// functions are called from many existing test fixtures with no caller
// identity in scope, and every real REST/gRPC call site already knows the
// actor at the point it calls them.
const (
	EventProjectCreated = "project.created"
	EventProjectUpdated = "project.updated"
	EventProjectDeleted = "project.deleted"
)

// EventProjectEnvironmentSeedFailed is audited when CreateProject/CreateProjectWithEnvs's
// per-environment seeding step fails or panics (seedProjectEnvironment). The project row
// itself has already committed by then (non-fatal by design -- see seedProjectEnvironment's
// doc comment), so this is the ONLY durable, queryable record that the project came out
// short an environment; previously this was a log.Printf only, visible to an operator
// tailing server logs but invisible to the audit trail, the API response, or any
// automated reconciliation sweep -- "observable" in the original #1996 fix did not mean
// "discoverable by the caller." Same convention as dynamic_secret.project_cascade_failed
// (revokeProjectDynamicSecretLeases, this file) for the identical class of problem.
const EventProjectEnvironmentSeedFailed = "project.environment_seed_failed"

// LogProjectCreated/LogProjectUpdated/LogProjectDeleted record a project
// create/update/delete. actorID is the acting admin (0 = none). See the
// EventProjectCreated doc comment above for why these are standalone methods.
func (c *KeyorixCore) LogProjectCreated(ctx context.Context, actorID, projectID uint, name string) {
	pid := projectID
	c.writeAuditEventFull(ctx, EventProjectCreated, actorPtr(actorID), nil, &pid, "",
		fmt.Sprintf("project %d (%q) created", projectID, name))
}

func (c *KeyorixCore) LogProjectUpdated(ctx context.Context, actorID, projectID uint, name string) {
	pid := projectID
	c.writeAuditEventFull(ctx, EventProjectUpdated, actorPtr(actorID), nil, &pid, "",
		fmt.Sprintf("project %d (%q) updated", projectID, name))
}

// name is read by the caller BEFORE the delete (the row is gone afterwards and
// there is no include-deleted project getter); empty degrades to the bare id.
func (c *KeyorixCore) LogProjectDeleted(ctx context.Context, actorID, projectID uint, name string, force bool) {
	pid := projectID
	c.writeAuditEventFull(ctx, EventProjectDeleted, actorPtr(actorID), nil, &pid, "",
		fmt.Sprintf("%s deleted (force=%t)", formatAuditRef(auditKindProject, projectID, name), force))
}

// identifierRegex is the anti-homograph/anti-spoofing charset guard (G38):
// letters, digits, spaces, hyphens, and underscores only — no zero-width
// characters, no mixed-script confusables, no control characters. Ported
// verbatim from server/validation/validator.go's identical `identifier` rule.
// Before this fix, this charset check was enforced ONLY by the HTTP JSON
// decoder's `validate:"identifier"` struct tag on the request body — the
// gRPC service layer and CLI embedded-mode path, which construct a Project
// directly without ever routing through that HTTP-specific validator, could
// create a project whose name silently smuggled a confusable/spoofed
// character sequence past every UI and audit log that assumes the HTTP path
// already sanitized it. Duplicated here (not imported from server/validation)
// to keep internal/core independent of the server/* packages that depend on
// it, matching this file's existing validateProjectName/validateEnvironmentName
// convention.
var identifierRegex = regexp.MustCompile(`^[a-zA-Z0-9 _-]+$`)

func validateIdentifier(name string) error {
	if !identifierRegex.MatchString(name) {
		return fmt.Errorf("%s: must contain only letters, digits, spaces, - or _", i18n.T("ErrorValidation", nil))
	}
	// Mirrors server/validation/validator.go's validateIdentifier: reject
	// whitespace variants that pass the charset check above but defeat the
	// anti-spoofing intent — all-whitespace, leading/trailing whitespace, or
	// repeated internal whitespace (e.g. "Support Team" vs "Support  Team").
	if trimmed := strings.TrimSpace(name); trimmed == "" || trimmed != name || strings.Contains(trimmed, "  ") {
		return fmt.Errorf("%s: must not be all whitespace or have leading, trailing, or repeated internal whitespace", i18n.T("ErrorValidation", nil))
	}
	return nil
}

// validateProjectName bounds Project.Name (#383): required, and capped so an
// unbounded text column can't be used to bloat storage/index size. Also
// enforces the anti-homograph identifier charset (G38) — see validateIdentifier.
func validateProjectName(name string) error {
	if name == "" {
		return fmt.Errorf("%s: project name is required", i18n.T("ErrorValidation", nil))
	}
	if len(name) > maxProjectNameLen {
		return fmt.Errorf("%s: project name exceeds %d characters", i18n.T("ErrorValidation", nil), maxProjectNameLen)
	}
	return validateIdentifier(name)
}

// validateEnvironmentName bounds Environment.Name (#383), mirroring
// validateProjectName. Also enforces the anti-homograph identifier charset
// (G38) — see validateIdentifier. Environment names were previously missed by
// G38's project-name fix, so a confusable/spoofed environment name could
// still slip past every transport (gRPC, CLI embedded mode), not just HTTP.
func validateEnvironmentName(name string) error {
	if name == "" {
		return fmt.Errorf("%s: environment name is required", i18n.T("ErrorValidation", nil))
	}
	if len(name) > maxEnvironmentNameLen {
		return fmt.Errorf("%s: environment name exceeds %d characters", i18n.T("ErrorValidation", nil), maxEnvironmentNameLen)
	}
	return validateIdentifier(name)
}

// translateProjectNameError surfaces storage.ErrDuplicateProjectName (#385, the
// case-insensitive partial unique index on projects.name) as a clean "name already in
// use" validation error, mirroring CreateUser's translation of ErrDuplicateEmail (#117),
// rather than letting a raw constraint-violation message reach the caller.
func translateProjectNameError(err error) error {
	if errors.Is(err, storage.ErrDuplicateProjectName) {
		return fmt.Errorf("%s: a project with this name already exists", i18n.T("ErrorValidation", nil))
	}
	return err
}

// ListProjects returns all projects from storage.
func (c *KeyorixCore) ListProjects(ctx context.Context) ([]*models.Project, error) {
	return c.storage.ListProjects(ctx)
}

// ListProjectsWithCounts returns projects with secret and environment counts.
// When includeDeleted is true, soft-deleted projects are included (flagged via
// the Deleted/DeletedAt fields) for the restore UI.
func (c *KeyorixCore) ListProjectsWithCounts(ctx context.Context, includeDeleted bool) ([]storage.ProjectWithCounts, error) {
	return c.storage.ListProjectsWithCounts(ctx, includeDeleted)
}

// GetProject returns a single project by ID.
func (c *KeyorixCore) GetProject(ctx context.Context, id uint) (*models.Project, error) {
	return c.storage.GetProject(ctx, id)
}

// UpdateProject updates an existing project's name and description, and — when
// requireMFA is non-nil — its per-project MFA requirement (ADR-037). A nil
// requireMFA leaves the flag unchanged (backward-compatible).
func (c *KeyorixCore) UpdateProject(ctx context.Context, id uint, name, description string, requireMFA *bool) (*models.Project, error) {
	if err := validateProjectName(name); err != nil {
		return nil, err
	}
	if err := validateDescription(description); err != nil {
		return nil, err
	}
	project, err := c.storage.GetProject(ctx, id)
	if err != nil {
		return nil, err
	}
	mfaChanged := requireMFA != nil && *requireMFA != project.RequireMFA
	// #2697: a column-scoped write of the fields this call actually owns, onto a
	// row that is still live. The previous full-row Save carried the whole
	// pre-read struct back: its upsert fallback resurrected a project deleted
	// after the GetProject above, and it rewrote require_mfa even when requireMFA
	// was nil — silently disabling an ADR-037 per-project MFA requirement an
	// admin had just enabled, with no audit event, since mfaChanged is false in
	// exactly that case. requireMFA stays a pointer all the way down so a nil one
	// never reaches the UPDATE's SET list.
	matched, err := c.storage.UpdateProjectFields(ctx, id, name, description, requireMFA, c.now())
	if err != nil {
		return nil, translateProjectNameError(err)
	}
	if !matched {
		return nil, fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
	}
	// Return the committed row, not the struct read before the write.
	updated, err := c.storage.GetProject(ctx, id)
	if err != nil {
		return nil, err
	}
	if mfaChanged {
		pid := id
		state := "disabled"
		if *requireMFA {
			state = "enabled"
		}
		c.writeAuditEventFull(ctx, "project.mfa_requirement_"+state, nil, nil, &pid, "",
			fmt.Sprintf("per-project MFA requirement %s for project %q", state, updated.Name))
	}
	return updated, nil
}

// ProjectRequiresMFA reports whether the project enforces a per-project MFA
// requirement (ADR-037). A missing project is treated as not requiring MFA.
func (c *KeyorixCore) ProjectRequiresMFA(ctx context.Context, projectID uint) (bool, error) {
	project, err := c.storage.GetProject(ctx, projectID)
	if err != nil {
		return false, err
	}
	return project.RequireMFA, nil
}

// DeleteProject deletes a project by ID.
// By default (force=false) it returns an error if the project still contains secrets (ADR-019).
// Pass force=true to delete the project and all its secrets (cascade).
//
// #369: the storage-layer cascade (LocalStorage.DeleteProject) also disables every
// dynamic-secret config scoped to the project in the same transaction, so IssueLease/
// RenewLease refuse to touch it from the instant the delete commits. Once that commits,
// this revokes every active (and previously revoke_failed) lease under those configs
// against their real targets — deliberately AFTER the transaction, and best-effort: each
// call is real network I/O to an operator-defined external database, which must not hold
// a DB transaction open, and a target being unreachable must not block the project delete
// itself (the lease stays revoke_failed/retryable, same as any other RevokeLeasesForConfig
// use, and is reachable again via the sweep or a manual retry once the target recovers).
func (c *KeyorixCore) DeleteProject(ctx context.Context, id uint, force bool) error {
	// #313 / #528: the guard count and the cascade delete must not run as two separate
	// top-level storage calls with core-layer control flow in between — a secret created
	// in that window would silently get swept into the cascade despite the caller
	// expecting the delete to be rejected. #313 originally closed this by running both
	// inside one storage.WithTransaction call; #528 replaced that with
	// DeleteProjectIfEmpty, a single atomic storage primitive doing the same guard+
	// cascade in ONE call. force=true intentionally skips the guard entirely and keeps
	// calling the plain unconditional cascade.
	if force {
		if err := c.storage.DeleteProject(ctx, id); err != nil {
			return err
		}
	} else {
		blocking, err := c.storage.DeleteProjectIfEmpty(ctx, id)
		if err != nil {
			return err
		}
		if blocking > 0 {
			return fmt.Errorf("project has %d secret(s) — delete them first or use --force to cascade", blocking)
		}
	}
	c.revokeProjectDynamicSecretLeases(ctx, id)
	return nil
}

// revokeProjectDynamicSecretLeases is DeleteProject's post-commit dynamic-secrets
// cascade (#369): it revokes every active lease under every dynamic-secret config
// scoped to id (the config rows themselves were already marked Disabled inside
// DeleteProject's transaction). Best-effort and system-actored (userID 0, like the
// expiry sweep) — a target-side revoke failure is recorded per-lease (revoke_failed,
// retryable) by RevokeLeasesForConfig and must not fail project deletion itself, which
// has already committed by the time this runs.
//
// A panic from this cascade (ListDynamicSecretConfigs or RevokeLeasesForConfig) is
// recovered here rather than left to propagate: DeleteProject's own transaction has
// already committed by the time this runs, so a panic escaping to the HTTP/gRPC
// handler would misreport a project that is, in fact, already deleted as a failed
// request (oracle (a) — same class of fix as CreateProject's seeding recover above).
// Un-revoked leases stay discoverable exactly as for the existing per-config error
// path: recorded via dynamic_secret.project_cascade_failed and left revoke_failed/
// retryable via the sweep or a manual retry. A panic BEFORE commit (inside
// DeleteProject's own transaction) is deliberately NOT covered by this recover — it
// must still roll back and surface as an error, which is why this recover lives here
// and not around DeleteProject as a whole.
func (c *KeyorixCore) revokeProjectDynamicSecretLeases(ctx context.Context, projectID uint) {
	defer func() {
		if r := recover(); r != nil {
			c.writeAuditEventFull(ctx, "dynamic_secret.project_cascade_failed", nil, nil, &projectID, "",
				fmt.Sprintf("panic revoking dynamic-secret leases after project %d deletion: %v — revoke them manually", projectID, r))
			log.Printf("project %d dynamic-secret lease revocation cascade panicked: %v\n%s", projectID, r, debug.Stack())
		}
	}()
	configs, err := c.storage.ListDynamicSecretConfigs(ctx, projectID, 0)
	if err != nil {
		c.writeAuditEventFull(ctx, "dynamic_secret.project_cascade_failed", nil, nil, &projectID, "",
			fmt.Sprintf("failed to list dynamic-secret configs to revoke after project %d deletion: %v — revoke them manually", projectID, err))
		return
	}
	if len(configs) == 0 {
		return
	}
	var revokedTotal, failedTotal int
	for _, cfg := range configs {
		revoked, failed, rerr := c.RevokeLeasesForConfig(ctx, cfg.ID, 0, "project deleted")
		if rerr != nil {
			// RevokeLeasesForConfig only errors on a failure to even list the config's
			// leases (not on a per-lease target failure, which it counts in `failed`
			// instead) — still non-fatal here; audited below alongside the summary.
			failedTotal++
			continue
		}
		revokedTotal += revoked
		failedTotal += failed
	}
	c.writeAuditEventFull(ctx, "dynamic_secret.project_cascade_revoke", nil, nil, &projectID, "",
		fmt.Sprintf("project %d delete disabled %d dynamic-secret config(s) and revoked %d active lease(s) (%d failed — see per-lease audit)",
			projectID, len(configs), revokedTotal, failedTotal))
}

// RestoreProject reverses a soft-delete, bringing back the project and the
// environments and secrets that were removed with it. actorID is the acting admin
// (0 = none). Audited as project.restored, with a per-type count of what the
// cascade actually resurrected (#311) — the storage layer already refuses to touch
// children retired independently of the project (see LocalStorage.RestoreProject's
// deletion-timestamp correlation), but the single generic event previously gave no
// way to tell HOW MANY environments/secrets came back, so a DR-test or accidental
// delete-then-undo left no forensic trail distinguishing "1 secret" from "200".
//
// #161: restoring reinstates every role bound to the project (any environment), so
// before restoring, this checks that aggregate role SET against the actor's own
// authority — the same treatment #147 applies to group restore. See
// requireGlobalAdminToReinstateAdminRoles.
//
// #369: unlike secrets/environments, this deliberately does NOT re-enable the
// project's dynamic-secret configs that DeleteProject's cascade disabled. A
// resurrected dynamic-secret config can immediately mint live database
// credentials against a real external target the instant it's re-enabled — a
// materially higher-consequence "silent resurrection" than a restored static
// secret (whose value is inert until read). Leaving configs disabled-until-
// manually-re-enabled means an admin must make an explicit, auditable decision
// (SetDynamicSecretConfigEnabled, per config) rather than a bulk project
// restore quietly reinstating database-credential issuance nobody explicitly
// asked to bring back. Restoring leases themselves is not on the table at all
// — they were revoked against the real target, not just marked; there is no
// "credential" left to restore.
func (c *KeyorixCore) RestoreProject(ctx context.Context, actorID, id uint) error {
	if err := c.requireAuthorityToReinstateProjectRoles(ctx, actorID, id, "project"); err != nil {
		return err
	}
	envCount, secretCount, err := c.storage.RestoreProject(ctx, id)
	if err != nil {
		return err
	}
	pid := id
	c.writeAuditEventFull(ctx, "project.restored", actorPtr(actorID), nil, &pid, "",
		fmt.Sprintf("%s restored (cascade resurrected %d environment(s) and %d secret(s))", c.auditRef(ctx, c.storage, auditKindProject, id), envCount, secretCount))
	return nil
}

// requireAuthorityToReinstateProjectRoles collects every role bound directly to
// projectID (any environment, user or group grant) and refuses if that set
// contains an admin-tier role the actor cannot themselves match. Shared by
// RestoreProject and RestoreEnvironment (an environment's role grants are a
// subset of its project's).
func (c *KeyorixCore) requireAuthorityToReinstateProjectRoles(ctx context.Context, actorID, projectID uint, objectDesc string) error {
	assignments, err := c.storage.ListProjectRoleAssignments(ctx, projectID)
	if err != nil {
		return fmt.Errorf("failed to resolve project role grants: %w", err)
	}
	roleIDs := make([]uint, 0, len(assignments))
	for _, a := range assignments {
		roleIDs = append(roleIDs, a.RoleID)
	}
	return c.requireGlobalAdminToReinstateAdminRoles(ctx, actorID, roleIDs, objectDesc)
}

// DeleteEnvironment deletes an environment by ID. The active-secret guard
// and its serialization against a concurrent CreateSecret both live in the
// storage layer (LocalStorage.DeleteEnvironment's own doc comment,
// internal/storage/store/local_secrets.go) -- this core wrapper is
// deliberately thin.
func (c *KeyorixCore) DeleteEnvironment(ctx context.Context, id uint) error {
	return c.storage.DeleteEnvironment(ctx, id)
}

// EventEnvironmentCreated/EventEnvironmentDeleted are audited on every
// environment create/delete (F3, audit-completeness campaign). Standalone
// methods, not parameters on CreateEnvironment/DeleteEnvironment themselves
// -- same reasoning as LogRoleCreated/LogRoleUpdated/LogRoleDeleted (audit.go)
// and this file's own LogProjectCreated/LogProjectUpdated/LogProjectDeleted.
const (
	EventEnvironmentCreated = "environment.created"
	EventEnvironmentDeleted = "environment.deleted"
)

// LogEnvironmentCreated records an environment creation. actorID is the
// creating admin (0 = none).
func (c *KeyorixCore) LogEnvironmentCreated(ctx context.Context, actorID, environmentID, projectID uint, name string) {
	pid := projectID
	c.writeAuditEventFull(ctx, EventEnvironmentCreated, actorPtr(actorID), nil, &pid, "",
		fmt.Sprintf("environment %d (%q) created in project %d", environmentID, name, projectID))
}

// LogEnvironmentDeleted records an environment deletion. actorID is the
// deleting admin (0 = none).
func (c *KeyorixCore) LogEnvironmentDeleted(ctx context.Context, actorID, environmentID uint) {
	c.writeAuditEvent(ctx, EventEnvironmentDeleted, actorPtr(actorID), nil,
		fmt.Sprintf("environment %d deleted", environmentID))
}

// RestoreEnvironment clears the soft-delete on an environment, scoped to
// projectID so a caller authorized for one project cannot restore another's.
// actorID is the acting admin (0 = none). Audited as environment.restored.
//
// #161: see RestoreProject — the same aggregate role-set ceiling check applies,
// scoped to the owning project (the environment's own grants are a subset of it).
func (c *KeyorixCore) RestoreEnvironment(ctx context.Context, actorID, projectID, id uint) error {
	if err := c.requireAuthorityToReinstateProjectRoles(ctx, actorID, projectID, "environment"); err != nil {
		return err
	}
	if err := c.storage.RestoreEnvironment(ctx, projectID, id); err != nil {
		return err
	}
	pid := projectID
	c.writeAuditEventFull(ctx, "environment.restored", actorPtr(actorID), nil, &pid, "", fmt.Sprintf("environment %d restored in project %d", id, projectID))
	return nil
}

// CreateProject creates a new project and seeds it with default environments.
func (c *KeyorixCore) CreateProject(ctx context.Context, name, description string) (*models.Project, error) {
	if err := validateProjectName(name); err != nil {
		return nil, err
	}
	if err := validateDescription(description); err != nil {
		return nil, err
	}
	// Wrap the project-row create and the default-environment seeding in one
	// storage.WithTransaction, same pattern as CreateRole/UpdateRole (#1969-class).
	// This closes the mixed-state half of the fault-fuzz finding (Project committed,
	// Environment never attempted) — an effect-then-error fault on the FIRST call now
	// rolls back to old state instead of leaving a mix; a lost-ack-after-commit fault
	// yields the full new state. Both are old-OR-new, which oracle (d) accepts. Does
	// NOT close the ambiguous-response half (the client is still told "error" even
	// when the write commits) — that needs an idempotency key, tracked separately.
	var project *models.Project
	var seedFailures []projectEnvSeedFailure
	txErr := c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
		var err error
		project, err = tx.CreateProject(ctx, &models.Project{Name: name, Description: description})
		if err != nil {
			return err
		}
		// Seed default environments for new project. Non-fatal (found by
		// fuzz-injecting a CreateEnvironment failure: the comment here used to
		// say "log and continue" but discarded the error with `_ = err` instead
		// of actually logging it — the project silently ended up missing one or
		// more of its expected default environments with zero operator
		// visibility into why): the project row itself already committed, and a
		// caller retries environment creation separately if seeding fails, but
		// this must be OBSERVABLE, not a swallowed error. See
		// seedProjectEnvironment's own doc comment for the SAVEPOINT/panic
		// handling shared with CreateProjectWithEnvs, and
		// reportProjectEnvironmentSeedFailures for why the audit write is
		// deferred until after this transaction commits.
		for _, envName := range defaultEnvironmentNames {
			if f := seedProjectEnvironment(ctx, tx, project, envName); f != nil {
				seedFailures = append(seedFailures, *f)
			}
		}
		return nil
	})
	c.reportProjectEnvironmentSeedFailures(ctx, project, seedFailures)
	if txErr != nil {
		if errors.Is(txErr, storage.ErrDuplicateProjectName) {
			return nil, translateProjectNameError(txErr)
		}
		return nil, fmt.Errorf("failed to create project: %w", txErr)
	}
	return project, nil
}

// ListEnvironments returns all environments from storage.
func (c *KeyorixCore) ListEnvironments(ctx context.Context) ([]*models.Environment, error) {
	return c.storage.ListEnvironments(ctx)
}

// ListEnvironmentsByProject returns environments scoped to a specific project.
func (c *KeyorixCore) ListEnvironmentsByProject(ctx context.Context, projectID uint) ([]*models.Environment, error) {
	return c.storage.ListEnvironmentsByProject(ctx, projectID)
}

// ListEnvironmentsByProjectIncludingDeleted returns a project's environments,
// including soft-deleted ones, for the restore UI.
func (c *KeyorixCore) ListEnvironmentsByProjectIncludingDeleted(ctx context.Context, projectID uint) ([]*models.Environment, error) {
	return c.storage.ListEnvironmentsByProjectIncludingDeleted(ctx, projectID)
}

// GetEnvironment returns a single environment by ID.
//
// storage.Storage's GetEnvironment/DeleteEnvironment take a bare, unscoped id
// (unlike RestoreEnvironment, which is deliberately project-scoped) because
// some legitimate callers don't yet know which project an id belongs to and
// use this to find out (e.g. server/middleware.ScopeFromEnvParam resolving an
// authorization scope from a URL id, or the read-only display-name cache in
// permission_matrix.go). Callers that already believe an environment belongs
// to a specific project — and would silently operate on the wrong tenant's
// environment if that belief were wrong — must use GetEnvironmentInProject
// below instead of calling this (or storage.GetEnvironment) directly.
func (c *KeyorixCore) GetEnvironment(ctx context.Context, id uint) (*models.Environment, error) {
	return c.storage.GetEnvironment(ctx, id)
}

// GetEnvironmentInProject returns an environment by id, but only if it
// actually belongs to projectID — the project-scoped counterpart to the bare
// GetEnvironment above, mirroring the scoping storage.Storage.RestoreEnvironment
// already gets from its signature. Use this (not GetEnvironment) whenever a
// caller already has a projectID in hand (from a nested URL path, a request
// body field, an active CLI project context, etc.) and is about to look up or
// act on an environment it BELIEVES belongs to that project — so a bare-id
// mismatch (the environment actually belongs to a different project) is
// refused instead of silently operating cross-tenant.
//
// Returns a generic "environment not found" error (not a distinct "wrong
// project" error) on mismatch, matching storage.GetEnvironment's own
// not-found error and RestoreEnvironment's WHERE-clause behavior, so a caller
// without access to project B can't use this to probe whether a given
// environment id exists there.
func (c *KeyorixCore) GetEnvironmentInProject(ctx context.Context, projectID, id uint) (*models.Environment, error) {
	env, err := c.storage.GetEnvironment(ctx, id)
	if err != nil {
		return nil, err
	}
	if env.ProjectID != projectID {
		return nil, fmt.Errorf("environment not found")
	}
	return env, nil
}

// CreateEnvironment creates a single environment under an existing project,
// validating the name (#383). This is the single-environment counterpart to
// CreateProjectWithEnvs's fan-out create; callers (the HTTP
// POST /projects/{id}/environments handler, the `keyorix project env create`
// CLI) previously wrote straight to storage, bypassing any name-length guard.
//
// G38: also confirms projectID names a LIVE (non-soft-deleted) project before
// creating anything under it. The HTTP handler's own scope middleware resolves
// projectID from the URL without verifying the project still exists, so
// without this check here, a caller who still held write authority on a
// since-soft-deleted project (RBAC grants aren't retroactively revoked by a
// project delete) could re-establish a usable environment/scope under it —
// storage.GetProject excludes soft-deleted projects, so this fails closed the
// same way the HTTP handler's own defense-in-depth check already does, but
// now for every transport (gRPC, CLI embedded mode) instead of only HTTP.
func (c *KeyorixCore) CreateEnvironment(ctx context.Context, projectID uint, name string) (*models.Environment, error) {
	if err := validateEnvironmentName(name); err != nil {
		return nil, err
	}
	if _, err := c.storage.GetProject(ctx, projectID); err != nil {
		return nil, fmt.Errorf("%s: project not found", i18n.T("ErrorNotFound", nil))
	}
	// #2710: the GetProject above is an unlocked read outside any transaction, so
	// DeleteProject's cascade can commit in the window between it and the insert.
	// The cascade row-locks the project and sweeps its environments, so the
	// legitimate order "delete wins, sweeps the environments that exist, commits;
	// create then inserts anyway" left a LIVE environment under a deleted project
	// — never purged (PurgeDeletedEnvironmentsBefore takes only deleted rows), so
	// it outlives the project purge, and core.CreateSecret checks only that the
	// environment is live, so a global-scope principal can then create secrets in
	// it. Same end state as #2656, which was fixed for RestoreEnvironment only.
	//
	// Insert then re-check, in one transaction. The GetProject above is kept as a
	// cheap early rejection with a better message; it is no longer what makes this
	// safe. Note the seed path (seedProjectEnvironment, called from
	// CreateProject/CreateProjectWithEnvs) does NOT come through here — it calls
	// tx.CreateEnvironment directly inside a transaction that just created the
	// project, so there is no deleted-parent window to close there.
	var env *models.Environment
	if err := c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
		var cerr error
		env, cerr = tx.CreateEnvironment(ctx, &models.Environment{ProjectID: projectID, Name: name})
		if cerr != nil {
			return cerr
		}
		live, lerr := tx.LockLiveProject(ctx, projectID)
		if lerr != nil {
			return lerr
		}
		if !live {
			return fmt.Errorf("%s: project %d was deleted while this environment was being created",
				i18n.T("ErrorNotFound", nil), projectID)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return env, nil
}

// CreateProjectWithEnvs creates a new project seeded with the specified environment names.
// Used when the CLI --envs flag overrides the default development/staging/production set.
func (c *KeyorixCore) CreateProjectWithEnvs(ctx context.Context, name, description string, envNames []string) (*models.Project, error) {
	if err := validateProjectName(name); err != nil {
		return nil, err
	}
	if err := validateDescription(description); err != nil {
		return nil, err
	}
	// #383: cap the environment fan-out before touching storage at all — without
	// this, a single ~10 MiB request (a JSON array entry as short as `"a",` fits
	// roughly 1-2 million times in that budget) could request on the order of a
	// million environments, degrading the shared install for every other tenant.
	if len(envNames) > maxEnvNamesPerCreate {
		return nil, fmt.Errorf("%s: at most %d environments per project create (got %d)",
			i18n.T("ErrorValidation", nil), maxEnvNamesPerCreate, len(envNames))
	}
	for _, envName := range envNames {
		if err := validateEnvironmentName(envName); err != nil {
			return nil, err
		}
	}
	// Same tx-wrap as CreateProject above, including the per-seed SAVEPOINT
	// (nested tx.WithTransaction) — a failed CreateEnvironment must not abort the
	// whole create on PostgreSQL, same reasoning as CreateProject's own loop.
	var project *models.Project
	var seedFailures []projectEnvSeedFailure
	txErr := c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
		var err error
		project, err = tx.CreateProject(ctx, &models.Project{Name: name, Description: description})
		if err != nil {
			return err
		}
		for _, envName := range envNames {
			if f := seedProjectEnvironment(ctx, tx, project, envName); f != nil {
				seedFailures = append(seedFailures, *f)
			}
		}
		return nil
	})
	c.reportProjectEnvironmentSeedFailures(ctx, project, seedFailures)
	if txErr != nil {
		if errors.Is(txErr, storage.ErrDuplicateProjectName) {
			return nil, translateProjectNameError(txErr)
		}
		return nil, fmt.Errorf("failed to create project: %w", txErr)
	}
	return project, nil
}

// projectEnvSeedFailure captures one failed/panicked per-environment seed from
// seedProjectEnvironment, for reportProjectEnvironmentSeedFailures to audit once the outer
// transaction has committed -- see that function's doc comment for why the audit write
// cannot safely happen while the transaction seedProjectEnvironment runs inside is still open.
type projectEnvSeedFailure struct {
	envName string
	reason  string
}

// seedProjectEnvironment creates one environment for a just-created project (shared by
// CreateProject's default set and CreateProjectWithEnvs's caller-specified set), inside its
// own nested tx.WithTransaction (a SAVEPOINT on PostgreSQL, gorm's own nested-transaction
// support). On PostgreSQL a FAILED STATEMENT aborts the enclosing transaction at the
// protocol level (any later statement errors, and COMMIT downgrades to ROLLBACK, pgx's
// ErrTxCommitRollback) — unlike SQLite, which has no such poisoning. Without the SAVEPOINT, a
// single faulted CreateEnvironment call would silently fail the WHOLE project create on
// Postgres, even though this is meant to be non-fatal. Found reviewing PR #1996 before merge
// — SQLite-only fault-fuzz validation stayed green despite this, since SQLite has no
// equivalent transaction-abort behavior.
//
// A failure (or a panic, recovered here — found live by FuzzStorageFaultOperations, same
// class as CreateUser's seeding in users.go: without it, a panic would propagate out to the
// Recovery middleware and misreport the create as a failed request, oracle (a)) is non-fatal
// by design (server/faultops's opScopedBestEffortTables entry for this exact call,
// #2350/#2252): the project row has already committed, and a caller recovers by calling
// POST /projects/{id}/environments for the missing name. Returns the failure (nil on
// success) for the caller to audit later -- NOT written here, even though project/envName are
// in scope: this runs inside the still-open outer tx (the same storage.WithTransaction call
// that created the project row), and c.writeAuditEventFull goes through c.storage, a
// DIFFERENT connection than tx. Writing from inside tx's own goroutine while tx itself still
// holds an open write transaction can self-deadlock on SQLite (single-writer: the audit
// INSERT blocks waiting for a lock only this same, still-uncommitted transaction holds, and
// it can't release that lock until the blocked call returns) — the exact shape
// TestCreateProject_SeedFailureSurvivesWithoutDeadlock guards against.
func seedProjectEnvironment(ctx context.Context, tx storage.Storage, project *models.Project, envName string) (failure *projectEnvSeedFailure) {
	defer func() {
		if r := recover(); r != nil {
			reason := fmt.Sprintf("seeding panicked: %v", r)
			log.Printf("Warning: project %d (%s) created without its environment %q: %s", project.ID, project.Name, envName, reason)
			failure = &projectEnvSeedFailure{envName: envName, reason: reason}
		}
	}()
	if err := tx.WithTransaction(ctx, func(savepoint storage.Storage) error {
		_, err := savepoint.CreateEnvironment(ctx, &models.Environment{Name: envName, ProjectID: project.ID})
		return err
	}); err != nil {
		log.Printf("Warning: project %d (%s) created without its environment %q: %v", project.ID, project.Name, envName, err)
		return &projectEnvSeedFailure{envName: envName, reason: err.Error()}
	}
	return nil
}

// reportProjectEnvironmentSeedFailures writes an EventProjectEnvironmentSeedFailed audit
// event for each environment seedProjectEnvironment failed to create, once the project's own
// transaction has returned (committed or not -- a no-op when failures is empty, which it
// always is when the transaction itself failed before reaching the seed loop). Deferred to
// here, after commit, specifically so the audit write — through c.storage, a connection
// distinct from the transaction's own tx handle — can never run while that transaction is
// still open; see seedProjectEnvironment's doc comment for the self-deadlock this avoids.
// Doing this makes the gap DISCOVERABLE via the audit trail, not just a log.Printf an
// operator happens to be tailing — the caller still recovers the same way either way: POST
// /projects/{id}/environments for the missing name.
func (c *KeyorixCore) reportProjectEnvironmentSeedFailures(ctx context.Context, project *models.Project, failures []projectEnvSeedFailure) {
	for _, f := range failures {
		msg := fmt.Sprintf("project %d (%s) created without its environment %q: %s — create it manually via POST /projects/%d/environments",
			project.ID, project.Name, f.envName, f.reason, project.ID)
		c.writeAuditEventFull(ctx, EventProjectEnvironmentSeedFailed, nil, nil, &project.ID, "", msg)
	}
}
