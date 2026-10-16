package storage

import (
	"context"
	"errors"
	"time"

	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ErrLegalHoldAlreadyActive is returned by CreateLegalHold when a partial unique
// index (or equivalent constraint) at the storage layer rejects a second concurrent
// placement — the backstop for the TOCTOU race in core.PlaceLegalHold's
// read-then-insert (#305): two concurrent placements can both observe "no active
// hold" and both attempt to insert one, but only the first commits. Callers should
// treat this as a client error ("already active"), not a storage failure.
var ErrLegalHoldAlreadyActive = errors.New("a legal hold is already active")

// Storage defines the unified interface for data persistence operations.
// LocalStorage (internal/storage/store) is the sole implementation today.
// A second implementation, RemoteStorage, proxied every call over HTTP to an
// upstream server; it has since been deleted (ADR-083/ADR-108: remote storage
// is a CLI/client-mode concept, not a server storage backend). Several method
// pairs below (e.g. TryAcquireSchedulerLock/ReleaseSchedulerLock instead of a
// single WithSchedulerLock-only API) still carry doc comments explaining the
// cross-process-atomicity constraints RemoteStorage's HTTP-proxy nature used
// to impose — kept as design history for why the interface has the shape it
// does, not because a second implementation still exists.
type Storage interface {
	// Login rate limiting (ADR-040) — cluster-wide brute-force protection. Replaces
	// the per-process in-memory limiter so the limit holds across HA replicas.
	RecordLoginAttempt(ctx context.Context, ip string, at time.Time) error
	CountRecentLoginAttempts(ctx context.Context, ip string, since time.Time) (int64, error)
	PruneLoginAttempts(ctx context.Context, before time.Time) (int64, error)

	// ReserveLoginAttempt is RecordLoginAttempt's releasable counterpart: it writes
	// the same row but returns its id, so a caller that reserves BEFORE a slow
	// check runs (closing the concurrent-burst race RecordLoginAttempt's own
	// callers rely on — see core.ReserveLoginAttempt) can undo the write via
	// ReleaseLoginAttempt if that check turns out not to be a confirmed negative
	// result. Every auth budget write goes through it, releasable or not (core
	// budgetWriteKeyed, #2837): the per-key idempotence is what makes a failed
	// write safe to retry. RecordLoginAttempt is left to the relay
	// (core.RecordLoginAttemptRelay), which returns the error to its caller.
	//
	// key is a caller-generated reservation identifier, unique per reservation
	// (#2956 follow-up). The write is idempotent per key: reserving the same key
	// again writes nothing and returns the existing row's id. That is what lets a
	// caller whose write landed but reported an error retry with the same key and
	// get the reservation back instead of losing it or counting it twice.
	ReserveLoginAttempt(ctx context.Context, ip string, at time.Time, key string) (id uint, err error)
	// ReleaseLoginAttempt deletes the LoginAttempt row `id`, undoing a prior
	// ReserveLoginAttempt. A no-op, not an error, if the row is already gone
	// (e.g. a maintenance prune raced it).
	ReleaseLoginAttempt(ctx context.Context, id uint) error

	// WithSchedulerLock runs fn only if this process can take the named scheduler
	// lock, so a background job runs on a single replica at a time (HA, ADR-039).
	// On PostgreSQL it uses a session advisory lock (pg_try_advisory_lock); on
	// SQLite (single instance) fn always runs. Returns ran=false (and nil error)
	// when another replica holds the lock — the caller should simply skip this tick.
	WithSchedulerLock(ctx context.Context, key int64, fn func() error) (ran bool, err error)

	// TryAcquireSchedulerLock and ReleaseSchedulerLock (#530) are the two
	// building blocks WithSchedulerLock is composed from. They exist as their
	// own Storage methods (rather than being private to one implementation)
	// because RemoteStorage's now-deleted WithSchedulerLock had to acquire, run
	// fn locally against itself (which could in turn make its own further
	// proxied calls), and release as two separate HTTP round trips — a real
	// cross-process transaction could not span the acquire and release the way
	// LocalStorage's single in-process call does, so each half had to be
	// independently atomic and safely idempotent. LocalStorage still keeps the
	// same two-method split even with RemoteStorage gone.
	//
	// TryAcquireSchedulerLock atomically attempts to take (or renew, if holder
	// already owns it) the named lock for ttl, in ONE round trip: acquired=true
	// only when this holder now owns it (a fresh acquire, a reclaim of an
	// expired lease, or a renewal of its own still-held lease); acquired=false
	// when a DIFFERENT holder's lease has not yet expired. Calling it again with
	// the SAME holder before ExpiresAt is therefore a safe heartbeat/renewal,
	// not a new acquisition attempt.
	TryAcquireSchedulerLock(ctx context.Context, key int64, holder string, ttl time.Duration) (acquired bool, err error)

	// ReleaseSchedulerLock releases the named lock IFF it is still held by
	// holder — a conditional delete, never a bare unconditional one, so a
	// holder whose lease already expired (and was possibly reclaimed by a
	// different holder in the meantime) can never clobber that newer holder's
	// lease. A release for a lock this holder does not (or no longer) own is a
	// silent no-op, not an error — mirroring ConsumeSSOLoginState's
	// already-consumed-is-not-an-error stance for the same reason: the caller's
	// own crashed-holder safety net is ExpiresAt, not a hard release
	// requirement.
	ReleaseSchedulerLock(ctx context.Context, key int64, holder string) error

	// WithAuditCheckpointLock serializes the audit-checkpoint chain-walk + decide +
	// create-checkpoint sequence (ADR-029) across every trigger — the scheduler tick,
	// the HTTP POST /api/v1/audit/checkpoint endpoint, and the gRPC
	// WriteAuditCheckpoint RPC — even when they land on different replicas (ADR-039
	// HA). Unlike WithSchedulerLock, this BLOCKS until the lock is free rather than
	// skipping on contention: every caller must actually run its checkpoint decision
	// against a consistent, serialized view, not silently no-op (#300). On PostgreSQL
	// it holds a session advisory lock (pg_advisory_lock) for the duration of fn; on
	// SQLite (single instance, no cross-process concern) a process mutex is enough.
	WithAuditCheckpointLock(ctx context.Context, fn func() error) error

	// WithBootstrapLock serializes BootstrapSystem's whole "is this a fresh
	// install" check through admin/RBAC/project seeding (auth_bootstrap.go) across
	// every replica of an HA deployment (ADR-039), mirroring WithAuditCheckpointLock's
	// mutex+advisory-lock design: an in-process mutex alone only serializes callers
	// within ONE server, so two different replicas racing POST /system/init could
	// both observe "not yet initialised" before either's commit is visible to the
	// other and each independently seed a "first admin" (double-seed / partial-RBAC
	// corruption). This BLOCKS until the lock is free, same as
	// WithAuditCheckpointLock: a losing replica must actually re-check under the
	// lock and observe the winner's now-committed state, not silently skip. On
	// PostgreSQL it holds a session advisory lock (pg_advisory_lock) for the
	// duration of fn; on SQLite (single instance, no cross-process concern) a
	// process mutex is enough.
	WithBootstrapLock(ctx context.Context, fn func() error) error

	// WithNamedLock serializes fn against every OTHER caller using the identical
	// lockKey, across replicas of an HA deployment (ADR-039) -- the general-purpose
	// form of WithAuditCheckpointLock/WithBootstrapLock's dedicated-mutex pattern,
	// for check-then-act invariants that don't warrant their own bespoke method
	// (#1646: the separation-of-duties preventive gate, the last-project-admin
	// guard, and the last-global-admin guard were each previously serialized by
	// an in-process KeyorixCore-level sync.Mutex ONLY -- meaning two independent
	// replicas of a real multi-instance Postgres deployment were never
	// serialized against each other at all, reproduced live for the SoD case).
	// On PostgreSQL it holds a session advisory lock (pg_advisory_lock) keyed by
	// a hash of lockKey for the duration of fn; on SQLite (single instance, no
	// cross-process concern) a single shared process mutex is enough. This
	// BLOCKS until the lock is free, same as WithAuditCheckpointLock/
	// WithBootstrapLock: a losing caller must actually re-check under the lock
	// and observe the winner's now-committed state, not silently skip.
	//
	// fn receives the lock-marked context. A caller that itself calls
	// WithNamedLock again (directly or transitively) MUST pass this ctx through,
	// not whatever ctx it closed over -- otherwise the reentrancy marker is lost
	// and a nested call self-deadlocks (see store.namedLockHeldCtxKey).
	WithNamedLock(ctx context.Context, lockKey string, fn func(ctx context.Context) error) error

	// WithTransaction runs fn inside a single storage transaction: every mutation fn
	// performs through the provided Storage commits together, or rolls back together if
	// fn returns an error. LocalStorage opens a real DB transaction and hands fn a
	// transaction-scoped Storage. (The now-deleted RemoteStorage instead ran fn directly
	// against itself as a no-op passthrough, since each proxied HTTP call was already
	// atomic server-side and there was no client-side transaction to open — several
	// comments elsewhere in this file still explain invariants shaped by that
	// constraint.) Use it for multi-step mutations that must not half-apply (e.g. a
	// suspend + delete pair).
	WithTransaction(ctx context.Context, fn func(Storage) error) error

	// LockLiveProject re-reads project projectID and reports whether it is still
	// live (not soft-deleted). On Postgres it takes SELECT ... FOR SHARE on that
	// row, so it serializes against DeleteProject's cascade, which row-locks the
	// project FOR UPDATE before it sweeps any child (#2656).
	//
	// It is ONLY meaningful on a transaction-scoped Storage — the handle
	// WithTransaction hands fn — and only when called AFTER the child write it
	// guards, rolling the transaction back when it returns false. That ordering is
	// the whole mechanism, and it is not interchangeable with checking first: a
	// cascade that runs entirely between a pre-write check and the write never
	// sees the child, and the child commits under a deleted project. Called on a
	// non-transactional Storage it still answers the question correctly, but
	// guarantees nothing, because the row lock is released the instant that
	// single autocommit statement completes.
	//
	// #2702/#2710/#2711/#2712: core.CreateSecret, core.CreateFolder,
	// core.CreateEnvironment and LocalStorage.RestoreSecret each checked the
	// ENVIRONMENT's liveness (via the EnvironmentSecretGuardLockKey named lock)
	// but never the project's, and deleteProjectCascade takes no such named lock —
	// so a child committed under a project deleted in the window. The store-internal
	// lockLiveParent helper this exposes already backed RestoreEnvironment's
	// identical fix (#2656); the method exists so a core-layer caller already
	// inside WithTransaction can use it without the full-row write
	// internal/storage/store would otherwise have to grow a bespoke method for.
	LockLiveProject(ctx context.Context, projectID uint) (bool, error)

	// Project / Environment management
	CreateProject(ctx context.Context, project *models.Project) (*models.Project, error)
	GetProject(ctx context.Context, id uint) (*models.Project, error)
	// UpdateProjectFields persists ONLY name, description and updated_at — plus
	// require_mfa when (and only when) requireMFA is non-nil — onto a LIVE
	// project row: "UPDATE projects SET ... WHERE id = ? AND deleted_at IS
	// NULL". matched=false (no error) means the project is gone; the caller must
	// not report success.
	//
	// This REPLACES the former UpdateProject, a bare GORM Save of a struct the
	// caller read earlier (#2697). Two consequences, both closed by the shape
	// above rather than by the caller being careful:
	//   - Save's 0-rows fallback is an upsert that writes deleted_at = NULL, so
	//     a rename landing after DeleteProject resurrected the project row
	//     alone (its secrets and environments stayed deleted), after which
	//     requireLiveProject and the RestoreSecret/RestoreEnvironment liveness
	//     checks passed again for project-scoped grant holders;
	//   - Save wrote every column, so a plain rename whose read predated an
	//     admin enabling ADR-037's per-project require_mfa wrote `false` back
	//     over it — no roles.assign needed, and no audit event, because
	//     core.UpdateProject only audits when ITS OWN argument changes the
	//     value it read. requireMFA is a pointer here so "I am not changing
	//     this flag" is expressible, and a nil one never reaches the UPDATE.
	UpdateProjectFields(ctx context.Context, id uint, name, description string, requireMFA *bool, updatedAt time.Time) (matched bool, err error)
	DeleteProject(ctx context.Context, id uint) error
	// DeleteProjectIfEmpty atomically enforces DeleteProject(force=false)'s guard —
	// reject the delete if the project still has any live secret — and, only when the
	// project IS empty, performs the SAME cascade soft-delete DeleteProject does, all as
	// ONE storage operation (#528). It replaces core.DeleteProject's prior
	// WithTransaction-wrapped ListSecrets+DeleteProject pair (#313): that pair depended
	// on WithTransaction opening a REAL transaction to keep the guard's read and the
	// cascade's write atomic, which held for LocalStorage but NOT for the now-deleted
	// RemoteStorage — its WithTransaction was a no-op passthrough over HTTP (see its doc
	// comment above), so a naive two-call proxy of that same pair would have reopened a
	// TOCTOU window across a full network round trip: a secret created between the count
	// and the cascade would silently let a force=false delete cascade over it anyway, the
	// same check-then-act-split-by-a-non-transactional-WithTransaction bug class this
	// campaign has already hit repeatedly. Folding the guard and the cascade into one call
	// closed that gap; under LocalStorage it is (and always was) one DB transaction.
	// Returns the count of live secrets blocking the delete (0 means the
	// delete happened) so the caller can format the same "project has N secret(s)..."
	// error DeleteProject(force=false) has always returned.
	DeleteProjectIfEmpty(ctx context.Context, id uint) (blockingSecretCount int, err error)
	// RestoreProject reverses a project soft-delete and cascades to the environments/
	// secrets that were removed WITH it (matched by deletion timestamp — independently
	// retired children stay deleted, see LocalStorage.RestoreProject). It returns the
	// count of environments and secrets the cascade actually restored, so the caller
	// can audit what came back (#311), not just that "the project" was restored.
	RestoreProject(ctx context.Context, id uint) (restoredEnvironments, restoredSecrets int, err error)
	ListProjects(ctx context.Context) ([]*models.Project, error)
	ListProjectsWithCounts(ctx context.Context, includeDeleted bool) ([]ProjectWithCounts, error)
	CreateEnvironment(ctx context.Context, env *models.Environment) (*models.Environment, error)
	GetEnvironment(ctx context.Context, id uint) (*models.Environment, error)
	DeleteEnvironment(ctx context.Context, id uint) error
	// RestoreEnvironment restores a soft-deleted environment, scoped to projectID
	// so a caller authorized for one project cannot restore another's environment.
	RestoreEnvironment(ctx context.Context, projectID, id uint) error
	ListEnvironments(ctx context.Context) ([]*models.Environment, error)
	ListEnvironmentsByProject(ctx context.Context, projectID uint) ([]*models.Environment, error)
	ListEnvironmentsByProjectIncludingDeleted(ctx context.Context, projectID uint) ([]*models.Environment, error)
	ListProjectMembers(ctx context.Context, projectID uint) ([]ProjectMember, error)
	// ListProjectRoleAssignments returns every direct (user) and group role grant
	// scoped to the project (project_id = projectID, any environment) — the raw
	// rows for a project access review. Global (project 0) grants are excluded:
	// those are install-level, reviewed separately.
	ListProjectRoleAssignments(ctx context.Context, projectID uint) ([]RoleAssignment, error)
	// ListProjectMachineRoleAssignments returns every machine-identity role grant
	// scoped to the project (project_id = projectID, any environment) — the machine
	// counterpart to ListProjectRoleAssignments's user/group rows, kept separate so
	// existing callers (compliance posture, RBAC/SCIM last-admin guards) are
	// unaffected; only the access review enumerates it (#91).
	ListProjectMachineRoleAssignments(ctx context.Context, projectID uint) ([]RoleAssignment, error)
	// ListGlobalAdminAssignmentsForUpdate returns every global-scope (project 0,
	// environment 0) direct user and group role grant whose role is in
	// adminRoleIDs, taking a row-level write lock on backends that support one
	// (Postgres: SELECT ... FOR UPDATE) so a concurrent racing removal serializes
	// against this read. This is the atomicity fix for #340: guardLastGlobalAdmin's
	// prior read-then-conditional-write let two admins racing to remove each
	// other's role assignment both observe "another admin still exists" before
	// either write landed, stranding the install. On SQLite this is a plain read;
	// the caller's own process-level mutex serializes same-process callers,
	// mirroring LockUserForUpdate/LockWebAuthnCredentialForUpdate.
	ListGlobalAdminAssignmentsForUpdate(ctx context.Context, adminRoleIDs []uint) ([]RoleAssignment, error)
	// RemoveGlobalAdminRoleGuarded atomically checks-then-removes a user's
	// global-scope (project 0, environment 0) role grant, refusing (without
	// removing anything) if doing so would leave the install with zero
	// admin-tier holders among adminRoleIDs — the exact guardLastGlobalAdmin
	// (#340) check and its RemoveRole write, folded into ONE storage call.
	//
	// Added for #525: RemoveUserRole previously ran this check (via
	// ListGlobalAdminAssignmentsForUpdate) and the removal (via RemoveRole) as TWO
	// separate calls inside a WithTransaction closure. That is correct against
	// LocalStorage (a real DB transaction + Postgres row lock spans both), but the
	// now-deleted RemoteStorage's WithTransaction was a no-op passthrough — two
	// separate HTTP round trips would have given a concurrent racing removal a
	// window to observe "another admin still exists" before either write landed,
	// reopening the exact cross-process last-admin lockout race #340 closed for HA
	// Postgres replicas. Folding the check and the write into one call means
	// whichever server actually owns the row is the only one that ever needs to
	// enforce it atomically, exactly like CreateSecretDependencyExclusive (#260) and
	// TransitionMachineIdentityState (#388/#518) did for their own TOCTOU classes.
	//
	// Returns ErrWouldStrandLastAdmin if the removal is refused, or
	// ErrRoleNotAssigned (wrapped) if the (userID, roleID) grant does not exist at
	// the global scope.
	RemoveGlobalAdminRoleGuarded(ctx context.Context, userID, roleID uint, adminRoleIDs []uint) error
	// LastUserSecretActivity returns, per user, the most recent secret-access time
	// in the project (from the audit trail). Backs dormant-access detection in the
	// access review — a grant whose principal has no recent activity is stale
	// standing access to prune. Users with no recorded activity are absent from the
	// map.
	LastUserSecretActivity(ctx context.Context, projectID uint) (map[uint]time.Time, error)
	// LastUserRoleManagementActivity returns, per user, the most recent time they
	// granted/revoked a role or group-role attributable to this project (the
	// roles.assign-tier half of admin-tier dormant-role-grant detection: #258,
	// narrowed per-permission by #487). A plain secrets.read/write role is
	// considered "used" by any entry in LastUserSecretActivity, but a role that
	// additionally confers role-management (e.g. project_admin's roles.assign)
	// should only be considered "used" via THIS capability if the principal
	// actually exercised it — routine secret reads (or even a SEPARATE admin-tier
	// grant's secrets.delete activity) under a different grant must not mask this
	// one as active. Users with no recorded role-management activity are absent
	// from the map.
	LastUserRoleManagementActivity(ctx context.Context, projectID uint) (map[uint]time.Time, error)
	// LastUserSecretDeletionActivity returns, per user, the most recent time they
	// deleted a secret attributable to this project (the secrets.delete/admin-tier
	// half of admin-tier dormant-role-grant detection: #258, narrowed
	// per-permission by #487) — see LastUserRoleManagementActivity's doc for why
	// this is kept separate rather than folded into one combined "elevated
	// activity" signal. Users with no recorded deletion activity are absent from
	// the map.
	LastUserSecretDeletionActivity(ctx context.Context, projectID uint) (map[uint]time.Time, error)
	// LastUserSecretReadActivity returns, per user, the most recent secret.read
	// time attributable to this project — the secrets.read half of plain-tier
	// dormant-role-grant detection (#487 round 112). Mirrors
	// LastUserRoleManagementActivity/LastUserSecretDeletionActivity's per-
	// permission split, one level down from admin-tier: before this, a plain-tier
	// grant was credited "used" by ANY secret activity (read OR write) in
	// LastUserSecretActivity regardless of which specific permission (secrets.read
	// vs secrets.write) the grant's OWN bundle actually confers, so a user holding
	// a read-only grant AND a separate write-only grant in the same project had
	// BOTH masked non-dormant by either one's activity. Users with no recorded
	// read activity are absent from the map.
	LastUserSecretReadActivity(ctx context.Context, projectID uint) (map[uint]time.Time, error)
	// LastUserSecretWriteActivity returns, per user, the most recent
	// secret.created/updated/rotated time attributable to this project — the
	// secrets.write half of plain-tier dormant-role-grant detection (#487 round
	// 112). See LastUserSecretReadActivity's doc for why this is kept separate
	// rather than folded into one combined signal. Users with no recorded write
	// activity are absent from the map.
	LastUserSecretWriteActivity(ctx context.Context, projectID uint) (map[uint]time.Time, error)

	// Project invitations (ADR-024).
	CreateProjectInvitation(ctx context.Context, inv *models.ProjectInvitation) (*models.ProjectInvitation, error)
	GetProjectInvitation(ctx context.Context, id uint) (*models.ProjectInvitation, error)
	// UpdateProjectInvitation persists an invitation state transition with a
	// conditional UPDATE (only an invitation whose CURRENT stored state is still
	// "pending" may be transitioned). The bool reports whether the row matched and
	// was updated; false means the invitation was already resolved (accepted,
	// revoked, or expired) by a prior or racing call and this write was rejected,
	// not silently applied (#412).
	UpdateProjectInvitation(ctx context.Context, inv *models.ProjectInvitation) (bool, error)
	ListProjectInvitations(ctx context.Context, projectID uint) ([]*models.ProjectInvitation, error)

	// Access requests (ADR-024).
	CreateAccessRequest(ctx context.Context, req *models.AccessRequest) (*models.AccessRequest, error)
	GetAccessRequest(ctx context.Context, id uint) (*models.AccessRequest, error)
	// UpdateAccessRequest persists an access-request state transition with a
	// conditional UPDATE (only a request whose CURRENT stored state is still
	// "pending" may be transitioned). The bool reports whether the row matched and
	// was updated; false means the request was already resolved (approved,
	// rejected, withdrawn, or expired) by a prior or racing call and this write was
	// rejected, not silently applied (#277).
	UpdateAccessRequest(ctx context.Context, req *models.AccessRequest) (bool, error)
	ListAccessRequests(ctx context.Context, projectID uint) ([]*models.AccessRequest, error)
	// Access-request approvals (N-of-M dual control). One row per approver sign-off.
	CreateAccessRequestApproval(ctx context.Context, a *models.AccessRequestApproval) error
	ListAccessRequestApprovals(ctx context.Context, requestID uint) ([]*models.AccessRequestApproval, error)

	// Access-review campaigns (ISO 27001 A.5.18) — periodic recertification cycles
	// and the per-grant items captured within them.
	CreateAccessReviewCampaign(ctx context.Context, c *models.AccessReviewCampaign) (*models.AccessReviewCampaign, error)
	GetAccessReviewCampaign(ctx context.Context, id uint) (*models.AccessReviewCampaign, error)
	ListAccessReviewCampaigns(ctx context.Context, projectID uint) ([]*models.AccessReviewCampaign, error)
	// GetOpenAccessReviewCampaign returns the project's currently open campaign, or
	// nil if none is open — a targeted single-row lookup for callers (e.g. the
	// recertification scheduler tick, #238) that only need to know whether a review
	// is already in flight, not the project's full historical campaign list.
	GetOpenAccessReviewCampaign(ctx context.Context, projectID uint) (*models.AccessReviewCampaign, error)
	// GetLatestClosedAccessReviewCampaign returns the project's most recently closed
	// campaign (by CreatedAt), or nil if it has never had one. A targeted
	// ORDER BY ... LIMIT 1 lookup for callers that only need the anchor point for the
	// next recertification due-date, not the entire historical corpus (#238).
	GetLatestClosedAccessReviewCampaign(ctx context.Context, projectID uint) (*models.AccessReviewCampaign, error)
	// UpdateAccessReviewCampaign persists a campaign state transition with a
	// conditional UPDATE (only a campaign whose CURRENT stored state is still "open"
	// may be transitioned). The bool reports whether the row matched and was updated;
	// false means the campaign was already closed (by a prior or racing call) and
	// this write was rejected, not silently applied.
	UpdateAccessReviewCampaign(ctx context.Context, c *models.AccessReviewCampaign) (bool, error)
	CreateAccessReviewItems(ctx context.Context, items []*models.AccessReviewItem) error
	ListAccessReviewItems(ctx context.Context, campaignID uint) ([]*models.AccessReviewItem, error)
	// CountPendingAccessReviewItems returns the number of items in a campaign still
	// awaiting a decision (decision = "pending"), without loading the item rows
	// themselves — used by the recertification scheduler tick (#238) to size an
	// in-flight campaign's remaining work for a reminder.
	CountPendingAccessReviewItems(ctx context.Context, campaignID uint) (int, error)
	GetAccessReviewItem(ctx context.Context, id uint) (*models.AccessReviewItem, error)
	// UpdateAccessReviewItem persists a decision with a conditional UPDATE (only an
	// item whose CURRENT stored decision is still "pending", in a campaign whose
	// CURRENT stored state is still "open", may be transitioned). The bool reports
	// whether the row matched and was updated; false means either the item was
	// already decided or the parent campaign was closed (by a prior or racing call)
	// and this write was rejected, not silently applied.
	UpdateAccessReviewItem(ctx context.Context, item *models.AccessReviewItem) (bool, error)
	// RevertAccessReviewItemClaim compensates a claim whose real action then failed
	// to apply (revoke's post-claim failure window — see claimItemDecision's doc
	// comment for why revoke must claim before acting). Conditional UPDATE, same
	// atomic-compare-and-swap shape as UpdateAccessReviewItem's own claim, run in
	// reverse (WHERE id = ? AND decision = fromDecision AND decided_by = actorID).
	// The bool reports whether the row matched and was reverted; false means
	// someone else already changed it since this caller's own claim, and the
	// caller must fail closed (leave it alone), not overwrite that other change.
	RevertAccessReviewItemClaim(ctx context.Context, itemID uint, fromDecision string, actorID uint) (bool, error)

	// Separation-of-duties policies (ISO 27001 A.5.3 / SOX) — toxic permission pairs.
	CreateSoDPolicy(ctx context.Context, p *models.SoDPolicy) (*models.SoDPolicy, error)
	GetSoDPolicy(ctx context.Context, id uint) (*models.SoDPolicy, error)
	ListSoDPolicies(ctx context.Context) ([]*models.SoDPolicy, error)
	DeleteSoDPolicy(ctx context.Context, id uint) error

	// Secret dependency edges (ADR-052) — the per-project secret dependency graph.
	CreateSecretDependency(ctx context.Context, d *models.SecretDependency) (*models.SecretDependency, error)
	GetSecretDependency(ctx context.Context, id uint) (*models.SecretDependency, error)
	ListSecretDependenciesForProject(ctx context.Context, projectID uint) ([]*models.SecretDependency, error)
	DeleteSecretDependency(ctx context.Context, id uint) error
	// ListSecretDependenciesForProjectForUpdate is ListSecretDependenciesForProject,
	// taking a row-level write lock on every returned edge on backends that support
	// one (Postgres FOR UPDATE), mirroring LockUserForUpdate/
	// ListGlobalAdminAssignmentsForUpdate (#260). Retained as a raw storage
	// primitive but no longer used by AddSecretDependency
	// (internal/core/secret_dependencies.go) — see CreateSecretDependencyExclusive
	// below for why the cycle-check read and the edge write had to be collapsed
	// into ONE storage-layer call rather than orchestrated by the caller across
	// this method and CreateSecretDependency.
	ListSecretDependenciesForProjectForUpdate(ctx context.Context, projectID uint) ([]*models.SecretDependency, error)
	// CreateSecretDependencyExclusive atomically validates and persists one secret
	// dependency edge under a project-scoped exclusive lock (Postgres FOR UPDATE),
	// rejecting it with storage.ErrDuplicateSecretDependency or
	// storage.ErrSecretDependencyCycle if the CURRENT edge set (read under that
	// same lock) already contains the pair, or adding it would close a cycle.
	//
	// This is what AddSecretDependency now calls instead of orchestrating
	// ListSecretDependenciesForProjectForUpdate + CreateSecretDependency itself
	// inside a WithTransaction (#260's original design): the now-deleted
	// RemoteStorage's WithTransaction was a no-op passthrough — no real transaction
	// spanned the wire — so a caller-driven "list under lock, decide, then create"
	// sequence against a RemoteStorage backend was really two independent HTTP
	// round trips with no lock held between them, silently losing #260's whole
	// guarantee for any downstream server booted with storage.type: remote
	// (ADR-049) — including the exact case that guarantee exists for: multiple
	// such downstream replicas racing to add a reciprocal edge pair against the
	// SAME upstream project concurrently. Collapsing the check-and-write into one
	// storage-interface call fixed that: LocalStorage's implementation runs the
	// identical duplicate/cycle logic AddSecretDependency used to run itself, just
	// moved down a layer and wrapped in one real DB transaction — the same
	// wire-code-translation technique that preserves CreateProjectMembership's
	// DB-level unique-index atomicity across a remote boundary (#511), just for an
	// invariant (acyclicity) no unique index can express.
	CreateSecretDependencyExclusive(ctx context.Context, d *models.SecretDependency) (*models.SecretDependency, error)

	// Secret ACL (RBAC Phase 3) — per-secret fine-grained access grants.
	// A SecretACL row grants (UserID, SecretID, Permissions) independent of project RBAC.
	// Folder-level grants are inherited by descendant secrets via the ancestor walk in
	// HasSecretACL (uses GetSecretAncestors to climb the ParentID chain).
	CreateOrUpdateSecretACL(ctx context.Context, acl *models.SecretACL) error
	ListSecretACLs(ctx context.Context, secretID uint) ([]*models.SecretACL, error)
	// ListSecretACLsByUser returns all ACL rows where user_id = userID, across all secrets.
	// Used by ListSecretsWithSharingInfo to surface secrets the user can access via explicit
	// per-secret/per-folder grants but does not own and has no ShareRecord for.
	ListSecretACLsByUser(ctx context.Context, userID uint) ([]*models.SecretACL, error)
	GetSecretACL(ctx context.Context, secretID, userID uint) (*models.SecretACL, error)
	DeleteSecretACL(ctx context.Context, id uint) error
	// DeleteSecretACLsByUserAndProject removes all ACL grants for userID on secrets
	// that belong to projectID. Called during project member removal so that a
	// revoked member's per-secret ACL grants do not survive offboarding (CWE-284).
	DeleteSecretACLsByUserAndProject(ctx context.Context, userID, projectID uint) error
	// GetSecretAncestors returns the ancestor SecretNode IDs for nodeID,
	// ordered from immediate parent to root (breadth-first up the ParentID
	// chain). Used by HasSecretACL to walk the folder ACL inheritance path.
	// Capped at 20 levels to guard against accidental circular ParentID
	// references in the data. LocalStorage climbs the chain via repeated
	// GetSecret calls.
	GetSecretAncestors(ctx context.Context, nodeID uint) ([]uint, error)

	// Temporal access schedule — restricts a secret's reads to a configured
	// time window (day-of-week + hour range). GetSecretAccessSchedule returns
	// nil, nil when no schedule has been configured for the secret.
	GetSecretAccessSchedule(ctx context.Context, secretNodeID uint) (*models.SecretAccessSchedule, error)
	SetSecretAccessSchedule(ctx context.Context, schedule *models.SecretAccessSchedule) error
	DeleteSecretAccessSchedule(ctx context.Context, secretNodeID uint) error
	// GetSecretScheduleAndLatestVersion is GetSecretAccessSchedule plus
	// GetLatestSecretVersion for one secret, for a latest-version value read
	// (PERF-FIX-4, collapse C5): the schedule row and the latest-version cache
	// generation come from ONE statement (one snapshot), and the version row is
	// read only when the version cache misses. The returned error is the shared
	// statement's failure only; a latest-version failure is carried in
	// LatestVersionErr, exactly as GetLatestSecretVersion would have returned it,
	// so the caller still judges the schedule first.
	GetSecretScheduleAndLatestVersion(ctx context.Context, secretNodeID uint) (*SecretScheduleAndLatestVersion, error)

	// Legal hold (ISO 27001 A.5.34 / eDiscovery) — a deployment-wide hold that
	// blocks the purge jobs from hard-deleting records while active.
	CreateLegalHold(ctx context.Context, h *models.LegalHold) (*models.LegalHold, error)
	GetActiveLegalHold(ctx context.Context) (*models.LegalHold, error)
	UpdateLegalHold(ctx context.Context, h *models.LegalHold) error

	// Risk exceptions (ISO 27001 A.5.8 risk treatment) — governed, time-bound
	// acceptances of a known control gap. CreateRiskException records one;
	// ListRiskExceptions returns all (activeOnly excludes revoked rows; expiry is
	// computed in core); GetRiskException/RevokeRiskExceptionIfNotRevoked support
	// revoke.
	CreateRiskException(ctx context.Context, e *models.RiskException) (*models.RiskException, error)
	ListRiskExceptions(ctx context.Context, activeOnly bool) ([]*models.RiskException, error)
	GetRiskException(ctx context.Context, id uint) (*models.RiskException, error)
	// RevokeRiskExceptionIfNotRevoked persists e's full row (Revoked/RevokedBy/
	// RevokedAt already set by the caller) via a single conditional UPDATE —
	// "WHERE id = ? AND revoked = false" — succeeding only if the row's CURRENT
	// persisted revoked flag is still false, mirroring TransitionMachineIdentityState's
	// `WHERE id = ? AND state = ?` pattern (#388) and UpdateProjectInvitation's
	// `WHERE id = ? AND state = 'pending'` pattern (#412) for this same TOCTOU class.
	// The bool reports whether the row matched and was updated; false means the
	// exception was already revoked by a prior or racing call (e.g. a concurrent
	// RevokeRiskException or ApproveRiskException) and this write was rejected, not
	// silently applied. core.RevokeRiskException's own precondition check
	// (e.Revoked) only protects against the case where the initial read already
	// showed revoked=true — it does nothing for a revoke that happens in the
	// window between that read and this write, which is exactly the gap this
	// conditional UPDATE closes.
	//
	// This exists — rather than a plain full-row overwrite — for the same reason
	// TransitionMachineIdentityState does: the now-deleted RemoteStorage's
	// WithTransaction was a no-op passthrough, so a caller-driven
	// read-then-conditional-write sequence run against it got none of the
	// atomicity a real DB transaction + row lock gives LocalStorage. Routing the
	// write through this one conditional round trip — a single LocalStorage
	// conditional SQL UPDATE — restores the guarantee.
	RevokeRiskExceptionIfNotRevoked(ctx context.Context, e *models.RiskException) (bool, error)
	// ApproveRiskExceptionIfPending persists e's full row (Approved/ApprovedBy/
	// ApprovedAt already set by the caller) via a single conditional UPDATE —
	// "WHERE id = ? AND revoked = false AND approved = false" — succeeding only if
	// the row is CURRENTLY still un-revoked AND un-approved. See
	// RevokeRiskExceptionIfNotRevoked's doc for why this exists as a dedicated
	// conditional round trip rather than a plain full-row overwrite. The
	// bool reports whether the row matched and was updated; false means the
	// exception was concurrently revoked, or already approved, by a prior or
	// racing call and this write was rejected, not silently applied.
	ApproveRiskExceptionIfPending(ctx context.Context, e *models.RiskException) (bool, error)

	// SSO login state (OIDC human SSO) — short-lived CSRF/nonce state.
	// ConsumeSSOLoginState is single-use: it returns the row and deletes it.
	CreateSSOLoginState(ctx context.Context, s *models.SSOLoginState) error
	ConsumeSSOLoginState(ctx context.Context, state string) (*models.SSOLoginState, error)

	// Break-glass emergency-access activations (NIS2/DORA incident response).
	// GetBreakGlassActivation/ListBreakGlassActivations project State to
	// 'expired' for a TTL-lapsed 'active' row (watermark-clamped) as a pure
	// read-time computation -- never persisted from either (#1653 reopened: a
	// list/get read path persisting an access-control-adjacent state transition
	// was the actual defect, not merely a premise nobody had asserted).
	CreateBreakGlassActivation(ctx context.Context, a *models.BreakGlassActivation) (*models.BreakGlassActivation, error)
	GetBreakGlassActivation(ctx context.Context, id uint) (*models.BreakGlassActivation, error)
	ListBreakGlassActivations(ctx context.Context, projectID uint) ([]*models.BreakGlassActivation, error)
	UpdateBreakGlassActivation(ctx context.Context, a *models.BreakGlassActivation) error
	// ReconcileExpiredBreakGlassActivation transitions userID's own TTL-lapsed
	// 'active' row in projectID to 'expired' (watermark-clamped), if one
	// exists. The one place a TTL-lapse transition is ever persisted -- called
	// only from ActivateBreakGlass, a mutating operation, immediately before it
	// attempts to create a new activation, so a genuinely-expired-but-never-
	// revisited prior row doesn't hold the one-active-slot-per-(project,user)
	// partial unique index forever.
	ReconcileExpiredBreakGlassActivation(ctx context.Context, projectID, userID uint) error
	// RevokeBreakGlassActivation atomically transitions activation id from
	// active-OR-expired to revoked, recording who revoked it and when, via a
	// single conditional UPDATE rather than a read-modify-write — so two
	// concurrent revokes of the same activation cannot both "win": only the
	// first transitions state, and the second gets ErrBreakGlassNotActive
	// rather than silently overwriting the first revoker's attribution.
	// Accepts 'expired' as well as 'active' so a caller is never refused a
	// revoke because of what a clock-derived State happens to read; only an
	// already-'revoked' row is excluded.
	RevokeBreakGlassActivation(ctx context.Context, id, revokedBy, revokedByMachineID uint, revokedAt time.Time) error
	// ReviewBreakGlassActivation (ADR-112 §3, break-glass review item 5)
	// atomically records a post-activation review -- reviewer, when, and an
	// optional note -- via a single conditional UPDATE guarded on
	// reviewed_at IS NULL, the same shape as RevokeBreakGlassActivation's
	// guard, so two concurrent review submissions for the same activation
	// cannot both "win": only the first is recorded, the second gets
	// ErrBreakGlassAlreadyReviewed. This storage-layer primitive itself does
	// not condition on active/expired/revoked state -- it records a review
	// against whatever row id names. #2461 round 2: that is NOT the same as
	// "a review is allowed at any state" -- core.ReviewBreakGlass, the only
	// production caller, refuses a still-active activation BEFORE reaching
	// here (ErrBreakGlassStillActive), so in practice this is only ever
	// called once the activation has concluded.
	ReviewBreakGlassActivation(ctx context.Context, id, reviewerID uint, note string, reviewedAt time.Time) error
	// ListUnreviewedBreakGlassActivationsBefore returns every activation
	// (across all projects) with reviewed_at still NULL and created_at at or
	// before cutoff -- the posture report's (item 4) source for "open
	// break-glass activations without review."
	ListUnreviewedBreakGlassActivationsBefore(ctx context.Context, cutoff time.Time) ([]*models.BreakGlassActivation, error)
	// Machine identities (ADR-023) — non-human project members.
	CreateMachineIdentity(ctx context.Context, m *models.MachineIdentity) (*models.MachineIdentity, error)
	GetMachineIdentity(ctx context.Context, id uint) (*models.MachineIdentity, error)
	// LockMachineIdentityForUpdate re-reads a machine identity by ID, taking a
	// row-level write lock on backends that support one (Postgres: SELECT … FOR
	// UPDATE) so a read-modify-write on the row serializes against a concurrent
	// writer of the same row — mirroring LockUserForUpdate. Use this — not
	// GetMachineIdentity — inside a WithTransaction whenever a caller conditionally
	// mutates state (e.g. TransitionMachineIdentity's revoked-is-terminal invariant,
	// #388) that must not lose an update under concurrency.
	LockMachineIdentityForUpdate(ctx context.Context, id uint) (*models.MachineIdentity, error)
	// TransitionMachineIdentityState persists m's full row via a single
	// conditional write — "UPDATE ... WHERE id = ? AND state = ?" — succeeding
	// only if the row's CURRENT persisted state still equals fromState (the
	// value TransitionMachineIdentity observed via LockMachineIdentityForUpdate
	// immediately before mutating m in memory), mirroring
	// UpdateProjectInvitation's `WHERE id = ? AND state = 'pending'` pattern
	// (#412). Returns whether the write actually matched a row.
	//
	// This exists because the now-deleted RemoteStorage's WithTransaction was a
	// no-op passthrough — there was no client-side transaction to open over HTTP
	// — so a generic two-call Lock-then-Update sequence run against it got NONE of
	// the atomicity LocalStorage provides via a real DB transaction + row lock
	// (Postgres: SELECT ... FOR UPDATE), silently reopening the exact #388 race (a
	// concurrent revoke and reactivate racing off the same pre-transition state
	// could un-revoke a just-revoked machine identity) across the HTTP hop.
	// Routing the actual write through this one conditional round trip restores
	// the same guarantee LocalStorage already has, without making any
	// transition-legality decision here: the caller (core.TransitionMachineIdentity)
	// still decides fromState/to via canTransitionMachine before calling this;
	// a false match result must be treated exactly like an illegal transition,
	// not retried or silently overwritten.
	TransitionMachineIdentityState(ctx context.Context, m *models.MachineIdentity, fromState string) (bool, error)
	ListMachineIdentities(ctx context.Context, projectID uint) ([]*models.MachineIdentity, error)
	// ListAllMachineIdentities returns every machine identity across all projects —
	// for install-wide sweeps such as SoD conflict detection over non-human principals.
	ListAllMachineIdentities(ctx context.Context) ([]*models.MachineIdentity, error)
	// CountMachineIdentitiesByClassification returns install-wide counts keyed by
	// classification label ("" = unclassified) for the compliance posture.
	CountMachineIdentitiesByClassification(ctx context.Context) (map[string]int, error)
	// CountStaleMachineIdentitiesByProject returns, for every project in
	// projectIDs in a single grouped query, the count of ACTIVE machine identities
	// not seen since olderThan (never-seen counts from creation) — the same
	// definition as ListStaleMachineIdentities, but deployment-wide in one query
	// instead of one call per project. Used by the hygiene rollup (#393). A
	// project absent from the result has zero stale machine identities.
	CountStaleMachineIdentitiesByProject(ctx context.Context, projectIDs []uint, olderThan time.Time) (map[uint]int, error)

	// Machine-token credentials (ADR-030) — opaque bearer tokens, hashed at rest.
	CreateMachineIdentityCredential(ctx context.Context, c *models.MachineIdentityCredential) (*models.MachineIdentityCredential, error)
	GetMachineIdentityCredentialByHash(ctx context.Context, hash string) (*models.MachineIdentityCredential, error)
	// GetMachineIdentityCredentialWithIdentityStateByHash is
	// GetMachineIdentityCredentialByHash plus the owning MachineIdentity's State,
	// fetched in ONE query (a JOIN) instead of the two sequential round trips
	// GetMachineIdentityCredentialByHash + GetMachineIdentity would otherwise cost
	// every call (SESSION-PERF, #2403 follow-up). Returns only the identity's State,
	// not the full MachineIdentity row: CurrentMachineTokenRestriction — the one
	// caller this exists for — never needed anything else from it, and returning a
	// single scalar (rather than hand-listing every MachineIdentity column to avoid
	// a name collision with MachineIdentityCredential's own, e.g. both have `id`/
	// `name`/`created_at`/`classification`) keeps this safe from column drift if
	// either model gains fields later. identityState is "" if the identity row is
	// somehow missing (the INNER JOIN would have excluded it; treat as not-found,
	// same as today's sequential GetMachineIdentity failing).
	GetMachineIdentityCredentialWithIdentityStateByHash(ctx context.Context, hash string) (cred *models.MachineIdentityCredential, identityState string, err error)
	GetMachineIdentityCredentialByID(ctx context.Context, id uint) (*models.MachineIdentityCredential, error)
	ListMachineIdentityCredentials(ctx context.Context, machineID uint) ([]*models.MachineIdentityCredential, error)
	// ListMachineCredentialUsageByMachineIDs is the batch form of ListMachineIdentityCredentials
	// for the machine audit report (LIST-ENDPOINTS-1): per machine, its credentials with ONLY
	// id, machine_identity_id and last_used_at populated (no token hash or CIDR list).
	ListMachineCredentialUsageByMachineIDs(ctx context.Context, machineIDs []uint) (map[uint][]*models.MachineIdentityCredential, error)
	// ListActiveMachineIdentityCredentials returns every non-revoked machine
	// credential across all identities — the deployment-wide view for token-hygiene
	// auditing (stale / expired-but-active).
	ListActiveMachineIdentityCredentials(ctx context.Context) ([]*models.MachineIdentityCredential, error)
	// SetMachineIdentityCredentialClassification persists ONLY the
	// classification column of credentialID, and only if the row's CURRENT
	// classification is still fromClassification (the value the caller read
	// before deciding to change it): "UPDATE ... SET classification WHERE
	// id = ? AND classification = ?". matched=false (no error) means the row
	// moved since that read; the caller must fail closed.
	//
	// This REPLACES the former UpdateMachineIdentityCredential, a bare GORM
	// Save of the whole row (#2696). Classification is the only field any
	// caller of that method ever changed, but Save wrote back every column
	// the caller's earlier, unlocked read had put in the struct — `revoked`
	// included. A RevokeMachineToken that committed on another replica in
	// between was therefore silently undone, and the revoked token
	// authenticated again with no audit record of the un-revoke. The narrow
	// method is deliberately the ONLY one left: a full-row writer for this
	// model would reintroduce that for whatever the next caller forgets.
	SetMachineIdentityCredentialClassification(ctx context.Context, credentialID uint, fromClassification, toClassification string) (matched bool, err error)
	// RevokeMachineIdentityCredential revokes credentialID, but only if it
	// belongs to a machine identity owned by projectID (#1551) — the same
	// ownership check core.machineInProject already applies for every other
	// machine-token operation, now enforced at the storage boundary too so a
	// caller that reaches this primitive directly (bypassing core, e.g. the
	// /system RevokeMachineIdentityCredentialProxy relay) can't revoke a
	// credential cross-tenant by supplying a project_id it doesn't actually
	// own for a credential that belongs to a different one. Returns
	// ErrNotFound (via the same not-found path as an unknown ID) when the
	// credential exists but its machine's project doesn't match — the two
	// cases are indistinguishable to the caller by design, matching how a
	// non-existent row and a row a caller wasn't allowed to see already read
	// the same "not found" elsewhere in this codebase.
	RevokeMachineIdentityCredential(ctx context.Context, projectID, credentialID uint) error
	// CountMachineIdentityCredentialsByClassification returns install-wide counts
	// keyed by classification label ("" = unclassified) for the compliance posture.
	CountMachineIdentityCredentialsByClassification(ctx context.Context) (map[string]int, error)
	TouchMachineIdentityCredential(ctx context.Context, id uint, usedAt time.Time, staleness time.Duration) error
	// ListExpiringMachineCredentials returns every non-revoked MachineIdentityCredential
	// whose ExpiresAt is non-nil and strictly before before. Used by CheckTokenExpiry.
	ListExpiringMachineCredentials(ctx context.Context, before time.Time) ([]models.MachineIdentityCredential, error)

	// Machine-identity role grants (ADR-030) — mirror the user_roles surface.
	AssignMachineRole(ctx context.Context, machineID, roleID uint, scope Scope) error
	RemoveMachineRole(ctx context.Context, machineID, roleID uint, scope Scope) error
	GetMachineRoleIDsAt(ctx context.Context, machineID uint, scope Scope) ([]uint, error)
	// ResolveMachinePermissionAt is GetMachineRoleIDsAt plus RoleSetHasPermission
	// for one machine-principal decision (PERF-FIX-6, collapse C4): the role ids
	// and the role->permission cache generation come from ONE statement (one
	// snapshot), and the permission join runs only when that cache misses.
	// BypassesPermissionChecks is never set: a machine never bypasses (ADR-030).
	ResolveMachinePermissionAt(ctx context.Context, machineID uint, scope Scope, permission string) (*PrincipalPermission, error)
	GetMachineRoles(ctx context.Context, machineID uint) ([]*models.Role, error)
	// GetMachineRoleScopes returns the distinct (project, environment) scopes at
	// which machineID holds ANY role grant (machine_identity_roles) — the
	// machine-identity mirror of GetUserRoleScopes (G33): a helper that must
	// enumerate every scope a principal holds a role at (e.g. actorRoleIDs's
	// Connect ref-grant match, GetReadableScopes) needs this to discover
	// project-scoped machine grants the same way it already discovers
	// project-scoped user grants, rather than resolving only the global scope.
	GetMachineRoleScopes(ctx context.Context, machineID uint) ([]Scope, error)

	// Machine-identity OIDC bindings (ADR-031) — map an external token's
	// (issuer, subject) to a machine identity for federated authentication.
	CreateOIDCBinding(ctx context.Context, b *models.MachineIdentityOIDCBinding) (*models.MachineIdentityOIDCBinding, error)
	GetMachineByOIDCSubject(ctx context.Context, issuer, subject string) (*models.MachineIdentity, error)
	ListOIDCBindings(ctx context.Context, machineID uint) ([]*models.MachineIdentityOIDCBinding, error)
	GetOIDCBindingByID(ctx context.Context, id uint) (*models.MachineIdentityOIDCBinding, error)
	DeleteOIDCBinding(ctx context.Context, id uint) error

	// Project membership lifecycle (ADR-022). Separate from the role grant.
	CreateProjectMembership(ctx context.Context, m *models.ProjectMembership) (*models.ProjectMembership, error)
	GetProjectMembership(ctx context.Context, id uint) (*models.ProjectMembership, error)
	// TransitionProjectMembershipState persists m's full row via a single
	// conditional write — "UPDATE ... WHERE id = ? AND state = ?" — succeeding
	// only if the row's CURRENT persisted state still equals fromState (the
	// value TransitionMembership/revertFailedActivation observed immediately
	// before mutating m in memory), mirroring TransitionMachineIdentityState's
	// exact shape (#G42). Unlike that helper, there's no row lock backing this
	// read — the conditional write is the ONLY thing closing the race, so
	// there must never be a plain unconditional-write alternative for a state
	// transition: a concurrent TransitionMembership call landing between the
	// read and the write would otherwise be silently reverted (or silently
	// revert this call), corrupting the ADR-022 state machine. Returns whether
	// the write actually matched a row; a false match must be treated exactly
	// like an illegal transition, not retried or silently overwritten.
	TransitionProjectMembershipState(ctx context.Context, m *models.ProjectMembership, fromState string) (bool, error)
	ListProjectMemberships(ctx context.Context, projectID uint) ([]*models.ProjectMembership, error)
	// GetActiveProjectMembership returns the user's non-revoked membership in a
	// project, or an error if none exists.
	GetActiveProjectMembership(ctx context.Context, projectID, userID uint) (*models.ProjectMembership, error)
	// ListStaleInvitedMemberships returns memberships still in `invited` state
	// that were invited before the cutoff.
	ListStaleInvitedMemberships(ctx context.Context, before time.Time) ([]*models.ProjectMembership, error)

	// In-app notifications (ADR-024).
	CreateNotification(ctx context.Context, n *models.Notification) (*models.Notification, error)
	// ListNotifications returns a user's notifications newest-first; when
	// unreadOnly is set, only unread ones. limit caps the result (0 = default).
	ListNotifications(ctx context.Context, userID uint, unreadOnly bool, limit int) ([]*models.Notification, error)
	CountUnreadNotifications(ctx context.Context, userID uint) (int64, error)
	// HasUnreadNotification reports whether the user has an unread notification of
	// the given type scoped to the given project. Filters at the DB level (no
	// unbounded/"top N of everything" fetch), so it finds a match regardless of
	// how many other unread notifications of other types/projects exist (#399).
	HasUnreadNotification(ctx context.Context, userID uint, nType string, projectID uint) (bool, error)
	// GetUnreadNotification returns the user's unread notification of the given
	// type scoped to the given project, or nil if none exists. Unlike
	// HasUnreadNotification, this returns the full row so a dedup check can also
	// compare (and, on escalation, update) its recorded Severity instead of only
	// checking existence (#250).
	GetUnreadNotification(ctx context.Context, userID uint, nType string, projectID uint) (*models.Notification, error)
	// UpdateNotification updates an existing notification's Title/Message/Severity
	// in place, scoped to its owner (id + userID must both match or nothing is
	// changed). Used to escalate a standing reminder when a recheck finds a more
	// severe state than what was originally recorded (#250), instead of creating
	// a second unread notification and piling up.
	UpdateNotification(ctx context.Context, n *models.Notification) error
	// MarkNotificationRead marks one notification read, scoped to its owner.
	MarkNotificationRead(ctx context.Context, id, userID uint) error
	MarkAllNotificationsRead(ctx context.Context, userID uint) error
	// The Scoped variants see only the user's notifications inside scope (see
	// NotificationScope): the feed of a restricted personal access token. The
	// narrowing is in the query, so limit and the count apply to the rows the token
	// can see, not to a newest-N window of all of them (PAT-GUARD-1).
	ListScopedNotifications(ctx context.Context, userID uint, scope NotificationScope, unreadOnly bool, limit int) ([]*models.Notification, error)
	CountUnreadScopedNotifications(ctx context.Context, userID uint, scope NotificationScope) (int64, error)
	// MarkScopedNotificationRead returns not-found for a notification outside scope.
	MarkScopedNotificationRead(ctx context.Context, id, userID uint, scope NotificationScope) error
	MarkAllScopedNotificationsRead(ctx context.Context, userID uint, scope NotificationScope) error
	// ListUserProjectMemberships returns all membership rows for a single user,
	// newest first (powers the per-user assignments view).
	ListUserProjectMemberships(ctx context.Context, userID uint) ([]*models.ProjectMembership, error)
	// ListUserProjectMembershipsByUserIDs is the batch form of ListUserProjectMemberships
	// (LIST-ENDPOINTS-1): each user's rows, newest invite first, keyed by user id; a user
	// with no row is absent.
	ListUserProjectMembershipsByUserIDs(ctx context.Context, userIDs []uint) (map[uint][]*models.ProjectMembership, error)
	// CountProjectMembershipsByUsers returns per-user membership tallies (active
	// and non-revoked total) for the given user IDs in one grouped query.
	CountProjectMembershipsByUsers(ctx context.Context, userIDs []uint) (map[uint]MembershipCounts, error)

	// Secret Management
	//
	// CreateSecret persists secret's metadata; secret itself carries no value
	// field at all (models.SecretNode has none — the plaintext normally lives
	// only in core.CreateSecretRequest.Value and is routed to a separate
	// CreateSecretVersion call core.CreateSecret makes right after this one).
	// The optional plaintextValue variadic (#499) existed ONLY for the now-deleted
	// RemoteStorage: its upstream HTTP handler required "value" in the SAME POST
	// /api/v1/secrets body and created version 1 atomically as part of handling
	// it, with no separate "create metadata now, add the value later" route to
	// call instead. LocalStorage's implementation has always ignored this
	// parameter — the value flows through the existing, unchanged
	// CreateSecretVersion path — but callers (internal/core/secrets.go) still
	// construct and pass it on every call, for a backend that no longer exists.
	// Candidate for a follow-up cleanup: drop the parameter, ValueStored
	// (models.SecretNode), and the now-always-false branch in core.CreateSecret
	// that checks it — left untouched here since it threads through the
	// interface, LocalStorage, and the generated fault-injection wrapper, and
	// deserves its own reviewed PR rather than riding along with a comment sweep.
	CreateSecret(ctx context.Context, secret *models.SecretNode, plaintextValue ...string) (*models.SecretNode, error)
	GetSecret(ctx context.Context, id uint) (*models.SecretNode, error)
	// GetSecretsByIDs is the batch form of GetSecret: every secret in ids, in one
	// query, instead of one GetSecret call per ID. IDs with no matching row are
	// simply absent from the result (no error) — same as GetSecret's own
	// not-found case, just without the per-ID error wrapping. Used by the rotation
	// planner's risk-scoring batch (#409) so scoring N candidate secrets costs a
	// small constant number of queries, not N.
	GetSecretsByIDs(ctx context.Context, ids []uint) ([]*models.SecretNode, error)
	// Batch name lookups for list views (LIST-ENDPOINTS-1): one query per page
	// instead of one GetUser / GetGroup / GetMachineIdentity / GetSecretTags per
	// row. Each selects only the id and display column. An id with no live row is
	// absent from the map (no error), as the single-row getters report not-found.
	// GetSecretTagsBySecretIDs returns name-ordered tags; an untagged secret is absent.
	GetUsernamesByIDs(ctx context.Context, ids []uint) (map[uint]string, error)
	// GetUserBriefsByIDs is GetUsernamesByIDs plus the email (id, username, email columns only).
	GetUserBriefsByIDs(ctx context.Context, ids []uint) (map[uint]UserBrief, error)
	GetGroupNamesByIDs(ctx context.Context, ids []uint) (map[uint]string, error)
	GetMachineIdentityNamesByIDs(ctx context.Context, ids []uint) (map[uint]string, error)
	GetSecretTagsBySecretIDs(ctx context.Context, ids []uint) (map[uint][]string, error)
	GetSecretByName(ctx context.Context, name string, projectID, environmentID uint) (*models.SecretNode, error)
	// UpdateSecretFields persists ONLY the fields f names, onto a LIVE secret
	// row: "UPDATE secret_nodes SET <named columns> WHERE id = ? AND deleted_at
	// IS NULL". matched=false (no error) means the secret is gone; the caller
	// must not report success. See SecretFieldUpdate.
	//
	// This REPLACES the former UpdateSecret, a bare GORM Save of a struct the
	// caller read earlier and unlocked (#2695). Being on the SHARED primitive,
	// every one of its eight callers inherited two defects at once:
	//
	//   - Save's 0-rows fallback upserts with deleted_at = NULL, so ANY of them
	//     landing after a concurrent DeleteSecret RESURRECTED the secret — and
	//     DeleteSecret also revokes its shares and ACLs, so the secret came
	//     back without them, with no secret.restored audit event and without
	//     going through RestoreSecret;
	//   - Save writes every column, so each caller reverted whatever a narrower
	//     concurrent writer had changed since its own read: SuspendSecret's
	//     status=suspended (an incident freeze), TryIncrementSecretNodeReadCount's
	//     read_count (re-opening a spent MaxReads budget),
	//     ClearProjectSecretOwnership's owner_id=0 (an offboarded user regains
	//     the owner short-circuit), and the rotation columns.
	//
	// Per-field pointers are the fix, not a convenience: each caller names only
	// the columns it owns, so no caller can revert another's. A caller that
	// populates everything is visible as exactly that in a diff.
	UpdateSecretFields(ctx context.Context, id uint, f SecretFieldUpdate) (matched bool, err error)
	// UpdateSecret is the full-row Save UpdateSecretFields replaces. It is kept
	// ONLY because one caller still needs it: SetSecretAutoRotate
	// (rotation_executor.go), which is #2650's site and is converted to a
	// column-scoped UpdateSecretRotationConfig by open PR #2668 — in the same
	// few lines of this file. Deleting it here would make #2695 conflict with a
	// PR the coordinator is about to merge, for no safety gain, since that one
	// call site is exactly what #2668 fixes.
	//
	// Do not add a caller. TestUpdateSecret_HasNoProductionCallerBeyond2668
	// fails if one appears, and fails again once #2668 lands and the last one
	// goes away — at which point this method and that test both get deleted.
	UpdateSecret(ctx context.Context, secret *models.SecretNode) (*models.SecretNode, error)
	// TransitionSecretStatus persists secret's full row via a single conditional
	// write — "UPDATE ... WHERE id = ? AND status = ?" — succeeding only if the
	// row's CURRENT persisted status still equals fromStatus (the value the
	// caller observed via GetSecret immediately before mutating secret.Status in
	// memory), mirroring UpdateProjectInvitation's `WHERE id = ? AND state =
	// 'pending'` pattern and TransitionMachineIdentityState's `WHERE id = ? AND
	// state = ?` pattern exactly, just for SecretNode.Status. Returns whether the
	// write actually matched a row.
	//
	// This exists because SuspendSecret/ResumeSecret (internal/core/
	// secret_suspend.go) previously did a plain read-then-unconditional-
	// UpdateSecret: a suspend racing a resume on the same secret could silently
	// clobber each other depending on write order with no error to either
	// caller, and — because UpdateSecret persists the FULL in-memory struct —
	// any OTHER field mutated by a concurrent, unrelated operation between the
	// read and this write would be silently reverted to the stale value read at
	// the top, a general lost-update problem. And because the now-deleted
	// RemoteStorage's WithTransaction was a no-op passthrough, a naive two-call
	// GetSecret-then-UpdateSecret sequence run against it got NONE of the
	// atomicity a real DB transaction + conditional write provides, reopening the
	// same race across the HTTP hop. Routing the write through this one
	// conditional round trip instead
	// restores the same guarantee LocalStorage already has: a false match
	// result must be treated exactly like a lost race — surfaced as an error to
	// the caller — not retried or silently overwritten.
	TransitionSecretStatus(ctx context.Context, secret *models.SecretNode, fromStatus string) (bool, error)
	// UpdateSecretRotationConfig persists ONLY secret's auto-rotation columns
	// (auto_rotate, rotation_length, rotation_charset, rotation_backend,
	// rotation_ref) plus updated_at, via one conditional "UPDATE ... WHERE id = ?
	// AND project_id = ? AND rotation_backend = ? AND deleted_at IS NULL". It
	// succeeds only if the secret is still live, still in the project the caller
	// authorized against, and its CURRENT rotation_backend still equals
	// fromBackend — the pre-read value core.SetSecretAutoRotate's admin gate
	// (#90) was decided on. Returns whether the write matched a row; a false
	// result is a lost race and must fail closed, never be retried blind.
	//
	// It exists because SetSecretAutoRotate used to persist its pre-read
	// snapshot with UpdateSecret's full-row Save, which undeleted a concurrently
	// deleted secret (Save's upsert fallback writes deleted_at = NULL), reverted
	// a concurrent admin's backend binding and restored cleared ownership (#2650).
	UpdateSecretRotationConfig(ctx context.Context, secret *models.SecretNode, fromBackend string) (bool, error)
	DeleteSecret(ctx context.Context, id uint) error
	// RestoreSecret clears a soft-deleted secret's deleted_at (ADR-033).
	RestoreSecret(ctx context.Context, id uint) error
	// GetSecretIncludingDeleted loads a secret even if soft-deleted (Unscoped),
	// so the restore route can resolve a deleted secret's scope (ADR-033).
	GetSecretIncludingDeleted(ctx context.Context, id uint) (*models.SecretNode, error)
	ListSecrets(ctx context.Context, filter *SecretFilter) ([]*models.SecretNode, int64, error)
	// ListOrphanedSecrets returns a project's live secrets whose owner is no longer
	// a live user (the owner was deleted/soft-deleted) — offboarding hygiene, so an
	// admin can re-assign ownership. Scoped to the project via the environment JOIN.
	ListOrphanedSecrets(ctx context.Context, projectID uint) ([]*models.SecretNode, error)
	// CountOrphanedSecretsByProject returns the orphaned-secret count (same
	// definition as ListOrphanedSecrets) for every project in projectIDs, in a
	// single grouped query keyed by project ID — the deployment-wide counterpart
	// used by the hygiene rollup (#393) instead of calling ListOrphanedSecrets once
	// per project. A project absent from the result has zero orphaned secrets.
	CountOrphanedSecretsByProject(ctx context.Context, projectIDs []uint) (map[uint]int, error)
	// CountExpiringSecretsByProject returns, for every project in projectIDs in a
	// single grouped query, the count of live secrets with a non-null expiration
	// before expiresBefore — the deployment-wide counterpart to the
	// ListSecrets(ExpiresBefore) count ProjectHygieneSummary uses per-project
	// (#393). A project absent from the result has zero expiring secrets.
	CountExpiringSecretsByProject(ctx context.Context, projectIDs []uint, expiresBefore time.Time) (map[uint]int, error)
	// ListLiveSecretNamesByProject returns every live secret (folders excluded)
	// across every project in projectIDs — id/name/type/classification/environment
	// plus its project ID — in a SINGLE query ordered by project then name, capped at
	// limit total rows. This is the deployment-wide counterpart to the per-project
	// ListSecrets call SecretNameConformance uses (#416): naming-policy regex
	// matching is not a SQL concern, so this intentionally returns raw rows for the
	// caller to check against the policy in memory — only the N+1 QUERY pattern
	// (one ListSecrets call per project) is eliminated, not the in-memory regex
	// work. The returned bool reports whether limit was hit (result truncated).
	ListLiveSecretNamesByProject(ctx context.Context, projectIDs []uint, limit int) ([]SecretNameRow, bool, error)
	// GetSecretTags returns a secret's tag names (sorted). SetSecretTags replaces a
	// secret's tags wholesale, upserting Tag rows by name — secret organization/search.
	GetSecretTags(ctx context.Context, secretID uint) ([]string, error)
	SetSecretTags(ctx context.Context, secretID uint, tagNames []string) error
	// ListProjectSecretsForDrift returns one lightweight row per secret in the
	// project (folders excluded, secrets in soft-deleted environments excluded),
	// carrying just the fields cross-environment drift detection pivots on:
	// environment id, name, type, and whether expiration / max_reads are set. No
	// secret values are read.
	ListProjectSecretsForDrift(ctx context.Context, projectID uint) ([]DriftSecretRow, error)
	GetSecretVersions(ctx context.Context, secretID uint) ([]*models.SecretVersion, error)
	CreateSecretVersion(ctx context.Context, version *models.SecretVersion) (*models.SecretVersion, error)
	GetLatestSecretVersion(ctx context.Context, secretID uint) (*models.SecretVersion, error)
	// SetSecretCertNotAfter caches a certificate-typed secret's parsed leaf expiry
	// (ADR-056), a targeted column update with no other side effects.
	SetSecretCertNotAfter(ctx context.Context, secretID uint, notAfter *time.Time) error
	// SetRetentionOverride sets the RetentionOverrideDays on a SecretNode row.
	// days = 0 clears the override (reverts to the global policy).
	SetRetentionOverride(ctx context.Context, secretID uint, days int) error
	IncrementSecretReadCount(ctx context.Context, versionID uint) error
	// TryIncrementSecretReadCount atomically increments a version's read count only
	// while it is still below maxReads, in a single conditional UPDATE. Returns true
	// when the increment happened (the read is within the cap), false when the cap is
	// already reached (or the version is gone). This is the race-free gate for
	// max-reads enforcement: concurrent reads can never collectively exceed the cap.
	TryIncrementSecretReadCount(ctx context.Context, versionID uint, maxReads int) (bool, error)
	// TryIncrementSecretNodeReadCount is TryIncrementSecretReadCount's secret-level
	// twin (#133): keyed on the SECRET, not a version, so the count carries forward
	// across rotate/rollback creating a new version — a per-version counter resets
	// to zero on every new version, letting a burn-after-N-reads secret become
	// re-readable simply by rolling back. This is the authoritative max-reads gate;
	// TryIncrementSecretReadCount remains for the per-version read_count DISPLAY
	// field only.
	TryIncrementSecretNodeReadCount(ctx context.Context, secretID uint, maxReads int) (bool, error)
	// ListSecretsWithQuota returns every live secret (IsSecret=true, not
	// soft-deleted) whose MaxReads pointer is set and greater than zero —
	// the full candidate set for the read-quota alert job. No values are read.
	ListSecretsWithQuota(ctx context.Context) ([]models.SecretNode, error)

	// Secret Sharing Management
	CreateShareRecord(ctx context.Context, share *models.ShareRecord) (*models.ShareRecord, error)
	GetShareRecord(ctx context.Context, shareID uint) (*models.ShareRecord, error)
	UpdateShareRecord(ctx context.Context, share *models.ShareRecord) (*models.ShareRecord, error)
	DeleteShareRecord(ctx context.Context, shareID uint) error
	// now is the instant "currently active" is evaluated against (expires_at IS
	// NULL OR expires_at > now) -- an explicit parameter, not an internal
	// time.Now() read, so every caller of these seven methods sources it from
	// the SAME clock its own active-share check uses (KeyorixCore.shareEffectiveNow),
	// instead of this storage layer reading the real wall clock independently
	// (#1983 investigation finding: this was the one "split clock in series"
	// gap among the sharing methods -- see jit_access.go's shareEffectiveNow
	// callers for the production wiring). Mirrors DeleteExpiredShareRecords'
	// existing before time.Time parameter below, not a new mechanism.
	ListSharesBySecret(ctx context.Context, secretID uint, now time.Time) ([]*models.ShareRecord, error)
	// ListSharesBySecretIDs is the batch form of ListSharesBySecret: currently-active
	// share records for every secret in secretIDs, in one query — used by the
	// rotation planner's risk-scoring batch (#409) instead of one ListSharesBySecret
	// call per candidate secret.
	ListSharesBySecretIDs(ctx context.Context, secretIDs []uint, now time.Time) ([]*models.ShareRecord, error)
	ListSharesByUser(ctx context.Context, userID uint, now time.Time) ([]*models.ShareRecord, error)
	ListSharesByOwner(ctx context.Context, ownerID uint, now time.Time) ([]*models.ShareRecord, error)
	ListSharesByGroup(ctx context.Context, groupID uint, now time.Time) ([]*models.ShareRecord, error)
	ListSharedSecrets(ctx context.Context, userID uint, now time.Time) ([]*models.SecretNode, error)
	CheckSharePermission(ctx context.Context, secretID, userID uint, now time.Time) (string, error)
	// DeleteExpiredShareRecords removes time-bound shares whose ExpiresAt is non-NULL
	// and at or before the cutoff, returning the removed rows so the caller can audit
	// each expiry. Server-side only (run by the JIT expiry scheduler).
	DeleteExpiredShareRecords(ctx context.Context, before time.Time) ([]*models.ShareRecord, error)
	// ReassignSecretShareOwner re-stamps ShareRecord.OwnerID to newOwnerID on EVERY row
	// of secretID — live, expired-unswept and soft-deleted (revoked) alike — and returns
	// how many rows it wrote (#3102). Only owner_id is written: permission, expires_at,
	// recipient and deleted_at are untouched, so no recipient's access changes and a
	// revoked share stays revoked. It exists for ONE caller, the ownership transfer
	// (core.transferOwnership), and MUST run in the same WithTransaction as the
	// secret's owner_id write: ShareRecord.OwnerID is the key of the owner-scoped share
	// lists while revoke/update are gated on owning the SECRET, so the two have to move
	// together. Every soft-deleted row is re-stamped too, so nothing that ever
	// resurrects a row can bring the previous owner back as the share's owner.
	ReassignSecretShareOwner(ctx context.Context, secretID, newOwnerID uint) (int64, error)

	// User Management
	//
	// CreateUser persists user, which by this point already carries its final
	// bcrypt PasswordHash (`json:"-"` — core.buildUserForCreate hashes and
	// discards the caller-supplied plaintext before ever reaching here). The
	// optional plaintextPassword variadic (#499) existed ONLY for the now-deleted
	// RemoteStorage: its upstream HTTP handler re-hashed its own bcrypt copy
	// server-side and therefore required the PLAINTEXT password in its request
	// body, not a hash it could not verify was produced honestly. LocalStorage's
	// implementation has always ignored this parameter (it already has the hash
	// and never additionally receives, logs, or persists the plaintext) — same
	// follow-up cleanup candidate as CreateSecret's plaintextValue above (drop the
	// parameter; call sites still construct and pass it for a backend that no
	// longer exists).
	CreateUser(ctx context.Context, user *models.User, plaintextPassword ...string) (*models.User, error)
	// CreateUserWithRoleGrants creates the user and applies all role grants in a
	// single transaction (ADR-028 atomic provisioning); on any failure nothing is
	// persisted.
	CreateUserWithRoleGrants(ctx context.Context, user *models.User, grants []RoleGrant) (*models.User, error)
	GetUser(ctx context.Context, id uint) (*models.User, error)
	// LockUserForUpdate re-reads a user by ID inside a WithTransaction, taking a
	// row-level write lock on backends that support one (Postgres: SELECT … FOR
	// UPDATE) so a read-modify-write on the row serializes against concurrent writers
	// across replicas. On backends without row locks (SQLite) it is a plain read, and
	// the caller is responsible for its own process-level serialization. Returns the
	// typed ErrUserNotFound when the user is absent. Use this — not GetUser — whenever
	// a transaction increments or conditionally mutates per-user counters (e.g. the
	// login-lockout failed-attempt count) that must not lose updates under concurrency.
	LockUserForUpdate(ctx context.Context, id uint) (*models.User, error)
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	UpdateUser(ctx context.Context, user *models.User) (*models.User, error)
	// UpdateUserIfActiveStateMatches persists ONLY the profile columns UpdateUser
	// applies in memory from a request (username/username_folded, email/
	// email_folded, display name, the new IsActive value, updated_at) — never the
	// full row, so it cannot revert a concurrent narrow write to any other column
	// (SetAccountState, SetPasswordHash, MFA, lockout; #2653/#2654) — via a single
	// conditional "UPDATE ... WHERE id = ? AND is_active = ?", succeeding only if
	// the row's CURRENT persisted is_active still equals fromActive (the value
	// UpdateUser observed via GetUser, i.e. wasActive, before applying any of the
	// request's field changes in memory). Returns whether the write actually
	// matched a row, mirroring TransitionMachineIdentityState's `WHERE id = ? AND
	// state = ?` / UpdateProjectInvitation's `WHERE id = ? AND state = 'pending'`
	// pattern (#388/#412) for this codebase's other state-transition TOCTOU class.
	//
	// UpdateUser is a general-purpose multi-field update (username, email,
	// display name, IsActive, ...), not a single-purpose state-transition
	// function, so a plain c.storage.UpdateUser write is fine for requests that
	// leave IsActive untouched. But whenever req.IsActive != nil, UpdateUser
	// routes its final persist through THIS method instead: IsActive can flip
	// concurrently with any other UpdateUser call touching the same user (a
	// profile edit racing an admin deactivation, or two deactivation attempts
	// racing each other), and a plain write silently clobbers whichever change
	// lost the race, with no error to either caller. This exists for the exact
	// same reason TransitionMachineIdentityState does: the now-deleted
	// RemoteStorage's WithTransaction was a no-op passthrough, so a naive
	// GetUser-then-UpdateUser sequence run against it got none of the atomicity
	// LocalStorage provides via a real DB transaction — routing the actual write
	// through this one conditional round trip restores the same
	// guarantee LocalStorage already has, without making any validation decision
	// here: the caller (core.UpdateUser) still decides which fields to mutate and
	// what fromActive to assert before calling this; a false match result must be
	// treated as a lost-race error, not retried or silently overwritten.
	UpdateUserIfActiveStateMatches(ctx context.Context, user *models.User, fromActive bool) (bool, error)
	// UpdateLastLogin stamps the user's last_login_at column without touching any
	// other field (no updated_at bump). Called on every successful login.
	UpdateLastLogin(ctx context.Context, userID uint, loginAt time.Time) error
	// SetAccountState persists ONLY the account_state column (plus updated_at) —
	// narrower than the generic UpdateUser, and deliberately so (#454): an admin
	// suspend/reactivate (setAccountState) or a SCIM deprovision/reactivate (UpdateSCIMUser,
	// via the conditional SetAccountStateIfMatches below) is an explicit, security-relevant directive, not passive accounting — the caller must
	// see a hard error rather than a false "success" that leaves the account state
	// unchanged if this write ever fails.
	SetAccountState(ctx context.Context, id uint, state string, updatedAt time.Time) error
	// SetAccountStateIfMatches is SetAccountState made conditional on the row's
	// CURRENT account_state still being fromState (the value the caller read
	// before computing toState): "UPDATE ... SET account_state, updated_at WHERE
	// id = ? AND account_state = ? AND deleted_at IS NULL". matched=false (no
	// error) means the row moved — or is gone — since that read; the caller must
	// fail closed rather than revert a concurrent writer's state (e.g. a SCIM
	// reactivation must not turn a suspension that committed after its read back
	// into active). Used by the SCIM lifecycle paths, whose new state is derived
	// from the old one (applySCIMActiveState, DeprovisionSCIMUser); see
	// C-RACE-FIX-B2. A NULL column is matched by fromState "".
	SetAccountStateIfMatches(ctx context.Context, id uint, fromState, toState string, updatedAt time.Time) (bool, error)
	// ClaimUserExternalIDIfUnset persists ONLY external_id (plus updated_at) for
	// a user whose external_id is still UNSET and whose row is still live:
	// "UPDATE ... SET external_id, updated_at WHERE id = ? AND
	// COALESCE(external_id,'') = '' AND deleted_at IS NULL". claimed=false (no
	// error) means someone else federated the account first, or it is gone.
	//
	// This is resolveSSOUser's first-federation write (#2699). It used the
	// generic full-row UpdateUser, whose GORM Save upsert-fallback resurrected
	// an account an admin had deleted after resolveSSOUser's unlocked read —
	// writing back deleted_at=NULL, is_active=true, account_state=active — and
	// the same window also reverted a concurrent suspension, password change,
	// MFA enable or lockout. Narrow and conditional here; the caller re-reads
	// afterwards so its login gate sees the committed row, not its own stale
	// snapshot.
	ClaimUserExternalIDIfUnset(ctx context.Context, id uint, externalID string, updatedAt time.Time) (claimed bool, err error)
	// SetPasswordHash persists ONLY the password_hash and password_changed_at columns
	// (plus updated_at) — narrower than the generic UpdateUser, and deliberately so
	// (#484, the same rationale as SetAccountState above). A password change
	// (applyNewPassword, shared by self-service ChangePassword and the setup-token
	// consume flow) is exactly the kind of explicit security directive #454 already
	// treats as needing fail-closed semantics for account_state: a user must never be
	// told their password changed when it silently didn't. Any accompanying
	// account_state clear (a restricted state resetting to active) is persisted
	// separately via SetAccountState, not folded into this primitive.
	//
	// It also CLEARS one_time_password_expires_at: any newly set password supersedes
	// a one-time password, so the expiry must never outlive the credential it
	// belonged to (OTP-EXPIRY-1). A caller that installs a one-time password calls
	// SetOneTimePasswordExpiry AFTER this, in the same transaction.
	SetPasswordHash(ctx context.Context, id uint, hash string, changedAt time.Time) error
	// SetOneTimePasswordExpiry persists ONLY one_time_password_expires_at (plus
	// updated_at): the instant after which the current one-time password is refused
	// at login (OTP-EXPIRY-1). nil clears it. Must run in the same transaction as
	// the SetPasswordHash that installs the one-time password.
	SetOneTimePasswordExpiry(ctx context.Context, id uint, expiresAt *time.Time, updatedAt time.Time) error
	// UpdateLoginLockoutState persists ONLY the four login-lockout accounting columns
	// (failed_login_attempts, last_failed_login_at, login_locked_until,
	// login_lockout_count) — the same #454 rationale as SetAccountState above. Unlike
	// SetAccountState, though, lockout accounting is a passive backstop counter, not an
	// explicit security directive (mirrors #452's identical call on
	// CountRecentLoginAttempts/RecordLoginAttempt): a genuine write failure here is a
	// best-effort, fail-open backstop degradation (see login_lockout.go), not a hard
	// error to the caller.
	UpdateLoginLockoutState(ctx context.Context, id uint, attempts int, lastFailedAt, lockedUntil *time.Time, lockoutCount int) error
	DeleteUser(ctx context.Context, id uint) error
	RestoreUser(ctx context.Context, id uint) error
	// PurgeDeleted*Before hard-delete soft-deleted rows whose deleted_at is
	// older than `before`, returning the number purged (ADR-032). Irreversible.
	PurgeDeletedUsersBefore(ctx context.Context, before time.Time) (int64, error)
	PurgeDeletedProjectsBefore(ctx context.Context, before time.Time) (int64, error)
	PurgeDeletedEnvironmentsBefore(ctx context.Context, before time.Time) (int64, error)
	PurgeDeletedSecretsBefore(ctx context.Context, before time.Time) (int64, error)
	// Delete*Before hard-delete compliance records past their retention window
	// (ISO A.5.33 / GDPR), returning the number removed. Unlike the soft-delete
	// purge these age out live records by a time column, never touch active rows,
	// and cascade to dependent rows where noted. Irreversible.
	// DeleteAnomalyAlertsBefore removes an anomaly alert when EITHER: it is
	// ALREADY-ACKNOWLEDGED and detected_at < ackBefore (the normal, short window —
	// an old but never-acknowledged alert is still a live, unreviewed signal and is
	// never purged by this clause alone); OR it is unacknowledged and detected_at <
	// unackCeiling, a separate and much more generous absolute-age safety net (#489)
	// so an alert nobody ever acknowledges cannot accumulate forever (disk
	// exhaustion / unbounded ListAnomalyAlerts scans). A zero time.Time for either
	// parameter disables that clause entirely (matches it against nothing).
	DeleteAnomalyAlertsBefore(ctx context.Context, ackBefore, unackCeiling time.Time) (int64, error)
	// DeleteClosedAccessReviewsBefore removes closed campaigns (closed_at < before)
	// and their snapshot items, returning (campaigns, items) removed.
	DeleteClosedAccessReviewsBefore(ctx context.Context, before time.Time) (campaigns int64, items int64, err error)
	// DeleteExpiredBreakGlassBefore reconciles any TTL-lapsed 'active' row to
	// 'expired' (without deleting it in the same pass -- see local_purge.go's
	// doc comment), then removes non-active activations (created_at < before).
	DeleteExpiredBreakGlassBefore(ctx context.Context, before time.Time) (int64, error)
	// DeleteResolvedAccessRequestsBefore removes terminal-state requests (resolved_at
	// < before) and their approval records, returning (requests, approvals) removed.
	DeleteResolvedAccessRequestsBefore(ctx context.Context, before time.Time) (requests int64, approvals int64, err error)
	ListUsers(ctx context.Context, filter *UserFilter) ([]*models.User, int64, error)
	// ListUsersInStateBefore returns users whose account_state equals state and
	// who were created before the cutoff (ADR-025 stale-account warnings).
	ListUsersInStateBefore(ctx context.Context, state string, before time.Time) ([]*models.User, error)
	// ListInactiveUsers returns all live (non-deleted) users who have not logged
	// in since threshold: specifically, those whose last_login_at IS NULL AND
	// created_at < threshold, OR whose last_login_at < threshold. Used by the
	// inactivity auto-suspension job (SuspendInactiveUsers).
	ListInactiveUsers(ctx context.Context, threshold time.Time) ([]*models.User, error)
	GetUserByUsername(ctx context.Context, username string) (*models.User, error)
	// GetUserByExternalID resolves a SCIM-provisioned user by the IdP's externalId
	// (RFC 7644). Returns the not-found error when no user carries that external id.
	GetUserByExternalID(ctx context.Context, externalID string) (*models.User, error)
	GetUserGroups(ctx context.Context, userID uint) ([]*models.Group, error)
	// ListAllUserGroupMemberships returns every user_groups row in the
	// deployment, unfiltered by project scope (#G44) — the batch-load
	// counterpart to GetUserGroups: GetPermissionBaseline uses this to load
	// every user's group membership in one query instead of one GetUserGroups
	// call per user, a genuine N+1 whose cost scales with the deployment's own
	// user count. Preserves GetUserGroups' exact per-user multiplicity (a user
	// with both a global and a project-scoped membership row for the same
	// group yields two rows here too, matching GetUserGroups' unfiltered JOIN).
	ListAllUserGroupMemberships(ctx context.Context) ([]UserGroupMembership, error)

	// Password history (ADR-025 history_count). AddPasswordHistory records a
	// bcrypt hash; RecentPasswordHashes returns the most recent `limit` hashes
	// (newest first); PrunePasswordHistory keeps only the newest `keep` rows.
	AddPasswordHistory(ctx context.Context, userID uint, hash string, at time.Time) error
	RecentPasswordHashes(ctx context.Context, userID uint, limit int) ([]string, error)
	PrunePasswordHistory(ctx context.Context, userID uint, keep int) error

	// Group Management
	CreateGroup(ctx context.Context, group *models.Group) (*models.Group, error)
	GetGroup(ctx context.Context, id uint) (*models.Group, error)
	// UpdateGroupFields persists ONLY the non-nil fields among name,
	// nameFolded and description (plus updated_at) onto a LIVE group row:
	// "UPDATE groups SET ... WHERE id = ? AND deleted_at IS NULL".
	// matched=false (no error) means the group is gone; the caller must not
	// report success. name and nameFolded must be passed together — they are
	// one value in two columns (#1642) and a stale nameFolded would leave the
	// uniqueness index checking a name the group no longer has.
	//
	// This REPLACES the former UpdateGroup, a bare GORM Save (#2697). Save's
	// 0-rows fallback is an upsert that writes deleted_at = NULL, and DeleteGroup
	// deliberately KEEPS a deleted group's GroupRole and UserGroup rows so
	// RestoreGroup can work — so a rename landing after a delete or SCIM
	// deprovision brought the group back with every role grant and membership
	// live, with no restore audit event and without going through RestoreGroup.
	// An IdP DELETE closely followed by a PUT is enough: ReplaceSCIMGroup and
	// PatchSCIMGroup rename through this same primitive, outside the
	// withGroupProjectAdminGuardLocks that deleteGroupGuarded holds.
	UpdateGroupFields(ctx context.Context, id uint, name, nameFolded, description *string, updatedAt time.Time) (matched bool, err error)
	DeleteGroup(ctx context.Context, id uint) error
	// RestoreGroup clears a soft-deleted group's deleted_at (with its grants/members).
	RestoreGroup(ctx context.Context, id uint) error
	ListGroups(ctx context.Context) ([]*models.Group, error)
	// ListGroupsPage returns one name-ordered page of groups (offset is a 0-based
	// row offset) and the total count, without loading the rest of the table — used
	// by the SCIM Groups list so an unfiltered request can't drain the whole
	// directory into memory (see ListGroups' full-scan callers for why that's fine
	// there: they intentionally want every group, e.g. SSO group sync).
	ListGroupsPage(ctx context.Context, offset, pageSize int) ([]*models.Group, int64, error)
	// AddUserToGroup adds userID to groupID. projectID scopes the membership: 0
	// means global (the user is a member in every project context), non-zero
	// restricts it to that project only. The authorisation path unions both.
	AddUserToGroup(ctx context.Context, userID, groupID, projectID uint) error
	// RemoveUserFromGroup removes the (userID, groupID, projectID) membership row.
	// projectID must match the value used when the membership was created.
	RemoveUserFromGroup(ctx context.Context, userID, groupID, projectID uint) error
	ListGroupMembers(ctx context.Context, groupID uint) ([]*models.User, error)
	// ListGroupMembersByGroupIDs is the batch form of ListGroupMembers: the members
	// of every group in groupIDs, keyed by group ID, in one query — used by the
	// rotation planner's risk-scoring batch (#409) instead of one ListGroupMembers
	// call per group share, per candidate secret.
	ListGroupMembersByGroupIDs(ctx context.Context, groupIDs []uint) (map[uint][]*models.User, error)
	// ListGroupMembersAt is ListGroupMembers scoped: only members whose UserGroup
	// row is global (project_id=0) OR matches scope.ProjectID (#G01). Unlike
	// ListGroupMembers (which returns every member regardless of their
	// membership's own scope), this is for callers that need to know whether a
	// member's membership actually confers authority AT this scope — e.g. "does
	// this group's GLOBAL role grant give member X global admin authority" must
	// exclude a member whose membership in the group is itself project-scoped.
	ListGroupMembersAt(ctx context.Context, groupID uint, scope Scope) ([]*models.User, error)

	// Permission Management
	CreatePermission(ctx context.Context, permission *models.Permission) (*models.Permission, error)
	AssignPermissionToRole(ctx context.Context, roleID, permissionID uint) error

	// Role Management
	//
	// CreateRole takes a typed identity.FoldedName, not a raw string or a
	// pre-built *models.Role, deliberately (#1642): both server/http and
	// server/grpc's role-creation handlers call this directly, bypassing
	// internal/core entirely (no length cap, no charset check, no
	// normalization of any kind existed before this). Patching each of those
	// two known call sites to construct a FoldedName themselves would still
	// let a third, future caller bypass it again by passing a raw string —
	// putting the typed parameter in the signature makes every caller,
	// present and future, go through identity.NewFoldedName's validation
	// (which also rejects control characters and bidi-override characters as
	// part of the PRECIS profile) or fail to compile.
	CreateRole(ctx context.Context, name identity.FoldedName, description string) (*models.Role, error)
	GetRole(ctx context.Context, id uint) (*models.Role, error)
	GetRoleByName(ctx context.Context, name string) (*models.Role, error)
	UpdateRole(ctx context.Context, role *models.Role) (*models.Role, error)
	// DeleteRole hard-deletes a role and cascades the delete to every
	// UserRole/GroupRole/MachineIdentityRole/RolePermission/ConnectRefGrant row
	// referencing it (SESSION-AT AT1 row 2). The returned RoleDeleteCascadeCounts
	// reports how many live assignments the cascade actually removed, strictly
	// for the audit trail (PR #2357 review) -- not a correctness mechanism, so a
	// caller that ignores it loses nothing but the audit detail.
	DeleteRole(ctx context.Context, id uint) (RoleDeleteCascadeCounts, error)
	ListRoles(ctx context.Context) ([]*models.Role, error)
	// SetRoleBypassesPermissionChecks sets models.Role.BypassesPermissionChecks
	// (ADR-084) for roleID. Deliberately NOT reachable from CreateRole/UpdateRole
	// or any request DTO -- called only by role seeding
	// (defaultRoles/BootstrapSystem, internal/core/auth_bootstrap.go) for the
	// four reserved admin-tier role names, immediately after creating them. No
	// other production caller should exist; this is the one narrow, storage-
	// internal write path the ADR names, not a general role-mutation primitive.
	SetRoleBypassesPermissionChecks(ctx context.Context, roleID uint, value bool) error

	// RBAC Operations.
	// AssignRole/RemoveRole bind a role to a user at the given Scope
	// (zero Scope = global). GetUserRoleIDsAt / GetUserGroupRoleIDsAt return the
	// role IDs that apply at a target scope (directly, or via group membership),
	// and RoleSetHasPermission reports whether any of those roles grants a
	// permission. Together they back core.Authorize.
	AssignRole(ctx context.Context, userID, roleID uint, scope Scope) error
	// AssignRoleWithExpiry binds a time-bound role to a user (just-in-time access):
	// the grant stops authorizing the moment expiresAt passes (the auth queries
	// filter on it) and is later swept by DeleteExpiredRoleGrants.
	AssignRoleWithExpiry(ctx context.Context, userID, roleID uint, scope Scope, expiresAt time.Time) error
	RemoveRole(ctx context.Context, userID, roleID uint, scope Scope) error
	// RemoveAllProjectRoleGrants deletes every user_roles row for (userID, projectID),
	// across ALL environments — not just the project-level (environment_id = 0) grant
	// RemoveRole's exact-scope match would touch. RemoveProjectMember uses it so that
	// offboarding a project member also revokes any environment-scoped grant (e.g.
	// "prod-only access", created via POST /user-roles) they separately hold in the
	// same project; otherwise it silently survives project-level removal, invisible to
	// the project admin who performed the offboarding (#232).
	RemoveAllProjectRoleGrants(ctx context.Context, userID, projectID uint) error
	// ClearProjectSecretOwnership clears the owner_id field (sets to 0) for every
	// live secret in projectID that is owned by userID. Called by RemoveProjectMember
	// so that an offboarded user's stale owner_id tag cannot grant them post-offboarding
	// owner-level access to those secrets via CheckSecretPermission's owner short-circuit
	// (RBAC-002).
	ClearProjectSecretOwnership(ctx context.Context, userID, projectID uint) error
	GetUserRoles(ctx context.Context, userID uint) ([]*models.Role, error)
	// ListAllUserRoleGrants returns every user→role grant row in the deployment,
	// including scoped (project/environment) and global (project_id=0) grants.
	// Includes time-bound (JIT) grants; callers filter by ExpiresAt if needed.
	ListAllUserRoleGrants(ctx context.Context) ([]*models.UserRole, error)
	// ListExpiringUserRoles returns every UserRole whose ExpiresAt is non-nil and
	// before the given cutoff (i.e. expiring or already expired). Used by
	// CheckRoleExpiry to find grants approaching their deadline.
	ListExpiringUserRoles(ctx context.Context, before time.Time) ([]models.UserRole, error)
	GetUserRoleIDsAt(ctx context.Context, userID uint, scope Scope) ([]uint, error)
	GetUserRoleIDsExact(ctx context.Context, userID uint, scope Scope) ([]uint, error)
	// IsProjectMember reports whether the user holds a LIVE role grant scoped to the
	// project itself (project_id = projectID), directly or via a group — i.e. real
	// membership. A global/install-wide role (project_id = 0) does NOT count.
	IsProjectMember(ctx context.Context, userID, projectID uint) (bool, error)
	// ProjectMembershipsAmong is IsProjectMember for many projects at once
	// (SHARES-BATCH-AUTHZ-1): the subset of projectIDs the user is a live member of,
	// by exactly IsProjectMember's rules (project 0 is never a membership; a global
	// role does not count; expired grants and soft-deleted groups do not count).
	ProjectMembershipsAmong(ctx context.Context, userID uint, projectIDs []uint) (map[uint]bool, error)
	// ListUserRoleGrants returns every live role grant of userID, direct and via a live
	// group, each with its own scope, so a caller can derive the role set at any number
	// of scopes in memory (SHARES-BATCH-AUTHZ-1). Applying UserRoleGrant.AppliesAt to
	// the rows yields exactly the role set ResolveUserPermissionAt reads at that scope.
	ListUserRoleGrants(ctx context.Context, userID uint) ([]UserRoleGrant, error)
	// ListUserLiveGroupMemberships returns userID's memberships in non-deleted groups
	// with the project each membership is scoped to (0 = global): the rows
	// GetUserGroupsAt filters by scope, for every scope at once.
	ListUserLiveGroupMemberships(ctx context.Context, userID uint) ([]UserGroupMembershipAt, error)
	// IsGroupProjectScoped reports whether groupID itself holds a LIVE role grant
	// scoped to the project (group_roles.project_id = projectID) — the group-share
	// counterpart to IsProjectMember, used to reject group shares whose recipient
	// group has no legitimate tie to the secret's project. A global/install-wide
	// group role grant (project_id = 0) does NOT count, matching IsProjectMember's
	// own global exclusion.
	IsGroupProjectScoped(ctx context.Context, groupID, projectID uint) (bool, error)
	GetUserGroupRoleIDsAt(ctx context.Context, userID uint, scope Scope) ([]uint, error)
	// GetUserGroupsAt is GetUserGroups scoped: only groups where userID's own
	// UserGroup row is global (project_id=0) OR matches scope.ProjectID (#G01).
	// GetUserGroups returns every group the user has ANY membership row in,
	// regardless of that membership's own project scope — callers resolving
	// "does this group membership grant authority within THIS project/secret"
	// must use this instead, or a membership scoped to project X is silently
	// treated as if it applied everywhere.
	GetUserGroupsAt(ctx context.Context, userID uint, scope Scope) ([]*models.Group, error)
	// GetUserRoleScopes returns the distinct (project, environment) scopes at which
	// userID holds ANY role, directly or via a live (non-deleted) group. It is the
	// scope-DISCOVERY step behind a scope-aware admin-rank-ceiling comparison
	// (impersonation's #165 check): the caller doesn't know in advance which
	// project a target might hold a project-scoped admin role in, so it must
	// enumerate every scope the target actually has a grant at, then evaluate
	// GetUserRoleIDsAt/GetUserGroupRoleIDsAt (via scopedRoleIDs) per scope.
	GetUserRoleScopes(ctx context.Context, userID uint) ([]Scope, error)
	// GetUserRoleScopesByUserIDs is the batch form of GetUserRoleScopes (LIST-ENDPOINTS-1):
	// the same distinct live scopes per user, keyed by user id; a user with no live role is absent.
	GetUserRoleScopesByUserIDs(ctx context.Context, userIDs []uint) (map[uint][]Scope, error)
	RoleSetHasPermission(ctx context.Context, roleIDs []uint, permission string) (bool, error)
	// RoleSetBypassesPermissionChecks reports whether any role in roleIDs has
	// BypassesPermissionChecks = true (ADR-084) -- the structural,
	// resolve-by-ID replacement for roleSetContainsAdmin's old fixed-name-list
	// lookup (internal/core/authz.go). Mirrors RoleSetHasPermission's shape.
	RoleSetBypassesPermissionChecks(ctx context.Context, roleIDs []uint) (bool, error)
	// ResolveUserPermissionAt is one user-principal role decision's reads
	// (PERF-FIX-6, collapse C4): GetUserRoleIDsAt ∪ GetUserGroupRoleIDsAt,
	// RoleSetBypassesPermissionChecks over that set and the role->permission
	// cache generation come from ONE statement (one snapshot); RoleSetHasPermission
	// is then answered from the cache under that generation, or by the live join
	// on a miss. The permission is not resolved (HasPermission false) when the
	// set is empty or bypasses, exactly as core.Authorize never asked then.
	ResolveUserPermissionAt(ctx context.Context, userID uint, scope Scope, permission string) (*PrincipalPermission, error)
	// ListAdminBypassRoleIDs enumerates every role ID carrying
	// BypassesPermissionChecks = true (ADR-084) -- the ENUMERATION counterpart to
	// RoleSetBypassesPermissionChecks' membership test, and the single source of
	// truth for "which roles confer administrative authority" (#2496,
	// INV-CORE-20). The last-install-admin guards need the set, not a yes/no on a
	// candidate set: they ask "which assignment rows count as an admin grant" and
	// "who else holds one", neither of which a membership predicate can answer.
	// Before this existed, those guards resolved the set by NAME
	// (installAdminRoleIDSet over a fixed super_admin/admin/system_admin list),
	// a second definition of "admin" that disagreed with the flag in both
	// directions -- see internal/core/admin_roles.go.
	//
	// Returns an error on any genuine resolution failure; callers must fail
	// closed (refuse the mutation) rather than treat it as an empty set, for
	// roleSetContainsAdmin's documented reason: an inability to verify must not
	// be indistinguishable from "there is no admin role here".
	ListAdminBypassRoleIDs(ctx context.Context) ([]uint, error)
	GetUserPermissions(ctx context.Context, userID uint) ([]*Permission, error)
	// GetUserGroupPermissions returns the permissions a user holds via GROUP
	// membership (group → group_roles → role_permissions), scope-agnostically and
	// across all of the user's groups — the counterpart to GetUserPermissions, which
	// covers only direct user_roles. Callers that need a user's full effective
	// permission set (e.g. SoD conflict detection, GetUserPermissionsByID) must
	// union both, mirroring how Authorize unions direct and group-inherited roles.
	GetUserGroupPermissions(ctx context.Context, userID uint) ([]*Permission, error)

	// Permission queries
	ListPermissions(ctx context.Context) ([]*models.Permission, error)
	GetPermission(ctx context.Context, id uint) (*models.Permission, error)
	GetRolePermissions(ctx context.Context, roleID uint) ([]*models.Permission, error)
	RemovePermissionFromRole(ctx context.Context, roleID, permissionID uint) error

	// Keyorix Connect per-reference grants (ADR-045). ListConnectRefGrantsByConnector
	// returns the grants scoped to one connector (the enforcement path);
	// ListConnectRefGrants returns all grants (management/listing).
	ListConnectRefGrantsByConnector(ctx context.Context, connector string) ([]*models.ConnectRefGrant, error)
	ListConnectRefGrants(ctx context.Context) ([]*models.ConnectRefGrant, error)
	CreateConnectRefGrant(ctx context.Context, grant *models.ConnectRefGrant) (*models.ConnectRefGrant, error)
	DeleteConnectRefGrant(ctx context.Context, id uint) error

	// GetProjectByName resolves a project by name, case-insensitively, matching the
	// same LOWER(name) WHERE deleted_at IS NULL partial unique index Project.Name's
	// own uniqueness is enforced by (ensureProjectNameIndex) — a soft-deleted
	// project's name must not resolve here, consistent with it being freed for reuse.
	// Returns a "not found"-substring error (matching GetProject's own convention)
	// when no live project matches.
	GetProjectByName(ctx context.Context, name string) (*models.Project, error)

	// GetConnectorProjectBinding returns the persisted project-ID binding for a
	// Connect connector (ADR-082) — see ConnectorProjectBinding's own doc comment for
	// why boot-time resolution is pinned by ID rather than re-resolved by name on
	// every boot. Returns a "not found"-substring error if the connector has no
	// binding yet (first boot for that connector).
	GetConnectorProjectBinding(ctx context.Context, connector string) (*models.ConnectorProjectBinding, error)
	// CreateConnectorProjectBinding persists a connector's first-boot project
	// resolution (ADR-082): the connector name, the resolved project ID, and the
	// project's name at resolution time (for later rename detection).
	CreateConnectorProjectBinding(ctx context.Context, binding *models.ConnectorProjectBinding) (*models.ConnectorProjectBinding, error)
	// ListConnectorProjectBindings returns every persisted connector→project
	// binding row (#1477's orphan-detection direction: a binding whose connector
	// name is no longer in cfg.Connect.Connectors). Boot-time-diagnostic only —
	// GetConnectorProjectBinding/CreateConnectorProjectBinding cover the
	// per-connector resolution path this does not participate in.
	ListConnectorProjectBindings(ctx context.Context) ([]*models.ConnectorProjectBinding, error)

	// Group-Role assignments. Assign/Remove bind a role to a group at the given
	// Scope (zero Scope = global).
	GetGroupRoles(ctx context.Context, groupID uint) ([]*models.Role, error)
	// GetGroupRoleGrants is GetGroupRoles plus each grant's time-bound expiry
	// (nil = permanent), so callers can surface remaining time on a JIT grant.
	GetGroupRoleGrants(ctx context.Context, groupID uint) ([]*GroupRoleGrant, error)
	// ListGroupRoleAssignments returns every role grant held by a group across ALL
	// scopes (unlike ListProjectRoleAssignments, which is scoped to one project) —
	// used to evaluate the admin-rank ceiling before adding a member to the group,
	// and the last-install-administrator invariant before removing one or deleting
	// the group outright.
	ListGroupRoleAssignments(ctx context.Context, groupID uint) ([]RoleAssignment, error)
	// ListAllGroupRoleGrants returns every group→role grant row in the deployment,
	// including scoped (project/environment) and global (project_id=0) grants, and
	// including already-expired time-bound grants — the group-grant counterpart to
	// ListAllUserRoleGrants. Unlike GetGroupRoles/GetGroupRoleGrants (role only, no
	// scope) or ListGroupRoleAssignments (scope, but silently drops expired rows),
	// this is the one call that carries a group grant's role, scope, AND expiry
	// together, unfiltered — what GetPermissionBaseline needs to report a
	// group-inherited grant's real scope and flag (not hide) an expired one (#G25).
	ListAllGroupRoleGrants(ctx context.Context) ([]*models.GroupRole, error)
	AssignRoleToGroup(ctx context.Context, groupID, roleID uint, scope Scope) error
	// AssignRoleToGroupWithExpiry binds a time-bound role to a group; see
	// AssignRoleWithExpiry.
	AssignRoleToGroupWithExpiry(ctx context.Context, groupID, roleID uint, scope Scope, expiresAt time.Time) error
	RemoveRoleFromGroup(ctx context.Context, groupID, roleID uint, scope Scope) error
	// DeleteExpiredRoleGrants removes user/group role grants whose ExpiresAt is at
	// or before `before`, returning the removed grants so the caller can audit each
	// expiry. Backs the JIT access-expiry scheduler.
	DeleteExpiredRoleGrants(ctx context.Context, before time.Time) ([]RoleAssignment, error)

	// Stats Snapshots
	SaveStatsSnapshot(ctx context.Context, snapshot *models.StatsSnapshot) error
	GetPreviousStatsSnapshot(ctx context.Context, userID uint) (*models.StatsSnapshot, error)

	// SaveDeploymentStatsSnapshot persists a deployment-wide stats snapshot.
	// Call once per UTC day from GetDashboardStats when admin stats are available.
	SaveDeploymentStatsSnapshot(ctx context.Context, snap *models.DeploymentStatsSnapshot) error

	// GetPreviousDeploymentStatsSnapshot returns the most recent deployment stats
	// snapshot that is older than 20 hours (so a new snapshot saved today doesn't
	// immediately compare against itself).  Returns nil, nil if none exists.
	GetPreviousDeploymentStatsSnapshot(ctx context.Context) (*models.DeploymentStatsSnapshot, error)

	// Compliance Posture Snapshots
	SaveCompliancePostureSnapshot(ctx context.Context, snap *models.CompliancePostureSnapshot) error
	// GetPreviousCompliancePostureSnapshot returns the most recent snapshot whose
	// snapshot_date is strictly before today's UTC midnight (i.e., from a prior
	// calendar day), to avoid same-day self-comparison.
	// Returns nil, nil when no prior snapshot exists.
	GetPreviousCompliancePostureSnapshot(ctx context.Context, before time.Time) (*models.CompliancePostureSnapshot, error)
	// ListCompliancePostureSnapshots returns snapshots ordered by snapshot_date
	// descending (most recent first). limit ≤ 0 returns the default cap (90 rows).
	ListCompliancePostureSnapshots(ctx context.Context, limit int) ([]*models.CompliancePostureSnapshot, error)

	// Credential Hygiene Trend Snapshots — daily counts of stale/expired PATs and
	// stale machine credentials for per-day trend queries.
	//
	// SaveHygieneTrendSnapshot upserts a snapshot for the given UTC calendar day
	// (first write creates; same-day re-run overwrites in place). Used by
	// RecordHygieneTrendPoint and the daily hygiene scheduler.
	SaveHygieneTrendSnapshot(ctx context.Context, snap *models.HygieneTrendSnapshot) error
	// ListHygieneTrendSnapshots returns up to `days` snapshots ordered by
	// snapshot_date DESC (newest first). Used by GetHygieneTrends.
	ListHygieneTrendSnapshots(ctx context.Context, days int) ([]*models.HygieneTrendSnapshot, error)
	// CountStalePATs returns the count of non-revoked PersonalAccessTokens where
	// ExpiresAt IS NULL OR ExpiresAt > now (active), AND
	// (LastUsedAt IS NULL OR LastUsedAt < threshold) — stale but not expired.
	CountStalePATs(ctx context.Context, threshold time.Time) (int, error)
	// CountExpiredPATs returns the count of non-revoked PersonalAccessTokens where
	// ExpiresAt IS NOT NULL AND ExpiresAt < now (expired but never revoked).
	CountExpiredPATs(ctx context.Context) (int, error)
	// CountStaleMachineCredentials returns the count of distinct machine identities
	// (active state) where all their credentials are either never used or were
	// last used before threshold (i.e. the machine identity is "stale").
	CountStaleMachineCredentials(ctx context.Context, threshold time.Time) (int, error)

	// Audit Logging
	LogAuditEvent(ctx context.Context, event *models.AuditEvent) error
	// LogAuditEventWithAccessLog is LogAuditEvent plus a secret_access_logs row,
	// committed together as one atomic unit (SESSION-PERF, #2403 follow-up, item 3)
	// — a caller that needs both (e.g. a secret read) gets them as one call
	// instead of two separate writes that could succeed/fail independently.
	// accessLog may be nil.
	LogAuditEventWithAccessLog(ctx context.Context, event *models.AuditEvent, accessLog *models.SecretAccessLog) error
	CreateSecretAccessLog(ctx context.Context, log *models.SecretAccessLog) error
	ListSecretAccessLogs(ctx context.Context, secretID uint, since time.Time) ([]models.SecretAccessLog, error)
	// CountSecretReadsBySecretIDs returns, for every secret in secretIDs with at
	// least one qualifying row, the number of "read" access-log entries at or
	// after since — aggregated in SQL (GROUP BY + COUNT), not one
	// ListSecretAccessLogs call per secret. Used by the rotation planner's
	// risk-scoring batch (#409); a secret absent from the result had zero
	// qualifying reads, same as ListSecretAccessLogs returning an empty slice.
	CountSecretReadsBySecretIDs(ctx context.Context, secretIDs []uint, since time.Time) (map[uint]int, error)
	// PrincipalSecretFirstSeen returns, for every non-empty accessed_by with at least
	// one access log row at or after `since`, the earliest access time per secret it
	// touched in that range — aggregated in SQL (GROUP BY + MIN), not loaded as full
	// log rows, so this stays cheap regardless of per-secret read volume. Backs the
	// anomaly detector's per-principal breadth-exfiltration pass (#101): a principal
	// reading many DIFFERENT secrets it has never touched before is invisible to the
	// per-secret rules (each secret only sees one unremarkable access), so this
	// aggregates across secrets by principal instead. See the LocalStorage
	// implementation's doc comment for why `since` must stay a coarse (date-scale)
	// bound rather than a narrow live-window one.
	PrincipalSecretFirstSeen(ctx context.Context, since time.Time) (map[string]map[uint]time.Time, error)
	// ListSecretIDsAccessedSince returns the distinct secret IDs with at least one
	// access-log row (any action, any accessor) at or after since. Backs the anomaly
	// detector's incremental sweep: a secret with no access-log row in the detection
	// horizon cannot trip any per-secret rule, so the detector skips its per-secret
	// access-log reads instead of sweeping every secret on every pass.
	ListSecretIDsAccessedSince(ctx context.Context, since time.Time) ([]uint, error)
	// MostAccessedSecrets returns the most-read secrets (optionally scoped to a
	// project and, further, to a single environment within it) in the window
	// since `since`, ordered by read count descending, capped at `limit`. Backs
	// the usage-analytics dashboard.
	MostAccessedSecrets(ctx context.Context, projectID, environmentID *uint, since time.Time, limit int) ([]SecretUsageStat, error)
	// UnusedSecrets returns secrets (optionally scoped to a project and, further,
	// to a single environment within it) with no read access since
	// `notReadSince` — including never-read secrets — ordered never-read first,
	// then oldest last read.
	UnusedSecrets(ctx context.Context, projectID, environmentID *uint, notReadSince time.Time) ([]UnusedSecretStat, error)
	// CountUnusedSecretsByProject returns, for every project in projectIDs in a
	// single grouped query, the count of secrets not read since notReadSince (or
	// never read) — the deployment-wide counterpart to UnusedSecrets, used by the
	// hygiene rollup (#393) instead of calling UnusedSecrets once per project. A
	// project absent from the result has zero unused secrets.
	CountUnusedSecretsByProject(ctx context.Context, projectIDs []uint, notReadSince time.Time) (map[uint]int, error)
	// GetSecretReadCounts aggregates "secret.read" audit events for the given
	// secret in the time window [since, until), returning the top-N actors sorted
	// by read count desc. Used by the secret read aggregation report.
	GetSecretReadCounts(ctx context.Context, secretID uint, since, until time.Time, limit int) ([]SecretReadEntry, error)
	// GetAnomalyConfig retrieves the single anomaly config row, or returns sensible
	// defaults if no row has been saved yet.
	GetAnomalyConfig(ctx context.Context) (*models.AnomalyConfigRecord, error)
	SaveAnomalyConfig(ctx context.Context, cfg *models.AnomalyConfigRecord) error
	CreateAnomalyAlert(ctx context.Context, alert *models.AnomalyAlert) error
	ListAnomalyAlerts(ctx context.Context, acknowledged *bool) ([]models.AnomalyAlert, error)
	// AcknowledgeAnomalyAlert marks an alert acknowledged and stamps who did it and
	// when directly on the row (#217), alongside the separate audit event the core
	// layer emits.
	AcknowledgeAnomalyAlert(ctx context.Context, id, actorID uint, at time.Time) error
	// ListUnalertedAnomalyAlerts returns alerts not yet pushed out (alerted=false),
	// and MarkAnomalyAlertAlerted flags one as pushed — for proactive alerting.
	ListUnalertedAnomalyAlerts(ctx context.Context) ([]models.AnomalyAlert, error)
	MarkAnomalyAlertAlerted(ctx context.Context, id uint) error
	GetAuditLogs(ctx context.Context, filter *AuditFilter) ([]*models.AuditEvent, int64, error)
	// MaxAuditEventID returns the highest audit_events.id (0 when the table is
	// empty): an O(1) read of the primary key's right edge. Scheduler jobs that
	// keep an id high-water mark read it first and bound their scan with
	// AuditFilter.UpToID, so a run costs O(rows added since the last run).
	MaxAuditEventID(ctx context.Context) (uint, error)
	// AuditRetentionStats returns the total audit event count and the oldest /
	// newest event timestamps. Keyorix never purges audit events, so these raw
	// aggregates let an operator demonstrate how far back the trail reaches
	// (NIS2 mandates 12 months of retention). Oldest/Newest are nil on an empty
	// table.
	AuditRetentionStats(ctx context.Context) (*AuditRetentionStats, error)
	// DeleteAuditLogsBefore hard-deletes the longest contiguous id prefix of
	// AuditEvent rows whose event_time is ALL before cutoff (INV-STORE-22,
	// #2633) — never a row past the first one that is not, so a row whose
	// event_time is out of id order is retained rather than cut out of the
	// middle of the hash chain — under the same KEYAUDIT lock appends use.
	// Returns the number of rows deleted, plus a re-anchor candidate when the
	// delete reached into the chained (post-ADR-029) region: the new earliest
	// surviving row's id/prev_hash/entry_hash, for the caller to authenticate
	// (HMAC, checkpoint signing key) and persist as the retention anchor BEFORE
	// VerifyAuditChain can walk the surviving chain again — nil when nothing
	// chained was deleted (nothing to re-anchor). The candidate's PurgedEvents
	// is the number of chained rows this delete removed. See AuditChainAnchor.
	DeleteAuditLogsBefore(ctx context.Context, cutoff time.Time) (int64, *AuditChainAnchor, error)
	// VerifyAuditChain re-walks the tamper-evidence hash chain (ADR-029) over
	// audit_events and reports whether it is intact. The first divergence —
	// modified field, deleted/inserted row, or broken linkage — is reported
	// with the offending event id. A leading run of pre-ADR-029 rows with empty
	// hashes is counted as an unchained legacy prefix, not a failure.
	//
	// anchor, when non-nil, seeds the walk at a legitimately-moved chain start
	// (a retention purge removed the original earliest rows) instead of
	// requiring the true genesis: the earliest surviving row must match
	// anchor.RowID/PrevHash/EntryHash exactly, or the chain is reported broken.
	// The caller MUST have already authenticated anchor (this layer trusts it
	// literally); pass nil to verify from genesis as before. A surviving chain
	// that already starts at genesis (the purge only removed the legacy
	// unchained prefix, or the table is now empty) ignores a non-nil anchor.
	VerifyAuditChain(ctx context.Context, anchor *AuditChainAnchor) (*AuditChainVerification, error)
	// VerifyAuditChainSegment walks one bounded part of the chain with the same
	// per-row rules as VerifyAuditChain (docs/specs/audit-incremental-verification.md).
	// With seg.AfterID == 0 it starts at the chain start exactly like
	// VerifyAuditChain(ctx, seg.Anchor). With seg.AfterID > 0 the row AfterID is
	// pinned first: it must exist, carry entry_hash == seg.SeedHash and recompute
	// from its own fields; the walk then continues with the rows id > AfterID,
	// the first of which must link to SeedHash. The walk stops after ThroughID
	// (0 = no bound) or MaxRows rows (0 = no bound). The result's HeadID/HeadHash
	// are the last row verified (the pinned row when nothing followed it), and
	// ChainedEvents counts the rows walked after the pinned row. Truncated
	// reports that MaxRows stopped the walk before ThroughID / the end.
	VerifyAuditChainSegment(ctx context.Context, seg AuditChainSegment) (*AuditChainVerification, error)
	// MigrateAuditChainEncoding re-derives entry_hash/prev_hash for every chained
	// audit_events row, in ascending id order, under computeAuditEntryHash's
	// current (length-prefixed) encoding — closing the gap left when that
	// encoding replaced the prior NUL-delimited one (a breaking, non-content-
	// preserving hash-format change; see computeAuditEntryHash's doc comment).
	// The unchained legacy prefix (pre-ADR-029 rows with an empty entry_hash) is
	// left untouched.
	//
	// anchor has EXACTLY the same meaning and applicability rule as
	// VerifyAuditChain's own anchor parameter: when non-nil AND the earliest
	// chained row's CURRENTLY STORED prev_hash is not auditGenesisHash (a prior
	// sanctioned retention purge moved the chain start), the walk seeds from
	// anchor.PrevHash instead of genesis. The caller MUST have already
	// authenticated anchor; this layer trusts it literally.
	//
	// Holds the same cross-process exclusivity LogAuditEvent uses (Postgres
	// advisory lock; SQLite's own single-writer semantics) for the ENTIRE
	// migration, in one transaction — not just per batch — so no concurrently
	// appended row can be hashed against a partially-migrated chain. Callers
	// MUST ensure no other process can reach this database's audit_events table
	// for the duration (this transaction only prevents concurrent writes
	// THROUGH this same storage backend's own LogAuditEvent path, not from an
	// entirely separate process/connection pool bypassing it).
	//
	// dryRun computes and returns the same result WITHOUT persisting anything
	// (the transaction is rolled back), so an operator can preview row/anchor
	// counts before committing.
	MigrateAuditChainEncoding(ctx context.Context, dryRun bool, anchor *AuditChainAnchor) (*AuditChainMigrationResult, error)
	// CreateAuditCheckpoint appends a signed checkpoint of the chain head (ADR-029).
	CreateAuditCheckpoint(ctx context.Context, cp *models.AuditCheckpoint) error
	// UpdateAuditCheckpointAnchor stores the external-notary anchor (RFC 3161 token,
	// asserted time, provider) on an existing checkpoint row (ADR-029); the signed
	// fields stay immutable.
	UpdateAuditCheckpointAnchor(ctx context.Context, id uint, token []byte, anchoredAt time.Time, provider string) error
	// LatestAuditCheckpoint returns the most recently written checkpoint, or
	// (nil, nil) when none exists yet.
	LatestAuditCheckpoint(ctx context.Context) (*models.AuditCheckpoint, error)
	// AuditEntryHashByID returns the entry_hash of the audit row with the given
	// id; found is false when no such row exists (e.g. it was truncated away).
	AuditEntryHashByID(ctx context.Context, id uint) (hash string, found bool, err error)
	// GetSystemMetadata returns the value stored for key; found is false when the key
	// has never been set. A small singleton key/value store for server-managed state.
	GetSystemMetadata(ctx context.Context, key string) (value string, found bool, err error)
	// SetSystemMetadata upserts a system-metadata key/value (last write wins).
	SetSystemMetadata(ctx context.Context, key, value string) error
	// GetRecoveryKeyRecord returns the local admin recovery key's verifier
	// record (docs/design-b2-recover-admin.md §2); found is false on an
	// install that predates this feature or has never generated one.
	GetRecoveryKeyRecord(ctx context.Context) (record *models.RecoveryKeyRecord, found bool, err error)
	// SetRecoveryKeyRecord upserts the singleton recovery-key record —
	// generation and rotation are the same call; the caller sets KeyVersion
	// (and RotatedAt on rotation). Exactly one row ever exists.
	SetRecoveryKeyRecord(ctx context.Context, record *models.RecoveryKeyRecord) error
	GetDistinctActiveUserIDs(ctx context.Context, since time.Time) ([]uint, error)
	// CountImpersonatedActions returns the number of impersonated audit events
	// recorded for actingAs by impersonator since `since`, excluding the
	// impersonation.start/impersonation.end markers themselves. Used to report
	// the action count on an impersonation.end event.
	CountImpersonatedActions(ctx context.Context, actingAs, impersonator uint, since time.Time) (int64, error)

	// Session Management
	CreateSession(ctx context.Context, session *models.Session) (*models.Session, error)
	// GetSession looks up a LIVE (not-yet-rotated) session by token. A token
	// belonging to a session RefreshSession has since rotated away must behave
	// exactly like a deleted one here (see RotatedAt on models.Session) — used on
	// every authenticated request and on Logout.
	GetSession(ctx context.Context, token string) (*models.Session, error)
	// GetSessionAny looks up a session by token regardless of rotation state.
	// Used only by RefreshSession's reuse-detection path (#211), which must tell an
	// already-rotated token (a reuse signal) apart from one that never existed.
	GetSessionAny(ctx context.Context, token string) (*models.Session, error)
	GetSessionByID(ctx context.Context, id uint) (*models.Session, error)
	// GetSessionAuthLiveness is GetUser(userID) plus GetSessionByID(sessionID)
	// in ONE statement (PERF-FIX-7, collapse C6): the HTTP auth middleware's
	// session cache-hit check reads the owning account's state and the session
	// row from one snapshot. Each half reports what its per-statement method
	// would have (see SessionAuthLiveness); a failure of the combined statement
	// is answered through those methods (ComposeSessionAuthLiveness).
	GetSessionAuthLiveness(ctx context.Context, userID, sessionID uint) (*SessionAuthLiveness, error)
	ListSessionsByUser(ctx context.Context, userID uint) ([]*models.Session, error)
	// EnforceSessionLimit deletes a user's oldest sessions beyond the `keep` most-recent
	// (by created_at), bounding concurrent sessions per user. No-op when under the cap.
	EnforceSessionLimit(ctx context.Context, userID uint, keep int) error
	DeleteSession(ctx context.Context, id uint) error
	// DeleteSessionsForUserExcept removes every session owned by userID except the
	// one with id exceptID. Used to drop other sessions on a password change.
	DeleteSessionsForUserExcept(ctx context.Context, userID, exceptID uint) error
	// ListSessionTokenHashesForUser returns the stored session_token values (SHA-256
	// hashes — equal to the auth-cache key) for every session owned by or impersonating
	// userID, so a state change can evict them from the auth cache immediately.
	ListSessionTokenHashesForUser(ctx context.Context, userID uint) ([]string, error)
	// RotateSession atomically supersedes the session at oldID with newSession inside
	// a single DB transaction (#211): the CAS guard (rotated_at IS NULL) makes
	// rotation race-free under concurrent refreshes of the same token — at most one
	// caller wins (won=true). The loser must treat the loss as a reuse signal exactly
	// like an out-of-band replay of an already-rotated token.
	RotateSession(ctx context.Context, oldID uint, newSession *models.Session, now time.Time) (created *models.Session, won bool, err error)
	// ListSessionTokenHashesByFamily / DeleteSessionsByFamily revoke every session
	// descended from the same login (see FamilyID on models.Session) — used to kill
	// the whole lineage when a refresh-token reuse is detected (#211).
	ListSessionTokenHashesByFamily(ctx context.Context, familyID string) ([]string, error)
	DeleteSessionsByFamily(ctx context.Context, familyID string) error
	// TouchSession bumps last_seen_at only when it is older than the given staleness
	// window (no-op otherwise) so the auth hot path is not turned into a write per request.
	TouchSession(ctx context.Context, id uint, seenAt time.Time, staleness time.Duration) error
	CleanupExpiredSessions(ctx context.Context) error

	// MFA / TOTP (per-user two-factor authentication).
	UpsertMFASecret(ctx context.Context, s *models.MFASecret) error
	GetMFASecret(ctx context.Context, userID uint) (*models.MFASecret, error)
	// ActivateMFASecret marks userID's TOTP secret activated only if its stored
	// ciphertext still equals secretEnc, the row ActivateMFA validated the code
	// against (#2655). matched=false means a concurrent BeginMFAEnrollment
	// replaced the secret in between; nothing was written and the caller must
	// fail closed rather than activate a secret no code was checked against.
	ActivateMFASecret(ctx context.Context, userID uint, secretEnc []byte) (matched bool, err error)
	// MarkTOTPStepUsed atomically records that the given TOTP time-step was accepted for
	// userID, returning true only if it was newly consumed (step strictly greater than
	// the stored last-used step). A false return means the code is a replay.
	MarkTOTPStepUsed(ctx context.Context, userID uint, step int64) (bool, error)
	// ReleaseTOTPStepIfUnchanged reverts a step MarkTOTPStepUsed just marked as
	// used back to step-1 (re-permitting exactly that step), but ONLY if the
	// stored last-used step still equals step unchanged since the mark — a CAS
	// guard so this never regresses the anti-replay counter past a step some
	// OTHER, later-arriving request has since legitimately advanced it to.
	// Returns false (no error) when the CAS didn't match (nothing released).
	// Exists for #2567: a caller that marked a step used and then failed to
	// complete the side effect that depended on it (minting a session) can
	// give the user back their one attempt at that same code, instead of
	// forcing a wait for the next 30s time-step over a storage hiccup that had
	// nothing to do with the code itself.
	ReleaseTOTPStepIfUnchanged(ctx context.Context, userID uint, step int64) (bool, error)
	DeleteMFAForUser(ctx context.Context, userID uint) error // clears secret + recovery codes
	SetUserMFAEnabled(ctx context.Context, userID uint, enabled bool) error
	CreateMFARecoveryCodes(ctx context.Context, userID uint, codeHashes []string) error
	// ConsumeMFARecoveryCode marks a matching unused code used and reports whether one was consumed.
	ConsumeMFARecoveryCode(ctx context.Context, userID uint, codeHash string, now time.Time) (bool, error)
	// CountUnusedMFARecoveryCodes returns how many of the user's recovery codes remain unused.
	CountUnusedMFARecoveryCodes(ctx context.Context, userID uint) (int, error)
	// DeleteMFARecoveryCodes removes all of the user's recovery codes (the regenerate flow replaces them).
	DeleteMFARecoveryCodes(ctx context.Context, userID uint) error
	// Dynamic secrets (ADR-035).
	CreateDynamicSecretConfig(ctx context.Context, c *models.DynamicSecretConfig) (*models.DynamicSecretConfig, error)
	GetDynamicSecretConfig(ctx context.Context, id uint) (*models.DynamicSecretConfig, error)
	ListDynamicSecretConfigs(ctx context.Context, projectID, environmentID uint) ([]*models.DynamicSecretConfig, error)
	UpdateDynamicSecretConfig(ctx context.Context, c *models.DynamicSecretConfig) error
	// SetDynamicSecretConfigAdminDSN writes ONLY a config's encrypted admin DSN
	// (admin_dsn_enc, admin_dsn_meta) and updated_at, never the rest of the row
	// (#2651). CreateDynamicSecretConfig's second write used UpdateDynamicSecretConfig
	// (a full-row Save) and wrote disabled=false back over a concurrent DeleteProject's
	// #369 disable. Returns an error when no row matched.
	SetDynamicSecretConfigAdminDSN(ctx context.Context, id uint, enc, meta []byte) error
	// SetDynamicSecretConfigClassification persists ONLY the classification
	// column (plus updated_at), and only if the row's CURRENT classification is
	// still fromClassification (the value the caller read). matched=false (no
	// error) means another classifier moved it; the caller must fail closed.
	//
	// ClassifyDynamicSecretConfig used the full-row UpdateDynamicSecretConfig
	// (a bare Save) and therefore wrote `disabled=false` back over a concurrent
	// SetDynamicSecretConfigEnabled(false) — the incident kill switch, which
	// also revokes the config's live leases — so IssueLease could mint real
	// database credentials again, with an audit trail reading "config_disabled"
	// then only "classified" and nothing recording the re-enable (#2698). The
	// same column is what DeleteProject's #369 cascade sets, so the same write
	// also re-enabled a config under a deleted project.
	SetDynamicSecretConfigClassification(ctx context.Context, id uint, fromClassification, toClassification string, updatedAt time.Time) (matched bool, err error)
	// TransitionDynamicSecretConfigDisabled persists cfg's full row via a single
	// conditional write — "UPDATE ... WHERE id = ? AND disabled = ?" — succeeding
	// only if the row's CURRENT persisted disabled value still equals fromDisabled
	// (the value SetDynamicSecretConfigEnabled observed via GetDynamicSecretConfig
	// immediately before mutating cfg.Disabled in memory), mirroring
	// UpdateProjectInvitation's `WHERE id = ? AND state = 'pending'` pattern (#412)
	// and TransitionMachineIdentityState's `WHERE id = ? AND state = ?` pattern
	// (#388/#518) exactly, just gated on DynamicSecretConfig.Disabled instead of a
	// string state column. Returns whether the write actually matched a row.
	//
	// This exists for the same reason TransitionMachineIdentityState does: the
	// now-deleted RemoteStorage's WithTransaction was a no-op passthrough, so a
	// plain GetDynamicSecretConfig-then-UpdateDynamicSecretConfig sequence — the
	// shape SetDynamicSecretConfigEnabled used before this fix — had no atomicity
	// at all against it: two racing callers (e.g. one admin enabling while another
	// is mid-disable, or an unrelated concurrent edit landing between the read and
	// the write) could silently clobber each other's change, or clobber an
	// unrelated field mutated by the other racer, with no error surfaced. Routing
	// the actual write through this one conditional round trip instead of a
	// separate proxied Update restores the same guarantee LocalStorage's
	// conditional UPDATE already provides, without making any enable/disable
	// decision here: the caller (core.SetDynamicSecretConfigEnabled) still decides
	// the target Disabled value before calling this; a false match result must be
	// treated as a lost race, not retried or silently overwritten.
	TransitionDynamicSecretConfigDisabled(ctx context.Context, cfg *models.DynamicSecretConfig, fromDisabled bool) (bool, error)
	// CountDynamicSecretConfigsByClassification returns install-wide config counts
	// keyed by classification label ("" = unclassified) for the compliance posture.
	CountDynamicSecretConfigsByClassification(ctx context.Context) (map[string]int, error)
	CreateDynamicSecretLease(ctx context.Context, l *models.DynamicSecretLease) (*models.DynamicSecretLease, error)
	GetDynamicSecretLease(ctx context.Context, leaseID string) (*models.DynamicSecretLease, error)
	ListDynamicSecretLeases(ctx context.Context, configID uint) ([]*models.DynamicSecretLease, error)
	// CountActiveLeases returns how many leases from configID still hold a live
	// credential upstream — "active" AND "revoke_failed" (#411: a revoke_failed
	// lease's earlier revoke attempt failed on the target, so the credential is
	// still live) — used to enforce the config's MaxActiveLeases ceiling.
	CountActiveLeases(ctx context.Context, configID uint) (int64, error)
	UpdateDynamicSecretLease(ctx context.Context, l *models.DynamicSecretLease) error
	// ExtendDynamicSecretLeaseExpiry persists ONLY expires_at, and only for a
	// lease whose status is STILL "active": "UPDATE ... SET expires_at WHERE
	// lease_id = ? AND status = 'active'". matched=false (no error) means the
	// lease is no longer active (revoked, expired, or revoke_failed) and the
	// renewal must be refused.
	//
	// RenewLease used the full-row UpdateDynamicSecretLease (a bare Save) and
	// therefore wrote the stale Status/RevokeError/RevokedAt back (#2698): a
	// concurrent successful RevokeLease became `active` again with a LATER
	// expiry, so the row lied about a dead credential and kept holding a
	// MaxActiveLeases slot until the sweep; a revoke that had recorded
	// `revoke_failed` was erased outright, its error cleared. Renew is a no-op
	// on several backends, so nothing downstream would have noticed.
	ExtendDynamicSecretLeaseExpiry(ctx context.Context, leaseID string, newExpiry time.Time) (matched bool, err error)
	// RecordDynamicSecretLeaseRevocation persists ONLY status, revoke_reason,
	// revoke_error and revoked_at. Deliberately NOT conditional on the current
	// status: it records what already happened to the credential at the
	// backend, so it must land regardless of what else moved meanwhile — a
	// lease whose target drop failed must never be left reading `active`.
	// What it must not do is carry the caller's whole pre-read row with it.
	RecordDynamicSecretLeaseRevocation(ctx context.Context, leaseID, status, revokeReason, revokeError string, revokedAt *time.Time) (matched bool, err error)
	ListExpiredActiveLeases(ctx context.Context, before time.Time) ([]*models.DynamicSecretLease, error)

	CreateMFAChallenge(ctx context.Context, c *models.MFAChallenge) error
	// ConsumeMFAChallenge atomically finds an unused, unexpired challenge by token
	// hash, marks it used, and returns it (or an error if none).
	ConsumeMFAChallenge(ctx context.Context, tokenHash string, now time.Time) (*models.MFAChallenge, error)
	// GetActiveMFAChallenge finds an unused, unexpired challenge by token hash
	// WITHOUT consuming it (used to resolve the user at WebAuthn login-begin; the
	// challenge is consumed later, atomically, at login-finish).
	GetActiveMFAChallenge(ctx context.Context, tokenHash string, now time.Time) (*models.MFAChallenge, error)

	// UpsertMFAStepupToken records (or refreshes) the MFA step-up window for
	// userID. expiresAt is set by the caller (core) from the configured window. One
	// row per user; the previous row is replaced on re-verification so re-login
	// extends the window cleanly. (The now-deleted RemoteStorage implemented this
	// as an intentional no-op stub — the step-up token was always created and
	// checked server-side.)
	UpsertMFAStepupToken(ctx context.Context, userID uint, expiresAt time.Time) error
	// HasActiveMFAStepup reports whether userID has a non-expired MFA step-up
	// record, confirming a recent second-factor verification.
	HasActiveMFAStepup(ctx context.Context, userID uint) (bool, error)

	// CreateMFAStepUpGrant persists a new MFA step-up grant for userID. The
	// grant's Purpose field must be set by the caller (core) — it is what
	// GetActiveMFAStepUpGrant matches on, so a grant minted for one purpose can
	// never be misread as authorizing a different one.
	CreateMFAStepUpGrant(ctx context.Context, grant *models.MFAStepUpGrant) error
	// GetActiveMFAStepUpGrant returns the most recent non-expired MFA step-up
	// grant for userID AND purpose as of now, or (nil, nil) when none exists.
	// purpose is a required exact match, not a filter of convenience: a grant
	// minted for models.MFAStepUpPurposeRestrictedSecretRead must never satisfy
	// a query for models.MFAStepUpPurposeReauth or vice versa.
	GetActiveMFAStepUpGrant(ctx context.Context, userID uint, purpose models.MFAStepUpPurpose, now time.Time) (*models.MFAStepUpGrant, error)
	// ConsumeMFAStepUpGrant atomically marks every live (unconsumed, unexpired)
	// grant for (userID, purpose) as consumed and reports whether any were
	// found — the single-use variant of GetActiveMFAStepUpGrant, mirroring
	// ConsumeMFARecoveryCode/ConsumeWebAuthnSession's conditional-UPDATE shape
	// (no read-then-write race: two near-simultaneous callers racing the same
	// live grant can never both observe consumed=true). requireReauth is the
	// sole intended caller, and only for models.MFAStepUpPurposeReauth — that
	// purpose must be single-use-per-action (one re-auth proof must not
	// authorize disabling MFA, deleting a WebAuthn credential, regenerating
	// recovery codes, AND changing the account email all from the same proof).
	// models.MFAStepUpPurposeRestrictedSecretRead grants are deliberately never
	// passed here; they stay multi-use for the window's duration via the
	// non-consuming GetActiveMFAStepUpGrant/HasActiveMFAStepUp.
	ConsumeMFAStepUpGrant(ctx context.Context, userID uint, purpose models.MFAStepUpPurpose, now time.Time) (bool, error)
	// DeleteMFAStepUpGrantsFor removes all step-up grants for userID (used on
	// session revocation or security-incident response).
	DeleteMFAStepUpGrantsFor(ctx context.Context, userID uint) error
	// PruneMFAStepUpGrants removes MFAStepUpGrant rows whose ExpiresAt predates
	// `before`, returning how many were removed (store-mfa-002: each successful
	// VerifyMFAStepUp creates a new grant row, kept briefly past its own expiry
	// for audit purposes — see internal/storage/store/local_mfa_stepup_grant.go
	// — but with no bound this grows without limit). The sole intended caller is
	// internal/core.KeyorixCore.PruneMFAStepUpGrants, which computes and clamps
	// the cutoff; callers should not invoke this directly with an
	// externally-influenced `before`.
	PruneMFAStepUpGrants(ctx context.Context, before time.Time) (int64, error)

	// WebAuthn / passkeys (ADR-036).
	CreateWebAuthnCredential(ctx context.Context, c *models.WebAuthnCredential) error
	ListWebAuthnCredentials(ctx context.Context, userID uint) ([]*models.WebAuthnCredential, error)
	// GetWebAuthnCredentialByCredID looks up a credential by its (unique) credential
	// ID, scoped to the claimed owner: the query itself requires user_id = userID, so
	// correctness does not depend on every caller re-checking ownership after the
	// fetch (#307).
	GetWebAuthnCredentialByCredID(ctx context.Context, credentialID []byte, userID uint) (*models.WebAuthnCredential, error)
	// LockWebAuthnCredentialForUpdate re-reads a WebAuthn credential by (credential_id,
	// user_id), taking a row-level write lock on backends that support one
	// (Postgres: SELECT … FOR UPDATE). This is now an ORDINARY (non-atomic) read
	// primitive: it and UpdateWebAuthnCredential remain for callers that read/write a
	// credential outside the signature-counter race (e.g. a plain lookup, or
	// rejectIfCloned's best-effort "mark disabled" write, whose worst outcome under a
	// lost race is a harmless redundant write, not a security regression). The
	// counter-advance path that USED to compose these two into a single
	// WithTransaction call (closing the cloned-authenticator race, #306) now goes
	// through AdvanceWebAuthnCredentialCounter below instead, which performs the
	// lock+compare+write as ONE atomic storage-layer call — required because the
	// now-deleted RemoteStorage's WithTransaction was a no-op passthrough:
	// composing LockWebAuthnCredentialForUpdate + UpdateWebAuthnCredential as two
	// separate remote calls would have reopened the exact TOCTOU race the
	// transaction was built to prevent.
	LockWebAuthnCredentialForUpdate(ctx context.Context, credentialID []byte, userID uint) (*models.WebAuthnCredential, error)
	// DisableWebAuthnCredential sets ONLY `disabled = true` on an EXISTING
	// credential row, returning matched=false when the row is gone.
	// SetWebAuthnCredentialCounterState persists ONLY the signature-counter blob
	// and last_used_at.
	//
	// Together they REPLACE the former UpdateWebAuthnCredential, a bare GORM Save
	// (#2700). WebAuthnCredential is HARD-deleted (no DeletedAt), so Save's
	// 0-rows fallback — `INSERT ... ON CONFLICT (id) DO UPDATE` — re-inserted a
	// passkey the user had just deleted. It came back with Disabled=true, so it
	// fails closed for authentication; what it corrupts is the credential count
	// and the webauthn_enabled bookkeeping derived from it. Low severity, and
	// deliberately described as such.
	DisableWebAuthnCredential(ctx context.Context, id uint) (matched bool, err error)
	SetWebAuthnCredentialCounterState(ctx context.Context, id uint, blob []byte, lastUsedAt time.Time) (matched bool, err error)
	// AdvanceWebAuthnCredentialCounter conditionally persists an advanced signature
	// counter (newBlob/newSignCount) and lastUsedAt for the credential identified by
	// (credentialID, userID), IFF newSignCount is not stale relative to whatever
	// counter is CURRENTLY persisted — the single atomic primitive
	// persistUpdatedCredential (internal/core/webauthn.go) is built on to close the
	// cloned-authenticator race (#306/#517): two concurrent logins asserting the same
	// credential must never let the loser's stale, lower counter clobber the
	// winner's already-persisted higher one. "Not stale" mirrors go-webauthn's own
	// Authenticator.UpdateCounter gate exactly: a (0, 0) comparison (many platform
	// authenticators never implement a counter and always report 0) is never
	// stale — only reject when at least one side is nonzero and newSignCount fails to
	// strictly exceed the row's current stored count.
	//
	// LocalStorage implements this as a single row-locked transaction — the exact
	// Lock+compare+Update sequence persistUpdatedCredential used to run inline,
	// moved down into this one storage-layer call. (The now-deleted RemoteStorage
	// implemented it as ONE HTTP call whose server-side handler performed the
	// identical locked compare-and-swap against its own storage, since its
	// WithTransaction could not provide client-side atomicity at all.)
	//
	// Returns advanced=false, err=nil (not an error) when the write was skipped as
	// stale — a benign, expected outcome of losing a race, not a failure — mirroring
	// persistUpdatedCredential's pre-existing best-effort semantics (a write failure
	// here must never fail an otherwise-valid login). err is reserved for a genuine
	// storage-layer failure (e.g. the credential row doesn't exist).
	AdvanceWebAuthnCredentialCounter(ctx context.Context, credentialID []byte, userID uint, newBlob []byte, newSignCount uint32, lastUsedAt time.Time) (advanced bool, err error)
	DeleteWebAuthnCredential(ctx context.Context, userID, id uint) error
	CountWebAuthnCredentials(ctx context.Context, userID uint) (int64, error)
	SetUserWebAuthnEnabled(ctx context.Context, userID uint, enabled bool) error
	CreateWebAuthnSession(ctx context.Context, s *models.WebAuthnSession) error
	// ConsumeWebAuthnSession atomically finds an unused, unexpired ceremony session
	// by token hash, marks it used, and returns it (or an error if none).
	ConsumeWebAuthnSession(ctx context.Context, tokenHash string, now time.Time) (*models.WebAuthnSession, error)

	// Personal Access Token Management (ADR-027) — user-owned bearer credentials.
	CreatePersonalAccessToken(ctx context.Context, t *models.PersonalAccessToken) (*models.PersonalAccessToken, error)
	ListPersonalAccessTokensByUser(ctx context.Context, userID uint) ([]*models.PersonalAccessToken, error)
	// ListActivePersonalAccessTokens returns every non-revoked PAT across all users —
	// the deployment-wide view for token-hygiene auditing (stale / expired-but-active).
	ListActivePersonalAccessTokens(ctx context.Context) ([]*models.PersonalAccessToken, error)
	GetPersonalAccessTokenByID(ctx context.Context, id uint) (*models.PersonalAccessToken, error)
	GetPersonalAccessTokenByHash(ctx context.Context, hash string) (*models.PersonalAccessToken, error)
	RevokePersonalAccessToken(ctx context.Context, id uint) error
	// RevokeAllPersonalAccessTokensForUser revokes every active PAT for a user and returns
	// their token hashes (for immediate auth-cache eviction). Used on a password change/
	// reset so PATs die with the password.
	RevokeAllPersonalAccessTokensForUser(ctx context.Context, userID uint) ([]string, error)
	TouchPersonalAccessToken(ctx context.Context, id uint, usedAt time.Time, staleness time.Duration) error
	// ListExpiredPATsByUser returns all non-revoked PATs for userID whose ExpiresAt
	// is in the past (expired but never explicitly revoked). Ordered newest first.
	ListExpiredPATsByUser(ctx context.Context, userID uint, now time.Time) ([]*models.PersonalAccessToken, error)
	// BulkRevokeExpiredPATsByUser revokes every non-revoked, expired PAT belonging to
	// userID (ExpiresAt < now) and returns their token hashes for cache eviction.
	BulkRevokeExpiredPATsByUser(ctx context.Context, userID uint, now time.Time) ([]string, error)
	// ListExpiringPATs returns every non-revoked PersonalAccessToken whose ExpiresAt
	// is non-nil and strictly before before (i.e. will expire before that instant).
	// Used by CheckTokenExpiry to find tokens approaching their deadline.
	ListExpiringPATs(ctx context.Context, before time.Time) ([]models.PersonalAccessToken, error)

	// Setup Token Management (ADR-028) — single-use, hashed-at-rest credential-delivery tokens.
	CreateSetupToken(ctx context.Context, t *models.SetupToken) (*models.SetupToken, error)
	// GetSetupTokenByHash is the consumption lookup (indexed equality on token_hash).
	GetSetupTokenByHash(ctx context.Context, hash string) (*models.SetupToken, error)
	// GetSetupTokenByID looks up a setup token by primary key. Only ever called
	// from KeyorixCore.ExpireSetupTokenByID (#1622) to resolve purpose/subject
	// detail for an explicit (non-lazy-read) expiry's audit write --
	// ExpireSetupTokenByID's own doc has more on why that method (and so this
	// one) has zero production callers today.
	GetSetupTokenByID(ctx context.Context, id uint) (*models.SetupToken, error)
	// SupersedeActiveSetupTokens flips every active token for (purpose, email) to
	// superseded, so reissuing ("resend") atomically kills the prior link.
	// projectID, when non-nil, additionally restricts the flip to tokens whose
	// InvitationID belongs to that project (via project_invitations) — so a
	// project-scoped invitation_accept reissue only supersedes that SAME project's
	// pending invite to the address, not an unrelated project's (CORE-INVITATIONS-003).
	// A nil projectID preserves the original (purpose, email)-only scope, which
	// callers with no project dimension (global invites, account_setup,
	// password_reset_link) still rely on.
	SupersedeActiveSetupTokens(ctx context.Context, purpose, email string, projectID *uint) error
	// MarkSetupTokenConsumed transitions active → consumed only if the token is still
	// active, stamping consumedAt. It reports whether the transition happened, so a
	// concurrent replay (state already consumed/expired/superseded) is rejected.
	MarkSetupTokenConsumed(ctx context.Context, id uint, consumedAt time.Time) (bool, error)
	// MarkSetupTokenExpired transitions active → expired (lazy expiry on read).
	MarkSetupTokenExpired(ctx context.Context, id uint) error
	// CountSetupTokensSince counts tokens minted for (purpose, email) since a cutoff,
	// backing resend throttling / daily caps.
	CountSetupTokensSince(ctx context.Context, purpose, email string, since time.Time) (int64, error)

	// Rotation Policy Management
	CreateRotationPolicy(ctx context.Context, p *models.RotationPolicy) error
	GetRotationPolicy(ctx context.Context, id uint) (*models.RotationPolicy, error)
	// GetRotationPolicyBySecret returns the first active rotation policy that covers
	// the secret (by matching the secret's project_id and/or environment_id). Returns
	// ErrNotFound (via the store package) when no policy exists for the secret.
	GetRotationPolicyBySecret(ctx context.Context, secretID uint) (*models.RotationPolicy, error)
	ListRotationPolicies(ctx context.Context, projectID *uint, environmentID *uint) ([]*models.RotationPolicy, error)
	// UpdateRotationPolicyFields persists ONLY the six operator-editable columns
	// named by f (plus updated_at), onto a LIVE policy row. matched=false (no
	// error) means the policy is gone; the caller must not report success.
	//
	// This REPLACES the former UpdateRotationPolicy, a bare GORM Save (#2700),
	// which got two things wrong at once. RotationPolicy IS soft-deletable, so
	// the 0-rows upsert fallback wrote deleted_at = NULL and a stale edit brought
	// a deleted policy back ACTIVE — resuming rotation and breach alerts although
	// the delete had reported success. And the full-row write reverted
	// rotation_state / last_rotation_error / last_state_at, which belong to
	// UpdateRotationState (the executor), hiding a failed rotation; those three
	// columns are deliberately absent from this method.
	UpdateRotationPolicyFields(ctx context.Context, id uint, f RotationPolicyFieldUpdate, updatedAt time.Time) (matched bool, err error)
	DeleteRotationPolicy(ctx context.Context, id uint) error
	// UpdateRotationState stamps the execution state on a RotationPolicy row.
	// state must be one of: idle, pending, rotating, succeeded, failed.
	UpdateRotationState(ctx context.Context, policyID uint, state, errMsg string) error

	// Health and Maintenance
	HealthCheck(ctx context.Context) error
	GetStats(ctx context.Context) (*StorageStats, error)

	// GetProjectUsageStats returns per-project usage stats for the given projects
	// over the past windowDays days. Passing nil for projectIDs returns stats for
	// ALL projects. The result may omit projects with zero activity and zero secrets.
	GetProjectUsageStats(ctx context.Context, projectIDs []uint, windowDays int) ([]ProjectUsageStat, error)

	// GetBillingReport returns per-project usage stats for the half-open interval [from, to).
	// If projectIDs is non-empty, only those projects are included; otherwise all projects
	// with any activity in the window (or existing secrets) are included.
	GetBillingReport(ctx context.Context, from, to time.Time, projectIDs []uint) (*BillingReport, error)

	// Secret version comments — free-text annotations on a specific secret version,
	// providing a human-readable audit trail of why a version was created or changed.
	// List/Delete are scoped by secretID/versionID (not just the comment's own primary
	// key) so a caller authorized on one secret cannot reach another's comments (#G53).
	CreateSecretVersionComment(ctx context.Context, c *models.SecretVersionComment) error
	ListSecretVersionComments(ctx context.Context, secretID, versionID uint) ([]models.SecretVersionComment, error)
	DeleteSecretVersionComment(ctx context.Context, secretID, versionID, id uint) error

	// Notification channel management — runtime-managed outbound destinations
	// (webhook/slack/teams/email). The REST API is the remote surface; these
	// methods only run server-side via LocalStorage.
	ListNotificationChannels(ctx context.Context) ([]*models.NotificationChannel, error)
	GetNotificationChannel(ctx context.Context, id uint) (*models.NotificationChannel, error)
	GetNotificationChannelByName(ctx context.Context, name string) (*models.NotificationChannel, error)
	CreateNotificationChannel(ctx context.Context, ch *models.NotificationChannel) error
	UpdateNotificationChannel(ctx context.Context, ch *models.NotificationChannel) error
	DeleteNotificationChannel(ctx context.Context, id uint) error
	// UpdateNotificationRetryPolicy updates the retry fields on a NotificationChannel row.
	UpdateNotificationRetryPolicy(ctx context.Context, channelID uint, maxRetries, backoffMs int) error

	// Rejection reason templates — pre-defined reasons for rejecting access
	// requests. The REST API is the remote surface; these methods only run
	// server-side via LocalStorage.
	CreateRejectionReasonTemplate(ctx context.Context, t *models.RejectionReasonTemplate) error
	ListRejectionReasonTemplates(ctx context.Context) ([]models.RejectionReasonTemplate, error)
	DeleteRejectionReasonTemplate(ctx context.Context, id uint) error

	// ListAccessRequestsByIDs returns the access requests matching the given IDs.
	// Used by the bulk-approve/reject operations to pre-fetch all requests in one
	// query and provide per-item errors without N individual GetAccessRequest calls.
	ListAccessRequestsByIDs(ctx context.Context, ids []uint) ([]*models.AccessRequest, error)

	// Secret Template Management — reusable metadata presets for secret creation.
	// Templates pre-fill classification, tags, and description hints at create time.
	CreateSecretTemplate(ctx context.Context, t *models.SecretTemplate) error
	GetSecretTemplate(ctx context.Context, id uint) (*models.SecretTemplate, error)
	GetSecretTemplateByName(ctx context.Context, name string) (*models.SecretTemplate, error)
	ListSecretTemplates(ctx context.Context) ([]*models.SecretTemplate, error)
	// UpdateSecretTemplateFields persists ONLY the six editable columns named by
	// f (plus updated_at) of an EXISTING template row. matched=false means the
	// template is gone.
	//
	// This REPLACES the former UpdateSecretTemplate, a bare GORM Save (#2700).
	// SecretTemplate is HARD-deleted (no DeletedAt), so Save's 0-rows fallback
	// re-INSERTED a template a concurrent delete had removed, with its old id.
	// Integrity only — a template mints nothing by itself — and low severity,
	// stated as such.
	UpdateSecretTemplateFields(ctx context.Context, id uint, f SecretTemplateFieldUpdate, updatedAt time.Time) (matched bool, err error)
	DeleteSecretTemplate(ctx context.Context, id uint) error

	// AlertEscalationPolicy CRUD
	CreateAlertEscalationPolicy(ctx context.Context, p *models.AlertEscalationPolicy) error
	GetAlertEscalationPolicy(ctx context.Context, id uint) (*models.AlertEscalationPolicy, error)
	ListAlertEscalationPolicies(ctx context.Context) ([]models.AlertEscalationPolicy, error)
	UpdateAlertEscalationPolicy(ctx context.Context, p *models.AlertEscalationPolicy) error
	DeleteAlertEscalationPolicy(ctx context.Context, id uint) error

	// ListUnacknowledgedAnomalyAlertsBefore returns unacknowledged anomaly alerts
	// whose created_at (detected_at) is older than the given threshold.
	ListUnacknowledgedAnomalyAlertsBefore(ctx context.Context, threshold time.Time) ([]models.AnomalyAlert, error)
}

// RotationPolicyFieldUpdate is the set of columns an operator edit of a rotation
// policy owns (#2700). Every field is written, because core.UpdateRotationPolicy
// requires all six on its request — unlike SecretFieldUpdate there is no
// "leave this one alone" case to express. What matters is which columns are NOT
// here: rotation_state, last_rotation_error and last_state_at belong to the
// executor (UpdateRotationState), and a policy edit used to revert them.
type RotationPolicyFieldUpdate struct {
	Name            string
	Description     string
	IntervalDays    int
	AlertDaysBefore int
	NotifyOnBreach  bool
	IsActive        bool
}

// SecretTemplateFieldUpdate is the set of columns an edit of a secret template
// owns (#2700). Same reasoning as RotationPolicyFieldUpdate: all six come from
// the request, and the point is the exclusion of created_by/created_at.
type SecretTemplateFieldUpdate struct {
	Name                  string
	Description           string
	DefaultClassification string
	DefaultTags           string
	DescriptionPattern    string
	RotationHintDays      int
}

// SecretFieldUpdate names the secret_nodes columns one operation owns, for
// UpdateSecretFields. A nil pointer means "do not write this column at all" —
// which is the whole point: it replaced a full-row GORM Save whose eight
// callers each silently reverted every column the others owned (#2695).
//
// The union of fields here is exactly what those callers legitimately change,
// and nothing more. Columns deliberately ABSENT, because no caller of this
// method owns them and a full-row write was how they got clobbered:
// `deleted_at` (DeleteSecret / RestoreSecret), `status` (TransitionSecretStatus),
// `read_count` (TryIncrementSecretNodeReadCount — a MaxReads budget),
// `auto_rotate` and the other rotation columns (UpdateSecretRotationConfig),
// `project_id` / `environment_id` / `is_secret`, and the certificate cache.
// Adding a field here is a decision about which operation may revert which
// other operation, not a mechanical convenience — say why in the commit.
//
// The four nullable columns use an explicit Set* flag rather than relying on a
// nil pointer, so "clear this column" is distinguishable from "leave it alone"
// and reads as the deliberate act it is at the call site.
type SecretFieldUpdate struct {
	Name           *string
	Description    *string
	Classification *string
	Type           *string
	OwnerID        *uint
	Metadata       *models.JSON
	UpdatedAt      *time.Time

	SetParentID bool
	ParentID    *uint // nil + SetParentID = move to root

	SetExpiration bool
	Expiration    *time.Time // nil + SetExpiration = clear the expiry

	SetMaxReads bool
	MaxReads    *int // nil + SetMaxReads = clear the read cap

	SetLastRotatedAt bool
	LastRotatedAt    *time.Time
}

// SecretFilter defines filtering options for secret queries
type SecretFilter struct {
	ProjectID     *uint
	EnvironmentID *uint
	Type          *string
	Tags          []string
	CreatedBy     *string
	// OwnerID, when set, restricts to secrets owned by that user (owner_id) — the
	// canonical ownership the permission model uses (CheckSecretPermission), as
	// opposed to the mutable created_by username string.
	OwnerID       *uint
	CreatedAfter  *time.Time
	CreatedBefore *time.Time
	// ExpiresBefore, when set, restricts to secrets with a non-null expiration
	// earlier than the given time (i.e. already expired or expiring before it).
	ExpiresBefore *time.Time
	// Classification, when set, restricts to secrets with that data-classification
	// label (A.5.12). Use the sentinel "unclassified" to match the empty label.
	Classification *string
	// ParentID, when set, restricts to secrets whose parent_id equals the given
	// value. Use to list the direct children of a folder node.
	ParentID *uint
	// Search, when set, restricts to secrets whose name contains the given
	// substring (case-insensitive). Uses LOWER/LIKE so it works on both SQLite
	// and PostgreSQL.
	Search *string
	// FolderOnly, when true, restricts to folder nodes (is_secret=false). Mutually
	// exclusive with listing only real secrets — callers set one or the other.
	FolderOnly bool
	Page       int
	PageSize   int
	// IncludeDeleted, when true, also returns soft-deleted secrets (ADR-033) —
	// for a restore UI. Default false: GORM auto-scopes deleted_at IS NULL.
	IncludeDeleted bool
	// DeletedOnly, when true, returns ONLY soft-deleted secrets (deleted_at IS NOT
	// NULL) — the recycle-bin / restore view. Implies reaching past GORM's
	// soft-delete scope. Takes precedence over IncludeDeleted.
	DeletedOnly bool
	// IsSecret, when set, restricts to nodes matching the given value:
	// true = actual secrets only, false = folder nodes only.
	// When nil, both secrets and folders are returned.
	IsSecret *bool
}

// PrincipalPermission is ResolveUserPermissionAt's / ResolveMachinePermissionAt's
// result. RoleIDs is the de-duplicated role set that applies at the scope (the
// set core's scopedRoleIDs / GetMachineRoleIDsAt returned; order unspecified).
// BypassesPermissionChecks reports whether any of them carries the ADR-084
// flag (users only). HasPermission is RoleSetHasPermission(RoleIDs, permission),
// resolved only when RoleIDs is non-empty and does not bypass.
type PrincipalPermission struct {
	RoleIDs                  []uint
	BypassesPermissionChecks bool
	HasPermission            bool
}

// SecretScheduleAndLatestVersion is GetSecretScheduleAndLatestVersion's result.
// Schedule is nil when the secret has no access schedule (no restriction, as
// GetSecretAccessSchedule's nil, nil). Exactly one of LatestVersion and
// LatestVersionErr is set; LatestVersionErr is the error GetLatestSecretVersion
// would have returned (wrapping ErrSecretVersionNotFound when there is none).
type SecretScheduleAndLatestVersion struct {
	Schedule         *models.SecretAccessSchedule
	LatestVersion    *models.SecretVersion
	LatestVersionErr error
}

// DriftSecretRow is one secret's drift-relevant projection: which environment it
// lives in, its name (the cross-environment key), its type, and whether it has
// an expiration / max-reads cap set. Used to build the per-key × per-environment
// presence matrix for cross-environment drift detection.
type DriftSecretRow struct {
	EnvironmentID uint
	Name          string
	Type          string
	HasExpiration bool
	HasMaxReads   bool
}

// SecretNameRow is one live secret's naming-conformance-relevant projection plus its
// project ID — the row shape ListLiveSecretNamesByProject returns for the
// deployment-wide naming-policy conformance scan (#416). Mirrors the fields
// SecretNameViolation already carries per-project, so the deployment-wide caller can
// build a DeploymentSecretNameViolation directly without a second lookup.
type SecretNameRow struct {
	ProjectID      uint
	ID             uint
	Name           string
	Type           string
	Classification string
	EnvironmentID  uint
}

// UserFilter defines filtering options for user queries
type UserFilter struct {
	Search       *string // OR match across username and email (LIKE %search%)
	Username     *string
	Email        *string
	IsActive     *bool
	CreatedAfter *time.Time
	// InactiveSince, when set, returns only users who have not logged in since the
	// given time — i.e. last_login_at IS NULL OR last_login_at < InactiveSince.
	InactiveSince  *time.Time
	IncludeDeleted bool // when true, also return soft-deleted users
	Page           int
	PageSize       int
	// Offset, when > 0, sets the row offset directly (overriding the Page-derived
	// offset). Used for SCIM startIndex paging, where the window is an arbitrary 1-based
	// item offset that need not align to a Page boundary.
	Offset int
}

// MembershipCounts holds a user's project-membership tallies: Active counts
// memberships in the `active` state; Total counts all non-revoked memberships.
// UserBrief is the identity a list view shows for a user: never the full row.
type UserBrief struct {
	Username string
	Email    string
}

type MembershipCounts struct {
	Active int
	Total  int
}

// AuditFilter defines filtering options for audit log queries
// NotificationScope selects the notifications that carry a project: every such row
// when ProjectID is 0, otherwise only that project's. A notification with no project
// is never in any scope.
type NotificationScope struct {
	ProjectID uint
}

type AuditFilter struct {
	ProjectID *uint
	UserID    *uint
	// SecretID restricts to events about a specific secret (secret_node_id).
	SecretID *uint
	Action   *string
	// Actions matches any of several event types (event_type IN). Used to pull a
	// related family of events together, e.g. the RBAC audit log (role.*).
	Actions  []string
	Resource *string
	Success  *bool
	// ActorType filters by acting-principal kind: "user" or "machine_identity"
	// (also "system"). Nil = all actor types. (ADR-023)
	ActorType *string
	StartTime *time.Time
	EndTime   *time.Time
	Page      int
	PageSize  int

	// Cursor pagination for incremental SIEM export. When AfterID is set the
	// query returns events with id > *AfterID in ascending id order (a stable
	// forward cursor), ignoring Page. Use with the /audit/export endpoint.
	AfterID   *uint
	Ascending bool
	// UpToID, when set, adds id <= *UpToID (inclusive upper bound). With AfterID
	// it bounds the scan to the primary-key range (AfterID, UpToID].
	UpToID *uint

	// IPAddress filters events by the exact IP address that originated the request.
	IPAddress *string
	// ActorUsername filters events by a partial match on the actor's username
	// (resolved via a LEFT JOIN on the users table). Nil = no username filter.
	ActorUsername *string
	// ResourceType filters events by the resource type embedded in the event_type
	// (the prefix before the first dot, e.g. "secret" from "secret.read").
	ResourceType *string

	// Before is the keyset cursor of the newest-first order (event_time DESC,
	// id DESC): only rows strictly after that position are returned and Page is
	// ignored. Ignored in Ascending mode. See docs/specs/audit-list-keyset.md.
	Before *AuditCursor
	// Count selects how the total is computed. The zero value is the exact
	// COUNT(*) over every match; a caller that discards the total passes
	// AuditCountNone, and the public list views pass AuditCountCapped.
	Count AuditCountMode
}

// AuditCursor is a position in the newest-first audit order: the event_time
// and id of the last row a page returned.
type AuditCursor struct {
	EventTime time.Time
	ID        uint
}

// AuditCountMode selects how GetAuditLogs computes its total.
type AuditCountMode int

const (
	// AuditCountExact counts every matching row (the default).
	AuditCountExact AuditCountMode = iota
	// AuditCountNone skips the count; the returned total is 0.
	AuditCountNone
	// AuditCountCapped counts at most AuditCountCap+1 matching rows, so the cost
	// is bounded by the cap rather than by the table. A total above
	// AuditCountCap means "more than AuditCountCap".
	AuditCountCapped
)

// AuditCountCap bounds AuditCountCapped. It equals the deepest offset the
// public list views let a caller reach by page number (AuditOffsetCap in
// internal/core), so a capped total still yields every reachable page.
const AuditCountCap = 10_000

// Scope identifies the project/environment a role assignment or an
// authorization check applies to. It uses a 0 = global/unspecified sentinel,
// matching the stored user_roles/group_roles columns:
//
//	{0, 0}  global — every project and environment
//	{P, 0}  all environments in project P
//	{P, E}  only environment E of project P
//
// A stored assignment authorizes a target scope when its project is global or
// equal AND its environment is global or equal (see GetUserRoleIDsAt).
type Scope struct {
	ProjectID     uint
	EnvironmentID uint
}

// RoleGrant is a single role-to-scope grant applied atomically alongside a user
// creation (ADR-028 atomic provisioning).
type RoleGrant struct {
	RoleID uint
	Scope  Scope
}

// Permission represents a fine-grained permission
type Permission struct {
	ID          uint   `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
}

// ProjectUsageStat is one row in a usage report, aggregating all metrics for
// one project over the reporting window.
type ProjectUsageStat struct {
	ProjectID     uint   `json:"project_id"`
	ProjectName   string `json:"project_name"`
	SecretCount   int64  `json:"secret_count"`    // active leaf secrets (is_secret=true, not deleted)
	ReadsInWindow int64  `json:"reads_in_window"` // audit_events: event_type="secret.read", success=true, in window
	UniqueReaders int    `json:"unique_readers"`  // distinct user_id values in those audit events
}

// UsageReport is the full usage response.
type UsageReport struct {
	WindowDays  int                `json:"window_days"`
	GeneratedAt time.Time          `json:"generated_at"`
	Projects    []ProjectUsageStat `json:"projects"`
}

// BillingProjectStat is one project's usage breakdown for a billing period.
type BillingProjectStat struct {
	ProjectID       uint   `json:"project_id"`
	ProjectName     string `json:"project_name"`
	SecretCount     int64  `json:"secret_count"`     // active leaf secrets at report time
	SecretReads     int64  `json:"secret_reads"`     // secret.read events in window
	SecretWrites    int64  `json:"secret_writes"`    // secret.create + secret.update + secret.rotate in window
	SecretRotations int64  `json:"secret_rotations"` // secret.rotate events in window (subset of writes)
	UniqueUsers     int    `json:"unique_users"`     // distinct human user_ids
	MachineReads    int64  `json:"machine_reads"`    // secret.read where actor_type='machine'
}

// BillingTotals aggregates BillingProjectStat across all projects.
type BillingTotals struct {
	Projects        int   `json:"projects"`
	SecretCount     int64 `json:"secret_count"`
	SecretReads     int64 `json:"secret_reads"`
	SecretWrites    int64 `json:"secret_writes"`
	SecretRotations int64 `json:"secret_rotations"`
	UniqueUsers     int   `json:"unique_users"`
	MachineReads    int64 `json:"machine_reads"`
}

// BillingReport is the response from GetBillingReport.
type BillingReport struct {
	From        time.Time            `json:"from"`
	To          time.Time            `json:"to"`
	GeneratedAt time.Time            `json:"generated_at"`
	Projects    []BillingProjectStat `json:"projects"`
	Totals      BillingTotals        `json:"totals"`
}

// StorageStats provides statistics about the storage system
type StorageStats struct {
	TotalSecrets   int64      `json:"total_secrets"`
	TotalUsers     int64      `json:"total_users"`
	TotalRoles     int64      `json:"total_roles"`
	TotalSessions  int64      `json:"total_sessions"`
	TotalAuditLogs int64      `json:"total_audit_logs"`
	DatabaseSize   int64      `json:"database_size_bytes"`
	LastBackup     *time.Time `json:"last_backup"`
}

// ProjectWithCounts is returned by ListProjectsWithCounts, adding aggregate
// counts so the frontend project list page can show secret/env totals.
type ProjectWithCounts struct {
	ID               uint   `json:"id"`
	Name             string `json:"name"`
	Description      string `json:"description"`
	SecretCount      int64  `json:"secret_count"`
	EnvironmentCount int64  `json:"environment_count"`
	LastActivity     string `json:"last_activity,omitempty"` // most recent of project update or any secret change
	Deleted          bool   `json:"deleted"`                 // true when soft-deleted (only returned when includeDeleted)
	DeletedAt        string `json:"deleted_at,omitempty"`    // RFC3339 timestamp when soft-deleted
}

// SecretUsageStat is one row of the most-accessed-secrets report.
type SecretUsageStat struct {
	SecretID      uint       `json:"secret_id"`
	SecretName    string     `json:"secret_name"`
	EnvironmentID uint       `json:"environment_id"`
	ReadCount     int64      `json:"read_count"`
	LastRead      *time.Time `json:"last_read"`
}

// AuditRetentionStats holds the raw aggregates backing the audit-retention
// coverage report: how many audit events exist and the timestamps of the
// oldest and newest. Oldest/Newest are nil when the audit table is empty.
type AuditRetentionStats struct {
	TotalEvents int64
	Oldest      *time.Time
	Newest      *time.Time
}

// AuditChainVerification is the verdict of re-walking the audit hash chain
// (ADR-029). Valid is true when every chained event's hash and linkage check
// out. On failure, FirstBrokenID and Reason identify the first divergence.
type AuditChainVerification struct {
	// Valid is true when the chained suffix is intact end to end.
	Valid bool
	// ChainedEvents is the number of hash-chained events verified.
	ChainedEvents int64
	// UnchainedEvents is the leading run of legacy rows (pre-ADR-029, empty
	// hashes) skipped before the chain begins.
	UnchainedEvents int64
	// FirstBrokenID is the id of the first event that failed verification, nil
	// when Valid.
	FirstBrokenID *uint
	// Reason is a human-readable description of the first failure, empty when
	// Valid.
	Reason string
	// HeadHash is the entry_hash of the last chained event (the chain head),
	// genesis when there are no chained events. HeadID is its id. Surfaced so an
	// external monitor can record (ChainedEvents, HeadHash) and detect tail-
	// truncation or a genesis re-seed — which an unanchored on-box re-walk cannot
	// catch on its own (ADR-029): a shorter-but-self-consistent chain still
	// verifies, so the count dropping or the head changing for a known prefix is
	// the off-box tamper signal.
	HeadHash string
	HeadID   uint

	// Checkpointed is true when the live chain was additionally verified against
	// a signed in-DB checkpoint (ADR-029) — an on-box anchor a DBA cannot forge.
	// When a valid checkpoint exists and the chain has dropped below it (or the
	// checkpointed head changed), Valid is false and CheckpointReason explains it.
	// CheckpointReason also carries non-fatal notes (e.g. a checkpoint signed
	// under a superseded key version, which is recorded but not enforced).
	Checkpointed     bool
	CheckpointReason string

	// AnchorToken/AnchoredAt/AnchorProvider surface the latest checkpoint's raw
	// external-notary (RFC 3161) receipt (ADR-029), when one exists — regardless of
	// whether this server was able to (re-)verify it locally (i.e. even without a
	// configured trust root, or when local re-verification fails). Handing back the
	// opaque token lets an operator or an independent monitor verify it themselves
	// against the TSA out-of-band, without having to trust this server's own
	// verification of it — the point of an external anchor in the first place.
	// Empty when checkpoints are unavailable, no checkpoint exists yet, or the
	// latest checkpoint was never anchored.
	AnchorToken    []byte
	AnchoredAt     *time.Time
	AnchorProvider string
	// AnchorTrustRootConfigured is true when a TSA trust root
	// (audit.checkpoint_notary.ca_cert_path) is configured, i.e. this server is
	// actually able to locally re-verify AnchorToken against a root of trust.
	// Only meaningful when AnchorToken is non-empty. When false, AnchorToken was
	// still merely RECORDED (a raw TSA receipt was obtained and stored) but this
	// server has never checked it against any root of trust — callers must not
	// treat a recorded-but-unverifiable anchor as equivalent to a verified one.
	AnchorTrustRootConfigured bool

	// Truncated is set only by VerifyAuditChainSegment: the MaxRows cap stopped
	// the walk before ThroughID or the end of the chain, so rows after HeadID
	// were NOT verified.
	Truncated bool
}

// AuditChainAnchor is an authenticated re-anchor point for VerifyAuditChain's
// walk, produced when a retention purge (DeleteAuditLogsBefore) removes rows
// from the chained (post-ADR-029) region: the new earliest surviving row's own
// id, prev_hash (which now points at a deleted predecessor), and entry_hash.
//
// The store layer that walks the chain has no signing key and trusts this
// value literally — authenticating it (HMAC-signing at write time under the
// checkpoint signing key, verifying the signature before ever constructing one
// to pass in) is entirely the caller's (core layer's) responsibility. Without
// that, any DB-writable actor could forge an anchor claiming an arbitrary gap
// is sanctioned, defeating the tamper-evidence the chain exists to provide.
type AuditChainAnchor struct {
	RowID     uint
	PrevHash  string
	EntryHash string
	// PurgedEvents counts CHAINED rows removed by sanctioned retention purges
	// (#3257); legacy unchained rows are never counted, because the
	// checkpoint/high-water counts they are compared with never included them.
	// On a candidate returned by DeleteAuditLogsBefore it is the chained rows
	// THAT delete removed. On an anchor the core layer loaded and authenticated
	// it is the cumulative total, covered by the anchor's HMAC, so a DB-level
	// actor cannot raise it to excuse a truncation. Checkpoint and high-water
	// checks compare chained + PurgedEvents against the certified count.
	PurgedEvents int64
}

// AuditVerifyJobLockKey is the WithSchedulerLock key that admits one background
// full audit-chain verification job across replicas ("KEYSAVJB"; distinct from
// server/main.go's schedLock* keys; uniqueness against every *LockKey constant
// is guarded by store.TestEveryAdvisoryLockKeyConstantIsUnique).
const AuditVerifyJobLockKey int64 = 0x4B455953_41564A42

// AuditChainSegment bounds one VerifyAuditChainSegment walk. AfterID/SeedHash
// come from an authenticated source (a signed checkpoint head, or the signed
// incremental-verification state); like AuditChainAnchor, the store layer
// trusts them literally.
type AuditChainSegment struct {
	// AfterID is the pinned seed row; 0 = start at the chain start.
	AfterID uint
	// SeedHash is the entry_hash AfterID was certified/verified with.
	SeedHash string
	// Anchor is the authenticated retention anchor, used only when AfterID == 0.
	Anchor *AuditChainAnchor
	// ThroughID is the last id to walk (inclusive); 0 = to the end.
	ThroughID uint
	// MaxRows caps the rows walked after the pinned row; 0 = no cap.
	MaxRows int
}

// AuditChainMigrationResult reports the outcome of MigrateAuditChainEncoding.
type AuditChainMigrationResult struct {
	// RowsMigrated is the number of chained rows whose entry_hash/prev_hash
	// were (or, under dry-run, would be) rewritten.
	RowsMigrated int64
	// UnchainedRowsSkipped is the legacy pre-ADR-029 prefix left untouched.
	UnchainedRowsSkipped int64
	// HeadID/HeadHash are the migrated chain's final row id and its newly
	// computed entry_hash (auditGenesisHash-derived if RowsMigrated is 0).
	HeadID   uint
	HeadHash string
	// AnchorRowID/AnchorNewEntryHash are set when the earliest migrated row's
	// id matches the anchor the caller seeded this call with (seedPrevHash
	// came from a real retention anchor, not genesis) — the caller must re-sign
	// and persist an updated anchor for AnchorRowID using AnchorNewEntryHash
	// (its PrevHash is unchanged; it represents an already-purged predecessor
	// that cannot be recomputed). Zero/empty when no anchor applies.
	AnchorRowID        uint
	AnchorNewEntryHash string
}

// UnusedSecretStat is one row of the unused-secrets report. LastRead is nil when
// the secret has never been read.
type UnusedSecretStat struct {
	SecretID      uint       `json:"secret_id"`
	SecretName    string     `json:"secret_name"`
	EnvironmentID uint       `json:"environment_id"`
	LastRead      *time.Time `json:"last_read"`
}

// SecretReadEntry is one row in the secret read aggregation report, representing
// the total reads by a single actor (user or machine identity) within a window.
type SecretReadEntry struct {
	// ActorID is the actor identifier: a user's numeric ID rendered as a string,
	// or a machine identity name (from actor_type="machine_identity" rows).
	ActorID string `json:"actor_id"`
	// ActorUsername is the resolved display name for the actor, empty when the
	// user row is absent (e.g. deleted users or machine identities).
	ActorUsername string    `json:"actor_username,omitempty"`
	ReadCount     int64     `json:"read_count"`
	LastReadAt    time.Time `json:"last_read_at"`
}

// ProjectMember is a user who holds a role at a project's scope (ADR-021).
type ProjectMember struct {
	UserID      uint   `json:"user_id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Email       string `json:"email"`
	RoleID      uint   `json:"role_id"`
	RoleName    string `json:"role_name"`
}

// RoleDeleteCascadeCounts reports how many live principal-assignment rows
// DeleteRole's cascade removed (SESSION-AT AT1 row 2, PR #2357 review) — the
// user/group/machine-identity grants that pointed at the deleted role.
// Deliberately excludes RolePermission/ConnectRefGrant: those are the role's
// OWN composition (its permission bundle, its connector grants), not another
// principal's assignment, so their removal isn't audit-worthy in the same
// way — it's an expected consequence of deleting the role's own definition,
// not something a user/group/machine "lost."
type RoleDeleteCascadeCounts struct {
	UserAssignments    int
	GroupAssignments   int
	MachineAssignments int
}

// RoleAssignment is one principal↔role grant at a scope — the raw rows behind an
// access review (ISO 27001 A.5.18). Unlike ProjectMember it does NOT collapse a
// principal to a single role: a user/group with several roles at a scope yields
// several RoleAssignments. PrincipalType is "user" or "group".
type RoleAssignment struct {
	PrincipalType string `json:"principal_type"`
	PrincipalID   uint   `json:"principal_id"`
	RoleID        uint   `json:"role_id"`
	ProjectID     uint   `json:"project_id"`
	EnvironmentID uint   `json:"environment_id"`
}

// UserGroupMembership is one user→group membership row, as returned by
// ListAllUserGroupMemberships.
type UserGroupMembership struct {
	UserID  uint `json:"user_id"`
	GroupID uint `json:"group_id"`
}

// GroupRoleGrant is a role assigned to a group together with the grant's optional
// time-bound expiry (nil = permanent). Mirrors a models.Role plus expires_at so the
// group-roles API can show remaining time on a just-in-time grant.
type GroupRoleGrant struct {
	ID          uint       `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}
