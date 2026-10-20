package storage

import (
	"errors"
)

// ErrUserNotFound is returned (wrapped) by GetUser when the user positively does not
// exist, as distinct from a transient retrieval failure. Callers that must fail
// closed on uncertainty — e.g. authorization decisions keyed on "is this account
// gone?" — should match it with errors.Is rather than treating any error as absence.
var ErrUserNotFound = errors.New("user not found")

// ErrMFAChallengeInvalid is returned (wrapped or bare) by ConsumeMFAChallenge
// when no unused, unexpired challenge matches — the expected negative result for
// a stale, replayed or guessed challenge token — as distinct from a genuine
// storage failure. core.FinishWebAuthnLogin matches it with errors.Is: an
// invalid challenge is an ordinary failed attempt (counted toward the per-IP
// login budget), a storage failure is not an attempt that was ever evaluated
// (#2565).
var ErrMFAChallengeInvalid = errors.New("invalid or expired challenge")

// ErrMFASecretActivated is returned by UpsertMFASecret when the user's existing
// TOTP secret row is already activated: the conditional upsert never replaces an
// activated secret (#2692), and nothing was written. core.BeginMFAEnrollment maps
// it to ErrMFAAlreadyEnabled.
var ErrMFASecretActivated = errors.New("mfa secret already activated")

// ErrWebAuthnSessionInvalid is ConsumeWebAuthnSession's counterpart of
// ErrMFAChallengeInvalid: no unused, unexpired ceremony session matched.
var ErrWebAuthnSessionInvalid = errors.New("invalid or expired webauthn session")

// ErrRoleNotFound is returned (wrapped) by GetRole when the role positively does
// not exist, as distinct from a transient retrieval failure. isGlobalAdminRoleName
// (internal/core/sod.go) matches it with errors.Is: a dangling user-role/group-role
// row pointing at a since-deleted role (the orphan class AT4's guard #2380 exists
// for) must not block every SoD/legal-hold/risk-exception/license-expiry check for
// that user indefinitely — a role that no longer exists cannot confer admin-bypass
// either way, so this one case is "not this role, keep looking," not a resolution
// failure to fail closed on.
var ErrRoleNotFound = errors.New("role not found")

// ErrSQLiteWriteContention is returned when a write transaction waited the
// in-process SQLite write gate's full bound without getting the write lock:
// the clear, bounded failure that replaces an unbounded stall. Callers may
// retry.
//
// Declared HERE, not next to the gate in internal/storage, because the one
// classifier that most needs it lives in internal/storage/store
// (isSQLiteBusyErr, local_audit_chain.go) and internal/storage already imports
// internal/storage/store — so the gate's own package is unreachable from the
// classifier without an import cycle. Both packages already import this one.
//
// That reachability is not cosmetic: the coordinator's review of #2637 found
// that the audit-chain busy classifier matched only SQLITE_BUSY / "database is
// locked", so once the gate existed the DOMINANT contention error stopped
// being recognised by the retry budget built for exactly that condition, and
// commitAuditBatch bisected a batch-global failure as if it were a poisoned
// item.
var ErrSQLiteWriteContention = errors.New("sqlite: timed out waiting for the database write lock (sustained write contention); retry the request")

// ErrSoDPolicyNotFound is returned (wrapped) by GetSoDPolicy when no policy exists
// for the given id, as distinct from a transient retrieval failure. DeleteSoDPolicy
// (internal/core/sod.go) matches it with errors.Is to decide whether a real 404 is
// safe to return (only when the caller is authorized at global admin-tier
// regardless of which policy this is) versus collapsing it into the same
// permission-denied response a non-admin caller gets for an existing policy they
// don't own (#1645 403-for-both) — a string match against a translatable "not
// found" message would silently stop working the moment that translation key is
// actually translated.
var ErrSoDPolicyNotFound = errors.New("sod policy not found")

// ErrRiskExceptionNotFound is returned (wrapped) by GetRiskException when no
// exception exists for the given id, as distinct from a transient retrieval
// failure. Same convention and same reason as ErrSoDPolicyNotFound above —
// RevokeRiskException (internal/core/risk_exceptions.go) matches it with
// errors.Is to decide whether a real 404 is safe (admin-tier caller only) vs
// collapsing it into the same permission-denied response a non-admin caller
// gets for an existing-but-foreign exception (#1645 403-for-both). Part 2
// regression audit (adversarial review run 2): RevokeRiskException still had
// this exact gap (existence lookup before the creator/admin check) after
// PR #1695 fixed the identical shape for DeleteSoDPolicy but didn't sweep to
// this sibling site, despite risk_exceptions.go's own doc comment already
// naming the same #1529 precedent SoD's fix cites.
var ErrRiskExceptionNotFound = errors.New("risk exception not found")

// ErrRoleNotAssigned is returned (wrapped) by RemoveRole when the (user, role, scope)
// row positively does not exist — e.g. it already auto-expired or was already
// removed — as distinct from a genuine storage failure. Callers for whom "already
// gone" is an acceptable outcome (idempotent removal) should match it with
// errors.Is rather than swallowing every error identically.
var ErrRoleNotAssigned = errors.New("role not assigned")

// ErrWouldStrandLastAdmin is returned (wrapped) by RemoveGlobalAdminRoleGuarded when
// removing the (user, role) grant at the global scope would leave the install with
// zero super_admin/admin/system_admin holders (#340, #525) — the storage-layer
// sentinel for guardLastGlobalAdmin's refusal.
var ErrWouldStrandLastAdmin = errors.New("refusing to remove the last install administrator")

// ErrBreakGlassNotActive is returned (wrapped) when a conditional break-glass state
// transition (e.g. revoke) finds the activation is no longer in the expected prior
// state — most often because a concurrent revoke already won the race. Distinct
// from a genuine storage failure; callers should surface it as "already revoked"
// rather than a generic error.
var ErrBreakGlassNotActive = errors.New("break-glass activation is not active")

// ErrBreakGlassAlreadyReviewed is returned (wrapped) when
// ReviewBreakGlassActivation's conditional UPDATE finds reviewed_at already
// set — either a genuine second review attempt, or two concurrent
// submissions racing for the same activation (only the first wins).
var ErrBreakGlassAlreadyReviewed = errors.New("break-glass activation has already been reviewed")

// ErrBreakGlassNotFound is returned (wrapped) by GetBreakGlassActivation for a
// definitive "no such activation row" (gorm.ErrRecordNotFound) only — never
// for a transient retrieval failure, which keeps its ErrorRetrievalFailed
// wrapping so a caller can still tell a 404 from a 500. Same convention and
// same reason as ErrUserNotFound/ErrSecretNotFound: the i18n text
// GetBreakGlassActivation embeds is an implementation detail that changes with
// the deployment's locale, so it is not a classification contract (#2461
// round 2 — ReviewBreakGlass's handler matched the English words "not found"
// and returned 500 under ru/fr/de).
var ErrBreakGlassNotFound = errors.New("break-glass activation not found")

// IsBreakGlassNotFound is IsUserNotFound's break-glass counterpart — true only
// for a definitive "this activation does not exist", false for a transient
// retrieval failure.
func IsBreakGlassNotFound(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrBreakGlassNotFound)
}

// ErrDuplicateActiveMembership is returned (wrapped) by CreateProjectMembership when the
// insert collides with the partial unique index on (project_id, user_id) scoped to
// non-revoked rows. InviteMember's own "no active membership" check races with a
// concurrent invite for the same pair (#309 TOCTOU); this lets the loser of that race
// be told cleanly that the membership already exists, rather than surfacing a raw
// constraint-violation error or silently leaving an orphaned row.
var ErrDuplicateActiveMembership = errors.New("an active membership already exists for this project and user")

// ErrDuplicateEmail is returned (wrapped) by CreateUser/CreateUserWithRoleGrants/UpdateUser
// when the write collides with the partial, case-insensitive unique index on users.email
// (live rows only). Every email-uniqueness check in this codebase (CreateUser, signup,
// invite-accept, SSO JIT-provision, SCIM provision/update) is a check-then-act read
// followed by a later write, which is inherently racy — two concurrent calls for the
// identical email can both pass their pre-check before either commits (#117). The DB-level
// index makes the loser's write fail here instead of silently minting a second account
// sharing the email (which left GetUserByEmail resolving to an arbitrary one of them);
// callers translate this into a clean "email already in use" error rather than a raw
// constraint-violation message.
var ErrDuplicateEmail = errors.New("a user with this email already exists")

// ErrDuplicateProjectName is returned (wrapped) by CreateProject/UpdateProject when the
// write collides with the partial, case-insensitive unique index on projects.name (live
// rows only, #385). Without this, "Production"/"production" landed as two distinct,
// both-succeeding rows — and the CLI's project name resolution (resolveProjectID)
// resolves case-insensitively over an unordered project list, returning the FIRST match —
// so a same-name-different-case shadow project could silently hijack a later `keyorix
// secret import/export --project production`. Callers translate this into a clean
// "project name already in use" error rather than a raw constraint-violation message.
var ErrDuplicateProjectName = errors.New("a project with this name already exists")

// ErrDuplicateGroupName is returned (wrapped) by CreateGroup when the insert collides
// with the partial unique index on groups.name_folded (live rows only, #1642). Callers
// translate it into a 409 with a message naming the conflict instead of a bare 500
// (#2779); matching the driver's message text at the handler is not reliable (SQLite
// says "UNIQUE constraint failed", Postgres "duplicate key value violates unique
// constraint").
var ErrDuplicateGroupName = errors.New("a group with this name already exists")

// ErrDuplicateNotificationChannelName is returned (wrapped) by CreateNotificationChannel
// when the insert collides with the unique index on notification_channels.name (#2779).
var ErrDuplicateNotificationChannelName = errors.New("a notification channel with this name already exists")

// ErrDuplicateSecretVersion is returned (wrapped) by CreateSecretVersion when the insert
// collides with the unique index on (secret_node_id, version_number). RotateSecret's
// GetLatestSecretVersion -> +1 -> storeSecretVersion sequence is a read-then-write race
// (#121): two concurrent rotations of the same secret can both read the same "latest"
// version and both attempt to write the same next version_number. The unique index makes
// the loser's write fail here instead of silently producing two rows sharing one
// version_number; callers retry with a freshly re-read latest version rather than failing
// the rotation outright on ordinary concurrent contention.
var ErrDuplicateSecretVersion = errors.New("a secret version with this version number already exists")

// ErrSecretValueTooLarge is returned (wrapped, with the actual size and limit) by
// LocalStorage.CreateSecretVersion when a version's encrypted value exceeds
// MaxSecretSizeHardCeiling (internal/storage/store/local_secrets.go). This is
// defense-in-depth: internal/core.checkSecretSize already enforces the
// operator-configured (possibly smaller) secrets.limits.max_secret_size on every
// write path BEFORE this is ever reached, so this check should never actually
// fire in normal operation — it exists so that a bug in, or a future write path
// that bypasses, the core-layer check cannot silently persist a secret value
// above the architectural maximum regardless of what an operator configured.
var ErrSecretValueTooLarge = errors.New("secret value exceeds the maximum allowed size")

// ErrBreakGlassAlreadyActive is returned (wrapped) by CreateBreakGlassActivation when
// the partial unique index on (project_id, user_id) WHERE state='active' rejects the
// insert: a concurrent activation for the same project+user already won the race and
// is active. This closes the check-then-act gap between ActivateBreakGlass's
// "no existing active activation" list-and-scan check and its own insert — under a
// race, both callers could pass the check before either inserted; the DB constraint
// is the actual source of truth. Callers should match it with errors.Is to surface
// the same friendly "already active" message a losing racer gets from the earlier
// application-level check.
var ErrBreakGlassAlreadyActive = errors.New("an active break-glass grant already exists for this project and user")

// ErrDuplicateDynamicSecretConfig is returned (wrapped) by CreateDynamicSecretConfig
// when the insert collides with the unique index on dynamic_secret_configs
// (project_id, environment_id, name, #462), matching DynamicSecretConfig's own doc
// comment ("one per (project, env, name)") — previously documented but not enforced.
// Callers translate this into a clean validation error instead of a raw
// constraint-violation message.
var ErrDuplicateDynamicSecretConfig = errors.New("a dynamic-secret config with this name already exists in this project and environment")

// ErrDynamicSecretConfigDisabled is returned by CreateDynamicSecretLease when an
// ACTIVE lease's config was disabled (DeleteProject's #369 cascade, or the config
// disable kill switch) before the lease row could commit (#2652). The insert is
// rolled back; the caller must revoke the credential it just minted.
var ErrDynamicSecretConfigDisabled = errors.New("dynamic-secret config is disabled")

// ErrDuplicateRolePermission is returned (wrapped) by AssignPermissionToRole
// when the insert collides with role_permissions' composite primary key
// (role_id, permission_id) -- i.e. the role already has this permission.
// Before this existed, that primary-key violation fell through
// AssignPermissionToRole's core wrapper as a generic "Storage operation
// failed" error, which server/http/handlers/rbac.go's AssignPermissionToRole
// handler could not distinguish from any other storage failure, so a
// re-assign of an already-held permission (a plausible idempotent-retry
// shape, not an attack) 500ed instead of returning 409 Conflict. Found by
// SESSION-I's fresh-install API smoke driver (scripts/e2e).
var ErrDuplicateRolePermission = errors.New("this role already has this permission")

// ErrDuplicateReminderNotification is returned (wrapped) by CreateNotification when
// the insert collides with the partial unique index on notifications (user_id, type,
// project_id) scoped to unread rotation/expiry reminders (#488). Both
// SendRotationReminders and SendExpiryReminders dedupe with a check-then-act read
// (GetUnreadNotification) followed by a separate CreateNotification call, which is a
// TOCTOU race: unlike the scheduled path (single-replica-gated via WithSchedulerLock,
// ADR-039), the on-demand admin-jobs HTTP trigger
// (POST /api/v1/admin/jobs/rotation-reminders or .../expiry-reminders) has no lock at
// all, so two concurrent runs (or one racing the scheduler's own tick) against a
// project with no existing reminder can both pass the "does a reminder already exist"
// check before either commits, producing duplicate reminder rows. The index makes the
// loser's insert fail here instead of silently duplicating; callers treat this as a
// benign no-op skip, not a failure.
var ErrDuplicateReminderNotification = errors.New("an unread reminder notification already exists for this user, type, and project")

// ErrDuplicateSecretDependency is returned (wrapped) by CreateSecretDependencyExclusive
// when the CURRENT edge set (read under this call's own lock — see that method's doc)
// already contains the same (dependent, depends_on) pair. Backed by the real unique
// index on secret_dependencies (idx_secret_dep_edge), so a plain CreateSecretDependency
// insert would also fail with a unique-constraint violation for the exact same case;
// CreateSecretDependencyExclusive additionally checks it up front (alongside the cycle
// check, which the index cannot express) so both rejections share one code path and one
// sentinel. Callers translate this into a clean "already exists" validation error.
var ErrDuplicateSecretDependency = errors.New("this secret dependency already exists")

// ErrSecretDependencyCycle is returned (wrapped) by CreateSecretDependencyExclusive when
// adding the edge would make the depends_on secret transitively depend on the dependent
// secret, closing a cycle in the project's dependency graph (ADR-052). Unlike
// ErrDuplicateSecretDependency, no DB constraint can express "acyclic" directly, so this
// is evaluated in application code against the lock-consistent edge read
// CreateSecretDependencyExclusive takes — see its doc for why that check must run in the
// SAME storage-layer call as the write (#260), not as a separate caller-orchestrated
// read-then-write. Callers translate this into a clean "would create a cycle"
// validation error.
var ErrSecretDependencyCycle = errors.New("this secret dependency would create a cycle")

// ErrSessionNotFound is returned (wrapped) by GetSessionByID when the row positively
// does not exist (hard-deleted, e.g. by RevokeUserSessions), as distinct from a
// transient retrieval failure. SessionLiveForToken (internal/core/auth.go) matches it
// with errors.Is to decide "the session is definitively gone, deny" versus "the lookup
// itself failed, fall back to the cached snapshot" — collapsing the two would either
// deny live traffic on an ordinary DB blip, or (worse) treat an unreachable backend as
// proof of revocation it never actually observed.
var ErrSessionNotFound = errors.New("session not found")

// IsUserNotFound reports whether err represents "this user positively does not
// exist" (#504). LocalStorage wraps the ErrUserNotFound sentinel above
// (errors.Is), which is not reliably detectable by matching an error's rendered
// text — the i18n string LocalStorage happens to embed in ErrUserNotFound's
// wrapping message is an implementation detail, not a contract. Callers that
// must distinguish "genuinely absent" from a transient retrieval failure should
// use this instead of a text match.
func IsUserNotFound(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrUserNotFound)
}

// IsRoleNotFound is IsUserNotFound's role counterpart — true only for a
// definitive "this role does not exist" (ErrRoleNotFound), false for a
// transient retrieval failure.
func IsRoleNotFound(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrRoleNotFound)
}

// IsSessionNotFound is IsUserNotFound's session counterpart — true only for a
// definitive "this session row does not exist" (ErrSessionNotFound), false for
// every other error.
func IsSessionNotFound(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrSessionNotFound)
}

// ErrSecretNotFound is returned (wrapped) by GetSecret/GetSecretByName when no
// secret exists for the given id/name, as distinct from a transient retrieval
// failure. Same convention as ErrUserNotFound/ErrSoDPolicyNotFound — added
// 2026-09-23 (docs/findings/2026-09-23-FINDING-update-secret-read-error-swallowed.md):
// CreateSecret's duplicate-name pre-check previously could not distinguish "no
// duplicate" from "the check itself failed" and silently assumed the former.
var ErrSecretNotFound = errors.New("secret not found")

// ErrSecretVersionNotFound is returned (wrapped) by GetLatestSecretVersion/
// GetSecretVersion when no version exists, as distinct from a transient
// retrieval failure. Same convention and same reason as ErrSecretNotFound above
// — storeNextSecretVersion previously could not distinguish "no versions yet"
// from "the read failed" and silently assumed the former, defaulting to
// version 1 either way (see the finding doc cited above).
var ErrSecretVersionNotFound = errors.New("secret version not found")

// IsSecretNotFound is IsUserNotFound's secret counterpart — true only for a
// definitive "this secret does not exist" (ErrSecretNotFound), false for every
// other error.
func IsSecretNotFound(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrSecretNotFound)
}

// IsSecretVersionNotFound is IsUserNotFound's secret-version counterpart —
// true only for a definitive "this version does not exist"
// (ErrSecretVersionNotFound), false for every other error.
func IsSecretVersionNotFound(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrSecretVersionNotFound)
}
