// auth_bootstrap.go — First-boot system initialisation (BootstrapSystem).
//
// Seeds admin user, RBAC roles/permissions (see defaultRoles), default project/environments.
// Idempotent: if users already exist, returns current state with AlreadyInitialized=true.
// For session auth see auth.go.
package core

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/besteffort"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// BootstrapRequest holds credentials and display name for the initial bootstrap.
// Token is the caller-supplied bootstrap token, matched against the server's
// configured token (see KeyorixCore.SetBootstrapToken) to authorize the first-admin
// claim.
type BootstrapRequest struct {
	Username    string
	Email       string
	Password    string
	DisplayName string
	Token       string
}

// BootstrapResult is returned after a bootstrap call (first-time or idempotent repeat).
type BootstrapResult struct {
	AlreadyInitialized bool
	User               *models.User
	Project            *models.Project
	Environments       []*models.Environment
}

// bootstrapPermissionDef describes a permission to create during bootstrap.
type bootstrapPermissionDef struct {
	Name        string
	Description string
	Resource    string
	Action      string
}

// defaultPermissions is the canonical set of permissions seeded on first boot.
var defaultPermissions = []bootstrapPermissionDef{
	{permSecretsRead, "Read secrets", "secrets", "read"},
	{permSecretsWrite, "Create and update secrets", "secrets", "write"},
	{permSecretsDelete, "Delete secrets", "secrets", "delete"},
	{permUsersRead, "View user information", "users", "read"},
	{"users.write", "Create and update users", "users", "write"},
	{"users.delete", "Delete users", "users", "delete"},
	{permRolesRead, "View roles", "roles", "read"},
	{"roles.write", "Create and update roles", "roles", "write"},
	{permRolesAssign, "Assign roles to users", "roles", "assign"},
	{permAuditRead, "View audit logs", "audit", "read"},
	{permSystemRead, "View system information", "system", "read"},
	// #227: this permission's blast radius must stay narrow — the description must
	// name its exact footprint so an operator granting a custom role system.write
	// knows what they're actually handing over: audit-checkpoint writes and
	// anomaly-alert acknowledgment, legal-hold place/lift, risk-exception
	// create/approve/revoke, SoD-policy create/delete, and on-demand admin job
	// triggers (rotation/expiry reminders, anomaly alerts, compliance digest).
	//
	// #F6 (system-proxy-target-authority audit, 2026-09-21) through ADR-108 Phase 6
	// (#2162/#2171): this permission USED TO also be the blanket gate on the entire
	// /api/v1/system RemoteStorage-sync proxy route tree (server/http/router.go's
	// r.Route("/system", ...) — machine-identity/credential/OIDC-binding CRUD, group
	// CRUD, secret dependencies, invitations, setup tokens, break-glass,
	// access-review campaigns, and more), a much broader footprint than the
	// narrow, documented use case above. That entire route tree — along with
	// RemoteStorage itself, the deployment topology it served — has since been
	// deleted; system.write's actual footprint is now exactly the narrow use case
	// this description names.
	{"system.write", "Manage audit checkpoints/alerts, legal holds, risk exceptions, SoD policies, and admin job triggers", "system", "write"},
	// F1 (ADR-110 follow-up, Andrei 2026-09-28): split off the alerting-operator
	// slice of system.write's footprint into its own permission — notification
	// channels, escalation policies, and the on-demand job triggers that only
	// ever emit/dispatch a notification (never mutate account/role/audit state).
	// system.write remains a strict superset: every current system.write holder
	// also gets alerts.write via ReconcileAlertsWriteRole's one-time backfill
	// (alerts_write_role_reconcile.go), so no existing holder loses access.
	{permAlertsWrite, "Manage notification channels, escalation policies, and on-demand alert/reminder job triggers", "alerts", "write"},
	{"connect.read", "Read secrets from external stores via Keyorix Connect (ADR-043)", "connect", "read"},
	// ADR-082 branch 4: narrows scope: platform connector reads, which connect.read
	// alone permitted for any holder through branch 3 (an interim fail-open, marked
	// by a TODO). Distinct from connect.read (which still gates the whole Connect
	// surface, project-scoped connectors included) — this only narrows the
	// platform-scoped subset.
	{"connect.platform.use", "Read secrets from platform-scoped Keyorix Connect connectors (ADR-082 §B/§H)", "connect", "platform.use"},
}

// adminPermissions lists the permission names granted to the admin role.
var adminPermissions = []string{
	permSecretsRead, permSecretsWrite, permSecretsDelete,
	permUsersRead, "users.write", "users.delete",
	permRolesRead, "roles.write", permRolesAssign,
	permAuditRead, permSystemRead, "system.write",
	permAlertsWrite,
	"connect.read", "connect.platform.use",
}

// alertOperatorPermissions lists the permission names granted to the
// alert_operator role (F1, ADR-110 follow-up): the narrower "alerting
// operator" persona — notification channels, escalation policies, and
// on-demand alert/reminder job triggers — without the compliance/legal/
// risk/SoD/audit-checkpoint authority the rest of system.write still covers.
var alertOperatorPermissions = []string{permAlertsWrite}

// editorPermissions lists the permission names granted to the editor role.
// Editor is the canonical "can change secrets, but not manage users/roles" role
// and is meant to be granted at a project/environment scope (RBAC Phase 2).
var editorPermissions = []string{permSecretsRead, permSecretsWrite, permSecretsDelete, permUsersRead}

// viewerPermissions lists the permission names granted to the viewer role.
var viewerPermissions = []string{permSecretsRead, permUsersRead, permAuditRead}

// bootstrapRoleDef describes a role to seed on first boot and the permissions
// it grants (by permission name, resolved against defaultPermissions).
type bootstrapRoleDef struct {
	Name        string
	Description string
	Permissions []string
}

// defaultRoles is the canonical set of roles seeded on first boot.
//
// admin/editor/viewer are the legacy single-tier roles, retained for backward
// compatibility. The system_* and project_* roles implement the ADR-021 two-tier
// model on the RBAC Phase 2 sentinel schema: a system role is meant to be
// assigned at the global scope (project 0 = install-wide), a project role at a
// project scope (project P). The split is purely by where each is assigned —
// there is no separate scope column; project_id = 0 is the system sentinel.
// system_admin and project_admin bypass the per-permission check at the scope
// they hold (see adminRoleNames in authz.go), so their explicit permission lists
// matter only where the bypass does not apply.
var defaultRoles = []bootstrapRoleDef{
	{"admin", "Administrator with full access (legacy alias of system_admin)", adminPermissions},
	{"editor", "Create, update and delete secrets within a scope", editorPermissions},
	{"viewer", "Read-only access", viewerPermissions},

	// ADR-021 system roles — assign at the global scope (project 0).
	{"system_admin", "Install-wide administrator: manage projects, users, roles and settings", adminPermissions},
	{"system_auditor", "Install-wide read-only access plus audit, for compliance personas",
		[]string{permSecretsRead, permUsersRead, permRolesRead, permAuditRead, permSystemRead}},
	{"system_viewer", "Minimal install baseline; project access comes from project roles",
		[]string{permSystemRead}},

	// ADR-021 project roles — assign at a project scope (project P).
	{"project_admin", "Full control within a project, including members and settings",
		[]string{permSecretsRead, permSecretsWrite, permSecretsDelete, permUsersRead, permRolesRead, permRolesAssign, permAuditRead}},
	{"project_developer", "Read, write and rotate secrets in all environments of a project",
		[]string{permSecretsRead, permSecretsWrite, permSecretsDelete, permUsersRead}},
	{"project_viewer", "Read-only access to a project's secrets",
		[]string{permSecretsRead, permUsersRead}},
	{"project_auditor", "Read-only access to a project's secrets plus its audit log",
		[]string{permSecretsRead, permUsersRead, permAuditRead}},

	// F1 (ADR-110 follow-up) — a global-scope (project 0) alerting-operator
	// persona: manages notification channels, escalation policies, and
	// on-demand alert/reminder job triggers, without system.write's broader
	// compliance/legal/risk/SoD/audit-checkpoint authority.
	{"alert_operator", "Manages notification channels, escalation policies, and on-demand alert/reminder jobs",
		alertOperatorPermissions},
}

// builtinRoleNames are the roles that ship with the product and must not be
// deleted through any API (deleting e.g. super_admin/admin would invalidate live
// assignments and can lock every administrator out). This is the single source of
// truth shared by the HTTP and gRPC role-delete guards; it is a superset of
// defaultRoles (it also pins the historical "super_admin"/"auditor" aliases).
var builtinRoleNames = map[string]bool{
	"super_admin": true,
	"admin":       true,
	"editor":      true,
	"viewer":      true,
	"auditor":     true,
	// ADR-021 two-tier named roles.
	"system_admin":      true,
	"system_auditor":    true,
	"system_viewer":     true,
	"project_admin":     true,
	"project_developer": true,
	"project_viewer":    true,
	"project_auditor":   true,
	"alert_operator":    true,
}

// IsBuiltinRole reports whether a role name is a product built-in that the API
// must refuse to delete. Used by both the HTTP and gRPC DeleteRole paths so the
// guard cannot be bypassed by switching transport.
func IsBuiltinRole(name string) bool {
	return builtinRoleNames[name]
}

// defaultEnvironmentNames is the ordered list of environment names created on first boot.
var defaultEnvironmentNames = []string{"development", "staging", "production"}

// systemInitializedKey is the permanent SystemMetadata marker set once bootstrap
// completes successfully. Unlike the live user count, it survives every user later
// being soft-deleted (see core.DeleteUser / #106): without it, a full deprovision
// would zero ListUsers' count and SystemNeedsBootstrap/BootstrapSystem would treat
// the install as never-initialised again, letting a stale/leaked bootstrap token
// (or a freshly regenerated one — GenerateBootstrapToken logs it on every restart
// while uninitialised) re-seize admin even though the original users still exist,
// soft-deleted and restorable.
const systemInitializedKey = "system_initialized" // #nosec G101 -- metadata key name, not a credential

// BootstrapSystem ensures the server has a fully-configured initial state:
//   - admin user (with the supplied credentials)
//   - canonical RBAC permissions and roles (legacy admin/editor/viewer plus the
//     ADR-021 two-tier system_* and project_* roles)
//   - default project ("default")
//   - three default environments (development, staging, production)
//
// Idempotent: if the install is already initialised, returns the current state
// with AlreadyInitialized=true and performs no writes. The whole check-then-create
// sequence runs under storage.WithBootstrapLock (#339, #core-auth-03): without it,
// two concurrent callers who both already hold the valid bootstrap token (different
// usernames) could each observe total==0 before either CreateUser lands, producing
// two "first admins" — and, in an HA deployment (ADR-039), those two callers can
// land on different replicas, where a plain in-process mutex provides no
// coordination at all. The token check above already closes the unauthenticated
// race; the lock closes the authenticated one, across every replica.
func (c *KeyorixCore) BootstrapSystem(ctx context.Context, req *BootstrapRequest) (*BootstrapResult, error) { // NOSONAR -- cognitive complexity 28, suppress go:S3776
	var result *BootstrapResult
	err := c.storage.WithBootstrapLock(ctx, func(ctx context.Context) error {
		res, berr := c.bootstrapSystemLocked(ctx, req)
		result = res
		return berr
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// bootstrapSystemLocked performs the actual check-then-create sequence. The
// caller MUST hold storage.WithBootstrapLock for the duration of this call (see
// BootstrapSystem).
func (c *KeyorixCore) bootstrapSystemLocked(ctx context.Context, req *BootstrapRequest) (*BootstrapResult, error) {
	// The permanent marker is authoritative once set — see systemInitializedKey.
	if _, found, err := c.storage.GetSystemMetadata(ctx, systemInitializedKey); err != nil {
		return nil, fmt.Errorf("failed to check system initialisation state: %w", err)
	} else if found {
		return c.currentBootstrapState(ctx)
	}

	_, total, err := c.storage.ListUsers(ctx, &storage.UserFilter{Page: 1, PageSize: 1})
	if err != nil {
		return nil, fmt.Errorf("failed to check existing users: %w", err)
	}
	if total > 0 {
		// A pre-fix install has users but never wrote the marker; backfill it now so
		// a future full-deprovision can't reopen bootstrap for THIS install either.
		if err := c.storage.SetSystemMetadata(ctx, systemInitializedKey, "1"); err != nil {
			return nil, fmt.Errorf("failed to record system initialisation state: %w", err)
		}
		return c.currentBootstrapState(ctx)
	}

	// Authorize the first-admin claim. Without this gate the bootstrap is an
	// unauthenticated, first-caller-wins admin seizure on any fresh, network-reachable
	// instance. An unset server token disables API bootstrap entirely (fail closed).
	if c.bootstrapToken == "" {
		return nil, fmt.Errorf("system initialisation over the API is disabled: %w", ErrInvalidBootstrapToken)
	}
	if subtle.ConstantTimeCompare([]byte(req.Token), []byte(c.bootstrapToken)) != 1 {
		return nil, ErrInvalidBootstrapToken
	}
	displayName := req.DisplayName
	if displayName == "" {
		displayName = req.Username
	}
	// The initial admin is the most privileged account; enforce the password policy
	// here too (plain CreateUser does not), so it can't be seeded with a weak password.
	// Validate against the admin's own identity (username / email / display name)
	// HERE, before any write: CreateUser runs the same personal-info check later,
	// and a rejection there used to land after permissions and roles were already
	// committed, leaving the install unable to bootstrap again (every retry hit a
	// duplicate-permission 500; FINDINGS-inbox, Session J, 2026-09-28).
	if err := c.passwordPolicy.Validate(req.Password, &models.User{
		Username:    req.Username,
		Email:       req.Email,
		DisplayName: displayName,
	}); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}

	// Everything that writes happens in ONE transaction: permission / role
	// seeding, the admin user, its baseline and admin role grants, the default
	// project and environments, and the systemInitializedKey marker. A failure at
	// ANY step rolls all of it back, so a failed bootstrap never leaves an admin
	// user without the admin role (or a half-seeded catalog) behind; the next
	// attempt starts from the same empty state. The user row is built and
	// validated first (no writes), and the seeding below stays idempotent so
	// installs already left half-seeded by the pre-transaction code can still
	// complete bootstrap.
	user, hash, err := c.buildUserForCreate(ctx, &CreateUserRequest{
		Username:    req.Username,
		Email:       req.Email,
		Password:    req.Password,
		DisplayName: displayName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create admin user: %w", err)
	}

	var (
		createdUser *models.User
		project     *models.Project
		envs        []*models.Environment
	)
	txErr := c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
		// Seed permissions and roles BEFORE creating the admin user, so the
		// baseline system_viewer role exists when it is granted below (ADR-021;
		// the original ordering bug left the first admin without it on every
		// fresh install).
		//
		// Seeding is idempotent: a previous attempt that failed after this point
		// (any later step, not only the password check above) may have committed
		// some permissions / roles / role-permission links already. Reuse what
		// exists instead of failing on a unique constraint, so a failed bootstrap
		// stays retryable. Only default-catalog names are reused, and only while the
		// install is still un-initialised (no marker, no users -- checked above
		// under the bootstrap lock), so this cannot adopt anything an operator made.
		existingPerms, err := tx.ListPermissions(ctx)
		if err != nil {
			return fmt.Errorf("failed to list existing permissions: %w", err)
		}
		permByName := make(map[string]*models.Permission, len(existingPerms))
		for _, p := range existingPerms {
			permByName[p.Name] = p
		}
		existingRoles, err := tx.ListRoles(ctx)
		if err != nil {
			return fmt.Errorf("failed to list existing roles: %w", err)
		}
		roleByFolded := make(map[string]*models.Role, len(existingRoles))
		for _, r := range existingRoles {
			roleByFolded[r.NameFolded] = r
		}

		permIDs := make(map[string]uint, len(defaultPermissions))
		for _, def := range defaultPermissions {
			if p, ok := permByName[def.Name]; ok {
				permIDs[def.Name] = p.ID
				continue
			}
			p, err := tx.CreatePermission(ctx, &models.Permission{
				Name:        def.Name,
				Description: def.Description,
				Resource:    def.Resource,
				Action:      def.Action,
			})
			if err != nil {
				return fmt.Errorf("failed to create permission %s: %w", def.Name, err)
			}
			permIDs[def.Name] = p.ID
		}

		roleIDs := make(map[string]uint, len(defaultRoles))
		for _, rdef := range defaultRoles {
			foldedName, ferr := identity.NewFoldedName(rdef.Name)
			if ferr != nil {
				return fmt.Errorf("failed to normalize seed role name %s: %w", rdef.Name, ferr)
			}
			role, reused := roleByFolded[foldedName.Folded()]
			if !reused {
				created, err := tx.CreateRole(ctx, foldedName, rdef.Description)
				if err != nil {
					return fmt.Errorf("failed to create role %s: %w", rdef.Name, err)
				}
				role = created
			}
			roleIDs[rdef.Name] = role.ID
			// ADR-084: the four admin-tier seeded roles get the structural bypass
			// flag here, at creation, via the one narrow storage primitive that
			// exists for exactly this — never through CreateRole/UpdateRole's
			// general (request-reachable) path. isAdminRoleName is the same
			// fixed-name check requireAuthorityForRole uses to gate a role GRANT
			// by requested name; using it here to decide which SEEDED roles get
			// the flag is a one-time bootstrap decision, not an ongoing lookup.
			if isAdminRoleName(rdef.Name) {
				if err := tx.SetRoleBypassesPermissionChecks(ctx, role.ID, true); err != nil {
					return fmt.Errorf("failed to flag admin-tier role %s (ADR-084): %w", rdef.Name, err)
				}
			}
			linked := map[uint]bool{}
			if reused {
				have, err := tx.GetRolePermissions(ctx, role.ID)
				if err != nil {
					return fmt.Errorf("failed to read permissions of role %s: %w", rdef.Name, err)
				}
				for _, p := range have {
					linked[p.ID] = true
				}
			}
			for _, name := range rdef.Permissions {
				if linked[permIDs[name]] {
					continue
				}
				if err := tx.AssignPermissionToRole(ctx, role.ID, permIDs[name]); err != nil {
					return fmt.Errorf("failed to assign permission %s to role %s: %w", name, rdef.Name, err)
				}
			}
		}

		createdUser, err = tx.CreateUser(ctx, user, req.Password)
		if err != nil {
			if errors.Is(err, storage.ErrDuplicateEmail) {
				return fmt.Errorf("failed to create admin user: %w: user with email already exists", ErrUserAlreadyExists)
			}
			return fmt.Errorf("failed to create admin user: %w", err)
		}

		// Baseline system_viewer (ADR-021) and the global admin role. Unlike plain
		// CreateUser, both are fatal here: the roles were seeded a moment ago in
		// this same transaction, so a failure is a real fault, and the whole
		// bootstrap must roll back rather than leave an admin without rights.
		if err := tx.AssignRole(ctx, createdUser.ID, roleIDs["system_viewer"], Scope{}); err != nil {
			return fmt.Errorf("failed to assign system_viewer role to admin user: %w", err)
		}
		if err := tx.AssignRole(ctx, createdUser.ID, roleIDs["admin"], Scope{}); err != nil {
			return fmt.Errorf("failed to assign admin role to user: %w", err)
		}

		project, err = tx.CreateProject(ctx, &models.Project{
			Name:        "default",
			Description: "Default project",
		})
		if err != nil {
			return fmt.Errorf("failed to create default project: %w", err)
		}

		envs = make([]*models.Environment, 0, len(defaultEnvironmentNames))
		for _, name := range defaultEnvironmentNames {
			env, err := tx.CreateEnvironment(ctx, &models.Environment{Name: name, ProjectID: project.ID})
			if err != nil {
				return fmt.Errorf("failed to create environment %s: %w", name, err)
			}
			envs = append(envs, env)
		}

		if err := tx.SetSystemMetadata(ctx, systemInitializedKey, "1"); err != nil {
			return fmt.Errorf("failed to record system initialisation state: %w", err)
		}
		return nil
	})
	if txErr != nil {
		return nil, txErr
	}

	// Audit only AFTER the transaction has committed: an event written inside
	// (or before) it would claim success for a bootstrap that then rolled back.
	// actorID 0 = the system itself (no authenticated actor exists yet).
	c.LogUserCreated(ctx, 0, createdUser.ID, createdUser.Username)
	c.LogProjectCreated(ctx, 0, project.ID, project.Name)

	// Seed password history with the initial password (ADR-025), best-effort
	// and after commit, exactly as CreateUser does for every other user.
	if c.passwordPolicy.HistoryCount > 0 {
		besteffort.Run(ctx, "auth_bootstrap.BootstrapSystem.AddPasswordHistory", func() error {
			return c.storage.AddPasswordHistory(ctx, createdUser.ID, hash, c.now())
		})
	}

	// The bootstrap token is single-use: clear it so a captured/logged token (see
	// GenerateBootstrapToken) can never re-open initialisation later, even before
	// considering the marker above.
	c.bootstrapToken = ""

	return &BootstrapResult{
		AlreadyInitialized: false,
		User:               createdUser,
		Project:            project,
		Environments:       envs,
	}, nil
}

// currentBootstrapState returns an idempotent BootstrapResult for an already-initialised system.
// Best-effort: partial results are acceptable since the caller only uses this for display output.
func (c *KeyorixCore) currentBootstrapState(ctx context.Context) (*BootstrapResult, error) {
	users, _, err := c.storage.ListUsers(ctx, &storage.UserFilter{Page: 1, PageSize: 1})
	var firstUser *models.User
	if err == nil && len(users) > 0 {
		firstUser = users[0]
	}

	projects, projErr := c.storage.ListProjects(ctx)
	var project *models.Project
	if projErr == nil && len(projects) > 0 {
		project = projects[0]
	}

	envs, envErr := c.storage.ListEnvironments(ctx)
	if envErr != nil {
		envs = nil
	}

	return &BootstrapResult{
		AlreadyInitialized: true,
		User:               firstUser,
		Project:            project,
		Environments:       envs,
	}, nil
}

// SystemNeedsBootstrap reports whether the install has never completed
// initialisation (i.e. POST /system/init would seed the first admin). The server
// uses this at startup to decide whether to surface the bootstrap token to the
// operator. Checks the permanent systemInitializedKey marker first — see its doc
// comment — falling back to the live user count only for a pre-fix install that
// never wrote the marker.
func (c *KeyorixCore) SystemNeedsBootstrap(ctx context.Context) (bool, error) {
	if _, found, err := c.storage.GetSystemMetadata(ctx, systemInitializedKey); err != nil {
		return false, err
	} else if found {
		return false, nil
	}
	_, total, err := c.storage.ListUsers(ctx, &storage.UserFilter{Page: 1, PageSize: 1})
	if err != nil {
		return false, err
	}
	return total == 0, nil
}

// GenerateBootstrapToken returns a fresh, high-entropy bootstrap token. The server
// uses it when no KEYORIX_BOOTSTRAP_TOKEN is configured, logging the value so the
// operator can initialise the (still-empty) install.
func GenerateBootstrapToken() (string, error) {
	return randToken()
}
