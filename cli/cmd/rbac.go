// rbac.go ports `keyorix rbac` (docs/cli-split-inventory.md §2.3, PR 3):
// role-based access control management, REST only. Same flags, output, and exit
// codes as the old CLI's internal/cli/rbac package's remote-mode branch
// (ADR-108 Decision A removes local mode entirely -- every command here is the
// "remote" branch of its old-CLI counterpart, ported unchanged from
// internal/cli/rbac/remote.go).
//
// Two embedded-mode-only findings from docs/cli-split-inventory.md §8 are moot
// by construction here, not silently dropped: Finding S11/D1 (assign-role/
// remove-role's embedded-mode actor-0 attribution: internal/core.
// AssignUserRoleScoped/RemoveUserRoleScoped took no actor parameter) and
// Finding S9 (invite list's embedded-only stricter-than-REST check) both only
// existed on the embedded (direct-DB) code path this CLI never has. Every
// command below goes through the real HTTP API, whose real authenticated
// session is the actor -- decided explicitly, per the inventory's own
// instruction, rather than left unaddressed.
package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

var rbacCmd = &cobra.Command{
	Use:   "rbac",
	Short: "Role-Based Access Control management commands",
}

func init() {
	rootCmd.AddCommand(rbacCmd)
}

// rbacAPIClient resolves the stored credentials and builds a client, the
// shared pre-flight every rbac subcommand needs.
func rbacAPIClient() (*apiclient.ClientWithResponses, error) {
	store, err := resolveCredStore()
	if err != nil {
		return nil, fmt.Errorf("resolve credential store: %w", err)
	}
	serverURL, token, err := resolveServerAndToken(store)
	if err != nil {
		return nil, err
	}
	return newAPIClient(serverURL, token)
}

// ── shared resolution helpers (ported from internal/cli/rbac/remote.go) ────────

// resolveRBACProjectIDByName finds a project's ID by name via GET /api/v1/projects,
// case-insensitively -- matches the old CLI's rbac package exactly (distinct
// from machine.go's resolveMachineProjectID, which matches case-sensitively).
func resolveRBACProjectIDByName(ctx context.Context, client *apiclient.ClientWithResponses, name string) (int, error) {
	_, id, err := resolveProjectRef(ctx, client, name, true)
	return id, err
}

// resolveRBACEnvironmentIDByName finds an environment's ID by name WITHIN a
// specific project, via the project-scoped GET /api/v1/projects/{id}/environments
// -- never the deployment-wide listing, so a name that doesn't exist in the
// target project can't silently resolve to a same-named environment in a
// different project (G78).
func resolveRBACEnvironmentIDByName(ctx context.Context, client *apiclient.ClientWithResponses, projectID int, name string) (int, error) {
	resp, err := client.ListProjectEnvironmentsWithResponse(ctx, uint32(projectID), nil) // #nosec G115 -- projectID comes from a resolved project ID (already a small positive int from the server's own listing)
	if err != nil {
		return 0, fmt.Errorf("failed to list environments: %w", err)
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil || resp.JSON200.Data.Environments == nil {
		return 0, httpStatusError("failed to list environments", resp.StatusCode(), resp.Body)
	}
	for _, e := range *resp.JSON200.Data.Environments {
		if e.Name != nil && strings.EqualFold(*e.Name, name) {
			return derefInt(e.Id), nil
		}
	}
	return 0, fmt.Errorf("environment %q not found in project", name)
}

// resolveUserIDByEmail finds a user's ID by email via GET /api/v1/users,
// mirroring the old CLI's exact page_size=1000 fetch-all-then-filter approach.
func resolveUserIDByEmail(ctx context.Context, client *apiclient.ClientWithResponses, email string) (int, error) {
	pageSize := 1000
	resp, err := client.ListUsersWithResponse(ctx, &apiclient.ListUsersParams{PageSize: &pageSize})
	if err != nil {
		return 0, fmt.Errorf("failed to list users: %w", err)
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil || resp.JSON200.Data.Users == nil {
		return 0, httpStatusError("failed to list users", resp.StatusCode(), resp.Body)
	}
	for _, u := range *resp.JSON200.Data.Users {
		if u.Email != nil && strings.EqualFold(*u.Email, email) {
			return derefInt(u.Id), nil
		}
	}
	return 0, fmt.Errorf("user %q not found", email)
}

// fetchRoles returns all roles via GET /api/v1/roles.
func fetchRoles(ctx context.Context, client *apiclient.ClientWithResponses) ([]apiclient.RoleWithPermissions, error) {
	resp, err := client.ListRolesWithResponse(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list roles: %w", err)
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return nil, httpStatusError("failed to list roles", resp.StatusCode(), resp.Body)
	}
	return derefRoleSlice(resp.JSON200.Data.Roles), nil
}

// resolveRoleIDByName finds a role's ID by name via GET /api/v1/roles.
func resolveRoleIDByName(ctx context.Context, client *apiclient.ClientWithResponses, name string) (int, error) {
	roles, err := fetchRoles(ctx, client)
	if err != nil {
		return 0, err
	}
	for _, r := range roles {
		if r.Name != nil && strings.EqualFold(*r.Name, name) {
			return derefInt(r.Id), nil
		}
	}
	return 0, fmt.Errorf("role %q not found — run 'keyorix rbac list-roles' to see available roles", name)
}

// fetchUserRoles returns the roles assigned to a user via GET /api/v1/users/{id}/roles.
func fetchUserRoles(ctx context.Context, client *apiclient.ClientWithResponses, userID int) ([]apiclient.RoleRef, error) {
	resp, err := client.GetUserRolesForUserWithResponse(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return nil, httpStatusError("failed to get user roles", resp.StatusCode(), resp.Body)
	}
	return derefRoleRefSlice(resp.JSON200.Data.Roles), nil
}

// userEffectivePermissions returns the de-duplicated set of permission names a
// user holds, composed from each assigned role's permissions
// (GET /api/v1/roles/{id}/permissions) -- there is no single by-email
// permission endpoint, so the union is assembled client-side, same as the old CLI.
func userEffectivePermissions(ctx context.Context, client *apiclient.ClientWithResponses, userID int) ([]string, error) {
	roles, err := fetchUserRoles(ctx, client, userID)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var names []string
	for _, role := range roles {
		resp, err := client.GetRolePermissionsWithResponse(ctx, derefInt(role.Id))
		if err != nil {
			return nil, fmt.Errorf("failed to get permissions for role %q: %w", derefStr(role.Name), err)
		}
		if resp.JSON200 == nil || resp.JSON200.Data == nil {
			return nil, httpStatusError(fmt.Sprintf("failed to get permissions for role %q", derefStr(role.Name)), resp.StatusCode(), resp.Body)
		}
		for _, p := range derefPermissionSlice(resp.JSON200.Data.Permissions) {
			name := derefStr(p.Name)
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			names = append(names, name)
		}
	}
	return names, nil
}

// scopeSuffix returns a human-readable scope qualifier for display messages.
func scopeSuffix(project, env string) string {
	if project == "" {
		return ""
	}
	if env != "" {
		return fmt.Sprintf(" in project '%s' / environment '%s'", project, env)
	}
	return fmt.Sprintf(" in project '%s'", project)
}

// ── slice/pointer deref helpers ─────────────────────────────────────────────────

func derefRoleSlice(s *[]apiclient.RoleWithPermissions) []apiclient.RoleWithPermissions {
	if s == nil {
		return nil
	}
	return *s
}

func derefRoleRefSlice(s *[]apiclient.RoleRef) []apiclient.RoleRef {
	if s == nil {
		return nil
	}
	return *s
}

func derefPermissionSlice(s *[]apiclient.Permission) []apiclient.Permission {
	if s == nil {
		return nil
	}
	return *s
}

// ── assign-role ─────────────────────────────────────────────────────────────────

var (
	rbacUserEmail     string
	rbacRoleName      string
	rbacRoleTTL       time.Duration
	rbacAssignProject string
	rbacAssignEnv     string
)

var rbacAssignRoleCmd = &cobra.Command{
	Use:   "assign-role",
	Short: "Assign a role to a user",
	Long: `Assign a role to a user by email address.

With --project, the grant is scoped to that project only (rather than globally).
With --environment, the grant is further narrowed to a single environment within
that project (--project must also be supplied).

With --ttl, the grant is time-bound (just-in-time access): it stops authorizing
once the window passes and is swept automatically. Useful for emergency or
contractor access. Example: --ttl 4h grants the role for four hours.`,
	RunE: runRBACAssignRole,
}

func init() {
	rbacAssignRoleCmd.Flags().StringVar(&rbacUserEmail, "user", "", "User email address (required)")
	rbacAssignRoleCmd.Flags().StringVar(&rbacRoleName, "role", "", "Role name to assign (required)")
	rbacAssignRoleCmd.Flags().DurationVar(&rbacRoleTTL, "ttl", 0, "Time-bound grant lifetime (e.g. 4h, 30m); omit for a permanent grant")
	rbacAssignRoleCmd.Flags().StringVar(&rbacAssignProject, "project", "", "Scope the grant to this project (optional)")
	rbacAssignRoleCmd.Flags().StringVar(&rbacAssignEnv, "environment", "", "Scope the grant to this environment within --project (optional; requires --project)")
	rbacCmd.AddCommand(rbacAssignRoleCmd)
}

func runRBACAssignRole(cmd *cobra.Command, args []string) error {
	if rbacUserEmail == "" || rbacRoleName == "" {
		return usageErrorf("--user and --role are required")
	}
	if rbacRoleTTL < 0 {
		return fmt.Errorf("--ttl must be positive")
	}
	if rbacAssignEnv != "" && rbacAssignProject == "" {
		return fmt.Errorf("--environment requires --project")
	}
	client, err := rbacAPIClient()
	if err != nil {
		return err
	}
	ctx := context.Background()

	userID, err := resolveUserIDByEmail(ctx, client, rbacUserEmail)
	if err != nil {
		return err
	}
	roleID, err := resolveRoleIDByName(ctx, client, rbacRoleName)
	if err != nil {
		return err
	}
	body := apiclient.AssignUserRoleJSONRequestBody{UserId: userID, RoleId: roleID}
	if rbacRoleTTL > 0 {
		exp := time.Now().Add(rbacRoleTTL).UTC()
		body.ExpiresAt = &exp
	}
	if rbacAssignProject != "" {
		projectID, err := resolveRBACProjectIDByName(ctx, client, rbacAssignProject)
		if err != nil {
			return err
		}
		body.ProjectId = &projectID
		if rbacAssignEnv != "" {
			envID, err := resolveRBACEnvironmentIDByName(ctx, client, projectID, rbacAssignEnv)
			if err != nil {
				return err
			}
			body.EnvironmentId = &envID
		}
	}
	resp, err := client.AssignUserRoleWithResponse(ctx, body)
	if err != nil {
		return fmt.Errorf("failed to assign role: %w", err)
	}
	if resp.JSON201 == nil {
		return httpStatusError("failed to assign role", resp.StatusCode(), resp.Body)
	}
	suffix := scopeSuffix(rbacAssignProject, rbacAssignEnv)
	if rbacRoleTTL > 0 {
		fmt.Printf("Assigned role '%s' to user '%s'%s for %s (time-bound)\n", rbacRoleName, rbacUserEmail, suffix, rbacRoleTTL)
	} else {
		fmt.Printf("Successfully assigned role '%s' to user '%s'%s\n", rbacRoleName, rbacUserEmail, suffix)
	}
	return nil
}

// ── remove-role ─────────────────────────────────────────────────────────────────

var (
	rbacRemoveUserEmail string
	rbacRemoveRoleName  string
	rbacRemoveProject   string
	rbacRemoveEnv       string
)

var rbacRemoveRoleCmd = &cobra.Command{
	Use:   "remove-role",
	Short: "Remove a role from a user",
	Long: `Remove a role assignment from a user by email address.

With --project, removes only the grant scoped to that project.
With --environment, removes only the grant scoped to that environment within
the project (--project must also be supplied).`,
	RunE: runRBACRemoveRole,
}

func init() {
	rbacRemoveRoleCmd.Flags().StringVar(&rbacRemoveUserEmail, "user", "", "User email address (required)")
	rbacRemoveRoleCmd.Flags().StringVar(&rbacRemoveRoleName, "role", "", "Role name to remove (required)")
	rbacRemoveRoleCmd.Flags().StringVar(&rbacRemoveProject, "project", "", "Remove the grant scoped to this project (optional)")
	rbacRemoveRoleCmd.Flags().StringVar(&rbacRemoveEnv, "environment", "", "Remove the grant scoped to this environment within --project (optional; requires --project)")
	rbacCmd.AddCommand(rbacRemoveRoleCmd)
}

func runRBACRemoveRole(cmd *cobra.Command, args []string) error {
	if rbacRemoveUserEmail == "" || rbacRemoveRoleName == "" {
		return usageErrorf("--user and --role are required")
	}
	if rbacRemoveEnv != "" && rbacRemoveProject == "" {
		return fmt.Errorf("--environment requires --project")
	}
	client, err := rbacAPIClient()
	if err != nil {
		return err
	}
	ctx := context.Background()

	userID, err := resolveUserIDByEmail(ctx, client, rbacRemoveUserEmail)
	if err != nil {
		return err
	}
	roleID, err := resolveRoleIDByName(ctx, client, rbacRemoveRoleName)
	if err != nil {
		return err
	}
	body := apiclient.RemoveUserRoleJSONRequestBody{UserId: userID, RoleId: roleID}
	if rbacRemoveProject != "" {
		projectID, err := resolveRBACProjectIDByName(ctx, client, rbacRemoveProject)
		if err != nil {
			return err
		}
		body.ProjectId = &projectID
		if rbacRemoveEnv != "" {
			envID, err := resolveRBACEnvironmentIDByName(ctx, client, projectID, rbacRemoveEnv)
			if err != nil {
				return err
			}
			body.EnvironmentId = &envID
		}
	}
	resp, err := client.RemoveUserRoleWithResponse(ctx, body)
	if err != nil {
		return fmt.Errorf("failed to remove role: %w", err)
	}
	if resp.StatusCode() != 204 {
		return httpStatusError("failed to remove role", resp.StatusCode(), resp.Body)
	}
	suffix := scopeSuffix(rbacRemoveProject, rbacRemoveEnv)
	fmt.Printf("Successfully removed role '%s' from user '%s'%s\n", rbacRemoveRoleName, rbacRemoveUserEmail, suffix)
	return nil
}
