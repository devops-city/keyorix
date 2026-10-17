// rbac_group_roles.go — RBAC subcommands for managing group role assignments.
// The group-side counterparts to assign-role/remove-role/list-user-roles.
package cmd

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

const rbacGroupFlagUsage = "Group name or numeric ID (required)"

// resolveRBACGroupID resolves a group name or numeric ID string to a group ID
// and its display name via GET /api/v1/groups -- a value that parses as an
// integer is used directly (matches the old CLI's rbac package).
func resolveRBACGroupID(ctx context.Context, client *apiclient.ClientWithResponses, nameOrID string) (int, string, error) {
	if id, err := strconv.Atoi(nameOrID); err == nil {
		return id, nameOrID, nil
	}
	resp, err := client.ListGroupsWithResponse(ctx)
	if err != nil {
		return 0, "", fmt.Errorf("failed to list groups: %w", err)
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil || resp.JSON200.Data.Groups == nil {
		return 0, "", httpStatusError("failed to list groups", resp.StatusCode(), resp.Body)
	}
	for _, g := range *resp.JSON200.Data.Groups {
		if g.Name != nil && strings.EqualFold(*g.Name, nameOrID) {
			return derefInt(g.Id), derefStr(g.Name), nil
		}
	}
	return 0, "", fmt.Errorf("group %q not found", nameOrID)
}

const rbacGroupRoleTableFmt = "%-20s %-35s %-10s\n"

func printRBACGroupRoleTable(roles []apiclient.GroupRoleGrant) {
	fmt.Printf(rbacGroupRoleTableFmt, "ROLE", "DESCRIPTION", "EXPIRES")
	fmt.Printf(rbacGroupRoleTableFmt, strings.Repeat("-", 20), strings.Repeat("-", 35), strings.Repeat("-", 10))
	for _, r := range roles {
		exp := "never"
		if r.ExpiresAt != nil {
			exp = r.ExpiresAt.UTC().Format("2006-01-02 15:04:05 UTC")
		}
		fmt.Printf(rbacGroupRoleTableFmt, derefStr(r.Name), derefStr(r.Description), exp)
	}
}

// ── assign-role-to-group ────────────────────────────────────────────────────────

var (
	rbacGroupRoleGroupFlag string
	rbacGroupRoleName      string
	rbacGroupRoleProject   string
	rbacGroupRoleEnv       string
	rbacGroupRoleTTL       time.Duration
)

var rbacAssignRoleToGroupCmd = &cobra.Command{
	Use:   "assign-role-to-group",
	Short: "Assign a role to a group",
	Long: `Assign a role to a group.

With --project, the grant is scoped to that project only.
With --environment, the grant is further narrowed to a single environment within
that project (--project must also be supplied).

With --ttl, the grant is time-bound (just-in-time access).`,
	RunE: runRBACAssignRoleToGroup,
}

func init() {
	rbacAssignRoleToGroupCmd.Flags().StringVar(&rbacGroupRoleGroupFlag, "group", "", rbacGroupFlagUsage)
	rbacAssignRoleToGroupCmd.Flags().StringVar(&rbacGroupRoleName, "role", "", "Role name to assign (required)")
	rbacAssignRoleToGroupCmd.Flags().StringVar(&rbacGroupRoleProject, "project", "", "Scope the grant to this project (optional)")
	rbacAssignRoleToGroupCmd.Flags().StringVar(&rbacGroupRoleEnv, "environment", "", "Scope the grant to this environment within --project (optional; requires --project)")
	rbacAssignRoleToGroupCmd.Flags().DurationVar(&rbacGroupRoleTTL, "ttl", 0, "Time-bound grant lifetime (e.g. 4h, 30m); omit for a permanent grant")
	rbacCmd.AddCommand(rbacAssignRoleToGroupCmd)
}

func runRBACAssignRoleToGroup(cmd *cobra.Command, args []string) error {
	if rbacGroupRoleGroupFlag == "" || rbacGroupRoleName == "" {
		return usageErrorf("--group and --role are required")
	}
	if rbacGroupRoleTTL < 0 {
		return fmt.Errorf("--ttl must be positive")
	}
	if rbacGroupRoleEnv != "" && rbacGroupRoleProject == "" {
		return fmt.Errorf("--environment requires --project")
	}
	client, err := rbacAPIClient()
	if err != nil {
		return err
	}
	ctx := context.Background()

	groupID, groupName, err := resolveRBACGroupID(ctx, client, rbacGroupRoleGroupFlag)
	if err != nil {
		return err
	}
	roleID, err := resolveRoleIDByName(ctx, client, rbacGroupRoleName)
	if err != nil {
		return err
	}
	body := apiclient.AssignRoleToGroupJSONRequestBody{RoleId: roleID}
	if rbacGroupRoleTTL > 0 {
		exp := time.Now().Add(rbacGroupRoleTTL).UTC()
		body.ExpiresAt = &exp
	}
	if rbacGroupRoleProject != "" {
		projectID, err := resolveRBACProjectIDByName(ctx, client, rbacGroupRoleProject)
		if err != nil {
			return err
		}
		body.ProjectId = &projectID
		if rbacGroupRoleEnv != "" {
			envID, err := resolveRBACEnvironmentIDByName(ctx, client, projectID, rbacGroupRoleEnv)
			if err != nil {
				return err
			}
			body.EnvironmentId = &envID
		}
	}
	resp, err := client.AssignRoleToGroupWithResponse(ctx, groupID, body)
	if err != nil {
		return fmt.Errorf("failed to assign role: %w", err)
	}
	if resp.JSON201 == nil {
		return httpStatusError("failed to assign role", resp.StatusCode(), resp.Body)
	}
	suffix := scopeSuffix(rbacGroupRoleProject, rbacGroupRoleEnv)
	if rbacGroupRoleTTL > 0 {
		fmt.Printf("Assigned role '%s' to group '%s'%s for %s (time-bound)\n", rbacGroupRoleName, groupName, suffix, rbacGroupRoleTTL)
	} else {
		fmt.Printf("Successfully assigned role '%s' to group '%s'%s\n", rbacGroupRoleName, groupName, suffix)
	}
	return nil
}

// ── remove-role-from-group ──────────────────────────────────────────────────────

var (
	rbacRemoveGroupRoleGroupFlag string
	rbacRemoveGroupRoleName      string
	rbacRemoveGroupRoleProject   string
	rbacRemoveGroupRoleEnv       string
)

var rbacRemoveRoleFromGroupCmd = &cobra.Command{
	Use:   "remove-role-from-group",
	Short: "Remove a role from a group",
	Long: `Remove a role assignment from a group.

With --project, removes only the grant scoped to that project.
With --environment, removes only the grant scoped to that environment within
the project (--project must also be supplied).`,
	RunE: runRBACRemoveRoleFromGroup,
}

func init() {
	rbacRemoveRoleFromGroupCmd.Flags().StringVar(&rbacRemoveGroupRoleGroupFlag, "group", "", rbacGroupFlagUsage)
	rbacRemoveRoleFromGroupCmd.Flags().StringVar(&rbacRemoveGroupRoleName, "role", "", "Role name to remove (required)")
	rbacRemoveRoleFromGroupCmd.Flags().StringVar(&rbacRemoveGroupRoleProject, "project", "", "Remove the grant scoped to this project (optional)")
	rbacRemoveRoleFromGroupCmd.Flags().StringVar(&rbacRemoveGroupRoleEnv, "environment", "", "Remove the grant scoped to this environment within --project (optional; requires --project)")
	rbacCmd.AddCommand(rbacRemoveRoleFromGroupCmd)
}

func runRBACRemoveRoleFromGroup(cmd *cobra.Command, args []string) error {
	if rbacRemoveGroupRoleGroupFlag == "" || rbacRemoveGroupRoleName == "" {
		return usageErrorf("--group and --role are required")
	}
	if rbacRemoveGroupRoleEnv != "" && rbacRemoveGroupRoleProject == "" {
		return fmt.Errorf("--environment requires --project")
	}
	client, err := rbacAPIClient()
	if err != nil {
		return err
	}
	ctx := context.Background()

	groupID, groupName, err := resolveRBACGroupID(ctx, client, rbacRemoveGroupRoleGroupFlag)
	if err != nil {
		return err
	}
	roleID, err := resolveRoleIDByName(ctx, client, rbacRemoveGroupRoleName)
	if err != nil {
		return err
	}
	params := &apiclient.RemoveRoleFromGroupParams{}
	if rbacRemoveGroupRoleProject != "" {
		projectID, err := resolveRBACProjectIDByName(ctx, client, rbacRemoveGroupRoleProject)
		if err != nil {
			return err
		}
		params.ProjectId = &projectID
		if rbacRemoveGroupRoleEnv != "" {
			envID, err := resolveRBACEnvironmentIDByName(ctx, client, projectID, rbacRemoveGroupRoleEnv)
			if err != nil {
				return err
			}
			params.EnvironmentId = &envID
		}
	}
	resp, err := client.RemoveRoleFromGroupWithResponse(ctx, groupID, roleID, params)
	if err != nil {
		return fmt.Errorf("failed to remove role: %w", err)
	}
	if resp.StatusCode() != 204 {
		return httpStatusError("failed to remove role", resp.StatusCode(), resp.Body)
	}
	suffix := scopeSuffix(rbacRemoveGroupRoleProject, rbacRemoveGroupRoleEnv)
	fmt.Printf("Successfully removed role '%s' from group '%s'%s\n", rbacRemoveGroupRoleName, groupName, suffix)
	return nil
}

// ── list-group-roles ─────────────────────────────────────────────────────────────

var rbacListGroupRolesGroupFlag string

var rbacListGroupRolesCmd = &cobra.Command{
	Use:   "list-group-roles",
	Short: "List roles assigned to a group",
	Long:  "List all roles assigned to a specific group.",
	RunE:  runRBACListGroupRoles,
}

func init() {
	rbacListGroupRolesCmd.Flags().StringVar(&rbacListGroupRolesGroupFlag, "group", "", rbacGroupFlagUsage)
	rbacCmd.AddCommand(rbacListGroupRolesCmd)
}

func runRBACListGroupRoles(cmd *cobra.Command, args []string) error {
	if err := checkOutputFormat(groupRolesFormat); err != nil {
		return err
	}
	if rbacListGroupRolesGroupFlag == "" {
		return usageErrorf("--group is required")
	}
	client, err := rbacAPIClient()
	if err != nil {
		return err
	}
	ctx := context.Background()

	groupID, groupName, err := resolveRBACGroupID(ctx, client, rbacListGroupRolesGroupFlag)
	if err != nil {
		return err
	}
	resp, err := client.GetGroupRolesWithResponse(ctx, groupID)
	if err != nil {
		return fmt.Errorf("failed to get group roles: %w", err)
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return httpStatusError("failed to get group roles", resp.StatusCode(), resp.Body)
	}
	roles := derefGroupRoleGrantSlice(resp.JSON200.Data.Roles)
	return emitList(groupRolesFormat, roles, func() error {
		if len(roles) == 0 {
			fmt.Printf("No roles assigned to group '%s'\n", groupName)
			return nil
		}
		printRBACGroupRoleTable(roles)
		return nil
	})
}

func derefGroupRoleGrantSlice(s *[]apiclient.GroupRoleGrant) []apiclient.GroupRoleGrant {
	if s == nil {
		return nil
	}
	return *s
}
