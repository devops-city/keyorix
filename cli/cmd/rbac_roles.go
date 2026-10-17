package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// ── list-roles ──────────────────────────────────────────────────────────────────

var rbacListRolesCmd = &cobra.Command{
	Use:   "list-roles",
	Short: "List all available roles",
	Long:  "List all roles in the system",
	RunE:  runRBACListRoles,
}

func init() {
	rbacCmd.AddCommand(rbacListRolesCmd)
}

func runRBACListRoles(cmd *cobra.Command, args []string) error {
	client, err := rbacAPIClient()
	if err != nil {
		return err
	}
	roles, err := fetchRoles(context.Background(), client)
	if err != nil {
		return err
	}
	if len(roles) == 0 {
		fmt.Println("No roles found")
		return nil
	}
	fmt.Println("Available roles:")
	for _, role := range roles {
		fmt.Printf("  - %s: %s\n", derefStr(role.Name), derefStr(role.Description))
	}
	return nil
}

// ── list-user-roles ─────────────────────────────────────────────────────────────

var rbacListUserRolesEmail string

var rbacListUserRolesCmd = &cobra.Command{
	Use:   "list-user-roles",
	Short: "List roles assigned to a user",
	Long:  "List all roles assigned to a specific user by email address",
	RunE:  runRBACListUserRoles,
}

func init() {
	rbacListUserRolesCmd.Flags().StringVar(&rbacListUserRolesEmail, "user", "", "User email address (required)")
	rbacCmd.AddCommand(rbacListUserRolesCmd)
}

func runRBACListUserRoles(cmd *cobra.Command, args []string) error {
	if rbacListUserRolesEmail == "" {
		return usageErrorf("--user is required")
	}
	client, err := rbacAPIClient()
	if err != nil {
		return err
	}
	ctx := context.Background()
	userID, err := resolveUserIDByEmail(ctx, client, rbacListUserRolesEmail)
	if err != nil {
		return err
	}
	roles, err := fetchUserRoles(ctx, client, userID)
	if err != nil {
		return err
	}
	if len(roles) == 0 {
		fmt.Printf("No roles assigned to user '%s'\n", rbacListUserRolesEmail)
		return nil
	}
	fmt.Printf("Roles assigned to user '%s':\n", rbacListUserRolesEmail)
	for _, role := range roles {
		fmt.Printf("  - %s\n", derefStr(role.Name))
	}
	return nil
}

// ── list-permissions ────────────────────────────────────────────────────────────

var rbacListPermissionsEmail string

var rbacListPermissionsCmd = &cobra.Command{
	Use:   "list-permissions",
	Short: "List all permissions for a user",
	Long:  "List all permissions assigned to a user through their roles",
	RunE:  runRBACListPermissions,
}

func init() {
	rbacListPermissionsCmd.Flags().StringVar(&rbacListPermissionsEmail, "user", "", "User email address (required)")
	rbacCmd.AddCommand(rbacListPermissionsCmd)
}

func runRBACListPermissions(cmd *cobra.Command, args []string) error {
	if rbacListPermissionsEmail == "" {
		return usageErrorf("--user is required")
	}
	client, err := rbacAPIClient()
	if err != nil {
		return err
	}
	ctx := context.Background()
	userID, err := resolveUserIDByEmail(ctx, client, rbacListPermissionsEmail)
	if err != nil {
		return err
	}
	perms, err := userEffectivePermissions(ctx, client, userID)
	if err != nil {
		return err
	}
	if len(perms) == 0 {
		fmt.Printf("No permissions found for user '%s'\n", rbacListPermissionsEmail)
		return nil
	}
	fmt.Printf("Permissions for user '%s':\n", rbacListPermissionsEmail)
	for _, p := range perms {
		fmt.Printf("  - %s\n", p)
	}
	return nil
}

// ── check-permission ────────────────────────────────────────────────────────────

var (
	rbacCheckUserEmail string
	rbacCheckPermName  string
)

var rbacCheckPermissionCmd = &cobra.Command{
	Use:   "check-permission",
	Short: "Check if a user has a specific permission",
	Long:  "Check if a user has a specific permission by email address and permission name",
	RunE:  runRBACCheckPermission,
}

func init() {
	rbacCheckPermissionCmd.Flags().StringVar(&rbacCheckUserEmail, "user", "", "User email address (required)")
	rbacCheckPermissionCmd.Flags().StringVar(&rbacCheckPermName, "permission", "", "Permission name to check (required)")
	rbacCmd.AddCommand(rbacCheckPermissionCmd)
}

func runRBACCheckPermission(cmd *cobra.Command, args []string) error {
	if rbacCheckUserEmail == "" || rbacCheckPermName == "" {
		return usageErrorf("--user and --permission are required")
	}
	// Validate the "resource.action" shape up front for a clear error, matching the old CLI.
	if _, _, err := splitPermissionName(rbacCheckPermName); err != nil {
		return err
	}
	client, err := rbacAPIClient()
	if err != nil {
		return err
	}
	ctx := context.Background()
	userID, err := resolveUserIDByEmail(ctx, client, rbacCheckUserEmail)
	if err != nil {
		return err
	}
	perms, err := userEffectivePermissions(ctx, client, userID)
	if err != nil {
		return err
	}
	for _, p := range perms {
		if strings.EqualFold(p, rbacCheckPermName) {
			fmt.Printf("User '%s' has permission '%s'\n", rbacCheckUserEmail, rbacCheckPermName)
			return nil
		}
	}
	fmt.Printf("User '%s' does NOT have permission '%s'\n", rbacCheckUserEmail, rbacCheckPermName)
	return nil
}

// splitPermissionName parses a "resource.action" permission name into its parts.
func splitPermissionName(name string) (resource, action string, err error) {
	parts := strings.SplitN(name, ".", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("permission must be in 'resource.action' form (e.g. secrets.read), got %q", name)
	}
	return parts[0], parts[1], nil
}
