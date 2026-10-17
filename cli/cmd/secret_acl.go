// secret_acl.go — keyorix secret acl list/grant/revoke (RBAC Phase 3): manage
// per-secret ACL grants.
package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

var secretACLCmd = &cobra.Command{
	Use:   "acl",
	Short: "Manage per-secret ACL grants (RBAC Phase 3)",
	Long: `Manage fine-grained per-secret access control (RBAC Phase 3).

An ACL grant allows a specific user to access one secret independently of
their project role. Requires secrets.manage at the secret's project scope.`,
}

func init() {
	SecretCmd.AddCommand(secretACLCmd)
}

var secretACLListCmd = &cobra.Command{
	Use:          "list <secret-id>",
	Short:        "List ACL grants for a secret",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, args []string) error {
		id, err := parseSecretArg(args[0])
		if err != nil {
			return err
		}
		client, err := secretAPIClient()
		if err != nil {
			return err
		}
		resp, err := client.ListSecretACLsWithResponse(context.Background(), id)
		if err != nil {
			return err
		}
		if resp.JSON200 == nil {
			return httpStatusError("list secret ACLs", resp.StatusCode(), resp.Body)
		}
		acls := derefSecretACLSlice(resp.JSON200.Data)
		if len(acls) == 0 {
			fmt.Println("No ACL grants for this secret.")
			return nil
		}
		fmt.Printf("%-6s %-10s %-12s %s\n", "ID", "USER_ID", "GRANTED_BY", "PERMISSIONS")
		for _, a := range acls {
			fmt.Printf("%-6d %-10d %-12d %s\n", derefSecretInt(a.Id), derefSecretInt(a.UserId), derefSecretInt(a.GrantedBy), strings.Join(derefStrSlice(a.Permissions), ","))
		}
		return nil
	},
}

var (
	secretACLGrantSecret int
	secretACLGrantUser   int
	secretACLGrantPerms  []string
)

var secretACLGrantCmd = &cobra.Command{
	Use:          "grant",
	Short:        "Grant a user ACL access to a secret",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		if secretACLGrantSecret == 0 {
			return usageErrorf("--secret <id> is required")
		}
		if secretACLGrantUser == 0 {
			return usageErrorf("--user <user-id> is required")
		}
		if len(secretACLGrantPerms) == 0 {
			return usageErrorf("--perm <permission> is required (e.g. --perm secrets.read)")
		}
		client, err := secretAPIClient()
		if err != nil {
			return err
		}
		resp, err := client.GrantSecretACLWithResponse(context.Background(), secretACLGrantSecret, apiclient.GrantSecretACLJSONRequestBody{
			UserId: secretACLGrantUser, Permissions: secretACLGrantPerms,
		})
		if err != nil {
			return err
		}
		if resp.JSON200 == nil {
			return httpStatusError("grant secret ACL", resp.StatusCode(), resp.Body)
		}
		fmt.Printf("ACL granted: user %d now has %v on secret %d.\n", secretACLGrantUser, secretACLGrantPerms, secretACLGrantSecret)
		return nil
	},
}

var (
	secretACLRevokeSecret int
	secretACLRevokeACL    int
)

var secretACLRevokeCmd = &cobra.Command{
	Use:          "revoke",
	Short:        "Revoke an ACL grant from a secret",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		if secretACLRevokeSecret == 0 {
			return usageErrorf("--secret <id> is required")
		}
		if secretACLRevokeACL == 0 {
			return usageErrorf("--acl <acl-id> is required")
		}
		client, err := secretAPIClient()
		if err != nil {
			return err
		}
		resp, err := client.RevokeSecretACLWithResponse(context.Background(), secretACLRevokeSecret, secretACLRevokeACL)
		if err != nil {
			return err
		}
		if resp.JSON200 == nil {
			return httpStatusError("revoke secret ACL", resp.StatusCode(), resp.Body)
		}
		fmt.Printf("ACL %d revoked from secret %d.\n", secretACLRevokeACL, secretACLRevokeSecret)
		return nil
	},
}

func init() {
	secretACLGrantCmd.Flags().IntVar(&secretACLGrantSecret, "secret", 0, "Secret ID to grant access to")
	secretACLGrantCmd.Flags().IntVar(&secretACLGrantUser, "user", 0, "User ID to grant access to")
	secretACLGrantCmd.Flags().StringArrayVar(&secretACLGrantPerms, "perm", nil, "Permission to grant (secrets.read or secrets.write); may be repeated")

	secretACLRevokeCmd.Flags().IntVar(&secretACLRevokeSecret, "secret", 0, "Secret ID to revoke the ACL from")
	secretACLRevokeCmd.Flags().IntVar(&secretACLRevokeACL, "acl", 0, "ACL entry ID to revoke (from `acl list`)")

	secretACLCmd.AddCommand(secretACLListCmd, secretACLGrantCmd, secretACLRevokeCmd)
}

func derefSecretACLSlice(s *[]apiclient.SecretACL) []apiclient.SecretACL {
	if s == nil {
		return nil
	}
	return *s
}
