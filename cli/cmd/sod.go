// sod.go ports `keyorix sod` (docs/cli-split-inventory.md §2.6, PR 8): separation-of-duties
// policies and violation detection (ISO 27001 A.5.3 / SOX). Same flags, output, and exit
// codes as the old CLI's internal/cli/sod package -- a pure transport port, not a behavior
// change.
package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
	"github.com/keyorixhq/keyorix/cli/internal/cliout"
)

var sodCmd = &cobra.Command{
	Use:   "sod",
	Short: "Separation-of-duties policies and violations (ISO 27001 A.5.3)",
	Long:  "Define toxic permission combinations and find the principals who hold both sides.",
}

var sodPolicyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage separation-of-duties policies",
}

func init() {
	sodPolicyCmd.AddCommand(sodPolicyListCmd, sodPolicyCreateCmd, sodPolicyDeleteCmd)
	sodCmd.AddCommand(sodPolicyCmd, sodViolationsCmd)
	rootCmd.AddCommand(sodCmd)
}

type sodPolicyView struct {
	ID          uint   `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	PermissionA string `json:"permission_a"`
	PermissionB string `json:"permission_b"`
}

type sodViolationView struct {
	PolicyName  string `json:"policy_name"`
	Username    string `json:"username"`
	Email       string `json:"email"`
	PermissionA string `json:"permission_a"`
	PermissionB string `json:"permission_b"`
}

var (
	sodName  string
	sodDesc  string
	sodPermA string
	sodPermB string
	sodID    uint32
)

var sodPolicyListCmd = &cobra.Command{
	Use:          "list",
	Short:        "List separation-of-duties policies",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if err := checkOutputFormat(sodListFormat); err != nil {
			return err
		}
		ctx := context.Background()
		client, err := apiClientWithSkewCheck(ctx)
		if err != nil {
			return err
		}
		resp, err := client.ListSoDPoliciesWithResponse(ctx)
		if err != nil {
			return err
		}
		if resp.StatusCode() != 200 {
			return apiError("list SoD policies", resp.StatusCode(), resp.Body)
		}
		out, err := decodeData[struct {
			Policies []sodPolicyView `json:"policies"`
			Count    int             `json:"count"`
		}](resp.Body)
		if err != nil {
			return err
		}
		return emitList(sodListFormat, out.Policies, func() error {
			if out.Count == 0 {
				fmt.Println("No separation-of-duties policies defined.")
				return nil
			}
			fmt.Printf("%-5s %-26s %-22s %s\n", "ID", "NAME", "PERMISSION A", "PERMISSION B")
			for _, p := range out.Policies {
				fmt.Printf("%-5d %-26s %-22s %s\n", p.ID, truncateRunes(cliout.SanitizeForTerminal(p.Name), 26), p.PermissionA, p.PermissionB)
			}
			return nil
		})
	},
}

var sodPolicyCreateCmd = &cobra.Command{
	Use:          "create",
	Short:        "Create a separation-of-duties policy (two conflicting permissions)",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if sodName == "" || sodPermA == "" || sodPermB == "" {
			return fmt.Errorf("--name, --permission-a and --permission-b are required")
		}
		ctx := context.Background()
		client, err := apiClientWithSkewCheck(ctx)
		if err != nil {
			return err
		}
		body := apiclient.CreateSoDPolicyJSONRequestBody{
			Name: sodName, Description: &sodDesc, PermissionA: sodPermA, PermissionB: sodPermB,
		}
		resp, err := client.CreateSoDPolicyWithResponse(ctx, body)
		if err != nil {
			return err
		}
		if resp.StatusCode() != 200 && resp.StatusCode() != 201 {
			return apiError("create SoD policy", resp.StatusCode(), resp.Body)
		}
		out, err := decodeData[struct {
			Policy sodPolicyView `json:"policy"`
		}](resp.Body)
		if err != nil {
			return err
		}
		fmt.Printf("Created SoD policy %d (%q): %s + %s must not be held together.\n", out.Policy.ID, sodName, sodPermA, sodPermB)
		return nil
	},
}

var sodPolicyDeleteCmd = &cobra.Command{
	Use:          "delete",
	Short:        "Delete a separation-of-duties policy",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if sodID == 0 {
			return fmt.Errorf("--id is required")
		}
		ctx := context.Background()
		client, err := apiClientWithSkewCheck(ctx)
		if err != nil {
			return err
		}
		resp, err := client.DeleteSoDPolicyWithResponse(ctx, sodID)
		if err != nil {
			return err
		}
		if resp.StatusCode() != 200 && resp.StatusCode() != 204 {
			return apiError("delete SoD policy", resp.StatusCode(), resp.Body)
		}
		fmt.Printf("Deleted SoD policy %d.\n", sodID)
		return nil
	},
}

var sodViolationsCmd = &cobra.Command{
	Use:          "violations",
	Short:        "List principals that violate a separation-of-duties policy",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx := context.Background()
		client, err := apiClientWithSkewCheck(ctx)
		if err != nil {
			return err
		}
		resp, err := client.ListSoDViolationsWithResponse(ctx)
		if err != nil {
			return err
		}
		if resp.StatusCode() != 200 {
			return apiError("list SoD violations", resp.StatusCode(), resp.Body)
		}
		out, err := decodeData[struct {
			Violations      []sodViolationView `json:"violations"`
			Count           int                `json:"count"`
			Degraded        bool               `json:"degraded"`
			DegradedReasons []string           `json:"degraded_reasons"`
		}](resp.Body)
		if err != nil {
			return err
		}
		if out.Degraded {
			fmt.Println("*** DEGRADED SCAN — one or more principals' permissions could not be read ***")
			fmt.Println("*** This list may be MISSING a violation for them.                        ***")
			for _, reason := range out.DegradedReasons {
				fmt.Printf("    - %s\n", reason)
			}
			fmt.Println()
		}
		if out.Count == 0 {
			fmt.Println("No separation-of-duties violations.")
			return nil
		}
		fmt.Printf("%d violation(s):\n\n", out.Count)
		fmt.Printf("%-26s %-22s %-22s %s\n", "POLICY", "USER", "PERMISSION A", "PERMISSION B")
		for _, v := range out.Violations {
			user := v.Username
			if v.Email != "" {
				user = fmt.Sprintf("%s <%s>", v.Username, v.Email)
			}
			fmt.Printf("%-26s %-22s %-22s %s\n", truncateRunes(cliout.SanitizeForTerminal(v.PolicyName), 26), truncateRunes(cliout.SanitizeForTerminal(user), 22), v.PermissionA, v.PermissionB)
		}
		return nil
	},
}

// truncateRunes truncates s to at most n runes, appending an ellipsis when it does.
// Mirrors the old CLI's internal/cli/sod.truncate exactly.
func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "…"
}

func init() {
	sodPolicyCreateCmd.Flags().StringVar(&sodName, "name", "", "Policy name (required)")
	sodPolicyCreateCmd.Flags().StringVar(&sodDesc, "description", "", "Description")
	sodPolicyCreateCmd.Flags().StringVar(&sodPermA, "permission-a", "", "First permission, e.g. roles.assign (required)")
	sodPolicyCreateCmd.Flags().StringVar(&sodPermB, "permission-b", "", "Second permission, e.g. secrets.delete (required)")
	sodPolicyDeleteCmd.Flags().Uint32Var(&sodID, "id", 0, "Policy ID to delete (required)")
}
