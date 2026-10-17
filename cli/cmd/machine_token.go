// machine_token.go — machine identity token management commands (ADR-030).
package cmd

import (
	"bufio"
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

var machineTokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Manage machine identity tokens",
	Long:  "Issue, list, and revoke bearer tokens for a machine identity (ADR-030).",
}

var (
	machineTokenProjectName     string
	machineTokenIssueName       string
	machineTokenIssueExpiryDays int
	machineTokenIssueClass      string
	machineTokenRevokeForce     bool
)

var machineTokenIssueCmd = &cobra.Command{
	Use:          "issue <name|id>",
	Short:        "Issue a new bearer token for a machine identity",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE:         runMachineTokenIssue,
}

var machineTokenListCmd = &cobra.Command{
	Use:          "list <name|id>",
	Short:        "List tokens for a machine identity",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE:         runMachineTokenList,
}

var machineTokenRevokeCmd = &cobra.Command{
	Use:          "revoke <name|id> <token-id>",
	Short:        "Revoke a machine identity token",
	Args:         machineTokenRevokeArgs,
	SilenceUsage: true,
	RunE:         runMachineTokenRevoke,
}

// machineTokenRevokeArgs replaces cobra.ExactArgs(2), whose "accepts 2 arg(s),
// received 1" left a presenter guessing which two (#2981).
func machineTokenRevokeArgs(_ *cobra.Command, args []string) error {
	if len(args) == 2 {
		return nil
	}
	return fmt.Errorf("revoke takes the machine identity AND the token id: `keyorix machine token revoke <name|id> <token-id>` "+
		"(got %d argument(s)); list a machine's token ids with `keyorix machine token list <name|id>`", len(args))
}

func init() {
	machineTokenIssueCmd.Flags().StringVar(&machineTokenProjectName, "project", "", "Project name or numeric ID")
	machineTokenIssueCmd.Flags().StringVar(&machineTokenIssueName, "name", "", "Token label (required)")
	machineTokenIssueCmd.Flags().IntVar(&machineTokenIssueExpiryDays, "expires-in-days", 0, "Token lifetime in days (0 = never expires)")
	machineTokenIssueCmd.Flags().StringVar(&machineTokenIssueClass, "classification", "", "Data classification: public | internal | confidential | restricted")

	machineTokenListCmd.Flags().StringVar(&machineTokenProjectName, "project", "", "Project name or numeric ID")

	machineTokenRevokeCmd.Flags().StringVar(&machineTokenProjectName, "project", "", "Project name or numeric ID")
	machineTokenRevokeCmd.Flags().BoolVar(&machineTokenRevokeForce, "force", false, "Skip the confirmation prompt")

	machineTokenCmd.AddCommand(machineTokenIssueCmd, machineTokenListCmd, machineTokenRevokeCmd)
	machineCmd.AddCommand(machineTokenCmd)
}

func runMachineTokenIssue(cmd *cobra.Command, args []string) error {
	if machineTokenIssueName == "" {
		return usageErrorf("--name is required")
	}
	client, err := machineAPIClient()
	if err != nil {
		return err
	}
	_, projectID, err := resolveMachineProjectID(client, machineTokenProjectName)
	if err != nil {
		return err
	}
	m, err := findMachineByRef(client, projectID, args[0])
	if err != nil {
		return err
	}

	body := apiclient.IssueMachineTokenJSONRequestBody{Name: machineTokenIssueName}
	if machineTokenIssueExpiryDays > 0 {
		body.ExpiresInDays = &machineTokenIssueExpiryDays
	}
	if machineTokenIssueClass != "" {
		body.Classification = &machineTokenIssueClass
	}
	resp, err := client.IssueMachineTokenWithResponse(context.Background(), projectID, derefInt(m.Id), body)
	if err != nil {
		return fmt.Errorf("failed to issue machine token: %w", err)
	}
	if resp.JSON201 == nil || resp.JSON201.Data == nil {
		return httpStatusError("failed to issue machine token", resp.StatusCode(), resp.Body)
	}
	data := *resp.JSON201.Data
	fmt.Println("Machine token issued. Copy it now — it will not be shown again.")
	fmt.Println()
	fmt.Printf("Token:   %s\n", derefStr(data.Token))
	fmt.Printf("ID:      %d\n", derefInt(data.Id))
	fmt.Printf("Prefix:  %s\n", derefStr(data.Prefix))
	if data.ExpiresAt != nil && !data.ExpiresAt.IsZero() {
		fmt.Printf("Expires: %s\n", data.ExpiresAt.Format("2006-01-02"))
	} else {
		fmt.Println("Expires: never")
	}
	return nil
}

func runMachineTokenList(cmd *cobra.Command, args []string) error {
	if err := checkOutputFormat(tokenListFormat); err != nil {
		return err
	}
	client, err := machineAPIClient()
	if err != nil {
		return err
	}
	_, projectID, err := resolveMachineProjectID(client, machineTokenProjectName)
	if err != nil {
		return err
	}
	m, err := findMachineByRef(client, projectID, args[0])
	if err != nil {
		return err
	}

	resp, err := client.ListMachineTokensWithResponse(context.Background(), projectID, derefInt(m.Id))
	if err != nil {
		return fmt.Errorf("failed to list machine tokens: %w", err)
	}
	if resp.StatusCode() != 200 {
		return httpStatusError("failed to list machine tokens", resp.StatusCode(), resp.Body)
	}
	var rows []apiclient.MachineToken
	if resp.JSON200 != nil && resp.JSON200.Data != nil && resp.JSON200.Data.Tokens != nil {
		rows = *resp.JSON200.Data.Tokens
	}
	return emitList(tokenListFormat, rows, func() error {
		if len(rows) == 0 {
			fmt.Println("No tokens found.")
			return nil
		}
		fmt.Printf("%-6s %-22s %-20s %-18s %-12s %s\n", "ID", "NAME", "PREFIX", "LAST USED", "EXPIRES", "REVOKED")
		for _, r := range rows {
			lastUsed := "-"
			if r.LastUsedAt != nil && !r.LastUsedAt.IsZero() {
				lastUsed = r.LastUsedAt.Format("2006-01-02 15:04")
			}
			expires := "never"
			if r.ExpiresAt != nil && !r.ExpiresAt.IsZero() {
				expires = r.ExpiresAt.Format("2006-01-02")
			}
			revoked := "false"
			if derefBool(r.Revoked) {
				revoked = "true"
			}
			fmt.Printf("%-6d %-22s %-20s %-18s %-12s %s\n", derefInt(r.Id), derefStr(r.Name), derefStr(r.Prefix), lastUsed, expires, revoked)
		}
		return nil
	})
}

func runMachineTokenRevoke(cmd *cobra.Command, args []string) error {
	tokenID, err := strconv.Atoi(args[1])
	if err != nil {
		return fmt.Errorf("invalid token ID %q: must be a numeric ID", args[1])
	}
	client, err := machineAPIClient()
	if err != nil {
		return err
	}
	_, projectID, err := resolveMachineProjectID(client, machineTokenProjectName)
	if err != nil {
		return err
	}
	m, err := findMachineByRef(client, projectID, args[0])
	if err != nil {
		return err
	}

	if !machineTokenRevokeForce {
		fmt.Printf("Revoke token %d? [y/N]: ", tokenID)
		reader := bufio.NewReader(cmd.InOrStdin())
		input, _ := reader.ReadString('\n')
		if strings.ToLower(strings.TrimSpace(input)) != "y" {
			fmt.Println("Revoke aborted.")
			return nil
		}
	}

	resp, err := client.RevokeMachineTokenWithResponse(context.Background(), projectID, derefInt(m.Id), tokenID)
	if err != nil {
		return fmt.Errorf("failed to revoke machine token: %w", err)
	}
	if resp.StatusCode() < 200 || resp.StatusCode() >= 300 {
		return httpStatusError("failed to revoke machine token", resp.StatusCode(), resp.Body)
	}
	fmt.Println("Machine token revoked.")
	return nil
}
