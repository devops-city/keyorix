// machine_token.go — machine identity token management commands (ADR-030).
package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

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
	machineTokenIssueOutputFile string
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

	machineTokenIssueCmd.Flags().StringVar(&machineTokenIssueOutputFile, "output-file", "",
		"Write the token to this new file (mode 0600, refuses to overwrite) instead of printing it, so it never passes through terminal scrollback or shell history")

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
	// Create the destination first: a token minted with nowhere to go is lost, and an
	// existing file is refused before anything is issued.
	var outFile *os.File
	if machineTokenIssueOutputFile != "" {
		outFile, err = secureCreateOutputFile(machineTokenIssueOutputFile)
		if err != nil {
			return fmt.Errorf("cannot create --output-file %s (it must not exist yet; no token was issued): %w",
				machineTokenIssueOutputFile, err)
		}
	}
	discardOutFile := func() {
		if outFile != nil {
			_ = outFile.Close()
			_ = os.Remove(machineTokenIssueOutputFile)
		}
	}
	resp, err := client.IssueMachineTokenWithResponse(context.Background(), projectID, derefInt(m.Id), body)
	if err != nil {
		discardOutFile()
		return fmt.Errorf("failed to issue machine token: %w", err)
	}
	if resp.JSON201 == nil || resp.JSON201.Data == nil {
		discardOutFile()
		return httpStatusError("failed to issue machine token", resp.StatusCode(), resp.Body)
	}
	data := *resp.JSON201.Data
	if outFile != nil {
		_, werr := outFile.WriteString(derefStr(data.Token) + "\n")
		if cerr := outFile.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			// The token exists on the server but was never saved or shown: say how to undo it.
			_ = os.Remove(machineTokenIssueOutputFile)
			return fmt.Errorf("token %d was issued but could not be written to %s (%w); it was not shown. "+
				"Next step: revoke it with `keyorix machine token revoke %s %d` and issue a new one",
				derefInt(data.Id), machineTokenIssueOutputFile, werr, args[0], derefInt(data.Id))
		}
		fmt.Printf("Machine token issued and written to %s (mode 0600). It will not be shown again.\n\n", machineTokenIssueOutputFile)
		printMachineTokenMeta(data.Id, data.Prefix, data.ExpiresAt)
		return nil
	}
	fmt.Println("Machine token issued. Copy it now — it will not be shown again.")
	fmt.Println()
	fmt.Printf("Token:   %s\n", derefStr(data.Token))
	printMachineTokenMeta(data.Id, data.Prefix, data.ExpiresAt)
	return nil
}

// printMachineTokenMeta prints everything about an issued token except the token itself.
func printMachineTokenMeta(id *int, prefix *string, expiresAt *time.Time) {
	fmt.Printf("ID:      %d\n", derefInt(id))
	fmt.Printf("Prefix:  %s\n", derefStr(prefix))
	if expiresAt != nil && !expiresAt.IsZero() {
		fmt.Printf("Expires: %s\n", expiresAt.Format("2006-01-02"))
	} else {
		fmt.Println("Expires: never")
	}
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
