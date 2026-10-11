// secret_lifecycle.go — keyorix secret suspend/resume/trash/restore.
package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

// ── suspend / resume ────────────────────────────────────────────────────────────

var (
	secretSuspendID     int
	secretSuspendReason string
	secretResumeID      int
)

var secretSuspendCmd = &cobra.Command{
	Use:   "suspend",
	Short: "Suspend a secret -- block value reads without deleting it",
	Long: `Freeze a secret: value reads are refused until it is resumed. Versions,
shares, and the audit trail are preserved. Requires secrets.write.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if secretSuspendID == 0 {
			return fmt.Errorf("--id is required")
		}
		client, err := secretAPIClient()
		if err != nil {
			return err
		}
		body := apiclient.SuspendSecretJSONRequestBody{}
		if secretSuspendReason != "" {
			body.Reason = &secretSuspendReason
		}
		resp, err := client.SuspendSecretWithResponse(context.Background(), secretSuspendID, body)
		if err != nil {
			return err
		}
		if resp.StatusCode() < 200 || resp.StatusCode() >= 300 {
			return httpStatusError("suspend secret", resp.StatusCode(), resp.Body)
		}
		fmt.Printf("Secret %d suspended -- value reads are now blocked.\n", secretSuspendID)
		return nil
	},
}

var secretResumeCmd = &cobra.Command{
	Use:          "resume",
	Short:        "Resume a suspended secret -- restore value reads",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if secretResumeID == 0 {
			return fmt.Errorf("--id is required")
		}
		client, err := secretAPIClient()
		if err != nil {
			return err
		}
		resp, err := client.ResumeSecretWithResponse(context.Background(), secretResumeID)
		if err != nil {
			return err
		}
		if resp.StatusCode() < 200 || resp.StatusCode() >= 300 {
			return httpStatusError("resume secret", resp.StatusCode(), resp.Body)
		}
		fmt.Printf("Secret %d resumed -- value reads are restored.\n", secretResumeID)
		return nil
	},
}

func init() {
	secretSuspendCmd.Flags().IntVar(&secretSuspendID, "id", 0, "Secret ID (required)")
	secretSuspendCmd.Flags().StringVar(&secretSuspendReason, "reason", "", "Optional reason recorded in the audit event")
	secretResumeCmd.Flags().IntVar(&secretResumeID, "id", 0, "Secret ID (required)")
	SecretCmd.AddCommand(secretSuspendCmd, secretResumeCmd)
}

// ── trash / restore ─────────────────────────────────────────────────────────────

var (
	secretTrashProject int
	secretTrashLimit   int
	secretRestoreID    int
)

var secretTrashCmd = &cobra.Command{
	Use:   "trash",
	Short: "List a project's soft-deleted (restorable) secrets",
	Long: `Show the recycle bin for a project: secrets that were deleted but are still
restorable (until the purge job reaps them), newest-deleted first. Use the ID
with 'secret restore --id <id>'. Requires secrets.read at the project scope.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if secretTrashProject == 0 {
			return fmt.Errorf("--project is required")
		}
		client, err := secretAPIClient()
		if err != nil {
			return err
		}
		var params *apiclient.ListDeletedSecretsParams
		if secretTrashLimit > 0 {
			params = &apiclient.ListDeletedSecretsParams{Limit: &secretTrashLimit}
		}
		resp, err := client.ListDeletedSecretsWithResponse(context.Background(), secretTrashProject, params)
		if err != nil {
			return err
		}
		if resp.JSON200 == nil || resp.JSON200.Data == nil {
			return httpStatusError("list deleted secrets", resp.StatusCode(), resp.Body)
		}
		rows := derefDeletedSecretSlice(resp.JSON200.Data.Deleted)
		if len(rows) == 0 {
			fmt.Println("Recycle bin is empty.")
			return nil
		}
		fmt.Printf("%-8s %-24s %-12s %-14s %-26s %s\n", "ID", "NAME", "TYPE", "CLASS", "DELETED", "PURGE AFTER (UTC)")
		for _, r := range rows {
			fmt.Printf("%-8d %-24s %-12s %-14s %-26s %s\n", derefSecretInt(r.Id), derefStr(r.Name), derefStr(r.Type), derefStr(r.Classification), derefStr(r.DeletedAt), purgeAtCell(r.PurgeAt))
		}
		return nil
	},
}

// purgeAtCell renders a trash row's purge instant in UTC RFC 3339, or "-" when the server
// (older than the field) did not send one.
func purgeAtCell(t *time.Time) string {
	if t == nil || t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

var secretRestoreCmd = &cobra.Command{
	Use:   "restore",
	Short: "Restore a soft-deleted secret",
	Long: `Restore a soft-deleted secret by clearing its deletion, returning it to the
live list. Find restorable secrets with 'secret trash --project <id>'.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if secretRestoreID == 0 {
			return fmt.Errorf("--id is required")
		}
		client, err := secretAPIClient()
		if err != nil {
			return err
		}
		resp, err := client.RestoreSecretWithResponse(context.Background(), secretRestoreID)
		if err != nil {
			return err
		}
		if resp.JSON200 == nil {
			return httpStatusError("restore secret", resp.StatusCode(), resp.Body)
		}
		fmt.Printf("Secret %d restored.\n", secretRestoreID)
		return nil
	},
}

func derefDeletedSecretSlice(s *[]apiclient.DeletedSecretEntry) []apiclient.DeletedSecretEntry {
	if s == nil {
		return nil
	}
	return *s
}

func init() {
	secretTrashCmd.Flags().IntVar(&secretTrashProject, "project", 0, "Project ID (required)")
	secretTrashCmd.Flags().IntVar(&secretTrashLimit, "limit", 0, "Max entries to show (default server-side: 100, cap 500)")
	secretRestoreCmd.Flags().IntVar(&secretRestoreID, "id", 0, "Secret ID (required)")
	SecretCmd.AddCommand(secretTrashCmd, secretRestoreCmd)
}
