// secret_organize.go — keyorix secret move/copy/copy-environment.
package cmd

import (
	"context"
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

// ── move ────────────────────────────────────────────────────────────────────────

var (
	secretMoveID int
	secretMoveTo int
)

var secretMoveCmd = &cobra.Command{
	Use:   "move",
	Short: "Move a secret or folder to a different parent folder",
	Long: `Move a secret or folder to a different parent folder.

Use --to 0 (or omit --to) to move the node to the root (no parent).`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		if secretMoveID == 0 {
			return usageErrorf("--id is required")
		}
		client, err := secretAPIClient()
		if err != nil {
			return err
		}
		resp, err := client.MoveSecretWithResponse(context.Background(), secretMoveID, apiclient.MoveSecretJSONRequestBody{ParentId: &secretMoveTo})
		if err != nil {
			return err
		}
		if resp.StatusCode() < 200 || resp.StatusCode() >= 300 {
			return httpStatusError("move secret", resp.StatusCode(), resp.Body)
		}
		dest := "root"
		if secretMoveTo != 0 {
			dest = "folder " + strconv.Itoa(secretMoveTo)
		}
		fmt.Printf("Secret %d moved to %s\n", secretMoveID, dest)
		return nil
	},
}

func init() {
	secretMoveCmd.Flags().IntVar(&secretMoveID, "id", 0, "Secret or folder ID to move (required)")
	secretMoveCmd.Flags().IntVar(&secretMoveTo, "to", 0, "Target parent folder ID (0 = root)")
	SecretCmd.AddCommand(secretMoveCmd)
}

// ── copy ────────────────────────────────────────────────────────────────────────

var (
	secretCopyID      int
	secretCopyToEnv   int
	secretCopyNewName string
)

var secretCopyCmd = &cobra.Command{
	Use:   "copy",
	Short: "Copy a secret's value and metadata into another environment",
	Long: `Promote a secret into another environment of the same project (e.g. staging ->
production) without re-typing the value. Creates a new, independently-owned
secret with the source's value, type, classification, and description.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if secretCopyID == 0 || secretCopyToEnv == 0 {
			return usageErrorf("--id and --to-environment are required")
		}
		client, err := secretAPIClient()
		if err != nil {
			return err
		}
		body := apiclient.CopySecretJSONRequestBody{EnvironmentId: secretCopyToEnv}
		if secretCopyNewName != "" {
			body.Name = &secretCopyNewName
		}
		resp, err := client.CopySecretWithResponse(context.Background(), secretCopyID, body)
		if err != nil {
			return err
		}
		if resp.JSON200 == nil || resp.JSON200.Data == nil {
			return httpStatusError("copy secret", resp.StatusCode(), resp.Body)
		}
		fmt.Printf("Copied secret %d to environment %d as new secret %d.\n", secretCopyID, secretCopyToEnv, derefSecretInt(resp.JSON200.Data.ID))
		return nil
	},
}

func init() {
	secretCopyCmd.Flags().IntVar(&secretCopyID, "id", 0, "Source secret ID (required)")
	secretCopyCmd.Flags().IntVar(&secretCopyToEnv, "to-environment", 0, "Target environment ID, same project (required)")
	secretCopyCmd.Flags().StringVar(&secretCopyNewName, "name", "", "Name for the copy (default: the source name)")
	SecretCmd.AddCommand(secretCopyCmd)
}

// ── copy-environment ────────────────────────────────────────────────────────────

var (
	secretCopyEnvProject int
	secretCopyEnvFrom    int
	secretCopyEnvTo      int
)

var secretCopyEnvironmentCmd = &cobra.Command{
	Use:   "copy-environment",
	Short: "Copy every secret from one environment into another (same project)",
	Long: `Bulk-promote a whole environment -- copy every secret from one environment
into another of the same project (e.g. seed production from staging) in a
single call. Name clashes in the target are skipped, never overwritten.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if secretCopyEnvProject == 0 || secretCopyEnvFrom == 0 || secretCopyEnvTo == 0 {
			return usageErrorf("--project, --from-environment and --to-environment are required")
		}
		if secretCopyEnvFrom == secretCopyEnvTo {
			return fmt.Errorf("--from-environment and --to-environment must differ")
		}
		client, err := secretAPIClient()
		if err != nil {
			return err
		}
		resp, err := client.CopyEnvironmentSecretsWithResponse(context.Background(), secretCopyEnvProject, secretCopyEnvFrom,
			apiclient.CopyEnvironmentSecretsJSONRequestBody{TargetEnvironmentId: secretCopyEnvTo})
		if err != nil {
			return err
		}
		if resp.JSON200 == nil || resp.JSON200.Data == nil {
			return httpStatusError("copy environment secrets", resp.StatusCode(), resp.Body)
		}
		fmt.Printf("Promoted environment %d -> %d: %d copied, %d skipped (name clashes).\n",
			secretCopyEnvFrom, secretCopyEnvTo, derefSecretInt(resp.JSON200.Data.Copied), derefSecretInt(resp.JSON200.Data.Skipped))
		return nil
	},
}

func init() {
	secretCopyEnvironmentCmd.Flags().IntVar(&secretCopyEnvProject, "project", 0, "Project ID (required)")
	secretCopyEnvironmentCmd.Flags().IntVar(&secretCopyEnvFrom, "from-environment", 0, "Source environment ID (required)")
	secretCopyEnvironmentCmd.Flags().IntVar(&secretCopyEnvTo, "to-environment", 0, "Target environment ID, same project (required)")
	SecretCmd.AddCommand(secretCopyEnvironmentCmd)
}
