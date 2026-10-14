// project_freeze.go — keyorix project suspend-secrets / resume-secrets: the breach
// "freeze the project" action (POST /projects/{id}/secrets/suspend-all and resume-all).
package cmd

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

var (
	projectFreezeID          int
	projectFreezeReason      string
	projectFreezeClearCopies bool
	projectThawID            int
)

var projectSuspendSecretsCmd = &cobra.Command{
	Use:   "suspend-secrets",
	Short: "Suspend every secret in a project -- block value reads project-wide",
	Long: `Freeze a whole project (a breach response): value reads of every active secret
in the project that you may write are refused until you resume them. Versions, shares
and the audit trail are preserved. Requires secrets.write on the project, the same as
suspending one secret.

With --clear-synced-copies the copies of those secrets synced to Kubernetes clusters
(by the operator or keyorix-k8s-sync) are also emptied for the duration of THIS
suspension, whatever each resource's own onSuspend setting says. Use it when the
secrets are compromised, and rotate them afterwards. Resuming removes the request and
the next sync restores the copies. Running suspend-secrets again with the flag adds
the request to secrets that are already suspended without it.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if projectFreezeID == 0 {
			return fmt.Errorf("--id is required")
		}
		client, err := secretAPIClient()
		if err != nil {
			return err
		}
		body := apiclient.SuspendProjectSecretsJSONRequestBody{}
		if projectFreezeReason != "" {
			body.Reason = &projectFreezeReason
		}
		if projectFreezeClearCopies {
			body.ClearSyncedCopies = &projectFreezeClearCopies
		}
		resp, err := client.SuspendProjectSecretsWithResponse(context.Background(), projectFreezeID, body)
		if err != nil {
			return err
		}
		if resp.StatusCode() < 200 || resp.StatusCode() >= 300 {
			return httpStatusError("suspend project secrets", resp.StatusCode(), resp.Body)
		}
		var env struct {
			Data struct {
				Suspended int `json:"suspended"`
			} `json:"data"`
		}
		_ = json.Unmarshal(resp.Body, &env)
		fmt.Printf("Project %d: %d secret(s) suspended -- value reads are now blocked.\n", projectFreezeID, env.Data.Suspended)
		if projectFreezeClearCopies {
			fmt.Println("Copies synced to Kubernetes clusters will be cleared on their next sync.")
			fmt.Println("If the secrets are compromised, rotate them too: `keyorix secret rotate`.")
		}
		return nil
	},
}

var projectResumeSecretsCmd = &cobra.Command{
	Use:          "resume-secrets",
	Short:        "Resume every suspended secret in a project -- restore value reads",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if projectThawID == 0 {
			return fmt.Errorf("--id is required")
		}
		client, err := secretAPIClient()
		if err != nil {
			return err
		}
		resp, err := client.ResumeProjectSecretsWithResponse(context.Background(), projectThawID)
		if err != nil {
			return err
		}
		if resp.StatusCode() < 200 || resp.StatusCode() >= 300 {
			return httpStatusError("resume project secrets", resp.StatusCode(), resp.Body)
		}
		var env struct {
			Data struct {
				Resumed int `json:"resumed"`
			} `json:"data"`
		}
		_ = json.Unmarshal(resp.Body, &env)
		fmt.Printf("Project %d: %d secret(s) resumed -- value reads are restored.\n", projectThawID, env.Data.Resumed)
		return nil
	},
}

func init() {
	projectSuspendSecretsCmd.Flags().IntVar(&projectFreezeID, "id", 0, "Project ID (required)")
	projectSuspendSecretsCmd.Flags().StringVar(&projectFreezeReason, "reason", "", "Optional reason recorded in the audit events")
	projectSuspendSecretsCmd.Flags().BoolVar(&projectFreezeClearCopies, "clear-synced-copies", false, "Also clear the copies synced to Kubernetes clusters for this suspension (compromise response; rotate the secrets afterwards)")
	projectResumeSecretsCmd.Flags().IntVar(&projectThawID, "id", 0, "Project ID (required)")
	projectCmd.AddCommand(projectSuspendSecretsCmd, projectResumeSecretsCmd)
}
