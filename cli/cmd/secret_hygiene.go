// secret_hygiene.go — keyorix secret expiring/orphaned/name-conformance/quota-report/
// ownership-history/reassign-owner.
package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

// ── expiring ─────────────────────────────────────────────────────────────────

var (
	expiringProject int
	expiringDays    int
)

var secretExpiringCmd = &cobra.Command{
	Use:   "expiring",
	Short: "List a project's secrets expiring (or already expired) within a window",
	Long: `Show a project's secrets expiring soon (or already expired), soonest-first, so you
can renew or rotate them before they lapse. Requires secrets.read at the project scope.`,
	SilenceUsage: true,
	RunE:         runSecretExpiring,
}

func runSecretExpiring(_ *cobra.Command, _ []string) error {
	if expiringProject == 0 {
		return usageErrorf("--project is required")
	}
	client, err := secretAPIClient()
	if err != nil {
		return err
	}
	var params *apiclient.ListExpiringSecretsParams
	if expiringDays > 0 {
		params = &apiclient.ListExpiringSecretsParams{Days: &expiringDays}
	}
	resp, err := client.ListExpiringSecretsWithResponse(context.Background(), expiringProject, params)
	if err != nil {
		return err
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return httpStatusError("list expiring secrets", resp.StatusCode(), resp.Body)
	}
	rows := resp.JSON200.Data.Expiring
	if rows == nil || len(*rows) == 0 {
		fmt.Println("No expiring secrets.")
		return nil
	}
	fmt.Printf("%-8s %-24s %-12s %-10s %s\n", "ID", "NAME", "TYPE", "STATE", "EXPIRES")
	for _, r := range *rows {
		state := "expiring"
		if derefBool(r.Expired) {
			state = "EXPIRED"
		}
		expiration := ""
		if r.Expiration != nil {
			expiration = r.Expiration.Format("2006-01-02T15:04:05Z07:00")
		}
		fmt.Printf("%-8d %-24s %-12s %-10s %s\n", derefInt(r.Id), derefStr(r.Name), derefStr(r.Type), state, expiration)
	}
	return nil
}

func init() {
	secretExpiringCmd.Flags().IntVar(&expiringProject, "project", 0, "Project ID (required)")
	secretExpiringCmd.Flags().IntVar(&expiringDays, "days", 0, "Window in days (default server-side: 30, cap 3650)")
	SecretCmd.AddCommand(secretExpiringCmd)
}

// ── orphaned ─────────────────────────────────────────────────────────────────

var orphanedProject int

var secretOrphanedCmd = &cobra.Command{
	Use:   "orphaned",
	Short: "List secrets whose owner is no longer a live user",
	Long: `Show a project's secrets whose owner has been deleted (offboarding hygiene). Each is
left without an accountable owner — re-assign one with 'keyorix secret reassign-owner'.
Requires secrets.read at the project scope.`,
	SilenceUsage: true,
	RunE:         runSecretOrphaned,
}

func runSecretOrphaned(_ *cobra.Command, _ []string) error {
	if orphanedProject == 0 {
		return usageErrorf("--project is required")
	}
	client, err := secretAPIClient()
	if err != nil {
		return err
	}
	resp, err := client.ListOrphanedSecretsWithResponse(context.Background(), orphanedProject)
	if err != nil {
		return err
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return httpStatusError("list orphaned secrets", resp.StatusCode(), resp.Body)
	}
	rows := resp.JSON200.Data.Orphaned
	if rows == nil || len(*rows) == 0 {
		fmt.Println("No orphaned secrets.")
		return nil
	}
	fmt.Printf("%-8s %-24s %-12s %-14s %s\n", "ID", "NAME", "TYPE", "CLASS", "EX-OWNER")
	for _, r := range *rows {
		fmt.Printf("%-8d %-24s %-12s %-14s %d\n", derefInt(r.Id), derefStr(r.Name), derefStr(r.Type), derefStr(r.Classification), derefInt(r.OwnerId))
	}
	return nil
}

func init() {
	secretOrphanedCmd.Flags().IntVar(&orphanedProject, "project", 0, "Project ID (required)")
	SecretCmd.AddCommand(secretOrphanedCmd)
}

// ── name-conformance ─────────────────────────────────────────────────────────

var nameConformanceProject int

var secretNameConformanceCmd = &cobra.Command{
	Use:   "name-conformance",
	Short: "List secrets whose names violate the current naming policy",
	Long: `Show the live secrets whose names fail the current secret naming policy. The policy is
enforced only when a secret is created, so names can fall out of conformance after the
policy is added or tightened — this surfaces those stragglers so you can rename them.

With --project, scopes to one project (requires secrets.read at the project scope).
Without --project, reports across every project (requires audit.read — admin view).`,
	SilenceUsage: true,
	RunE:         runSecretNameConformance,
}

func runSecretNameConformance(_ *cobra.Command, _ []string) error {
	client, err := secretAPIClient()
	if err != nil {
		return err
	}
	ctx := context.Background()
	orgWide := nameConformanceProject == 0

	if orgWide {
		resp, err := client.DeploymentSecretNameConformanceWithResponse(ctx)
		if err != nil {
			return err
		}
		if resp.JSON200 == nil || resp.JSON200.Data == nil {
			return httpStatusError("get org-wide name conformance", resp.StatusCode(), resp.Body)
		}
		printDeploymentNameConformance(resp.JSON200.Data)
		return nil
	}

	resp, err := client.SecretNameConformanceWithResponse(ctx, nameConformanceProject)
	if err != nil {
		return err
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return httpStatusError("get name conformance", resp.StatusCode(), resp.Body)
	}
	printNameConformance(resp.JSON200.Data)
	return nil
}

func printNameConformance(r *apiclient.SecretNameConformanceReport) {
	if !derefBool(r.PolicyEnabled) {
		fmt.Println("No secret naming policy is configured — nothing to check.")
		return
	}
	violations := 0
	if r.Violations != nil {
		violations = len(*r.Violations)
	}
	if violations == 0 {
		fmt.Printf("All %d secret(s) conform to the naming policy.\n", derefInt(r.TotalSecrets))
		return
	}
	fmt.Printf("%d of %d secret(s) violate the naming policy:\n\n", violations, derefInt(r.TotalSecrets))
	fmt.Printf("%-8s %-24s %-12s %s\n", "ID", "NAME", "TYPE", "REASON")
	for _, v := range *r.Violations {
		fmt.Printf("%-8d %-24s %-12s %s\n", derefInt(v.Id), derefStr(v.Name), derefStr(v.Type), derefStr(v.Reason))
	}
}

func printDeploymentNameConformance(r *apiclient.DeploymentSecretNameConformanceReport) {
	if !derefBool(r.PolicyEnabled) {
		fmt.Println("No secret naming policy is configured — nothing to check.")
		return
	}
	violations := 0
	if r.Violations != nil {
		violations = len(*r.Violations)
	}
	if violations == 0 {
		fmt.Printf("All %d secret(s) conform to the naming policy.\n", derefInt(r.TotalSecrets))
		return
	}
	fmt.Printf("%d of %d secret(s) violate the naming policy:\n\n", violations, derefInt(r.TotalSecrets))
	fmt.Printf("%-20s %-8s %-24s %-12s %s\n", "PROJECT", "ID", "NAME", "TYPE", "REASON")
	for _, v := range *r.Violations {
		fmt.Printf("%-20s %-8d %-24s %-12s %s\n", derefStr(v.ProjectName), derefInt(v.Id), derefStr(v.Name), derefStr(v.Type), derefStr(v.Reason))
	}
}

func init() {
	secretNameConformanceCmd.Flags().IntVar(&nameConformanceProject, "project", 0, "Project ID (omit for an org-wide admin view)")
	SecretCmd.AddCommand(secretNameConformanceCmd)
}

// ── quota-report ─────────────────────────────────────────────────────────────

var secretQuotaReportCmd = &cobra.Command{
	Use:   "quota-report",
	Short: "Show secrets approaching or at their MaxReads quota",
	Long: `List all secrets with a MaxReads cap configured, showing current read count,
quota percentage, and status (ok / warning / critical / exhausted). Requires
audit.read (a usage-report endpoint, not secret-value access).`,
	SilenceUsage: true,
	RunE:         runSecretQuotaReport,
}

func runSecretQuotaReport(_ *cobra.Command, _ []string) error {
	client, err := secretAPIClient()
	if err != nil {
		return err
	}
	resp, err := client.GetQuotaReportWithResponse(context.Background())
	if err != nil {
		return err
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return httpStatusError("get quota report", resp.StatusCode(), resp.Body)
	}
	rows := resp.JSON200.Data.Secrets
	if rows == nil || len(*rows) == 0 {
		fmt.Println("No secrets with a read quota configured.")
		return nil
	}
	fmt.Printf("%-8s %-28s %10s %10s %8s %s\n", "ID", "NAME", "READ_COUNT", "MAX_READS", "USAGE%", "STATUS")
	for _, r := range *rows {
		status := ""
		if r.Status != nil {
			status = string(*r.Status)
		}
		fmt.Printf("%-8d %-28s %10d %10d %7d%% %s\n",
			derefInt(r.SecretId), derefStr(r.SecretName), derefInt(r.ReadCount), derefInt(r.MaxReads), derefInt(r.UsagePct), status)
	}
	return nil
}

func init() {
	SecretCmd.AddCommand(secretQuotaReportCmd)
}

// ── ownership-history ────────────────────────────────────────────────────────

var ownershipHistoryID int

var secretOwnershipHistoryCmd = &cobra.Command{
	Use:   "ownership-history",
	Short: "Show a secret's ownership-transfer chain",
	Long: `List all ownership transfers for a secret in chronological order. Each record
shows who the secret was transferred from, who it was transferred to, who performed
the transfer, and when. Requires secrets.read at the secret's scope.`,
	SilenceUsage: true,
	RunE:         runSecretOwnershipHistory,
}

func runSecretOwnershipHistory(_ *cobra.Command, _ []string) error {
	if ownershipHistoryID == 0 {
		return usageErrorf("--id is required")
	}
	client, err := secretAPIClient()
	if err != nil {
		return err
	}
	resp, err := client.GetSecretOwnershipHistoryWithResponse(context.Background(), ownershipHistoryID)
	if err != nil {
		return err
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return httpStatusError("get ownership history", resp.StatusCode(), resp.Body)
	}
	records := resp.JSON200.Data.OwnershipHistory
	if records == nil || len(*records) == 0 {
		fmt.Println("No ownership transfers recorded.")
		return nil
	}
	fmt.Printf("%-10s %-10s %-10s %-10s %s\n", "EVENT ID", "FROM", "TO", "BY", "TIME")
	for _, r := range *records {
		changedAt := ""
		if r.ChangedAt != nil {
			changedAt = r.ChangedAt.Format("2006-01-02T15:04:05Z07:00")
		}
		fmt.Printf("%-10d %-10d %-10d %-10d %s\n", derefInt(r.EventId), derefInt(r.FromId), derefInt(r.ToId), derefInt(r.ChangedBy), changedAt)
	}
	return nil
}

func init() {
	secretOwnershipHistoryCmd.Flags().IntVar(&ownershipHistoryID, "id", 0, "Secret ID (required)")
	SecretCmd.AddCommand(secretOwnershipHistoryCmd)
}

// ── reassign-owner ───────────────────────────────────────────────────────────

var (
	reassignProject int
	reassignFrom    int
	reassignTo      int
)

var secretReassignOwnerCmd = &cobra.Command{
	Use:   "reassign-owner",
	Short: "Re-home all of a departed user's secrets to a new owner",
	Long: `Transfer every secret in a project owned by one user to another, in one call —
the bulk completion of offboarding after 'keyorix secret orphaned' surfaces a gone
owner's secrets. Requires roles.assign at the project scope (the same blast radius
as a role grant, not secrets.write); each secret is authorized individually.`,
	SilenceUsage: true,
	RunE:         runSecretReassignOwner,
}

func runSecretReassignOwner(_ *cobra.Command, _ []string) error {
	if reassignProject == 0 || reassignFrom == 0 || reassignTo == 0 {
		return usageErrorf("--project, --from and --to are all required")
	}
	client, err := secretAPIClient()
	if err != nil {
		return err
	}
	resp, err := client.ReassignSecretOwnerWithResponse(context.Background(), reassignProject, apiclient.ReassignSecretOwnerJSONRequestBody{
		FromOwnerId: reassignFrom,
		ToOwnerId:   reassignTo,
	})
	if err != nil {
		return err
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return httpStatusError("reassign owner", resp.StatusCode(), resp.Body)
	}
	fmt.Printf("Reassigned %d secret(s) from user %d to user %d.\n", derefInt(resp.JSON200.Data.Reassigned), reassignFrom, reassignTo)
	return nil
}

func init() {
	secretReassignOwnerCmd.Flags().IntVar(&reassignProject, "project", 0, "Project ID (required)")
	secretReassignOwnerCmd.Flags().IntVar(&reassignFrom, "from", 0, "Current owner's user ID (required)")
	secretReassignOwnerCmd.Flags().IntVar(&reassignTo, "to", 0, "New owner's user ID (required)")
	SecretCmd.AddCommand(secretReassignOwnerCmd)
}
