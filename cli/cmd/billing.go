// billing.go ports `keyorix billing report` (docs/cli-split-inventory-census.md, FINISH-SPLIT
// census-gaps batch): the remote-mode branch of internal/cli/billing/billing.go's `report`
// subcommand. Same flags, output, and exit codes -- a pure transport port, not a behavior
// change. The local/embedded-mode branch is NOT ported, same reason as usage.go: no
// userID/caller-identity parameter to authorize against (docs/cli-split-inventory.md §8
// Finding S17).
package cmd

import (
	"context"
	"fmt"
	"os"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
	"github.com/keyorixhq/keyorix/cli/internal/cliout"
)

var billingCmd = &cobra.Command{
	Use:   "billing",
	Short: "FinOps billing and usage reports (requires billing license feature)",
}

func init() {
	rootCmd.AddCommand(billingCmd)
}

var (
	billingReportFrom      string
	billingReportTo        string
	billingReportProjectID string
	billingReportFormat    string
)

var billingReportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate a per-project billing report for a date range",
	Long: `Generate a per-project billing report showing secret counts, reads, writes,
rotations, unique human users, and machine reads for the specified date window
(GET /admin/billing/report). Requires audit.read and the "billing" license feature.`,
	SilenceUsage: true,
	RunE:         runBillingReport,
}

func init() {
	billingReportCmd.Flags().StringVar(&billingReportFrom, "from", "", "Start of billing window, RFC3339 (e.g. 2026-01-01T00:00:00Z) — required")
	billingReportCmd.Flags().StringVar(&billingReportTo, "to", "", "End of billing window, RFC3339 (e.g. 2026-02-01T00:00:00Z) — required")
	billingReportCmd.Flags().StringVar(&billingReportProjectID, "project-id", "", "Comma-separated project IDs to include (omit for all)")
	addOutputFlag(billingReportCmd, &billingReportFormat)
	if err := billingReportCmd.MarkFlagRequired("from"); err != nil {
		panic(err)
	}
	if err := billingReportCmd.MarkFlagRequired("to"); err != nil {
		panic(err)
	}
	billingCmd.AddCommand(billingReportCmd)
}

func runBillingReport(_ *cobra.Command, _ []string) error {
	if err := checkOutputFormat(billingReportFormat); err != nil {
		return err
	}
	from, err := time.Parse(time.RFC3339, billingReportFrom)
	if err != nil {
		return fmt.Errorf("invalid --from value %q: must be RFC3339 (e.g. 2026-01-01T00:00:00Z)", billingReportFrom)
	}
	to, err := time.Parse(time.RFC3339, billingReportTo)
	if err != nil {
		return fmt.Errorf("invalid --to value %q: must be RFC3339 (e.g. 2026-02-01T00:00:00Z)", billingReportTo)
	}

	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}

	params := &apiclient.GetBillingReportParams{From: from, To: to}
	if billingReportProjectID != "" {
		params.ProjectId = &billingReportProjectID
	}
	resp, err := client.GetBillingReportWithResponse(ctx, params)
	if err != nil {
		return fmt.Errorf("failed to fetch billing report: %w", err)
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return apiError("get billing report", resp.StatusCode(), resp.Body)
	}
	return printBillingReport(resp.JSON200.Data)
}

func printBillingReport(report *apiclient.BillingReport) error {
	if billingReportFormat != outputTable {
		return printStructured(billingReportFormat, report)
	}

	projects := []apiclient.BillingProjectStat{}
	if report.Projects != nil {
		projects = *report.Projects
	}
	sort.Slice(projects, func(i, j int) bool {
		if derefStr(projects[i].ProjectName) != derefStr(projects[j].ProjectName) {
			return derefStr(projects[i].ProjectName) < derefStr(projects[j].ProjectName)
		}
		return derefInt(projects[i].ProjectId) < derefInt(projects[j].ProjectId)
	})

	fromStr, toStr, generatedAt := "", "", ""
	if report.From != nil {
		fromStr = report.From.Format("2006-01-02")
	}
	if report.To != nil {
		toStr = report.To.Format("2006-01-02")
	}
	if report.GeneratedAt != nil {
		generatedAt = report.GeneratedAt.Format("2006-01-02 15:04:05 UTC")
	}
	fmt.Printf("Billing report %s – %s (generated %s)\n\n", fromStr, toStr, generatedAt)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "PROJECT\tSECRETS\tREADS\tWRITES\tROTATIONS\tUNIQUE USERS\tMACHINE READS"); err != nil {
		return err
	}
	for _, p := range projects {
		// #G69: ProjectName is attacker-controlled free text.
		name := cliout.SanitizeForTerminal(derefStr(p.ProjectName))
		if name == "" {
			name = fmt.Sprintf("(project %d)", derefInt(p.ProjectId))
		}
		if _, err := fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%d\t%d\t%d\n",
			name, derefInt(p.SecretCount), derefInt(p.SecretReads), derefInt(p.SecretWrites),
			derefInt(p.SecretRotations), derefInt(p.UniqueUsers), derefInt(p.MachineReads)); err != nil {
			return err
		}
	}
	if len(projects) == 0 {
		if _, err := fmt.Fprintln(w, "(no data)"); err != nil {
			return err
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}

	if report.Totals != nil {
		t := report.Totals
		fmt.Printf("\nTotals (%d project(s)): %d secrets  %d reads  %d writes  %d rotations  %d unique users  %d machine reads\n",
			derefInt(t.Projects), derefInt(t.SecretCount), derefInt(t.SecretReads), derefInt(t.SecretWrites),
			derefInt(t.SecretRotations), derefInt(t.UniqueUsers), derefInt(t.MachineReads))
	}
	return nil
}
