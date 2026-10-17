// usage.go ports `keyorix usage show` (docs/cli-split-inventory-census.md, FINISH-SPLIT
// census-gaps batch): the remote-mode branch of internal/cli/usage/usage.go's `show`
// subcommand. Same flags, output, and exit codes -- a pure transport port, not a behavior
// change. The local/embedded-mode branch is NOT ported: it calls core.GetUsageReport with no
// userID/caller-identity parameter at all, so there is nothing for a permission check to be
// threaded through (docs/cli-split-inventory.md §8 Finding S17) -- exactly the class of gap
// ADR-108 Decision A removes local mode to close, not a branch to carry forward.
package cmd

import (
	"context"
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
	"github.com/keyorixhq/keyorix/cli/internal/cliout"
)

var usageCmd = &cobra.Command{
	Use:   "usage",
	Short: "View usage and activity reports",
}

func init() {
	rootCmd.AddCommand(usageCmd)
}

var (
	usageShowDays      int
	usageShowProjectID int
	usageShowFormat    string
)

var usageShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show per-project secret usage for a time window",
	Long: `Display a per-project secret usage report (secret counts and read activity) for the
given reporting window (GET /admin/usage). Requires audit.read.`,
	SilenceUsage: true,
	RunE:         runUsageShow,
}

func init() {
	usageShowCmd.Flags().IntVar(&usageShowDays, "days", 30, "Reporting window in days (1-365)")
	usageShowCmd.Flags().IntVar(&usageShowProjectID, "project-id", 0, "Scope to a single project (0 = all)")
	addOutputFlagWithFormatAlias(usageShowCmd, &usageShowFormat)
	usageCmd.AddCommand(usageShowCmd)
}

func runUsageShow(_ *cobra.Command, _ []string) error {
	if err := checkOutputFormat(usageShowFormat); err != nil {
		return err
	}
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}

	params := &apiclient.GetUsageReportParams{Days: &usageShowDays}
	if usageShowProjectID != 0 {
		params.ProjectId = &usageShowProjectID
	}
	resp, err := client.GetUsageReportWithResponse(ctx, params)
	if err != nil {
		return fmt.Errorf("failed to fetch usage report: %w", err)
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return apiError("get usage report", resp.StatusCode(), resp.Body)
	}
	return printUsageReport(resp.JSON200.Data)
}

func printUsageReport(report *apiclient.UsageReport) error {
	if usageShowFormat != outputTable {
		return printStructured(usageShowFormat, report)
	}

	projects := []apiclient.ProjectUsageStat{}
	if report.Projects != nil {
		projects = *report.Projects
	}
	sort.Slice(projects, func(i, j int) bool {
		if derefStr(projects[i].ProjectName) != derefStr(projects[j].ProjectName) {
			return derefStr(projects[i].ProjectName) < derefStr(projects[j].ProjectName)
		}
		return derefInt(projects[i].ProjectId) < derefInt(projects[j].ProjectId)
	})

	generatedAt := ""
	if report.GeneratedAt != nil {
		generatedAt = report.GeneratedAt.Format("2006-01-02 15:04:05 UTC")
	}
	fmt.Printf("Usage report — last %d days (generated %s)\n\n", derefInt(report.WindowDays), generatedAt)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "PROJECT\tSECRETS\tREADS\tUNIQUE READERS"); err != nil {
		return err
	}
	for _, p := range projects {
		// #G69: ProjectName is attacker-controlled free text -- must never carry a terminal
		// escape sequence into this report.
		name := cliout.SanitizeForTerminal(derefStr(p.ProjectName))
		if name == "" {
			name = fmt.Sprintf("(project %d)", derefInt(p.ProjectId))
		}
		if _, err := fmt.Fprintf(w, "%s\t%d\t%d\t%d\n", name, derefInt(p.SecretCount), derefInt(p.ReadsInWindow), derefInt(p.UniqueReaders)); err != nil {
			return err
		}
	}
	if len(projects) == 0 {
		if _, err := fmt.Fprintln(w, "(no data)"); err != nil {
			return err
		}
	}
	return w.Flush()
}
