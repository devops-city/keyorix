// rotation.go ports `keyorix rotation` (docs/cli-split-inventory.md §2.4, PR 1): secret-
// rotation policies and posture (NIS2 / ISO A.5.15). Same flags, output, and exit codes as
// the old CLI's internal/cli/rotation package -- this is a pure transport port (REST only,
// Zero GAPs), not a behavior change.
package cmd

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

var rotationCmd = &cobra.Command{
	Use:     "rotation",
	Aliases: []string{"rotation-policy", "rotate"},
	Short:   "Manage secret-rotation policies and see rotation posture",
}

const rotFlagProjectID = "project-id"

var (
	rotCName     string
	rotCDesc     string
	rotCScope    string
	rotCProject  int
	rotCEnv      int
	rotCInterval int
	rotCAlert    int
	rotCNotify   bool

	rotLProject int
	rotLEnv     int

	rotSProject int

	rotPlanAllProjects bool
)

var rotListCmd = &cobra.Command{
	Use:   "list",
	Short: "List rotation policies",
	RunE:  runRotList,
}

var rotCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a rotation policy",
	RunE:  runRotCreate,
}

var rotShowCmd = &cobra.Command{
	Use:   "show <id>",
	Short: "Show a rotation policy",
	Args:  cobra.ExactArgs(1),
	RunE:  runRotShow,
}

var rotDeleteCmd = &cobra.Command{
	Use:   "delete <id>",
	Short: "Delete a rotation policy",
	Args:  cobra.ExactArgs(1),
	RunE:  runRotDelete,
}

var rotStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show policy-covered secrets that are overdue or approaching rotation",
	RunE:  runRotStatus,
}

var rotPlanCmd = &cobra.Command{
	Use:   "plan [project-id]",
	Short: "Print an automated rotation plan (dependency-safe waves, by urgency)",
	Long: `Print the rotation plan for a project: its overdue and due-soon secrets, batched
into dependency-safe waves (rotate a wave at a time, top to bottom; within a wave the
most urgent first) and annotated with why each is due and what it must follow (ADR-053).

With --all-projects, print the deployment-wide roll-up instead: every project's plan
aggregated into install-wide totals, most pressing project first. Dependencies are
per-project, so each project keeps its own wave order.`,
	Args:         cobra.MaximumNArgs(1),
	SilenceUsage: true,
	RunE:         runRotPlan,
}

var rotOrderCmd = &cobra.Command{
	Use:   "order <project-id>",
	Short: "Print a safe rotation sequence for a project's dependency graph",
	Long: `Print the order in which a project's secrets should be rotated so that each secret
is rotated before anything that depends on it (a topological sort of the dependency
graph, ADR-052). Only secrets that appear in the graph are listed.`,
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE:         runRotOrder,
}

func init() {
	rotCreateCmd.Flags().StringVar(&rotCName, "name", "", "Policy name (required)")
	rotCreateCmd.Flags().StringVar(&rotCDesc, "description", "", "Policy description")
	rotCreateCmd.Flags().StringVar(&rotCScope, "scope", "", "Scope: project | environment (required)")
	rotCreateCmd.Flags().IntVar(&rotCProject, rotFlagProjectID, 0, "Target project (required when --scope project)")
	rotCreateCmd.Flags().IntVar(&rotCEnv, "environment-id", 0, "Target environment (required when --scope environment)")
	rotCreateCmd.Flags().IntVar(&rotCInterval, "interval-days", 0, "Rotation interval in days, 1-365 (required)")
	rotCreateCmd.Flags().IntVar(&rotCAlert, "alert-days-before", 7, "Warn this many days before the deadline (0-90)")
	rotCreateCmd.Flags().BoolVar(&rotCNotify, "notify-on-breach", true, "Notify when a covered secret goes overdue")

	rotListCmd.Flags().IntVar(&rotLProject, rotFlagProjectID, 0, "Filter by project")
	rotListCmd.Flags().IntVar(&rotLEnv, "environment-id", 0, "Filter by environment")

	rotStatusCmd.Flags().IntVar(&rotSProject, rotFlagProjectID, 0, "Limit to a single project")

	rotPlanCmd.Flags().BoolVar(&rotPlanAllProjects, "all-projects", false, "Plan rotation across every project (deployment-wide roll-up)")

	rotationCmd.AddCommand(rotListCmd, rotCreateCmd, rotShowCmd, rotDeleteCmd, rotStatusCmd, rotPlanCmd, rotOrderCmd)
	rootCmd.AddCommand(rotationCmd)
}

// rotationAPIClient resolves the stored credentials and builds a client, the shared
// pre-flight every rotation subcommand needs.
func rotationAPIClient() (*apiclient.ClientWithResponses, error) {
	store, err := resolveCredStore()
	if err != nil {
		return nil, fmt.Errorf("resolve credential store: %w", err)
	}
	serverURL, token, err := resolveServerAndToken(store)
	if err != nil {
		return nil, err
	}
	return newAPIClient(serverURL, token)
}

func rotScopeTarget(p apiclient.RotationPolicy) string {
	scope := derefStr((*string)(p.Scope))
	if scope == "project" && p.ProjectId != nil {
		return fmt.Sprintf("project=%d", *p.ProjectId)
	}
	if scope == "environment" && p.EnvironmentId != nil {
		return fmt.Sprintf("env=%d", *p.EnvironmentId)
	}
	return scope
}

func runRotList(_ *cobra.Command, _ []string) error {
	if err := checkOutputFormat(rotationListFormat); err != nil {
		return err
	}
	client, err := rotationAPIClient()
	if err != nil {
		return err
	}
	var params apiclient.ListRotationPoliciesParams
	if rotLProject > 0 {
		params.ProjectId = &rotLProject
	}
	if rotLEnv > 0 {
		params.EnvironmentId = &rotLEnv
	}
	resp, err := client.ListRotationPoliciesWithResponse(context.Background(), &params)
	if err != nil {
		return err
	}
	var policies []apiclient.RotationPolicy
	if resp.JSON200 != nil && resp.JSON200.Data != nil {
		policies = *resp.JSON200.Data
	}
	return emitList(rotationListFormat, policies, func() error {
		if resp.JSON200 == nil || resp.JSON200.Data == nil || len(*resp.JSON200.Data) == 0 {
			fmt.Println("No rotation policies.")
			return nil
		}
		// Fixed-width fmt.Printf, not cliout.NewStdoutTable: the old CLI's listCmd
		// rolls its own fixed-width columns here rather than using a shared
		// tabwriter helper (unlike pat/machine list, which do use one and so
		// happen to already match cliout's tabwriter output) -- matching it
		// exactly is what makes this command's output byte-for-byte parity-
		// checkable in scripts/cli-parity-check.sh, per this port's own mandate.
		fmt.Printf("%-5s %-24s %-14s %-9s %-7s %s\n", "ID", "NAME", "TARGET", "INTERVAL", "ACTIVE", "ALERT")
		for _, p := range *resp.JSON200.Data {
			fmt.Printf("%-5d %-24s %-14s %-9s %-7t %dd\n",
				derefUint32(p.Id), derefStr(p.Name), rotScopeTarget(p),
				fmt.Sprintf("%dd", derefInt(p.IntervalDays)), derefBool(p.IsActive), derefInt(p.AlertDaysBefore))
		}
		return nil
	})
}

func runRotCreate(_ *cobra.Command, _ []string) error {
	if strings.TrimSpace(rotCName) == "" {
		return usageErrorf("--name is required")
	}
	if rotCScope != "project" && rotCScope != "environment" {
		return fmt.Errorf("--scope must be 'project' or 'environment'")
	}
	if rotCInterval < 1 || rotCInterval > 365 {
		return fmt.Errorf("--interval-days must be between 1 and 365")
	}
	if rotCScope == "project" && rotCProject == 0 {
		return usageErrorf("--project-id is required when --scope project")
	}
	if rotCScope == "environment" && rotCEnv == 0 {
		return usageErrorf("--environment-id is required when --scope environment")
	}

	body := apiclient.CreateRotationPolicyJSONRequestBody{
		Name:            rotCName,
		Scope:           apiclient.CreateRotationPolicyJSONBodyScope(rotCScope),
		IntervalDays:    rotCInterval,
		AlertDaysBefore: &rotCAlert,
		NotifyOnBreach:  &rotCNotify,
	}
	if rotCDesc != "" {
		body.Description = &rotCDesc
	}
	if rotCProject > 0 {
		body.ProjectId = &rotCProject
	}
	if rotCEnv > 0 {
		body.EnvironmentId = &rotCEnv
	}

	client, err := rotationAPIClient()
	if err != nil {
		return err
	}
	resp, err := client.CreateRotationPolicyWithResponse(context.Background(), body)
	if err != nil {
		return err
	}
	if resp.JSON201 == nil || resp.JSON201.Data == nil {
		return httpStatusError("create rotation policy failed", resp.StatusCode(), resp.Body)
	}
	p := *resp.JSON201.Data
	fmt.Printf("Created rotation policy #%d %q (%s, every %dd, alert %dd before).\n",
		derefUint32(p.Id), derefStr(p.Name), rotScopeTarget(p), derefInt(p.IntervalDays), derefInt(p.AlertDaysBefore))
	return nil
}

func runRotShow(_ *cobra.Command, args []string) error {
	id, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("invalid policy id: %s", args[0])
	}
	client, err := rotationAPIClient()
	if err != nil {
		return err
	}
	resp, err := client.GetRotationPolicyWithResponse(context.Background(), id)
	if err != nil {
		return err
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return httpStatusError("get rotation policy failed", resp.StatusCode(), resp.Body)
	}
	p := *resp.JSON200.Data
	fmt.Printf("id:               %d\n", derefUint32(p.Id))
	fmt.Printf("name:             %s\n", derefStr(p.Name))
	if d := derefStr(p.Description); d != "" {
		fmt.Printf("description:      %s\n", d)
	}
	fmt.Printf("target:           %s\n", rotScopeTarget(p))
	fmt.Printf("interval:         %d days\n", derefInt(p.IntervalDays))
	fmt.Printf("alert before:     %d days\n", derefInt(p.AlertDaysBefore))
	fmt.Printf("notify on breach: %t\n", derefBool(p.NotifyOnBreach))
	fmt.Printf("active:           %t\n", derefBool(p.IsActive))
	fmt.Printf("created by:       %s\n", derefStr(p.CreatedBy))
	return nil
}

func runRotDelete(_ *cobra.Command, args []string) error {
	id, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("invalid policy id: %s", args[0])
	}
	client, err := rotationAPIClient()
	if err != nil {
		return err
	}
	resp, err := client.DeleteRotationPolicyWithResponse(context.Background(), id)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 204 {
		return httpStatusError("delete rotation policy failed", resp.StatusCode(), resp.Body)
	}
	fmt.Printf("Rotation policy %d deleted.\n", id)
	return nil
}

// runRotStatus matches the old CLI's `rotation status` exactly: it calls
// GET /api/v1/rotation-policies/evaluate (EvaluateRotationPolicies), NOT
// /rotation-policies/status (GetRotationStatus) despite the subcommand's name --
// confirmed against internal/cli/rotation/rotation.go's statusCmd, ground truth
// that overrides docs/cli-split-inventory.md §2.4's route-mapping summary (which
// says "status under /rotation-policies/status"; the doc is wrong here, the code
// is the source of truth). Only overdue/approaching secrets are listed -- a
// secret currently fine is omitted entirely, unlike GetRotationStatus's posture
// report which would include "ok" entries too.
func runRotStatus(_ *cobra.Command, _ []string) error {
	client, err := rotationAPIClient()
	if err != nil {
		return err
	}
	var params apiclient.EvaluateRotationPoliciesParams
	if rotSProject > 0 {
		params.ProjectId = &rotSProject
	}
	resp, err := client.EvaluateRotationPoliciesWithResponse(context.Background(), &params)
	if err != nil {
		return err
	}
	var evals []apiclient.RotationPolicyEvaluation
	if resp.JSON200 != nil && resp.JSON200.Data != nil {
		evals = *resp.JSON200.Data
	}
	overdue, approaching := 0, 0
	for _, e := range evals {
		if derefBool(e.IsOverdue) {
			overdue++
		} else if derefBool(e.IsApproaching) {
			approaching++
		}
	}
	if overdue == 0 && approaching == 0 {
		fmt.Println("All policy-covered secrets are within their rotation window.")
		return nil
	}
	fmt.Printf("%-6s %-26s %-9s %-10s %s\n", "SECRET", "NAME", "PROJECT", "STATUS", "DAYS")
	for _, e := range evals {
		var status, days string
		switch {
		case derefBool(e.IsOverdue):
			status, days = "OVERDUE", fmt.Sprintf("%d over", derefInt(e.DaysOverdue))
		case derefBool(e.IsApproaching):
			status, days = "approaching", fmt.Sprintf("%d left", -derefInt(e.DaysOverdue))
		default:
			continue
		}
		fmt.Printf("%-6d %-26s %-9d %-10s %s\n", derefUint32(e.SecretId), derefStr(e.SecretName), derefUint32(e.ProjectId), status, days)
	}
	fmt.Printf("\n%d overdue, %d approaching.\n", overdue, approaching)
	return nil
}

func runRotPlan(_ *cobra.Command, args []string) error {
	if rotPlanAllProjects {
		if len(args) > 0 {
			return fmt.Errorf("--all-projects takes no project-id argument")
		}
	} else if len(args) != 1 {
		return fmt.Errorf("provide a project id, or use --all-projects for the deployment-wide plan")
	}

	client, err := rotationAPIClient()
	if err != nil {
		return err
	}
	if rotPlanAllProjects {
		resp, err := client.GetDeploymentRotationPlanWithResponse(context.Background())
		if err != nil {
			return err
		}
		if resp.JSON200 == nil || resp.JSON200.Data == nil {
			return httpStatusError("get deployment rotation plan failed", resp.StatusCode(), resp.Body)
		}
		printDeploymentPlan(resp.JSON200.Data)
		return nil
	}

	projectID, err := strconv.ParseUint(strings.TrimSpace(args[0]), 10, 32)
	if err != nil || projectID == 0 {
		return fmt.Errorf("invalid project id %q", args[0])
	}
	resp, err := client.GetProjectRotationPlanWithResponse(context.Background(), uint32(projectID))
	if err != nil {
		return err
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return httpStatusError("get rotation plan failed", resp.StatusCode(), resp.Body)
	}
	plan := resp.JSON200.Data
	if plan.Waves == nil || len(*plan.Waves) == 0 {
		fmt.Println("Nothing to rotate — no policy-covered secret in this project is overdue or due soon.")
		return nil
	}
	printProjectPlan(plan, "")
	return nil
}

// printProjectPlan prints one project's plan: a header line, then its waves. indent is
// prefixed to every line so the same renderer serves both the single-project view (no
// indent) and each project block in the deployment-wide view.
func printProjectPlan(plan *apiclient.RotationPlan, indent string) {
	waves := 0
	if plan.Waves != nil {
		waves = len(*plan.Waves)
	}
	fmt.Printf("%sRotation plan for project %d — %d to rotate (%d overdue, %d due soon), %d wave(s):\n",
		indent, derefUint32(plan.ProjectId), derefInt(plan.TotalSecrets), derefInt(plan.OverdueCount), derefInt(plan.DueSoonCount), waves)
	if plan.Waves == nil {
		return
	}
	for _, w := range *plan.Waves {
		fmt.Printf("\n%sWave %d  (safe to rotate together):\n", indent, derefInt(w.Index)+1)
		if w.Secrets == nil {
			continue
		}
		for _, s := range *w.Secrets {
			fmt.Printf("%s  %-26s %-9s %s%s\n", indent, derefStr(s.SecretName), rotStatusLabel(s), rotRiskLabel(derefStr(s.RiskBand)), rotAutoRotateLabel(derefBool(s.AutoRotate)))
			if s.Reasons != nil && len(*s.Reasons) > 0 {
				fmt.Printf("%s      ↳ %s\n", indent, strings.Join(*s.Reasons, " · "))
			}
		}
	}
}

// printDeploymentPlan prints the install-wide roll-up: a summary line then each project's
// plan, most pressing first.
func printDeploymentPlan(plan *apiclient.DeploymentRotationPlan) {
	if derefInt(plan.ProjectsWithWork) == 0 {
		fmt.Printf("Nothing to rotate — no policy-covered secret is overdue or due soon across %d project(s).\n", derefInt(plan.ProjectsScanned))
		return
	}
	fmt.Printf("Deployment rotation plan — %d to rotate (%d overdue, %d due soon) across %d of %d project(s):\n",
		derefInt(plan.TotalSecrets), derefInt(plan.OverdueCount), derefInt(plan.DueSoonCount), derefInt(plan.ProjectsWithWork), derefInt(plan.ProjectsScanned))
	if plan.Projects == nil {
		return
	}
	for i := range *plan.Projects {
		fmt.Println()
		printProjectPlan(&(*plan.Projects)[i], "  ")
	}
}

func rotStatusLabel(s apiclient.RotationPlanSecret) string {
	if derefStr((*string)(s.Status)) == "overdue" {
		return fmt.Sprintf("%dd over", derefInt(s.DaysOverdue))
	}
	return fmt.Sprintf("%dd left", -derefInt(s.DaysOverdue))
}

func rotRiskLabel(band string) string {
	if band == "" {
		return ""
	}
	return band + " risk"
}

func rotAutoRotateLabel(auto bool) string {
	if auto {
		return "  (self-rotating)"
	}
	return ""
}

func runRotOrder(_ *cobra.Command, args []string) error {
	projectID, err := strconv.ParseUint(strings.TrimSpace(args[0]), 10, 32)
	if err != nil || projectID == 0 {
		return fmt.Errorf("invalid project id %q", args[0])
	}
	client, err := rotationAPIClient()
	if err != nil {
		return err
	}
	resp, err := client.GetProjectRotationOrderWithResponse(context.Background(), uint32(projectID))
	if err != nil {
		return err
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return httpStatusError("get rotation order failed", resp.StatusCode(), resp.Body)
	}
	view := resp.JSON200.Data
	if view.Order == nil || len(*view.Order) == 0 {
		fmt.Println("No secret dependencies in this project — secrets can rotate in any order.")
		return nil
	}
	fmt.Printf("Rotation order for project %d (rotate top to bottom):\n", derefUint32(view.ProjectId))
	for i, s := range *view.Order {
		fmt.Printf("  %2d. %-6d %s\n", i+1, derefUint32(s.SecretId), derefStr(s.SecretName))
	}
	return nil
}
