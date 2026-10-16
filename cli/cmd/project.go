// project.go ports `keyorix project` (docs/cli-split-inventory.md §2.2, PR 6): project and
// environment management. Same flags, output, and exit codes as the old CLI's
// internal/cli/project package's remote-mode branch -- this is a pure transport port (REST
// only), not a behavior change, with one exception: `project use`/`env list|create|delete|
// clone --project` no longer read/write ~/.keyorix/cli.yaml's ActiveProject (that whole file
// is gone, ADR-108 PR 0 Decision) -- they read/write the one credentials file's own
// ActiveProject field instead (cli/internal/credstore).
package cmd

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

var projectCmd = &cobra.Command{
	Use:   "project",
	Short: "Manage projects",
	Long:  "Commands for listing, creating, and inspecting Keyorix projects.",
}

var envCmd = &cobra.Command{
	Use:   "env",
	Short: "Manage environments within a project",
}

func init() {
	projectCmd.AddCommand(projectCreateCmd)
	projectCmd.AddCommand(projectListCmd)
	projectCmd.AddCommand(projectUseCmd)
	projectCmd.AddCommand(projectCurrentCmd)
	projectCmd.AddCommand(projectDescribeCmd)
	projectCmd.AddCommand(projectStatsCmd)
	projectCmd.AddCommand(projectHygieneCmd)
	projectCmd.AddCommand(projectHealthCmd)
	// Legacy alias, kept per the same conservative default this track's PR 8 step
	// documents for its own comparable decision ("don't block on it if the default is
	// conservative -- keep behaviour"): docs/cli-split-inventory.md §7 flags this as a
	// product decision, not a hard prerequisite, and the DROP candidate applies to the
	// OLD CLI's misleading local-mode failure report (Finding S8) -- this thin CLI has
	// no local mode at all, so that failure mode cannot occur here. Functionally
	// identical to `env list`.
	projectCmd.AddCommand(projectEnvironmentsCmd)

	envCmd.AddCommand(envListCmd)
	envCmd.AddCommand(envCreateCmd)
	envCmd.AddCommand(envDeleteCmd)
	envCmd.AddCommand(envCloneCmd)
	projectCmd.AddCommand(envCmd)
}

// ── project create ──────────────────────────────────────────────────────────

var (
	projectCreateName string
	projectCreateDesc string
	projectCreateEnvs string
)

var projectCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new project",
	RunE:  runProjectCreate,
}

func init() {
	projectCreateCmd.Flags().StringVar(&projectCreateName, "name", "", "Project name (required)")
	projectCreateCmd.Flags().StringVar(&projectCreateDesc, "description", "", "Project description")
	projectCreateCmd.Flags().StringVar(&projectCreateEnvs, "envs", "",
		`Comma-separated environment names to seed (default: "development,staging,production")`)
}

func runProjectCreate(_ *cobra.Command, _ []string) error {
	if projectCreateName == "" {
		return fmt.Errorf("--name is required")
	}
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}

	body := apiclient.CreateProjectJSONRequestBody{
		Name: projectCreateName,
	}
	if projectCreateDesc != "" {
		body.Description = &projectCreateDesc
	}
	var envList []string
	if projectCreateEnvs != "" {
		envList = splitCommaList(projectCreateEnvs)
		if len(envList) == 0 {
			return fmt.Errorf("--envs must not be empty")
		}
		body.Environments = &envList
	}

	resp, err := client.CreateProjectWithResponse(ctx, body)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 201 {
		return apiError("create project", resp.StatusCode(), resp.Body)
	}
	project, err := decodeData[struct {
		ID   uint   `json:"id"`
		Name string `json:"name"`
	}](resp.Body)
	if err != nil {
		return err
	}

	fmt.Printf("Project created: id=%d name=%q\n", project.ID, project.Name)
	if projectCreateEnvs != "" {
		fmt.Printf("Environments seeded: %s\n", projectCreateEnvs)
	} else {
		fmt.Println("Default environments (development, staging, production) have been seeded.")
	}
	return nil
}

func splitCommaList(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// ── project list ────────────────────────────────────────────────────────────

type projectListItem struct {
	ID          uint   `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

var projectListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all projects",
	RunE:  runProjectList,
}

func runProjectList(_ *cobra.Command, _ []string) error {
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	projects, err := listProjects(ctx, client)
	if err != nil {
		return err
	}
	printProjects(projects)
	return nil
}

// listProjects GETs /api/v1/projects, shared by every command below that needs to resolve
// a project name to an ID.
func listProjects(ctx context.Context, client *apiclient.ClientWithResponses) ([]projectListItem, error) {
	resp, err := client.ListProjectsWithResponse(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("list projects: %w", err)
	}
	if resp.StatusCode() != 200 {
		return nil, apiError("list projects", resp.StatusCode(), resp.Body)
	}
	data, err := decodeData[struct {
		Projects []projectListItem `json:"projects"`
	}](resp.Body)
	if err != nil {
		return nil, err
	}
	return data.Projects, nil
}

func printProjects(projects []projectListItem) {
	if len(projects) == 0 {
		fmt.Println("No projects found.")
		return
	}
	fmt.Printf("%-5s %-30s %s\n", "ID", "NAME", "DESCRIPTION")
	fmt.Printf("%-5s %-30s %s\n", "-----", "------------------------------", "-----------")
	for _, p := range projects {
		desc := p.Description
		if len(desc) > 40 {
			desc = desc[:37] + "..."
		}
		fmt.Printf("%-5d %-30s %s\n", p.ID, p.Name, desc)
	}
}

// ── project use / current ───────────────────────────────────────────────────

var projectUseCmd = &cobra.Command{
	Use:   "use <name>",
	Short: "Set the active project for subsequent commands",
	Long: `Saves the active project name to the credentials file (cli/internal/credstore).
All project-scoped commands inherit this context; override per-command with --project.`,
	Args: cobra.ExactArgs(1),
	RunE: runProjectUse,
}

func runProjectUse(_ *cobra.Command, args []string) error {
	name := args[0]
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	// Stored exactly as given: a project-scoped caller who ran `project use 2`
	// must keep resolving by ID later, since the name form needs the global
	// listing they cannot see (#2562).
	if _, err := resolveProjectItem(ctx, client, name); err != nil {
		return err
	}

	store, err := resolveCredStore()
	if err != nil {
		return fmt.Errorf("resolve credential store: %w", err)
	}
	// A genuinely MISSING file is not fatal here: an operator authenticating purely
	// via KEYORIX_SERVER/KEYORIX_TOKEN env vars (never ran `login`) has no credentials
	// file yet, but `project use` is still meaningful -- it only needs to persist
	// ActiveProject, not overwrite ServerURL/Token with values it never had. A file
	// that EXISTS but was refused (wider-than-0600 permissions, a symlink -- see
	// credstore.FileStore.Load's doc) must still propagate, not be silently
	// overwritten with a fresh struct -- that refusal is a tamper signal, and
	// clobbering the file would destroy the evidence and any real ServerURL/Token it
	// held.
	creds, err := store.Load()
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("load credentials: %w", err)
	}
	creds.ActiveProject = name
	if err := store.Save(creds); err != nil {
		return fmt.Errorf("save credentials: %w", err)
	}
	fmt.Printf("Active project set to %q\n", name)
	fmt.Println("All project-scoped commands will now use this project by default.")
	return nil
}

var projectCurrentCmd = &cobra.Command{
	Use:   "current",
	Short: "Show the currently active project",
	RunE:  runProjectCurrent,
}

func runProjectCurrent(_ *cobra.Command, _ []string) error {
	name, err := resolveActiveProjectName("")
	if err != nil {
		fmt.Println("No active project set.")
		fmt.Println("Run 'keyorix project use <name>' or set KEYORIX_PROJECT to configure one.")
		return nil
	}
	fmt.Println(name)
	return nil
}

// resolveActiveProjectName applies the precedence flag > KEYORIX_PROJECT env var > the
// credentials file's stored ActiveProject (mirrors the old CLI's common.ResolveProject).
func resolveActiveProjectName(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	if v := os.Getenv("KEYORIX_PROJECT"); v != "" {
		return v, nil
	}
	store, err := resolveCredStore()
	if err == nil {
		if creds, lerr := store.Load(); lerr == nil && creds.ActiveProject != "" {
			return creds.ActiveProject, nil
		}
	}
	return "", fmt.Errorf("no project specified — use --project, set KEYORIX_PROJECT, or run 'keyorix project use <name>'")
}

// resolveProjectContext resolves the active (or flag-overridden) project name to its
// numeric ID, shared by every `env` subcommand.
func resolveProjectContext(ctx context.Context, client *apiclient.ClientWithResponses, flagValue string) (string, uint, error) {
	name, err := resolveActiveProjectName(flagValue)
	if err != nil {
		return "", 0, err
	}
	p, err := resolveProjectItem(ctx, client, name)
	if err != nil {
		return "", 0, err
	}
	return name, p.ID, nil
}

// ── project describe ────────────────────────────────────────────────────────

var projectDescribeCmd = &cobra.Command{
	Use:   "describe [name]",
	Short: "Show details of a project",
	Long:  "Displays environments and description for the specified project (or the active project if none given).",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runProjectDescribe,
}

func runProjectDescribe(_ *cobra.Command, args []string) error {
	var nameArg string
	if len(args) == 1 {
		nameArg = args[0]
	}
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	name, err := resolveActiveProjectName(nameArg)
	if err != nil {
		return err
	}
	p, err := resolveProjectItem(ctx, client, name)
	if err != nil {
		return err
	}

	envs, err := listEnvironments(ctx, client, p.ID)
	if err != nil {
		return err
	}
	fmt.Printf("Project:      %s (id=%d)\n", p.Name, p.ID)
	if p.Description != "" {
		fmt.Printf("Description:  %s\n", p.Description)
	}
	fmt.Printf("Environments: %d\n", len(envs))
	for _, e := range envs {
		fmt.Printf("  - %s (id=%d)\n", e.Name, e.ID)
	}
	return nil
}

// ── project stats ───────────────────────────────────────────────────────────

var projectStatsFormat string

type projectStats struct {
	ProjectID   uint   `json:"project_id"`
	ProjectName string `json:"project_name"`

	TotalSecrets     int `json:"total_secrets"`
	ActiveSecrets    int `json:"active_secrets"`
	ExpiredSecrets   int `json:"expired_secrets"`
	ExpiringIn30Days int `json:"expiring_in_30_days"`

	RotationEnabled int        `json:"rotation_enabled"`
	OverdueRotation int        `json:"overdue_rotation"`
	LastRotationAt  *time.Time `json:"last_rotation_at,omitempty"`

	UniqueAccessors int `json:"unique_accessors"`
	OpenAnomalies   int `json:"open_anomalies"`

	ClassificationCounts map[string]int `json:"classification_counts"`

	ComputedAt time.Time `json:"computed_at"`
}

var projectStatsCmd = &cobra.Command{
	Use:          "stats <name>",
	Short:        "Show rich statistics for a project",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE:         runProjectStats,
}

func init() {
	addOutputFlag(projectStatsCmd, &projectStatsFormat)
}

func runProjectStats(_ *cobra.Command, args []string) error {
	if err := checkOutputFormat(projectStatsFormat); err != nil {
		return err
	}
	name := args[0]
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	p, err := resolveProjectItem(ctx, client, name)
	if err != nil {
		return err
	}

	resp, err := client.GetProjectStatsWithResponse(ctx, uint32(p.ID)) // #nosec G115 -- p.ID is a DB auto-increment project ID, never near uint32's range
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		return apiError("get project stats", resp.StatusCode(), resp.Body)
	}
	stats, err := decodeData[projectStats](resp.Body)
	if err != nil {
		return err
	}
	return printProjectStats(name, &stats)
}

func printProjectStats(projectName string, s *projectStats) error {
	if projectStatsFormat == outputTable {
		printProjectStatsTable(projectName, s)
		return nil
	}
	return printStructured(projectStatsFormat, s)
}

func printProjectStatsTable(projectName string, s *projectStats) {
	fmt.Printf("Project: %s\n\n", projectName)

	fmt.Println("Secrets")
	fmt.Printf("  %-22s %d\n", "Total:", s.TotalSecrets)
	fmt.Printf("  %-22s %d\n", "Active:", s.ActiveSecrets)
	fmt.Printf("  %-22s %d\n", "Expired:", s.ExpiredSecrets)
	fmt.Printf("  %-22s %d\n", "Expiring (30d):", s.ExpiringIn30Days)
	fmt.Println()

	fmt.Println("Rotation")
	fmt.Printf("  %-22s %d\n", "With config:", s.RotationEnabled)
	fmt.Printf("  %-22s %d\n", "Overdue:", s.OverdueRotation)
	lastRot := "never"
	if s.LastRotationAt != nil {
		lastRot = s.LastRotationAt.Format("2006-01-02")
	}
	fmt.Printf("  %-22s %s\n", "Last rotation:", lastRot)
	fmt.Println()

	fmt.Println("Access")
	fmt.Printf("  %-22s %d\n", "Unique accessors:", s.UniqueAccessors)
	fmt.Printf("  %-22s %d\n", "Open anomalies:", s.OpenAnomalies)
	fmt.Println()

	if len(s.ClassificationCounts) > 0 {
		fmt.Println("Classification")
		keys := make([]string, 0, len(s.ClassificationCounts))
		for k := range s.ClassificationCounts {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("  %-22s %d\n", k+":", s.ClassificationCounts[k])
		}
	}
}

// ── project hygiene ──────────────────────────────────────────────────────────

type projectHygieneSummary struct {
	OrphanedSecrets        int `json:"orphaned_secrets"`
	UnusedSecrets          int `json:"unused_secrets"`
	ExpiringSecrets        int `json:"expiring_secrets"`
	StaleMachineIdentities int `json:"stale_machine_identities"`
	RotationOverdue        int `json:"rotation_overdue"`
}

var projectHygieneCmd = &cobra.Command{
	Use:   "hygiene <project-id>",
	Short: "Show a project's security-hygiene posture (counts)",
	Long: `Summarize a project's outstanding cleanup signals in one call: secrets whose owner
departed, secrets unused for a long window, secrets expiring/expired, and stale machine
identities. Requires secrets.read at the project scope.`,
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE:         runProjectHygiene,
}

func runProjectHygiene(_ *cobra.Command, args []string) error {
	id, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		return fmt.Errorf("invalid project ID: %s", args[0])
	}
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	resp, err := client.GetProjectHygieneWithResponse(ctx, uint32(id))
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		return apiError("get project hygiene", resp.StatusCode(), resp.Body)
	}
	h, err := decodeData[projectHygieneSummary](resp.Body)
	if err != nil {
		return err
	}
	fmt.Printf("Hygiene for project %d:\n", id)
	fmt.Printf("  orphaned secrets         %d\n", h.OrphanedSecrets)
	fmt.Printf("  unused secrets           %d\n", h.UnusedSecrets)
	fmt.Printf("  expiring/expired secrets %d\n", h.ExpiringSecrets)
	fmt.Printf("  stale machine identities %d\n", h.StaleMachineIdentities)
	fmt.Printf("  rotation overdue         %d\n", h.RotationOverdue)
	return nil
}

// ── project health ──────────────────────────────────────────────────────────

var (
	projectHealthLimit  int
	projectHealthFormat string
)

type projectHealthRiskFactor struct {
	Key    string  `json:"key"`
	Label  string  `json:"label"`
	Score  int     `json:"score"`
	Weight float64 `json:"weight"`
	Detail string  `json:"detail"`
}

type projectHealthSecretScore struct {
	SecretID   uint                      `json:"secret_id"`
	SecretName string                    `json:"secret_name"`
	Score      int                       `json:"score"`
	Band       string                    `json:"band"`
	Factors    []projectHealthRiskFactor `json:"factors"`
}

type projectHealthSummary struct {
	ProjectID       uint                       `json:"project_id"`
	TotalSecrets    int                        `json:"total_secrets"`
	HighRiskCount   int                        `json:"high_risk_count"`
	MediumRiskCount int                        `json:"medium_risk_count"`
	LowRiskCount    int                        `json:"low_risk_count"`
	TopRiskSecrets  []projectHealthSecretScore `json:"secrets"`
}

var projectHealthCmd = &cobra.Command{
	Use:          "health <name>",
	Short:        "Show the secret health summary for a project",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE:         runProjectHealth,
}

func init() {
	projectHealthCmd.Flags().IntVar(&projectHealthLimit, "limit", 20, "Maximum number of secrets to display (1-100)")
	addOutputFlag(projectHealthCmd, &projectHealthFormat)
}

func runProjectHealth(_ *cobra.Command, args []string) error {
	if err := checkOutputFormat(projectHealthFormat); err != nil {
		return err
	}
	name := args[0]
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	p, err := resolveProjectItem(ctx, client, name)
	if err != nil {
		return err
	}

	var params *apiclient.GetProjectHealthParams
	if projectHealthLimit != 20 {
		limit := projectHealthLimit
		params = &apiclient.GetProjectHealthParams{Limit: &limit}
	}
	resp, err := client.GetProjectHealthWithResponse(ctx, uint32(p.ID), params) // #nosec G115 -- p.ID is a DB auto-increment project ID, never near uint32's range
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		return apiError("get project health", resp.StatusCode(), resp.Body)
	}
	summary, err := decodeData[projectHealthSummary](resp.Body)
	if err != nil {
		return err
	}
	return printProjectHealth(name, &summary)
}

func printProjectHealth(projectName string, s *projectHealthSummary) error {
	if projectHealthFormat == outputTable {
		printProjectHealthTable(projectName, s)
		return nil
	}
	return printStructured(projectHealthFormat, s)
}

func printProjectHealthTable(projectName string, s *projectHealthSummary) {
	fmt.Printf("Project: %s  (%d secrets: %d HIGH · %d MEDIUM · %d LOW)\n\n",
		projectName, s.TotalSecrets, s.HighRiskCount, s.MediumRiskCount, s.LowRiskCount)

	if len(s.TopRiskSecrets) == 0 {
		fmt.Println("No secrets found.")
		return
	}

	fmt.Printf("%-30s  %5s  %-8s  %s\n", "SECRET NAME", "SCORE", "BAND", "TOP FACTOR")
	fmt.Printf("%-30s  %5s  %-8s  %s\n",
		strings.Repeat("-", 30), "-----", "--------", strings.Repeat("-", 30))

	for _, rs := range s.TopRiskSecrets {
		topFactor := topProjectHealthFactorDetail(rs.Factors)
		name := rs.SecretName
		if len(name) > 30 {
			name = name[:27] + "..."
		}
		fmt.Printf("%-30s  %5d  %-8s  %s\n",
			name, rs.Score, strings.ToUpper(rs.Band), topFactor)
	}
}

func topProjectHealthFactorDetail(factors []projectHealthRiskFactor) string {
	if len(factors) == 0 {
		return ""
	}
	best := factors[0]
	for _, f := range factors[1:] {
		if f.Score > best.Score {
			best = f
		}
	}
	return best.Detail
}

// ── project environments (legacy alias) ─────────────────────────────────────

var projectEnvironmentsCmd = &cobra.Command{
	Use:   "environments <project-id>",
	Short: "List environments for a project",
	Args:  cobra.ExactArgs(1),
	RunE:  runProjectEnvironments,
}

func runProjectEnvironments(_ *cobra.Command, args []string) error {
	id, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		return fmt.Errorf("invalid project ID: %s", args[0])
	}
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	envs, err := listEnvironments(ctx, client, uint(id))
	if err != nil {
		return err
	}
	printEnvironmentsByID(envs, uint(id))
	return nil
}

func printEnvironmentsByID(envs []environmentItem, projectID uint) {
	if len(envs) == 0 {
		fmt.Printf("No environments found for project %d.\n", projectID)
		return
	}
	fmt.Printf("Environments for project %d:\n", projectID)
	fmt.Printf("%-5s %s\n", "ID", "NAME")
	fmt.Printf("%-5s %s\n", "-----", "--------------------")
	for _, e := range envs {
		fmt.Printf("%-5d %s\n", e.ID, e.Name)
	}
}

// ── env list / create / delete / clone ──────────────────────────────────────

type environmentItem struct {
	ID   uint   `json:"id"`
	Name string `json:"name"`
}

func listEnvironments(ctx context.Context, client *apiclient.ClientWithResponses, projectID uint) ([]environmentItem, error) {
	resp, err := client.ListProjectEnvironmentsWithResponse(ctx, uint32(projectID), nil) // #nosec G115 -- projectID is a DB auto-increment project ID, never near uint32's range
	if err != nil {
		return nil, fmt.Errorf("list environments: %w", err)
	}
	if resp.StatusCode() != 200 {
		return nil, apiError("list environments", resp.StatusCode(), resp.Body)
	}
	data, err := decodeData[struct {
		Environments []environmentItem `json:"environments"`
	}](resp.Body)
	if err != nil {
		return nil, err
	}
	return data.Environments, nil
}

var envProjectFlag string

var envListCmd = &cobra.Command{
	Use:   "list",
	Short: "List environments for the active (or specified) project",
	RunE:  runEnvList,
}

func runEnvList(_ *cobra.Command, _ []string) error {
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	name, projectID, err := resolveProjectContext(ctx, client, envProjectFlag)
	if err != nil {
		return err
	}
	envs, err := listEnvironments(ctx, client, projectID)
	if err != nil {
		return err
	}
	printEnvironmentTable(envs, name)
	return nil
}

func printEnvironmentTable(envs []environmentItem, projectName string) {
	if len(envs) == 0 {
		fmt.Printf("No environments found for project %q.\n", projectName)
		return
	}
	fmt.Printf("Environments for project %q:\n", projectName)
	fmt.Printf("%-5s %s\n", "ID", "NAME")
	fmt.Printf("%-5s %s\n", "-----", "--------------------")
	for _, e := range envs {
		fmt.Printf("%-5d %s\n", e.ID, e.Name)
	}
}

var envCreateName string

var envCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new environment in the active (or specified) project",
	RunE:  runEnvCreate,
}

func init() {
	envCreateCmd.Flags().StringVar(&envCreateName, "name", "", "Environment name (required)")
	_ = envCreateCmd.MarkFlagRequired("name")
	envListCmd.Flags().StringVar(&envProjectFlag, "project", "", "Override the active project")
	envCreateCmd.Flags().StringVar(&envProjectFlag, "project", "", "Override the active project")
	envDeleteCmd.Flags().StringVar(&envProjectFlag, "project", "", "Override the active project")
	envDeleteCmd.Flags().BoolVar(&envDeleteConfirm, "confirm", false, "Confirm deletion without interactive prompt")
}

func runEnvCreate(_ *cobra.Command, _ []string) error {
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	_, projectID, err := resolveProjectContext(ctx, client, envProjectFlag)
	if err != nil {
		return err
	}
	resp, err := client.CreateProjectEnvironmentWithResponse(ctx, uint32(projectID), // #nosec G115 -- projectID is a DB auto-increment project ID, never near uint32's range
		apiclient.CreateProjectEnvironmentJSONRequestBody{Name: envCreateName})
	if err != nil {
		return err
	}
	if resp.StatusCode() != 201 {
		return apiError("create environment", resp.StatusCode(), resp.Body)
	}
	env, err := decodeData[environmentItem](resp.Body)
	if err != nil {
		return err
	}
	fmt.Printf("Environment %q created (id=%d)\n", env.Name, env.ID)
	return nil
}

var envDeleteConfirm bool

var envDeleteCmd = &cobra.Command{
	Use:   "delete <env-id>",
	Short: "Delete an environment by ID",
	Args:  cobra.ExactArgs(1),
	RunE:  runEnvDelete,
}

func runEnvDelete(_ *cobra.Command, args []string) error {
	id, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		return fmt.Errorf("invalid environment ID: %s", args[0])
	}
	if !envDeleteConfirm {
		return fmt.Errorf("add --confirm to confirm deletion of environment %d", id)
	}

	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}

	// Mirrors the old CLI's env delete --project safety net (env.go): when --project is
	// explicitly given, verify the id actually belongs to that project before deleting
	// it, so an operator who names the wrong project for a bare environment ID doesn't
	// silently delete a DIFFERENT project's environment. Omitted --project keeps prior
	// delete-by-bare-id behavior.
	if envProjectFlag != "" {
		_, projectID, err := resolveProjectContext(ctx, client, envProjectFlag)
		if err != nil {
			return err
		}
		envs, err := listEnvironments(ctx, client, projectID)
		if err != nil {
			return err
		}
		found := false
		for _, e := range envs {
			if e.ID == uint(id) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("environment %d does not belong to project %d", id, projectID)
		}
	}

	resp, err := client.DeleteEnvironmentWithResponse(ctx, uint32(id))
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		return apiError("delete environment", resp.StatusCode(), resp.Body)
	}
	fmt.Printf("Environment %d deleted\n", id)
	return nil
}

var envCloneProjectFlag string

var envCloneCmd = &cobra.Command{
	Use:   "clone <src-env-name> <dst-env-name>",
	Short: "Clone all secrets from one environment to another in the same project",
	Long: `Copies every secret from the source environment into the destination environment
within the same project. Secrets that already exist by name in the destination are
skipped (not overwritten). Only the latest version of each secret is copied.`,
	Args: cobra.ExactArgs(2),
	RunE: runEnvClone,
}

func init() {
	envCloneCmd.Flags().StringVar(&envCloneProjectFlag, "project", "", "Override the active project")
}

// envCloneResult mirrors core.EnvCloneResult's wire shape, via the handler-level
// envCloneResultWire type (server/http/handlers/catalog_wire.go).
type envCloneResult struct {
	SourceEnv      string   `json:"source_env"`
	DestEnv        string   `json:"dest_env"`
	SecretsCloned  int      `json:"secrets_cloned"`
	SecretsSkipped int      `json:"secrets_skipped"`
	Errors         []string `json:"errors,omitempty"`
}

func runEnvClone(_ *cobra.Command, args []string) error {
	srcName, dstName := args[0], args[1]
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	_, projectID, err := resolveProjectContext(ctx, client, envCloneProjectFlag)
	if err != nil {
		return err
	}
	envs, err := listEnvironments(ctx, client, projectID)
	if err != nil {
		return err
	}
	var srcID, dstID uint
	for _, e := range envs {
		switch e.Name {
		case srcName:
			srcID = e.ID
		case dstName:
			dstID = e.ID
		}
	}
	if srcID == 0 {
		return fmt.Errorf("source environment %q not found in project", srcName)
	}
	if dstID == 0 {
		return fmt.Errorf("destination environment %q not found in project", dstName)
	}

	resp, err := client.CloneEnvironmentWithResponse(ctx, uint32(projectID), uint32(srcID), // #nosec G115 -- projectID/srcID/dstID are DB auto-increment IDs, never near uint32's range
		apiclient.CloneEnvironmentJSONRequestBody{DestinationEnvironmentId: uint32(dstID)})
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		return apiError("clone environment", resp.StatusCode(), resp.Body)
	}
	result, err := decodeData[envCloneResult](resp.Body)
	if err != nil {
		return err
	}
	fmt.Printf("Cloned environment %q → %q\n", srcName, dstName)
	fmt.Printf("  Secrets cloned:  %d\n", result.SecretsCloned)
	if result.SecretsSkipped > 0 {
		fmt.Printf("  Secrets skipped: %d  (already exist in destination)\n", result.SecretsSkipped)
	}
	return nil
}
