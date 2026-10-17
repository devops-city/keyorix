// anomalies.go ports `keyorix anomalies` (docs/cli-split-inventory.md §2.5, PR 7): anomaly
// alerts, runtime detection config, and alert-escalation policies. Same flags, output, and
// exit codes as the old CLI's internal/cli/anomalies package -- a pure transport port (REST
// only, already REST-only in the old CLI too), not a behavior change, except: `anomalies
// escalation run` now calls the real human route (POST /api/v1/admin/jobs/run-alert-
// escalation) instead of the old CLI's `/api/v1/system/admin/jobs/run-alert-escalation` --
// the doomed `/system` proxy ADR-108 deletes in PR 14. Same request/response shape, same
// permission (system.write), so this is not a behavior change for the operator either.
package cmd

import (
	"context"
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
	"github.com/keyorixhq/keyorix/cli/internal/cliout"
)

var anomaliesCmd = &cobra.Command{
	Use:   "anomalies",
	Short: "Manage anomaly detection alerts",
}

var anomalyConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage anomaly detection runtime configuration",
}

var anomalyEscalationCmd = &cobra.Command{
	Use:   "escalation",
	Short: "Manage alert escalation policies",
}

func init() {
	anomaliesCmd.AddCommand(anomalyListCmd, anomalyAcknowledgeCmd)
	anomalyConfigCmd.AddCommand(anomalyConfigGetCmd, anomalyConfigSetCmd)
	anomalyEscalationCmd.AddCommand(escalationListCmd, escalationCreateCmd, escalationDeleteCmd, escalationRunCmd)
	anomaliesCmd.AddCommand(anomalyConfigCmd, anomalyEscalationCmd)
}

// ── anomalies list / acknowledge ─────────────────────────────────────────────

var anomalyUnacknowledged bool

var anomalyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List anomaly alerts",
	RunE:  runAnomalyList,
}

func init() {
	anomalyListCmd.Flags().BoolVar(&anomalyUnacknowledged, "unacknowledged", false, "Show only unacknowledged alerts")
}

type anomalyAlert struct {
	ID           uint   `json:"ID"`
	SecretName   string `json:"SecretName"`
	AlertType    string `json:"AlertType"`
	Severity     string `json:"Severity"`
	Description  string `json:"Description"`
	AccessedBy   string `json:"AccessedBy"`
	IPAddress    string `json:"IPAddress"`
	DetectedAt   string `json:"DetectedAt"`
	Acknowledged bool   `json:"Acknowledged"`
}

type anomalyListResponse struct {
	Alerts []anomalyAlert `json:"alerts"`
	Total  int            `json:"total"`
}

func runAnomalyList(_ *cobra.Command, _ []string) error {
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	var params *apiclient.ListAnomalyAlertsParams
	if anomalyUnacknowledged {
		t := true
		params = &apiclient.ListAnomalyAlertsParams{Unacknowledged: &t}
	}
	resp, err := client.ListAnomalyAlertsWithResponse(ctx, params)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		return apiError("list anomaly alerts", resp.StatusCode(), resp.Body)
	}
	result, err := decodeData[anomalyListResponse](resp.Body)
	if err != nil {
		return err
	}
	if len(result.Alerts) == 0 {
		fmt.Println("No anomaly alerts found.")
		return nil
	}
	fmt.Printf("Anomaly Alerts (%d total)\n", result.Total)
	fmt.Println("======================")
	for _, a := range result.Alerts {
		ack := ""
		if a.Acknowledged {
			ack = " [ACK]"
		}
		fmt.Printf("[%d] %s | %s | %s%s\n", a.ID, a.Severity, a.AlertType, a.DetectedAt[:min(16, len(a.DetectedAt))], ack)
		// #G69: secret name/accessed-by/description are all attacker-controlled
		// free text -- they must not be able to hide or spoof their own alert row.
		fmt.Printf("    Secret: %s | User: %s | IP: %s\n",
			cliout.SanitizeForTerminal(a.SecretName), cliout.SanitizeForTerminal(a.AccessedBy), cliout.SanitizeForTerminal(a.IPAddress))
		fmt.Printf("    %s\n\n", cliout.SanitizeForTerminal(a.Description))
	}
	return nil
}

var anomalyAcknowledgeCmd = &cobra.Command{
	Use:   "acknowledge <id>",
	Short: "Acknowledge an anomaly alert",
	Args:  cobra.ExactArgs(1),
	RunE:  runAnomalyAcknowledge,
}

func runAnomalyAcknowledge(_ *cobra.Command, args []string) error {
	id, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("invalid alert ID: %s", args[0])
	}
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	resp, err := client.AcknowledgeAnomalyAlertWithResponse(ctx, id)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		return apiError("acknowledge anomaly alert", resp.StatusCode(), resp.Body)
	}
	fmt.Printf("Alert %d acknowledged.\n", id)
	return nil
}

// ── anomaly config get / set ─────────────────────────────────────────────────

type anomalyConfigRecord struct {
	LookbackDays     int     `json:"lookback_days"`
	QuarantineHours  int     `json:"quarantine_hours"`
	OffHoursEnabled  bool    `json:"off_hours_enabled"`
	OffHoursTimezone string  `json:"off_hours_timezone"`
	OffHoursStart    int     `json:"off_hours_start"`
	OffHoursEnd      int     `json:"off_hours_end"`
	MLEnabled        bool    `json:"ml_enabled"`
	MLThreshold      float64 `json:"ml_threshold"`
	MLNumTrees       int     `json:"ml_num_trees"`
	MLSampleSize     int     `json:"ml_sample_size"`
	UpdatedAt        string  `json:"updated_at"`
	UpdatedBy        string  `json:"updated_by"`
}

type anomalyConfigResponse struct {
	Config anomalyConfigRecord `json:"config"`
}

var anomalyConfigGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Show the current anomaly detection configuration",
	RunE:  runAnomalyConfigGet,
}

func runAnomalyConfigGet(_ *cobra.Command, _ []string) error {
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	resp, err := client.GetAnomalyConfigWithResponse(ctx)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		return apiError("get anomaly config", resp.StatusCode(), resp.Body)
	}
	result, err := decodeData[anomalyConfigResponse](resp.Body)
	if err != nil {
		return err
	}
	printAnomalyConfig(result.Config)
	return nil
}

var (
	anomalyCfgLookbackDays     int
	anomalyCfgQuarantineHours  int
	anomalyCfgOffHoursEnabled  bool
	anomalyCfgOffHoursTimezone string
	anomalyCfgOffHoursStart    int
	anomalyCfgOffHoursEnd      int
	anomalyCfgMLEnabled        bool
	anomalyCfgMLThreshold      float64
	anomalyCfgMLNumTrees       int
	anomalyCfgMLSampleSize     int
)

var anomalyConfigSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Update one or more anomaly detection configuration fields",
	Long: `Update the anomaly detection runtime configuration.

Only flags that are explicitly provided are changed; all others keep their
current stored values. Changes take effect on the next detection scan
without restarting the server.`,
	RunE: runAnomalyConfigSet,
}

func init() {
	anomalyConfigSetCmd.Flags().IntVar(&anomalyCfgLookbackDays, "lookback-days", 0, "Lookback window for baseline (days)")
	anomalyConfigSetCmd.Flags().IntVar(&anomalyCfgQuarantineHours, "quarantine-hours", 0, "Quarantine period before a new actor is trusted (hours)")
	anomalyConfigSetCmd.Flags().BoolVar(&anomalyCfgOffHoursEnabled, "off-hours-enabled", false, "Enable off-hours rule")
	anomalyConfigSetCmd.Flags().StringVar(&anomalyCfgOffHoursTimezone, "off-hours-timezone", "", "IANA timezone for off-hours band (e.g. America/New_York)")
	anomalyConfigSetCmd.Flags().IntVar(&anomalyCfgOffHoursStart, "off-hours-start", 0, "Off-hours band start hour (0–23)")
	anomalyConfigSetCmd.Flags().IntVar(&anomalyCfgOffHoursEnd, "off-hours-end", 0, "Off-hours band end hour (0–23)")
	anomalyConfigSetCmd.Flags().BoolVar(&anomalyCfgMLEnabled, "ml-enabled", false, "Enable ML (Isolation Forest) anomaly detection")
	anomalyConfigSetCmd.Flags().Float64Var(&anomalyCfgMLThreshold, "ml-threshold", 0, "ML anomaly-score threshold (0.5–1.0)")
	anomalyConfigSetCmd.Flags().IntVar(&anomalyCfgMLNumTrees, "ml-num-trees", 0, "ML Isolation Forest tree count")
	anomalyConfigSetCmd.Flags().IntVar(&anomalyCfgMLSampleSize, "ml-sample-size", 0, "ML Isolation Forest per-tree subsample size")
}

func runAnomalyConfigSet(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}

	// Full-replace update: GET the current config, patch only the flags the caller
	// passed, PUT the whole object back. See the old CLI's identical NOTE (config.go)
	// on the accepted GET-then-PUT lost-update race -- unchanged by this port.
	getResp, err := client.GetAnomalyConfigWithResponse(ctx)
	if err != nil {
		return err
	}
	if getResp.StatusCode() != 200 {
		return apiError("fetch current anomaly config", getResp.StatusCode(), getResp.Body)
	}
	current, err := decodeData[anomalyConfigResponse](getResp.Body)
	if err != nil {
		return fmt.Errorf("fetch current config: %w", err)
	}
	cfg := current.Config

	if cmd.Flags().Changed("lookback-days") {
		cfg.LookbackDays = anomalyCfgLookbackDays
	}
	if cmd.Flags().Changed("quarantine-hours") {
		cfg.QuarantineHours = anomalyCfgQuarantineHours
	}
	if cmd.Flags().Changed("off-hours-enabled") {
		cfg.OffHoursEnabled = anomalyCfgOffHoursEnabled
	}
	if cmd.Flags().Changed("off-hours-timezone") {
		cfg.OffHoursTimezone = anomalyCfgOffHoursTimezone
	}
	if cmd.Flags().Changed("off-hours-start") {
		cfg.OffHoursStart = anomalyCfgOffHoursStart
	}
	if cmd.Flags().Changed("off-hours-end") {
		cfg.OffHoursEnd = anomalyCfgOffHoursEnd
	}
	if cmd.Flags().Changed("ml-enabled") {
		cfg.MLEnabled = anomalyCfgMLEnabled
	}
	if cmd.Flags().Changed("ml-threshold") {
		cfg.MLThreshold = anomalyCfgMLThreshold
	}
	if cmd.Flags().Changed("ml-num-trees") {
		cfg.MLNumTrees = anomalyCfgMLNumTrees
	}
	if cmd.Flags().Changed("ml-sample-size") {
		cfg.MLSampleSize = anomalyCfgMLSampleSize
	}

	body := apiclient.UpdateAnomalyConfigJSONRequestBody{
		LookbackDays:     &cfg.LookbackDays,
		QuarantineHours:  &cfg.QuarantineHours,
		OffHoursEnabled:  &cfg.OffHoursEnabled,
		OffHoursTimezone: &cfg.OffHoursTimezone,
		OffHoursStart:    &cfg.OffHoursStart,
		OffHoursEnd:      &cfg.OffHoursEnd,
		MlEnabled:        &cfg.MLEnabled,
		MlNumTrees:       &cfg.MLNumTrees,
		MlSampleSize:     &cfg.MLSampleSize,
	}
	mlThreshold := float32(cfg.MLThreshold)
	body.MlThreshold = &mlThreshold

	resp, err := client.UpdateAnomalyConfigWithResponse(ctx, body)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		return apiError("update anomaly config", resp.StatusCode(), resp.Body)
	}
	updated, err := decodeData[anomalyConfigResponse](resp.Body)
	if err != nil {
		return err
	}
	fmt.Println("Anomaly detection configuration updated.")
	printAnomalyConfig(updated.Config)
	return nil
}

func printAnomalyConfig(cfg anomalyConfigRecord) {
	fmt.Printf("Lookback:          %d days\n", cfg.LookbackDays)
	fmt.Printf("Quarantine:        %d hours\n", cfg.QuarantineHours)
	fmt.Printf("Off-hours enabled: %v\n", cfg.OffHoursEnabled)
	fmt.Printf("Off-hours tz:      %s\n", cfg.OffHoursTimezone)
	fmt.Printf("Off-hours band:    %02d:00–%02d:00\n", cfg.OffHoursStart, cfg.OffHoursEnd)
	fmt.Printf("ML enabled:        %v\n", cfg.MLEnabled)
	fmt.Printf("ML threshold:      %.2f\n", cfg.MLThreshold)
	fmt.Printf("ML num trees:      %d\n", cfg.MLNumTrees)
	fmt.Printf("ML sample size:    %d\n", cfg.MLSampleSize)
	if cfg.UpdatedBy != "" {
		fmt.Printf("Last updated by:   %s at %s\n", cfg.UpdatedBy, cfg.UpdatedAt)
	}
}

// ── anomaly escalation list / create / delete / run ─────────────────────────

var escalationListCmd = &cobra.Command{
	Use:   "list",
	Short: "List alert escalation policies",
	RunE:  runEscalationList,
}

type escalationPolicy struct {
	ID                   float64 `json:"id"`
	Name                 string  `json:"name"`
	MinSeverity          string  `json:"min_severity"`
	EscalateAfterMinutes float64 `json:"escalate_after_minutes"`
	ChannelIDs           string  `json:"channel_ids"`
	Enabled              bool    `json:"enabled"`
}

type escalationListResponse struct {
	Policies []escalationPolicy `json:"policies"`
}

func runEscalationList(_ *cobra.Command, _ []string) error {
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	resp, err := client.ListAlertEscalationPoliciesWithResponse(ctx)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		return apiError("list alert escalation policies", resp.StatusCode(), resp.Body)
	}
	result, err := decodeData[escalationListResponse](resp.Body)
	if err != nil {
		return err
	}
	if len(result.Policies) == 0 {
		fmt.Println("No alert escalation policies found.")
		return nil
	}
	fmt.Printf("Alert Escalation Policies (%d)\n", len(result.Policies))
	fmt.Println("================================")
	for _, p := range result.Policies {
		enabled := ""
		if !p.Enabled {
			enabled = " [disabled]"
		}
		fmt.Printf("[%.0f] %s — min_severity=%s, after=%d min, channels=%q%s\n",
			p.ID, p.Name, p.MinSeverity, int(p.EscalateAfterMinutes), p.ChannelIDs, enabled)
	}
	return nil
}

var (
	escalationName         string
	escalationMinSeverity  string
	escalationAfterMinutes int
	escalationChannels     string
)

var escalationCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create an alert escalation policy",
	RunE:  runEscalationCreate,
}

func init() {
	escalationCreateCmd.Flags().StringVar(&escalationName, "name", "", "Policy name (required)")
	escalationCreateCmd.Flags().StringVar(&escalationMinSeverity, "min-severity", "medium", "Minimum severity to escalate: low|medium|high|critical")
	escalationCreateCmd.Flags().IntVar(&escalationAfterMinutes, "after-minutes", 30, "Escalate if unacknowledged for this many minutes")
	escalationCreateCmd.Flags().StringVar(&escalationChannels, "channels", "", "Comma-separated NotificationChannel IDs")
}

func runEscalationCreate(_ *cobra.Command, _ []string) error {
	if escalationName == "" {
		return usageErrorf("--name is required")
	}
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	enabled := true
	body := apiclient.CreateAlertEscalationPolicyJSONRequestBody{
		Name:                 escalationName,
		MinSeverity:          &escalationMinSeverity,
		EscalateAfterMinutes: &escalationAfterMinutes,
		ChannelIds:           &escalationChannels,
		Enabled:              &enabled,
	}
	resp, err := client.CreateAlertEscalationPolicyWithResponse(ctx, body)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 201 {
		return apiError("create alert escalation policy", resp.StatusCode(), resp.Body)
	}
	created, err := decodeData[escalationPolicy](resp.Body)
	if err != nil {
		return err
	}
	fmt.Printf("Created alert escalation policy %.0f: %s\n", created.ID, created.Name)
	return nil
}

var escalationDeleteCmd = &cobra.Command{
	Use:   "delete <id>",
	Short: "Delete an alert escalation policy",
	Args:  cobra.ExactArgs(1),
	RunE:  runEscalationDelete,
}

func runEscalationDelete(_ *cobra.Command, args []string) error {
	id, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("invalid policy ID: %s", args[0])
	}
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	resp, err := client.DeleteAlertEscalationPolicyWithResponse(ctx, id)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		return apiError("delete alert escalation policy", resp.StatusCode(), resp.Body)
	}
	fmt.Printf("Deleted alert escalation policy %d.\n", id)
	return nil
}

var escalationRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Trigger the alert escalation job immediately",
	RunE:  runEscalationRun,
}

type escalationRunResult struct {
	Evaluated int `json:"evaluated"`
	Escalated int `json:"escalated"`
	Skipped   int `json:"skipped"`
}

func runEscalationRun(_ *cobra.Command, _ []string) error {
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	resp, err := client.RunAlertEscalationWithResponse(ctx)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		return apiError("run alert escalation", resp.StatusCode(), resp.Body)
	}
	result, err := decodeData[escalationRunResult](resp.Body)
	if err != nil {
		return err
	}
	fmt.Printf("Alert escalation run complete: evaluated=%d, escalated=%d, skipped=%d\n",
		result.Evaluated, result.Escalated, result.Skipped)
	return nil
}
