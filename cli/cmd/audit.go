// audit.go ports `keyorix audit` (docs/cli-split-inventory.md §2.5, PR 7): operator access
// to the tamper-evident audit trail (ADR-029). Same flags, output, and exit codes as the
// old CLI's internal/cli/audit package -- a pure transport port (REST only, already
// REST-only in the old CLI too), not a behavior change.
package cmd

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
	"github.com/keyorixhq/keyorix/cli/internal/cliout"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Verify and export the tamper-evident audit trail",
}

func init() {
	auditCmd.AddCommand(auditVerifyCmd, auditExportCmd, auditCheckpointCmd, auditLogsCmd, auditSearchCmd, auditMigrateChainCmd)
}

// ── audit verify ─────────────────────────────────────────────────────────────

var (
	auditVerifyJSON    bool
	auditVerifyFull    bool
	auditVerifyTimeout time.Duration
	// auditVerifyPollInterval is how often --full polls the job (a var for tests).
	auditVerifyPollInterval = 2 * time.Second
)

var auditVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Report the audit hash chain's integrity (non-zero exit if broken or not proven)",
	Long: `Report the audit hash chain's integrity.

By default this reads the server's incremental verification: the rolling full
re-walk (every row re-hashed at least once per cycle) plus a check of the rows
after the latest signed checkpoint. Status is VALID, BROKEN, or NOT PROVEN
(no recent full verification covers the older rows yet). --full runs a full
walk on the server now, as a background job, and waits for it.`,
	SilenceUsage: true,
	RunE:         runAuditVerify,
}

func init() {
	auditVerifyCmd.Flags().BoolVar(&auditVerifyJSON, "json", false, "Emit the raw verification result as JSON (for recording the external anchor)")
	auditVerifyCmd.Flags().BoolVar(&auditVerifyFull, "full", false, "Run a full walk of the chain on the server now (a background job) and wait for its result")
	auditVerifyCmd.Flags().DurationVar(&auditVerifyTimeout, "timeout", 30*time.Minute, "With --full: how long to wait for the job")
}

type verifyResult struct {
	Valid                     bool   `json:"valid"`
	Status                    string `json:"status,omitempty"`
	Mode                      string `json:"mode,omitempty"`
	NotProvenReason           string `json:"not_proven_reason,omitempty"`
	ChainedEvents             int    `json:"chained_events"`
	UnchainedEvents           int    `json:"unchained_events"`
	HeadHash                  string `json:"head_hash"`
	HeadID                    uint   `json:"head_id"`
	FirstBrokenID             uint   `json:"first_broken_id"`
	Reason                    string `json:"reason"`
	Checkpointed              bool   `json:"checkpointed"`
	CheckpointReason          string `json:"checkpoint_reason"`
	AnchorToken               string `json:"anchor_token,omitempty"`
	AnchoredAt                string `json:"anchored_at,omitempty"`
	AnchorProvider            string `json:"anchor_provider,omitempty"`
	AnchorTrustRootConfigured bool   `json:"anchor_trust_root_configured,omitempty"`
	LastFullVerificationAt    string `json:"last_full_verification_at,omitempty"`
	LastFullThroughID         uint   `json:"last_full_verification_through_id,omitempty"`
	Coverage                  *struct {
		CheckpointID  uint `json:"checkpoint_id"`
		TailFromID    uint `json:"tail_from_id"`
		TailThroughID uint `json:"tail_through_id"`
		TailComplete  bool `json:"tail_complete"`
	} `json:"coverage,omitempty"`
}

// verifyStatus is the result's status; a server from before incremental
// verification sends only valid.
func (v *verifyResult) verifyStatus() string {
	if v.Status != "" {
		return v.Status
	}
	if v.Valid {
		return "valid"
	}
	return "broken"
}

type verifyJob struct {
	JobID  string        `json:"job_id"`
	State  string        `json:"state"`
	Error  string        `json:"error"`
	Result *verifyResult `json:"result"`
}

func runAuditVerify(_ *cobra.Command, _ []string) error {
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	var v *verifyResult
	if auditVerifyFull {
		v, err = runAuditVerifyFullJob(ctx, client)
	} else {
		var resp *apiclient.VerifyAuditChainResponse
		resp, err = client.VerifyAuditChainWithResponse(ctx, nil)
		if err == nil && resp.StatusCode() != 200 {
			err = apiError("verify audit chain", resp.StatusCode(), resp.Body)
		}
		if err == nil {
			var d verifyResult
			d, err = decodeData[verifyResult](resp.Body)
			v = &d
		}
	}
	if err != nil {
		return err
	}
	status := v.verifyStatus()

	if auditVerifyJSON {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		fmt.Println(string(b))
	} else {
		label := map[string]string{"valid": "VALID", "broken": "BROKEN", "not_proven": "NOT PROVEN"}[status]
		if label == "" {
			label = strings.ToUpper(status)
		}
		fmt.Printf("Audit chain: %s\n", label)
		fmt.Printf("  chained events:   %d\n", v.ChainedEvents)
		fmt.Printf("  unchained events: %d\n", v.UnchainedEvents)
		fmt.Printf("  head id:          %d\n", v.HeadID)
		fmt.Printf("  head hash:        %s\n", v.HeadHash)
		if v.Checkpointed {
			fmt.Println("  checkpoint:       checked against a signed in-DB checkpoint (on-box truncation detection)")
		} else {
			fmt.Println("  checkpoint:       none enforced (record (chained events, head hash) externally to anchor)")
		}
		if v.Mode == "incremental" {
			if c := v.Coverage; c != nil {
				fmt.Printf("  this check:       rows %d..%d after signed checkpoint #%d (complete: %t)\n", c.TailFromID+1, c.TailThroughID, c.CheckpointID, c.TailComplete)
			}
			if v.LastFullVerificationAt != "" {
				fmt.Printf("  full re-walk:     every row through id %d re-hashed, completed %s\n", v.LastFullThroughID, v.LastFullVerificationAt)
			} else {
				fmt.Println("  full re-walk:     none completed yet")
			}
		}
		switch status {
		case "broken":
			fmt.Printf("  first broken id:  %d\n", v.FirstBrokenID)
			fmt.Printf("  reason:           %s\n", v.Reason)
		case "not_proven":
			fmt.Printf("  not proven:       %s\n", v.NotProvenReason)
			fmt.Println("  hint:             'keyorix audit verify --full' runs a full walk now")
		default:
			if v.CheckpointReason != "" {
				fmt.Printf("  note:             %s\n", v.CheckpointReason)
			}
		}
		if v.AnchorToken != "" {
			fmt.Printf("  anchored at:      %s\n", v.AnchoredAt)
			fmt.Printf("  anchor:           %s\n", v.AnchorProvider)
			fmt.Printf("  anchor token:     %s\n", v.AnchorToken)
			if v.AnchorTrustRootConfigured {
				fmt.Println("  anchor verified:  yes (checked locally against the configured TSA trust root)")
			} else {
				fmt.Println("  anchor verified:  NO — no TSA trust root (ca_cert_path) is configured; this token was recorded but never checked against any root of trust")
			}
		}
	}

	switch status {
	case "valid":
		return nil
	case "not_proven":
		return fmt.Errorf("audit chain integrity NOT PROVEN: %s", v.NotProvenReason)
	default:
		return fmt.Errorf("audit chain verification FAILED (first broken id %d): %s", v.FirstBrokenID, v.Reason)
	}
}

// runAuditVerifyFullJob starts a server-side full walk (?full=true) and polls
// its job until it finishes.
func runAuditVerifyFullJob(ctx context.Context, client *apiclient.ClientWithResponses) (*verifyResult, error) {
	full := apiclient.VerifyAuditChainParamsFullTrue
	resp, err := client.VerifyAuditChainWithResponse(ctx, &apiclient.VerifyAuditChainParams{Full: &full})
	if err != nil {
		return nil, err
	}
	if resp.StatusCode() != http.StatusAccepted {
		return nil, apiError("start full audit verification", resp.StatusCode(), resp.Body)
	}
	started, err := decodeData[verifyJob](resp.Body)
	if err != nil {
		return nil, err
	}
	if !auditVerifyJSON {
		fmt.Fprintf(os.Stderr, "Full audit verification running on the server (job %s)...\n", started.JobID)
	}
	deadline := time.Now().Add(auditVerifyTimeout)
	for {
		jr, err := client.GetAuditVerifyJobWithResponse(ctx, started.JobID)
		if err != nil {
			return nil, err
		}
		if jr.StatusCode() != 200 {
			return nil, apiError("audit verification job", jr.StatusCode(), jr.Body)
		}
		j, err := decodeData[verifyJob](jr.Body)
		if err != nil {
			return nil, err
		}
		switch j.State {
		case "running":
		case "succeeded":
			if j.Result == nil {
				return nil, fmt.Errorf("audit verification job %s succeeded without a result", j.JobID)
			}
			return j.Result, nil
		default:
			return nil, fmt.Errorf("audit verification job %s %s: %s", j.JobID, j.State, j.Error)
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("audit verification job %s still running after %s (poll it at /api/v1/audit/verify/jobs/%s)", j.JobID, auditVerifyTimeout, j.JobID)
		}
		time.Sleep(auditVerifyPollInterval)
	}
}

// ── audit export ─────────────────────────────────────────────────────────────

var (
	auditExportSince   string
	auditExportAfterID uint
	auditExportLimit   int
	auditExportAll     bool
	auditExportCSV     bool
)

var auditExportCmd = &cobra.Command{
	Use:          "export",
	Short:        "Stream the audit feed as NDJSON (one event per line) for SIEM pull",
	SilenceUsage: true,
	RunE:         runAuditExport,
}

func init() {
	auditExportCmd.Flags().StringVar(&auditExportSince, "since", "", "Only export events at/after this time (RFC3339)")
	auditExportCmd.Flags().UintVar(&auditExportAfterID, "after-id", 0, "Resume after this event id (exclusive cursor)")
	auditExportCmd.Flags().IntVar(&auditExportLimit, "limit", 100, "Events per page (1–1000)")
	auditExportCmd.Flags().BoolVar(&auditExportAll, "all", false, "Follow the cursor to the end, emitting every event")
	auditExportCmd.Flags().BoolVar(&auditExportCSV, "csv", false, "Emit CSV (header + one row per event) instead of NDJSON")
}

type exportPage struct {
	Events     []json.RawMessage `json:"events"`
	Count      int               `json:"count"`
	NextCursor *uint             `json:"next_cursor"`
}

type csvEventRow struct {
	ID          uint   `json:"id"`
	EventType   string `json:"event_type"`
	Timestamp   string `json:"timestamp"`
	Actor       string `json:"actor"`
	ActorType   string `json:"actor_type"`
	UserID      *uint  `json:"user_id"`
	ProjectID   *uint  `json:"project_id"`
	SecretID    *uint  `json:"secret_id"`
	IPAddress   string `json:"ip_address"`
	Success     bool   `json:"success"`
	Description string `json:"description"`
}

func uintPtrStr(p *uint) string {
	if p == nil {
		return ""
	}
	return strconv.FormatUint(uint64(*p), 10)
}

func runAuditExport(cmd *cobra.Command, _ []string) error {
	if auditExportLimit < 1 || auditExportLimit > 1000 {
		return fmt.Errorf("--limit must be between 1 and 1000")
	}
	var sinceTime *time.Time
	if auditExportSince != "" {
		t, err := time.Parse(time.RFC3339, auditExportSince)
		if err != nil {
			return fmt.Errorf("invalid --since %q (want RFC3339, e.g. 2026-06-01T00:00:00Z): %w", auditExportSince, err)
		}
		sinceTime = &t
	}
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}

	var cw *csv.Writer
	if auditExportCSV {
		cw = csv.NewWriter(cmd.OutOrStdout())
		_ = cw.Write([]string{
			"id", "event_time", "event_type", "actor", "actor_type",
			"user_id", "project_id", "secret_id", "ip_address", "success", "description",
		})
	}

	after := auditExportAfterID
	total := 0
	var lastCursor *uint
	for {
		limit := auditExportLimit
		params := &apiclient.ExportAuditLogsParams{Limit: &limit, Since: sinceTime}
		if after > 0 {
			afterID := int(after)
			params.AfterId = &afterID
		}
		resp, err := client.ExportAuditLogsWithResponse(ctx, params)
		if err != nil {
			return err
		}
		if resp.StatusCode() != 200 {
			return apiError("export audit logs", resp.StatusCode(), resp.Body)
		}
		page, err := decodeData[exportPage](resp.Body)
		if err != nil {
			return err
		}
		for _, e := range page.Events {
			if cw != nil {
				var row csvEventRow
				if err := json.Unmarshal(e, &row); err != nil {
					continue
				}
				_ = cw.Write([]string{
					strconv.FormatUint(uint64(row.ID), 10), row.Timestamp, cliout.CSVSafe(row.EventType),
					cliout.CSVSafe(row.Actor), cliout.CSVSafe(row.ActorType), uintPtrStr(row.UserID), uintPtrStr(row.ProjectID),
					uintPtrStr(row.SecretID), cliout.CSVSafe(row.IPAddress), strconv.FormatBool(row.Success), cliout.CSVSafe(row.Description),
				})
				continue
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), string(e))
		}
		total += len(page.Events)
		lastCursor = page.NextCursor

		if !auditExportAll || page.NextCursor == nil || len(page.Events) == 0 {
			break
		}
		after = *page.NextCursor
	}
	if cw != nil {
		cw.Flush()
	}

	if lastCursor != nil {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "exported %d event(s); resume with --after-id %d\n", total, *lastCursor)
	} else {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "exported %d event(s); caught up\n", total)
	}
	return nil
}

// ── audit checkpoint ─────────────────────────────────────────────────────────

var auditCheckpointCmd = &cobra.Command{
	Use:          "checkpoint",
	Short:        "Write a signed checkpoint of the current audit-chain head (ADR-029)",
	SilenceUsage: true,
	RunE:         runAuditCheckpoint,
}

type checkpointResult struct {
	ID                        uint   `json:"id"`
	ChainedEvents             int64  `json:"chained_events"`
	HeadID                    uint   `json:"head_id"`
	HeadHash                  string `json:"head_hash"`
	KeyVersion                string `json:"key_version"`
	AnchoredAt                string `json:"anchored_at"`
	AnchorProvider            string `json:"anchor_provider"`
	AnchorToken               string `json:"anchor_token"`
	AnchorTrustRootConfigured bool   `json:"anchor_trust_root_configured"`
}

func runAuditCheckpoint(_ *cobra.Command, _ []string) error {
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	resp, err := client.WriteAuditCheckpointWithResponse(ctx)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		return apiError("write audit checkpoint", resp.StatusCode(), resp.Body)
	}
	out, err := decodeData[checkpointResult](resp.Body)
	if err != nil {
		return err
	}
	fmt.Println("Audit checkpoint written:")
	fmt.Printf("  id:             %d\n", out.ID)
	fmt.Printf("  chained events: %d\n", out.ChainedEvents)
	fmt.Printf("  head id:        %d\n", out.HeadID)
	fmt.Printf("  head hash:      %s\n", out.HeadHash)
	if out.AnchoredAt != "" {
		fmt.Printf("  anchored at:    %s\n", out.AnchoredAt)
		fmt.Printf("  anchor:         %s\n", out.AnchorProvider)
		fmt.Printf("  anchor token:   %s\n", out.AnchorToken)
		if !out.AnchorTrustRootConfigured {
			fmt.Println("  anchor verified: NO — no TSA trust root (ca_cert_path) is configured; this token was recorded but never checked against any root of trust")
		}
	}
	return nil
}

// ── audit migrate-chain-encoding ─────────────────────────────────────────────

var auditMigrateConfirm bool

var auditMigrateChainCmd = &cobra.Command{
	Use:          "migrate-chain-encoding",
	Short:        "One-time re-derivation of the audit hash chain under the current encoding",
	SilenceUsage: true,
	RunE:         runAuditMigrateChain,
}

func init() {
	auditMigrateChainCmd.Flags().BoolVar(&auditMigrateConfirm, "confirm", false,
		"Apply the migration for real. Without this flag, the command only previews what would change — nothing is written.")
}

type migrateChainResult struct {
	DryRun               bool   `json:"dry_run"`
	RowsMigrated         int64  `json:"rows_migrated"`
	UnchainedRowsSkipped int64  `json:"unchained_rows_skipped"`
	HeadID               uint   `json:"head_id"`
	HeadHash             string `json:"head_hash"`
	AnchorRowID          uint   `json:"anchor_row_id,omitempty"`
	AnchorNewEntryHash   string `json:"anchor_new_entry_hash,omitempty"`
}

func runAuditMigrateChain(_ *cobra.Command, _ []string) error {
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	dryRun := apiclient.MigrateAuditChainEncodingParamsDryRun("true")
	if auditMigrateConfirm {
		dryRun = apiclient.MigrateAuditChainEncodingParamsDryRun("false")
	}
	resp, err := client.MigrateAuditChainEncodingWithResponse(ctx, &apiclient.MigrateAuditChainEncodingParams{DryRun: &dryRun})
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		return apiError("migrate audit chain encoding", resp.StatusCode(), resp.Body)
	}
	out, err := decodeData[migrateChainResult](resp.Body)
	if err != nil {
		return err
	}

	if out.DryRun {
		fmt.Println("DRY RUN — nothing was written. Re-run with --confirm to apply.")
	} else {
		fmt.Println("Audit chain encoding migration applied:")
	}
	fmt.Printf("  rows migrated:          %d\n", out.RowsMigrated)
	fmt.Printf("  unchained rows skipped: %d\n", out.UnchainedRowsSkipped)
	fmt.Printf("  new head id:            %d\n", out.HeadID)
	fmt.Printf("  new head hash:          %s\n", out.HeadHash)
	if out.AnchorRowID != 0 {
		fmt.Printf("  retention anchor row:   %d (re-signed with the migrated entry_hash)\n", out.AnchorRowID)
	}
	if out.DryRun {
		fmt.Println("\nRun 'keyorix audit migrate-chain-encoding --confirm' to apply.")
	} else {
		fmt.Println("\nRun 'keyorix audit verify' to confirm the chain now verifies end to end.")
	}
	return nil
}

// ── audit logs ───────────────────────────────────────────────────────────────

var (
	auditLogEventType string
	auditLogUserID    uint
	auditLogProjectID uint
	auditLogActorType string
	auditLogSince     string
	auditLogUntil     string
	auditLogLimit     int
	auditLogCursor    string
	auditLogTotal     bool
)

var auditLogsCmd = &cobra.Command{
	Use:          "logs",
	Short:        "Query the audit trail with filters (human-readable table)",
	SilenceUsage: true,
	RunE:         runAuditLogs,
}

func init() {
	auditLogsCmd.Flags().StringVar(&auditLogEventType, "event-type", "", "Filter by event type (e.g. secret.read, secret.deleted)")
	auditLogsCmd.Flags().UintVar(&auditLogUserID, "user-id", 0, "Filter by actor user id")
	auditLogsCmd.Flags().UintVar(&auditLogProjectID, "project-id", 0, "Filter by project id")
	auditLogsCmd.Flags().StringVar(&auditLogActorType, "actor-type", "", "Filter by actor kind: user | machine_identity | system")
	auditLogsCmd.Flags().StringVar(&auditLogSince, "since", "", "Only events at/after this time (RFC3339)")
	auditLogsCmd.Flags().StringVar(&auditLogUntil, "until", "", "Only events at/before this time (RFC3339)")
	auditLogsCmd.Flags().IntVar(&auditLogLimit, "limit", 50, "Max events to show (1–100)")
	auditLogsCmd.Flags().StringVar(&auditLogCursor, "cursor", "", "Continue after a previous page (the cursor printed under it)")
	auditLogsCmd.Flags().BoolVar(&auditLogTotal, "include-total", false, "Count every matching event (exact total; slower on a large audit trail)")
}

type logEntry struct {
	ID             uint   `json:"id"`
	EventType      string `json:"event_type"`
	Actor          string `json:"actor"`
	ActorType      string `json:"actor_type"`
	Description    string `json:"description"`
	Timestamp      string `json:"timestamp"`
	Impersonation  bool   `json:"impersonation"`
	ImpersonatedBy string `json:"impersonated_by"`
}

// auditPageFooter is the paging part of the /audit/logs and /audit/search
// envelopes: total and total_exact are absent on a cursor page that did not
// ask for the total; next_cursor is null on the last page.
type auditPageFooter struct {
	Total      *int64  `json:"total"`
	TotalExact *bool   `json:"total_exact"`
	NextCursor *string `json:"next_cursor"`
}

type logsPage struct {
	Logs []logEntry `json:"logs"`
	auditPageFooter
}

func runAuditLogs(_ *cobra.Command, _ []string) error {
	if auditLogLimit < 1 || auditLogLimit > 100 {
		return fmt.Errorf("--limit must be between 1 and 100")
	}
	if auditLogActorType != "" && auditLogActorType != "user" && auditLogActorType != "machine_identity" && auditLogActorType != "system" {
		return fmt.Errorf("--actor-type must be user, machine_identity, or system")
	}
	params := &apiclient.ListAuditLogsParams{}
	limit := auditLogLimit
	params.PageSize = &limit
	if auditLogCursor != "" {
		params.Cursor = &auditLogCursor
	}
	if auditLogTotal {
		params.IncludeTotal = &auditLogTotal
	}
	if auditLogEventType != "" {
		params.Action = &auditLogEventType
	}
	if auditLogUserID > 0 {
		id := int(auditLogUserID)
		params.UserId = &id
	}
	if auditLogProjectID > 0 {
		id := int(auditLogProjectID)
		params.ProjectId = &id
	}
	if auditLogActorType != "" {
		at := apiclient.ListAuditLogsParamsActorType(auditLogActorType)
		params.ActorType = &at
	}
	if auditLogSince != "" {
		t, err := time.Parse(time.RFC3339, auditLogSince)
		if err != nil {
			return fmt.Errorf("invalid --since %q (want RFC3339, e.g. 2026-06-01T00:00:00Z): %w", auditLogSince, err)
		}
		params.StartTime = &t
	}
	if auditLogUntil != "" {
		t, err := time.Parse(time.RFC3339, auditLogUntil)
		if err != nil {
			return fmt.Errorf("invalid --until %q (want RFC3339, e.g. 2026-06-01T00:00:00Z): %w", auditLogUntil, err)
		}
		params.EndTime = &t
	}

	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	resp, err := client.ListAuditLogsWithResponse(ctx, params)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		return apiError("list audit logs", resp.StatusCode(), resp.Body)
	}
	page, err := decodeData[logsPage](resp.Body)
	if err != nil {
		return err
	}
	if len(page.Logs) == 0 {
		fmt.Println("No audit events match.")
		return nil
	}
	printAuditLogTable(page.Logs, page.auditPageFooter)
	return nil
}

// auditEventColMax caps the EVENT column; the column is otherwise as wide as the
// longest event type shown, so names such as "secret.auto_rotate_completed" are
// never cut mid-word (#2942).
const auditEventColMax = 40

func printAuditLogTable(logs []logEntry, footer auditPageFooter) {
	evW := len("EVENT")
	for _, e := range logs {
		if n := len(e.EventType); n > evW {
			evW = n
		}
	}
	if evW > auditEventColMax {
		evW = auditEventColMax
	}
	// Times are always UTC, labelled as such: other commands used to print local
	// time, and the two disagreed by the local offset on stage (#2942).
	fmt.Printf("%-6s %-20s %-16s %-9s %-*s %s\n", "ID", "TIME (UTC)", "ACTOR", "KIND", evW, "EVENT", "DESCRIPTION")
	for _, e := range logs {
		actor := e.Actor
		if e.Impersonation && e.ImpersonatedBy != "" {
			actor = e.ImpersonatedBy + "→" + e.Actor
		}
		fmt.Printf("%-6d %-20s %-16s %-9s %-*s %s\n",
			e.ID, shortTime(e.Timestamp), auditTruncate(cliout.SanitizeForTerminal(actor), 16), e.ActorType,
			evW, auditTruncate(cliout.SanitizeForTerminal(e.EventType), evW), cliout.SanitizeForTerminal(e.Description))
	}
	switch {
	case footer.Total == nil:
		fmt.Printf("\nShowing %d event(s).\n", len(logs))
	case footer.TotalExact != nil && !*footer.TotalExact:
		fmt.Printf("\nShowing %d of more than %d event(s) (--include-total counts them all).\n", len(logs), *footer.Total)
	default:
		fmt.Printf("\nShowing %d of %d total event(s).\n", len(logs), *footer.Total)
	}
	if footer.NextCursor != nil && *footer.NextCursor != "" {
		// Server-supplied text: sanitized like every other value printed here.
		fmt.Printf("Next page: --cursor %s\n", cliout.SanitizeForTerminal(*footer.NextCursor))
	}
}

func shortTime(s string) string {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return utcTime(t)
	}
	return s
}

// utcTime is the one human-readable timestamp format of the CLI: UTC, no zone
// suffix (for table columns headed "(UTC)"). Commands used to mix local
// time, RFC3339 with an offset and raw "...Z" strings (#2942).
func utcTime(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05") }

func auditTruncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

// ── audit search ─────────────────────────────────────────────────────────────

var (
	auditSearchActor        string
	auditSearchUserID       uint
	auditSearchProjectID    uint
	auditSearchAction       string
	auditSearchResourceType string
	auditSearchResourceID   uint
	auditSearchIP           string
	auditSearchSuccess      string
	auditSearchSince        string
	auditSearchUntil        string
	auditSearchLimit        int
	auditSearchOffset       int
	auditSearchCursor       string
	auditSearchTotal        bool
)

var auditSearchCmd = &cobra.Command{
	Use:          "search",
	Short:        "Search the audit trail with structured filters",
	SilenceUsage: true,
	RunE:         runAuditSearch,
}

func init() {
	auditSearchCmd.Flags().StringVar(&auditSearchActor, "actor", "", "Partial match on actor username")
	auditSearchCmd.Flags().UintVar(&auditSearchUserID, "user-id", 0, "Filter by exact actor user ID")
	auditSearchCmd.Flags().UintVar(&auditSearchProjectID, "project-id", 0, "Filter by project ID")
	auditSearchCmd.Flags().StringVar(&auditSearchAction, "action", "", "Filter by exact event type (e.g. secret.read)")
	auditSearchCmd.Flags().StringVar(&auditSearchResourceType, "resource-type", "", "Filter by resource kind (e.g. secret, user, role)")
	auditSearchCmd.Flags().UintVar(&auditSearchResourceID, "resource-id", 0, "Filter by exact resource ID (secret_node_id)")
	auditSearchCmd.Flags().StringVar(&auditSearchIP, "ip", "", "Filter by originating IP address")
	auditSearchCmd.Flags().StringVar(&auditSearchSuccess, "success", "", "Filter by outcome: true or false")
	auditSearchCmd.Flags().StringVar(&auditSearchSince, "since", "", "Only events at/after this RFC3339 time")
	auditSearchCmd.Flags().StringVar(&auditSearchUntil, "until", "", "Only events at/before this RFC3339 time")
	auditSearchCmd.Flags().IntVar(&auditSearchLimit, "limit", 100, "Max results (1–1000)")
	auditSearchCmd.Flags().IntVar(&auditSearchOffset, "offset", 0, "Pagination offset (offset+limit up to 10000; use --cursor beyond)")
	auditSearchCmd.Flags().StringVar(&auditSearchCursor, "cursor", "", "Continue after a previous page (the cursor printed under it)")
	auditSearchCmd.Flags().BoolVar(&auditSearchTotal, "include-total", false, "Count every matching event (exact total; slower on a large audit trail)")
}

// searchPage is the GET /api/v1/audit/search envelope. Its events are the same
// redacted AuditLogEntry rows as `audit logs` (timestamp, actor, actor_type, ...):
// the server never sends event_time or ip_address there (audit.go: "no
// IPAddress"), which is why the old search table printed blank TIME and IP
// columns (#2942).
type searchPage struct {
	Events []logEntry `json:"events"`
	auditPageFooter
}

func runAuditSearch(_ *cobra.Command, _ []string) error {
	if auditSearchLimit < 1 || auditSearchLimit > 1000 {
		return fmt.Errorf("--limit must be between 1 and 1000")
	}
	if auditSearchSuccess != "" && auditSearchSuccess != "true" && auditSearchSuccess != "false" {
		return fmt.Errorf("--success must be true or false")
	}
	params := &apiclient.SearchAuditLogsParams{}
	limit := auditSearchLimit
	params.Limit = &limit
	if auditSearchOffset > 0 {
		offset := auditSearchOffset
		params.Offset = &offset
	}
	if auditSearchCursor != "" {
		params.Cursor = &auditSearchCursor
	}
	if auditSearchTotal {
		params.IncludeTotal = &auditSearchTotal
	}
	if auditSearchActor != "" {
		params.Actor = &auditSearchActor
	}
	if auditSearchUserID > 0 {
		id := int(auditSearchUserID)
		params.UserId = &id
	}
	if auditSearchProjectID > 0 {
		id := int(auditSearchProjectID)
		params.ProjectId = &id
	}
	if auditSearchAction != "" {
		params.Action = &auditSearchAction
	}
	if auditSearchResourceType != "" {
		params.ResourceType = &auditSearchResourceType
	}
	if auditSearchResourceID > 0 {
		id := int(auditSearchResourceID)
		params.ResourceId = &id
	}
	if auditSearchIP != "" {
		params.Ip = &auditSearchIP
	}
	if auditSearchSuccess != "" {
		s := apiclient.SearchAuditLogsParamsSuccess(auditSearchSuccess)
		params.Success = &s
	}
	if auditSearchSince != "" {
		t, err := time.Parse(time.RFC3339, auditSearchSince)
		if err != nil {
			return fmt.Errorf("invalid --since %q (want RFC3339, e.g. 2026-06-01T00:00:00Z): %w", auditSearchSince, err)
		}
		params.Since = &t
	}
	if auditSearchUntil != "" {
		t, err := time.Parse(time.RFC3339, auditSearchUntil)
		if err != nil {
			return fmt.Errorf("invalid --until %q (want RFC3339, e.g. 2026-06-01T00:00:00Z): %w", auditSearchUntil, err)
		}
		params.Until = &t
	}

	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	resp, err := client.SearchAuditLogsWithResponse(ctx, params)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		return apiError("search audit logs", resp.StatusCode(), resp.Body)
	}
	page, err := decodeData[searchPage](resp.Body)
	if err != nil {
		return err
	}
	if len(page.Events) == 0 {
		fmt.Println("No audit events match.")
		return nil
	}
	printAuditLogTable(page.Events, page.auditPageFooter)
	return nil
}
