// compliance.go ports `keyorix compliance` (docs/cli-split-inventory.md §2.6, PR 8): the
// deployment's controls-posture report for auditors (ISO 27001 / SOC 2 / NIS2 / DORA).
// Same flags, output, and exit codes as the old CLI's internal/cli/compliance package (10
// leaf commands: report, export, controls[.csv], verify, digest[/send],
// permission-changes, permission-baseline[.csv/json], inventory[.csv], credential-trends,
// rotation-by-backend) -- a pure transport port, not a behavior change.
//
// One known, deliberate gap carried forward unchanged (PR 8's conservative-default
// decision, docs/cli-split-inventory.md §6 GAP-2): `compliance export`'s evidence pack is
// signed only when the server's encryption is enabled and only via this on-demand call --
// it is NOT the same signed artifact the scheduled ExportComplianceEvidence job produces,
// and there is exactly one caller of that job-side signer. Porting `export`/`verify`
// as-is keeps the existing (degraded-but-safe: an unsigned pack is clearly labeled
// unsigned, never silently claimed authentic) behavior rather than changing it in this
// transport-only PR.
package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
	"github.com/keyorixhq/keyorix/cli/internal/cliout"
	"github.com/keyorixhq/keyorix/cli/internal/regularfile"
	"github.com/keyorixhq/keyorix/cli/internal/securefiles"
)

var complianceCmd = &cobra.Command{
	Use:   "compliance",
	Short: "Deployment controls-posture report (ISO 27001 / SOC 2 / NIS2 / DORA)",
}

func init() {
	complianceCmd.AddCommand(complianceReportCmd, complianceExportCmd, complianceControlsCmd, complianceVerifyCmd,
		complianceDigestCmd, compliancePermissionChangesCmd, compliancePermissionBaselineCmd, complianceInventoryCmd,
		complianceCredentialTrendsCmd, complianceRotationByBackendCmd)
	rootCmd.AddCommand(complianceCmd)
}

// ── shared: operator-supplied --output write, with the export/verify round-trip's own
// symlink/overwrite-safety guarantee (see the securefiles package). ───────────────────

func writeOutput(outputPath string, data []byte, force bool, label string) error {
	writeOut := securefiles.CreateFile
	if force {
		writeOut = securefiles.WriteFile
	}
	if err := writeOut(filepath.Dir(outputPath), filepath.Base(outputPath), data, 0o600); err != nil {
		return fmt.Errorf("cannot create output file %q (it may already exist — remove it, choose a different path, or pass --force): %w", outputPath, err)
	}
	fmt.Printf("%s written to %s.\n", label, outputPath)
	return nil
}

// emitCSV downloads a raw CSV artifact's response body and writes it to outputPath, or,
// if empty, to stdout.
func emitCSV(body []byte, outputPath, label string, force bool) error {
	if outputPath != "" {
		return writeOutput(outputPath, body, force, label)
	}
	_, _ = os.Stdout.Write(body)
	return nil
}

// ── compliance report ────────────────────────────────────────────────────────────────

type complianceClassCounts struct {
	Total        int `json:"total"`
	Public       int `json:"public"`
	Internal     int `json:"internal"`
	Confidential int `json:"confidential"`
	Restricted   int `json:"restricted"`
	Unclassified int `json:"unclassified"`
}

type compliancePosture struct {
	GeneratedAt    string `json:"generated_at"`
	AuditIntegrity struct {
		ChainVerified bool   `json:"chain_verified"`
		ChainedEvents int64  `json:"chained_events"`
		Checkpointed  bool   `json:"checkpointed"`
		Reason        string `json:"reason"`
	} `json:"audit_integrity"`
	AccessGovernance struct {
		Projects                 int `json:"projects"`
		ProjectsWithOpenCampaign int `json:"projects_with_open_campaign"`
		ProjectsNeverReviewed    int `json:"projects_never_reviewed"`
		OpenCampaigns            int `json:"open_campaigns"`
		PendingItems             int `json:"pending_items"`
		ProjectsOverdue          int `json:"projects_overdue"`
		DormantRoleGrants        int `json:"dormant_role_grants"`
		SoDViolations            int `json:"sod_violations"`
	} `json:"access_governance"`
	Rotation struct {
		CoveredSecrets int `json:"covered_secrets"`
		Overdue        int `json:"overdue"`
		DueSoon        int `json:"due_soon"`
	} `json:"rotation"`
	Identity struct {
		ActiveUsers           int `json:"active_users"`
		UsersWithSecondFactor int `json:"users_with_second_factor"`
		SecondFactorPercent   int `json:"second_factor_percent"`
	} `json:"identity"`
	EmergencyAccess struct {
		ActiveActivations int `json:"active_activations"`
		TotalActivations  int `json:"total_activations"`
	} `json:"emergency_access"`
	Classification struct {
		TotalSecrets       int                   `json:"total_secrets"`
		Public             int                   `json:"public"`
		Internal           int                   `json:"internal"`
		Confidential       int                   `json:"confidential"`
		Restricted         int                   `json:"restricted"`
		Unclassified       int                   `json:"unclassified"`
		DynamicConfigs     complianceClassCounts `json:"dynamic_configs"`
		MachineIdentities  complianceClassCounts `json:"machine_identities"`
		MachineCredentials complianceClassCounts `json:"machine_credentials"`
	} `json:"classification"`
	Anomalies struct {
		Unacknowledged   int `json:"unacknowledged"`
		HighSeverityOpen int `json:"high_severity_open"`
	} `json:"anomalies"`
	LegalHold struct {
		Active bool   `json:"active"`
		Reason string `json:"reason"`
	} `json:"legal_hold"`
	Retention struct {
		Enabled                    bool `json:"enabled"`
		AnomalyAlertsDays          int  `json:"anomaly_alerts_days"`
		ClosedAccessReviewsDays    int  `json:"closed_access_reviews_days"`
		BreakGlassDays             int  `json:"break_glass_days"`
		ResolvedAccessRequestsDays int  `json:"resolved_access_requests_days"`
	} `json:"retention"`
	Degraded        bool     `json:"degraded"`
	DegradedReasons []string `json:"degraded_reasons"`
}

func retDays(d int) string {
	if d <= 0 {
		return "keep"
	}
	return fmt.Sprintf("%dd", d)
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

var complianceReportCmd = &cobra.Command{
	Use:          "report",
	Short:        "Print the deployment's controls-posture report",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx := context.Background()
		client, err := apiClientWithSkewCheck(ctx)
		if err != nil {
			return err
		}
		resp, err := client.GetCompliancePostureWithResponse(ctx)
		if err != nil {
			return err
		}
		if resp.StatusCode() != 200 {
			return apiError("get compliance posture", resp.StatusCode(), resp.Body)
		}
		p, err := decodeData[compliancePosture](resp.Body)
		if err != nil {
			return err
		}
		fmt.Printf("Compliance posture — %s\n\n", p.GeneratedAt)

		if p.Degraded {
			fmt.Println("*** DEGRADED SNAPSHOT — one or more controls could not be collected this run ***")
			fmt.Println("*** Affected fields below hold an UNKNOWN value, NOT a verified-clean one.   ***")
			for _, reason := range p.DegradedReasons {
				fmt.Printf("    - %s\n", reason)
			}
			fmt.Println()
		}

		fmt.Println("Audit integrity (ADR-029)")
		fmt.Printf("  chain verified : %s (%d chained events)\n", yesNo(p.AuditIntegrity.ChainVerified), p.AuditIntegrity.ChainedEvents)
		fmt.Printf("  checkpointed   : %s\n", yesNo(p.AuditIntegrity.Checkpointed))
		if p.AuditIntegrity.Reason != "" {
			fmt.Printf("  note           : %s\n", p.AuditIntegrity.Reason)
		}

		fmt.Println("\nAccess governance (ISO A.5.18)")
		fmt.Printf("  projects                  : %d\n", p.AccessGovernance.Projects)
		fmt.Printf("  with an open campaign     : %d\n", p.AccessGovernance.ProjectsWithOpenCampaign)
		fmt.Printf("  never reviewed            : %d\n", p.AccessGovernance.ProjectsNeverReviewed)
		fmt.Printf("  overdue for recert        : %d\n", p.AccessGovernance.ProjectsOverdue)
		fmt.Printf("  open campaigns / pending  : %d / %d\n", p.AccessGovernance.OpenCampaigns, p.AccessGovernance.PendingItems)
		fmt.Printf("  dormant role grants       : %d\n", p.AccessGovernance.DormantRoleGrants)
		fmt.Printf("  separation-of-duties viol.: %d\n", p.AccessGovernance.SoDViolations)

		fmt.Println("\nRotation hygiene (ISO A.5.15)")
		fmt.Printf("  covered secrets : %d\n", p.Rotation.CoveredSecrets)
		fmt.Printf("  overdue/due-soon: %d / %d\n", p.Rotation.Overdue, p.Rotation.DueSoon)

		fmt.Println("\nIdentity (second factor)")
		fmt.Printf("  active users        : %d\n", p.Identity.ActiveUsers)
		fmt.Printf("  with second factor  : %d (%d%%)\n", p.Identity.UsersWithSecondFactor, p.Identity.SecondFactorPercent)

		fmt.Println("\nEmergency access (break-glass)")
		fmt.Printf("  active / total activations : %d / %d\n", p.EmergencyAccess.ActiveActivations, p.EmergencyAccess.TotalActivations)

		fmt.Println("\nData classification (ISO A.5.12)")
		fmt.Printf("  total secrets : %d\n", p.Classification.TotalSecrets)
		fmt.Printf("  restricted / confidential : %d / %d\n", p.Classification.Restricted, p.Classification.Confidential)
		fmt.Printf("  internal / public         : %d / %d\n", p.Classification.Internal, p.Classification.Public)
		fmt.Printf("  unclassified              : %d\n", p.Classification.Unclassified)
		dc := p.Classification.DynamicConfigs
		fmt.Printf("  dynamic configs (total / restricted / unclassified)     : %d / %d / %d\n", dc.Total, dc.Restricted, dc.Unclassified)
		mi := p.Classification.MachineIdentities
		fmt.Printf("  machine identities (total / restricted / unclassified)  : %d / %d / %d\n", mi.Total, mi.Restricted, mi.Unclassified)
		mc := p.Classification.MachineCredentials
		fmt.Printf("  machine credentials (total / restricted / unclassified) : %d / %d / %d\n", mc.Total, mc.Restricted, mc.Unclassified)

		fmt.Println("\nAccess anomalies (NIS2 detection)")
		fmt.Printf("  open / high-severity : %d / %d\n", p.Anomalies.Unacknowledged, p.Anomalies.HighSeverityOpen)

		fmt.Println("\nLegal hold (ISO A.5.34)")
		if p.LegalHold.Active {
			fmt.Printf("  ACTIVE — purges blocked (%s)\n", p.LegalHold.Reason)
		} else {
			fmt.Println("  none — purges run normally")
		}

		fmt.Println("\nData retention (ISO A.5.33 / GDPR)")
		if p.Retention.Enabled {
			fmt.Printf("  anomaly alerts          : %s\n", retDays(p.Retention.AnomalyAlertsDays))
			fmt.Printf("  closed access reviews   : %s\n", retDays(p.Retention.ClosedAccessReviewsDays))
			fmt.Printf("  break-glass register    : %s\n", retDays(p.Retention.BreakGlassDays))
			fmt.Printf("  resolved access requests: %s\n", retDays(p.Retention.ResolvedAccessRequestsDays))
		} else {
			fmt.Println("  not configured — compliance records kept indefinitely")
		}
		return nil
	},
}

// ── compliance export / verify ──────────────────────────────────────────────────────

var (
	complianceExportOutput string
	complianceExportForce  bool
)

var complianceExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export the auditor evidence pack (posture + supporting records) as JSON",
	Long: `Export a timestamped evidence pack — the posture plus the records that
substantiate it (the audit-chain anchor, access-review campaigns, the break-glass
register, and overdue rotations) — as JSON, for an auditor to archive. Writes to
stdout by default, or to --output FILE. Refuses to overwrite an existing --output file
unless --force is passed (a scheduled/CI evidence run reusing a fixed path needs it).`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx := context.Background()
		client, err := apiClientWithSkewCheck(ctx)
		if err != nil {
			return err
		}
		resp, err := client.GetComplianceEvidenceWithResponse(ctx)
		if err != nil {
			return err
		}
		if resp.StatusCode() != 200 {
			return apiError("get compliance evidence", resp.StatusCode(), resp.Body)
		}
		out, err := decodeData[struct {
			Filename  string `json:"filename"`
			DataB64   string `json:"data_b64"`
			Signature string `json:"signature"`
			Signed    bool   `json:"signed"`
		}](resp.Body)
		if err != nil {
			return err
		}
		// The server already pretty-prints before base64-encoding, and these bytes are
		// exactly what it signed -- do NOT re-indent/reformat them here: any reformatting
		// would change what gets written to disk from what `compliance verify` later
		// reads back, breaking the signature on a genuinely untampered pack.
		data, err := base64.StdEncoding.DecodeString(out.DataB64)
		if err != nil {
			return fmt.Errorf("server returned a malformed evidence payload: %w", err)
		}
		if complianceExportOutput != "" {
			if err := writeOutput(complianceExportOutput, data, complianceExportForce, "Evidence pack"); err != nil {
				return err
			}
			if !out.Signed {
				fmt.Println("Note: evidence signing is unavailable on the server (encryption disabled) — this pack cannot be authenticated with `keyorix compliance verify`.")
				return nil
			}
			// The signature is bound to out.Filename (the server-assigned canonical
			// name), not to complianceExportOutput's operator-chosen basename --
			// --output may legitimately differ (a fixed path for a scheduled/CI run
			// reusing it). Carrying the canonical name alongside the signature, rather
			// than re-deriving it from local disk state, is what `verify` checks
			// against later.
			sigPath := complianceExportOutput + ".sig"
			sigContent := []byte(out.Filename + "\n" + out.Signature + "\n")
			if err := writeOutput(sigPath, sigContent, complianceExportForce, "Signature"); err != nil {
				return fmt.Errorf("evidence pack written, but failed to write its detached signature %q: %w", sigPath, err)
			}
			return nil
		}
		_, _ = os.Stdout.Write(data)
		if out.Signed {
			fmt.Fprintln(os.Stderr, "Note: signature not persisted (no --output) — re-run with --output FILE to produce a pack `keyorix compliance verify` can check.")
		}
		return nil
	},
}

var (
	complianceVerifyFile string
	complianceVerifySig  string
)

// parseEvidenceSignatureFile reads a detached ".sig" file. See compliance export's doc
// comment for why the canonical filename travels WITH the signature rather than being
// re-derived from local disk state. A bare single-line signature (the format the
// server-side scheduled export writes locally, where the file is always already named
// canonically) is also accepted: falls back to verifyFilePath's own basename.
func parseEvidenceSignatureFile(raw []byte, verifyFilePath string) (filename, signature string) {
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) >= 2 && strings.TrimSpace(lines[0]) != "" && strings.TrimSpace(lines[1]) != "" {
		return strings.TrimSpace(lines[0]), strings.TrimSpace(lines[1])
	}
	return filepath.Base(verifyFilePath), strings.TrimSpace(string(raw))
}

var complianceVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify an exported evidence pack against its detached signature",
	Long: `Verify the authenticity of an archived evidence pack. Reads the pack file and
its signature (default <file>.sig) and asks the server to recompute the HMAC with its
DEK-derived signing key — proving the pack was produced by this deployment and has
not been modified. Requires server-side encryption (the signing key is DEK-derived).`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if complianceVerifyFile == "" {
			return fmt.Errorf("--file is required")
		}
		sigPath := complianceVerifySig
		if sigPath == "" {
			sigPath = complianceVerifyFile + ".sig"
		}
		data, err := regularfile.ReadFile("evidence pack", complianceVerifyFile)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", complianceVerifyFile, err)
		}
		sigRaw, err := regularfile.ReadFile("signature", sigPath)
		if err != nil {
			return fmt.Errorf("failed to read signature %s: %w", sigPath, err)
		}
		filename, signature := parseEvidenceSignatureFile(sigRaw, complianceVerifyFile)

		ctx := context.Background()
		client, err := apiClientWithSkewCheck(ctx)
		if err != nil {
			return err
		}
		body := apiclient.VerifyComplianceEvidenceJSONRequestBody{
			DataB64:   base64.StdEncoding.EncodeToString(data),
			Signature: signature,
		}
		resp, err := client.VerifyComplianceEvidenceWithResponse(ctx, body)
		if err != nil {
			return err
		}
		if resp.StatusCode() != 200 {
			return apiError("verify compliance evidence", resp.StatusCode(), resp.Body)
		}
		res, err := decodeData[struct {
			Valid          bool   `json:"valid"`
			KeyVersion     string `json:"key_version"`
			CurrentVersion string `json:"current_version"`
			Reason         string `json:"reason"`
			Filename       string `json:"filename"`
		}](resp.Body)
		if err != nil {
			return err
		}
		_ = filename // carried for symmetry with the old CLI's request shape; the server derives the binding from the request body itself
		if res.Valid {
			fmt.Printf("VALID — %s is authentic and unmodified (key version %s).\n", complianceVerifyFile, res.KeyVersion)
			return nil
		}
		fmt.Printf("NOT VERIFIED — %s\n", res.Reason)
		return fmt.Errorf("evidence pack failed verification")
	},
}

// ── compliance controls[.csv] ───────────────────────────────────────────────────────

type complianceControlMatrix struct {
	GeneratedAt string `json:"generated_at"`
	Summary     struct {
		Total         int `json:"total"`
		Pass          int `json:"pass"`
		Gap           int `json:"gap"`
		NotConfigured int `json:"not_configured"`
		Unknown       int `json:"unknown"`
	} `json:"summary"`
	Controls []struct {
		Name       string `json:"name"`
		Area       string `json:"area"`
		Status     string `json:"status"`
		Detail     string `json:"detail"`
		Frameworks struct {
			ISO27001 []string `json:"iso_27001"`
			SOC2     []string `json:"soc2"`
			NIS2     []string `json:"nis2"`
			DORA     []string `json:"dora"`
		} `json:"frameworks"`
	} `json:"controls"`
}

func statusMark(s string) string {
	switch s {
	case "pass":
		return "PASS"
	case "gap":
		return "GAP "
	case "unknown":
		return "UNK "
	default:
		return "n/a "
	}
}

func joinRefs(refs ...[]string) string {
	var all []string
	for _, r := range refs {
		all = append(all, r...)
	}
	if len(all) == 0 {
		return "—"
	}
	out := all[0]
	for _, r := range all[1:] {
		out += ", " + r
	}
	return out
}

var (
	complianceControlsCSV    bool
	complianceControlsOutput string
	complianceControlsForce  bool
)

var complianceControlsCmd = &cobra.Command{
	Use:          "controls",
	Short:        "Control matrix — controls mapped to ISO 27001 / SOC 2 / NIS2 / DORA with status",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx := context.Background()
		client, err := apiClientWithSkewCheck(ctx)
		if err != nil {
			return err
		}
		if complianceControlsCSV {
			resp, err := client.ExportComplianceControlsCSVWithResponse(ctx)
			if err != nil {
				return err
			}
			if resp.StatusCode() != 200 {
				return apiError("export control matrix CSV", resp.StatusCode(), resp.Body)
			}
			return emitCSV(resp.Body, complianceControlsOutput, "Control matrix CSV", complianceControlsForce)
		}
		if complianceControlsOutput != "" {
			return fmt.Errorf("--output is only valid together with --csv")
		}
		resp, err := client.GetComplianceControlsWithResponse(ctx)
		if err != nil {
			return err
		}
		if resp.StatusCode() != 200 {
			return apiError("get control matrix", resp.StatusCode(), resp.Body)
		}
		m, err := decodeData[complianceControlMatrix](resp.Body)
		if err != nil {
			return err
		}
		fmt.Printf("Control matrix — %s\n", m.GeneratedAt)
		fmt.Printf("  %d controls: %d pass, %d gap, %d not-configured, %d unknown\n", m.Summary.Total, m.Summary.Pass, m.Summary.Gap, m.Summary.NotConfigured, m.Summary.Unknown)
		if m.Summary.Unknown > 0 {
			fmt.Println("  *** one or more controls could not be collected this run (UNK) — treat this matrix as incomplete, not passing ***")
		}
		fmt.Println()
		for _, ctrl := range m.Controls {
			fmt.Printf("[%s] %s (%s)\n", statusMark(ctrl.Status), ctrl.Name, ctrl.Area)
			fmt.Printf("        %s\n", ctrl.Detail)
			fmt.Printf("        ISO: %s | SOC2: %s | NIS2: %s | DORA: %s\n",
				joinRefs(ctrl.Frameworks.ISO27001), joinRefs(ctrl.Frameworks.SOC2),
				joinRefs(ctrl.Frameworks.NIS2), joinRefs(ctrl.Frameworks.DORA))
		}
		return nil
	},
}

// ── compliance digest[/send] ────────────────────────────────────────────────────────

var complianceDigestSend bool

func sanitizeDigestBody(body string) string {
	lines := strings.Split(body, "\n")
	for i, line := range lines {
		lines[i] = cliout.SanitizeForTerminal(line)
	}
	return strings.Join(lines, "\n")
}

var complianceDigestCmd = &cobra.Command{
	Use:   "digest",
	Short: "Print the compliance digest, or broadcast it to notification channels (--send)",
	Long: `Print the on-demand compliance digest (the same title + body that is normally
broadcast on a schedule to Slack/Teams/webhook/email channels), or trigger an
immediate broadcast to the configured notification channels with --send.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx := context.Background()
		client, err := apiClientWithSkewCheck(ctx)
		if err != nil {
			return err
		}
		if complianceDigestSend {
			resp, err := client.SendComplianceDigestWithResponse(ctx)
			if err != nil {
				return err
			}
			if resp.StatusCode() != 200 {
				return apiError("send compliance digest", resp.StatusCode(), resp.Body)
			}
			out, err := decodeData[struct {
				Sent bool `json:"sent"`
			}](resp.Body)
			if err != nil {
				return err
			}
			if out.Sent {
				fmt.Println("Compliance digest broadcast to notification channels.")
			} else {
				fmt.Println("No notification channels configured — digest not sent.")
			}
			return nil
		}
		resp, err := client.GetComplianceDigestWithResponse(ctx)
		if err != nil {
			return err
		}
		if resp.StatusCode() != 200 {
			return apiError("get compliance digest", resp.StatusCode(), resp.Body)
		}
		d, err := decodeData[struct {
			Title string `json:"title"`
			Body  string `json:"body"`
		}](resp.Body)
		if err != nil {
			return err
		}
		fmt.Println(cliout.SanitizeForTerminal(d.Title))
		fmt.Println()
		fmt.Print(sanitizeDigestBody(d.Body))
		return nil
	},
}

// ── compliance permission-changes ───────────────────────────────────────────────────

const compliancePermChangeTimeFormat = "2006-01-02T15:04:05Z"

type compliancePermChangeReport struct {
	Since   time.Time                  `json:"since"`
	Until   time.Time                  `json:"until"`
	Changes []compliancePermChangeItem `json:"changes"`
	Total   int                        `json:"total"`
}

type compliancePermChangeItem struct {
	EventID    uint      `json:"event_id"`
	Action     string    `json:"action"`
	ActorName  string    `json:"actor_name"`
	TargetUser string    `json:"target_user"`
	RoleName   string    `json:"role_name"`
	Scope      string    `json:"scope"`
	ChangedAt  time.Time `json:"changed_at"`
}

var (
	compliancePermChangeSince string
	compliancePermChangeUntil string
	compliancePermChangeLimit int
)

var compliancePermissionChangesCmd = &cobra.Command{
	Use:   "permission-changes",
	Short: "Show role grant/revoke events from the audit trail (permission change audit)",
	Long: `Download a structured list of permission change events (role grants and
revokes) from the audit trail. Prints a table of: Time | Actor | Action | Target | Role | Scope.
Requires audit.read.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		params := &apiclient.GetCompliancePermissionChangesParams{}
		if compliancePermChangeSince != "" {
			t, err := time.Parse(time.RFC3339, compliancePermChangeSince)
			if err != nil {
				return fmt.Errorf("invalid --since value %q: must be RFC3339 (e.g. 2026-01-01T00:00:00Z)", compliancePermChangeSince)
			}
			params.Since = &t
		}
		if compliancePermChangeUntil != "" {
			t, err := time.Parse(time.RFC3339, compliancePermChangeUntil)
			if err != nil {
				return fmt.Errorf("invalid --until value %q: must be RFC3339 (e.g. 2026-12-31T23:59:59Z)", compliancePermChangeUntil)
			}
			params.Until = &t
		}
		if compliancePermChangeLimit > 0 {
			params.Limit = &compliancePermChangeLimit
		}

		ctx := context.Background()
		client, err := apiClientWithSkewCheck(ctx)
		if err != nil {
			return err
		}
		resp, err := client.GetCompliancePermissionChangesWithResponse(ctx, params)
		if err != nil {
			return err
		}
		if resp.StatusCode() != 200 {
			return apiError("get permission changes", resp.StatusCode(), resp.Body)
		}
		report, err := decodeData[compliancePermChangeReport](resp.Body)
		if err != nil {
			return err
		}

		fmt.Printf("Permission change audit trail (%d events, %s – %s)\n\n",
			report.Total,
			report.Since.UTC().Format(compliancePermChangeTimeFormat),
			report.Until.UTC().Format(compliancePermChangeTimeFormat),
		)

		if report.Total == 0 {
			fmt.Println("No permission changes in the selected window.")
			return nil
		}

		fmt.Printf("%-22s  %-16s  %-16s  %-16s  %-20s  %s\n",
			"Time", "Actor", "Action", "Target", "Role", "Scope")
		fmt.Printf("%-22s  %-16s  %-16s  %-16s  %-20s  %s\n",
			"----------------------", "----------------", "----------------",
			"----------------", "--------------------", "------")
		for _, e := range report.Changes {
			fmt.Printf("%-22s  %-16s  %-16s  %-16s  %-20s  %s\n",
				e.ChangedAt.UTC().Format(compliancePermChangeTimeFormat),
				truncateRunes(cliout.SanitizeForTerminal(e.ActorName), 16),
				truncateRunes(e.Action, 16),
				truncateRunes(cliout.SanitizeForTerminal(e.TargetUser), 16),
				truncateRunes(cliout.SanitizeForTerminal(e.RoleName), 20),
				cliout.SanitizeForTerminal(e.Scope),
			)
		}
		return nil
	},
}

// ── compliance permission-baseline[.csv/json] ──────────────────────────────────────

var (
	compliancePermBaselineFormat string
	compliancePermBaselineOutput string
	compliancePermBaselineForce  bool
)

var compliancePermissionBaselineCmd = &cobra.Command{
	Use:   "permission-baseline",
	Short: "Export the permission baseline (every user's effective permissions) as CSV or JSON",
	Long: `Download the full permission baseline — every user's effective permissions,
expanded through direct role grants and group membership — for auditor hand-off.
Outputs CSV by default; use --format json for the JSON form.
Writes to stdout by default, or to --output FILE. Refuses to overwrite an existing
--output file unless --force is passed (a scheduled/CI evidence run reusing a fixed
path needs it).
Requires audit.read.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx := context.Background()
		client, err := apiClientWithSkewCheck(ctx)
		if err != nil {
			return err
		}
		switch compliancePermBaselineFormat {
		case "json":
			resp, err := client.GetCompliancePermissionBaselineWithResponse(ctx)
			if err != nil {
				return err
			}
			if resp.StatusCode() != 200 {
				return apiError("get permission baseline", resp.StatusCode(), resp.Body)
			}
			raw, err := decodeData[json.RawMessage](resp.Body)
			if err != nil {
				return err
			}
			var pretty bytes.Buffer
			if err := json.Indent(&pretty, raw, "", "  "); err != nil {
				pretty.Write(raw)
			}
			pretty.WriteByte('\n')
			if compliancePermBaselineOutput != "" {
				return writeOutput(compliancePermBaselineOutput, pretty.Bytes(), compliancePermBaselineForce, "Permission baseline JSON")
			}
			_, _ = os.Stdout.Write(pretty.Bytes())
			return nil
		case "csv", "":
			resp, err := client.GetCompliancePermissionBaselineCSVWithResponse(ctx)
			if err != nil {
				return err
			}
			if resp.StatusCode() != 200 {
				return apiError("get permission baseline CSV", resp.StatusCode(), resp.Body)
			}
			return emitCSV(resp.Body, compliancePermBaselineOutput, "Permission baseline CSV", compliancePermBaselineForce)
		default:
			return fmt.Errorf("unknown format %q — use csv or json", compliancePermBaselineFormat)
		}
	},
}

// ── compliance inventory[.csv] ──────────────────────────────────────────────────────

var (
	complianceInventoryProject uint32
	complianceInventoryOutput  string
	complianceInventoryForce   bool
)

var complianceInventoryCmd = &cobra.Command{
	Use:   "inventory",
	Short: "Export the secret asset inventory as CSV (deployment-wide, or one project)",
	Long: `Download the secret asset-inventory as CSV for an auditor hand-off — secrets
listed by name, project, environment, type, classification, owner, and lifecycle
status, with no secret values. Deployment-wide by default (needs system.read);
--project <id> scopes it to a single project (needs secrets.read on that project).
Writes to stdout, or to --output FILE. Refuses to overwrite an existing --output file
unless --force is passed (a scheduled/CI evidence run reusing a fixed path needs it).`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx := context.Background()
		client, err := apiClientWithSkewCheck(ctx)
		if err != nil {
			return err
		}
		var (
			resp interface {
				StatusCode() int
			}
			body []byte
		)
		if complianceInventoryProject != 0 {
			r, err := client.GetProjectSecretsInventoryCSVWithResponse(ctx, complianceInventoryProject)
			if err != nil {
				return err
			}
			resp, body = r, r.Body
		} else {
			r, err := client.GetSecretsInventoryCSVWithResponse(ctx)
			if err != nil {
				return err
			}
			resp, body = r, r.Body
		}
		if resp.StatusCode() != 200 {
			return apiError("get secret inventory CSV", resp.StatusCode(), body)
		}
		return emitCSV(body, complianceInventoryOutput, "Secret inventory CSV", complianceInventoryForce)
	},
}

// ── compliance credential-trends ────────────────────────────────────────────────────

type complianceTrendPoint struct {
	Date          time.Time `json:"date"`
	StalePATs     int       `json:"stale_pats"`
	ExpiredPATs   int       `json:"expired_pats"`
	StaleMachines int       `json:"stale_machines"`
	TotalPATs     int       `json:"total_pats"`
	TotalMachines int       `json:"total_machines"`
}

type complianceTrendsReport struct {
	Days   int                    `json:"days"`
	Points []complianceTrendPoint `json:"points"`
}

var complianceCredTrendDays int

var complianceCredentialTrendsCmd = &cobra.Command{
	Use:          "credential-trends",
	Short:        "Show 30/60/90-day credential hygiene trends (stale/expired PATs, stale machine creds)",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if complianceCredTrendDays != 30 && complianceCredTrendDays != 60 && complianceCredTrendDays != 90 {
			complianceCredTrendDays = 30
		}
		ctx := context.Background()
		client, err := apiClientWithSkewCheck(ctx)
		if err != nil {
			return err
		}
		days := apiclient.GetComplianceCredentialTrendsParamsDays(complianceCredTrendDays)
		resp, err := client.GetComplianceCredentialTrendsWithResponse(ctx, &apiclient.GetComplianceCredentialTrendsParams{Days: &days})
		if err != nil {
			return err
		}
		if resp.StatusCode() != 200 {
			return apiError("get credential trends", resp.StatusCode(), resp.Body)
		}
		report, err := decodeData[complianceTrendsReport](resp.Body)
		if err != nil {
			return err
		}
		fmt.Printf("Credential hygiene trends — last %d days\n\n", report.Days)
		fmt.Printf("%-12s  %10s  %12s  %14s  %10s  %14s\n",
			"Date", "StalePATs", "ExpiredPATs", "StaleMachines", "TotalPATs", "TotalMachines")
		fmt.Printf("%-12s  %10s  %12s  %14s  %10s  %14s\n",
			"------------", "----------", "------------", "--------------", "----------", "--------------")
		for _, p := range report.Points {
			fmt.Printf("%-12s  %10d  %12d  %14d  %10d  %14d\n",
				p.Date.UTC().Format("2006-01-02"),
				p.StalePATs,
				p.ExpiredPATs,
				p.StaleMachines,
				p.TotalPATs,
				p.TotalMachines,
			)
		}
		return nil
	},
}

// ── compliance rotation-by-backend ──────────────────────────────────────────────────

type complianceBackendReport struct {
	GeneratedAt  time.Time               `json:"generated_at"`
	Backends     []complianceBackendStat `json:"backends"`
	TotalOverdue int                     `json:"total_overdue"`
}

type complianceBackendStat struct {
	Backend      string `json:"backend"`
	Total        int    `json:"total"`
	Overdue      int    `json:"overdue"`
	UpToDate     int    `json:"up_to_date"`
	NeverRotated int    `json:"never_rotated"`
}

var complianceRotationByBackendCmd = &cobra.Command{
	Use:   "rotation-by-backend",
	Short: "Rotation-overdue secrets grouped by backend",
	Long: `Print a table of rotation-overdue secrets grouped by RotationBackend across
the whole deployment. Requires audit.read permission.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx := context.Background()
		client, err := apiClientWithSkewCheck(ctx)
		if err != nil {
			return err
		}
		resp, err := client.GetComplianceRotationByBackendWithResponse(ctx)
		if err != nil {
			return err
		}
		if resp.StatusCode() != 200 {
			return apiError("get rotation by backend", resp.StatusCode(), resp.Body)
		}
		report, err := decodeData[complianceBackendReport](resp.Body)
		if err != nil {
			return err
		}
		fmt.Printf("Rotation overdue by backend — %s\n", report.GeneratedAt.Format(time.RFC3339))
		fmt.Printf("Total overdue: %d\n\n", report.TotalOverdue)

		if len(report.Backends) == 0 {
			fmt.Println("No rotation policies found.")
			return nil
		}

		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "BACKEND\tTOTAL\tOVERDUE\tUP-TO-DATE\tNEVER ROTATED")
		for _, b := range report.Backends {
			backend := b.Backend
			if backend == "" {
				backend = "(keyorix-internal)"
			}
			_, _ = fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\n",
				backend, b.Total, b.Overdue, b.UpToDate, b.NeverRotated)
		}
		_ = tw.Flush()
		return nil
	},
}

func init() {
	complianceExportCmd.Flags().StringVar(&complianceExportOutput, "output", "", "Write the evidence pack to a file instead of stdout")
	complianceExportCmd.Flags().BoolVar(&complianceExportForce, "force", false, "Overwrite an existing --output file (default: refuse)")
	complianceControlsCmd.Flags().BoolVar(&complianceControlsCSV, "csv", false, "Download the control matrix as CSV instead of the text report")
	complianceControlsCmd.Flags().StringVar(&complianceControlsOutput, "output", "", "With --csv, write to a file instead of stdout")
	complianceControlsCmd.Flags().BoolVar(&complianceControlsForce, "force", false, "With --csv, overwrite an existing --output file (default: refuse)")
	complianceVerifyCmd.Flags().StringVar(&complianceVerifyFile, "file", "", "Path to the evidence pack JSON to verify (required)")
	complianceVerifyCmd.Flags().StringVar(&complianceVerifySig, "sig", "", "Path to the signature file (default <file>.sig)")
	complianceDigestCmd.Flags().BoolVar(&complianceDigestSend, "send", false, "Broadcast the digest to configured notification channels instead of printing it")
	compliancePermissionChangesCmd.Flags().StringVar(&compliancePermChangeSince, "since", "", "Start of the time window (RFC3339, e.g. 2026-01-01T00:00:00Z); defaults to 30 days ago")
	compliancePermissionChangesCmd.Flags().StringVar(&compliancePermChangeUntil, "until", "", "End of the time window (RFC3339); defaults to now")
	compliancePermissionChangesCmd.Flags().IntVar(&compliancePermChangeLimit, "limit", 0, "Maximum number of events to return (default 100, max 1000)")
	compliancePermissionBaselineCmd.Flags().StringVar(&compliancePermBaselineFormat, "format", "csv", "Output format: csv or json")
	compliancePermissionBaselineCmd.Flags().StringVar(&compliancePermBaselineOutput, "output", "", "Write the output to a file instead of stdout")
	compliancePermissionBaselineCmd.Flags().BoolVar(&compliancePermBaselineForce, "force", false, "Overwrite an existing --output file (default: refuse)")
	complianceInventoryCmd.Flags().Uint32Var(&complianceInventoryProject, "project", 0, "Scope to one project by ID (default: deployment-wide)")
	complianceInventoryCmd.Flags().StringVar(&complianceInventoryOutput, "output", "", "Write the CSV to a file instead of stdout")
	complianceInventoryCmd.Flags().BoolVar(&complianceInventoryForce, "force", false, "Overwrite an existing --output file (default: refuse)")
	complianceCredentialTrendsCmd.Flags().IntVar(&complianceCredTrendDays, "days", 30, "Trend window in days (30, 60, or 90)")
}
