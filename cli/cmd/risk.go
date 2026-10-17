// risk.go ports `keyorix risk` (docs/cli-split-inventory.md §2.6, PR 8): the risk register
// / exceptions (ISO 27001 A.5.8 risk treatment). Same flags, output, and exit codes as the
// old CLI's internal/cli/risk package -- a pure transport port, not a behavior change.
package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
	"github.com/keyorixhq/keyorix/cli/internal/cliout"
)

var riskCmd = &cobra.Command{
	Use:   "risk",
	Short: "Risk register — governed, time-bound exceptions to control gaps (A.5.8)",
	Long: `Record and review accepted risk exceptions: a known control gap, accepted by
an owner with a justification, that sunsets at a fixed date. An active exception is
the evidence that a gap is governed (accepted with a deadline) rather than ignored.`,
}

func init() {
	riskCmd.AddCommand(riskListCmd, riskAddCmd, riskApproveCmd, riskRevokeCmd)
	rootCmd.AddCommand(riskCmd)
}

type riskExceptionView struct {
	ID            uint   `json:"id"`
	Title         string `json:"title"`
	Category      string `json:"category"`
	Reference     string `json:"reference"`
	Justification string `json:"justification"`
	Status        string `json:"status"`
	ExpiresAt     string `json:"expires_at"`
	CreatedBy     uint   `json:"created_by"`
	// Approved is dual-control: the exception only suppresses its matched violation
	// from the compliance posture once a different system.write holder than the
	// creator approves it (`keyorix risk approve`).
	Approved bool `json:"approved"`
}

var riskListAll bool

var riskListCmd = &cobra.Command{
	Use:          "list",
	Short:        "List risk exceptions (active by default; --all includes expired)",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if err := checkOutputFormat(riskListFormat); err != nil {
			return err
		}
		ctx := context.Background()
		client, err := apiClientWithSkewCheck(ctx)
		if err != nil {
			return err
		}
		all := riskListAll
		resp, err := client.ListRiskExceptionsWithResponse(ctx, &apiclient.ListRiskExceptionsParams{All: &all})
		if err != nil {
			return err
		}
		if resp.StatusCode() != 200 {
			return apiError("list risk exceptions", resp.StatusCode(), resp.Body)
		}
		out, err := decodeData[struct {
			Exceptions []riskExceptionView `json:"exceptions"`
		}](resp.Body)
		if err != nil {
			return err
		}
		return emitList(riskListFormat, out.Exceptions, func() error {
			if len(out.Exceptions) == 0 {
				fmt.Println("No risk exceptions.")
				return nil
			}
			for _, e := range out.Exceptions {
				approval := "pending approval"
				if e.Approved {
					approval = "approved"
				}
				fmt.Printf("[%s, %s] #%d %s (category=%s, ref=%q)\n", e.Status, approval, e.ID,
					cliout.SanitizeForTerminal(e.Title), cliout.SanitizeForTerminal(e.Category), cliout.SanitizeForTerminal(e.Reference))
				fmt.Printf("        expires %s — %s\n", e.ExpiresAt, cliout.SanitizeForTerminal(e.Justification))
			}
			return nil
		})
	},
}

var (
	riskAddTitle, riskAddCategory, riskAddReference, riskAddJustification, riskAddExpires string
)

var riskAddCmd = &cobra.Command{
	Use:          "add",
	Short:        "Record a risk exception (accept a control gap for a bounded time)",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if riskAddTitle == "" || riskAddJustification == "" {
			return usageErrorf("--title and --justification are required")
		}
		if riskAddExpires == "" {
			return usageErrorf("--expires is required (RFC3339, e.g. 2026-12-31T00:00:00Z)")
		}
		expiresAt, err := time.Parse(time.RFC3339, riskAddExpires)
		if err != nil {
			return fmt.Errorf("--expires must be RFC3339 (e.g. 2026-12-31T00:00:00Z)")
		}
		ctx := context.Background()
		client, err := apiClientWithSkewCheck(ctx)
		if err != nil {
			return err
		}
		category := apiclient.CreateRiskExceptionJSONBodyCategory(riskAddCategory)
		body := apiclient.CreateRiskExceptionJSONRequestBody{
			Title:         riskAddTitle,
			Category:      &category,
			Reference:     &riskAddReference,
			Justification: riskAddJustification,
			ExpiresAt:     expiresAt,
		}
		resp, err := client.CreateRiskExceptionWithResponse(ctx, body)
		if err != nil {
			return err
		}
		if resp.StatusCode() != 200 && resp.StatusCode() != 201 {
			return apiError("record risk exception", resp.StatusCode(), resp.Body)
		}
		out, err := decodeData[struct {
			Exception riskExceptionView `json:"exception"`
		}](resp.Body)
		if err != nil {
			return err
		}
		fmt.Printf("Risk exception recorded (id=%d), expiring %s.\n", out.Exception.ID, riskAddExpires)
		return nil
	},
}

var riskApproveID int

var riskApproveCmd = &cobra.Command{
	Use:   "approve",
	Short: "Approve a risk exception so it takes effect (dual control — must not be its own creator)",
	Long: `An exception is inert until approved: it does not suppress its matched
violation from the compliance posture until a DIFFERENT system.write holder than
the one who created it approves it. This prevents a single principal from
unilaterally creating and self-approving a suppression of their own risk.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if riskApproveID == 0 {
			return usageErrorf("--id is required")
		}
		ctx := context.Background()
		client, err := apiClientWithSkewCheck(ctx)
		if err != nil {
			return err
		}
		resp, err := client.ApproveRiskExceptionWithResponse(ctx, riskApproveID)
		if err != nil {
			return err
		}
		if resp.StatusCode() != 200 {
			return apiError("approve risk exception", resp.StatusCode(), resp.Body)
		}
		fmt.Printf("Risk exception %d approved.\n", riskApproveID)
		return nil
	},
}

var riskRevokeID int

var riskRevokeCmd = &cobra.Command{
	Use:          "revoke",
	Short:        "Revoke a risk exception before its expiry",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if riskRevokeID == 0 {
			return usageErrorf("--id is required")
		}
		ctx := context.Background()
		client, err := apiClientWithSkewCheck(ctx)
		if err != nil {
			return err
		}
		resp, err := client.RevokeRiskExceptionWithResponse(ctx, riskRevokeID)
		if err != nil {
			return err
		}
		if resp.StatusCode() != 200 {
			return apiError("revoke risk exception", resp.StatusCode(), resp.Body)
		}
		fmt.Printf("Risk exception %d revoked.\n", riskRevokeID)
		return nil
	},
}

func init() {
	riskListCmd.Flags().BoolVar(&riskListAll, "all", false, "Include expired exceptions (history)")
	riskAddCmd.Flags().StringVar(&riskAddTitle, "title", "", "Short name for the accepted risk (required)")
	riskAddCmd.Flags().StringVar(&riskAddCategory, "category", "other", "sod | mfa | rotation | dormant_access | classification | other")
	riskAddCmd.Flags().StringVar(&riskAddReference, "reference", "", "What it applies to (a user, an SoD pair, a secret)")
	riskAddCmd.Flags().StringVar(&riskAddJustification, "justification", "", "Why the risk is accepted (required, recorded for audit)")
	riskAddCmd.Flags().StringVar(&riskAddExpires, "expires", "", "When the exception sunsets (RFC3339, required)")
	riskApproveCmd.Flags().IntVar(&riskApproveID, "id", 0, "ID of the exception to approve (required)")
	riskRevokeCmd.Flags().IntVar(&riskRevokeID, "id", 0, "ID of the exception to revoke (required)")
}
