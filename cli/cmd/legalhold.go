// legalhold.go ports `keyorix legal-hold` (docs/cli-split-inventory.md §2.6, PR 8): a
// deployment-wide litigation/investigation hold (ISO 27001 A.5.34 / eDiscovery). Same
// flags, output, and exit codes as the old CLI's internal/cli/legalhold package -- a pure
// transport port, not a behavior change.
package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

var legalHoldCmd = &cobra.Command{
	Use:   "legal-hold",
	Short: "Deployment-wide legal hold — block purges to preserve records (A.5.34)",
	Long: `Place or lift a litigation/investigation hold. While a hold is active, the
retention-purge, JIT-expiry, and login-prune jobs are blocked from hard-deleting
any records, so data subject to legal hold is preserved.`,
}

func init() {
	legalHoldCmd.AddCommand(legalHoldStatusCmd, legalHoldPlaceCmd, legalHoldLiftCmd)
	rootCmd.AddCommand(legalHoldCmd)
}

type legalHoldView struct {
	ID       uint   `json:"id"`
	Reason   string `json:"reason"`
	PlacedBy uint   `json:"placed_by"`
	PlacedAt string `json:"placed_at"`
}

var legalHoldStatusCmd = &cobra.Command{
	Use:          "status",
	Short:        "Show whether a legal hold is active",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx := context.Background()
		client, err := apiClientWithSkewCheck(ctx)
		if err != nil {
			return err
		}
		resp, err := client.GetLegalHoldWithResponse(ctx)
		if err != nil {
			return err
		}
		if resp.StatusCode() != 200 {
			return apiError("get legal hold status", resp.StatusCode(), resp.Body)
		}
		out, err := decodeData[struct {
			Active bool          `json:"active"`
			Hold   legalHoldView `json:"hold"`
		}](resp.Body)
		if err != nil {
			return err
		}
		if !out.Active {
			fmt.Println("No legal hold is active. Purge jobs run normally.")
			return nil
		}
		fmt.Printf("LEGAL HOLD ACTIVE (id=%d) since %s — purges are blocked.\n  Reason: %s\n",
			out.Hold.ID, out.Hold.PlacedAt, out.Hold.Reason)
		return nil
	},
}

var legalHoldPlaceReason string

var legalHoldPlaceCmd = &cobra.Command{
	Use:          "place",
	Short:        "Place a legal hold (block all purges until lifted)",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if legalHoldPlaceReason == "" {
			return usageErrorf("--reason is required")
		}
		ctx := context.Background()
		client, err := apiClientWithSkewCheck(ctx)
		if err != nil {
			return err
		}
		resp, err := client.PlaceLegalHoldWithResponse(ctx, apiclient.PlaceLegalHoldJSONRequestBody{Reason: legalHoldPlaceReason})
		if err != nil {
			return err
		}
		if resp.StatusCode() != 200 && resp.StatusCode() != 201 {
			return apiError("place legal hold", resp.StatusCode(), resp.Body)
		}
		out, err := decodeData[struct {
			Hold legalHoldView `json:"hold"`
		}](resp.Body)
		if err != nil {
			return err
		}
		fmt.Printf("Legal hold placed (id=%d). All purge jobs are now blocked until lifted.\n", out.Hold.ID)
		return nil
	},
}

var legalHoldLiftYes bool
var legalHoldLiftReason string

var legalHoldLiftCmd = &cobra.Command{
	Use:          "lift",
	Short:        "Lift the active legal hold (resume purges)",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		if legalHoldLiftReason == "" {
			return usageErrorf("--reason is required")
		}
		if !legalHoldLiftYes {
			fmt.Print("Lift the active legal hold? This immediately re-arms purge/retention/JIT-expiry\njobs and cannot be undone from here. Type 'yes' to confirm: ")
			var answer string
			_, _ = fmt.Fscanln(cmd.InOrStdin(), &answer)
			if answer != "yes" {
				fmt.Println("Aborted.")
				return nil
			}
		}
		ctx := context.Background()
		client, err := apiClientWithSkewCheck(ctx)
		if err != nil {
			return err
		}
		resp, err := client.LiftLegalHoldWithResponse(ctx, apiclient.LiftLegalHoldJSONRequestBody{Reason: legalHoldLiftReason})
		if err != nil {
			return err
		}
		if resp.StatusCode() != 200 {
			return apiError("lift legal hold", resp.StatusCode(), resp.Body)
		}
		fmt.Println("Legal hold lifted. Purge jobs will resume on their next tick.")
		return nil
	},
}

func init() {
	legalHoldPlaceCmd.Flags().StringVar(&legalHoldPlaceReason, "reason", "", "Why the hold is placed (required, recorded for audit)")
	legalHoldLiftCmd.Flags().BoolVar(&legalHoldLiftYes, "yes", false, "Skip the confirmation prompt")
	legalHoldLiftCmd.Flags().StringVar(&legalHoldLiftReason, "reason", "", "Why the hold is lifted (required, recorded for audit)")
}
