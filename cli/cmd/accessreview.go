// accessreview.go ports `keyorix access-review` (docs/cli-split-inventory.md §2.5, PR 7):
// the role-based access recertification report (ISO 27001 A.5.18) and its campaign
// workflow. Same flags, output, and exit codes as the old CLI's internal/cli/accessreview
// package -- a pure transport port (REST only, already REST-only in the old CLI too), not a
// behavior change.
package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
	"github.com/keyorixhq/keyorix/cli/internal/cliout"
)

var accessReviewCmd = &cobra.Command{
	Use:     "access-review",
	Aliases: []string{"access-recert", "recert"},
	Short:   "Review who has role-based access to a project's secrets (ISO 27001 A.5.18)",
	Long: `List every principal (user or group) that can reach a project's secrets via an
assigned role, with the highest secrets action that role grants — the role-based
standing-access surface for periodic access recertification. Requires roles.read
at the project scope.`,
	SilenceUsage: true,
	RunE:         runAccessReview,
}

var accessReviewProject int

func init() {
	accessReviewCmd.Flags().IntVar(&accessReviewProject, "project-id", 0, "Project to review (required)")
	addAccessReviewDecisionFlags(accessReviewRevokeCmd)
	addAccessReviewDecisionFlags(accessReviewAttestCmd)
	accessReviewCmd.AddCommand(accessReviewRevokeCmd, accessReviewAttestCmd)

	accessReviewCampaignOpenCmd.Flags().IntVar(&campaignProject, accessReviewFlagProjectID, 0, "Project to review (required)")
	accessReviewCampaignOpenCmd.Flags().StringVar(&campaignName, "name", "", "Campaign name (e.g. \"Q4 2026 access recertification\")")

	accessReviewCampaignListCmd.Flags().IntVar(&campaignProject, accessReviewFlagProjectID, 0, accessReviewDescProjectRequired)

	accessReviewCampaignShowCmd.Flags().IntVar(&campaignProject, accessReviewFlagProjectID, 0, accessReviewDescProjectRequired)
	accessReviewCampaignShowCmd.Flags().IntVar(&campaignID, accessReviewFlagCampaignID, 0, "Campaign to show (required)")

	accessReviewCampaignDecideCmd.Flags().IntVar(&campaignProject, accessReviewFlagProjectID, 0, accessReviewDescProjectRequired)
	accessReviewCampaignDecideCmd.Flags().IntVar(&campaignID, accessReviewFlagCampaignID, 0, "Campaign (required)")
	accessReviewCampaignDecideCmd.Flags().IntVar(&campaignItem, "item-id", 0, "Item to decide (required)")
	accessReviewCampaignDecideCmd.Flags().StringVar(&campaignAction, "action", "", "attest | revoke (required)")
	accessReviewCampaignDecideCmd.Flags().StringVar(&campaignReason, "reason", "", "Optional reviewer note")

	accessReviewCampaignCloseCmd.Flags().IntVar(&campaignProject, accessReviewFlagProjectID, 0, accessReviewDescProjectRequired)
	accessReviewCampaignCloseCmd.Flags().IntVar(&campaignID, accessReviewFlagCampaignID, 0, "Campaign to close (required)")
	accessReviewCampaignCloseCmd.Flags().BoolVar(&campaignForce, "force", false, "Close even if items remain pending")

	accessReviewCampaignCmd.AddCommand(accessReviewCampaignOpenCmd, accessReviewCampaignListCmd, accessReviewCampaignShowCmd, accessReviewCampaignDecideCmd, accessReviewCampaignCloseCmd)
	accessReviewCmd.AddCommand(accessReviewCampaignCmd)
}

type accessReviewEntry struct {
	PrincipalType string     `json:"principal_type"`
	PrincipalID   uint       `json:"principal_id"`
	PrincipalName string     `json:"principal_name"`
	Email         string     `json:"email"`
	Source        string     `json:"source"`
	RoleID        uint       `json:"role_id"`
	RoleName      string     `json:"role_name"`
	AccessLevel   string     `json:"access_level"`
	EnvironmentID uint       `json:"environment_id"`
	SecretID      uint       `json:"secret_id"`
	SecretName    string     `json:"secret_name"`
	LastUsedAt    *time.Time `json:"last_used_at"`
}

func runAccessReview(_ *cobra.Command, _ []string) error {
	if accessReviewProject <= 0 {
		return usageErrorf("--project-id is required")
	}
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	resp, err := client.GetProjectAccessReviewWithResponse(ctx, uint32(accessReviewProject)) // #nosec G115 -- accessReviewProject is a CLI-supplied int flag, always small
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		return apiError("get project access review", resp.StatusCode(), resp.Body)
	}
	out, err := decodeData[struct {
		Entries []accessReviewEntry `json:"entries"`
		Count   int                 `json:"count"`
	}](resp.Body)
	if err != nil {
		return err
	}
	if len(out.Entries) == 0 {
		fmt.Printf("No access to project %d's secrets.\n", accessReviewProject)
		return nil
	}
	fmt.Printf("Access review — project %d (%d grant(s)):\n\n", accessReviewProject, len(out.Entries))
	fmt.Printf("%-13s %-6s %-24s %-7s %-11s %s\n", "SOURCE", "TYPE", "PRINCIPAL", "ACCESS", "LAST-USED", "DETAIL")
	for _, e := range out.Entries {
		principal := cliout.SanitizeForTerminal(e.PrincipalName)
		if e.PrincipalType == "user" && e.Email != "" {
			principal = fmt.Sprintf("%s <%s>", principal, cliout.SanitizeForTerminal(e.Email))
		}
		detail := ""
		switch e.Source {
		case "role":
			scope := "project"
			if e.EnvironmentID > 0 {
				scope = fmt.Sprintf("env=%d", e.EnvironmentID)
			}
			detail = fmt.Sprintf("role=%s (%s)", cliout.SanitizeForTerminal(e.RoleName), scope)
		default:
			detail = "secret=" + cliout.SanitizeForTerminal(e.SecretName)
		}
		fmt.Printf("%-13s %-6s %-24s %-7s %-11s %s\n", e.Source, e.PrincipalType, accessReviewTruncate(principal, 24), e.AccessLevel, lastUsedLabel(e.PrincipalType, e.LastUsedAt), detail)
	}
	return nil
}

func lastUsedLabel(principalType string, t *time.Time) string {
	if principalType != "user" {
		return "—"
	}
	if t == nil || t.IsZero() {
		return "never"
	}
	days := int(time.Since(*t).Hours() / 24)
	if days >= 90 {
		return fmt.Sprintf("%dd stale", days)
	}
	return fmt.Sprintf("%dd", days)
}

func accessReviewTruncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

// ── access-review revoke / attest ───────────────────────────────────────────

var (
	decisionProject       int
	decisionSource        string
	decisionPrincipalType string
	decisionPrincipalID   uint
	decisionRoleID        uint
	decisionEnvironmentID uint
	decisionSecretID      uint
)

func addAccessReviewDecisionFlags(cmd *cobra.Command) {
	cmd.Flags().IntVar(&decisionProject, "project-id", 0, "Project the grant belongs to (required)")
	cmd.Flags().StringVar(&decisionSource, "source", "", "Grant source: role|direct_share|group_share (required)")
	cmd.Flags().StringVar(&decisionPrincipalType, "principal-type", "user", "Principal type: user|group (for role grants)")
	cmd.Flags().UintVar(&decisionPrincipalID, "principal-id", 0, "User or group ID the grant is for (required)")
	cmd.Flags().UintVar(&decisionRoleID, "role-id", 0, "Role ID (required when --source=role)")
	cmd.Flags().UintVar(&decisionEnvironmentID, "environment-id", 0, "Environment scope of a role grant (0 = whole project)")
	cmd.Flags().UintVar(&decisionSecretID, "secret-id", 0, "Secret ID (required when --source=direct_share|group_share)")
}

func runAccessReviewDecision(ctx context.Context, client *apiclient.ClientWithResponses, action string) error {
	if decisionProject <= 0 {
		return usageErrorf("--project-id is required")
	}
	if decisionSource == "" {
		return usageErrorf("--source is required (role|direct_share|group_share)")
	}
	if decisionPrincipalID == 0 {
		return usageErrorf("--principal-id is required")
	}
	if decisionSource == "role" && decisionRoleID == 0 {
		return usageErrorf("--role-id is required when --source=role")
	}
	if (decisionSource == "direct_share" || decisionSource == "group_share") && decisionSecretID == 0 {
		return usageErrorf("--secret-id is required when --source=%s", decisionSource)
	}
	principalID := uint32(decisionPrincipalID) // #nosec G115 -- CLI-supplied uint flag, always small
	roleID := uint32(decisionRoleID)           // #nosec G115 -- CLI-supplied uint flag, always small
	envID := uint32(decisionEnvironmentID)     // #nosec G115 -- CLI-supplied uint flag, always small
	secretID := uint32(decisionSecretID)       // #nosec G115 -- CLI-supplied uint flag, always small
	principalType := apiclient.AccessReviewDecisionPrincipalType(decisionPrincipalType)
	body := apiclient.AccessReviewDecision{
		Source:        apiclient.AccessReviewDecisionSource(decisionSource),
		PrincipalType: &principalType,
		PrincipalId:   &principalID,
		RoleId:        &roleID,
		EnvironmentId: &envID,
		SecretId:      &secretID,
	}

	var statusCode int
	var respBody []byte
	if action == "revoke" {
		resp, err := client.RevokeProjectAccessReviewWithResponse(ctx, uint32(decisionProject), body) // #nosec G115 -- decisionProject is a CLI-supplied int flag, always small
		if err != nil {
			return err
		}
		statusCode, respBody = resp.StatusCode(), resp.Body
	} else {
		resp, err := client.AttestProjectAccessReviewWithResponse(ctx, uint32(decisionProject), body) // #nosec G115 -- decisionProject is a CLI-supplied int flag, always small
		if err != nil {
			return err
		}
		statusCode, respBody = resp.StatusCode(), resp.Body
	}
	if statusCode != 200 {
		return apiError(fmt.Sprintf("%s access-review grant", action), statusCode, respBody)
	}
	verb := "Revoked"
	if action == "attest" {
		verb = "Attested"
	}
	fmt.Printf("%s %s grant for %s %d in project %d.\n", verb, decisionSource, decisionPrincipalType, decisionPrincipalID, decisionProject)
	return nil
}

var accessReviewRevokeCmd = &cobra.Command{
	Use:   "revoke",
	Short: "Revoke an access-review grant (remove the role assignment or share)",
	Long: `Remove the grant identified by the flags — a project-scoped role assignment
(--source role --role-id N) or a secret share (--source direct_share|group_share
--secret-id N). The removal is audited (access_review.revoked). Requires
roles.assign at the project scope.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx := context.Background()
		client, err := apiClientWithSkewCheck(ctx)
		if err != nil {
			return err
		}
		return runAccessReviewDecision(ctx, client, "revoke")
	},
}

var accessReviewAttestCmd = &cobra.Command{
	Use:   "attest",
	Short: "Attest an access-review grant (certify it was reviewed and kept)",
	Long: `Record that the grant identified by the flags was reviewed and intentionally
kept — the audit evidence of recertification (access_review.attested). Changes no
access. Requires roles.read at the project scope.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx := context.Background()
		client, err := apiClientWithSkewCheck(ctx)
		if err != nil {
			return err
		}
		return runAccessReviewDecision(ctx, client, "attest")
	},
}

// ── access-review campaign ──────────────────────────────────────────────────

const (
	accessReviewDescProjectRequired = "Project (required)"
	accessReviewFlagCampaignID      = "campaign-id"
	accessReviewFlagProjectID       = "project-id"
)

type campaignView struct {
	ID              uint     `json:"id"`
	ProjectID       uint     `json:"project_id"`
	Name            string   `json:"name"`
	State           string   `json:"state"`
	Degraded        bool     `json:"degraded"`
	DegradedReasons []string `json:"degraded_reasons"`
}

func printCampaignDegradedWarning(c campaignView) {
	if !c.Degraded {
		return
	}
	fmt.Println("*** DEGRADED SNAPSHOT — one or more secrets' shares could not be read when this campaign was opened ***")
	fmt.Println("*** This campaign may be MISSING a direct/group-share item for them.                                ***")
	for _, reason := range c.DegradedReasons {
		fmt.Printf("    - %s\n", reason)
	}
	fmt.Println()
}

type progressView struct {
	Total    int `json:"total"`
	Pending  int `json:"pending"`
	Attested int `json:"attested"`
	Revoked  int `json:"revoked"`
}

func progressStr(p progressView) string {
	return fmt.Sprintf("%d total — %d pending, %d attested, %d revoked", p.Total, p.Pending, p.Attested, p.Revoked)
}

type campaignItemView struct {
	ID            uint       `json:"id"`
	PrincipalType string     `json:"principal_type"`
	PrincipalName string     `json:"principal_name"`
	Email         string     `json:"email"`
	Source        string     `json:"source"`
	RoleName      string     `json:"role_name"`
	AccessLevel   string     `json:"access_level"`
	SecretName    string     `json:"secret_name"`
	LastUsedAt    *time.Time `json:"last_used_at"`
	Decision      string     `json:"decision"`
}

var (
	campaignProject int
	campaignID      int
	campaignItem    int
	campaignName    string
	campaignAction  string
	campaignReason  string
	campaignForce   bool
)

var accessReviewCampaignCmd = &cobra.Command{
	Use:   "campaign",
	Short: "Manage access-review campaigns (periodic recertification cycles, A.5.18)",
	Long: `Run periodic access recertification as a tracked campaign: open snapshots the
project's current access into reviewable items, decide attests or revokes each, and
close freezes the cycle as audit evidence.`,
}

var accessReviewCampaignOpenCmd = &cobra.Command{
	Use:          "open",
	Short:        "Open a new access-review campaign (snapshots current access)",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if campaignProject <= 0 {
			return usageErrorf("--project-id is required")
		}
		ctx := context.Background()
		client, err := apiClientWithSkewCheck(ctx)
		if err != nil {
			return err
		}
		name := campaignName
		resp, err := client.OpenAccessReviewCampaignWithResponse(ctx, uint32(campaignProject), apiclient.OpenAccessReviewCampaignJSONRequestBody{Name: &name}) // #nosec G115 -- campaignProject is a CLI-supplied int flag, always small
		if err != nil {
			return err
		}
		if resp.StatusCode() != 200 && resp.StatusCode() != 201 {
			return apiError("open access-review campaign", resp.StatusCode(), resp.Body)
		}
		out, err := decodeData[struct {
			Campaign campaignView `json:"campaign"`
			Progress progressView `json:"progress"`
		}](resp.Body)
		if err != nil {
			return err
		}
		printCampaignDegradedWarning(out.Campaign)
		fmt.Printf("Opened campaign %d (%q) for project %d — %s.\n", out.Campaign.ID, cliout.SanitizeForTerminal(out.Campaign.Name), campaignProject, progressStr(out.Progress))
		fmt.Printf("Review items: keyorix access-review campaign show --project-id %d --campaign-id %d\n", campaignProject, out.Campaign.ID)
		return nil
	},
}

var accessReviewCampaignListCmd = &cobra.Command{
	Use:          "list",
	Short:        "List a project's access-review campaigns",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if campaignProject <= 0 {
			return usageErrorf("--project-id is required")
		}
		ctx := context.Background()
		client, err := apiClientWithSkewCheck(ctx)
		if err != nil {
			return err
		}
		resp, err := client.ListAccessReviewCampaignsWithResponse(ctx, uint32(campaignProject)) // #nosec G115 -- campaignProject is a CLI-supplied int flag, always small
		if err != nil {
			return err
		}
		if resp.StatusCode() != 200 {
			return apiError("list access-review campaigns", resp.StatusCode(), resp.Body)
		}
		out, err := decodeData[struct {
			Campaigns []struct {
				Campaign campaignView `json:"campaign"`
				Progress progressView `json:"progress"`
			} `json:"campaigns"`
			Count int `json:"count"`
		}](resp.Body)
		if err != nil {
			return err
		}
		if out.Count == 0 {
			fmt.Printf("No access-review campaigns for project %d.\n", campaignProject)
			return nil
		}
		fmt.Printf("Access-review campaigns — project %d:\n\n", campaignProject)
		fmt.Printf("%-5s %-8s %-28s %s\n", "ID", "STATE", "NAME", "PROGRESS")
		anyDegraded := false
		for _, c := range out.Campaigns {
			state := c.Campaign.State
			if c.Campaign.Degraded {
				state += "*"
				anyDegraded = true
			}
			fmt.Printf("%-5d %-8s %-28s %s\n", c.Campaign.ID, state, accessReviewTruncate(cliout.SanitizeForTerminal(c.Campaign.Name), 28), progressStr(c.Progress))
		}
		if anyDegraded {
			fmt.Println("\n(* = degraded snapshot; run `campaign show` on it for details)")
		}
		return nil
	},
}

var accessReviewCampaignShowCmd = &cobra.Command{
	Use:          "show",
	Short:        "Show a campaign and its items (snapshot + decisions)",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if campaignProject <= 0 || campaignID <= 0 {
			return usageErrorf("--project-id and --campaign-id are required")
		}
		ctx := context.Background()
		client, err := apiClientWithSkewCheck(ctx)
		if err != nil {
			return err
		}
		resp, err := client.GetAccessReviewCampaignWithResponse(ctx, uint32(campaignProject), uint32(campaignID)) // #nosec G115 -- campaignProject/campaignID are CLI-supplied int flags, always small
		if err != nil {
			return err
		}
		if resp.StatusCode() != 200 {
			return apiError("show access-review campaign", resp.StatusCode(), resp.Body)
		}
		out, err := decodeData[struct {
			Campaign campaignView       `json:"campaign"`
			Items    []campaignItemView `json:"items"`
			Progress progressView       `json:"progress"`
		}](resp.Body)
		if err != nil {
			return err
		}
		fmt.Printf("Campaign %d (%q) — %s — %s\n\n", out.Campaign.ID, cliout.SanitizeForTerminal(out.Campaign.Name), out.Campaign.State, progressStr(out.Progress))
		printCampaignDegradedWarning(out.Campaign)
		if len(out.Items) == 0 {
			fmt.Println("No items.")
			return nil
		}
		fmt.Printf("%-6s %-10s %-13s %-22s %-7s %-11s %s\n", "ITEM", "DECISION", "SOURCE", "PRINCIPAL", "ACCESS", "LAST-USED", "DETAIL")
		for _, it := range out.Items {
			principal := cliout.SanitizeForTerminal(it.PrincipalName)
			if it.PrincipalType == "user" && it.Email != "" {
				principal = fmt.Sprintf("%s <%s>", principal, cliout.SanitizeForTerminal(it.Email))
			}
			detail := "secret=" + cliout.SanitizeForTerminal(it.SecretName)
			if it.Source == "role" {
				detail = "role=" + cliout.SanitizeForTerminal(it.RoleName)
			}
			fmt.Printf("%-6d %-10s %-13s %-22s %-7s %-11s %s\n", it.ID, it.Decision, it.Source, accessReviewTruncate(principal, 22), it.AccessLevel, lastUsedLabel(it.PrincipalType, it.LastUsedAt), detail)
		}
		return nil
	},
}

var accessReviewCampaignDecideCmd = &cobra.Command{
	Use:          "decide",
	Short:        "Decide on one campaign item: attest (keep) or revoke",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if campaignProject <= 0 || campaignID <= 0 || campaignItem <= 0 {
			return usageErrorf("--project-id, --campaign-id and --item-id are required")
		}
		if campaignAction != "attest" && campaignAction != "revoke" {
			return fmt.Errorf("--action must be attest or revoke")
		}
		ctx := context.Background()
		client, err := apiClientWithSkewCheck(ctx)
		if err != nil {
			return err
		}
		reason := campaignReason
		body := apiclient.DecideAccessReviewCampaignItemJSONRequestBody{
			Action: apiclient.DecideAccessReviewCampaignItemJSONBodyAction(campaignAction),
			Reason: &reason,
		}
		resp, err := client.DecideAccessReviewCampaignItemWithResponse(ctx, uint32(campaignProject), uint32(campaignID), uint32(campaignItem), body) // #nosec G115 -- CLI-supplied int flags, always small
		if err != nil {
			return err
		}
		if resp.StatusCode() != 200 {
			return apiError("decide access-review campaign item", resp.StatusCode(), resp.Body)
		}
		fmt.Printf("Item %d %sed in campaign %d.\n", campaignItem, campaignAction, campaignID)
		return nil
	},
}

var accessReviewCampaignCloseCmd = &cobra.Command{
	Use:          "close",
	Short:        "Close a campaign (freeze as evidence); refuses pending items unless --force",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if campaignProject <= 0 || campaignID <= 0 {
			return usageErrorf("--project-id and --campaign-id are required")
		}
		ctx := context.Background()
		client, err := apiClientWithSkewCheck(ctx)
		if err != nil {
			return err
		}
		force := campaignForce
		resp, err := client.CloseAccessReviewCampaignWithResponse(ctx, uint32(campaignProject), uint32(campaignID), apiclient.CloseAccessReviewCampaignJSONRequestBody{Force: &force}) // #nosec G115 -- CLI-supplied int flags, always small
		if err != nil {
			return err
		}
		if resp.StatusCode() != 200 {
			return apiError("close access-review campaign", resp.StatusCode(), resp.Body)
		}
		out, err := decodeData[struct {
			Campaign campaignView `json:"campaign"`
			Progress progressView `json:"progress"`
		}](resp.Body)
		if err != nil {
			return err
		}
		fmt.Printf("Closed campaign %d — %s.\n", out.Campaign.ID, progressStr(out.Progress))
		printCampaignDegradedWarning(out.Campaign)
		return nil
	},
}
