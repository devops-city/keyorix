// invite.go ports `keyorix invite` (docs/cli-split-inventory.md §2.2, PR 3):
// project invitations (ADR-024), REST only. Same flags, output, and exit codes as
// the old CLI's internal/cli/invite package's remote-mode branch (ADR-108
// Decision A removes local mode entirely) -- with one deliberate drop: the old
// CLI's --by flag existed only to attribute an invitation to an actor in
// EMBEDDED mode (there is no real authenticated session there); the old CLI's
// remote-mode branch never read --by at all (the real session's actor is used
// instead), so it has nothing to port forward here. This also closes §8 Finding
// S9 (invite list's embedded-only stricter-than-REST authority check) by
// construction: there is no embedded authority check left to diverge from REST.
package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/oapi-codegen/runtime/types"
	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

var inviteCmd = &cobra.Command{
	Use:   "invite",
	Short: "Manage project invitations",
	Long:  "Send, list, resend, and revoke project invitations (ADR-024).",
}

func init() {
	rootCmd.AddCommand(inviteCmd)
}

// inviteAPIClient resolves the stored credentials and builds a client plus the
// resolved server URL, the shared pre-flight every invite subcommand needs.
func inviteAPIClient() (*apiclient.ClientWithResponses, string, error) {
	store, err := resolveCredStore()
	if err != nil {
		return nil, "", fmt.Errorf("resolve credential store: %w", err)
	}
	serverURL, token, err := resolveServerAndToken(store)
	if err != nil {
		return nil, "", err
	}
	client, err := newAPIClient(serverURL, token)
	return client, serverURL, err
}

// resolveInviteProjectID resolves a project name (flag or KEYORIX_PROJECT) to
// its numeric ID via GET /api/v1/projects, mirroring machine.go's
// resolveMachineProjectID -- duplicated rather than shared because invite has
// no "active project" fallback of its own yet (ADR-108 PR 6 brings `project`).
func resolveInviteProjectID(client *apiclient.ClientWithResponses, flagValue string) (string, int, error) {
	return resolveMachineProjectID(client, flagValue)
}

// printProvisionResult prints how a setup/accept link was delivered (ADR-028),
// mirroring the old CLI's internal/cli/common.PrintProvisionResult exactly.
func printProvisionResult(prov *apiclient.ProvisionSetupResult) {
	if prov == nil {
		return
	}
	if prov.Delivered != nil && *prov.Delivered {
		fmt.Printf("Setup link delivered to %s via %s.\n", derefStr(prov.Email), derefProvisionChannel(prov.Channel))
		return
	}
	fmt.Printf("Setup link (relay this to %s securely — it is single-use and expires):\n  %s\n", derefStr(prov.Email), derefStr(prov.LinkForAdmin))
}

func derefProvisionChannel(c *apiclient.ProvisionSetupResultChannel) string {
	if c == nil {
		return ""
	}
	return string(*c)
}

// fmtInviteTime renders an optional timestamp for table output, or "-" when absent.
func fmtInviteTime(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.Format("2006-01-02 15:04")
}

// ── send ────────────────────────────────────────────────────────────────────────

var (
	inviteSendProject string
	inviteSendEmail   string
	inviteSendRole    string
)

var inviteSendCmd = &cobra.Command{
	Use:   "send",
	Short: "Send a project invitation",
	Long:  "Invite an email address to a project with an intended role (admin-driven, ADR-024).",
	RunE:  runInviteSend,
}

func init() {
	inviteSendCmd.Flags().StringVar(&inviteSendProject, "project", "", "Project name (or set KEYORIX_PROJECT)")
	inviteSendCmd.Flags().StringVar(&inviteSendEmail, "email", "", "Invitee email address (required)")
	inviteSendCmd.Flags().StringVar(&inviteSendRole, "role", "", "Intended project role (required)")
	inviteCmd.AddCommand(inviteSendCmd)
}

func runInviteSend(cmd *cobra.Command, args []string) error {
	if inviteSendEmail == "" || inviteSendRole == "" {
		return usageErrorf("--email and --role are required")
	}
	client, serverURL, err := inviteAPIClient()
	if err != nil {
		return err
	}
	projectName, projectID, err := resolveInviteProjectID(client, inviteSendProject)
	if err != nil {
		return err
	}
	fmt.Printf("Target: %s (project %q, id=%d)\n", serverURL, projectName, projectID)

	body := apiclient.CreateProjectInvitationJSONRequestBody{
		Email: types.Email(inviteSendEmail),
		Role:  inviteSendRole,
	}
	resp, err := client.CreateProjectInvitationWithResponse(context.Background(), projectID, body)
	if err != nil {
		return fmt.Errorf("failed to send invitation: %w", err)
	}
	if resp.JSON201 == nil || resp.JSON201.Data == nil || resp.JSON201.Data.Invitation == nil {
		return httpStatusError("failed to send invitation", resp.StatusCode(), resp.Body)
	}
	inv := *resp.JSON201.Data.Invitation
	if resp.JSON201.Data.DeliveryError != nil && *resp.JSON201.Data.DeliveryError != "" {
		fmt.Printf("Invitation created: id=%d email=%s role=%s project=%s expires=%s\n",
			derefInt(inv.ID), derefStr(inv.Email), derefStr(inv.Role), projectName, fmtInviteTime(inv.ExpiresAt))
		return fmt.Errorf("but the setup link could not be delivered: %s", *resp.JSON201.Data.DeliveryError)
	}
	fmt.Printf("Invitation sent: id=%d email=%s role=%s project=%s expires=%s\n",
		derefInt(inv.ID), derefStr(inv.Email), derefStr(inv.Role), projectName, fmtInviteTime(inv.ExpiresAt))
	printProvisionResult(resp.JSON201.Data.SetupLink)
	return nil
}

// ── list ────────────────────────────────────────────────────────────────────────

var (
	inviteListProject   string
	inviteListStaleDays int
)

var inviteListCmd = &cobra.Command{
	Use:   "list",
	Short: "List project invitations",
	Long:  "List a project's invitations. With --stale-days, show only pending invites older than N days.",
	RunE:  runInviteList,
}

func init() {
	inviteListCmd.Flags().StringVar(&inviteListProject, "project", "", "Project name (or set KEYORIX_PROJECT)")
	inviteListCmd.Flags().IntVar(&inviteListStaleDays, "stale-days", 0, "Show only pending invitations older than this many days")
	inviteCmd.AddCommand(inviteListCmd)
}

func runInviteList(cmd *cobra.Command, args []string) error {
	client, serverURL, err := inviteAPIClient()
	if err != nil {
		return err
	}
	projectName, projectID, err := resolveInviteProjectID(client, inviteListProject)
	if err != nil {
		return err
	}
	fmt.Printf("Target: %s (project %q, id=%d)\n", serverURL, projectName, projectID)

	resp, err := client.ListProjectInvitationsWithResponse(context.Background(), projectID)
	if err != nil {
		return fmt.Errorf("failed to list invitations: %w", err)
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return httpStatusError("failed to list invitations", resp.StatusCode(), resp.Body)
	}
	invitations := derefInvitationSlice(resp.JSON200.Data.Invitations)
	if inviteListStaleDays > 0 {
		cutoff := time.Now().Add(-time.Duration(inviteListStaleDays) * 24 * time.Hour)
		filtered := invitations[:0]
		for _, inv := range invitations {
			if inv.State != nil && *inv.State == apiclient.ProjectInvitationStatePending && inv.CreatedAt != nil && inv.CreatedAt.Before(cutoff) {
				filtered = append(filtered, inv)
			}
		}
		invitations = filtered
	}
	printInvitations(invitations)
	return nil
}

// printInvitations renders the invitation table, matching the old CLI's format exactly.
func printInvitations(invitations []apiclient.ProjectInvitation) {
	if len(invitations) == 0 {
		fmt.Println("No invitations found.")
		return
	}
	fmt.Printf("%-6s %-30s %-16s %-10s %s\n", "ID", "EMAIL", "ROLE", "STATE", "EXPIRES")
	for _, inv := range invitations {
		fmt.Printf("%-6d %-30s %-16s %-10s %s\n",
			derefInt(inv.ID), derefStr(inv.Email), derefStr(inv.Role), derefInviteState(inv.State), fmtInviteTime(inv.ExpiresAt))
	}
}

func derefInviteState(s *apiclient.ProjectInvitationState) string {
	if s == nil {
		return ""
	}
	return string(*s)
}

func derefInvitationSlice(s *[]apiclient.ProjectInvitation) []apiclient.ProjectInvitation {
	if s == nil {
		return nil
	}
	return *s
}

// ── revoke ──────────────────────────────────────────────────────────────────────

var (
	inviteRevokeID      int
	inviteRevokeProject string
)

var inviteRevokeCmd = &cobra.Command{
	Use:   "revoke",
	Short: "Revoke a pending invitation",
	Long:  "Cancel a pending project invitation by ID (ADR-024).",
	RunE:  runInviteRevoke,
}

func init() {
	inviteRevokeCmd.Flags().IntVar(&inviteRevokeID, "id", 0, "Invitation ID (required)")
	inviteRevokeCmd.Flags().StringVar(&inviteRevokeProject, "project", "", "Project name (or set KEYORIX_PROJECT)")
	inviteCmd.AddCommand(inviteRevokeCmd)
}

func runInviteRevoke(cmd *cobra.Command, args []string) error {
	if inviteRevokeID == 0 {
		return usageErrorf("--id is required")
	}
	client, serverURL, err := inviteAPIClient()
	if err != nil {
		return err
	}
	projectName, projectID, err := resolveInviteProjectID(client, inviteRevokeProject)
	if err != nil {
		return err
	}
	fmt.Printf("Target: %s (project %q, id=%d)\n", serverURL, projectName, projectID)

	resp, err := client.RevokeProjectInvitationWithResponse(context.Background(), projectID, inviteRevokeID)
	if err != nil {
		return fmt.Errorf("failed to revoke invitation: %w", err)
	}
	if resp.StatusCode() != 200 {
		return httpStatusError("failed to revoke invitation", resp.StatusCode(), resp.Body)
	}
	fmt.Printf("Invitation %d revoked.\n", inviteRevokeID)
	return nil
}

// ── resend ──────────────────────────────────────────────────────────────────────

var (
	inviteResendID      int
	inviteResendProject string
)

var inviteResendCmd = &cobra.Command{
	Use:   "resend",
	Short: "Reissue and redeliver an invitation's setup link (ADR-028)",
	Long: "Reissue a pending invitation's accept link, invalidating any prior link, and\n" +
		"deliver it again. In out-of-band mode the link is printed for you to relay.\n" +
		"Throttled per the ADR-028 resend limits.",
	RunE: runInviteResend,
}

func init() {
	inviteResendCmd.Flags().IntVar(&inviteResendID, "id", 0, "Invitation ID (required)")
	inviteResendCmd.Flags().StringVar(&inviteResendProject, "project", "", "Project name (or set KEYORIX_PROJECT)")
	inviteCmd.AddCommand(inviteResendCmd)
}

func runInviteResend(cmd *cobra.Command, args []string) error {
	if inviteResendID == 0 {
		return usageErrorf("invitation id is required (use --id)")
	}
	client, serverURL, err := inviteAPIClient()
	if err != nil {
		return err
	}
	projectName, projectID, err := resolveInviteProjectID(client, inviteResendProject)
	if err != nil {
		return err
	}
	fmt.Printf("Target: %s (project %q, id=%d)\n", serverURL, projectName, projectID)

	resp, err := client.ResendProjectInvitationWithResponse(context.Background(), projectID, inviteResendID)
	if err != nil {
		return fmt.Errorf("failed to resend invitation link: %w", err)
	}
	if resp.JSON200 == nil {
		return httpStatusError("failed to resend invitation link", resp.StatusCode(), resp.Body)
	}
	fmt.Printf("Invitation link reissued for invitation %d.\n", inviteResendID)
	printProvisionResult(resp.JSON200.Data.SetupLink)
	return nil
}
