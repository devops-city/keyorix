// breakglass.go ports `keyorix break-glass` (docs/cli-split-inventory.md §2.4, PR 1):
// self-service emergency access (NIS2/DORA incident response). Same flags, output, and
// exit codes as the old CLI's internal/cli/breakglass package -- this is a pure transport
// port (REST only, Zero GAPs), not a behavior change.
package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
	"github.com/keyorixhq/keyorix/cli/internal/cliout"
)

// breakGlassCmd is the `keyorix break-glass` command.
var breakGlassCmd = &cobra.Command{
	Use:   "break-glass",
	Short: "Self-service emergency access (incident response)",
	Long: `Activate emergency access to a project: immediately self-grant the configured
emergency role, time-bound and auto-expiring, with a written justification. Every
activation is loudly audited and alerts the project's admins. Use list/revoke to
review and end activations.`,
}

const bgFlagProjectID = "project-id"

var (
	bgProject    uint32
	bgJustify    string
	bgTTL        string
	bgActivation uint32
)

var bgActivateCmd = &cobra.Command{
	Use:          "activate",
	Short:        "Activate emergency access (self-grant the emergency role, time-bound)",
	SilenceUsage: true,
	RunE:         runBGActivate,
}

var bgListCmd = &cobra.Command{
	Use:          "list",
	Short:        "List a project's break-glass activations (all with roles.read, else your own as a member)",
	SilenceUsage: true,
	RunE:         runBGList,
}

var bgRevokeCmd = &cobra.Command{
	Use:          "revoke",
	Short:        "Revoke an active emergency grant early",
	SilenceUsage: true,
	RunE:         runBGRevoke,
}

func init() {
	bgActivateCmd.Flags().Uint32Var(&bgProject, bgFlagProjectID, 0, "Project to activate emergency access for (required)")
	bgActivateCmd.Flags().StringVar(&bgJustify, "justification", "", "Written reason for emergency access (required)")
	bgActivateCmd.Flags().StringVar(&bgTTL, "ttl", "", "Grant lifetime override, e.g. 2h (default + capped by server config)")

	bgListCmd.Flags().Uint32Var(&bgProject, bgFlagProjectID, 0, "Project (required)")

	bgRevokeCmd.Flags().Uint32Var(&bgProject, bgFlagProjectID, 0, "Project (required)")
	bgRevokeCmd.Flags().Uint32Var(&bgActivation, "activation-id", 0, "Activation to revoke (required)")

	breakGlassCmd.AddCommand(bgActivateCmd, bgListCmd, bgRevokeCmd)
	rootCmd.AddCommand(breakGlassCmd)
}

// breakGlassAPIClient resolves the stored credentials and builds a client, the shared
// pre-flight every break-glass subcommand needs.
func breakGlassAPIClient() (*apiclient.ClientWithResponses, error) {
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

func runBGActivate(_ *cobra.Command, _ []string) error {
	if bgProject == 0 {
		return usageErrorf("--project-id is required")
	}
	if bgJustify == "" {
		return usageErrorf("--justification is required")
	}
	client, err := breakGlassAPIClient()
	if err != nil {
		return err
	}
	body := apiclient.ActivateBreakGlassJSONRequestBody{Justification: bgJustify}
	if bgTTL != "" {
		body.Ttl = &bgTTL
	}
	resp, err := client.ActivateBreakGlassWithResponse(context.Background(), bgProject, body)
	if err != nil {
		return err
	}
	if resp.JSON201 == nil || resp.JSON201.Data == nil || resp.JSON201.Data.Activation == nil {
		return httpStatusError("activate break-glass failed", resp.StatusCode(), resp.Body)
	}
	a := resp.JSON201.Data.Activation
	fmt.Printf("Emergency access activated (id=%d): role %q until %s.\n",
		derefUint32(a.Id), derefStr(a.RoleName), derefStr(a.ExpiresAt))
	printBreakGlassEffect(client, bgProject, a)
	return nil
}

// printBreakGlassEffect says what activation changed, so the demo (and an incident
// responder) can SEE it (#2981). The role is granted on top of whatever the caller
// already holds on the project, so for a user who can already read secrets the
// visible difference is the extra permissions: they are listed when the role's
// permissions are readable by the caller (best-effort: roles.read may be missing,
// in which case only the always-true lines are printed).
func printBreakGlassEffect(client *apiclient.ClientWithResponses, projectID uint32, a *apiclient.BreakGlassActivation) {
	role := derefStr(a.RoleName)
	fmt.Printf("  %q is now granted to you on project %d, in addition to the access you already had there.\n", role, projectID)
	if roles, err := fetchRoles(context.Background(), client); err == nil {
		for _, r := range roles {
			if derefStr(r.Name) != role || r.Permissions == nil {
				continue
			}
			names := make([]string, 0, len(*r.Permissions))
			for _, p := range *r.Permissions {
				if n := derefStr(p.Name); n != "" {
					names = append(names, n)
				}
			}
			if len(names) > 0 {
				fmt.Printf("  It grants: %s\n", cliout.SanitizeForTerminal(strings.Join(names, ", ")))
			}
			break
		}
	}
	fmt.Printf("  It expires automatically; a project administrator can end it early with: keyorix break-glass revoke --project-id %d --activation-id %d\n",
		projectID, derefUint32(a.Id))
}

func runBGList(_ *cobra.Command, _ []string) error {
	if bgProject == 0 {
		return usageErrorf("--project-id is required")
	}
	client, err := breakGlassAPIClient()
	if err != nil {
		return err
	}
	resp, err := client.ListBreakGlassActivationsWithResponse(context.Background(), bgProject)
	if err != nil {
		return err
	}
	// #2981: a refusal (e.g. a machine identity without roles.read) used to fall into
	// "No break-glass activations" below, telling alice there were none while the
	// admin's own list showed hers. Only a successful empty list may say that.
	if resp.StatusCode() != 200 {
		return httpStatusError("list break-glass activations failed", resp.StatusCode(), resp.Body)
	}
	// BREAKGLASS-OWN-1: a caller without roles.read gets only their own activations
	// (scope "own"); say so, so "none" never reads as "none in the project".
	own := resp.JSON200 != nil && resp.JSON200.Data != nil && resp.JSON200.Data.Scope != nil &&
		*resp.JSON200.Data.Scope == "own"
	if resp.JSON200 == nil || resp.JSON200.Data == nil || derefInt(resp.JSON200.Data.Count) == 0 {
		if own {
			fmt.Printf("You have no break-glass activations on project %d (listing other users' activations needs roles.read).\n", bgProject)
			return nil
		}
		fmt.Printf("No break-glass activations for project %d.\n", bgProject)
		return nil
	}
	if own {
		fmt.Printf("Your break-glass activations — project %d (only your own; other users' need roles.read):\n\n", bgProject)
	} else {
		fmt.Printf("Break-glass activations — project %d:\n\n", bgProject)
	}
	var activations []apiclient.BreakGlassActivation
	if resp.JSON200.Data.Activations != nil {
		activations = *resp.JSON200.Data.Activations
	}
	// ROLE is as wide as the longest role name: "project_developer" used to be cut
	// to "project_develop…" (#2942).
	roleW := len("ROLE")
	for _, a := range activations {
		if n := len(derefStr(a.RoleName)); n > roleW {
			roleW = n
		}
	}
	fmt.Printf("%-5s %-8s %-9s %-*s %-20s %s\n", "ID", "USER", "STATE", roleW, "ROLE", "EXPIRES (UTC)", "JUSTIFICATION")
	for _, a := range activations {
		fmt.Printf("%-5d %-8d %-9s %-*s %-20s %s\n", derefUint32(a.Id), derefUint32(a.UserId),
			derefStr((*string)(a.State)), roleW, cliout.SanitizeForTerminal(derefStr(a.RoleName)), shortTime(derefStr(a.ExpiresAt)), derefStr(a.Justification))
	}
	return nil
}

func runBGRevoke(_ *cobra.Command, _ []string) error {
	if bgProject == 0 || bgActivation == 0 {
		return usageErrorf("--project-id and --activation-id are required")
	}
	client, err := breakGlassAPIClient()
	if err != nil {
		return err
	}
	resp, err := client.RevokeBreakGlassWithResponse(context.Background(), bgProject, bgActivation)
	if err != nil {
		return err
	}
	if resp.StatusCode() < 200 || resp.StatusCode() >= 300 {
		return httpStatusError("revoke break-glass activation failed", resp.StatusCode(), resp.Body)
	}
	fmt.Printf("Revoked break-glass activation %d in project %d.\n", bgActivation, bgProject)
	return nil
}
