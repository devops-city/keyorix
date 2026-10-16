// secret_bulk.go — keyorix secret bulk-rotate/bulk-rename/bulk-delete.
//
// All three take numeric --project (and, where relevant, --env) IDs rather than
// names with an "active project" fallback — that concept doesn't exist in this
// thin CLI (no local/embedded mode, no project-name resolution infrastructure
// yet), matching the convention every other secret command in this module uses.
package cmd

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

// ── bulk-rotate ──────────────────────────────────────────────────────────────

var (
	bulkRotateProject        int
	bulkRotateEnv            int
	bulkRotateClassification string
	bulkRotateNames          string
	bulkRotateConfirm        bool
)

var secretBulkRotateCmd = &cobra.Command{
	Use:   "bulk-rotate",
	Short: "Trigger rotation for multiple secrets at once",
	Long: `Trigger rotation for all matching secrets in a project — the CLI surface for
incident response ("rotate everything tagged confidential in project X").

Secrets without auto-rotate configured are skipped (reported in the failure list,
not treated as errors) so the operation is always best-effort.

Without --names the command rotates every matching secret in the project; use
--env and/or --classification to narrow the scope.

--confirm is required: this is a bulk destructive operation and an accidental
wide rotation cannot be undone.

--names requires --env: a secret name is only unique within one project's
environment, not across the whole project.`,
	SilenceUsage: true,
	RunE:         runSecretBulkRotate,
}

func runSecretBulkRotate(_ *cobra.Command, _ []string) error {
	if bulkRotateProject == 0 {
		return usageErrorf("--project is required")
	}
	if !bulkRotateConfirm {
		return usageErrorf("--confirm is required to proceed with bulk rotation (this is a destructive bulk operation)")
	}

	client, err := secretAPIClient()
	if err != nil {
		return err
	}
	ctx := context.Background()

	var secretIDs *[]int
	if bulkRotateNames != "" {
		if bulkRotateEnv == 0 {
			return usageErrorf("--env is required when using --names (a secret name is only unique within one project's environment, not across the whole project)")
		}
		ids, err := resolveSecretNamesToIDs(ctx, client, bulkRotateProject, bulkRotateEnv, splitSecretNames(bulkRotateNames))
		if err != nil {
			return fmt.Errorf("resolve secret names: %w", err)
		}
		secretIDs = &ids
	}

	body := apiclient.BulkRotateSecretsJSONRequestBody{SecretIds: secretIDs}
	if bulkRotateEnv != 0 {
		body.EnvironmentId = &bulkRotateEnv
	}
	if bulkRotateClassification != "" {
		body.Classification = &bulkRotateClassification
	}

	resp, err := client.BulkRotateSecretsWithResponse(ctx, bulkRotateProject, body)
	if err != nil {
		return err
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return httpStatusError("bulk rotate", resp.StatusCode(), resp.Body)
	}
	result := resp.JSON200.Data
	triggered, failed := 0, 0
	if result.Triggered != nil {
		triggered = len(*result.Triggered)
	}
	if result.Failed != nil {
		failed = len(*result.Failed)
	}
	fmt.Printf("Bulk rotation triggered: %d scheduled, %d failed\n", triggered, failed)
	if failed > 0 {
		fmt.Println("\nFailed:")
		for _, f := range *result.Failed {
			label := derefStr(f.Name)
			if label == "" {
				label = fmt.Sprintf("id:%d", derefInt(f.SecretId))
			}
			fmt.Printf("  %-30s %s\n", label+":", derefStr(f.Error))
		}
	}
	return nil
}

// splitSecretNames splits a comma-separated name list, trimming whitespace.
func splitSecretNames(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// resolveSecretNamesToIDs resolves a list of secret names to IDs by listing secrets
// scoped to BOTH the given project and environment — a project-only scope would let a
// name that exists in two different environments of the same project silently resolve
// to whichever one a name->ID map happened to insert last. A name with no match is
// skipped with a warning; a name matching MORE than one secret is never silently
// guessed — it aborts with every ambiguous name and its matching IDs listed.
func resolveSecretNamesToIDs(ctx context.Context, client *apiclient.ClientWithResponses, projectID, envID int, names []string) ([]int, error) {
	nameToIDs, err := listSecretNameIndex(ctx, client, projectID, envID)
	if err != nil {
		return nil, err
	}

	ids := make([]int, 0, len(names))
	var ambiguous []string
	for _, n := range names {
		switch matches := nameToIDs[n]; len(matches) {
		case 0:
			fmt.Printf("warning: secret %q not found — skipping\n", n)
		case 1:
			ids = append(ids, matches[0])
		default:
			ambiguous = append(ambiguous, fmt.Sprintf("%q (IDs %v)", n, matches))
		}
	}
	if len(ambiguous) > 0 {
		return nil, fmt.Errorf("secret name(s) ambiguous in project %d, environment %d: %s — refusing to guess", projectID, envID, strings.Join(ambiguous, "; "))
	}
	return ids, nil
}

// listSecretNameIndex GETs /secrets scoped to (projectID, envID) and returns a
// name->[]ID index, decoded off the raw (non-typed) generated method since listSecrets
// has no response schema yet (that's PR 4's job, a sibling independent PR).
func listSecretNameIndex(ctx context.Context, client *apiclient.ClientWithResponses, projectID, envID int) (map[string][]int, error) {
	params := &apiclient.ListSecretsParams{
		ProjectId:     &projectID,
		EnvironmentId: &envID,
		PageSize:      intPtr(500),
	}
	resp, err := client.ListSecretsWithResponse(ctx, params)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode() != 200 {
		return nil, httpStatusError("list secrets", resp.StatusCode(), resp.Body)
	}
	var body struct {
		Data struct {
			Secrets []struct {
				ID   int    `json:"ID"`
				Name string `json:"Name"`
			} `json:"secrets"`
		} `json:"data"`
	}
	if err := decodeJSONBody(resp.Body, &body); err != nil {
		return nil, fmt.Errorf("decode secret list: %w", err)
	}
	index := make(map[string][]int, len(body.Data.Secrets))
	for _, s := range body.Data.Secrets {
		index[s.Name] = append(index[s.Name], s.ID)
	}
	return index, nil
}

// intPtr is defined in secret_crud.go (PR 4).

func init() {
	secretBulkRotateCmd.Flags().IntVar(&bulkRotateProject, "project", 0, "Project ID (required)")
	secretBulkRotateCmd.Flags().IntVar(&bulkRotateEnv, "env", 0, "Environment ID (optional filter)")
	secretBulkRotateCmd.Flags().StringVar(&bulkRotateClassification, "classification", "", "Classification label filter (e.g. confidential)")
	secretBulkRotateCmd.Flags().StringVar(&bulkRotateNames, "names", "", "Comma-separated secret names to rotate (omit to rotate all matching)")
	secretBulkRotateCmd.Flags().BoolVar(&bulkRotateConfirm, "confirm", false, "Required: confirm you want to trigger bulk rotation")
	SecretCmd.AddCommand(secretBulkRotateCmd)
}

// ── bulk-rename ──────────────────────────────────────────────────────────────

var (
	bulkRenameProject int
	bulkRenameApply   bool
	bulkRenamePairs   []string
)

var secretBulkRenameCmd = &cobra.Command{
	Use:   "bulk-rename",
	Short: "Rename secrets toward naming-policy conformance",
	Long: `Rename one or more secrets in a project in a single call — the remediation for the
secrets that "secret name-conformance" lists as violating the current naming policy.

Each new name must itself satisfy the policy (you can only rename TOWARD conformance) and
must not collide with another secret in the same environment; any entry failing a check
is skipped with a reason while the rest proceed.

Specify renames as --rename <id>=<new-name> (repeatable). By default this is a DRY RUN
that only reports what would change; pass --apply to actually rename. Requires
secrets.write at the project scope.`,
	SilenceUsage: true,
	RunE:         runSecretBulkRename,
}

func runSecretBulkRename(_ *cobra.Command, _ []string) error {
	if bulkRenameProject == 0 {
		return usageErrorf("--project is required")
	}
	if len(bulkRenamePairs) == 0 {
		return usageErrorf("at least one --rename <id>=<new-name> is required")
	}
	entries, err := parseSecretRenamePairs(bulkRenamePairs)
	if err != nil {
		return err
	}

	client, err := secretAPIClient()
	if err != nil {
		return err
	}
	dryRun := !bulkRenameApply
	resp, err := client.BulkRenameSecretsWithResponse(context.Background(), bulkRenameProject, apiclient.BulkRenameSecretsJSONRequestBody{
		Renames: entries,
		DryRun:  &dryRun,
	})
	if err != nil {
		return err
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return httpStatusError("bulk rename", resp.StatusCode(), resp.Body)
	}
	report := resp.JSON200.Data

	if derefBool(report.DryRun) {
		fmt.Printf("Dry run — no changes made. Pass --apply to rename.\n\n")
	}
	fmt.Printf("%-8s %-24s %-24s %-14s %s\n", "ID", "OLD NAME", "NEW NAME", "STATUS", "REASON")
	if report.Outcomes != nil {
		for _, o := range *report.Outcomes {
			fmt.Printf("%-8d %-24s %-24s %-14s %s\n", derefInt(o.Id), derefStr(o.OldName), derefStr(o.NewName), derefStr(o.Status), derefStr(o.Reason))
		}
	}
	verb := "renamed"
	if derefBool(report.DryRun) {
		verb = "would be renamed"
	}
	fmt.Printf("\n%d %s, %d skipped.\n", derefInt(report.Renamed), verb, derefInt(report.Skipped))
	return nil
}

// parseSecretRenamePairs turns ["12=NAME","15=OTHER"] into rename entries, splitting on
// the FIRST '=' so a new name may itself contain '='.
func parseSecretRenamePairs(pairs []string) ([]struct {
	Id      *int    `json:"id,omitempty"`
	NewName *string `json:"new_name,omitempty"`
}, error) {
	entries := make([]struct {
		Id      *int    `json:"id,omitempty"`
		NewName *string `json:"new_name,omitempty"`
	}, 0, len(pairs))
	for _, p := range pairs {
		idStr, name, found := strings.Cut(p, "=")
		if !found {
			return nil, fmt.Errorf("invalid --rename %q: expected <id>=<new-name>", p)
		}
		id, err := strconv.Atoi(strings.TrimSpace(idStr))
		if err != nil || id <= 0 {
			return nil, fmt.Errorf("invalid --rename %q: %q is not a valid secret ID", p, idStr)
		}
		name = strings.TrimSpace(name)
		if name == "" {
			return nil, fmt.Errorf("invalid --rename %q: new name is empty", p)
		}
		entries = append(entries, struct {
			Id      *int    `json:"id,omitempty"`
			NewName *string `json:"new_name,omitempty"`
		}{Id: &id, NewName: &name})
	}
	return entries, nil
}

func init() {
	secretBulkRenameCmd.Flags().IntVar(&bulkRenameProject, "project", 0, "Project ID (required)")
	secretBulkRenameCmd.Flags().StringArrayVar(&bulkRenamePairs, "rename", nil, "Rename as <id>=<new-name> (repeatable)")
	secretBulkRenameCmd.Flags().BoolVar(&bulkRenameApply, "apply", false, "Actually rename (default is a dry run)")
	SecretCmd.AddCommand(secretBulkRenameCmd)
}

// ── bulk-delete ──────────────────────────────────────────────────────────────

var (
	bulkDeleteProject int
	bulkDeleteEnv     int
	bulkDeleteIDs     []int
	bulkDeleteNames   []string
	bulkDeleteConfirm bool
)

var secretBulkDeleteCmd = &cobra.Command{
	Use:   "bulk-delete",
	Short: "Delete multiple secrets in one operation",
	Long: `Delete one or more secrets in a project in a single call.

Pass secret IDs directly with --ids, or resolve by name with --names (requires
--project and --env — a secret name is only unique within one project's
environment, not across the whole project). --confirm is mandatory for the
deletion to proceed; without it the command prints what would be deleted and
exits.`,
	SilenceUsage: true,
	RunE:         runSecretBulkDelete,
}

func runSecretBulkDelete(_ *cobra.Command, _ []string) error {
	if len(bulkDeleteIDs) == 0 && len(bulkDeleteNames) == 0 {
		return usageErrorf("at least one of --ids or --names is required")
	}
	if bulkDeleteProject == 0 && len(bulkDeleteNames) > 0 {
		return usageErrorf("--project is required when using --names")
	}
	if bulkDeleteEnv == 0 && len(bulkDeleteNames) > 0 {
		return usageErrorf("--env is required when using --names (a secret name is only unique within one project's environment, not across the whole project)")
	}

	// The API client is only built once it's actually needed: a pure --ids preview
	// (no --names to resolve, no --confirm to execute) must work offline, the same
	// way a plain flag-validation error does — it must never require live
	// credentials just to print what WOULD happen.
	var client *apiclient.ClientWithResponses
	if len(bulkDeleteNames) > 0 || bulkDeleteConfirm {
		var err error
		client, err = secretAPIClient()
		if err != nil {
			return err
		}
	}
	ctx := context.Background()

	ids := make([]int, 0, len(bulkDeleteIDs)+len(bulkDeleteNames))
	ids = append(ids, bulkDeleteIDs...)
	if len(bulkDeleteNames) > 0 {
		resolved, err := resolveSecretNamesToIDsStrict(ctx, client, bulkDeleteProject, bulkDeleteEnv, bulkDeleteNames)
		if err != nil {
			return err
		}
		ids = append(ids, resolved...)
	}

	if !bulkDeleteConfirm {
		fmt.Printf("Would delete %d secret(s): %s\n", len(ids), joinInts(ids))
		fmt.Println("Pass --confirm to actually delete.")
		return nil
	}

	resp, err := client.BulkDeleteSecretsWithResponse(ctx, bulkDeleteProject, apiclient.BulkDeleteSecretsJSONRequestBody{SecretIds: ids})
	if err != nil {
		return err
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return httpStatusError("bulk delete", resp.StatusCode(), resp.Body)
	}
	result := resp.JSON200.Data
	deleted := 0
	if result.Deleted != nil {
		deleted = len(*result.Deleted)
	}
	fmt.Printf("Deleted %d secrets.\n", deleted)
	if result.Failed != nil && len(*result.Failed) > 0 {
		fmt.Println("\nFailed:")
		for _, f := range *result.Failed {
			label := derefStr(f.Name)
			if label == "" {
				label = fmt.Sprintf("id=%d", derefInt(f.SecretId))
			}
			fmt.Printf("  %s: %s\n", label, derefStr(f.Error))
		}
	}
	return nil
}

// resolveSecretNamesToIDsStrict is resolveSecretNamesToIDs's bulk-delete sibling: unlike
// bulk-rotate's best-effort "skip a missing name with a warning", a missing name here is
// a hard error — deleting is destructive enough that silently proceeding on a partial
// match set would be surprising.
func resolveSecretNamesToIDsStrict(ctx context.Context, client *apiclient.ClientWithResponses, projectID, envID int, names []string) ([]int, error) {
	nameToIDs, err := listSecretNameIndex(ctx, client, projectID, envID)
	if err != nil {
		return nil, err
	}
	ids := make([]int, 0, len(names))
	var missing, ambiguous []string
	for _, name := range names {
		switch matches := nameToIDs[name]; len(matches) {
		case 0:
			missing = append(missing, name)
		case 1:
			ids = append(ids, matches[0])
		default:
			ambiguous = append(ambiguous, fmt.Sprintf("%q (IDs %v)", name, matches))
		}
	}
	if len(ambiguous) > 0 {
		return nil, fmt.Errorf("secret name(s) ambiguous in project %d, environment %d: %s — refusing to guess", projectID, envID, strings.Join(ambiguous, "; "))
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("secret(s) not found in project %d, environment %d: %s", projectID, envID, strings.Join(missing, ", "))
	}
	return ids, nil
}

func joinInts(ids []int) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = strconv.Itoa(id)
	}
	return strings.Join(parts, ", ")
}

func init() {
	secretBulkDeleteCmd.Flags().IntVar(&bulkDeleteProject, "project", 0, "Project ID (required for --names and for cross-project guard)")
	secretBulkDeleteCmd.Flags().IntVar(&bulkDeleteEnv, "env", 0, "Environment ID (required for --names)")
	secretBulkDeleteCmd.Flags().IntSliceVar(&bulkDeleteIDs, "ids", nil, "Comma-separated secret IDs to delete")
	secretBulkDeleteCmd.Flags().StringSliceVar(&bulkDeleteNames, "names", nil, "Comma-separated secret names to delete (requires --project and --env)")
	secretBulkDeleteCmd.Flags().BoolVar(&bulkDeleteConfirm, "confirm", false, "Required to actually delete (omit to preview)")
	SecretCmd.AddCommand(secretBulkDeleteCmd)
}
