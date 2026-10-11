package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

// ── versions ────────────────────────────────────────────────────────────────────

var (
	secretVersionsID     int
	secretVersionsFormat string
)

var secretVersionsCmd = &cobra.Command{
	Use:   "versions",
	Short: "List secret versions",
	RunE:  runSecretVersions,
}

func init() {
	secretVersionsCmd.Flags().IntVar(&secretVersionsID, "id", 0, "Secret ID (required)")
	secretVersionsCmd.Flags().StringVar(&secretVersionsFormat, "format", "table", "Output format (table, json)")
	SecretCmd.AddCommand(secretVersionsCmd)
}

func runSecretVersions(cmd *cobra.Command, args []string) error {
	if secretVersionsID == 0 {
		return fmt.Errorf("secret ID is required (use --id)")
	}
	client, err := secretAPIClient()
	if err != nil {
		return err
	}
	ctx := context.Background()

	f := false
	sresp, err := client.GetSecretWithResponse(ctx, secretVersionsID, &apiclient.GetSecretParams{IncludeValue: &f})
	if err != nil {
		return fmt.Errorf("secret not found: %w", err)
	}
	if sresp.JSON200 == nil || sresp.JSON200.Data == nil {
		return httpStatusError("secret not found", sresp.StatusCode(), sresp.Body)
	}
	secret := secretGetResultToSecret(sresp.JSON200.Data)

	vresp, err := client.GetSecretVersionsWithResponse(ctx, secretVersionsID)
	if err != nil {
		return fmt.Errorf("failed to get versions: %w", err)
	}
	if vresp.JSON200 == nil || vresp.JSON200.Data == nil {
		return httpStatusError("failed to get versions", vresp.StatusCode(), vresp.Body)
	}
	versions := derefSecretVersionSlice(vresp.JSON200.Data.Versions)
	totalReads := vresp.JSON200.Data.TotalReads

	switch secretVersionsFormat {
	case "json":
		return displayVersionsJSON(secret, versions, totalReads)
	case "table":
		displayVersionsTable(secret, versions, totalReads)
		return nil
	default:
		return fmt.Errorf("unsupported format: %s (use 'table' or 'json')", secretVersionsFormat)
	}
}

// displayVersionsTable omits the size/algorithm columns the old CLI's
// embedded-mode table had: EncryptedValue/EncryptionMetadata are `json:"-"`
// on the server (internal/storage/models.SecretVersion) and never sent over
// the wire, so faking those columns from data that never arrives would be
// dishonest, not a parity gap.
func displayVersionsTable(secret *apiclient.Secret, versions []apiclient.SecretVersion, totalReads *int) {
	fmt.Println("Secret Versions")
	fmt.Println("==================")
	fmt.Printf("Secret: %s (ID: %d)\n", derefStr(secret.Name), derefSecretInt(secret.Id))
	fmt.Printf("Total Versions: %d\n", len(versions))
	if totalReads != nil {
		fmt.Printf("Total Reads: %d\n", *totalReads)
	}
	fmt.Println("(size/algorithm columns are omitted -- not exposed by the API)")
	fmt.Println()

	if len(versions) == 0 {
		fmt.Println("No versions found.")
		return
	}
	fmt.Printf("%-8s %-10s %-20s\n", "VERSION", "READS*", "CREATED (UTC)")
	fmt.Printf("%-8s %-10s %-20s\n", "--------", "----------", "--------------------")
	for _, v := range versions {
		created := ""
		if v.CreatedAt != nil {
			created = v.CreatedAt.UTC().Format("2006-01-02 15:04:05")
		}
		fmt.Printf("%-8d %-10d %-20s\n", derefSecretInt(v.VersionNumber), derefSecretInt(v.ReadCount), created)
	}
	if len(versions) > 0 {
		latest := versions[0]
		for _, v := range versions[1:] {
			if derefSecretInt(v.VersionNumber) > derefSecretInt(latest.VersionNumber) {
				latest = v
			}
		}
		created := ""
		if latest.CreatedAt != nil {
			created = latest.CreatedAt.UTC().Format("2006-01-02 15:04:05")
		}
		fmt.Printf("\nLatest Version: %d (Created: %s)\n", derefSecretInt(latest.VersionNumber), created)
		fmt.Println("* READS counts reads against a --max-reads limit only (0 when none is set); Total Reads above counts every value read of the secret; each is listed by `keyorix secret access-log`.")
	}
}

type jsonVersionEntry struct {
	ID            int    `json:"id"`
	VersionNumber int    `json:"version_number"`
	ReadCount     int    `json:"read_count"`
	CreatedAt     string `json:"created_at"`
}

func displayVersionsJSON(secret *apiclient.Secret, versions []apiclient.SecretVersion, totalReads *int) error {
	var out struct {
		Secret struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"secret"`
		TotalVersions int                `json:"total_versions"`
		TotalReads    *int               `json:"total_reads,omitempty"`
		Versions      []jsonVersionEntry `json:"versions"`
	}
	out.TotalReads = totalReads
	out.Secret.ID = derefSecretInt(secret.Id)
	out.Secret.Name = derefStr(secret.Name)
	out.Secret.Type = derefStr(secret.Type)
	out.TotalVersions = len(versions)
	out.Versions = make([]jsonVersionEntry, 0, len(versions))
	for _, v := range versions {
		entry := jsonVersionEntry{ID: derefSecretInt(v.ID), VersionNumber: derefSecretInt(v.VersionNumber), ReadCount: derefSecretInt(v.ReadCount)}
		if v.CreatedAt != nil {
			entry.CreatedAt = v.CreatedAt.Format(time.RFC3339)
		}
		out.Versions = append(out.Versions, entry)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// ── diff ────────────────────────────────────────────────────────────────────────

var (
	secretDiffID      int
	secretDiffProject int
	secretDiffEnv     int
)

var secretDiffCmd = &cobra.Command{
	Use:   "diff <name> <from-version> <to-version>",
	Short: "Diff metadata between two versions of a secret",
	Long: `Compare metadata between two versions of a secret.

Values (encrypted ciphertext) are never compared -- only classification,
expiry, read count, and the current ACL snapshot.

<name> is resolved to a secret ID via --project/--environment (both
required, matching every other by-name lookup in this command group --
GET /api/v1/secrets/by-name needs a numeric project_id/environment_id, not
a name filter), unless --id is given directly.`,
	Args:         cobra.ExactArgs(3),
	SilenceUsage: true,
	RunE:         runSecretDiff,
}

func init() {
	secretDiffCmd.Flags().IntVar(&secretDiffID, "id", 0, "Secret ID (skips the <name> lookup below when set)")
	secretDiffCmd.Flags().IntVar(&secretDiffProject, "project", 0, "Project ID (required unless --id is set)")
	secretDiffCmd.Flags().IntVar(&secretDiffEnv, "environment", 0, "Environment ID (required unless --id is set)")
	SecretCmd.AddCommand(secretDiffCmd)
}

func runSecretDiff(_ *cobra.Command, args []string) error {
	name := args[0]
	fromVersion, err := strconv.Atoi(args[1])
	if err != nil || fromVersion <= 0 {
		return fmt.Errorf("from-version must be a positive integer")
	}
	toVersion, err := strconv.Atoi(args[2])
	if err != nil || toVersion <= 0 {
		return fmt.Errorf("to-version must be a positive integer")
	}

	client, err := secretAPIClient()
	if err != nil {
		return err
	}
	ctx := context.Background()

	id := secretDiffID
	if id == 0 {
		if secretDiffProject == 0 || secretDiffEnv == 0 {
			return fmt.Errorf("--project and --environment are required to resolve <name> (or pass --id directly)")
		}
		resp, nerr := client.GetSecretByNameWithResponse(ctx, &apiclient.GetSecretByNameParams{
			Name: name, ProjectId: secretDiffProject, EnvironmentId: secretDiffEnv,
		})
		if nerr != nil {
			return fmt.Errorf("secret %q not found: %w", name, nerr)
		}
		if resp.JSON200 == nil || resp.JSON200.Data == nil {
			return httpStatusError(fmt.Sprintf("secret %q not found", name), resp.StatusCode(), resp.Body)
		}
		id = derefSecretInt(resp.JSON200.Data.Id)
	}

	resp, err := client.DiffSecretVersionsWithResponse(ctx, id, fromVersion, toVersion)
	if err != nil {
		return err
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return httpStatusError("diff secret versions", resp.StatusCode(), resp.Body)
	}
	d := resp.JSON200.Data
	printSecretDiff(derefStr(d.SecretName), derefSecretInt(d.FromVersion), derefSecretInt(d.ToVersion), derefDiffChangeSlice(d.Changes), derefSecretIntSlice(d.AclUserIds), derefSecretBool(d.Degraded))
	return nil
}

func printSecretDiff(secretName string, fromV, toV int, changes []apiclient.SecretVersionDiffChange, aclUserIDs []int, degraded bool) {
	fmt.Printf("Secret: %s  (v%d -> v%d)\n\n", secretName, fromV, toV)
	if len(changes) == 0 {
		fmt.Printf("No metadata changes between v%d and v%d.\n", fromV, toV)
	} else {
		for _, ch := range changes {
			fmt.Printf("  %-20s %q -> %q\n", derefStr(ch.Field), derefStr(ch.OldValue), derefStr(ch.NewValue))
		}
	}
	fmt.Println()
	switch {
	case degraded:
		fmt.Println("ACL (current): unavailable -- the ACL lookup failed, this is NOT a confirmed empty list.")
	case len(aclUserIDs) == 0:
		fmt.Println("No ACL entries (current).")
	default:
		ids := make([]string, len(aclUserIDs))
		for i, id := range aclUserIDs {
			ids[i] = strconv.Itoa(id)
		}
		fmt.Printf("ACL (current): users [%s]\n", strings.Join(ids, ", "))
	}
}

func derefDiffChangeSlice(s *[]apiclient.SecretVersionDiffChange) []apiclient.SecretVersionDiffChange {
	if s == nil {
		return nil
	}
	return *s
}

func derefSecretIntSlice(s *[]int) []int {
	if s == nil {
		return nil
	}
	return *s
}

// ── version comment ─────────────────────────────────────────────────────────────

var versionCommentCmd = &cobra.Command{
	Use:   "comment",
	Short: "Manage secret version comments",
}

var versionCommentAddCmd = &cobra.Command{
	Use:          "add <secret-id> <version-id> <comment>",
	Short:        "Add a comment to a secret version",
	Args:         cobra.ExactArgs(3),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		secretID, err := parseSecretArg(args[0])
		if err != nil {
			return fmt.Errorf("invalid secret ID %q: %w", args[0], err)
		}
		versionID, err := parseSecretArg(args[1])
		if err != nil {
			return fmt.Errorf("invalid version ID %q: %w", args[1], err)
		}
		comment := args[2]
		if comment == "" {
			return fmt.Errorf("comment cannot be empty")
		}
		client, err := secretAPIClient()
		if err != nil {
			return err
		}
		resp, err := client.AddSecretVersionCommentWithResponse(context.Background(), secretID, versionID, apiclient.AddSecretVersionCommentJSONRequestBody{Comment: comment})
		if err != nil {
			return fmt.Errorf("failed to add comment: %w", err)
		}
		if resp.JSON200 == nil || resp.JSON200.Data == nil {
			return httpStatusError("failed to add comment", resp.StatusCode(), resp.Body)
		}
		c := resp.JSON200.Data
		when := ""
		if c.CreatedAt != nil {
			when = c.CreatedAt.Format(time.RFC3339)
		}
		fmt.Printf("Comment added (id=%d) by %s at %s\n", derefSecretInt(c.Id), derefStr(c.Username), when)
		return nil
	},
}

var versionCommentListCmd = &cobra.Command{
	Use:          "list <secret-id> <version-id>",
	Short:        "List comments on a secret version",
	Args:         cobra.ExactArgs(2),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		secretID, err := parseSecretArg(args[0])
		if err != nil {
			return fmt.Errorf("invalid secret ID %q: %w", args[0], err)
		}
		versionID, err := parseSecretArg(args[1])
		if err != nil {
			return fmt.Errorf("invalid version ID %q: %w", args[1], err)
		}
		client, err := secretAPIClient()
		if err != nil {
			return err
		}
		resp, err := client.ListSecretVersionCommentsWithResponse(context.Background(), secretID, versionID)
		if err != nil {
			return fmt.Errorf("failed to list comments: %w", err)
		}
		if resp.JSON200 == nil || resp.JSON200.Data == nil {
			return httpStatusError("failed to list comments", resp.StatusCode(), resp.Body)
		}
		comments := derefVersionCommentSlice(resp.JSON200.Data.Comments)
		total := derefSecretInt(resp.JSON200.Data.Total)
		if total == 0 {
			fmt.Println("No comments found.")
			return nil
		}
		fmt.Printf("Comments for secret %s, version %s (%d total):\n", args[0], args[1], total)
		for _, c := range comments {
			when := ""
			if c.CreatedAt != nil {
				when = c.CreatedAt.UTC().Format("2006-01-02 15:04:05")
			}
			fmt.Printf("  [%d] %s (%s): %s\n", derefSecretInt(c.Id), derefStr(c.Username), when, derefStr(c.Comment))
		}
		return nil
	},
}

var versionCommentDeleteCmd = &cobra.Command{
	Use:          "delete <secret-id> <version-id> <comment-id>",
	Short:        "Delete a comment from a secret version",
	Args:         cobra.ExactArgs(3),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		secretID, err := parseSecretArg(args[0])
		if err != nil {
			return fmt.Errorf("invalid secret ID %q: %w", args[0], err)
		}
		versionID, err := parseSecretArg(args[1])
		if err != nil {
			return fmt.Errorf("invalid version ID %q: %w", args[1], err)
		}
		commentID, err := parseSecretArg(args[2])
		if err != nil {
			return fmt.Errorf("invalid comment ID %q: %w", args[2], err)
		}
		client, err := secretAPIClient()
		if err != nil {
			return err
		}
		resp, err := client.DeleteSecretVersionCommentWithResponse(context.Background(), secretID, versionID, commentID)
		if err != nil {
			return fmt.Errorf("failed to delete comment: %w", err)
		}
		if resp.StatusCode() != 204 {
			return httpStatusError("failed to delete comment", resp.StatusCode(), resp.Body)
		}
		fmt.Printf("Comment %d deleted.\n", commentID)
		return nil
	},
}

func derefVersionCommentSlice(s *[]apiclient.SecretVersionComment) []apiclient.SecretVersionComment {
	if s == nil {
		return nil
	}
	return *s
}

func init() {
	versionCommentCmd.AddCommand(versionCommentAddCmd, versionCommentListCmd, versionCommentDeleteCmd)
	SecretCmd.AddCommand(versionCommentCmd)
}

// ── rollback ────────────────────────────────────────────────────────────────────

var (
	secretRollbackID      int
	secretRollbackVersion int
)

var secretRollbackCmd = &cobra.Command{
	Use:   "rollback",
	Short: "Restore a secret to the value of a prior version",
	Long: `Restore a secret to an earlier version's value. The old value is re-instated
as a NEW version (history stays append-only, so the rollback itself can be undone).`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if secretRollbackID == 0 {
			return fmt.Errorf("--id is required")
		}
		if secretRollbackVersion <= 0 {
			return fmt.Errorf("--version must be a positive version number")
		}
		client, err := secretAPIClient()
		if err != nil {
			return err
		}
		resp, err := client.RollbackSecretWithResponse(context.Background(), secretRollbackID, apiclient.RollbackSecretJSONRequestBody{Version: secretRollbackVersion})
		if err != nil {
			return err
		}
		if resp.StatusCode() < 200 || resp.StatusCode() >= 300 {
			return httpStatusError("rollback secret", resp.StatusCode(), resp.Body)
		}
		fmt.Printf("Secret %d rolled back to the value of version %d (as a new version).\n", secretRollbackID, secretRollbackVersion)
		return nil
	},
}

func init() {
	secretRollbackCmd.Flags().IntVar(&secretRollbackID, "id", 0, "Secret ID (required)")
	secretRollbackCmd.Flags().IntVar(&secretRollbackVersion, "version", 0, "Version number to restore (required)")
	SecretCmd.AddCommand(secretRollbackCmd)
}
