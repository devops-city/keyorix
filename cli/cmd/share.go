// share.go ports `keyorix share` (docs/cli-split-inventory.md §2.x, PR 9): secret
// sharing (create/list/update/revoke/self-remove) plus the shared-secrets and
// group-shares read paths. Same flags and exit codes as the old CLI's
// internal/cli/share package's remote (server-backed) branch -- that branch is this
// CLI's only mode, so it is the golden-output baseline, not the embedded/local one.
//
// Deliberate deviation from the old CLI's remote branch: `share update`'s output
// previously printed only 4 of the 8 fields the embedded branch and `share create`
// print (docs/cli-split-inventory.md §8, output-parity gap). This port prints all 8,
// matching create/list/revoke -- a fix, not a faithful port of the narrower shape.
package cmd

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
	"github.com/keyorixhq/keyorix/cli/internal/cliout"
)

var shareCmd = &cobra.Command{
	Use:   "share",
	Short: "Share secrets with users and groups",
}

var (
	shareCreateSecretID    int
	shareCreateRecipientID int
	shareCreateIsGroup     bool
	shareCreatePermission  string
	shareCreateExpires     string
	shareCreateTTL         string
)

var shareCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Share a secret with another user or group",
	Long: `Share a secret with another user or group. The recipient must be a member of
the secret's project.

  read   the recipient can read the secret.
  write  the recipient can also update its value and metadata (description, tags)
         and rotate it. A write share never lets them suspend or resume it, change
         its expiry or read limit, move it, roll it back, transfer ownership,
         re-share it, change access rules or delete it: those need a project role.`,
	RunE: runShareCreate,
}

var shareListSecretID int

var shareListCmd = &cobra.Command{
	Use:   "list",
	Short: "List shares for a secret",
	RunE:  runShareList,
}

var (
	shareUpdateShareID     int
	shareUpdatePermission  string
	shareUpdateExpires     string
	shareUpdateTTL         string
	shareUpdateClearExpiry bool
)

var shareUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update a share's permission",
	RunE:  runShareUpdate,
}

var shareRevokeShareID int

var shareRevokeCmd = &cobra.Command{
	Use:   "revoke",
	Short: "Revoke a share",
	RunE:  runShareRevoke,
}

var shareSelfRemoveCmd = &cobra.Command{
	Use:   "self-remove <secret-id>",
	Short: "Remove yourself from a secret shared with you",
	Args:  cobra.ExactArgs(1),
	RunE:  runShareSelfRemove,
}

var sharedSecretsUserID int

var sharedSecretsCmd = &cobra.Command{
	Use:   "shared-secrets",
	Short: "List secrets shared with a user (defaults to yourself)",
	RunE:  runSharedSecrets,
}

var groupSharesGroupID int

var groupSharesCmd = &cobra.Command{
	Use:   "group-shares",
	Short: "List shares for a group",
	RunE:  runGroupShares,
}

func init() {
	shareCreateCmd.Flags().IntVar(&shareCreateSecretID, "secret-id", 0, "Secret ID (required)")
	shareCreateCmd.Flags().IntVar(&shareCreateRecipientID, "recipient-id", 0, "Recipient ID (required)")
	shareCreateCmd.Flags().BoolVar(&shareCreateIsGroup, "is-group", false, "Whether the recipient is a group")
	shareCreateCmd.Flags().StringVar(&shareCreatePermission, "permission", "read", "Permission level: read, or write (read + update value/metadata + rotate; see --help)")
	shareCreateCmd.Flags().StringVar(&shareCreateExpires, "expires", "", "Make the share time-bound: absolute expiry (RFC3339, e.g. 2026-07-01T15:00:00Z)")
	shareCreateCmd.Flags().StringVar(&shareCreateTTL, "ttl", "", "Make the share time-bound: lifetime from now (Go duration, e.g. 24h, 30m); mutually exclusive with --expires")
	_ = shareCreateCmd.MarkFlagRequired("secret-id")    // #nosec G104
	_ = shareCreateCmd.MarkFlagRequired("recipient-id") // #nosec G104

	shareListCmd.Flags().IntVar(&shareListSecretID, "secret-id", 0, "Secret ID (required)")
	_ = shareListCmd.MarkFlagRequired("secret-id") // #nosec G104

	shareUpdateCmd.Flags().IntVar(&shareUpdateShareID, "share-id", 0, "Share ID (required)")
	shareUpdateCmd.Flags().StringVar(&shareUpdatePermission, "permission", "", "Permission level: read, or write (read + update value/metadata + rotate) (required)")
	shareUpdateCmd.Flags().StringVar(&shareUpdateExpires, "expires", "", "Set/extend the time-bound expiry: absolute (RFC3339)")
	shareUpdateCmd.Flags().StringVar(&shareUpdateTTL, "ttl", "", "Set/extend the time-bound expiry: lifetime from now (Go duration, e.g. 24h); mutually exclusive with --expires")
	shareUpdateCmd.Flags().BoolVar(&shareUpdateClearExpiry, "clear-expiry", false, "Make the share permanent (remove its expiry)")
	_ = shareUpdateCmd.MarkFlagRequired("share-id")   // #nosec G104
	_ = shareUpdateCmd.MarkFlagRequired("permission") // #nosec G104

	shareRevokeCmd.Flags().IntVar(&shareRevokeShareID, "share-id", 0, "Share ID (required)")
	_ = shareRevokeCmd.MarkFlagRequired("share-id") // #nosec G104

	sharedSecretsCmd.Flags().IntVar(&sharedSecretsUserID, "user-id", 0,
		"User ID (defaults to yourself; viewing another user's shared secrets requires an admin permission and rank over that user)")

	groupSharesCmd.Flags().IntVar(&groupSharesGroupID, "group-id", 0, "Group ID (required)")
	_ = groupSharesCmd.MarkFlagRequired("group-id") // #nosec G104

	shareCmd.AddCommand(shareCreateCmd, shareListCmd, shareUpdateCmd, shareRevokeCmd, shareSelfRemoveCmd, sharedSecretsCmd, groupSharesCmd)
	rootCmd.AddCommand(shareCmd)
}

// shareAPIClient resolves the stored credentials and builds a client, the shared
// pre-flight every share subcommand needs.
func shareAPIClient() (*apiclient.ClientWithResponses, error) {
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

// resolveShareExpiry turns the --expires (absolute RFC3339) and --ttl (relative Go
// duration) flags into an absolute expiry instant for a share.
//
//   - The two flags are mutually exclusive.
//   - Both empty → (nil, nil): a permanent share (or, on update, "leave expiry as-is").
//   - --ttl is resolved against the current wall clock.
//
// A past expiry is left for the server to reject (it owns the authoritative "must be
// in the future" check against its own clock); this helper only parses and enforces
// that --ttl is positive, so the two flags can't silently disagree.
func resolveShareExpiry(expires, ttl string) (*time.Time, error) {
	if expires != "" && ttl != "" {
		return nil, fmt.Errorf("use only one of --expires or --ttl")
	}
	switch {
	case expires != "":
		t, err := time.Parse(time.RFC3339, expires)
		if err != nil {
			return nil, fmt.Errorf("invalid --expires (want RFC3339, e.g. 2026-07-01T15:00:00Z): %w", err)
		}
		return &t, nil
	case ttl != "":
		d, err := time.ParseDuration(ttl)
		if err != nil {
			return nil, fmt.Errorf("invalid --ttl (want a Go duration, e.g. 24h, 30m): %w", err)
		}
		if d <= 0 {
			return nil, fmt.Errorf("--ttl must be a positive duration")
		}
		t := time.Now().Add(d)
		return &t, nil
	default:
		return nil, nil
	}
}

// formatShareExpiry renders a share's expiry for CLI output: a local timestamp, or
// "never" for a permanent share.
func formatShareExpiry(expiresAt *time.Time) string {
	if expiresAt == nil {
		return "never"
	}
	return expiresAt.UTC().Format("2006-01-02 15:04:05")
}

func runShareCreate(cmd *cobra.Command, args []string) error {
	if shareCreatePermission != "read" && shareCreatePermission != "write" {
		return fmt.Errorf("invalid permission: %s (must be 'read' or 'write')", shareCreatePermission)
	}
	expiresAt, err := resolveShareExpiry(shareCreateExpires, shareCreateTTL)
	if err != nil {
		return err
	}

	body := apiclient.ShareSecretJSONRequestBody{
		RecipientId: shareCreateRecipientID,
		Permission:  apiclient.ShareSecretJSONBodyPermission(shareCreatePermission),
		ExpiresAt:   expiresAt,
	}
	if shareCreateIsGroup {
		body.IsGroup = &shareCreateIsGroup
	}

	client, err := shareAPIClient()
	if err != nil {
		return err
	}
	resp, err := client.ShareSecretWithResponse(context.Background(), shareCreateSecretID, body)
	if err != nil {
		return err
	}
	if resp.JSON201 == nil || resp.JSON201.Data == nil {
		return httpStatusError("failed to share secret", resp.StatusCode(), resp.Body)
	}
	s := resp.JSON201.Data
	fmt.Printf("✅ Secret shared successfully!\n")
	fmt.Printf("Share ID: %d\n", derefInt(s.Id))
	fmt.Printf("Secret ID: %d\n", derefInt(s.SecretId))
	fmt.Printf("Owner ID: %d\n", derefInt(s.OwnerId))
	fmt.Printf("Recipient ID: %d\n", derefInt(s.RecipientId))
	fmt.Printf("Is Group: %t\n", derefBool(s.IsGroup))
	fmt.Printf("Permission: %s\n", derefSharePermission(s.Permission))
	fmt.Printf("Created At: %s\n", formatShareExpiry(s.CreatedAt))
	fmt.Printf("Expires At: %s\n", formatShareExpiry(s.ExpiresAt))
	return nil
}

func runShareList(cmd *cobra.Command, args []string) error {
	client, err := shareAPIClient()
	if err != nil {
		return err
	}
	resp, err := client.ListSecretSharesWithResponse(context.Background(), shareListSecretID)
	if err != nil {
		return err
	}
	if resp.JSON200 == nil {
		return httpStatusError("failed to list shares", resp.StatusCode(), resp.Body)
	}
	var shares []apiclient.Share
	if resp.JSON200.Data != nil && resp.JSON200.Data.Shares != nil {
		shares = *resp.JSON200.Data.Shares
	}
	if len(shares) == 0 {
		fmt.Println("No shares found for this secret.")
		return nil
	}
	t := cliout.NewStdoutTable("ID", "SECRET ID", "OWNER ID", "RECIPIENT ID", "IS GROUP", "PERMISSION", "CREATED AT", "EXPIRES AT")
	for _, s := range shares {
		t.Row(derefInt(s.Id), derefInt(s.SecretId), derefInt(s.OwnerId), derefInt(s.RecipientId),
			derefBool(s.IsGroup), derefSharePermission(s.Permission), formatShareExpiry(s.CreatedAt), formatShareExpiry(s.ExpiresAt))
	}
	return t.Flush()
}

func runShareUpdate(cmd *cobra.Command, args []string) error {
	if shareUpdatePermission != "read" && shareUpdatePermission != "write" {
		return fmt.Errorf("invalid permission: %s (must be 'read' or 'write')", shareUpdatePermission)
	}
	if shareUpdateClearExpiry && (shareUpdateExpires != "" || shareUpdateTTL != "") {
		return fmt.Errorf("--clear-expiry cannot be combined with --expires or --ttl")
	}
	expiresAt, err := resolveShareExpiry(shareUpdateExpires, shareUpdateTTL)
	if err != nil {
		return err
	}

	body := apiclient.UpdateSharePermissionJSONRequestBody{
		Permission: apiclient.UpdateSharePermissionJSONBodyPermission(shareUpdatePermission),
		ExpiresAt:  expiresAt,
	}
	if shareUpdateClearExpiry {
		body.ClearExpiry = &shareUpdateClearExpiry
	}

	client, err := shareAPIClient()
	if err != nil {
		return err
	}
	resp, err := client.UpdateSharePermissionWithResponse(context.Background(), shareUpdateShareID, body)
	if err != nil {
		return err
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return httpStatusError("failed to update share permission", resp.StatusCode(), resp.Body)
	}
	s := resp.JSON200.Data
	fmt.Printf("Share permission updated successfully!\n")
	fmt.Printf("Share ID: %d\n", derefInt(s.Id))
	fmt.Printf("Secret ID: %d\n", derefInt(s.SecretId))
	fmt.Printf("Owner ID: %d\n", derefInt(s.OwnerId))
	fmt.Printf("Recipient ID: %d\n", derefInt(s.RecipientId))
	fmt.Printf("Is Group: %t\n", derefBool(s.IsGroup))
	fmt.Printf("Permission: %s\n", derefSharePermission(s.Permission))
	fmt.Printf("Updated At: %s\n", formatShareExpiry(s.UpdatedAt))
	fmt.Printf("Expires At: %s\n", formatShareExpiry(s.ExpiresAt))
	return nil
}

func runShareRevoke(cmd *cobra.Command, args []string) error {
	client, err := shareAPIClient()
	if err != nil {
		return err
	}
	resp, err := client.RevokeShareWithResponse(context.Background(), shareRevokeShareID)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 204 {
		return httpStatusError("failed to revoke share", resp.StatusCode(), resp.Body)
	}
	fmt.Printf("Share revoked successfully!\n")
	fmt.Printf("Share ID: %d\n", shareRevokeShareID)
	return nil
}

func runShareSelfRemove(cmd *cobra.Command, args []string) error {
	secretID, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("invalid secret ID %q: %w", args[0], err)
	}
	client, err := shareAPIClient()
	if err != nil {
		return err
	}
	resp, err := client.RemoveSelfFromShareWithResponse(context.Background(), secretID)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 204 {
		return httpStatusError("remove self from share", resp.StatusCode(), resp.Body)
	}
	fmt.Printf("Removed yourself from secret %d.\n", secretID)
	return nil
}

func runSharedSecrets(cmd *cobra.Command, args []string) error {
	client, err := shareAPIClient()
	if err != nil {
		return err
	}

	var secrets []apiclient.Secret
	if sharedSecretsUserID != 0 {
		resp, err := client.ListSharedSecretsForUserWithResponse(context.Background(), sharedSecretsUserID)
		if err != nil {
			return err
		}
		if resp.JSON200 == nil {
			return httpStatusError("failed to list shared secrets", resp.StatusCode(), resp.Body)
		}
		if resp.JSON200.Data != nil && resp.JSON200.Data.Secrets != nil {
			secrets = *resp.JSON200.Data.Secrets
		}
	} else {
		resp, err := client.ListSharedSecretsWithResponse(context.Background())
		if err != nil {
			return err
		}
		if resp.JSON200 == nil {
			return httpStatusError("failed to list shared secrets", resp.StatusCode(), resp.Body)
		}
		if resp.JSON200.Data != nil && resp.JSON200.Data.Secrets != nil {
			secrets = *resp.JSON200.Data.Secrets
		}
	}

	if len(secrets) == 0 {
		fmt.Println("No shared secrets found.")
		return nil
	}
	t := cliout.NewStdoutTable("ID", "NAME", "TYPE", "PROJECT", "ENVIRONMENT", "CREATED BY", "CREATED AT")
	for _, s := range secrets {
		t.Row(derefInt(s.Id), derefStr(s.Name), derefStr(s.Type), derefInt(s.ProjectId), derefInt(s.EnvironmentId),
			derefStr(s.CreatedBy), formatShareExpiry(s.CreatedAt))
	}
	return t.Flush()
}

func runGroupShares(cmd *cobra.Command, args []string) error {
	client, err := shareAPIClient()
	if err != nil {
		return err
	}
	resp, err := client.ListGroupSharesWithResponse(context.Background(), groupSharesGroupID)
	if err != nil {
		return err
	}
	if resp.JSON200 == nil {
		return httpStatusError("failed to list group shares", resp.StatusCode(), resp.Body)
	}
	var shares []apiclient.Share
	if resp.JSON200.Data != nil && resp.JSON200.Data.Shares != nil {
		shares = *resp.JSON200.Data.Shares
	}
	if len(shares) == 0 {
		fmt.Println("No shares found for this group.")
		return nil
	}
	t := cliout.NewStdoutTable("ID", "SECRET ID", "OWNER ID", "GROUP ID", "PERMISSION", "CREATED AT")
	for _, s := range shares {
		t.Row(derefInt(s.Id), derefInt(s.SecretId), derefInt(s.OwnerId), derefInt(s.RecipientId),
			derefSharePermission(s.Permission), formatShareExpiry(s.CreatedAt))
	}
	return t.Flush()
}

func derefSharePermission(p *apiclient.SharePermission) string {
	if p == nil {
		return ""
	}
	return string(*p)
}
