// pat.go ports `keyorix pat` (docs/cli-split-inventory.md §2.3, PR 2): self-service
// personal access tokens. Same flags, output, and exit codes as the old CLI's
// internal/cli/pat package -- this is a pure transport port (REST only, Zero GAPs),
// not a behavior change.
package cmd

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
	"github.com/keyorixhq/keyorix/cli/internal/cliout"
)

var patCmd = &cobra.Command{
	Use:     "pat",
	Aliases: []string{"token", "tokens"},
	Short:   "Create and manage personal access tokens",
}

var (
	patCreateName    string
	patCreateExpires string
	patCreateScopes  []string
	patCreateProject int
	patCreateEnv     int
	patCreateCIDRs   []string
)

var patCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a personal access token (the raw token is shown once)",
	RunE:  runPATCreate,
}

var patListCmd = &cobra.Command{
	Use:   "list",
	Short: "List your personal access tokens",
	RunE:  runPATList,
}

var patRevokeCmd = &cobra.Command{
	Use:   "revoke <token-id>",
	Short: "Revoke one of your tokens",
	Args:  cobra.ExactArgs(1),
	RunE:  runPATRevoke,
}

var patListExpiredCmd = &cobra.Command{
	Use:   "list-expired",
	Short: "List your expired (non-revoked) personal access tokens",
	RunE:  runPATListExpired,
}

var patCleanupExpiredCmd = &cobra.Command{
	Use:   "cleanup-expired",
	Short: "Bulk-revoke all your expired personal access tokens",
	RunE:  runPATCleanupExpired,
}

var patHygieneDays int

var patHygieneCmd = &cobra.Command{
	Use:   "hygiene",
	Short: "List stale or expired-but-active tokens across all users (admin)",
	Long: `Show the deployment-wide personal access tokens that should probably be
revoked: ones that have expired but were never revoked, and ones unused for a long
window (token sprawl). Requires global audit.read. Never prints a token's secret.`,
	RunE: runPATHygiene,
}

func init() {
	patCreateCmd.Flags().StringVar(&patCreateName, "name", "", "Token name (required)")
	patCreateCmd.Flags().StringVar(&patCreateExpires, "expires", "", "Expiry (RFC3339 or YYYY-MM-DD; omit = never)")
	patCreateCmd.Flags().StringArrayVar(&patCreateScopes, "scope", nil, "Least-privilege permission (repeatable; e.g. --scope secrets.read). Omit = inherit all your permissions")
	patCreateCmd.Flags().IntVar(&patCreateProject, "project-id", 0, "Confine the token to a single project (0 = any)")
	patCreateCmd.Flags().IntVar(&patCreateEnv, "environment-id", 0, "Confine the token to a single environment (0 = any; only with --project-id)")
	patCreateCmd.Flags().StringArrayVar(&patCreateCIDRs, "allowed-cidr", nil, "Restrict the token to source IPs in this CIDR (repeatable; e.g. --allowed-cidr 10.0.0.0/8). Omit = no network restriction")
	patHygieneCmd.Flags().IntVar(&patHygieneDays, "days", 0, "Staleness window in days (default server-side: 90, cap 3650)")

	patCmd.AddCommand(patCreateCmd, patListCmd, patRevokeCmd, patListExpiredCmd, patCleanupExpiredCmd, patHygieneCmd)
	rootCmd.AddCommand(patCmd)
}

// patAPIClient resolves the stored credentials and builds a client, the shared
// pre-flight every pat subcommand needs.
func patAPIClient() (*apiclient.ClientWithResponses, error) {
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

func runPATCreate(cmd *cobra.Command, args []string) error {
	if strings.TrimSpace(patCreateName) == "" {
		return fmt.Errorf("--name is required")
	}
	if patCreateEnv > 0 && patCreateProject == 0 {
		return fmt.Errorf("--environment-id requires --project-id (an environment belongs to a project)")
	}

	body := apiclient.CreatePATJSONRequestBody{Name: patCreateName}
	if patCreateExpires != "" {
		exp, err := normalizePATExpiry(patCreateExpires)
		if err != nil {
			return err
		}
		body.ExpiresAt = &exp
	}
	if len(patCreateScopes) > 0 {
		body.Scopes = &patCreateScopes
	}
	if len(patCreateCIDRs) > 0 {
		body.AllowedCidrs = &patCreateCIDRs
	}
	if patCreateProject > 0 {
		body.ProjectScope = &patCreateProject
	}
	if patCreateEnv > 0 {
		body.EnvironmentScope = &patCreateEnv
	}

	client, err := patAPIClient()
	if err != nil {
		return err
	}
	resp, err := client.CreatePATWithResponse(context.Background(), body)
	if err != nil {
		return err
	}
	if resp.JSON201 == nil || resp.JSON201.Data == nil {
		return httpStatusError("create token failed", resp.StatusCode(), resp.Body)
	}
	data := resp.JSON201.Data
	var pat apiclient.PATToken
	if data.Pat != nil {
		pat = *data.Pat
	}
	fmt.Println("Token created — copy it now, it will not be shown again:")
	fmt.Printf("  %s\n", derefStr(data.Token))
	fmt.Printf("  id:    %d\n  name:  %s\n  scope: %s\n", derefInt(pat.Id), derefStr(pat.Name), describePATScope(pat))
	return nil
}

func runPATList(cmd *cobra.Command, args []string) error {
	if err := checkOutputFormat(patListFormat); err != nil {
		return err
	}
	client, err := patAPIClient()
	if err != nil {
		return err
	}
	resp, err := client.ListPATsWithResponse(context.Background())
	if err != nil {
		return err
	}
	var tokens []apiclient.PATToken
	if resp.JSON200 != nil && resp.JSON200.Data != nil {
		tokens = *resp.JSON200.Data
	}
	// A listing never carries a token's secret, only its prefix (see the table below).
	return emitList(patListFormat, tokens, func() error {
		if len(tokens) == 0 {
			fmt.Println("You have no personal access tokens.")
			return nil
		}
		t := cliout.NewStdoutTable("ID", "NAME", "PREFIX", "CREATED", "LAST USED", "EXPIRES", "REVOKED", "SCOPE")
		for _, tok := range tokens {
			t.Row(derefInt(tok.Id), derefStr(tok.Name), derefStr(tok.TokenPrefix)+"…",
				patTimeDate(tok.CreatedAt), patTimeDate(tok.LastUsedAt), patTimeDate(tok.ExpiresAt),
				derefBool(tok.Revoked), describePATScope(tok))
		}
		return t.Flush()
	})
}

func runPATRevoke(cmd *cobra.Command, args []string) error {
	id, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("invalid token id: %s", args[0])
	}
	client, err := patAPIClient()
	if err != nil {
		return err
	}
	resp, err := client.RevokePATWithResponse(context.Background(), id)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 204 {
		return httpStatusError("revoke token failed", resp.StatusCode(), resp.Body)
	}
	fmt.Printf("Token %d revoked.\n", id)
	return nil
}

func runPATListExpired(cmd *cobra.Command, args []string) error {
	if err := checkOutputFormat(patExpiredFormat); err != nil {
		return err
	}
	client, err := patAPIClient()
	if err != nil {
		return err
	}
	resp, err := client.ListExpiredPATsWithResponse(context.Background())
	if err != nil {
		return err
	}
	var tokens []apiclient.PATToken
	if resp.JSON200 != nil && resp.JSON200.Data != nil {
		tokens = *resp.JSON200.Data
	}
	return emitList(patExpiredFormat, tokens, func() error {
		if resp.JSON200 == nil || resp.JSON200.Data == nil || len(*resp.JSON200.Data) == 0 {
			fmt.Println("You have no expired personal access tokens.")
			return nil
		}
		t := cliout.NewStdoutTable("ID", "NAME", "PREFIX", "CREATED", "EXPIRED", "SCOPE")
		for _, tok := range *resp.JSON200.Data {
			t.Row(derefInt(tok.Id), derefStr(tok.Name), derefStr(tok.TokenPrefix)+"…",
				patTimeDate(tok.CreatedAt), patTimeDate(tok.ExpiresAt), describePATScope(tok))
		}
		return t.Flush()
	})
}

func runPATCleanupExpired(cmd *cobra.Command, args []string) error {
	client, err := patAPIClient()
	if err != nil {
		return err
	}
	resp, err := client.BulkRevokeExpiredPATsWithResponse(context.Background())
	if err != nil {
		return err
	}
	if resp.StatusCode() < 200 || resp.StatusCode() >= 300 {
		return httpStatusError("cleanup-expired failed", resp.StatusCode(), resp.Body)
	}
	fmt.Println("All expired tokens have been revoked.")
	return nil
}

func runPATHygiene(cmd *cobra.Command, args []string) error {
	client, err := patAPIClient()
	if err != nil {
		return err
	}
	var params *apiclient.PatHygieneParams
	if patHygieneDays > 0 {
		params = &apiclient.PatHygieneParams{Days: &patHygieneDays}
	}
	resp, err := client.PatHygieneWithResponse(context.Background(), params)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		return httpStatusError("pat hygiene failed", resp.StatusCode(), resp.Body)
	}
	var rows []apiclient.PATHygieneRow
	if resp.JSON200 != nil && resp.JSON200.Data != nil && resp.JSON200.Data.Tokens != nil {
		rows = *resp.JSON200.Data.Tokens
	}
	if len(rows) == 0 {
		fmt.Println("No stale or expired tokens.")
		return nil
	}
	fmt.Printf("%-5s %-22s %-14s %-7s %-8s %s\n", "ID", "NAME", "PREFIX", "USER", "FLAGS", "LAST USED")
	for _, r := range rows {
		last := derefStr(r.LastUsedAt)
		if last == "" {
			last = "never"
		}
		fmt.Printf("%-5d %-22s %-14s %-7d %-8s %s\n", derefInt(r.Id), derefStr(r.Name), derefStr(r.TokenPrefix)+"…", derefInt(r.UserId), patHygieneFlagLabel(r), last)
	}
	return nil
}

func patHygieneFlagLabel(r apiclient.PATHygieneRow) string {
	expired := r.Expired != nil && *r.Expired
	stale := r.Stale != nil && *r.Stale
	switch {
	case expired && stale:
		return "exp,stale"
	case expired:
		return "expired"
	default:
		return "stale"
	}
}

// normalizePATExpiry accepts an RFC3339 timestamp or a bare YYYY-MM-DD date (treated
// as start-of-day UTC) and returns the time for the API.
func normalizePATExpiry(v string) (time.Time, error) {
	if strings.Contains(v, "T") {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return time.Time{}, fmt.Errorf("invalid --expires %q (want RFC3339 or YYYY-MM-DD): %w", v, err)
		}
		return t, nil
	}
	d, err := time.Parse("2006-01-02", v)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid --expires %q (want RFC3339 or YYYY-MM-DD): %w", v, err)
	}
	return d.UTC(), nil
}

// describePATScope renders a one-line summary of a token's least-privilege restriction.
func describePATScope(t apiclient.PATToken) string {
	scopes := derefStrSlice(t.Scopes)
	cidrs := derefStrSlice(t.AllowedCidrs)
	projectScope := derefInt(t.ProjectScope)
	envScope := derefInt(t.EnvironmentScope)
	if len(scopes) == 0 && projectScope == 0 && envScope == 0 && len(cidrs) == 0 {
		return "full access"
	}
	parts := make([]string, 0, 4)
	if projectScope > 0 {
		parts = append(parts, fmt.Sprintf("project=%d", projectScope))
	}
	if envScope > 0 {
		parts = append(parts, fmt.Sprintf("env=%d", envScope))
	}
	if len(scopes) > 0 {
		parts = append(parts, strings.Join(scopes, ","))
	}
	if len(cidrs) > 0 {
		parts = append(parts, "from="+strings.Join(cidrs, ","))
	}
	return strings.Join(parts, " ")
}

// patTimeDate renders an optional timestamp as a compact date, or "never" when absent.
func patTimeDate(t *time.Time) string {
	if t == nil || t.IsZero() {
		return "never"
	}
	return t.Format("2006-01-02")
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func derefInt(i *int) int {
	if i == nil {
		return 0
	}
	return *i
}

func derefBool(b *bool) bool {
	if b == nil {
		return false
	}
	return *b
}

func derefStrSlice(s *[]string) []string {
	if s == nil {
		return nil
	}
	return *s
}
