// system.go ports the network-facing subset of `keyorix system`
// (docs/cli-split-inventory.md §2.7, PR 10): `info`, `role-expiry-check`, and
// `token-expiry-check`. Same flags, output, and exit codes as the old CLI's
// internal/cli/system package -- a pure transport port, not a behavior change.
//
// `system audit`/`validate` are NOT ported here -- they are host-filesystem
// operations with no server interaction at all (ADMIN-B1 per the inventory doc), and belong
// in `keyorix-server admin`, not this network-only CLI.
//
// `system init` WAS dual-mode in the old CLI: local (host config/keys/DB, no server
// interaction) and --server (network bootstrap via POST /system/init). Only the local half
// is out of scope for the reason above -- it moved to `keyorix-server admin init`. The
// --server half is pure network I/O and belongs here; it was a PR 10 leftover gap, closed in
// systeminit.go.
package cmd

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/cliversion"
)

// buildValue renders a build-stamp field for humans. Go's ldflags defaults ("dev", "none",
// "unknown") and an empty value all mean "this binary was not stamped"; printing them raw
// makes a demo look unfinished and misreports what is running.
func buildValue(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "":
		return "n/a"
	case "none", "unknown":
		return "n/a (not stamped)"
	case "dev":
		return "dev (not stamped)"
	}
	return v
}

var systemCmd = &cobra.Command{
	Use:   "system",
	Short: "Server info and on-demand admin job triggers",
}

func init() {
	systemCmd.AddCommand(systemInfoCmd, systemRoleExpiryCheckCmd, systemTokenExpiryCheckCmd)
	rootCmd.AddCommand(systemCmd)
}

// systemInfoView mirrors the GET /api/v1/system/info response (snake_case DTO).
type systemInfoView struct {
	Version     string          `json:"version"`
	GitCommit   string          `json:"git_commit"`
	BuildTime   string          `json:"build_time"`
	GoVersion   string          `json:"go_version"`
	OS          string          `json:"os"`
	Arch        string          `json:"arch"`
	Uptime      string          `json:"uptime"`
	Environment string          `json:"environment"`
	Features    map[string]bool `json:"features"`
	Database    struct {
		Type      string `json:"type"`
		Connected bool   `json:"connected"`
	} `json:"database"`
	Security struct {
		TLSEnabled       bool   `json:"tls_enabled"`
		AuthEnabled      bool   `json:"auth_enabled"`
		EncryptionMethod string `json:"encryption_method"`
		AuditEnabled     bool   `json:"audit_enabled"`
	} `json:"security"`
}

var systemInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show the connected server's build identity and configuration",
	Long: `Display the remote Keyorix server's version, commit, runtime, and feature/security
configuration (GET /system/info). Useful for confirming which build you're talking to.
Requires a connection to a server and system.read.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx := context.Background()
		client, err := apiClientWithSkewCheck(ctx)
		if err != nil {
			return err
		}
		resp, err := client.GetSystemInfoWithResponse(ctx)
		if err != nil {
			return err
		}
		if resp.StatusCode() != 200 {
			return apiError("get system info", resp.StatusCode(), resp.Body)
		}
		info, err := decodeData[systemInfoView](resp.Body)
		if err != nil {
			return err
		}

		fmt.Printf("Version:     %s\n", buildValue(info.Version))
		fmt.Printf("Commit:      %s\n", buildValue(info.GitCommit))
		fmt.Printf("Built:       %s\n", buildValue(info.BuildTime))
		fmt.Printf("CLI:         %s\n", buildValue(cliversion.Version))
		fmt.Printf("Go:          %s\n", info.GoVersion)
		fmt.Printf("Platform:    %s/%s\n", info.OS, info.Arch)
		fmt.Printf("Uptime:      %s\n", info.Uptime)
		fmt.Printf("Environment: %s\n", info.Environment)
		fmt.Printf("Database:    %s (connected=%t)\n", info.Database.Type, info.Database.Connected)
		fmt.Printf("Security:    tls=%t auth=%t audit=%t encryption=%s\n",
			info.Security.TLSEnabled, info.Security.AuthEnabled, info.Security.AuditEnabled, info.Security.EncryptionMethod)

		if len(info.Features) > 0 {
			names := make([]string, 0, len(info.Features))
			for k := range info.Features {
				names = append(names, k)
			}
			sort.Strings(names)
			fmt.Print("Features:    ")
			for i, n := range names {
				if i > 0 {
					fmt.Print(", ")
				}
				fmt.Printf("%s=%t", n, info.Features[n])
			}
			fmt.Println()
		}
		return nil
	},
}

type roleExpiryCheckResult struct {
	Warnings  int `json:"warnings"`
	Criticals int `json:"criticals"`
}

var systemRoleExpiryCheckCmd = &cobra.Command{
	Use:   "role-expiry-check",
	Short: "Trigger a role-expiry notification scan on the connected server",
	Long: `Send immediate role-expiry notifications for time-bound role grants
approaching their deadline (POST /api/v1/admin/jobs/role-expiry-check).

Warning notifications are sent for grants expiring within 7 days; critical
notifications for those expiring within 1 day. Requires system.write.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx := context.Background()
		client, err := apiClientWithSkewCheck(ctx)
		if err != nil {
			return err
		}
		resp, err := client.RunRoleExpiryCheckWithResponse(ctx)
		if err != nil {
			return err
		}
		if resp.StatusCode() != 200 {
			return apiError("run role-expiry check", resp.StatusCode(), resp.Body)
		}
		result, err := decodeData[roleExpiryCheckResult](resp.Body)
		if err != nil {
			return err
		}
		fmt.Printf("Role-expiry check complete: %d warning(s), %d critical(s)\n", result.Warnings, result.Criticals)
		return nil
	},
}

type tokenExpiryCheckResult struct {
	PATWarnings      int `json:"pat_warnings"`
	PATCriticals     int `json:"pat_criticals"`
	MachineWarnings  int `json:"machine_warnings"`
	MachineCriticals int `json:"machine_criticals"`
}

var systemTokenExpiryCheckCmd = &cobra.Command{
	Use:   "token-expiry-check",
	Short: "Trigger a PAT and machine-credential expiry notification scan on the connected server",
	Long: `Send immediate expiry notifications for PersonalAccessTokens and
MachineIdentityCredentials approaching their deadline
(POST /api/v1/admin/jobs/token-expiry-check).

Warning notifications are sent for tokens expiring within 7 days; critical
notifications for those expiring within 1 day. Requires system.write.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx := context.Background()
		client, err := apiClientWithSkewCheck(ctx)
		if err != nil {
			return err
		}
		resp, err := client.RunTokenExpiryCheckWithResponse(ctx)
		if err != nil {
			return err
		}
		if resp.StatusCode() != 200 {
			return apiError("run token-expiry check", resp.StatusCode(), resp.Body)
		}
		result, err := decodeData[tokenExpiryCheckResult](resp.Body)
		if err != nil {
			return err
		}
		fmt.Printf("Token expiry check complete: %d PAT warning(s), %d PAT critical(s), %d machine warning(s), %d machine critical(s)\n",
			result.PATWarnings, result.PATCriticals, result.MachineWarnings, result.MachineCriticals)
		return nil
	},
}
