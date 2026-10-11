// systeminit.go ports the network-bootstrap half of the old CLI's `system init
// --server` (docs/cli-split-inventory.md §2.7 gap, PR 10 leftover): bootstraps a
// running Keyorix server -- creates the admin user, default RBAC roles, and default
// workspace (project + 3 environments) via POST /system/init. Unlike every other
// command in this module, it does not resolve stored credentials first: this IS
// how the first credentials come to exist, and the endpoint itself is
// unauthenticated (gated on the bootstrap token instead of a session/PAT token).
//
// The old CLI's `system init` was dual-mode: local (create config/keys/DB on this
// host) or --server (network bootstrap). Only the network half belongs in this
// network-only CLI -- the local half has no server interaction at all and belongs in
// `keyorix-server admin init` (see system.go's header comment, corrected alongside
// this file to stop implying `system init` doesn't belong here at all).
package cmd

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/oapi-codegen/runtime/types"
	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

var (
	systemInitServer         string
	systemInitAdminUsername  string
	systemInitAdminPassword  string
	systemInitAdminEmail     string
	systemInitBootstrapToken string
)

var systemInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Bootstrap a running Keyorix server (admin user + default workspace)",
	Long: `Bootstrap a running Keyorix server: creates the admin user, default RBAC
roles, and default workspace (project + 3 environments) via POST /system/init.
Safe to run more than once -- idempotent.

This is the network-bootstrap half only. Local host setup (config file, encryption
keys, database) is "keyorix-server admin init", a separate host-filesystem tool this
network-only CLI does not run.

Examples:
  keyorix system init --server http://localhost:8080
  keyorix system init --server https://vault.example.com \
      --admin-username admin --admin-password secret --admin-email admin@example.com`,
	SilenceUsage: true,
	RunE:         runSystemInit,
}

func init() {
	systemInitCmd.Flags().StringVar(&systemInitServer, "server", "", "Server base URL to bootstrap (required)")
	systemInitCmd.Flags().StringVar(&systemInitAdminUsername, "admin-username", "admin", "Admin username to create")
	// No default: a defaulted "admin" password would silently bootstrap a live server
	// with a well-known credential pair, and this command's only feedback is the
	// trailing success banner, printed AFTER the account already exists -- see G76.
	systemInitCmd.Flags().StringVar(&systemInitAdminPassword, "admin-password", "",
		"Admin password (required; INSECURE on the command line -- prefer KEYORIX_ADMIN_PASSWORD, or omit to be prompted)")
	systemInitCmd.Flags().StringVar(&systemInitAdminEmail, "admin-email", "admin@localhost", "Admin email address")
	systemInitCmd.Flags().StringVar(&systemInitBootstrapToken, "bootstrap-token", "",
		"Bootstrap token authorizing first-admin creation (or KEYORIX_BOOTSTRAP_TOKEN; printed in the server log on first boot; INSECURE on the command line)")
	_ = systemInitCmd.MarkFlagRequired("server") // #nosec G104

	systemCmd.AddCommand(systemInitCmd)
}

func runSystemInit(cmd *cobra.Command, _ []string) error {
	server := strings.TrimRight(systemInitServer, "/")
	warnIfInsecureEndpoint(server)

	password, err := resolveSystemInitAdminPassword(cmd)
	if err != nil {
		return err
	}
	token, err := resolveSystemInitBootstrapToken(cmd)
	if err != nil {
		return err
	}

	client, err := newAPIClient(server, "")
	if err != nil {
		return fmt.Errorf("build client for %s: %w", server, err)
	}

	body := apiclient.SystemInitJSONRequestBody{
		Username:    systemInitAdminUsername,
		Email:       types.Email(systemInitAdminEmail),
		Password:    password,
		DisplayName: strPtr("Administrator"),
	}
	if token != "" {
		body.BootstrapToken = strPtr(token)
	}

	ctx := context.Background()
	resp, err := client.SystemInitWithResponse(ctx, body)
	if err != nil {
		return fmt.Errorf("contact %s: %w", server, err)
	}
	if resp.StatusCode() != 200 {
		return apiError("bootstrap server", resp.StatusCode(), resp.Body)
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return fmt.Errorf("unexpected response from %s: HTTP %d", server, resp.StatusCode())
	}
	d := resp.JSON200.Data

	if d.AlreadyInitialized != nil && *d.AlreadyInitialized {
		fmt.Fprintf(os.Stderr, "Server at %s is already initialised.\n", server)
		fmt.Fprintf(os.Stderr, "Use \"keyorix login\" to authenticate.\n")
		return nil
	}

	envList := "development, staging, production"
	if d.Environments != nil && len(*d.Environments) > 0 {
		envList = strings.Join(*d.Environments, ", ")
	}
	project := ""
	if d.Project != nil {
		project = *d.Project
	}
	username := systemInitAdminUsername
	if d.User != nil && d.User.Username != nil && *d.User.Username != "" {
		username = *d.User.Username
	}

	fmt.Printf("Keyorix initialised successfully\n\n")
	fmt.Printf("Your workspace is ready:\n")
	fmt.Printf("  +-- Project: %s\n", project)
	fmt.Printf("  +-- Environments: %s\n", envList)
	fmt.Printf("  +-- Admin user: %s (change password after first login)\n", username)
	fmt.Printf("\nNext steps:\n")
	fmt.Printf("  keyorix login --server %s\n", server)
	fmt.Printf("  keyorix secret create --name my-first-secret --value \"hello\"\n")
	return nil
}

// resolveSystemInitAdminPassword resolves the admin password in order of
// preference: the (insecure, warned) --admin-password flag, then
// KEYORIX_ADMIN_PASSWORD, then an interactive no-echo prompt (login.go's
// promptPassword). Mirrors resolveAdminPassword from the old CLI's
// internal/cli/system/init.go.
func resolveSystemInitAdminPassword(cmd *cobra.Command) (string, error) {
	if systemInitAdminPassword != "" {
		warnInsecureFlag(cmd, "admin-password", "prefer the KEYORIX_ADMIN_PASSWORD environment variable, or omit it to be prompted.")
		return systemInitAdminPassword, nil
	}
	// KEYORIX_ADMIN_PASSWORD_FILE is accepted too; both set, an unreadable file or
	// a file with loose permissions is an error, never a silent prompt/fallback.
	p, found, err := lookupSecretEnv("KEYORIX_ADMIN_PASSWORD")
	if err != nil {
		return "", err
	}
	if found {
		return p, nil
	}
	p, err = promptPassword("Enter admin password for the new account: ")
	if err != nil {
		return "", fmt.Errorf("read admin password: %w", err)
	}
	if p == "" {
		return "", fmt.Errorf("admin password is required to bootstrap a server (--admin-password, KEYORIX_ADMIN_PASSWORD, or enter one at the prompt)")
	}
	return p, nil
}

// resolveSystemInitBootstrapToken resolves the bootstrap token: the (insecure,
// warned) --bootstrap-token flag, else KEYORIX_BOOTSTRAP_TOKEN. Never logged,
// echoed, or included in any error message -- it is as sensitive as the admin
// password this same request carries.
func resolveSystemInitBootstrapToken(cmd *cobra.Command) (string, error) {
	if systemInitBootstrapToken != "" {
		warnInsecureFlag(cmd, "bootstrap-token", "prefer the KEYORIX_BOOTSTRAP_TOKEN environment variable.")
		return systemInitBootstrapToken, nil
	}
	// KEYORIX_BOOTSTRAP_TOKEN_FILE is accepted too (both set, unreadable or too
	// open is an error).
	v, _, err := lookupSecretEnv("KEYORIX_BOOTSTRAP_TOKEN")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(v), nil
}

// warnIfInsecureEndpoint warns before this command's admin credentials and
// bootstrap token are sent to a non-HTTPS, non-loopback endpoint, where they
// would leave the machine in cleartext, MITM-capturable. Mirrors the old CLI's
// internal/cli/common.WarnIfInsecureEndpoint/endpointIsSecure.
func warnIfInsecureEndpoint(endpoint string) {
	if endpoint == "" || endpointIsSecure(endpoint) {
		return
	}
	fmt.Fprintf(os.Stderr, "WARNING: server %q is not HTTPS -- the admin password and bootstrap token are sent in cleartext and MITM-capturable.\n", endpoint)
}

func endpointIsSecure(endpoint string) bool {
	u, err := url.Parse(endpoint)
	if err != nil {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	host := u.Hostname()
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func strPtr(s string) *string { return &s }
