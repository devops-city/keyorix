package cmd

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the configured server, login state, and version-skew check",
	Long: `status is the remote-only successor to the old CLI's "status" command
(docs/cli-split-inventory.md §2.7): it has no local/embedded branch to fall back to (ADR-108
Decision A removes local mode entirely). Unlike the old command, it actually parses GET
/health's response body instead of discarding it, and reports the GET /api/v1/version
skew check.`,
	RunE: runStatus,
}

func runStatus(cmd *cobra.Command, args []string) error {
	store, err := resolveCredStore()
	if err != nil {
		return fmt.Errorf("resolve credential store: %w", err)
	}
	serverURL, token, err := resolveServerAndToken(store)
	if err != nil {
		return err
	}

	fmt.Printf("Server: %s\n", serverURL)
	if token != "" {
		fmt.Println("Logged in: yes")
	} else {
		fmt.Println("Logged in: no (KEYORIX_TOKEN/credentials file has a server but no token)")
	}

	ctx := context.Background()
	client, err := newAPIClient(serverURL, token)
	if err != nil {
		return fmt.Errorf("build client: %w", err)
	}

	healthResp, err := client.HealthCheckWithResponse(ctx)
	if err != nil {
		return fmt.Errorf("contact %s: %w", serverURL, err)
	}
	switch {
	case healthResp.StatusCode() == http.StatusOK && healthResp.JSON200 != nil && healthResp.JSON200.Status != nil:
		fmt.Printf("Health: %s\n", *healthResp.JSON200.Status)
	case healthResp.StatusCode() == http.StatusOK && strings.TrimSpace(string(healthResp.Body)) == "healthy":
		// The bundled web tier (nginx, compose :8088 / Helm web service) answers
		// /health itself with a plain-text "healthy" instead of proxying the
		// backend's JSON. That only proves the proxy is up, so say so; the
		// version check below goes through /api/v1/ and fails if the backend is down.
		fmt.Println("Health: ok (web proxy; backend is verified by the version check below)")
	default:
		fmt.Printf("Health: unreachable or unexpected response (HTTP %d)\n", healthResp.StatusCode())
	}

	skewResult, err := checkVersionSkew(ctx, client)
	if err != nil {
		return fmt.Errorf("version-skew check: %w", err)
	}
	switch {
	case skewResult.Refuse:
		return fmt.Errorf("incompatible with this server: %s", skewResult.Reason)
	case skewResult.Warning != "":
		fmt.Printf("Version: %s\n", skewResult.Warning)
	default:
		fmt.Println("Version: compatible")
	}

	if token != "" {
		profileResp, err := client.GetAuthProfileWithResponse(ctx)
		if err == nil && profileResp.StatusCode() == http.StatusUnauthorized {
			fmt.Println("Warning: stored token was rejected by the server (HTTP 401) -- run \"keyorix login\" again")
		}
	}

	return nil
}
