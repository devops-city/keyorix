// secret_access.go — keyorix secret access / access-log.
package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

var secretAccessID int

var secretAccessCmd = &cobra.Command{
	Use:   "access",
	Short: "List who can access a secret and at what effective level",
	Long: `Show the effective access list for a secret: every user who can read it, with
their EFFECTIVE permission (for a project member, the higher of their role and any
active share), the grant that gives it (SOURCE), and every grant they hold (GRANTS),
so a share that elevates a role is visible. Expired shares and shares to users who
are not project members grant nothing and are not listed. Global admins have
implicit access and are not listed. Requires secrets.read.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if secretAccessID == 0 {
			return usageErrorf("--id is required")
		}
		client, err := secretAPIClient()
		if err != nil {
			return err
		}
		resp, err := client.ListAccessorsWithResponse(context.Background(), secretAccessID)
		if err != nil {
			return err
		}
		if resp.JSON200 == nil || resp.JSON200.Data == nil {
			return httpStatusError("list accessors", resp.StatusCode(), resp.Body)
		}
		data := resp.JSON200.Data
		rows := derefSecretAccessorSlice(data.Accessors)
		if len(rows) == 0 {
			fmt.Println("No accessors.")
		} else {
			fmt.Printf("%-24s %-10s %-24s %s\n", "USER", "PERMISSION", "SOURCE", "GRANTS")
			for _, r := range rows {
				grants := "-"
				if r.Grants != nil && len(*r.Grants) > 0 {
					grants = strings.Join(*r.Grants, ", ")
				}
				fmt.Printf("%-24s %-10s %-24s %s\n", derefStr(r.Username), derefStr(r.Permission), derefStr(r.Source), grants)
			}
		}
		printAccessListDegraded(data.Degraded, data.DegradedReasons)
		return nil
	},
}

// printAccessListDegraded warns that the list is incomplete (an under-count: part of it
// was withheld from this caller, or a lookup failed), with the server's reasons, so a
// shortened list is never read as the full set of accessors.
func printAccessListDegraded(degraded *bool, reasons *[]string) {
	if degraded == nil || !*degraded {
		return
	}
	fmt.Println()
	fmt.Println("WARNING: this list is incomplete; more users may have access than are shown.")
	if reasons != nil {
		for _, r := range *reasons {
			fmt.Printf("  - %s\n", r)
		}
	}
}

var (
	secretAccessLogID   int
	secretAccessLogDays int
)

var secretAccessLogCmd = &cobra.Command{
	Use:          "access-log",
	Short:        "Show a secret's recent reads (who/when/from where)",
	Long:         "List the recent access-log entries for a secret. Requires secrets.read.",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if secretAccessLogID == 0 {
			return usageErrorf("--id is required")
		}
		client, err := secretAPIClient()
		if err != nil {
			return err
		}
		var params *apiclient.GetSecretAccessLogParams
		if secretAccessLogDays > 0 {
			params = &apiclient.GetSecretAccessLogParams{Days: &secretAccessLogDays}
		}
		resp, err := client.GetSecretAccessLogWithResponse(context.Background(), secretAccessLogID, params)
		if err != nil {
			return err
		}
		if resp.JSON200 == nil || resp.JSON200.Data == nil {
			return httpStatusError("get secret access log", resp.StatusCode(), resp.Body)
		}
		rows := derefSecretAccessLogSlice(resp.JSON200.Data.AccessLog)
		if len(rows) == 0 {
			fmt.Println("No reads in the window.")
			return nil
		}
		fmt.Printf("%-24s %-8s %-18s %s\n", "ACCESSED BY", "ACTION", "IP", "TIME")
		for _, r := range rows {
			// IpAddress is present only for a caller who separately holds audit.read
			// (server/http/handlers/secrets_access_history.go) -- derefStr renders
			// the common case (an ordinary secrets.read caller) as a blank column,
			// not an error.
			fmt.Printf("%-24s %-8s %-18s %s\n", derefStr(r.AccessedBy), derefStr(r.Action), derefStr(r.IpAddress), derefTimeRFC3339(r.AccessTime))
		}
		return nil
	},
}

func derefSecretAccessorSlice(s *[]apiclient.SecretAccessor) []apiclient.SecretAccessor {
	if s == nil {
		return nil
	}
	return *s
}

func derefSecretAccessLogSlice(s *[]apiclient.SecretAccessLogEntry) []apiclient.SecretAccessLogEntry {
	if s == nil {
		return nil
	}
	return *s
}

func derefTimeRFC3339(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format(time.RFC3339)
}

func init() {
	secretAccessCmd.Flags().IntVar(&secretAccessID, "id", 0, "Secret ID (required)")
	secretAccessLogCmd.Flags().IntVar(&secretAccessLogID, "id", 0, "Secret ID (required)")
	secretAccessLogCmd.Flags().IntVar(&secretAccessLogDays, "days", 0, "Lookback in days (default server-side: 30)")
	SecretCmd.AddCommand(secretAccessCmd)
	SecretCmd.AddCommand(secretAccessLogCmd)
}
