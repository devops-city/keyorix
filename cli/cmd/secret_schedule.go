// secret_schedule.go — keyorix secret set-schedule/get-schedule/clear-schedule:
// manage per-secret temporal access policies.
//
// Day names ("mon", "tue", ..., "sun") are converted to ISO weekday numbers
// before being sent; integers ("1"-"7") are passed through as-is.
package cmd

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

var secretDayNameToISO = map[string]int{
	"mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6, "sun": 7,
}

func convertSecretDayNames(days string) (string, error) {
	if days == "*" {
		return "*", nil
	}
	var parts []string
	for raw := range strings.SplitSeq(days, ",") {
		s := strings.TrimSpace(strings.ToLower(raw))
		if iso, ok := secretDayNameToISO[s]; ok {
			parts = append(parts, strconv.Itoa(iso))
			continue
		}
		d, err := strconv.Atoi(s)
		if err != nil || d < 1 || d > 7 {
			return "", fmt.Errorf("invalid day %q: must be mon-sun or 1-7 (or \"*\")", raw)
		}
		parts = append(parts, strconv.Itoa(d))
	}
	return strings.Join(parts, ","), nil
}

var (
	secretSchedDays      string
	secretSchedStartHour int
	secretSchedEndHour   int
	secretSchedTimezone  string
)

var secretSetScheduleCmd = &cobra.Command{
	Use:   "set-schedule <secret-id>",
	Short: "Set a temporal access schedule for a secret",
	Long: `Restrict read access to a secret to a specific day-of-week + hour window.

The schedule applies to all permission-checked reads (human users); admin/
machine reads bypass it.`,
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := parseSecretArg(args[0])
		if err != nil {
			return err
		}
		isoDays, err := convertSecretDayNames(secretSchedDays)
		if err != nil {
			return err
		}
		tz := secretSchedTimezone
		if tz == "" {
			tz = "UTC"
		}
		client, err := secretAPIClient()
		if err != nil {
			return err
		}
		resp, err := client.SetSecretScheduleWithResponse(context.Background(), id, apiclient.SetSecretScheduleJSONRequestBody{
			AllowedDays: isoDays, StartHour: secretSchedStartHour, EndHour: secretSchedEndHour, Timezone: &tz,
		})
		if err != nil {
			return err
		}
		if resp.JSON200 == nil || resp.JSON200.Data == nil {
			return httpStatusError("set secret schedule", resp.StatusCode(), resp.Body)
		}
		out := resp.JSON200.Data
		fmt.Printf("Schedule set: secret %d is readable on days %q, %02d:00-%02d:00 %s\n",
			id, derefStr(out.AllowedDays), derefSecretInt(out.StartHour), derefSecretInt(out.EndHour), derefStr(out.Timezone))
		return nil
	},
}

var secretGetScheduleCmd = &cobra.Command{
	Use:          "get-schedule <secret-id>",
	Short:        "Show the temporal access schedule for a secret",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, args []string) error {
		id, err := parseSecretArg(args[0])
		if err != nil {
			return err
		}
		client, err := secretAPIClient()
		if err != nil {
			return err
		}
		resp, err := client.GetSecretScheduleWithResponse(context.Background(), id)
		if err != nil {
			return err
		}
		if resp.JSON200 == nil || resp.JSON200.Data == nil {
			return httpStatusError("get secret schedule", resp.StatusCode(), resp.Body)
		}
		out := resp.JSON200.Data
		fmt.Printf("Secret %d schedule:\n", id)
		fmt.Printf("  Days:       %s\n", derefStr(out.AllowedDays))
		fmt.Printf("  Start hour: %d:00\n", derefSecretInt(out.StartHour))
		fmt.Printf("  End hour:   %d:00\n", derefSecretInt(out.EndHour))
		fmt.Printf("  Timezone:   %s\n", derefStr(out.Timezone))
		return nil
	},
}

var secretClearScheduleCmd = &cobra.Command{
	Use:          "clear-schedule <secret-id>",
	Short:        "Remove the temporal access schedule for a secret (idempotent)",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, args []string) error {
		id, err := parseSecretArg(args[0])
		if err != nil {
			return err
		}
		client, err := secretAPIClient()
		if err != nil {
			return err
		}
		resp, err := client.DeleteSecretScheduleWithResponse(context.Background(), id)
		if err != nil {
			return err
		}
		// The server answers 200 with a {deleted:true} envelope (#3173); 204 is
		// accepted too, so a proxy or a future server that sends no body still works.
		if sc := resp.StatusCode(); sc != http.StatusOK && sc != http.StatusNoContent {
			return httpStatusError("clear secret schedule", resp.StatusCode(), resp.Body)
		}
		fmt.Printf("Schedule cleared for secret %d.\n", id)
		return nil
	},
}

func init() {
	secretSetScheduleCmd.Flags().StringVar(&secretSchedDays, "days", "", "Allowed days: comma-separated day names (mon,tue,...) or ISO numbers (1-7), or \"*\" for all days (required)")
	secretSetScheduleCmd.Flags().IntVar(&secretSchedStartHour, "start-hour", 0, "Start hour of the read window (0-23, inclusive)")
	secretSetScheduleCmd.Flags().IntVar(&secretSchedEndHour, "end-hour", 24, "End hour of the read window (1-24, exclusive)")
	secretSetScheduleCmd.Flags().StringVar(&secretSchedTimezone, "timezone", "UTC", "IANA timezone name (default: UTC)")
	_ = secretSetScheduleCmd.MarkFlagRequired("days")

	SecretCmd.AddCommand(secretSetScheduleCmd, secretGetScheduleCmd, secretClearScheduleCmd)
}
