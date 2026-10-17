// notification.go ports `keyorix notification channel` (docs/cli-split-inventory.md §2.5,
// PR 7). Same flags, output, and exit codes as the old CLI's internal/cli/notification
// package -- a pure transport port (REST only, already REST-only in the old CLI too), not a
// behavior change.
package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

var notificationCmd = &cobra.Command{
	Use:   "notification",
	Short: "Manage notifications and notification channels",
}

var notificationChannelCmd = &cobra.Command{
	Use:   "channel",
	Short: "Manage runtime notification channel destinations",
}

func init() {
	notificationChannelCmd.AddCommand(channelListCmd, channelAddCmd, channelGetCmd, channelUpdateCmd, channelDeleteCmd)
	notificationCmd.AddCommand(notificationChannelCmd)
}

type notificationChannelWire struct {
	ID        uint   `json:"id"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	Enabled   bool   `json:"enabled"`
	URL       string `json:"url"`
	Email     string `json:"email"`
	Events    string `json:"events"`
	CreatedBy string `json:"created_by"`
}

type channelListResponse struct {
	Channels []notificationChannelWire `json:"channels"`
}

func listChannels(ctx context.Context, client *apiclient.ClientWithResponses) ([]notificationChannelWire, error) {
	resp, err := client.ListNotificationChannelsWithResponse(ctx)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode() != 200 {
		return nil, apiError("list notification channels", resp.StatusCode(), resp.Body)
	}
	result, err := decodeData[channelListResponse](resp.Body)
	if err != nil {
		return nil, err
	}
	return result.Channels, nil
}

var channelListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all notification channels",
	RunE:  runChannelList,
}

func runChannelList(_ *cobra.Command, _ []string) error {
	if err := checkOutputFormat(channelListFormat); err != nil {
		return err
	}
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	channels, err := listChannels(ctx, client)
	if err != nil {
		return err
	}
	return emitList(channelListFormat, channels, func() error {
		if len(channels) == 0 {
			fmt.Println("No notification channels configured.")
			return nil
		}
		fmt.Printf("%-5s %-24s %-8s %-8s %s\n", "ID", "NAME", "TYPE", "ENABLED", "EVENTS")
		for _, ch := range channels {
			enabled := "no"
			if ch.Enabled {
				enabled = "yes"
			}
			events := ch.Events
			if events == "" {
				events = "*"
			}
			fmt.Printf("%-5d %-24s %-8s %-8s %s\n", ch.ID, ch.Name, ch.Type, enabled, events)
		}
		return nil
	})
}

var (
	channelType   string
	channelURL    string
	channelEmail  string
	channelEvents string
)

var channelAddCmd = &cobra.Command{
	Use:   "add <name>",
	Short: "Add a notification channel",
	Args:  cobra.ExactArgs(1),
	RunE:  runChannelAdd,
}

func init() {
	channelAddCmd.Flags().StringVar(&channelType, "type", "", "Channel type: webhook, slack, teams, or email (required)")
	channelAddCmd.Flags().StringVar(&channelURL, "url", "", "Webhook URL (required for webhook/slack/teams)")
	channelAddCmd.Flags().StringVar(&channelEmail, "email", "", "Email address (required for email type)")
	channelAddCmd.Flags().StringVar(&channelEvents, "events", "", "Comma-separated event types, e.g. secret.rotated,anomaly.detected (empty = all)")
	_ = channelAddCmd.MarkFlagRequired("type")
}

func runChannelAdd(_ *cobra.Command, args []string) error {
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	name := args[0]
	enabled := true
	body := apiclient.CreateNotificationChannelJSONRequestBody{
		Name:    name,
		Type:    channelType,
		Enabled: &enabled,
		Url:     &channelURL,
		Email:   &channelEmail,
		Events:  &channelEvents,
	}
	resp, err := client.CreateNotificationChannelWithResponse(ctx, body)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 201 {
		return apiError("create notification channel", resp.StatusCode(), resp.Body)
	}
	result, err := decodeData[notificationChannelWire](resp.Body)
	if err != nil {
		return err
	}
	fmt.Printf("Notification channel %q (id=%d, type=%s) created.\n", result.Name, result.ID, result.Type)
	return nil
}

var channelGetCmd = &cobra.Command{
	Use:   "get <name>",
	Short: "Get details of a notification channel by name",
	Args:  cobra.ExactArgs(1),
	RunE:  runChannelGet,
}

func runChannelGet(_ *cobra.Command, args []string) error {
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	channels, err := listChannels(ctx, client)
	if err != nil {
		return err
	}
	for _, ch := range channels {
		if strings.EqualFold(ch.Name, args[0]) {
			printChannel(ch)
			return nil
		}
	}
	return fmt.Errorf("notification channel %q not found", args[0])
}

func printChannel(ch notificationChannelWire) {
	enabled := "no"
	if ch.Enabled {
		enabled = "yes"
	}
	events := ch.Events
	if events == "" {
		events = "*"
	}
	fmt.Printf("id:         %d\n", ch.ID)
	fmt.Printf("name:       %s\n", ch.Name)
	fmt.Printf("type:       %s\n", ch.Type)
	fmt.Printf("enabled:    %s\n", enabled)
	if ch.URL != "" {
		fmt.Printf("url:        %s\n", ch.URL)
	}
	if ch.Email != "" {
		fmt.Printf("email:      %s\n", ch.Email)
	}
	fmt.Printf("events:     %s\n", events)
	fmt.Printf("created by: %s\n", ch.CreatedBy)
}

var (
	channelUpdateURL     string
	channelUpdateEmail   string
	channelUpdateEvents  string
	channelUpdateEnable  bool
	channelUpdateDisable bool
)

var channelUpdateCmd = &cobra.Command{
	Use:   "update <name>",
	Short: "Update a notification channel by name",
	Args:  cobra.ExactArgs(1),
	RunE:  runChannelUpdate,
}

func init() {
	channelUpdateCmd.Flags().StringVar(&channelUpdateURL, "url", "", "New webhook URL")
	channelUpdateCmd.Flags().StringVar(&channelUpdateEmail, "email", "", "New email address")
	channelUpdateCmd.Flags().StringVar(&channelUpdateEvents, "events", "", "New event filter (comma-separated)")
	channelUpdateCmd.Flags().BoolVar(&channelUpdateEnable, "enabled", false, "Enable the channel")
	channelUpdateCmd.Flags().BoolVar(&channelUpdateDisable, "disabled", false, "Disable the channel")
}

func resolveChannelID(ctx context.Context, client *apiclient.ClientWithResponses, name string) (uint, error) {
	channels, err := listChannels(ctx, client)
	if err != nil {
		return 0, err
	}
	for _, ch := range channels {
		if strings.EqualFold(ch.Name, name) {
			return ch.ID, nil
		}
	}
	return 0, fmt.Errorf("notification channel %q not found", name)
}

func runChannelUpdate(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	id, err := resolveChannelID(ctx, client, args[0])
	if err != nil {
		return err
	}
	body := apiclient.UpdateNotificationChannelJSONRequestBody{}
	if cmd.Flags().Changed("url") {
		body.Url = &channelUpdateURL
	}
	if cmd.Flags().Changed("email") {
		body.Email = &channelUpdateEmail
	}
	if cmd.Flags().Changed("events") {
		body.Events = &channelUpdateEvents
	}
	if channelUpdateEnable {
		t := true
		body.Enabled = &t
	}
	if channelUpdateDisable {
		f := false
		body.Enabled = &f
	}
	resp, err := client.UpdateNotificationChannelWithResponse(ctx, int(id), body)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		return apiError("update notification channel", resp.StatusCode(), resp.Body)
	}
	result, err := decodeData[notificationChannelWire](resp.Body)
	if err != nil {
		return err
	}
	fmt.Printf("Notification channel %q (id=%d) updated.\n", result.Name, result.ID)
	return nil
}

var channelDeleteConfirm bool

var channelDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete a notification channel by name",
	Args:  cobra.ExactArgs(1),
	RunE:  runChannelDelete,
}

func init() {
	channelDeleteCmd.Flags().BoolVar(&channelDeleteConfirm, "confirm", false, "Confirm deletion without interactive prompt")
}

func runChannelDelete(_ *cobra.Command, args []string) error {
	if !channelDeleteConfirm {
		return fmt.Errorf("add --confirm to confirm deletion of notification channel %q", args[0])
	}
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	id, err := resolveChannelID(ctx, client, args[0])
	if err != nil {
		return err
	}
	resp, err := client.DeleteNotificationChannelWithResponse(ctx, int(id))
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		return apiError("delete notification channel", resp.StatusCode(), resp.Body)
	}
	fmt.Printf("Notification channel %q deleted.\n", args[0])
	return nil
}
