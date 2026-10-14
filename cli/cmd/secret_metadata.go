// secret_metadata.go — keyorix secret info/tags/description/classify: metadata
// commands that never touch the secret value.
package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

// ── info ────────────────────────────────────────────────────────────────────────

var secretInfoID int

var secretInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show a secret's metadata (no value)",
	Long: `Print a one-shot summary of a secret's metadata -- type, classification,
status, description, owner, expiration, and tags -- without retrieving the
value. Requires secrets.read at the secret's scope.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if secretInfoID == 0 {
			return fmt.Errorf("--id is required")
		}
		client, err := secretAPIClient()
		if err != nil {
			return err
		}
		ctx := context.Background()
		f := false
		resp, err := client.GetSecretWithResponse(ctx, secretInfoID, &apiclient.GetSecretParams{IncludeValue: &f})
		if err != nil {
			return err
		}
		if resp.JSON200 == nil || resp.JSON200.Data == nil {
			return httpStatusError("get secret", resp.StatusCode(), resp.Body)
		}
		v := secretGetResultToSecret(resp.JSON200.Data)

		// Tags are a separate endpoint; best-effort (don't fail the summary on it).
		var tags []string
		if tresp, terr := client.GetSecretTagsWithResponse(ctx, secretInfoID); terr == nil && tresp.JSON200 != nil && tresp.JSON200.Data != nil {
			tags = derefStrSlice(tresp.JSON200.Data.Tags)
		}

		line := func(label, val string) {
			if val == "" {
				val = "—"
			}
			fmt.Printf("  %-14s %s\n", label, val)
		}
		fmt.Printf("Secret %d: %s\n", derefSecretInt(v.Id), derefStr(v.Name))
		line("type", derefStr(v.Type))
		line("status", orDefaultSecret(derefStr(v.Status), "active"))
		line("classification", orDefaultSecret(derefStr(v.Classification), "unclassified"))
		line("owner", fmt.Sprintf("user #%d", derefSecretInt(v.OwnerId)))
		line("shared", boolWordSecret(derefSecretBool(v.IsShared)))
		line("created by", derefStr(v.CreatedBy))
		if v.Expiration != nil {
			line("expiration", v.Expiration.Format("2006-01-02T15:04:05Z07:00"))
		} else {
			line("expiration", "")
		}
		if v.LastRotatedAt != nil {
			line("last rotated", v.LastRotatedAt.Format("2006-01-02T15:04:05Z07:00"))
		} else {
			line("last rotated", "")
		}
		line("tags", strings.Join(tags, ", "))
		line("description", derefStr(v.Description))
		return nil
	},
}

func orDefaultSecret(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func boolWordSecret(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func init() {
	secretInfoCmd.Flags().IntVar(&secretInfoID, "id", 0, "Secret ID (required)")
	SecretCmd.AddCommand(secretInfoCmd)
}

// ── tags ────────────────────────────────────────────────────────────────────────

var (
	secretTagsID  int
	secretTagsSet string
)

var secretTagsCmd = &cobra.Command{
	Use:   "tags",
	Short: "List or set a secret's tags",
	Long: `Show a secret's tags, or replace them with --set.

Examples:
  keyorix secret tags --id 42                   # list the secret's tags
  keyorix secret tags --id 42 --set prod,tier1  # replace the tag set
  keyorix secret tags --id 42 --set ""          # clear all tags`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		if secretTagsID == 0 {
			return fmt.Errorf("--id is required")
		}
		client, err := secretAPIClient()
		if err != nil {
			return err
		}
		ctx := context.Background()

		if cmd.Flags().Changed("set") {
			tags := splitSecretTags(secretTagsSet)
			resp, serr := client.SetSecretTagsWithResponse(ctx, secretTagsID, apiclient.SetSecretTagsJSONRequestBody{Tags: tags})
			if serr != nil {
				return serr
			}
			if resp.JSON200 == nil || resp.JSON200.Data == nil {
				return httpStatusError("set secret tags", resp.StatusCode(), resp.Body)
			}
			printSecretTags(derefStrSlice(resp.JSON200.Data.Tags))
			return nil
		}

		resp, err := client.GetSecretTagsWithResponse(ctx, secretTagsID)
		if err != nil {
			return err
		}
		if resp.JSON200 == nil || resp.JSON200.Data == nil {
			return httpStatusError("get secret tags", resp.StatusCode(), resp.Body)
		}
		printSecretTags(derefStrSlice(resp.JSON200.Data.Tags))
		return nil
	},
}

func printSecretTags(tags []string) {
	if len(tags) == 0 {
		fmt.Println("(no tags)")
		return
	}
	fmt.Println(strings.Join(tags, ", "))
}

func splitSecretTags(v string) []string {
	out := []string{}
	for part := range strings.SplitSeq(v, ",") {
		if t := strings.TrimSpace(part); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func init() {
	secretTagsCmd.Flags().IntVar(&secretTagsID, "id", 0, "Secret ID (required)")
	secretTagsCmd.Flags().StringVar(&secretTagsSet, "set", "", "Replace the secret's tags with this comma-separated list (\"\" clears)")
	SecretCmd.AddCommand(secretTagsCmd)
}

// ── description ─────────────────────────────────────────────────────────────────

var (
	secretDescID  int
	secretDescSet string
)

var secretDescriptionCmd = &cobra.Command{
	Use:   "description",
	Short: "Show or set a secret's description",
	Long: `Show a secret's free-text note, or replace it with --set.

Examples:
  keyorix secret description --id 42                       # show the note
  keyorix secret description --id 42 --set "prod DB; dba@" # set the note
  keyorix secret description --id 42 --set ""              # clear it`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		if secretDescID == 0 {
			return fmt.Errorf("--id is required")
		}
		client, err := secretAPIClient()
		if err != nil {
			return err
		}
		ctx := context.Background()

		if cmd.Flags().Changed("set") {
			resp, serr := client.DescribeSecretWithResponse(ctx, secretDescID, apiclient.DescribeSecretJSONRequestBody{Description: &secretDescSet})
			if serr != nil {
				return serr
			}
			if resp.StatusCode() < 200 || resp.StatusCode() >= 300 {
				return httpStatusError("set secret description", resp.StatusCode(), resp.Body)
			}
		}

		f := false
		resp, err := client.GetSecretWithResponse(ctx, secretDescID, &apiclient.GetSecretParams{IncludeValue: &f})
		if err != nil {
			return err
		}
		if resp.JSON200 == nil || resp.JSON200.Data == nil {
			return httpStatusError("get secret", resp.StatusCode(), resp.Body)
		}
		desc := derefStr(resp.JSON200.Data.Description)
		if desc == "" {
			fmt.Println("(no description)")
			return nil
		}
		fmt.Println(desc)
		return nil
	},
}

func init() {
	secretDescriptionCmd.Flags().IntVar(&secretDescID, "id", 0, "Secret ID (required)")
	secretDescriptionCmd.Flags().StringVar(&secretDescSet, "set", "", "Replace the description with this text (\"\" clears)")
	SecretCmd.AddCommand(secretDescriptionCmd)
}

// ── classify ────────────────────────────────────────────────────────────────────

var (
	secretClassifyID    int
	secretClassifyLevel string
)

var secretClassifyCmd = &cobra.Command{
	Use:   "classify",
	Short: "Set a secret's data-classification label (ISO 27001 A.5.12)",
	Long: `Label a secret with its data-sensitivity classification: public, internal,
confidential, or restricted (or empty to clear). Requires secrets.write.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if secretClassifyID == 0 {
			return fmt.Errorf("--id is required")
		}
		switch secretClassifyLevel {
		case "", "public", "internal", "confidential", "restricted":
		default:
			return fmt.Errorf("--level must be public, internal, confidential, restricted, or empty to clear")
		}
		client, err := secretAPIClient()
		if err != nil {
			return err
		}
		body := apiclient.ClassifySecretJSONRequestBody{}
		if secretClassifyLevel != "" {
			body.Classification = &secretClassifyLevel
		}
		resp, err := client.ClassifySecretWithResponse(context.Background(), secretClassifyID, body)
		if err != nil {
			return err
		}
		if resp.StatusCode() < 200 || resp.StatusCode() >= 300 {
			return httpStatusError("classify secret", resp.StatusCode(), resp.Body)
		}
		label := secretClassifyLevel
		if label == "" {
			label = "unclassified"
		}
		fmt.Printf("Secret %d classified as %s.\n", secretClassifyID, label)
		return nil
	},
}

func init() {
	secretClassifyCmd.Flags().IntVar(&secretClassifyID, "id", 0, "Secret ID (required)")
	secretClassifyCmd.Flags().StringVar(&secretClassifyLevel, "level", "", "public|internal|confidential|restricted (empty clears)")
	SecretCmd.AddCommand(secretClassifyCmd)
}
