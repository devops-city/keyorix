// secret_templates.go — keyorix secret template list/get/create/delete.
package cmd

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

var secretTemplateCmd = &cobra.Command{
	Use:   "template",
	Short: "Manage secret templates",
	Long:  "Commands for creating, listing, getting and deleting reusable secret templates.",
}

func init() {
	SecretCmd.AddCommand(secretTemplateCmd)
}

var secretTemplateListCmd = &cobra.Command{
	Use:          "list",
	Short:        "List all secret templates",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		client, err := secretAPIClient()
		if err != nil {
			return err
		}
		resp, err := client.ListSecretTemplatesWithResponse(context.Background())
		if err != nil {
			return fmt.Errorf("list templates: %w", err)
		}
		if resp.JSON200 == nil || resp.JSON200.Data == nil {
			return httpStatusError("list templates", resp.StatusCode(), resp.Body)
		}
		templates := derefSecretTemplateSlice(resp.JSON200.Data.Templates)
		if len(templates) == 0 {
			fmt.Println("No templates found.")
			return nil
		}
		for _, t := range templates {
			fmt.Printf("%-4d  %-30s  %s\n", derefSecretInt(t.Id), derefStr(t.Name), derefStr(t.Description))
		}
		return nil
	},
}

var secretTemplateGetCmd = &cobra.Command{
	Use:          "get <name>",
	Short:        "Get a secret template by name",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := secretAPIClient()
		if err != nil {
			return err
		}
		resp, err := client.ListSecretTemplatesWithResponse(context.Background())
		if err != nil {
			return fmt.Errorf("get template: %w", err)
		}
		if resp.JSON200 == nil || resp.JSON200.Data == nil {
			return httpStatusError("get template", resp.StatusCode(), resp.Body)
		}
		for _, t := range derefSecretTemplateSlice(resp.JSON200.Data.Templates) {
			if derefStr(t.Name) == args[0] {
				out, merr := json.MarshalIndent(t, "", "  ")
				if merr != nil {
					return fmt.Errorf("marshal template: %w", merr)
				}
				fmt.Println(string(out))
				return nil
			}
		}
		return fmt.Errorf("template %q not found", args[0])
	},
}

var (
	secretTmplName           string
	secretTmplClassification string
	secretTmplTags           string
	secretTmplDescription    string
	secretTmplDescPattern    string
	secretTmplRotationDays   int
)

var secretTemplateCreateCmd = &cobra.Command{
	Use:          "create",
	Short:        "Create a secret template",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		if secretTmplName == "" {
			return usageErrorf("--name is required")
		}
		client, err := secretAPIClient()
		if err != nil {
			return err
		}
		body := apiclient.CreateSecretTemplateJSONRequestBody{Name: secretTmplName}
		if secretTmplClassification != "" {
			body.DefaultClassification = &secretTmplClassification
		}
		if secretTmplTags != "" {
			body.DefaultTags = &secretTmplTags
		}
		if secretTmplDescription != "" {
			body.Description = &secretTmplDescription
		}
		if secretTmplDescPattern != "" {
			body.DescriptionPattern = &secretTmplDescPattern
		}
		if secretTmplRotationDays != 0 {
			body.RotationHintDays = &secretTmplRotationDays
		}
		resp, err := client.CreateSecretTemplateWithResponse(context.Background(), body)
		if err != nil {
			return fmt.Errorf("create template: %w", err)
		}
		if resp.JSON200 == nil || resp.JSON200.Data == nil {
			return httpStatusError("create template", resp.StatusCode(), resp.Body)
		}
		fmt.Printf("Template %q created (ID %d).\n", derefStr(resp.JSON200.Data.Name), derefSecretInt(resp.JSON200.Data.Id))
		return nil
	},
}

var secretTemplateDeleteCmd = &cobra.Command{
	Use:          "delete <name>",
	Short:        "Delete a secret template by name",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := secretAPIClient()
		if err != nil {
			return err
		}
		ctx := context.Background()
		resp, err := client.ListSecretTemplatesWithResponse(ctx)
		if err != nil {
			return fmt.Errorf("list templates: %w", err)
		}
		if resp.JSON200 == nil || resp.JSON200.Data == nil {
			return httpStatusError("list templates", resp.StatusCode(), resp.Body)
		}
		var id int
		for _, t := range derefSecretTemplateSlice(resp.JSON200.Data.Templates) {
			if derefStr(t.Name) == args[0] {
				id = derefSecretInt(t.Id)
				break
			}
		}
		if id == 0 {
			return fmt.Errorf("template %q not found", args[0])
		}
		dresp, err := client.DeleteSecretTemplateWithResponse(ctx, id)
		if err != nil {
			return fmt.Errorf("delete template: %w", err)
		}
		if dresp.StatusCode() != 204 {
			return httpStatusError("delete template", dresp.StatusCode(), dresp.Body)
		}
		fmt.Printf("Template %q deleted.\n", args[0])
		return nil
	},
}

func derefSecretTemplateSlice(s *[]apiclient.SecretTemplate) []apiclient.SecretTemplate {
	if s == nil {
		return nil
	}
	return *s
}

func init() {
	secretTemplateCreateCmd.Flags().StringVar(&secretTmplName, "name", "", "Template name (required)")
	secretTemplateCreateCmd.Flags().StringVar(&secretTmplClassification, "classification", "", "Default classification (public|internal|confidential|restricted)")
	secretTemplateCreateCmd.Flags().StringVar(&secretTmplTags, "tags", "", "Default tags (comma-separated, e.g. db,prod)")
	secretTemplateCreateCmd.Flags().StringVar(&secretTmplDescription, "description", "", "Template description")
	secretTemplateCreateCmd.Flags().StringVar(&secretTmplDescPattern, "description-pattern", "", "Hint text for the description field")
	secretTemplateCreateCmd.Flags().IntVar(&secretTmplRotationDays, "rotation-hint-days", 0, "Suggested rotation interval in days (informational)")

	secretTemplateCmd.AddCommand(secretTemplateListCmd, secretTemplateGetCmd, secretTemplateCreateCmd, secretTemplateDeleteCmd)
}
