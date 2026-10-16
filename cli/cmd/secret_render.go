// secret_render.go — keyorix secret render.
package cmd

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
	"github.com/keyorixhq/keyorix/cli/internal/regularfile"
)

var (
	renderProject int
	renderOutput  string
)

var secretRenderCmd = &cobra.Command{
	Use:   "render [template-file]",
	Short: "Render a template, expanding ${secret:<environment>/<name>} references",
	Long: `Render a template file (or stdin) to stdout (or --output), replacing each
${secret:<environment>/<name>} placeholder with that secret's current value.

References are resolved within a single project (--project, a numeric ID). Only
secrets you can read there are resolved; a missing or forbidden reference fails
the render without writing partial output.

Examples:
  keyorix secret render app.env.tpl -o app.env --project 7
  cat app.env.tpl | keyorix secret render --project 7`,
	Args:         cobra.MaximumNArgs(1),
	SilenceUsage: true,
	RunE:         runSecretRender,
}

func runSecretRender(_ *cobra.Command, args []string) error {
	if renderProject == 0 {
		return usageErrorf("--project is required")
	}

	var tmpl []byte
	var err error
	if len(args) == 1 && args[0] != "-" {
		tmpl, err = regularfile.ReadFile("template", args[0])
		if err != nil {
			return fmt.Errorf("read template: %w", err)
		}
	} else {
		tmpl, err = io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("read template from stdin: %w", err)
		}
	}

	client, err := secretAPIClient()
	if err != nil {
		return err
	}
	resp, err := client.RenderSecretTemplateWithResponse(context.Background(), renderProject, apiclient.RenderSecretTemplateJSONRequestBody{
		Template: string(tmpl),
	})
	if err != nil {
		return err
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return httpStatusError("render template", resp.StatusCode(), resp.Body)
	}
	out := derefStr(resp.JSON200.Data.Rendered)

	if renderOutput != "" {
		// #nosec G304 -- operator-provided --output path; SecureCreateFileHandle refuses to
		// write through a symlink at any path component and refuses a pre-existing path.
		f, err := secureCreateOutputFile(renderOutput)
		if err != nil {
			return fmt.Errorf("write output: %w", err)
		}
		_, werr := f.Write([]byte(out))
		cerr := f.Close()
		if werr != nil {
			return fmt.Errorf("write output: %w", werr)
		}
		if cerr != nil {
			return fmt.Errorf("write output: %w", cerr)
		}
		fmt.Printf("Rendered to %s\n", renderOutput)
		return nil
	}
	fmt.Print(out)
	return nil
}

func init() {
	secretRenderCmd.Flags().IntVar(&renderProject, "project", 0, "Project ID (required)")
	secretRenderCmd.Flags().StringVarP(&renderOutput, "output", "o", "", "Write to this file instead of stdout")
	SecretCmd.AddCommand(secretRenderCmd)
}
