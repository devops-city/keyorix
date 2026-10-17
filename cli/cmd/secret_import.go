// secret_import.go — keyorix secret import (file mode only).
//
// Live-source modes (--source vault/aws/azure/gcp) are intentionally NOT ported here:
// they read live cloud/Vault credentials locally via cloud SDKs, which is in direct
// tension with ADR-108's goal of a thin CLI whose SBOM lists no cloud SDKs. Decision
// (docs/cli-split-inventory.md §7, PR 5): moved out, not dropped — those modes stay on
// the old CLI until a separate migration tool (working name keyorix-migrate) replaces
// them; the old CLI's deletion is gated on that tool existing.
package cmd

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
	"github.com/keyorixhq/keyorix/cli/internal/cliout"
	"github.com/keyorixhq/keyorix/cli/internal/regularfile"
)

var (
	importFile         string
	importFormat       string
	importProject      int
	importEnv          int
	importDryRun       bool
	importSkipExisting bool
	importDecryptWith  string
)

var secretImportCmd = &cobra.Command{
	Use:   "import",
	Short: "Import secrets from a file",
	Long: `Import secrets from a local file.

  keyorix secret import --file .env --format dotenv --project 7 --env 3
  keyorix secret import --file vault-export.yaml --format vault --project 7 --env 3
  keyorix secret import --file secrets.json --format json --project 7 --env 3
  keyorix secret import --file .env --format dotenv --project 7 --env 3 --dry-run
  keyorix secret import --file secrets.enc.json --decrypt-with private.pem --project 7 --env 3

Supported file formats (--format):
  dotenv  .env files (KEY=VALUE, comments and blank lines ignored)
  vault   Medusa/Vault YAML export (path hierarchy, last two segments become name)
  json    Flat key-value JSON object

Encrypted imports (--decrypt-with):
  When the file is a keyorix-encrypted-export-v1 envelope (produced by
  'keyorix secret export --format encrypted-json'), pass the RSA private key
  with --decrypt-with. The file is decrypted transparently and then imported
  as a standard JSON payload.

Importing from a live source (Vault/AWS/Azure/GCP) is not supported by this command —
use the old CLI's 'secret import --source' until the dedicated migration tool exists.`,
	SilenceUsage: true,
	RunE:         runSecretImport,
}

// secretEntry is a parsed key/value pair ready to be created.
type secretEntry struct {
	Name  string
	Value string
}

func runSecretImport(cmd *cobra.Command, _ []string) error {
	if importFile == "" {
		return usageErrorf("--file is required (this command only supports file-mode import — see --help)")
	}
	if importProject == 0 || importEnv == 0 {
		return usageErrorf("--project and --env are both required")
	}

	entries, err := collectImportEntries()
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		fmt.Println("No secrets found.")
		return nil
	}

	if importDryRun {
		fmt.Printf("Dry run — would import %d secret(s):\n\n", len(entries))
		for _, e := range entries {
			// #G58: a dry run must never put real secret bytes on the operator's terminal
			// (scrollback, tmux/screen logging, screen share) — show only the length.
			fmt.Printf("  %-30s = <%d bytes>\n", cliout.SanitizeForTerminal(e.Name), len(e.Value))
		}
		fmt.Printf("\nNo changes made (--dry-run).\n")
		return nil
	}

	client, err := secretAPIClient()
	if err != nil {
		return err
	}
	return doSecretImport(context.Background(), client, entries)
}

// collectImportEntries reads and parses --file, transparently decrypting first when
// --decrypt-with is set and the file looks like an encrypted-json envelope.
func collectImportEntries() ([]secretEntry, error) {
	clean := filepath.Clean(importFile)
	if _, err := os.Stat(clean); err != nil {
		return nil, fmt.Errorf("cannot open file %q: %w", importFile, err)
	}
	if importDecryptWith != "" {
		fileBytes, err := regularfile.ReadFile("import file", clean)
		if err != nil {
			return nil, fmt.Errorf("read file %q: %w", clean, err)
		}
		if bytes.HasPrefix(bytes.TrimSpace(fileBytes), []byte(`{"format":"`+encryptedExportFormat)) {
			plain, err := decryptExport(fileBytes, importDecryptWith)
			if err != nil {
				return nil, fmt.Errorf("decrypt %q: %w", clean, err)
			}
			return parseJSONBytes(plain)
		}
	}
	entries, err := parseImportFile(clean, importFormat)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s file: %w", importFormat, err)
	}
	return entries, nil
}

func doSecretImport(ctx context.Context, client *apiclient.ClientWithResponses, entries []secretEntry) error {
	imported, skipped, failed := 0, 0, 0

	for _, e := range entries {
		displayName := cliout.SanitizeForTerminal(e.Name)
		body := apiclient.CreateSecretJSONRequestBody{
			Name:          e.Name,
			Value:         e.Value,
			Type:          "generic",
			ProjectId:     &importProject,
			EnvironmentId: importEnv,
		}
		resp, err := client.CreateSecretWithResponse(ctx, body)
		if err != nil {
			fmt.Printf("  x Failed   %-30s %v\n", displayName, err)
			failed++
			continue
		}
		if resp.StatusCode() != 201 {
			if importSkipExisting && resp.StatusCode() == 409 {
				fmt.Printf("  - Skipped  %-30s (already exists)\n", displayName)
				skipped++
				continue
			}
			fmt.Printf("  x Failed   %-30s HTTP %d\n", displayName, resp.StatusCode())
			failed++
			continue
		}
		var created struct {
			Data struct {
				ID int `json:"ID"`
			} `json:"data"`
		}
		_ = decodeJSONBody(resp.Body, &created)
		fmt.Printf("  + Imported %-30s (id=%d)\n", displayName, created.Data.ID)
		imported++
	}

	total := imported + skipped + failed
	fmt.Printf("\nImported %d/%d secrets", imported, total)
	if skipped > 0 {
		fmt.Printf(", %d skipped", skipped)
	}
	if failed > 0 {
		fmt.Printf(", %d failed", failed)
	}
	fmt.Println()

	if failed > 0 {
		return fmt.Errorf("%d secret(s) failed to import", failed)
	}
	return nil
}

func init() {
	secretImportCmd.Flags().StringVar(&importFile, "file", "", "Path to the file to import (required)")
	secretImportCmd.Flags().StringVar(&importFormat, "format", "dotenv", "File format: dotenv, vault, json")
	secretImportCmd.Flags().IntVar(&importProject, "project", 0, "Project ID (required)")
	secretImportCmd.Flags().IntVar(&importEnv, "env", 0, "Environment ID (required)")
	secretImportCmd.Flags().BoolVar(&importDryRun, "dry-run", false, "Show what would be imported without creating anything")
	secretImportCmd.Flags().BoolVar(&importSkipExisting, "skip-existing", true, "Skip secrets that already exist instead of failing")
	secretImportCmd.Flags().StringVar(&importDecryptWith, "decrypt-with", "", "Path to RSA private key PEM to decrypt an encrypted-json export")
	SecretCmd.AddCommand(secretImportCmd)
}
