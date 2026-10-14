// secret.go ports `keyorix secret` (docs/cli-split-inventory.md §2.1, PR 4):
// core CRUD + metadata for secrets, REST only. Same flags, output, and exit
// codes as the old CLI's internal/cli/secret package's remote-mode branch
// (ADR-108 Decision A removes local mode entirely). Most of this package's
// commands were already remote-only in the old CLI (no embedded fallback to
// strip) -- this is a straightforward retarget onto the generated apiclient.
//
// PR 5 (§7) adds bulk/rotation/export/import/scan/hygiene to the same
// command group.
//
// This is the highest-scrutiny command group in the whole split: secret
// VALUES must never appear in a log line, an argv-visible flag echo, or an
// error message. See secret_test.go's
// TestNoSecretCommandLeaksTheCanaryValue for the standing regression guard.
package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
	"github.com/keyorixhq/keyorix/cli/internal/securefiles"
)

// SecretCmd is the root command for secret operations, exported (matching
// the old CLI's internal/cli/secret.SecretCmd) so sibling files in this
// package can attach their subcommands to it directly.
var SecretCmd = &cobra.Command{
	Use:   "secret",
	Short: "Manage secrets",
	Long:  "Create, read, update, delete, and manage secrets and their metadata; bulk operations, rotation, export/import, and hygiene reports.",
}

func init() {
	rootCmd.AddCommand(SecretCmd)
}

// secretAPIClient resolves the stored credentials and builds a client, the
// shared pre-flight every secret subcommand needs.
func secretAPIClient() (*apiclient.ClientWithResponses, error) {
	store, err := resolveCredStore()
	if err != nil {
		return nil, fmt.Errorf("resolve credential store: %w", err)
	}
	serverURL, token, err := resolveServerAndToken(store)
	if err != nil {
		return nil, err
	}
	return newAPIClient(serverURL, token)
}

// warnInsecureFlag mirrors the old CLI's internal/cli/common.WarnInsecureFlag:
// warns to stderr when a secret-bearing flag was passed on the command line
// (visible to other local users via ps/proc, and saved in shell history). It
// names the FLAG only -- it must never print the flag's value.
func warnInsecureFlag(cmd *cobra.Command, flagName, advice string) {
	if cmd.Flags().Changed(flagName) {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Warning: passing --%s on the command line is insecure (visible to other local users via ps/proc, and saved in shell history); %s\n", flagName, advice)
	}
}

// parseSecretArg parses a positional secret/edge/version ID argument,
// matching the old CLI's internal/cli/secret.parseSecretArg exactly (0 is
// never a valid ID).
func parseSecretArg(s string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid id %q", s)
	}
	return n, nil
}

func derefSecretInt(i *int) int {
	if i == nil {
		return 0
	}
	return *i
}

func derefSecretBool(b *bool) bool {
	if b == nil {
		return false
	}
	return *b
}

// secureCreateOutputFile opens path for a fresh output file (render --output, export
// --output, scan --report). Delegates to securefiles.SecureCreateFileHandle, which
// combines O_EXCL (refuses to write through OR overwrite a pre-existing path,
// including a symlink an attacker with write access to a shared directory planted at
// the target ahead of time) with a per-path-component O_NOFOLLOW walk. path may be an
// arbitrary operator-supplied absolute or relative path, so it's split into
// (baseDir, relPath) the way securefiles expects.
func secureCreateOutputFile(path string) (*os.File, error) {
	return securefiles.SecureCreateFileHandle(filepath.Dir(path), filepath.Base(path), 0o600)
}

// decodeJSONBody unmarshals a raw generated-client response body into v. Used for the
// operations this module's own openapi.yaml filter kept without a response schema
// (listSecrets, createSecret, getSecret — PR 4's job, a sibling independent PR), whose
// generated methods return only a raw []byte body rather than a typed JSON200 field.
func decodeJSONBody(body []byte, v any) error {
	return json.Unmarshal(body, v)
}
