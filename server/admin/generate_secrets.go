package admin

// generate_secrets.go -- `keyorix-server admin generate-secrets`: the three
// secrets a bare-metal install needs before the server first starts (master
// passphrase, bootstrap token, first-admin password), generated into 0600
// files so that nobody -- an operator's terminal scrollback, a shell history,
// or an AI assistant driving the install (INSTALL-WITH-AI.md) -- ever sees a
// value. Every consumer reads them by path through the X_FILE convention
// (internal/secretenv): KEYORIX_MASTER_PASSWORD_FILE, KEYORIX_BOOTSTRAP_TOKEN_FILE,
// KEYORIX_ADMIN_PASSWORD_FILE.
//
// The compose stack has scripts/selfhost/init-secrets.sh for the same job, but
// it writes 0640 group-readable files for Docker's bind mounts, which the
// master-passphrase reader (secretenv.LookupChecked) refuses for a file the
// running user owns. This is the host-install counterpart.
//
// Rules: a file that exists is never overwritten (a new master passphrase
// would make every stored secret undecryptable); values are never printed,
// logged or put in an error; nothing here touches the config or database.

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	"github.com/keyorixhq/keyorix/internal/core/rules"
	"github.com/keyorixhq/keyorix/internal/secretenv"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
)

// installSecretBytes of randomness per generated value (base64url, 43 chars).
const installSecretBytes = 32

// adminPasswordClassSuffix guarantees every character class the default
// password policy (ADR-025) requires, whatever the random part contains.
const adminPasswordClassSuffix = "-Aa1"

type installSecret struct {
	file   string // file name inside --dir
	envVar string // the variable whose _FILE form reads it
	gen    func() (string, error)
}

var installSecrets = []installSecret{
	{"master_password", "KEYORIX_MASTER_PASSWORD", randomInstallToken},
	{"bootstrap_token", "KEYORIX_BOOTSTRAP_TOKEN", randomInstallToken},
	{"admin_password", "KEYORIX_ADMIN_PASSWORD", randomAdminPassword},
}

var generateSecretsDir string

var generateSecretsCmd = &cobra.Command{
	Use:   "generate-secrets",
	Short: "Create the install secrets (master passphrase, bootstrap token, first-admin password) as 0600 files",
	Long: `Creates, in --dir (default ./secrets, mode 0700), each only if it does not exist:

  master_password   the passphrase the encryption KEK is derived from
  bootstrap_token   the one-time token that gates the first-admin bootstrap
  admin_password    the first admin's password (meets the default password policy)

Each file is mode 0600. No value is ever printed: the command prints the paths
and the KEYORIX_*_FILE variables that read them, which every keyorix-server and
keyorix command accepts in place of the value. An existing file is kept, never
overwritten -- a new master passphrase would make every stored secret
undecryptable -- so the command is safe to run again.

Back up master_password offline and away from keys/ and the database: losing
it makes every stored secret undecryptable.`,
	Args: cobra.NoArgs,
	RunE: runGenerateSecrets,
}

func init() {
	generateSecretsCmd.Flags().StringVar(&generateSecretsDir, "dir", "secrets", "Directory to create the secret files in (created 0700 if missing)")
	rootCmd.AddCommand(generateSecretsCmd)
}

func runGenerateSecrets(cmd *cobra.Command, args []string) error {
	if generateSecretsDir == "" {
		return fmt.Errorf("--dir must not be empty")
	}
	absDir, err := filepath.Abs(generateSecretsDir)
	if err != nil {
		return fmt.Errorf("resolve --dir: %w", err)
	}
	out := cmd.OutOrStdout()
	_, _ = fmt.Fprintf(out, "Install secrets in %s (values are never printed):\n", absDir)
	for _, s := range installSecrets {
		path := filepath.Join(generateSecretsDir, s.file)
		absPath := filepath.Join(absDir, s.file)
		exists, err := fileExists(path)
		if err != nil {
			return fmt.Errorf("check %s: %w", absPath, err)
		}
		if exists {
			// A kept file must still be usable: the readers refuse a key-material
			// file that is not 0600/0400, so say so now rather than at first start.
			if err := secretenv.CheckPermissions(path); err != nil {
				return fmt.Errorf("existing %s cannot be used (%w); fix its mode (chmod 600) or move it away", absPath, err)
			}
			_, _ = fmt.Fprintf(out, "  kept     %s (already exists; not overwritten)\n", absPath)
			continue
		}
		v, err := s.gen()
		if err != nil {
			return fmt.Errorf("generate %s: %w", s.file, err)
		}
		if err := createPrivateFile(path, []byte(v+"\n")); err != nil {
			return fmt.Errorf("write %s: %w", absPath, err)
		}
		_, _ = fmt.Fprintf(out, "  created  %s (0600)\n", absPath)
	}
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintln(out, "Pass them by path, never by value:")
	for _, s := range installSecrets {
		_, _ = fmt.Fprintf(out, "  export %s%s=%s\n", s.envVar, secretenv.FileSuffix, filepath.Join(absDir, s.file))
	}
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintln(out, "Back up master_password offline, away from keys/ and the database: losing it makes every stored secret undecryptable.")
	return nil
}

func randomInstallToken() (string, error) {
	raw := make([]byte, installSecretBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// adminPasswordAttempts bounds the retries for a random password that happens to
// embed the admin's username (about one in a million for "admin").
const adminPasswordAttempts = 20

func randomAdminPassword() (string, error) {
	// The first admin's identity is the one the entrypoint bootstraps with
	// (KEYORIX_ADMIN_USERNAME / _EMAIL, "Administrator"); a random password that
	// embeds it is regenerated rather than left to fail the bootstrap (#3201).
	user := &models.User{
		Username:    envOr("KEYORIX_ADMIN_USERNAME", "admin"),
		Email:       envOr("KEYORIX_ADMIN_EMAIL", "admin@keyorix.local"),
		DisplayName: "Administrator",
	}
	policy := rules.DefaultPasswordPolicy()
	var lastErr error
	for i := 0; i < adminPasswordAttempts; i++ {
		tok, err := randomInstallToken()
		if err != nil {
			return "", err
		}
		pw := tok + adminPasswordClassSuffix
		if lastErr = policy.Validate(pw, user); lastErr == nil {
			return pw, nil
		}
	}
	return "", fmt.Errorf("generated admin password does not meet the default policy: %w", lastErr)
}

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}
