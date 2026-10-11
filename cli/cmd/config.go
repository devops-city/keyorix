package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
	"github.com/keyorixhq/keyorix/cli/internal/credstore"
)

// configKeyCAFile is the only setting `keyorix config` manages today. It lives in the one
// credentials file (credstore: "one storage mechanism only"), not a second config file.
const configKeyCAFile = "ca_file"

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Show or change CLI settings stored with your credentials",
	Long: `config reads and writes CLI settings kept in the credentials file (see "keyorix status --help").

Keys:
  ca_file   PEM CA/certificate file trusted for the server's TLS certificate, instead of
            the system roots. "keyorix-server admin init" prints the path of the certificate
            it generates. --ca-file and KEYORIX_CA_FILE override it for one command.`,
}

var configSetCmd = &cobra.Command{
	Use:   "set <key> <value>",
	Short: "Set a CLI setting (key: ca_file)",
	Args:  cobra.ExactArgs(2),
	RunE:  runConfigSet,
}

var configGetCmd = &cobra.Command{
	Use:   "get <key>",
	Short: "Show the effective value of a CLI setting and where it comes from (key: ca_file)",
	Args:  cobra.ExactArgs(1),
	RunE:  runConfigGet,
}

var configUnsetCmd = &cobra.Command{
	Use:   "unset <key>",
	Short: "Remove a stored CLI setting (key: ca_file)",
	Args:  cobra.ExactArgs(1),
	RunE:  runConfigUnset,
}

func init() {
	configCmd.AddCommand(configSetCmd, configGetCmd, configUnsetCmd)
}

func requireConfigKey(key string) error {
	if key != configKeyCAFile {
		return fmt.Errorf("unknown setting %q (known: %s)", key, configKeyCAFile)
	}
	return nil
}

// updateStoredCredentials loads the credentials file, applies change and saves it. A
// missing file starts empty (an operator may set ca_file before the first login); a file
// that exists but is refused (permissions, symlink) propagates, exactly as `project use`
// does, so a tamper signal is never overwritten.
func updateStoredCredentials(change func(*credstore.Credentials)) error {
	store, err := resolveCredStore()
	if err != nil {
		return fmt.Errorf("resolve credential store: %w", err)
	}
	creds, err := store.Load()
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("load credentials: %w", err)
	}
	change(&creds)
	if err := store.Save(creds); err != nil {
		return fmt.Errorf("save credentials: %w", err)
	}
	return nil
}

func runConfigSet(cmd *cobra.Command, args []string) error {
	if err := requireConfigKey(args[0]); err != nil {
		return err
	}
	abs, err := filepath.Abs(args[1])
	if err != nil {
		return fmt.Errorf("resolve %s: %w", args[1], err)
	}
	// Validate now, not on the next command: a wrong file should fail here.
	if _, err := apiclient.LoadCAPool(abs); err != nil {
		return err
	}
	if err := updateStoredCredentials(func(c *credstore.Credentials) { c.CAFile = abs }); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "ca_file set to %s\n", abs)
	return nil
}

func runConfigGet(cmd *cobra.Command, args []string) error {
	if err := requireConfigKey(args[0]); err != nil {
		return err
	}
	path, source := resolveCAFile()
	if path == "" {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "ca_file is not set (the system roots are trusted)")
		return nil
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s (from %s)\n", path, source)
	return nil
}

func runConfigUnset(cmd *cobra.Command, args []string) error {
	if err := requireConfigKey(args[0]); err != nil {
		return err
	}
	if err := updateStoredCredentials(func(c *credstore.Credentials) { c.CAFile = "" }); err != nil {
		return err
	}
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "ca_file unset")
	return nil
}
