package cmd

import (
	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/cliversion"
)

var rootCmd = &cobra.Command{
	Use:   "keyorix",
	Short: "Keyorix CLI -- see ADR-108",
	Long: `keyorix is the Keyorix CLI. It talks to a Keyorix server exclusively over the REST API; it has no local database mode. Host-side operations (config/keys/database setup, encryption key rotation) are "keyorix-server admin", a separate command.

` + exitCodesHelp,
	Version: cliversion.Version,
	// main() prints the error once ("Error: ..."); cobra must not print it a
	// second time (#2938).
	SilenceErrors: true,
	// Usage is for argument/flag mistakes, which fail before PersistentPreRun.
	// Once the command is running, a failure (403, 409, wrong password) is not a
	// usage problem and the flags block would bury the message (#2938).
	PersistentPreRunE: rootPreRun,
}

// Execute runs the root command. Called from main().
func Execute() error {
	applySecretFlagPolicy()
	applyHelpExamples()
	applyErrorPolish()
	return rootCmd.Execute()
}

func init() {
	rootCmd.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return withExitCode(exitUsage, err) })
	rootCmd.PersistentFlags().StringVar(&caFileFlag, "ca-file", "",
		"PEM CA/certificate file to trust for the server's TLS certificate, instead of the system roots (or set KEYORIX_CA_FILE, or: keyorix config set ca_file <path>)")
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(logoutCmd)
	rootCmd.AddCommand(mfaCmd)
	rootCmd.AddCommand(auditCmd)
	rootCmd.AddCommand(anomaliesCmd)
	rootCmd.AddCommand(notificationCmd)
	rootCmd.AddCommand(accessReviewCmd)
	rootCmd.AddCommand(requestCmd)
	rootCmd.AddCommand(projectCmd)
	rootCmd.AddCommand(userCmd)
}
