package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/clidocs"
)

var docsCmd = &cobra.Command{
	Use:   "docs",
	Short: "Print the CLI reference (Markdown) or its man page",
	Long: `docs prints documentation generated from this binary's own command tree, so it always
matches the commands, flags and examples of the version you run. docs/cli-reference.md and
docs/man/keyorix.1 in the repository are produced the same way and checked for freshness
by the test suite.`,
}

var docsMarkdownCmd = &cobra.Command{
	Use:     "markdown",
	Short:   "Print the full command reference as Markdown",
	Example: `  keyorix docs markdown > cli-reference.md`,
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		_, err := fmt.Fprint(cmd.OutOrStdout(), clidocs.Markdown(rootCmd))
		return err
	},
}

var docsManCmd = &cobra.Command{
	Use:   "man",
	Short: "Print the man page (roff)",
	Example: `  # Read it without installing anything
  keyorix docs man | man -l -
  # Install it for the current user
  mkdir -p ~/.local/share/man/man1 && keyorix docs man > ~/.local/share/man/man1/keyorix.1`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		_, err := fmt.Fprint(cmd.OutOrStdout(), clidocs.Man(rootCmd))
		return err
	},
}

func init() {
	docsCmd.AddCommand(docsMarkdownCmd, docsManCmd)
	rootCmd.AddCommand(docsCmd)
}
