package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// Output formats of the commands that list or report things. `table` is the
// human layout; `json` and `yaml` are the same data for scripts.
const (
	outputTable = "table"
	outputJSON  = "json"
	outputYAML  = "yaml"
)

const outputFlagUsage = "Output format: table, json or yaml"

// addOutputFlag registers the canonical -o/--output flag on a command that lists or
// reports things, bound to dst, with shell completion for the three formats.
//
// Commands whose --output is a file path (compliance export, secret export, ...) do
// not use this; they are the writers, and say "--output FILE" in their own usage.
func addOutputFlag(cmd *cobra.Command, dst *string) {
	cmd.Flags().StringVarP(dst, "output", "o", outputTable, outputFlagUsage)
	_ = cmd.RegisterFlagCompletionFunc("output", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return []string{outputTable, outputJSON, outputYAML}, cobra.ShellCompDirectiveNoFileComp
	})
}

// addOutputFlagWithFormatAlias is addOutputFlag for a command that used to call this flag
// --format: --format stays as a hidden, deprecated alias bound to the same variable, so
// existing scripts keep working (with a notice on stderr).
func addOutputFlagWithFormatAlias(cmd *cobra.Command, dst *string) {
	addOutputFlag(cmd, dst)
	cmd.Flags().StringVar(dst, "format", outputTable, outputFlagUsage)
	_ = cmd.Flags().MarkDeprecated("format", "use --output (-o) instead")
}

// checkOutputFormat rejects anything but table, json and yaml, naming the choices.
// Call it before doing any server work so a typo fails immediately.
func checkOutputFormat(format string) error {
	switch format {
	case outputTable, outputJSON, outputYAML:
		return nil
	}
	return fmt.Errorf("unsupported output format %q: use table, json or yaml", format)
}

// printStructured writes v to stdout as indented JSON or as YAML. v must be the same
// value the json format would print; YAML is produced from its JSON form so the
// keys match the json field names exactly.
func printStructured(format string, v any) error {
	return writeStructured(os.Stdout, format, v)
}

func writeStructured(w io.Writer, format string, v any) error {
	switch format {
	case outputJSON:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(v)
	case outputYAML:
		raw, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("encode output: %w", err)
		}
		var generic any
		if err := json.Unmarshal(raw, &generic); err != nil {
			return fmt.Errorf("encode output: %w", err)
		}
		enc := yaml.NewEncoder(w)
		enc.SetIndent(2)
		if err := enc.Encode(generic); err != nil {
			return fmt.Errorf("encode output: %w", err)
		}
		return enc.Close()
	}
	if err := checkOutputFormat(format); err != nil {
		return err
	}
	return fmt.Errorf("output format %q is not structured: use json or yaml", format)
}
