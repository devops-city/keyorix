package cmd

import (
	"sync"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// The CLI grew its scope flags command by command: a project is `--project` on some
// commands and `--project-id` on others, an environment is `--env`, `--environment`
// or `--environment-id`. Renaming them would break every script, so instead each
// command also accepts the other spellings of the flag it already has: `--project`
// and `--env` work everywhere a project or environment can be named, and the old
// names keep working.
//
// The aliases are a pflag normalization function, not extra flags, so
// cmd.Flags().Changed("environment") is still true when the user typed `--env`, and
// `--help` keeps showing the one name the command defines. What the value means does
// not change: where the command's flag is a numeric ID, `--project payments` is still
// refused as "not an integer"; this only unifies the spelling.
var scopeFlagFamilies = [][]string{
	{"project", "project-id"},
	{"env", "environment", "environment-id"},
}

var applyScopeFlagAliasesOnce sync.Once

// applyScopeFlagAliases adds the aliases to every command. Called from Execute (and
// from tests) once the whole tree is built, like applyHelpExamples.
func applyScopeFlagAliases() {
	applyScopeFlagAliasesOnce.Do(func() { addScopeFlagAliases(rootCmd) })
}

func addScopeFlagAliases(c *cobra.Command) {
	for _, s := range c.Commands() {
		addScopeFlagAliases(s)
	}
	if c.HasAvailableSubCommands() {
		return
	}
	alias := map[string]string{}
	for _, family := range scopeFlagFamilies {
		var defined []string
		for _, name := range family {
			if c.Flags().Lookup(name) != nil {
				defined = append(defined, name)
			}
		}
		// A command that defines two spellings gave them different meanings (`run
		// --project` is a name, `--project-id` the numeric ID): leave it alone.
		if len(defined) != 1 {
			continue
		}
		for _, name := range family {
			if name != defined[0] {
				alias[name] = defined[0]
			}
		}
	}
	if len(alias) == 0 {
		return
	}
	c.Flags().SetNormalizeFunc(func(_ *pflag.FlagSet, name string) pflag.NormalizedName {
		if to, ok := alias[name]; ok {
			return pflag.NormalizedName(to)
		}
		return pflag.NormalizedName(name)
	})
}
