package cmd

import (
	"testing"

	"github.com/spf13/cobra"
)

func leafCommandsOf(root *cobra.Command) []*cobra.Command {
	var out []*cobra.Command
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if c != root && (c.Name() == "help" || c.Name() == "completion") {
			return
		}
		if !c.HasAvailableSubCommands() {
			out = append(out, c)
		}
		for _, s := range c.Commands() {
			walk(s)
		}
	}
	walk(root)
	return out
}

// TestScopeFlags_EveryProjectAndEnvCommandAcceptsTheCanonicalSpelling is the family
// check behind applyScopeFlagAliases: on every command that can name a project,
// `--project` is accepted, and on every command that can name an environment,
// `--env` is. Adding a command with `--environment-id` and no alias fails nothing
// (the alias is automatic); this fails if the mechanism stops covering the tree.
func TestScopeFlags_EveryProjectAndEnvCommandAcceptsTheCanonicalSpelling(t *testing.T) {
	applyScopeFlagAliases()

	var withProject, withEnv int
	for _, c := range leafCommandsOf(rootCmd) {
		for _, name := range []string{"project", "project-id"} {
			if c.Flags().Lookup(name) != nil && c.Flags().Lookup("project") == nil {
				t.Errorf("%s defines --%s but does not accept --project", c.CommandPath(), name)
			}
		}
		if c.Flags().Lookup("project") != nil {
			withProject++
		}
		for _, name := range []string{"env", "environment", "environment-id"} {
			if c.Flags().Lookup(name) != nil && c.Flags().Lookup("env") == nil {
				t.Errorf("%s defines --%s but does not accept --env", c.CommandPath(), name)
			}
		}
		if c.Flags().Lookup("env") != nil {
			withEnv++
		}
	}
	if withProject < 50 || withEnv < 15 {
		t.Fatalf("walk found only %d project / %d env commands; the check is vacuous", withProject, withEnv)
	}
}

func TestScopeFlagAliases_SetTheDefinedFlagAndKeepChanged(t *testing.T) {
	applyScopeFlagAliases()

	// pat create defines --project-id and --environment-id (ints).
	pc := patCreateCmd
	t.Cleanup(func() {
		_ = pc.Flags().Set("project-id", "0")
		_ = pc.Flags().Set("environment-id", "0")
		pc.Flags().Lookup("project-id").Changed = false
		pc.Flags().Lookup("environment-id").Changed = false
	})
	if err := pc.ParseFlags([]string{"--project", "3", "--env", "5", "--name", "t"}); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	if got := patCreateProject; got != 3 {
		t.Errorf("--project 3 set project-id to %d, want 3", got)
	}
	if got := patCreateEnv; got != 5 {
		t.Errorf("--env 5 set environment-id to %d, want 5", got)
	}
	if !pc.Flags().Changed("environment-id") {
		t.Error("Changed(\"environment-id\") must be true when the user typed --env")
	}
	// The command still shows the one name it defines.
	if f := pc.Flags().Lookup("env"); f == nil || f.Name != "environment-id" {
		t.Errorf("--env should resolve to the environment-id flag, got %+v", f)
	}
}

// run defines both --project (a name) and --project-id (the numeric ID): different
// meanings, so the aliasing must leave it alone.
func TestScopeFlagAliases_CommandWithBothSpellingsIsUntouched(t *testing.T) {
	applyScopeFlagAliases()
	p, id := runCmd.Flags().Lookup("project"), runCmd.Flags().Lookup("project-id")
	if p == nil || id == nil || p == id {
		t.Fatalf("run must keep --project and --project-id as two flags: %v %v", p, id)
	}
}
