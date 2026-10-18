package clidocs

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func sampleTree() *cobra.Command {
	root := &cobra.Command{Use: "tool", Short: "A tool -- for testing", Long: "tool does things.\n\nSecond paragraph."}
	root.PersistentFlags().String("ca-file", "", "CA file <path> to trust")

	grp := &cobra.Command{Use: "box", Short: "Box commands", Long: "Work with boxes.\n\nExit codes:\n  0  ok\n  2  usage"}
	get := &cobra.Command{
		Use: "get <id>", Short: "Get a box", Example: "  tool box get 7\n  tool box get 8 --verbose",
		Run: func(*cobra.Command, []string) {},
	}
	get.Flags().BoolP("verbose", "v", false, "Be chatty")
	get.Flags().String("kind", "wood", "Kind: wood|metal")
	get.Flags().Int("limit", 0, "Max results")
	get.Flags().String("old", "", "Deprecated spelling")
	_ = get.Flags().MarkDeprecated("old", "use --kind")
	get.Flags().String("secretish", "", "hidden")
	_ = get.Flags().MarkHidden("secretish")

	grp.AddCommand(get, &cobra.Command{Use: "list", Short: ".starts with a dot", Run: func(*cobra.Command, []string) {}})
	root.AddCommand(grp, &cobra.Command{Use: "internal", Short: "hidden one", Hidden: true, Run: func(*cobra.Command, []string) {}})
	return root
}

func TestMarkdown(t *testing.T) {
	md := Markdown(sampleTree())
	for _, want := range []string{
		"# Tool CLI reference",
		"## Global flags",
		"CA file \\<path\\> to trust",
		"- [`tool box`](#tool-box) — Box commands",
		"## `tool box get`",
		"**Usage:** `tool box get <id> [flags]`",
		"```sh\ntool box get 7\ntool box get 8 --verbose\n```",
		"| `-v`, `--verbose` | — | — | Be chatty |",
		"| `--kind` | `string` | `wood` | Kind: wood\\|metal |",
		"**Subcommands:**",
		"Exit codes:\n```text\n  0  ok\n  2  usage\n```", // an indented block in help text stays a block
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown lacks %q\n%s", want, md)
		}
	}
	for _, bad := range []string{"tool internal", "secretish", "--old", "`--limit`"} {
		// --limit has a zero default but must still be listed; the others are hidden/deprecated.
		if bad == "`--limit`" {
			if !strings.Contains(md, bad) {
				t.Errorf("a flag with a zero default must still be listed")
			}
			continue
		}
		if strings.Contains(md, bad) {
			t.Errorf("markdown must omit %q", bad)
		}
	}
}

func TestMan(t *testing.T) {
	man := Man(sampleTree())
	for _, want := range []string{
		".TH \"TOOL\" \"1\"",
		".SH NAME\ntool \\- A tool \\-\\- for testing",
		".SS tool box get",
		"\\fB\\-v\\fR, \\fB\\-\\-verbose\\fR",
		"\\fB\\-\\-kind\\fR \\fIstring\\fR\nKind: wood|metal (default wood)",
		".nf\ntool box get 7",
		"\\&.starts with a dot", // text that starts with '.' must not become a roff request
		".SH GLOBAL FLAGS",
	} {
		if !strings.Contains(man, want) {
			t.Errorf("man page lacks %q\n%s", want, man)
		}
	}
	for _, bad := range []string{"tool internal", "secretish"} {
		if strings.Contains(man, bad) {
			t.Errorf("man page must omit %q", bad)
		}
	}
	for i, line := range strings.Split(man, "\n") {
		if strings.HasPrefix(line, ".") && !validRequest(line) {
			t.Errorf("line %d looks like an unknown roff request: %q", i+1, line)
		}
	}
}

// validRequest accepts the requests this generator emits.
func validRequest(line string) bool {
	for _, ok := range []string{".TH ", ".SH ", ".SS ", ".B ", ".PP", ".TP", ".nf", ".fi", ".\\&"} {
		if strings.HasPrefix(line, ok) {
			return true
		}
	}
	return false
}

func TestOutputIsDeterministic(t *testing.T) {
	a, b := sampleTree(), sampleTree()
	if Markdown(a) != Markdown(b) || Man(a) != Man(b) {
		t.Fatal("two renderings of the same tree differ")
	}
	// Commands registered in a different order render the same (sorted by name).
	r1 := &cobra.Command{Use: "t"}
	r2 := &cobra.Command{Use: "t"}
	x := func(n string) *cobra.Command {
		return &cobra.Command{Use: n, Short: n, Run: func(*cobra.Command, []string) {}}
	}
	r1.AddCommand(x("b"), x("a"), x("c"))
	r2.AddCommand(x("c"), x("a"), x("b"))
	if Markdown(r1) != Markdown(r2) || Man(r1) != Man(r2) {
		t.Fatal("output depends on registration order")
	}
}
