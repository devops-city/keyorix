// Package clidocs renders the CLI's command tree as a Markdown reference and as a man
// page, so the published documentation is derived from the same cobra definitions
// `keyorix --help` prints and cannot drift from them. A test in cli/cmd compares the
// committed files with this package's output.
//
// The output is a pure function of the tree: no dates, no versions, no environment, no
// flag values. Hidden commands and flags (deprecated aliases) are left out, as in --help.
package clidocs

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// visible returns c's subcommands that --help would list, in name order. The `help`
// command is omitted: it documents nothing beyond --help itself.
func visible(c *cobra.Command) []*cobra.Command {
	var out []*cobra.Command
	for _, s := range c.Commands() {
		if s.Hidden || s.Deprecated != "" || s.Name() == "help" {
			continue
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// walk calls fn for c and every visible command below it, depth first, in name order.
func walk(c *cobra.Command, fn func(*cobra.Command)) {
	fn(c)
	for _, s := range visible(c) {
		walk(s, fn)
	}
}

type flagDoc struct {
	name, short, typ, def, usage string
}

// localFlags returns the flags defined on c itself (not inherited), without hidden ones.
func localFlags(c *cobra.Command) []flagDoc {
	return flagDocs(c.LocalNonPersistentFlags())
}

func persistentFlags(c *cobra.Command) []flagDoc {
	return flagDocs(c.PersistentFlags())
}

func flagDocs(fs *pflag.FlagSet) []flagDoc {
	var out []flagDoc
	fs.VisitAll(func(f *pflag.Flag) {
		// -h/--help is added to a command lazily, the first time it runs; listing it would make
		// the output depend on which commands ran before. It is documented once, globally.
		if f.Hidden || f.Deprecated != "" || f.Name == "help" {
			return
		}
		typ := f.Value.Type()
		if typ == "bool" {
			typ = ""
		}
		out = append(out, flagDoc{name: f.Name, short: f.Shorthand, typ: typ, def: defaultOf(f), usage: f.Usage})
	})
	return out
}

// defaultOf is the flag's default as --help prints it ("" when it is the zero value).
func defaultOf(f *pflag.Flag) string {
	switch f.DefValue {
	case "", "0", "false", "[]", "0s":
		return ""
	}
	return f.DefValue
}

// useLine is the synopsis, built from the declared Use and the command's own flags and
// subcommands. cobra's UseLine adds "[flags]" only once the help flag has been
// initialised, which depends on which commands have run, so it cannot be used here.
func useLine(c *cobra.Command) string {
	line := c.CommandPath()
	if _, args, ok := strings.Cut(c.Use, " "); ok {
		line += " " + strings.TrimSpace(args)
	}
	if len(visible(c)) > 0 {
		line += " [command]"
	}
	if len(localFlags(c)) > 0 {
		line += " [flags]"
	}
	return line
}

func exampleLines(c *cobra.Command) []string {
	var out []string
	for l := range strings.SplitSeq(strings.TrimRight(c.Example, "\n"), "\n") {
		out = append(out, strings.TrimPrefix(l, "  "))
	}
	if len(out) == 1 && out[0] == "" {
		return nil
	}
	return out
}

// ── Markdown ───────────────────────────────────────────────────────────────────

// Markdown renders the reference for root and everything below it.
func Markdown(root *cobra.Command) string {
	var b strings.Builder
	name := root.Name()
	fmt.Fprintf(&b, "# %s CLI reference\n\n", strings.ToUpper(name[:1])+name[1:])
	b.WriteString("<!-- GENERATED from the command tree by `" + name + " docs markdown`; do not edit.\n" +
		"     Regenerate: make -C cli docs   (TestCLIReferenceIsFresh fails when this file is stale). -->\n\n")
	fmt.Fprintf(&b, "%s\n\n", strings.TrimSpace(root.Long))

	if gf := persistentFlags(root); len(gf) > 0 {
		b.WriteString("## Global flags\n\n")
		writeFlagTable(&b, gf)
	}

	b.WriteString("## Commands\n\n")
	for _, c := range visible(root) {
		fmt.Fprintf(&b, "- [`%s %s`](#%s) — %s\n", name, c.Name(), anchor(c), mdInline(c.Short))
	}
	b.WriteString("\n")

	for _, top := range visible(root) {
		walk(top, func(c *cobra.Command) { writeCommand(&b, c) })
	}
	return strings.TrimRight(b.String(), "\n") + "\n"
}

func anchor(c *cobra.Command) string {
	var b strings.Builder
	for _, r := range strings.ToLower(c.CommandPath()) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-' || r == '_':
			b.WriteRune(r)
		case r == ' ':
			b.WriteRune('-')
		}
	}
	return b.String()
}

func writeCommand(b *strings.Builder, c *cobra.Command) {
	fmt.Fprintf(b, "## `%s`\n\n", c.CommandPath())
	fmt.Fprintf(b, "%s\n\n", mdText(c.Short))
	if long := strings.TrimSpace(c.Long); long != "" && long != strings.TrimSpace(c.Short) {
		fmt.Fprintf(b, "%s\n\n", mdText(long))
	}
	fmt.Fprintf(b, "**Usage:** `%s`\n\n", useLine(c))
	if ex := exampleLines(c); len(ex) > 0 {
		b.WriteString("**Examples:**\n\n```sh\n" + strings.Join(ex, "\n") + "\n```\n\n")
	}
	if fl := localFlags(c); len(fl) > 0 {
		b.WriteString("**Flags:**\n\n")
		writeFlagTable(b, fl)
	}
	if subs := visible(c); len(subs) > 0 {
		b.WriteString("**Subcommands:**\n\n")
		for _, s := range subs {
			fmt.Fprintf(b, "- [`%s`](#%s) — %s\n", s.CommandPath(), anchor(s), mdInline(s.Short))
		}
		b.WriteString("\n")
	}
}

func writeFlagTable(b *strings.Builder, fl []flagDoc) {
	b.WriteString("| Flag | Type | Default | Description |\n|---|---|---|---|\n")
	for _, f := range fl {
		flag := "`--" + f.name + "`"
		if f.short != "" {
			flag = "`-" + f.short + "`, " + flag
		}
		fmt.Fprintf(b, "| %s | %s | %s | %s |\n", flag, codeOrDash(f.typ), codeOrDash(f.def), mdInline(f.usage))
	}
	b.WriteString("\n")
}

func codeOrDash(s string) string {
	if s == "" {
		return "—"
	}
	return "`" + strings.ReplaceAll(s, "|", "\\|") + "`"
}

// mdInline escapes text for a single table cell or list item.
func mdInline(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	return escapeMarkdown(strings.ReplaceAll(s, "|", "\\|"))
}

// escapeMarkdown stops "<path>" being read as an HTML tag (and dropped by the renderer).
func escapeMarkdown(s string) string {
	s = strings.ReplaceAll(s, "<", "\\<")
	return strings.ReplaceAll(s, ">", "\\>")
}

// mdText keeps a paragraph's line structure (help text uses indented blocks and lists) by
// fencing any run of indented or list-like lines; plain paragraphs pass through.
func mdText(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	var out []string
	inFence := false
	for _, l := range lines {
		pre := strings.HasPrefix(l, "  ") || strings.HasPrefix(l, "\t")
		if pre && !inFence {
			out = append(out, "```text")
			inFence = true
		}
		if !pre && inFence && strings.TrimSpace(l) != "" {
			out = append(out, "```")
			inFence = false
		}
		if !pre {
			l = escapeMarkdown(l)
		}
		out = append(out, l)
	}
	if inFence {
		out = append(out, "```")
	}
	return strings.Join(out, "\n")
}

// ── man page ───────────────────────────────────────────────────────────────────

// Man renders one man(7) page for root and every command below it: a section per command
// under COMMANDS, so `man keyorix` and "/secret get" find anything.
func Man(root *cobra.Command) string {
	var b strings.Builder
	name := root.Name()
	fmt.Fprintf(&b, ".TH %q \"1\" \"\" \"%s CLI\" \"%s Manual\"\n", strings.ToUpper(name), strings.ToUpper(name[:1])+name[1:], strings.ToUpper(name[:1])+name[1:])
	fmt.Fprintf(&b, ".SH NAME\n%s \\- %s\n", roffWord(name), roffText(root.Short))
	fmt.Fprintf(&b, ".SH SYNOPSIS\n.B %s\n[\\fIglobal flags\\fR] \\fIcommand\\fR [\\fIflags\\fR] [\\fIargs\\fR]\n", roffWord(name))
	b.WriteString(".SH DESCRIPTION\n" + roffParas(root.Long) + "\n")
	if gf := persistentFlags(root); len(gf) > 0 {
		b.WriteString(".SH GLOBAL FLAGS\n")
		writeManFlags(&b, gf)
	}
	b.WriteString(".SH COMMANDS\n")
	for _, top := range visible(root) {
		walk(top, func(c *cobra.Command) {
			fmt.Fprintf(&b, ".SS %s\n%s\n", roffWord(c.CommandPath()), roffText(c.Short))
			if long := strings.TrimSpace(c.Long); long != "" && long != strings.TrimSpace(c.Short) {
				b.WriteString(".PP\n" + roffParas(long) + "\n")
			}
			fmt.Fprintf(&b, ".PP\nUsage: \\fB%s\\fR\n", roffText(useLine(c)))
			if ex := exampleLines(c); len(ex) > 0 {
				b.WriteString(".PP\nExamples:\n.PP\n.nf\n")
				for _, l := range ex {
					b.WriteString(roffText(l) + "\n")
				}
				b.WriteString(".fi\n")
			}
			if fl := localFlags(c); len(fl) > 0 {
				b.WriteString(".PP\nFlags:\n")
				writeManFlags(&b, fl)
			}
		})
	}
	return b.String()
}

func writeManFlags(b *strings.Builder, fl []flagDoc) {
	for _, f := range fl {
		b.WriteString(".TP\n")
		if f.short != "" {
			fmt.Fprintf(b, "\\fB\\-%s\\fR, ", roffWord(f.short))
		}
		fmt.Fprintf(b, "\\fB\\-\\-%s\\fR", roffWord(f.name))
		if f.typ != "" {
			fmt.Fprintf(b, " \\fI%s\\fR", roffWord(f.typ))
		}
		b.WriteString("\n" + roffText(f.usage))
		if f.def != "" {
			fmt.Fprintf(b, " (default %s)", roffText(f.def))
		}
		b.WriteString("\n")
	}
}

// roffGlyphs maps the few non-ASCII characters help text uses to man(7) named glyphs, so the
// page renders the same in every locale.
var roffGlyphs = strings.NewReplacer("—", "\\(em", "–", "\\(en", "·", "\\(bu", "…", "...", "→", "\\(->", "’", "'", "“", "\\(lq", "”", "\\(rq")

// roffWord escapes a token: backslashes and hyphens (so `--flag` is not typeset as a dash).
func roffWord(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	return strings.ReplaceAll(s, "-", "\\-")
}

// roffText escapes running text and keeps a line from being read as a request: a line that
// starts with "." or "'" gets the zero-width \& in front.
func roffText(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "-", "\\-")
	s = roffGlyphs.Replace(s)
	if strings.HasPrefix(s, ".") || strings.HasPrefix(s, "'") {
		s = "\\&" + s
	}
	return s
}

// roffParas renders help text as man paragraphs (blank line = new paragraph); indented
// blocks are kept verbatim in a no-fill region.
func roffParas(s string) string {
	var out []string
	var para []string
	var pre []string
	flushPara := func() {
		if len(para) > 0 {
			out = append(out, roffText(strings.Join(para, " ")))
			para = nil
		}
	}
	flushPre := func() {
		if len(pre) > 0 {
			out = append(out, ".nf")
			for _, l := range pre {
				t := roffGlyphs.Replace(strings.ReplaceAll(strings.ReplaceAll(l, "\\", "\\\\"), "-", "\\-"))
				if strings.HasPrefix(strings.TrimLeft(t, " \t"), ".") || strings.HasPrefix(strings.TrimLeft(t, " \t"), "'") {
					t = "\\&" + t
				}
				out = append(out, t)
			}
			out = append(out, ".fi")
			pre = nil
		}
	}
	for l := range strings.SplitSeq(strings.TrimSpace(s), "\n") {
		switch {
		case strings.HasPrefix(l, "  ") || strings.HasPrefix(l, "\t"):
			flushPara()
			pre = append(pre, l)
		case strings.TrimSpace(l) == "":
			flushPara()
			flushPre()
			out = append(out, ".PP")
		default:
			flushPre()
			para = append(para, l)
		}
	}
	flushPara()
	flushPre()
	return strings.Join(out, "\n")
}
