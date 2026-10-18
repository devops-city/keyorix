package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// maxDepth bounds the --help recursion; a cobra tree deeper than this is a bug
// in the walker (or a command that echoes its own name), not a real tree.
const maxDepth = 8

// helpFunc returns the --help text of the command at the given path.
type helpFunc func(path []string) (string, error)

var (
	flagLine = regexp.MustCompile(`^\s+(?:-\w, )?--([A-Za-z0-9][A-Za-z0-9_-]*)`)
	cmdLine  = regexp.MustCompile(`^  (\S+)`)
	// cobra's own bookkeeping, present on every tree and not a product choice.
	builtinCommands = map[string]bool{"help": true, "completion": true}
	builtinFlags    = map[string]bool{"help": true, "version": true}
)

// parseHelp extracts subcommand names and local flag names from cobra's default
// help template. Recognised sections: any header ending in "Commands:" ("Available
// Commands:", "Additional Commands:", a command group's title) and "Flags:" (the
// command's own flags; "Global Flags:" are inherited and counted where they are
// defined). Everything before the "Usage:" line is the Long description and is
// ignored, as is any other section.
func parseHelp(text string) (subs, flags []string) {
	section, seenUsage := "", false
	for line := range strings.SplitSeq(text, "\n") {
		switch {
		case line == "Usage:":
			seenUsage, section = true, ""
		case !seenUsage:
			// Short/Long description: free text, may contain anything.
		case strings.TrimSpace(line) == "":
			section = ""
		case !strings.HasPrefix(line, " ") && strings.HasSuffix(line, ":"):
			switch {
			case strings.HasSuffix(line, "Commands:"):
				section = "commands"
			case line == "Flags:":
				section = "flags"
			default:
				section = ""
			}
		case section == "commands":
			if m := cmdLine.FindStringSubmatch(line); m != nil && !builtinCommands[m[1]] {
				subs = append(subs, m[1])
			}
		case section == "flags":
			if m := flagLine.FindStringSubmatch(line); m != nil && !builtinFlags[m[1]] {
				flags = append(flags, m[1])
			}
		}
	}
	return subs, flags
}

// walkCobra returns "cmd <path>" for every command below the start path and
// "flag <path> --name" for every local flag of every command including the
// start command itself (shown as path "(root)").
func walkCobra(help helpFunc, start []string) ([]string, error) {
	var out []string
	var visit func(path []string) error
	visit = func(path []string) error {
		if len(path)-len(start) > maxDepth {
			return fmt.Errorf("command tree deeper than %d at %q", maxDepth, strings.Join(path, " "))
		}
		text, err := help(path)
		if err != nil {
			return fmt.Errorf("help for %q: %w", strings.Join(path, " "), err)
		}
		subs, flags := parseHelp(text)
		label := "(root)"
		if len(path) > len(start) {
			label = strings.Join(path[len(start):], " ")
			out = append(out, "cmd "+label)
		}
		for _, f := range flags {
			out = append(out, fmt.Sprintf("flag %s --%s", label, f))
		}
		for _, s := range subs {
			if err := visit(append(append([]string{}, path...), s)); err != nil {
				return err
			}
		}
		return nil
	}
	if err := visit(append([]string{}, start...)); err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

// cobraLines walks a real binary. HOME points at an empty directory so a
// developer's stored credentials or config never change what --help prints.
func cobraLines(bin string, start []string) ([]string, error) {
	if bin == "" {
		return nil, fmt.Errorf("-bin is required")
	}
	home, err := os.MkdirTemp("", "surfacewalk-home-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(home) }()
	abs, err := filepath.Abs(bin)
	if err != nil {
		return nil, err
	}
	return walkCobra(func(path []string) (string, error) {
		c := exec.Command(abs, append(append([]string{}, path...), "--help")...) // #nosec G204 G702 -- abs is the binary the operator passed with -bin to this hand-run dev tool nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command -- measurement tool; no remote input reaches it
		c.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home}
		c.Dir = home
		b, err := c.CombinedOutput()
		return string(b), err
	}, start)
}
