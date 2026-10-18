package cmd

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestEmitList(t *testing.T) {
	type rec struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	}
	tableCalled := false
	table := func() error { tableCalled = true; return nil }

	if err := emitList("table", []rec{{1, "a"}}, table); err != nil || !tableCalled {
		t.Fatalf("the table format must call the table printer: %v %v", err, tableCalled)
	}

	out := captureStdout(t, func() {
		if err := emitList("json", []rec(nil), table); err != nil {
			t.Fatal(err)
		}
	})
	if strings.TrimSpace(out) != "[]" {
		t.Errorf("a nil slice must print as [], got %q", out)
	}
	out = captureStdout(t, func() {
		if err := emitList("yaml", []rec{{1, "a"}, {2, "b"}}, table); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "- id: 1\n  name: a\n") || !strings.Contains(out, "- id: 2\n  name: b\n") {
		t.Errorf("yaml list:\n%s", out)
	}
}

// listOutputPending are list commands that do not take -o yet, each with the reason. The
// list may only shrink: TestEveryListCommandTakesOutput fails for a list command that is in
// neither this map nor converted, and for an entry that has since been converted.
var listOutputPending = map[string]string{
	"break-glass list": "prints a scope banner (own vs all activations) before the table; needs its own record shape",
}

func listCommands() []*cobra.Command {
	var out []*cobra.Command
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, s := range c.Commands() {
			walk(s)
		}
		n := c.Name()
		if (n == "list" || strings.HasPrefix(n, "list-")) && !c.HasSubCommands() {
			out = append(out, c)
		}
	}
	walk(rootCmd)
	return out
}

// TestEveryListCommandTakesOutput is the family guard for item 1's "--output where it
// lists things": every command named list or list-* has -o/--output, validates the value before contacting
// the server, and a command can
// only be left out by being named in listOutputPending.
func TestEveryListCommandTakesOutput(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer srv.Close()
	setSystemCreds(t, srv)

	cmds := listCommands()
	if len(cmds) < 25 {
		t.Fatalf("only %d list commands found; the walk is broken", len(cmds))
	}
	seenPending := map[string]bool{}
	for _, c := range cmds {
		name := strings.TrimPrefix(c.CommandPath(), rootCmd.Name()+" ")
		out := c.Flags().Lookup("output")
		if _, pending := listOutputPending[name]; pending {
			seenPending[name] = true
			if out != nil {
				t.Errorf("%s takes -o now: delete it from listOutputPending", name)
			}
			continue
		}
		if out == nil || out.Shorthand != "o" {
			t.Errorf("%s: no -o/--output flag (add addOutputFlag in list_output.go, or name it in listOutputPending with a reason)", name)
			continue
		}
		if err := c.Flags().Set("output", "xml"); err != nil {
			t.Fatal(err)
		}
		err := c.RunE(c, nil)
		_ = c.Flags().Set("output", "table")
		if err == nil || !strings.Contains(err.Error(), "table, json or yaml") {
			t.Errorf("%s: a bad format must be refused naming the choices, got %v", name, err)
		}
	}
	if called {
		t.Error("a server was contacted before a format was validated")
	}
	for name := range listOutputPending {
		if !seenPending[name] {
			t.Errorf("listOutputPending names %q, which is not a list command", name)
		}
	}
}
