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

// Every list command that takes -o validates the format before it contacts the server.
func TestListCommandsTakeOutputAndRefuseBadFormatsFirst(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer srv.Close()
	setSystemCreds(t, srv)

	for _, tc := range []struct {
		cmd *cobra.Command
		set *string
	}{
		{projectListCmd, &projectListFormat},
		{userListCmd, &userListFormat},
		{groupListCmd, &groupListFormat},
		{machineListCmd, &machineListFormat},
		{patListCmd, &patListFormat},
		{requestListCmd, &requestListFormat},
		{channelListCmd, &channelListFormat},
		{shareListCmd, &shareListFormat},
		{rbacListRolesCmd, &roleListFormat},
	} {
		name := tc.cmd.CommandPath()
		if f := tc.cmd.Flags().Lookup("output"); f == nil || f.Shorthand != "o" {
			t.Errorf("%s: no -o/--output flag", name)
		}
		if f := tc.cmd.Flags().Lookup("format"); f == nil || !f.Hidden {
			t.Errorf("%s: --format should remain as a hidden alias", name)
		}
		*tc.set = "xml"
		err := tc.cmd.RunE(tc.cmd, nil)
		*tc.set = "table"
		if err == nil || !strings.Contains(err.Error(), "table, json or yaml") {
			t.Errorf("%s: a bad format must be refused naming the choices, got %v", name, err)
		}
	}
	if called {
		t.Error("the server was contacted before the format was validated")
	}
}
