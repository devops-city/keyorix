package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func TestCheckOutputFormat(t *testing.T) {
	for _, ok := range []string{"table", "json", "yaml"} {
		if err := checkOutputFormat(ok); err != nil {
			t.Errorf("checkOutputFormat(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", "xml", "JSON", "csv", "text"} {
		err := checkOutputFormat(bad)
		if err == nil {
			t.Errorf("checkOutputFormat(%q) = nil, want an error", bad)
			continue
		}
		if !strings.Contains(err.Error(), "table, json or yaml") {
			t.Errorf("checkOutputFormat(%q) error %q does not name the choices", bad, err)
		}
	}
}

func TestWriteStructured_YAMLCarriesTheSameKeysAsJSON(t *testing.T) {
	type row struct {
		ID    int     `json:"id"`
		Name  string  `json:"name"`
		Notes *string `json:"notes,omitempty"`
	}
	v := struct {
		Total int   `json:"total"`
		Rows  []row `json:"rows"`
	}{Total: 2, Rows: []row{{ID: 1, Name: "a"}, {ID: 2, Name: "b: c"}}}

	var jb, yb bytes.Buffer
	if err := writeStructured(&jb, outputJSON, v); err != nil {
		t.Fatal(err)
	}
	if err := writeStructured(&yb, outputYAML, v); err != nil {
		t.Fatal(err)
	}
	var fromJSON, fromYAML any
	if err := json.Unmarshal(jb.Bytes(), &fromJSON); err != nil {
		t.Fatalf("json output is not JSON: %v\n%s", err, jb.String())
	}
	if err := yaml.Unmarshal(yb.Bytes(), &fromYAML); err != nil {
		t.Fatalf("yaml output is not YAML: %v\n%s", err, yb.String())
	}
	if fmt.Sprint(fromJSON) != fmt.Sprint(fromYAML) {
		t.Fatalf("yaml and json differ:\njson: %v\nyaml: %v", fromJSON, fromYAML)
	}
	if !strings.Contains(yb.String(), "total: 2") || strings.Contains(yb.String(), "notes") {
		t.Fatalf("yaml should use the json field names and honour omitempty:\n%s", yb.String())
	}
	if err := writeStructured(&yb, "table", v); err == nil {
		t.Fatal("writeStructured must refuse the table format")
	}
}

func TestAddOutputFlag_FormatIsAHiddenDeprecatedAlias(t *testing.T) {
	var format string
	c := &cobra.Command{Use: "probe"}
	addOutputFlagWithFormatAlias(c, &format)

	out := c.Flags().Lookup("output")
	if out == nil || out.Shorthand != "o" || out.DefValue != "table" {
		t.Fatalf("--output/-o not registered as expected: %+v", out)
	}
	old := c.Flags().Lookup("format")
	if old == nil || !old.Hidden || old.Deprecated == "" {
		t.Fatalf("--format must stay as a hidden, deprecated alias: %+v", old)
	}

	for args, want := range map[string]string{"--output=yaml": "yaml", "-o": "json", "--format=json": "json"} {
		format = ""
		a := strings.Fields(args)
		if args == "-o" {
			a = []string{"-o", "json"}
		}
		if err := c.ParseFlags(a); err != nil {
			t.Fatalf("ParseFlags(%v): %v", a, err)
		}
		if format != want {
			t.Errorf("%v -> %q, want %q", a, format, want)
		}
	}
}

func TestUsageShow_OutputYAMLAndJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/version" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"window_days":7,"generated_at":"2026-01-15T10:00:00Z","projects":[{"project_id":1,"project_name":"acme-prod","secret_count":5,"reads_in_window":42,"unique_readers":3}]}}`)
	}))
	defer srv.Close()
	setSystemCreds(t, srv)

	usageShowDays, usageShowProjectID = 7, 0
	defer func() { usageShowFormat = "table" }()

	usageShowFormat = "yaml"
	out := captureStdout(t, func() {
		if err := usageShowCmd.RunE(usageShowCmd, nil); err != nil {
			t.Fatalf("usage show -o yaml: %v", err)
		}
	})
	var doc struct {
		WindowDays int `yaml:"window_days"`
		Projects   []struct {
			Name  string `yaml:"project_name"`
			Reads int    `yaml:"reads_in_window"`
		} `yaml:"projects"`
	}
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("not YAML: %v\n%s", err, out)
	}
	if doc.WindowDays != 7 || len(doc.Projects) != 1 || doc.Projects[0].Name != "acme-prod" || doc.Projects[0].Reads != 42 {
		t.Fatalf("yaml content wrong: %+v\n%s", doc, out)
	}

	usageShowFormat = "json"
	out = captureStdout(t, func() {
		if err := usageShowCmd.RunE(usageShowCmd, nil); err != nil {
			t.Fatalf("usage show -o json: %v", err)
		}
	})
	if !json.Valid([]byte(out)) {
		t.Fatalf("not JSON: %s", out)
	}
}

// A mistyped format used to fall through to the table (usage, billing) or fail with a
// message naming only table and json; now it fails before any request is made.
func TestListCommands_UnsupportedOutputFailsBeforeAnyRequest(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer srv.Close()
	setSystemCreds(t, srv)

	usageShowFormat = "xml"
	defer func() { usageShowFormat = "table" }()
	err := usageShowCmd.RunE(usageShowCmd, nil)
	if err == nil || !strings.Contains(err.Error(), `unsupported output format "xml"`) {
		t.Fatalf("want an unsupported-format error, got %v", err)
	}
	if called {
		t.Fatal("the server was contacted before the format was validated")
	}
}
