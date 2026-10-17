//go:build e2e

package journeys

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// TestJourney_CLIListCommandsOutputFormats checks the list commands that take
// -o/--output (CLI-UX-1 item 1) against a real server and the real binary: json is the
// same records the table shows, yaml parses to the same thing, an empty list is `[]`
// rather than a sentence, and the table stays the default.
func TestJourney_CLIListCommandsOutputFormats(t *testing.T) {
	serverBin, cliBin := harness.BuildBinaries(t)
	s := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite"})
	t.Cleanup(s.Close)

	adminToken := mfaLogin(t, s, "smoketestadmin", harness.BootstrapAdminPassword)
	aEnv := adminEnv(s, adminToken)

	const proj = "j-list-out"
	runCLI(t, cliBin, aEnv, "project", "create", "--name", proj)
	pid := projectID(t, s, adminToken, proj)
	eid := environmentID(t, s, adminToken, pid, "development")
	runCLI(t, cliBin, aEnv, "group", "create", "--name", "list-out-group")
	runCLI(t, cliBin, aEnv, "machine", "create", "--project", proj, "--name", "list-out-machine", "--type", "ci")
	runCLI(t, cliBin, aEnv, "pat", "create", "--name", "list-out-pat", "--scope", "secrets.read")
	runCLI(t, cliBin, aEnv, "notification", "channel", "add", "list-out-chan", "--type", "email", "--email", "list-out@example.com")
	runCLI(t, cliBin, aEnv, "user", "create", "--username", "list-out-user", "--email", "list-out@example.com", "--one-time-password")
	restExpect(t, s, adminToken, http.MethodPost, "/api/v1/secrets", map[string]interface{}{
		"name": "list-out-secret", "value": "v", "project_id": pid, "environment_id": eid, "type": "generic",
	}, http.StatusCreated)
	sid := strconv.Itoa(secretID(t, s, adminToken, pid, eid, "list-out-secret"))

	// Each case: the command, the field its records are keyed by, and a value that must
	// appear in the records. wrap names the object key holding the array when the list is
	// paged (users).
	cases := []struct {
		name string
		args []string
		wrap string
		key  string
		want string
	}{
		{"project list", []string{"project", "list"}, "", "name", proj},
		{"user list", []string{"user", "list"}, "users", "username", "list-out-user"},
		{"group list", []string{"group", "list"}, "", "name", "list-out-group"},
		{"machine list", []string{"machine", "list", "--project", proj}, "", "name", "list-out-machine"},
		{"pat list", []string{"pat", "list"}, "", "name", "list-out-pat"},
		{"notification channel list", []string{"notification", "channel", "list"}, "", "name", "list-out-chan"},
		{"rbac list-roles", []string{"rbac", "list-roles"}, "", "name", "admin"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			records := func(format string) []map[string]any {
				t.Helper()
				args := append(append([]string{}, c.args...), "-o", format)
				out, errOut, err := runCLIStdout(t, cliBin, aEnv, args...)
				if err != nil {
					t.Fatalf("keyorix %s: %v\n%s", strings.Join(args, " "), err, errOut)
				}
				var doc any
				switch format {
				case "json":
					if err := json.Unmarshal([]byte(out), &doc); err != nil {
						t.Fatalf("not JSON: %v\n%s", err, out)
					}
				case "yaml":
					if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
						t.Fatalf("not YAML: %v\n%s", err, out)
					}
				}
				if c.wrap != "" {
					m, ok := doc.(map[string]any)
					if !ok {
						t.Fatalf("%s: want an object with %q, got %T", format, c.wrap, doc)
					}
					doc = m[c.wrap]
				}
				arr, ok := doc.([]any)
				if !ok {
					t.Fatalf("%s: want an array of records, got %T:\n%s", format, doc, out)
				}
				var recs []map[string]any
				for _, e := range arr {
					m, _ := e.(map[string]any)
					recs = append(recs, m)
				}
				return recs
			}
			has := func(recs []map[string]any) bool {
				for _, r := range recs {
					if r[c.key] == c.want {
						return true
					}
				}
				return false
			}
			jsonRecs, yamlRecs := records("json"), records("yaml")
			if !has(jsonRecs) {
				t.Errorf("json lacks %s=%q: %v", c.key, c.want, jsonRecs)
			}
			if !has(yamlRecs) || len(yamlRecs) != len(jsonRecs) {
				t.Errorf("yaml differs from json: %d vs %d records", len(yamlRecs), len(jsonRecs))
			}
			table := runCLI(t, cliBin, aEnv, c.args...)
			if !strings.Contains(table, c.want) {
				t.Errorf("the default table lost %q:\n%s", c.want, table)
			}
		})
	}

	t.Run("share list and an empty request list", func(t *testing.T) {
		uid := n20UserID(t, s, adminToken, "list-out-user")
		// Sharing needs the sharer and the recipient to be members of the secret's project.
		runCLI(t, cliBin, aEnv, "rbac", "assign-role", "--user", "smoketestadmin@example.invalid", "--role", "project_admin", "--project", proj)
		runCLI(t, cliBin, aEnv, "rbac", "assign-role", "--user", "list-out@example.com", "--role", "project_viewer", "--project", proj)
		runCLI(t, cliBin, aEnv, "share", "create", "--secret-id", sid, "--recipient-id", strconv.Itoa(uid), "--permission", "read")
		out, errOut, err := runCLIStdout(t, cliBin, aEnv, "share", "list", "--secret-id", sid, "-o", "json")
		if err != nil {
			t.Fatalf("share list -o json: %v\n%s", err, errOut)
		}
		var shares []map[string]any
		if err := json.Unmarshal([]byte(out), &shares); err != nil || len(shares) != 1 {
			t.Fatalf("want one share as a JSON array, got %v\n%s", err, out)
		}

		// No requests yet: json is an empty array, the table says so in words.
		out, _, err = runCLIStdout(t, cliBin, aEnv, "request", "list", "--project", proj, "-o", "json")
		if err != nil || strings.TrimSpace(out) != "[]" {
			t.Fatalf("empty list should be [], got %q (%v)", out, err)
		}
		table := runCLI(t, cliBin, aEnv, "request", "list", "--project", proj)
		if !strings.Contains(table, "No access requests found") {
			t.Errorf("the table keeps its sentence:\n%s", table)
		}
	})

	// The remaining list commands: whatever they hold (mostly nothing on a fresh server),
	// json and yaml must be valid documents holding an array, and an empty list is [].
	t.Run("the other list commands print valid json and yaml", func(t *testing.T) {
		pidArg := strconv.Itoa(pid)
		others := []struct {
			args    []string
			wrapKey string // set when the document is an object holding the array
			object  bool   // the document is one object, not a list
		}{
			{args: []string{"rotation", "list"}},
			{args: []string{"pat", "list-expired"}},
			{args: []string{"secret", "folder", "list", "--project", pidArg}},
			{args: []string{"project", "env", "list", "--project", proj}},
			{args: []string{"rbac", "list-user-roles", "--user", "smoketestadmin@example.invalid"}},
			{args: []string{"rbac", "list-permissions", "--user", "smoketestadmin@example.invalid"}},
			{args: []string{"rbac", "list-group-roles", "--group", "list-out-group"}},
			{args: []string{"secret", "acl", "list", sid}},
			{args: []string{"secret", "template", "list"}},
			{args: []string{"sod", "policy", "list"}},
			{args: []string{"risk", "list"}},
			{args: []string{"anomalies", "list"}},
			{args: []string{"anomalies", "escalation", "list"}},
			{args: []string{"request", "rejection-templates", "list"}},
			{args: []string{"machine", "token", "list", "list-out-machine", "--project", proj}},
			{args: []string{"machine", "binding", "list", "list-out-machine", "--project", proj}},
			{args: []string{"invite", "list", "--project", proj}},
			{args: []string{"access-review", "campaign", "list", "--project-id", pidArg}},
			{args: []string{"secret", "deps", "list", sid}, object: true},
		}
		for _, c := range others {
			for _, format := range []string{"json", "yaml"} {
				args := append(append([]string{}, c.args...), "-o", format)
				out, errOut, err := runCLIStdout(t, cliBin, aEnv, args...)
				if err != nil {
					t.Errorf("keyorix %s: %v\n%s%s", strings.Join(args, " "), err, out, errOut)
					continue
				}
				var doc any
				if format == "json" {
					err = json.Unmarshal([]byte(out), &doc)
				} else {
					err = yaml.Unmarshal([]byte(out), &doc)
				}
				if err != nil {
					t.Errorf("keyorix %s: not %s: %v\n%s", strings.Join(args, " "), format, err, out)
					continue
				}
				switch doc.(type) {
				case []any:
					if c.object {
						t.Errorf("keyorix %s: want one object, got a list", strings.Join(args, " "))
					}
				case map[string]any:
					if !c.object {
						t.Errorf("keyorix %s: want a list, got an object:\n%s", strings.Join(args, " "), out)
					}
				default:
					t.Errorf("keyorix %s: unexpected document %T:\n%s", strings.Join(args, " "), doc, out)
				}
			}
		}
	})

	t.Run("a bad format is refused for every list command", func(t *testing.T) {
		for _, c := range cases {
			args := append(append([]string{}, c.args...), "-o", "xml")
			out := runCLIExpectErr(t, cliBin, aEnv, args...)
			if !strings.Contains(out, "table, json or yaml") {
				t.Errorf("keyorix %s: want the choices named:\n%s", strings.Join(args, " "), out)
			}
		}
	})
}
