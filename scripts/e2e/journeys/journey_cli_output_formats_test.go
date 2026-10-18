//go:build e2e

package journeys

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os/exec"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// runCLIStdout runs the CLI and returns stdout and stderr separately, so a test can
// parse the data a script would pipe without a warning on stderr getting in the way.
func runCLIStdout(t *testing.T, cliBin string, env []string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	cmd := exec.Command(cliBin, args...) // #nosec G204 -- cliBin is this test's own built binary path, args are fixed by the test
	cmd.Env = env
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err = cmd.Run()
	return so.String(), se.String(), err
}

// TestJourney_CLIOutputFormats drives the list/report commands that take
// -o/--output table|json|yaml (CLI-UX-1) against a real server: the same data comes
// back in every format, the old --format spelling still works (with a notice on
// stderr only), and a bad format is refused naming the choices.
func TestJourney_CLIOutputFormats(t *testing.T) {
	serverBin, cliBin := harness.BuildBinaries(t)
	s := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite"})
	t.Cleanup(s.Close)

	const (
		proj = "j-out-fmt"
		name = "out-fmt-secret"
	)
	adminToken := mfaLogin(t, s, "smoketestadmin", harness.BootstrapAdminPassword)
	aEnv := adminEnv(s, adminToken)

	runCLI(t, cliBin, aEnv, "project", "create", "--name", proj)
	pid := projectID(t, s, adminToken, proj)
	eid := environmentID(t, s, adminToken, pid, "development")
	// Seeded through the REST API: the point of this journey is the output formats, and
	// no secret value belongs on a CLI command line.
	restExpect(t, s, adminToken, http.MethodPost, "/api/v1/secrets", map[string]interface{}{
		"name": name, "value": "value-for-" + name, "project_id": pid, "environment_id": eid, "type": "generic",
	}, http.StatusCreated)

	type listing struct {
		Total   int `json:"total" yaml:"total"`
		Secrets []struct {
			Name string `json:"name" yaml:"name"`
		} `json:"secrets" yaml:"secrets"`
	}

	t.Run("secret list -o json and -o yaml carry the same secret", func(t *testing.T) {
		var fromJSON, fromYAML listing
		out, errOut, err := runCLIStdout(t, cliBin, aEnv, "secret", "list", "--project", proj, "-o", "json")
		if err != nil {
			t.Fatalf("secret list -o json: %v\n%s", err, errOut)
		}
		if err := json.Unmarshal([]byte(out), &fromJSON); err != nil {
			t.Fatalf("stdout is not JSON: %v\n%s", err, out)
		}
		out, errOut, err = runCLIStdout(t, cliBin, aEnv, "secret", "list", "--project", proj, "--output", "yaml")
		if err != nil {
			t.Fatalf("secret list --output yaml: %v\n%s", err, errOut)
		}
		if err := yaml.Unmarshal([]byte(out), &fromYAML); err != nil {
			t.Fatalf("stdout is not YAML: %v\n%s", err, out)
		}
		if len(fromJSON.Secrets) != 1 || fromJSON.Secrets[0].Name != name {
			t.Fatalf("json listing wrong: %+v", fromJSON)
		}
		if len(fromYAML.Secrets) != 1 || fromYAML.Secrets[0].Name != name || fromYAML.Total != fromJSON.Total {
			t.Fatalf("yaml listing differs from json: %+v vs %+v", fromYAML, fromJSON)
		}
	})

	t.Run("the table stays the default", func(t *testing.T) {
		out := runCLI(t, cliBin, aEnv, "secret", "list", "--project", proj)
		if !strings.Contains(out, name) || !strings.Contains(out, "Secrets List") {
			t.Fatalf("default output is no longer the table:\n%s", out)
		}
	})

	t.Run("the old --format spelling still works and warns on stderr only", func(t *testing.T) {
		out, errOut, err := runCLIStdout(t, cliBin, aEnv, "secret", "list", "--project", proj, "--format", "json")
		if err != nil {
			t.Fatalf("secret list --format json: %v\n%s", err, errOut)
		}
		if !json.Valid([]byte(out)) {
			t.Fatalf("a deprecation notice must not reach stdout:\n%s", out)
		}
		if !strings.Contains(errOut, "--output") {
			t.Fatalf("stderr should point at --output, got: %q", errOut)
		}
	})

	t.Run("a bad format is refused and names the choices", func(t *testing.T) {
		out := runCLIExpectErr(t, cliBin, aEnv, "secret", "list", "--project", proj, "-o", "xml")
		if !strings.Contains(out, "table, json or yaml") {
			t.Fatalf("want the allowed formats named, got:\n%s", out)
		}
	})

	t.Run("project stats -o yaml", func(t *testing.T) {
		out, errOut, err := runCLIStdout(t, cliBin, aEnv, "project", "stats", proj, "-o", "yaml")
		if err != nil {
			t.Fatalf("project stats -o yaml: %v\n%s", err, errOut)
		}
		var doc struct {
			ProjectName  string `yaml:"project_name"`
			TotalSecrets int    `yaml:"total_secrets"`
		}
		if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatalf("stdout is not YAML: %v\n%s", err, out)
		}
		if doc.TotalSecrets != 1 {
			t.Fatalf("want 1 secret in the stats, got %+v\n%s", doc, out)
		}
	})
}
