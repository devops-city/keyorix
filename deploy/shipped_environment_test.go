package deploy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The `environment:` setting is a deployment label shown in system info (and the
// value "development" also switches CORS to the localhost dev origins). Every
// shipped server config says "production": the same value `admin init` writes
// (configs/dev_template_test.go pins that). The demo stack runs `admin init --dev`
// (scripts/demo/up.sh), so it gets the --dev value pinned there.
func environmentOf(t *testing.T, body []byte) string {
	t.Helper()
	var doc struct {
		Environment string `yaml:"environment"`
	}
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Environment
}

func TestShippedComposeConfig_EnvironmentIsProduction(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "keyorix.docker.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if got := environmentOf(t, body); got != "production" {
		t.Fatalf("keyorix.docker.yaml environment = %q, want production", got)
	}
}

func TestShippedHelmConfig_EnvironmentIsProduction(t *testing.T) {
	for _, sets := range [][]string{nil, {"secureBaseline.enabled=true"}} {
		path := renderHelmServerConfig(t, sets...)
		body, err := os.ReadFile(path) //nolint:gosec // test-created temp file
		if err != nil {
			t.Fatal(err)
		}
		if got := environmentOf(t, body); got != "production" {
			t.Fatalf("Helm server config (%v) environment = %q, want production", sets, got)
		}
	}
}

func TestDemoUp_UsesAdminInitDev(t *testing.T) {
	// The demo config comes from `admin init --dev`, so its environment label is
	// whatever configs.DevConfigTemplate writes (pinned in configs/).
	body, err := os.ReadFile(filepath.Join("..", "scripts", "demo", "up.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "admin init --dev") {
		t.Fatal("scripts/demo/up.sh no longer creates its config with `admin init --dev`; give the demo config an explicit non-\"development\" environment")
	}
}
