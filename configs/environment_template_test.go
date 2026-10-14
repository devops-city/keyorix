package configs

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func environmentIn(t *testing.T, b []byte) string {
	t.Helper()
	var d struct {
		Environment string `yaml:"environment"`
	}
	if err := yaml.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	return d.Environment
}

// `admin init` writes environment: production.
func TestDefaultConfigTemplate_EnvironmentIsProduction(t *testing.T) {
	if got := environmentIn(t, DefaultConfigTemplate); got != "production" {
		t.Fatalf("default template environment = %q, want production", got)
	}
}

// `admin init --dev` writes a label that is NOT "development": that exact value
// makes the HTTP server swap its CORS origins for the localhost dev origins
// (server/http getAllowedOrigins), a relaxation the --dev banner does not name.
// The server-side half of the guarantee is
// server/http TestEnvironmentLabel_TemplatesDoNotRelaxCORS.
func TestDevConfigTemplate_EnvironmentIsALabelNotARelaxation(t *testing.T) {
	dev, err := DevConfigTemplate()
	if err != nil {
		t.Fatal(err)
	}
	got := environmentIn(t, dev)
	if got == "" {
		t.Fatal("--dev template writes no environment")
	}
	if got == "development" {
		t.Fatal(`--dev template writes environment: development, which turns on the localhost CORS origins`)
	}
	if got != "local" {
		t.Fatalf("--dev template environment = %q, want local", got)
	}
}
