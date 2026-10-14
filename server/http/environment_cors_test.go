package http

import (
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/keyorixhq/keyorix/configs"
	"github.com/keyorixhq/keyorix/internal/config"
)

// The only security-relevant consumer of config.Environment is getAllowedOrigins:
// the exact value "development" replaces the configured CORS origins with the
// localhost dev origins. (The other readers, GET /system/info and the gRPC
// GetSystemInfo, only echo it.) The configs `admin init` writes must therefore
// never carry that value: a fresh install must get the same origins as a config
// with no environment at all.
func TestEnvironmentLabel_TemplatesDoNotRelaxCORS(t *testing.T) {
	dev, err := configs.DevConfigTemplate()
	if err != nil {
		t.Fatal(err)
	}
	templates := map[string][]byte{"default": configs.DefaultConfigTemplate, "dev": dev}

	for name, tpl := range templates {
		var cfg config.Config
		if err := yaml.Unmarshal(tpl, &cfg); err != nil {
			t.Fatalf("%s template: %v", name, err)
		}
		if cfg.Environment == "" {
			t.Fatalf("%s template writes no environment", name)
		}

		baseline := cfg
		baseline.Environment = ""
		if got, want := getAllowedOrigins(&cfg), getAllowedOrigins(&baseline); !reflect.DeepEqual(got, want) {
			t.Errorf("%s template (environment %q): CORS origins %v differ from a config with no environment %v", name, cfg.Environment, got, want)
		}
		for _, o := range getAllowedOrigins(&cfg) {
			if strings.Contains(o, "localhost") || strings.Contains(o, "127.0.0.1") {
				t.Errorf("%s template (environment %q) allows dev origin %q", name, cfg.Environment, o)
			}
		}

		// An operator-configured list is honoured, not replaced.
		cfg.Server.HTTP.AllowedOrigins = []string{"https://keyorix.example.com"}
		if got := getAllowedOrigins(&cfg); !reflect.DeepEqual(got, cfg.Server.HTTP.AllowedOrigins) {
			t.Errorf("%s template: configured origins not honoured, got %v", name, got)
		}
	}
}

// Calibration: the guard above is only meaningful because "development" really
// does relax CORS. If that ever stops being true this fails and the --dev label
// can be revisited.
func TestEnvironmentDevelopment_StillEnablesLocalhostOrigins(t *testing.T) {
	cfg := config.Config{Environment: "development"}
	got := getAllowedOrigins(&cfg)
	found := false
	for _, o := range got {
		if strings.Contains(o, "localhost") {
			found = true
		}
	}
	if !found {
		t.Fatalf("environment development no longer enables localhost origins (%v); update the --dev label rationale", got)
	}
}
