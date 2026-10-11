package deploy

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/keyorixhq/keyorix/internal/config"
)

// SECURE-DEFAULT-1 (ADR-112 §4): the secure-baseline compose config has no
// insecure_* setting in effect, and once the compose pins move past the last
// release that cannot run it, the stock compose must be the secure one.
//
// What this does not cover: that the stack boots and that `admin validate
// --posture` (which also reads the database and the files on disk) reports
// zero deviations on the running stack. That was verified on the e2e VM; see
// the PR. scripts/demo/check.sh --postgres runs the stack this way.

// lastReleaseWithoutSecureBaseline is the newest release whose backend image
// cannot run keyorix.docker.secure.yaml (no metrics_token_file, no entrypoint
// steps).
const lastReleaseWithoutSecureBaseline = "0.95.3"

// insecureInEffect loads path through the server's own loader and returns the
// InsecureSettingsRegistry entries in effect, the same loop admin validate
// --posture runs (collectInsecureSettingsPosture).
func insecureInEffect(t *testing.T, path string) []string {
	t.Helper()
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("config.Load(%s): %v", path, err)
	}
	var in []string
	for _, s := range config.InsecureSettingsRegistry {
		if s.InEffect(cfg) {
			in = append(in, s.Name+"="+s.Value(cfg))
		}
	}
	return in
}

// withLocalTokenFile copies a container config into a temp dir, pointing its
// metrics_token_file (an absolute in-container path) at a real 0600 file: an
// unreadable token file counts as "no token" by design.
func withLocalTokenFile(t *testing.T, repoFile, containerTokenPath string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", repoFile)) // #nosec G304 -- fixed repo-relative name
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), containerTokenPath) {
		t.Fatalf("%s does not reference %s; the check would not exercise the token file", repoFile, containerTokenPath)
	}
	dir := t.TempDir()
	token := filepath.Join(dir, "metrics_token")
	if err := os.WriteFile(token, []byte("test-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "keyorix.yaml")
	if err := os.WriteFile(out, []byte(strings.ReplaceAll(string(raw), containerTokenPath, token)), 0o600); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestComposeSecureConfig_NoInsecureSettingInEffect(t *testing.T) {
	path := withLocalTokenFile(t, "keyorix.docker.secure.yaml", "/app/tls/metrics_token")
	if in := insecureInEffect(t, path); len(in) > 0 {
		t.Fatalf("keyorix.docker.secure.yaml has insecure settings in effect: %v", in)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Server.HTTP.TLS.Enabled || !cfg.Security.RequireTransportTLS {
		t.Fatal("keyorix.docker.secure.yaml must serve and require TLS")
	}
	if !cfg.Security.EnableFilePermissionCheck || !cfg.Security.EnableFilePermissionCheckImplicitDefault {
		t.Fatal("keyorix.docker.secure.yaml must leave enable_file_permission_check on its implicit default (see TestShippedComposeConfig_FilePermissionCheckIsOn)")
	}
}

// The control: the stock compose config (pinned release) still has the three
// deviations, so the test above is not vacuously green.
func TestComposeStockConfig_StillHasTheThreeDeviations(t *testing.T) {
	abs, err := filepath.Abs(filepath.Join("..", "keyorix.docker.yaml")) // config.Load refuses a ".." path
	if err != nil {
		t.Fatal(err)
	}
	in := strings.Join(insecureInEffect(t, abs), " ")
	for _, want := range []string{
		"security.insecure_allow_cleartext_transport",
		"server.insecure_allow_unauthenticated_metrics",
		"server.insecure_disable_api_ratelimit",
	} {
		if !strings.Contains(in, want) {
			t.Errorf("stock keyorix.docker.yaml no longer reports %s; if it was hardened, update this control and TestComposeSecureBaselineFoldedAfterRelease", want)
		}
	}
}

// TestComposeSecureBaselineFoldedAfterRelease is the premise guard for the
// override: docker-compose.secure.yml exists only because the pinned images
// predate the secure baseline. The release bump that moves the pins past
// lastReleaseWithoutSecureBaseline must fold it into docker-compose.yml and
// keyorix.docker.yaml (RELEASING.md), or this fails.
func TestComposeSecureBaselineFoldedAfterRelease(t *testing.T) {
	pins := composePinRE.FindAllStringSubmatch(readRepoFile(t, "docker-compose.yml"), -1)
	if len(pins) == 0 {
		t.Fatal("no ghcr.io/keyorixhq image pins in docker-compose.yml; the check would be vacuous")
	}
	for _, p := range pins {
		if !versionAfter(t, p[2], lastReleaseWithoutSecureBaseline) {
			t.Skipf("docker-compose.yml pins %s:%s, which predates the secure baseline; docker-compose.secure.yml carries it until the next release", p[1], p[2])
		}
	}
	if _, err := os.Stat(filepath.Join("..", "docker-compose.secure.yml")); err == nil {
		t.Error("the compose pins are past v" + lastReleaseWithoutSecureBaseline + ": fold docker-compose.secure.yml into docker-compose.yml and delete it (RELEASING.md)")
	}
	if in := insecureInEffect(t, withLocalTokenFile(t, "keyorix.docker.yaml", "/app/tls/metrics_token")); len(in) > 0 {
		t.Errorf("the compose pins are past v%s but keyorix.docker.yaml still has insecure settings in effect: %v", lastReleaseWithoutSecureBaseline, in)
	}
}

var semverRE = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)$`)

// versionAfter reports whether semver a > b (X.Y.Z only).
func versionAfter(t *testing.T, a, b string) bool {
	t.Helper()
	pa, pb := semverRE.FindStringSubmatch(a), semverRE.FindStringSubmatch(b)
	if pa == nil || pb == nil {
		t.Fatalf("not an X.Y.Z version: %q / %q", a, b)
	}
	for i := 1; i <= 3; i++ {
		x, _ := strconv.Atoi(pa[i])
		y, _ := strconv.Atoi(pb[i])
		if x != y {
			return x > y
		}
	}
	return false
}

// renderHelmServerConfig renders the chart's server keyorix.yaml with extra
// --set flags, its metrics_token_file pointed at a real 0600 file.
func renderHelmServerConfig(t *testing.T, sets ...string) string {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed -- skipping chart config check")
	}
	args := []string{"template", "kx", filepath.Join("..", "deploy", "helm", "keyorix"), "-s", "templates/server-config.yaml",
		"--set", "auth.masterPassword=x", "--set", "postgresql.auth.password=x"}
	for _, s := range sets {
		args = append(args, "--set", s)
	}
	out, err := exec.Command("helm", args...).CombinedOutput() //nolint:gosec // fixed binary, chart path and flags
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	var cm struct {
		Data map[string]string `yaml:"data"`
	}
	if err := yaml.Unmarshal(out, &cm); err != nil {
		t.Fatal(err)
	}
	body, ok := cm.Data["keyorix.yaml"]
	if !ok {
		t.Fatalf("server ConfigMap has no keyorix.yaml: %s", out)
	}
	dir := t.TempDir()
	token := filepath.Join(dir, "metrics_token")
	if err := os.WriteFile(token, []byte("test-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "keyorix.yaml")
	if err := os.WriteFile(p, []byte(strings.ReplaceAll(body, "/app/run/tls/metrics_token", token)), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestHelmSecureConfig_NoInsecureSettingInEffect(t *testing.T) {
	path := renderHelmServerConfig(t, "secureBaseline.enabled=true")
	if in := insecureInEffect(t, path); len(in) > 0 {
		t.Fatalf("chart with secureBaseline.enabled=true has insecure settings in effect: %v", in)
	}
}

// The control: secureBaseline off (today's default) still has the deviations,
// including the bundled PostgreSQL's ssl_mode: disable.
func TestHelmDefaultConfig_StillHasTheDeviations(t *testing.T) {
	in := strings.Join(insecureInEffect(t, renderHelmServerConfig(t)), " ")
	for _, want := range []string{
		"security.insecure_allow_cleartext_transport",
		"server.insecure_allow_unauthenticated_metrics",
		"server.insecure_disable_api_ratelimit",
		"storage.database.insecure_disable_database_tls",
	} {
		if !strings.Contains(in, want) {
			t.Errorf("chart default no longer reports %s; if it was hardened, update this control and TestHelmSecureBaselineOnByDefaultAfterRelease", want)
		}
	}
}

// TestHelmSecureBaselineOnByDefaultAfterRelease is the chart's premise guard:
// secureBaseline defaults to off only because the chart's appVersion image
// predates it. Once appVersion moves past lastReleaseWithoutSecureBaseline the
// default must be on (RELEASING.md).
func TestHelmSecureBaselineOnByDefaultAfterRelease(t *testing.T) {
	var chart struct {
		AppVersion string `yaml:"appVersion"`
	}
	if err := yaml.Unmarshal([]byte(readRepoFile(t, "deploy/helm/keyorix/Chart.yaml")), &chart); err != nil {
		t.Fatal(err)
	}
	var values struct {
		SecureBaseline struct {
			Enabled bool `yaml:"enabled"`
		} `yaml:"secureBaseline"`
	}
	if err := yaml.Unmarshal([]byte(readRepoFile(t, "deploy/helm/keyorix/values.yaml")), &values); err != nil {
		t.Fatal(err)
	}
	if !versionAfter(t, strings.TrimPrefix(chart.AppVersion, "v"), lastReleaseWithoutSecureBaseline) {
		t.Skipf("chart appVersion %s predates the secure baseline; secureBaseline.enabled stays opt-in until the next release", chart.AppVersion)
	}
	if !values.SecureBaseline.Enabled {
		t.Errorf("chart appVersion %s is past v%s: set secureBaseline.enabled: true in values.yaml (RELEASING.md)", chart.AppVersion, lastReleaseWithoutSecureBaseline)
	}
}
