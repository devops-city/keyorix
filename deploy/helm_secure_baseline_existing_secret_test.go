package deploy

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// secureBaseline.existingSecret (HELM-1): GitOps tools render with `helm
// template`, where `lookup` sees no cluster, so the generated certificates and
// token changed on every sync. With existingSecret set the chart must generate
// nothing: two renders are byte-identical, no -secure-baseline Secret is
// rendered, and every workload mounts the named Secret. Unset, the generated
// Secret is still rendered (secure by default, nothing weakened).
//
// What this does not cover: the required-key check, which needs `lookup` to see
// a Secret (helm install/upgrade). It is tested in
// helm_secure_baseline_lookup_test.go against a fake API server, with the limits
// stated there.

const byoSecretName = "my-baseline"

func helmTemplateRaw(t *testing.T, sets ...string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed -- skipping existingSecret check")
	}
	args := []string{"template", "kx", filepath.Join("..", "deploy", "helm", "keyorix"),
		"--set", "auth.masterPassword=x", "--set", "postgresql.auth.password=x"}
	for _, s := range sets {
		args = append(args, "--set", s)
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("helm", args...) //nolint:gosec // fixed binary, chart path and flags
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	return stdout.String() + stderr.String(), err
}

func TestHelmSecureBaselineExistingSecret_RenderIsDeterministicAndGeneratesNothing(t *testing.T) {
	sets := []string{"secureBaseline.enabled=true", "secureBaseline.existingSecret=" + byoSecretName,
		"auth.existingSecret=my-auth"}
	first, err := helmTemplateRaw(t, sets...)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, first)
	}
	second, err := helmTemplateRaw(t, sets...)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, second)
	}
	if first != second {
		t.Fatal("two renders with secureBaseline.existingSecret differ: something is still generated at render time")
	}
	for _, forbidden := range []string{"BEGIN CERTIFICATE", "BEGIN RSA PRIVATE KEY", "kx-keyorix-secure-baseline"} {
		if strings.Contains(first, forbidden) {
			t.Errorf("render with existingSecret contains %q: the chart must not generate or reference its own Secret", forbidden)
		}
	}
	// server, web and bundled postgres each mount the named Secret.
	if got := strings.Count(first, "secretName: "+byoSecretName); got != 3 {
		t.Errorf("secretName: %s appears %d times, want 3 (server, web, postgresql)", byoSecretName, got)
	}
	for _, d := range renderHelmDocs(t, sets...) {
		if d.Kind == "Secret" && d.Metadata.Name == byoSecretName {
			t.Errorf("chart rendered the Secret %s it was told already exists", byoSecretName)
		}
	}
}

// The control: unset, the chart still generates its own Secret and the pods
// mount it, and the render differs between runs (random) -- today's behaviour.
func TestHelmSecureBaselineGenerated_StillRenderedWithoutExistingSecret(t *testing.T) {
	a, err := helmTemplateRaw(t, "secureBaseline.enabled=true")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, a)
	}
	b, err := helmTemplateRaw(t, "secureBaseline.enabled=true")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, b)
	}
	if !strings.Contains(a, "name: kx-keyorix-secure-baseline") || !strings.Contains(a, "secretName: kx-keyorix-secure-baseline") {
		t.Error("without existingSecret the chart must render and mount its own -secure-baseline Secret")
	}
	if a == b {
		t.Error("two renders without existingSecret are identical: generation is no longer random (control is vacuous)")
	}
}

// Silently ignoring the value would leave the operator believing their
// certificates are in use while the baseline is off.
func TestHelmSecureBaselineExistingSecret_RequiresEnabled(t *testing.T) {
	out, err := helmTemplateRaw(t, "secureBaseline.enabled=false", "secureBaseline.existingSecret="+byoSecretName)
	if err == nil {
		t.Fatal("helm template succeeded with existingSecret set and secureBaseline.enabled=false")
	}
	if !strings.Contains(out, "secureBaseline.existingSecret is set but secureBaseline.enabled is false") {
		t.Errorf("unhelpful error:\n%s", out)
	}
}
