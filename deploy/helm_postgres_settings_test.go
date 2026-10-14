package deploy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// postgresql.settings (DB-TUNE-1) renders extra `postgres -c key=value` args for
// the bundled PostgreSQL, keeps the secureBaseline TLS args, and refuses any
// value that turns commit durability off: the audit row is committed before a
// secret is returned, so synchronous_commit, fsync and full_page_writes stay
// on whatever the values say. Checks the RENDERED Deployment; skips when helm
// is not installed, like the other chart tests (CI's chart jobs have it).
func TestHelmPostgresSettings(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed -- skipping chart postgresql.settings check")
	}
	chart := filepath.Join("..", "deploy", "helm", "keyorix")
	render := func(sets ...string) (string, error) {
		args := []string{"template", "kx", chart, "-s", "templates/postgresql.yaml",
			"--set", "auth.masterPassword=x", "--set", "postgresql.auth.password=x"}
		for _, s := range sets {
			args = append(args, "--set-string", s)
		}
		out, err := exec.Command("helm", args...).CombinedOutput() //nolint:gosec // fixed binary and chart path
		return string(out), err
	}

	out, err := render()
	if err != nil {
		t.Fatalf("helm template (defaults): %v\n%s", err, out)
	}
	if strings.Contains(out, "postgresql.settings") || !strings.Contains(out, "- ssl=on") {
		t.Fatalf("default render must keep only the secureBaseline args:\n%s", out)
	}

	out, err = render("postgresql.settings.shared_buffers=256MB", "postgresql.settings.wal_compression=lz4", "postgresql.settings.synchronous_commit=on")
	if err != nil {
		t.Fatalf("helm template (profile): %v\n%s", err, out)
	}
	for _, want := range []string{`- "shared_buffers=256MB"`, `- "wal_compression=lz4"`, `- "synchronous_commit=on"`, "- ssl=on"} {
		if !strings.Contains(out, want) {
			t.Errorf("profile render is missing %s:\n%s", want, out)
		}
	}

	for _, bad := range []string{
		"postgresql.settings.synchronous_commit=off",
		"postgresql.settings.fsync=off",
		"postgresql.settings.fsync=false",
		"postgresql.settings.full_page_writes=OFF",
		// PostgreSQL accepts boolean prefixes and surrounding blanks: an
		// allow-list, not a deny-list, decides.
		"postgresql.settings.fsync=of",
		"postgresql.settings.synchronous_commit=f",
		"postgresql.settings.full_page_writes=n",
		"postgresql.settings.synchronous_commit= off",
		"postgresql.settings.bad\\;key=1",
		// Settings appended after the secure baseline must not override it or run commands.
		"postgresql.settings.ssl=off",
		"postgresql.settings.ssl_cert_file=/tmp/x.crt",
		"postgresql.settings.ssl_min_protocol_version=TLSv1",
		"postgresql.settings.hba_file=/tmp/pg_hba.conf",
		"postgresql.settings.listen_addresses=0.0.0.0",
		"postgresql.settings.password_encryption=md5",
		"postgresql.settings.archive_command=sh",
	} {
		if out, err := render(bad); err == nil {
			t.Errorf("--set-string %s must refuse to render, got:\n%s", bad, out)
		}
	}

	// A whole number from a values file is a float to Helm; it must render as
	// an integer, not 1e+07.
	vf := filepath.Join(t.TempDir(), "values.yaml")
	if err := os.WriteFile(vf, []byte("postgresql:\n  settings:\n    max_wal_size: 10000000\n    synchronous_commit: on\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := exec.Command("helm", "template", "kx", chart, "-s", "templates/postgresql.yaml", //nolint:gosec // fixed binary and chart path
		"--set", "auth.masterPassword=x", "--set", "postgresql.auth.password=x", "-f", vf).CombinedOutput()
	if err != nil {
		t.Fatalf("helm template (values file): %v\n%s", err, raw)
	}
	if !strings.Contains(string(raw), `- "max_wal_size=10000000"`) || !strings.Contains(string(raw), `- "synchronous_commit=true"`) {
		t.Errorf("values-file render must print whole numbers as integers and YAML on as true:\n%s", raw)
	}
}
