package deploy

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// HELM-AUDIT-DURABILITY: the chart's auditDurability lands in the server config as
// storage.database.audit_durability, is absent by default (backend default), and any
// value other than strict|standard fails the render (values.schema.json).
// Skips when helm is not installed, like the other chart tests; CI's chart jobs have it.
func TestHelmAuditDurability(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed -- skipping chart server-config check")
	}
	chart := filepath.Join("..", "deploy", "helm", "keyorix")
	render := func(extra ...string) (string, error) {
		args := append([]string{"template", "kx", chart, "-s", "templates/server-config.yaml",
			"--set", "auth.masterPassword=x", "--set", "postgresql.auth.password=x"}, extra...)
		out, err := exec.Command("helm", args...).CombinedOutput() //nolint:gosec // fixed binary and chart path
		return string(out), err
	}

	t.Run("default leaves it unset", func(t *testing.T) {
		out, err := render()
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		if strings.Contains(out, "audit_durability") {
			t.Errorf("default values must not set audit_durability:\n%s", out)
		}
	})
	for _, level := range []string{"strict", "standard"} {
		t.Run(level+" reaches storage.database", func(t *testing.T) {
			out, err := render("--set", "auditDurability="+level)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			want := `audit_durability: "` + level + `"`
			if !strings.Contains(out, want) {
				t.Fatalf("rendered server config lacks %q:\n%s", want, out)
			}
			i, j := strings.Index(out, "      database:"), strings.Index(out, "audit_durability:")
			k := strings.Index(out, "      encryption:")
			if i < 0 || j < i || k < j {
				t.Errorf("audit_durability must sit under storage.database:\n%s", out)
			}
		})
	}
	t.Run("an invalid value fails the render", func(t *testing.T) {
		out, err := render("--set", "auditDurability=relaxed")
		if err == nil {
			t.Fatalf("auditDurability=relaxed must fail the render:\n%s", out)
		}
		if !strings.Contains(out, "auditDurability") {
			t.Errorf("failure should name auditDurability:\n%s", out)
		}
	})
}
