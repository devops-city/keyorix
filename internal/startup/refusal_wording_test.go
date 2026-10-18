package startup

import (
	"os"
	"strings"
	"testing"
)

// BOOT-REFUSALS-1 "Misleading messages" items 1 and 2.

func explicitCheckConfig(t *testing.T) (configPath, dek, salt, dbPath string) {
	t.Helper()
	configPath, dek, salt, dbPath = adr112FirstBootConfig(t)
	body, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	writeConfig(t, configPath, string(body)+"security:\n  enable_file_permission_check: true\n")
	if err := os.Chmod(configPath, 0o600); err != nil {
		t.Fatal(err)
	}
	return configPath, dek, salt, dbPath
}

// Item 1: the refusal itself names the file and what is wrong with it, and the
// stage prefix is printed once (it used to read "file permission validation
// failed: file permission validation failed: ... unresolved issues", the cause
// only in an untimestamped [WARN] line above it).
func TestValidateStartup_PermissionRefusal_CarriesCauseOnce(t *testing.T) {
	configPath, dek, salt, dbPath := explicitCheckConfig(t)
	for p, mode := range map[string]os.FileMode{dek: 0o644, salt: 0o600, dbPath: 0o600} {
		if err := os.WriteFile(p, make([]byte, 64), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}
	_, err := ValidateStartup(configPath, false)
	if err == nil {
		t.Fatal("expected a 0644 wrapped DEK to be refused under an explicit enable_file_permission_check")
	}
	msg := err.Error()
	for _, want := range []string{"permissions or ownership audit found unresolved issues", dek, "has mode 644 but expected 600", "chmod"} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal %q does not contain %q", msg, want)
		}
	}
	if n := strings.Count(msg, "file permission validation failed"); n != 1 {
		t.Errorf("stage prefix printed %d times, want 1: %q", n, msg)
	}
}

// Item 2: an explicit true on a brand-new install (no key file, no database)
// still refuses (an unmounted key volume looks the same), but says so and what
// to do, instead of three "Cannot open file" lines.
func TestValidateStartup_ExplicitTrue_BrandNewInstall_SaysSo(t *testing.T) {
	configPath, dek, salt, _ := explicitCheckConfig(t)
	_, err := ValidateStartup(configPath, false)
	if err == nil {
		t.Fatal("an explicit enable_file_permission_check: true must keep refusing missing key material")
	}
	msg := err.Error()
	for _, want := range []string{"no key material exists", dek, salt, "set explicitly", "brand-new install", "remove security.enable_file_permission_check", "mount or restore"} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal %q does not contain %q", msg, want)
		}
	}
	if _, err := ValidateStartupTolerant(configPath, false); err == nil {
		t.Fatal("the tolerant variant must not relax an explicit setting")
	}
}

// With the database present it is not a first install: the audit names the
// missing key files instead.
func TestValidateStartup_ExplicitTrue_KeysMissingDatabasePresent_NamesFiles(t *testing.T) {
	configPath, dek, _, dbPath := explicitCheckConfig(t)
	if err := os.WriteFile(dbPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ValidateStartup(configPath, false)
	if err == nil {
		t.Fatal("expected missing key files to be refused")
	}
	msg := err.Error()
	if strings.Contains(msg, "brand-new install") {
		t.Errorf("a database exists, so the refusal must not suggest a first install: %q", msg)
	}
	if !strings.Contains(msg, "cannot open "+dek) {
		t.Errorf("refusal %q does not name the missing file %s", msg, dek)
	}
}
