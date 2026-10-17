// audit_durability_reachability_test.go — ADR-112 Amendments 1 and 3
// (docs/specs/fast-audit-mode.md) require storage.database.audit_durability,
// and its deprecated alias insecure_audit_skip_durable_sync, to be settable
// from the config FILE ONLY: no HTTP handler, no gRPC RPC, no environment
// variable and no CLI flag may change it. A compromised admin API must not be
// able to change an install's audit durability remotely -- the attack
// keyless_mode's own guard closes, so this mirrors
// keyless_mode_reachability_test.go.
//
// IDIOM-COMPLETENESS NOTE, per this repo's standing lesson ("an enumeration is
// only as complete as the idioms it knows about"). These tests recognise
// exactly TWO call shapes, and nothing else:
//
//  1. the literal Go selectors `.AuditDurability` and
//     `.InsecureAuditSkipDurableSync` (case-sensitive, whole identifier), with
//     // and /* */ comments STRIPPED first, so a doc comment that merely names
//     a field is not mistaken for a read of it;
//  2. environment-variable names mentioning the setting.
//
// Both are grepped across every non-test *.go file in the main module's repo
// tree. cli/ and operator/ are excluded for the same sound structural reason
// keyless_mode's scan excludes them: they are separate Go modules with their
// own go.mod, outside the root go.work, and cannot reference this package's
// DatabaseConfig type at all.
//
// What these tests would NOT see, stated so the gap reads as considered rather
// than overlooked: a refactor that copied a field out into a package-level var
// or a differently-named second field would be invisible to a grep -- that is
// the limit of a grep-based guard rather than a real dataflow analysis.
// Anyone doing that refactor must re-derive this list. It would also not catch
// a NEW env-var source added via config.resolveSecret, which only handles
// string credential fields; a new env helper would need its own entry in
// TestAuditDurability_NotSettableFromTheEnvironment below.
package config

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// auditDurabilityRawFieldAllowedFiles is the exhaustive, reasoned inventory of
// every non-test file OUTSIDE internal/config allowed to reference either raw
// field at all.
//
// IT IS DELIBERATELY EMPTY, and that is the invariant this file enforces.
// Every consumer (the storage factory, the start-up line, admin validate, the
// posture report, the settings diff, GET /system/info) reads
// DatabaseConfig.EffectiveAuditDurability, so the rule "which level is this
// install running at" -- backend default, alias mapping, SQLite strict-only --
// has ONE implementation. If a future file genuinely needs a raw field, add it
// here WITH the reason it cannot use EffectiveAuditDurability.
var auditDurabilityRawFieldAllowedFiles = map[string]string{}

// repoRootForFastAuditScan resolves the main module's repo root from this
// file's own location (internal/config/..), so the scan works regardless of
// the test runner's working directory.
func repoRootForFastAuditScan() string {
	thisFile := filepath.Join(srcpath.PkgDir(), "audit_durability_reachability_test.go")
	return filepath.Join(filepath.Dir(thisFile), "..", "..")
}

var fastAuditSelectorRe = regexp.MustCompile(`\.(AuditDurability|InsecureAuditSkipDurableSync)\b`)

// commentStripRe removes // line comments and /* */ block comments. Needed
// because this scan matches raw file bytes: internal/storage/store/entry.go
// legitimately NAMES the field in a doc comment ("set once at construction
// from config.DatabaseConfig.InsecureAuditSkipDurableSync") while reading only
// the computed status, and counting that as a reference would force a
// permanent allowlist entry for a file that does not actually touch the field.
// Crude by design -- it will also blank a // inside a string literal, which in
// this scan can only ever cause a MISSED match in a file that embeds the
// field's name in a string, and no such file exists (checked: the only string
// form anywhere is the YAML key, which has no leading dot and so never matches
// this selector regardless).
var commentStripRe = regexp.MustCompile(`(?s)//[^\n]*|/\*.*?\*/`)

func stripGoComments(data []byte) []byte {
	return commentStripRe.ReplaceAll(data, []byte(" "))
}

// walkMainModuleGoFiles calls fn(repoRelativeSlashPath, contents) for every
// non-test *.go file in the main module's tree.
func walkMainModuleGoFiles(t *testing.T, root string, fn func(rel string, data []byte)) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "cli", "operator":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, rerr := os.ReadFile(path) // #nosec G304 -- fixed test-time repo-tree walk, not user input
		if rerr != nil {
			return rerr
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		fn(filepath.ToSlash(rel), data)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
}

// TestAuditDurability_ReferencesAreAllowlisted is the completeness guard:
// every non-test file outside internal/config that references a raw field
// must have a reasoned allowlist entry, and every entry must still correspond
// to a real reference.
func TestAuditDurability_ReferencesAreAllowlisted(t *testing.T) {
	root := repoRootForFastAuditScan()
	actual := map[string]bool{}
	walkMainModuleGoFiles(t, root, func(rel string, data []byte) {
		if strings.HasPrefix(rel, "internal/config/") {
			// The fields' owning package: Load's deprecation line, Validate and
			// EffectiveAuditDurability are the legitimate reads.
			return
		}
		if fastAuditSelectorRe.Match(stripGoComments(data)) {
			actual[rel] = true
		}
	})

	var missing []string
	for path := range actual {
		if _, ok := auditDurabilityRawFieldAllowedFiles[path]; !ok {
			missing = append(missing, path)
		}
	}
	if len(missing) > 0 {
		t.Errorf("found file(s) OUTSIDE internal/config referencing the raw AuditDurability or "+
			"InsecureAuditSkipDurableSync field: %v\n"+
			"Read DatabaseConfig.EffectiveAuditDurability(storageType) instead: the raw fields do not know the "+
			"backend default (standard on PostgreSQL), the alias mapping, or that SQLite is strict only. If you "+
			"genuinely need a raw field, add a reasoned entry to auditDurabilityRawFieldAllowedFiles.", missing)
	}

	var stale []string
	for path := range auditDurabilityRawFieldAllowedFiles {
		if !actual[path] {
			stale = append(stale, path)
		}
	}
	if len(stale) > 0 {
		t.Errorf("allowlist entr(y/ies) no longer reference a raw audit durability field: %v -- remove them", stale)
	}
}

// TestAuditDurability_NoWriteAssignment is the security property: no
// assignment TO either field outside internal/config/config.go (where YAML
// unmarshal is the one legitimate write path). No HTTP handler, gRPC RPC or
// other Go code in the main module can change the level.
func TestAuditDurability_NoWriteAssignment(t *testing.T) {
	root := repoRootForFastAuditScan()
	writeRe := regexp.MustCompile(`\.(AuditDurability|InsecureAuditSkipDurableSync)\s*=[^=]`)

	walkMainModuleGoFiles(t, root, func(rel string, data []byte) {
		if rel == "internal/config/config.go" {
			return
		}
		if m := writeRe.Find(stripGoComments(data)); m != nil {
			t.Errorf("found what looks like a WRITE to an audit durability field outside "+
				"internal/config/config.go: %s: %q\n"+
				"ADR-112 Amendment 3 makes storage.database.audit_durability settable from the config FILE ONLY. "+
				"A test fixture belongs in a _test.go file (which this scan skips); production code doing this is "+
				"a remotely-reachable durability change and must not ship.", rel, m)
		}
	})
}

// TestAuditDurability_NotSettableFromTheEnvironment closes the other half of
// "config file only": no KEYORIX_* environment variable anywhere in the main
// module names the setting, and a config file that names neither key gets the
// backend default, nothing else.
func TestAuditDurability_NotSettableFromTheEnvironment(t *testing.T) {
	root := repoRootForFastAuditScan()
	envRe := regexp.MustCompile(`(?i)KEYORIX_[A-Z0-9_]*(AUDIT_SKIP|SKIP_DURABLE|DURABLE_SYNC|AUDIT_DURABILITY)[A-Z0-9_]*`)
	walkMainModuleGoFiles(t, root, func(rel string, data []byte) {
		if m := envRe.FindString(string(data)); m != "" {
			t.Errorf("%s introduces an environment variable %q for audit durability. ADR-112 scopes this setting "+
				"to the config FILE only; an env var is reachable from a container spec or a compromised "+
				"orchestrator without touching the audited config file.", rel, m)
		}
	})

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("storage:\n  type: local\n  database:\n    path: ./secrets.db\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Storage.Database.AuditDurability != "" || cfg.Storage.Database.InsecureAuditSkipDurableSync != nil {
		t.Fatalf("a config file that names neither key must leave both unset, got %q / %v",
			cfg.Storage.Database.AuditDurability, cfg.Storage.Database.InsecureAuditSkipDurableSync)
	}
	if got := cfg.Storage.Database.EffectiveAuditDurability(cfg.Storage.Type).Level; got != AuditDurabilityStrict {
		t.Fatalf("a SQLite config naming neither key must run strict, got %q", got)
	}
}
