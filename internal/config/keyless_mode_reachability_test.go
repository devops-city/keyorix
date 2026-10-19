// keyless_mode_reachability_test.go — docs/design-b2-recover-admin.md §5's
// own adversarial-review checklist item: "a grep-based guard test
// enumerating every code path that can reach this config value" — so that
// no HTTP handler and no gRPC RPC can ever set
// RecoverAdminConfig.KeylessMode, closing the specific attack design §5
// calls out: an attacker who has compromised the admin API silently
// downgrading the install's security by flipping this remotely.
//
// Idiom-completeness note (this repo's own standing lesson, CLAUDE.md: "An
// enumeration is only as complete as the idioms it knows about"): this test
// recognizes exactly ONE call shape — the literal Go selector `.KeylessMode`
// (case-sensitive), grepped across every non-test *.go file in the main
// module's repo tree (cli/ and operator/ are separate Go modules with their
// own go.mod, excluded — see repoRootForKeylessModeScan's own doc comment
// for why that's a sound exclusion here, not a blind spot like the ones
// this same lesson has caught before). A future refactor that renames the
// field, embeds RecoverAdminConfig anonymously (making the selector just
// `.KeylessMode` on a DIFFERENT outer type, still caught) or, more
// dangerously, copies the bool out into a package-level var or a second
// struct field under a different name, would be INVISIBLE to this scan —
// exactly the failure mode a "grep-based guard," not a real dataflow
// analysis, cannot close. Anyone doing that refactor should re-derive this
// list, not assume the guard still covers it.
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

// keylessModeAllowedFiles is the exhaustive, reasoned inventory of every
// non-test file allowed to reference KeylessMode at all — every one of them
// only ever READS it (`cfg.Security.RecoverAdmin.KeylessMode` on the
// right-hand side of `:=`, `if`, or a struct-literal field value); none
// assigns TO it. A file appearing here that turns out to WRITE it fails
// TestKeylessMode_NoWriteAssignment below, independent of this allowlist.
//
// internal/config/config.go itself is deliberately NOT in this list: the
// field's own DECLARATION (KeylessMode bool `yaml:"keyless_mode"`) has no
// leading dot, so the `.KeylessMode` selector this scan looks for never
// matches it — it is found (and specially exempted, as the one legitimate
// write path via ordinary YAML unmarshal) only by
// TestKeylessMode_NoWriteAssignment's own separate file-path check below,
// not by this allowlist.
var keylessModeAllowedFiles = map[string]string{
	"server/main.go": "reads it once at server startup (only) to print the repeated-every-boot warning and " +
		"write the startup audit event (docs/design-b2-recover-admin.md §5) — never writes it.",
	"server/http/handlers/system.go": "reads it once to populate SecurityInfo.KeylessRecoveryMode for the " +
		"authenticated GET /system/info response — never writes it. This is the one HTTP handler that touches " +
		"the field AT ALL, and it is read-only by construction (a http.HandlerFunc closure over an already-loaded " +
		"*config.Config, no request body ever reaches this value).",
	"server/admin/recover_admin.go": "reads it once, after config.Load, to decide whether --recovery-key/stdin " +
		"are required for THIS invocation of the offline, host-side `recover-admin` CLI command — never writes " +
		"it. No HTTP or gRPC transport is involved in reaching this code path at all (ADR-108 §B: no admin " +
		"command starts a network listener).",
	"server/admin/diagnose.go": "reads it once in diagnoseRecoveryKey, after config.Load, to report [SKIP] " +
		"instead of [WARN] for a missing recovery key on keyless-mode installs, inside the offline, host-side " +
		"`diagnose` CLI command -- never writes it. No HTTP or gRPC transport reaches this code path (ADR-108 " +
		"section B: no admin command starts a network listener).",
	"internal/config/insecure_settings_registry.go": "reads it once (inside the registry's InEffect/Value " +
		"closures for the insecure_keyless_admin_recovery entry, ADR-112 opt-out rule item 2) to decide " +
		"whether this setting is in effect, for the start-up warning loop and the settings-diff audit -- " +
		"never writes it. No HTTP or gRPC transport is involved: these closures only ever run from " +
		"server/main.go's own startup code, over an already-loaded *config.Config.",
}

// repoRootForKeylessModeScan resolves the main module's repo root from this
// test file's own location (internal/config/..), NOT the cli/ or operator/
// submodules — both are separate Go modules (their own go.mod, excluded
// from the root go.work) that cannot import internal/config's
// RecoverAdminConfig type at all (Go modules don't share unexported/
// internal packages across module boundaries without an explicit
// replace/require, which neither uses), so a config value defined in this
// package is structurally unreachable from either submodule regardless of
// what a grep there would or wouldn't find.
func repoRootForKeylessModeScan() string {
	thisFile := filepath.Join(srcpath.PkgDir(), "keyless_mode_reachability_test.go")
	return filepath.Join(filepath.Dir(thisFile), "..", "..")
}

var keylessModeSelectorRe = regexp.MustCompile(`\.KeylessMode\b`)

// findKeylessModeReferences scans every non-test *.go file in root for the
// literal `.KeylessMode` selector, returning repo-root-relative paths.
func findKeylessModeReferences(t *testing.T, root string) map[string]bool {
	t.Helper()
	found := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			base := d.Name()
			if base == ".git" || base == "node_modules" || base == "cli" || base == "operator" {
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
		if !keylessModeSelectorRe.Match(data) {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		found[filepath.ToSlash(rel)] = true
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return found
}

// TestKeylessMode_ReferencesAreAllowlisted is the completeness guard: every
// non-test file that references KeylessMode at all must be in
// keylessModeAllowedFiles, with a reasoned entry — and every entry must
// still correspond to a real reference, so a future removal doesn't leave a
// stale "reviewed as safe" claim about code that no longer exists.
func TestKeylessMode_ReferencesAreAllowlisted(t *testing.T) {
	root := repoRootForKeylessModeScan()
	actual := findKeylessModeReferences(t, root)

	var missing []string
	for path := range actual {
		if _, ok := keylessModeAllowedFiles[path]; !ok {
			missing = append(missing, path)
		}
	}
	if len(missing) > 0 {
		t.Errorf("found file(s) referencing KeylessMode with NO allowlist entry in keylessModeAllowedFiles "+
			"(internal/config/keyless_mode_reachability_test.go): %v\n"+
			"Every new reference must be a reasoned entry there — especially if it's an HTTP handler or gRPC "+
			"service, which must never set this field.", missing)
	}

	var stale []string
	for path := range keylessModeAllowedFiles {
		if !actual[path] {
			stale = append(stale, path)
		}
	}
	if len(stale) > 0 {
		t.Errorf("keylessModeAllowedFiles entr(y/ies) no longer reference KeylessMode: %v\n"+
			"Remove the stale entry — it's either been refactored away or the reference moved elsewhere.", stale)
	}
}

// TestKeylessMode_NoWriteAssignment asserts that among every reference this
// scan finds, NONE is a Go assignment TO the field (`.KeylessMode = `,
// `.KeylessMode: ` in a struct literal building THIS type, `&cfg...KeylessMode`
// taken for a pointer write) outside internal/config's own YAML-unmarshal
// path. This is the actual security property design §5 asks for: no HTTP
// handler, no gRPC RPC, no other Go code anywhere in the main module can
// ever SET this value — only read it.
func TestKeylessMode_NoWriteAssignment(t *testing.T) {
	root := repoRootForKeylessModeScan()
	writeRe := regexp.MustCompile(`\.KeylessMode\s*[:=]\s*(?:true|false|[A-Za-z_][A-Za-z0-9_.]*)\s*[,}\n]`)

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			base := d.Name()
			if base == ".git" || base == "node_modules" || base == "cli" || base == "operator" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		relSlash := filepath.ToSlash(rel)
		if relSlash == "internal/config/config.go" {
			return nil // the field's own definition; a struct-tag line matches the same regex harmlessly
		}
		data, rerr := os.ReadFile(path) // #nosec G304 -- fixed test-time repo-tree walk, not user input
		if rerr != nil {
			return rerr
		}
		if m := writeRe.FindString(string(data)); m != "" {
			t.Errorf("found what looks like a WRITE to KeylessMode outside internal/config/config.go: %s: %q\n"+
				"If this is a legitimate new write path, it needs its own explicit review and a name change to "+
				"this test explaining why a non-config-loading write is safe — do not just widen the regex.",
				relSlash, strings.TrimSpace(m))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
}
