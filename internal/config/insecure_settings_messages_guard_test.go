package config

// Guard for review point "remediation messages still name the old keys"
// (MERGE-MASTER, #2899): an operator-facing error/log string that tells someone
// to "set <old key>" sends them to a deprecated alias (which logs a warning).
// This scans every non-test Go string literal under internal/, server/ and cli/
// for the distinctive leaf of each deprecated alias and fails on a hit.
//
// Recognised: the old LEAF of every alias-table row whose leaf is specific
// enough to identify the setting (generic leaves such as "disabled" are skipped:
// they are indistinguishable from unrelated keys). A leaf matches as a whole
// word, so the new insecure_allow_... names, which contain some old leaves as
// substrings, do not trip it. NOT checked: comments (they may legitimately cite
// the old name), docs, and string literals in _test.go files; a literal that says
// "deprecated alias" is allowed to cite the old name. The files that
// DEFINE the aliases are exempt.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var messageGuardExempt = map[string]bool{
	"insecure_settings_aliases.go":  true, // the alias table itself
	"insecure_settings_registry.go": true, // records DeprecatedAlias for each entry
}

func oldLeafPatterns() map[string]*regexp.Regexp {
	pats := map[string]*regexp.Regexp{}
	for _, a := range deprecatedSettingAliases {
		segs := strings.Split(a.OldPath, ".")
		leaf := segs[len(segs)-1]
		if !strings.Contains(leaf, "allow_") && !strings.Contains(leaf, "keyless") && !strings.Contains(leaf, "trust_asserted") {
			continue
		}
		pats[leaf] = regexp.MustCompile(`(^|[^A-Za-z0-9_])` + regexp.QuoteMeta(leaf) + `([^A-Za-z0-9_]|$)`)
	}
	return pats
}

func offendingLiterals(t *testing.T, root string, pats map[string]*regexp.Regexp) []string {
	t.Helper()
	var hits []string
	fset := token.NewFileSet()
	for _, dir := range []string{"internal", "server", "cli"} {
		_ = filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") || messageGuardExempt[filepath.Base(p)] {
				return nil
			}
			f, perr := parser.ParseFile(fset, p, nil, 0)
			if perr != nil {
				return nil
			}
			ast.Inspect(f, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				if strings.Contains(lit.Value, "deprecated alias") {
					return true // deliberately cites the old name as the alias
				}
				for leaf, re := range pats {
					if re.MatchString(lit.Value) {
						hits = append(hits, fset.Position(lit.Pos()).String()+" names deprecated key "+leaf)
					}
				}
				return true
			})
			return nil
		})
	}
	return hits
}

func TestOperatorMessagesDoNotNameDeprecatedSettingKeys(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repo root not found at %s: %v", root, err)
	}
	pats := oldLeafPatterns()
	if len(pats) < 9 {
		t.Fatalf("guard is vacuous: only %d distinctive deprecated leaves recognised", len(pats))
	}
	for _, h := range offendingLiterals(t, root, pats) {
		t.Errorf("%s: operator-facing text must name the CURRENT insecure_ key (the old one is a deprecated alias)", h)
	}
}

// Red control: the scan must actually fire on a planted old-key message.
func TestOperatorMessagesGuard_CatchesPlantedOldKey(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "internal", "x"), 0o750); err != nil {
		t.Fatal(err)
	}
	src := "package x\nvar bad = \"set dynamic_secrets.allow_private_network_targets: true\"\nvar good = \"set dynamic_secrets.insecure_allow_private_network_dynamic_secret_targets: true\"\n"
	if err := os.WriteFile(filepath.Join(dir, "internal", "x", "x.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	hits := offendingLiterals(t, dir, oldLeafPatterns())
	if len(hits) != 1 || !strings.Contains(hits[0], "allow_private_network_targets") {
		t.Fatalf("want exactly the planted old-key literal flagged, got %v", hits)
	}
}
