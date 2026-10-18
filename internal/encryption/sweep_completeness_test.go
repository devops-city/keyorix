package encryption

// sweep_completeness_test.go — regression test for backlog #425's structural
// concern: SweepAllTables (sweep.go/sweep_auth.go) is a hand-maintained list of
// individual sweepXxx calls, and nothing prevents a future developer from adding
// a new DEK-encrypted column to internal/storage/models WITHOUT also adding a
// corresponding sweep — silently re-introducing the exact shape of #422 (a
// DEK-rotation sweep gap that caused permanent, irrecoverable data loss for the
// tables it missed).
//
// There is no way to make Go statically verify "every DEK-encrypted column has a
// sweep" — encryption happens at the application layer, not via any type the
// compiler could check. Instead, this test parses every non-test .go file in
// internal/storage/models via go/ast (NOT a hardcoded list of model types, so a
// brand-new model struct is picked up automatically — only the discovered FIELD
// still has to match the naming convention below) for struct fields matching the
// naming convention every one of today's 7 DEK-encrypted columns follows: type
// []byte, name either "Encrypted*" or "*Enc". It then diffs that discovered set
// against expectedSweptFields, a hand-maintained map mirroring exactly what
// SweepAllTables sweeps today.
//
// This only catches a NEW column that follows the existing naming convention —
// it can't catch one that doesn't, or a coincidentally-named non-encrypted field
// (there are none today; see the exhaustive grep this test's PR description
// documents). Within that scope, though, it turns "a future developer forgot to
// add a sweep" from a silent, discovered-in-production data-loss bug into a
// failing test, at test time, with an actionable message pointing at exactly
// which field is unaccounted for.
import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// modelField identifies one struct field in internal/storage/models.
type modelField struct {
	Struct string
	Field  string
}

func (f modelField) String() string { return f.Struct + "." + f.Field }

// expectedSweptFields mirrors exactly what SweepAllTables (sweep.go's
// sweepSecretVersions + sweep_auth.go's sweepAPITokens/sweepAPIClients/
// sweepPasswordResets/sweepMFASecrets/sweepDynamicSecretConfigs/
// sweepDynamicSecretLeases/sweepNotificationChannels) re-encrypts today. Keep this in lockstep with
// SweepAllTables — that's the entire point of this test. Session has no entry:
// its EncryptedSessionToken/SessionTokenMetadata columns were dropped outright
// (#1641), not swept — the live write path only ever hashed session tokens,
// never encrypted them, so there was nothing for a sweep to re-encrypt.
var expectedSweptFields = map[modelField]bool{
	{"SecretVersion", "EncryptedValue"}:     true,
	{"APIToken", "EncryptedToken"}:          true,
	{"APIClient", "EncryptedClientSecret"}:  true,
	{"PasswordReset", "EncryptedToken"}:     true,
	{"MFASecret", "SecretEnc"}:              true,
	{"DynamicSecretConfig", "AdminDSNEnc"}:  true,
	{"DynamicSecretLease", "CredentialEnc"}: true,
	{"NotificationChannel", "URLEnc"}:       true,
}

// discoverEncryptedModelFields parses every non-test .go file in dir and
// returns every struct field matching the DEK-encrypted naming convention
// (see looksLikeEncryptedFieldName): type []byte, name "Encrypted*" or
// "*Enc" — the actual, current set of DEK-encrypted-looking model fields,
// derived from source rather than hand-maintained.
func discoverEncryptedModelFields(t *testing.T, dir string) map[modelField]bool {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("failed to read %s: %v", dir, err)
	}
	var goFiles []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		goFiles = append(goFiles, filepath.Join(dir, e.Name()))
	}
	if len(goFiles) == 0 {
		t.Fatalf("no .go files found under %s — did the models package move?", dir)
	}

	fset := token.NewFileSet()
	discovered := map[modelField]bool{}
	for _, path := range goFiles {
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("failed to parse %s: %v", path, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			ts, ok := n.(*ast.TypeSpec)
			if !ok {
				return true
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok || st.Fields == nil {
				return true
			}
			for _, f := range st.Fields.List {
				if !isByteSliceType(f.Type) {
					continue
				}
				for _, name := range f.Names {
					if looksLikeEncryptedFieldName(name.Name) {
						discovered[modelField{ts.Name.Name, name.Name}] = true
					}
				}
			}
			return true
		})
	}
	return discovered
}

// TestEncryptedModelFieldScannerDetectsNamingConvention is this guard's
// red-proof.
//
// TestSweepCompleteness_EveryEncryptedModelFieldHasASweep's own zero-result
// Fatal only catches a total collapse of discoverEncryptedModelFields. This
// guard exists specifically because of #422 — a DEK-rotation sweep gap that
// caused permanent, irrecoverable data loss — so the value here is the
// struct-field scan itself, not isByteSliceType or looksLikeEncryptedFieldName
// individually (those are simple, low-value checks to test in isolation; the
// interesting behavior is discoverEncryptedModelFields correctly combining
// them across every struct in a file). A real fixture: a model with a
// SomethingEnc []byte field, alongside fields that must NOT be swept up —
// wrong type, wrong name convention.
func TestEncryptedModelFieldScannerDetectsNamingConvention(t *testing.T) {
	dir := t.TempDir()
	// Parsed, never compiled: undefined identifiers are fine and deliberate.
	const src = `package models

type FooModel struct {
	ID int

	// SecretEnc is a real DEK-encrypted field, mirroring MFASecret.SecretEnc.
	SecretEnc []byte

	// EncryptedBar is a real DEK-encrypted field, mirroring the "Encrypted*" convention.
	EncryptedBar []byte

	// PlainBytes is []byte but follows no naming convention -- must not be found.
	PlainBytes []byte

	// NameEnc follows the naming convention but isn't []byte -- must not be found.
	NameEnc string
}
`
	if err := os.WriteFile(filepath.Join(dir, "foo_model.go"), []byte(src), 0o600); err != nil {
		t.Fatalf("writing the synthetic fixture: %v", err)
	}

	discovered := discoverEncryptedModelFields(t, dir)

	if !discovered[modelField{"FooModel", "SecretEnc"}] {
		t.Errorf("discoverEncryptedModelFields must find FooModel.SecretEnc; got %v", discovered)
	}
	if !discovered[modelField{"FooModel", "EncryptedBar"}] {
		t.Errorf("discoverEncryptedModelFields must find FooModel.EncryptedBar; got %v", discovered)
	}
	if discovered[modelField{"FooModel", "PlainBytes"}] {
		t.Errorf("discoverEncryptedModelFields found PlainBytes, a []byte field with no naming-convention "+
			"match — the scanner is no longer discriminating by name, got %v", discovered)
	}
	if discovered[modelField{"FooModel", "NameEnc"}] {
		t.Errorf("discoverEncryptedModelFields found NameEnc, a string field (not []byte) — the scanner is "+
			"no longer discriminating by type, got %v", discovered)
	}
	if len(discovered) != 2 {
		t.Errorf("expected exactly 2 discovered fields, got %d: %v", len(discovered), discovered)
	}
}

// TestSweepCompleteness_EveryEncryptedModelFieldHasASweep is the regression test
// described above.
func TestSweepCompleteness_EveryEncryptedModelFieldHasASweep(t *testing.T) {
	thisFile := filepath.Join(srcpath.PkgDir(), "sweep_completeness_test.go")
	modelsDir := filepath.Join(filepath.Dir(thisFile), "..", "storage", "models")

	discovered := discoverEncryptedModelFields(t, modelsDir)
	if len(discovered) == 0 {
		t.Fatal("discovered zero Encrypted*/*Enc []byte fields in internal/storage/models — the AST walk is almost certainly broken (models.go alone has several), not that encryption was removed")
	}

	var missing []modelField
	for f := range discovered {
		if !expectedSweptFields[f] {
			missing = append(missing, f)
		}
	}
	var stale []modelField
	for f := range expectedSweptFields {
		if !discovered[f] {
			stale = append(stale, f)
		}
	}
	sort.Slice(missing, func(i, j int) bool { return missing[i].String() < missing[j].String() })
	sort.Slice(stale, func(i, j int) bool { return stale[i].String() < stale[j].String() })

	if len(missing) > 0 {
		t.Errorf("found DEK-encrypted-looking field(s) in internal/storage/models NOT accounted for by this test's expectedSweptFields map: %v\n"+
			"Verify each one is actually re-encrypted by SweepAllTables (internal/encryption/sweep.go + sweep_auth.go) — if it's a genuinely new "+
			"DEK-encrypted column, add a sweepXxx call for it there (see #422 for what happens if you don't), then add it to expectedSweptFields "+
			"here. If it's a false positive (a []byte field that happens to match the naming convention but isn't DEK-encrypted), narrow the "+
			"looksLikeEncryptedFieldName heuristic instead.", missing)
	}
	if len(stale) > 0 {
		t.Errorf("expectedSweptFields lists field(s) no longer found (by name+type) in internal/storage/models — update this test's expected map: %v", stale)
	}
}

// isByteSliceType reports whether expr is exactly `[]byte` (an unsized array/slice
// of the builtin identifier "byte").
func isByteSliceType(expr ast.Expr) bool {
	arr, ok := expr.(*ast.ArrayType)
	if !ok || arr.Len != nil {
		return false
	}
	ident, ok := arr.Elt.(*ast.Ident)
	return ok && ident.Name == "byte"
}

// looksLikeEncryptedFieldName reports whether name follows the DEK-encrypted
// column naming convention every one of today's 7 tracked fields uses:
// EncryptedValue, EncryptedToken (x2), EncryptedClientSecret,
// SecretEnc, AdminDSNEnc, CredentialEnc.
func looksLikeEncryptedFieldName(name string) bool {
	return strings.HasPrefix(name, "Encrypted") || strings.HasSuffix(name, "Enc")
}
