// share_secret_isgroup_guard_test.go — #3422 (AUTHZ-GUARDS-1): core.ShareSecret has no
// group-scope check (ShareSecretWithGroup's IsGroupProjectScoped is the only one), so no
// caller may hand it a group recipient. Core itself now refuses IsGroup
// (TestKeyorixCore_ShareSecret_RejectsGroupShare); this guard stops a caller from being
// written that way in the first place, which would otherwise only show up as a runtime
// refusal in the one transport that got it wrong.
//
// Population, derived: every call `<x>.ShareSecret(ctx, req)` in the root module's
// non-test code outside the storage layer and generated stubs, and every
// ShareSecretRequest composite literal. Recognised forms: the request is a
// `&core.ShareSecretRequest{...}` literal whose IsGroup is absent or the identifier
// `false`. Anything else (a variable, a function result, `IsGroup: req.IsGroup`) is
// reported, because the guard cannot prove it is not a group share; route such a caller
// through ShareSecretWithGroup or make the literal explicit.
//
// What it does NOT cover: a request built in one function and passed through another
// (reported as opaque, not followed), and the cli module (it speaks HTTP only).
package http

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// shareSecretViolations inspects f and returns the callers that may pass a group share,
// plus the number of ShareSecret calls it saw (for calibration).
func shareSecretViolations(fset *token.FileSet, rel string, f *ast.File) (bad []string, calls int) {
	isShareReqType := func(e ast.Expr) bool {
		switch t := e.(type) {
		case *ast.SelectorExpr:
			return t.Sel.Name == "ShareSecretRequest"
		case *ast.Ident:
			return t.Name == "ShareSecretRequest"
		}
		return false
	}
	at := func(p token.Pos) string { return rel + ":" + strconv.Itoa(fset.Position(p).Line) }

	// IsGroup must be absent or literally false in every ShareSecretRequest literal.
	ast.Inspect(f, func(n ast.Node) bool {
		cl, ok := n.(*ast.CompositeLit)
		if !ok || !isShareReqType(cl.Type) {
			return true
		}
		for _, el := range cl.Elts {
			kv, ok := el.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "IsGroup" && !isIdentNamed(kv.Value, "false") {
				bad = append(bad, at(kv.Pos())+": ShareSecretRequest.IsGroup is not literally false; "+
					"group shares go through ShareSecretWithGroup (#3422)")
			}
		}
		return true
	})
	// Every ShareSecret call must pass a visible literal (so the check above applies to it).
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "ShareSecret" || len(call.Args) != 2 {
			return true
		}
		calls++
		if u, ok := call.Args[1].(*ast.UnaryExpr); ok && u.Op == token.AND {
			if cl, ok := u.X.(*ast.CompositeLit); ok && isShareReqType(cl.Type) {
				return true
			}
		}
		bad = append(bad, at(call.Pos())+": ShareSecret is called with a request this guard cannot see "+
			"(not an inline &core.ShareSecretRequest{...}); pass a literal with IsGroup omitted/false (#3422)")
		return true
	})
	return bad, calls
}

func TestNoShareSecretCaller_PassesIsGroup(t *testing.T) {
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	var bad []string
	calls, scanned := 0, 0
	require.NoError(t, filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if skipSecretACLDir(root, path, d) {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		f, perr := parser.ParseFile(fset, path, nil, 0)
		require.NoError(t, perr, rel)
		scanned++
		b, c := shareSecretViolations(fset, rel, f)
		bad = append(bad, b...)
		calls += c
		return nil
	}))
	require.Greater(t, scanned, 500, "calibration: walk saw %d files", scanned)
	assert.GreaterOrEqual(t, calls, 2, "calibration: the HTTP and gRPC transports each call core.ShareSecret; saw %d", calls)
	sort.Strings(bad)
	for _, msg := range bad {
		t.Error(msg)
	}
}

func TestShareSecretIsGroupGuard_DetectorSelfTest(t *testing.T) {
	check := func(src string) []string {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "x.go", src, 0)
		require.NoError(t, err)
		bad, _ := shareSecretViolations(fset, "x.go", f)
		return bad
	}
	assert.Empty(t, check(`package p
func f() { s.core.ShareSecret(ctx, &core.ShareSecretRequest{SecretID: 1, IsGroup: false}) }`), "explicit false is green")
	assert.Empty(t, check(`package p
func f() { s.core.ShareSecret(ctx, &core.ShareSecretRequest{SecretID: 1}) }`), "omitted IsGroup is green")
	assert.NotEmpty(t, check(`package p
func f() { s.core.ShareSecret(ctx, &core.ShareSecretRequest{SecretID: 1, IsGroup: true}) }`), "IsGroup: true is red")
	assert.NotEmpty(t, check(`package p
func f() { s.core.ShareSecret(ctx, &core.ShareSecretRequest{SecretID: 1, IsGroup: req.IsGroup}) }`), "forwarding the wire flag is red")
	assert.NotEmpty(t, check(`package p
func f() { r := build(); s.core.ShareSecret(ctx, r) }`), "an opaque request is red")
}
