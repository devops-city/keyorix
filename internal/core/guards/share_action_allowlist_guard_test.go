// share_action_allowlist_guard_test.go — the source-scanning part of the core
// half of the #3001 follow-up guard (a write share elevates ONLY update value,
// update metadata, rotate). The allowlist tests that need the SecretAction type
// and secretActionShareElevates stay in internal/core/share_action_allowlist_guard_test.go.
package guards

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecretActionAllowlist_OnlyTheShareTermReachesTheRawShareLookup(t *testing.T) {
	files, err := filepath.Glob("../*.go")
	require.NoError(t, err)
	callers := map[string]bool{}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		src, rerr := os.ReadFile(file) // #nosec G304 -- this package's own source files
		require.NoError(t, rerr)
		f, perr := parser.ParseFile(token.NewFileSet(), file, src, 0)
		require.NoError(t, perr)
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil && bodyCalls(fd.Body, "activeShareGrant") {
				callers[fd.Name.Name] = true
			}
		}
	}
	assert.Equal(t, map[string]bool{"sharePermissionFor": true, "shareCoversButNotElevated": true}, callers,
		"activeShareGrant ignores the action allowlist: only the share term (and the refusal explainer) may call it")
}
