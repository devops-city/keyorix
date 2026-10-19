// auth_budget_record_keyed_test.go — the source-scanning half of #2837 shape 2
// (FIX-2837B). The behavioural tests (TestBudgetRecord_*) need the core package
// and stay in internal/core/auth_budget_record_keyed_test.go.
package guards

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuthBudget_EveryStoredWriteIsKeyed is the class guard: no budget write in
// auth_budget.go may use the non-idempotent RecordLoginAttempt, which can be
// neither retried (a lost acknowledgement would count twice) nor left
// unretried (one transient error moves the attempt off the shared table). Every
// stored write goes through budgetWriteKeyed; ReserveLoginAttempt is called
// from nowhere else in the file. RecordLoginAttemptRelay (rate_limit.go) is not
// a budget write: it returns the storage error to its caller.
func TestAuthBudget_EveryStoredWriteIsKeyed(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "../auth_budget.go", nil, 0)
	require.NoError(t, err)
	reserveCallers := map[string]int{}
	var unkeyed []string
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !isStorageValue(sel.X) {
				return true
			}
			switch sel.Sel.Name {
			case "RecordLoginAttempt":
				unkeyed = append(unkeyed, fset.Position(call.Pos()).String()+" "+fd.Name.Name)
			case "ReserveLoginAttempt":
				reserveCallers[fd.Name.Name]++
			}
			return true
		})
	}
	assert.Empty(t, unkeyed, "auth_budget.go writes login_attempts through the non-idempotent RecordLoginAttempt: use budgetWriteKeyed")
	assert.Equal(t, map[string]int{"budgetWriteKeyed": 2}, reserveCallers,
		"ReserveLoginAttempt must be called only by budgetWriteKeyed (the write and its one same-key retry); "+
			"a zero here means this guard no longer recognises the write and would pass vacuously")
}
