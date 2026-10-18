package core

// project_child_liveness_guard_test.go — the default-ci half of #2702, #2710,
// #2711 and #2712, so the fix is guarded in the DSN-less CI leg too (the four
// TestCTAReview_*_vs_DeleteProject_CrossReplicaPostgres tests are the
// behavioural proof and need real Postgres).
//
// It asserts the shape, not the behaviour: each of the four writers must do its
// child write and a project re-check inside ONE transaction. The ordering within
// that transaction — write first, then check — is what makes it sound, and this
// guard deliberately does not try to assert it: an AST walk that claimed to
// verify statement order across a closure boundary would be asserting more than
// it checks. The Postgres tests are what prove the ordering, by failing when the
// check is neutered.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/require"
)

// projectChildWriters is every entry point that creates or revives a row whose
// parent is a project, together with where its project re-check must live.
//
// How this list was derived, rather than asserted: DeleteProject's cascade
// (deleteProjectCascade, internal/storage/store/local_secrets.go) sweeps exactly
// three child tables — secret_nodes, environments, and dynamic_secret_configs
// (disabled, not soft-deleted). So the population is every writer that can make
// a row in one of those three live while the project is being deleted:
//
//   - secret_nodes: core.CreateSecret, core.CreateFolder (both insert), and
//     LocalStorage.RestoreSecret (clears deleted_at). core.RestoreFolder does not
//     exist; folders are restored through RestoreSecret, the same SecretNode row.
//     core.ResumeSecret (#2794) flips status suspended -> active: DeleteEnvironment
//     counts only active secrets, so a suspended one is no barrier, and resuming
//     inside a deleted environment/project would leave a live secret under a dead
//     parent. It is not an insert or an un-delete, but it is the same
//     "make a swept row live" write.
//   - environments: core.CreateEnvironment (insert) and
//     LocalStorage.RestoreEnvironment (clears deleted_at — already fixed by
//     #2656 and included here so a regression there is caught by the same guard).
//     seedProjectEnvironment is excluded: it runs inside the transaction that
//     just created the project, so there is no deleted-parent window.
//   - dynamic_secret_configs: the cascade DISABLES rather than deletes, and
//     IssueLease/RenewLease refuse against a disabled config, so a config created
//     in the window is inert rather than live-under-a-dead-parent. Excluded
//     deliberately, not overlooked — if the cascade ever starts soft-deleting
//     them, CreateDynamicSecretConfig belongs on this list.
//
// RestoreProject itself is NOT here: it is the parent, and its own race with a
// re-issued DeleteProject is #2723/#2724, a different shape (the cascade's
// FOR UPDATE matches nothing when the project row is already deleted).
var projectChildWriters = []struct {
	file, recvType, fn string
}{
	{"secrets.go", "KeyorixCore", "CreateSecret"},
	{"secrets.go", "KeyorixCore", "CreateFolder"},
	{"secret_suspend.go", "KeyorixCore", "ResumeSecret"},
	{"catalog.go", "KeyorixCore", "CreateEnvironment"},
	{"../storage/store/local_secrets.go", "LocalStorage", "RestoreSecret"},
	{"../storage/store/local_secrets.go", "LocalStorage", "RestoreEnvironment"},
}

// projectLivenessCheckNames are the two spellings of the re-check: the exported
// Storage method a core-layer caller uses, and the store-internal helper a
// LocalStorage method calls directly.
var projectLivenessCheckNames = map[string]bool{
	"LockLiveProject": true,
	"lockLiveParent":  true,
}

func TestProjectChildWrites_RecheckProjectLivenessInATransaction(t *testing.T) {
	for _, w := range projectChildWriters {
		calls := projectGuardCalls(t, w.file, w.recvType, w.fn)

		transactional := false
		for _, name := range calls {
			// mutationTx / withAuditedMutation (AUDIT-TX-2, mutation_audit_tx.go)
			// open the transaction themselves: plain, or with the audit rows in it.
			if name == "WithTransaction" || name == "Transaction" || name == "mutationTx" || name == "withAuditedMutation" {
				transactional = true
			}
		}
		require.True(t, transactional,
			"%s.%s must do its child write inside a transaction — the project re-check is only sound if it "+
				"shares one with the write (#2702/#2710/#2711/#2712)", w.recvType, w.fn)

		checked := false
		for _, name := range calls {
			if projectLivenessCheckNames[name] {
				checked = true
			}
		}
		require.True(t, checked,
			"%s.%s must re-check the parent project's liveness (LockLiveProject or lockLiveParent) after its "+
				"write; without it the child commits under a project deleted in the window, and "+
				"deleteProjectCascade takes no named lock that would have serialized them "+
				"(#2702/#2710/#2711/#2712)", w.recvType, w.fn)
	}
}

// TestLockLiveProject_GoesThroughLockLiveParent pins the one hop the guard above
// relies on: LockLiveProject must be the row-locking helper, not a plain read.
// An unlocked re-read answers the same question and serializes against nothing.
func TestLockLiveProject_GoesThroughLockLiveParent(t *testing.T) {
	calls := projectGuardCalls(t, "../storage/store/local_parent_liveness.go", "LocalStorage", "LockLiveProject")
	require.Contains(t, calls, "lockLiveParent",
		"LockLiveProject must go through lockLiveParent (SELECT ... FOR SHARE on Postgres) — a bare SELECT "+
			"would not serialize against deleteProjectCascade's FOR UPDATE on the project row")
}

// projectGuardCalls returns the names of every function/method call in the named
// function's body. Fails the test if the function is not found, so a rename
// turns the guard red rather than vacuous.
func projectGuardCalls(t *testing.T, file, recvType, name string) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	require.NoError(t, err)
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Name.Name != name || fd.Body == nil {
			continue
		}
		got := ""
		if fd.Recv != nil && len(fd.Recv.List) > 0 {
			x := fd.Recv.List[0].Type
			if st, ok := x.(*ast.StarExpr); ok {
				x = st.X
			}
			if id, ok := x.(*ast.Ident); ok {
				got = id.Name
			}
		}
		if got != recvType {
			continue
		}
		var names []string
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			ce, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fun := ce.Fun.(type) {
			case *ast.Ident:
				names = append(names, fun.Name)
			case *ast.SelectorExpr:
				names = append(names, fun.Sel.Name)
			}
			return true
		})
		return names
	}
	t.Fatalf("%s: function %s (receiver %q) not found — the guard's subject was renamed or moved; update the guard", file, name, recvType)
	return nil
}
