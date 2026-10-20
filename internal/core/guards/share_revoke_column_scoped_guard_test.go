package guards

import (
	"go/ast"
	"go/token"
	"strconv"
	"testing"
)

// TestRevokeShare_IsColumnScoped is the revoke-side guard for #2648. The issue's
// fix (UpdateShareRecord, guarded by TestUpdateSharePermission_IsColumnScoped)
// stops an UPDATE from resurrecting a revoked share; this pins that every path
// that REVOKES a share is itself a conditional soft delete of the active row(s)
// and never persists a pre-read ShareRecord snapshot, so a revoke cannot revert
// a concurrent permission change or write `deleted_at = NULL` back.
//
// Hops checked: KeyorixCore.RevokeShare (through its transaction handle) and
// KeyorixCore.RemoveSelfFromShare -> DeleteShareRecord -> its LocalStorage body;
// DeleteExpiredShareRecords (the sweep that also revokes) in storage.
//
// What this does NOT cover, and is reported to the coordinator because the
// issue names it: createShareRecordTx still persists an existing share with GORM
// Save in two places (the re-share path and the unique-violation fallback in
// internal/storage/store/local_sharing.go). That is the same resurrection
// primitive on the CREATE side, and a guard for it would be red on main. It is
// owned by SHARE-CAS-1 (share create/update/revoke concurrency), so it is
// recorded, not fixed or allowlisted, here.
func TestRevokeShare_IsColumnScoped(t *testing.T) {
	const store = "../../storage/store/local_sharing.go"
	assertConditionalSoftDelete(t, store, "DeleteShareRecord")
	assertConditionalSoftDelete(t, store, "DeleteExpiredShareRecords")
	assertCoreWritesOnlyVia(t, "../sharing.go", "RevokeShare", "tx", "DeleteShareRecord",
		"Save", "UpdateShareRecord", "CreateShareRecord")
	assertCoreWritesOnlyVia(t, "../sharing.go", "RemoveSelfFromShare", "storage", "DeleteShareRecord",
		"Save", "UpdateShareRecord", "CreateShareRecord")
}

// assertConditionalSoftDelete asserts the LocalStorage method name persists a
// revoke as GORM's soft delete behind a WHERE: it calls Where and Delete, and
// never Save (an upsert that can write deleted_at = NULL), Select("*"), or
// Unscoped (which would turn the soft delete into a hard one and lose the audit
// and restore trail).
func assertConditionalSoftDelete(t *testing.T, path, name string) {
	t.Helper()
	var where, del bool
	for _, c := range columnScopedFuncCalls(t, path, "LocalStorage", name) {
		switch c.Name {
		case "Save":
			t.Errorf("%s: LocalStorage.%s calls %s.Save — a full-row upsert", path, name, c.Recv)
		case "Unscoped":
			t.Errorf("%s: LocalStorage.%s calls %s.Unscoped — a revoke must stay a soft delete", path, name, c.Recv)
		case "Select":
			for _, a := range c.Args {
				if bl, ok := a.(*ast.BasicLit); ok && bl.Kind == token.STRING {
					if s, _ := strconv.Unquote(bl.Value); s == "*" {
						t.Errorf("%s: LocalStorage.%s calls Select(\"*\") — a full-row write", path, name)
					}
				}
			}
		case "Where":
			where = true
		case "Delete":
			del = true
		}
	}
	if !where || !del {
		t.Errorf("%s: LocalStorage.%s no longer issues a conditional soft delete (Where=%v, Delete=%v)", path, name, where, del)
	}
}
