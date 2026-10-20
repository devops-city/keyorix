// One file per entry; never append to a shared list. See registry_entries_test.go.
package core

func init() {
	registerSecretNodesRawSQLAllow("internal/storage/store/local_secret_acl.go:DeleteSecretACLsByUserAndProject", secretNodesRawSQLAllowEntry{
		reason: "Offboarding sweep: removes the user's ACL grants on every secret of the project INCLUDING soft-deleted ones, on purpose. Filtering on deleted_at IS NULL would leave the grant on a trashed secret, and RestoreSecret would then resurrect an offboarded user's access (CWE-284, the reason this function exists). Over-deleting a grant on a trashed secret is the safe direction.",
	})
}
