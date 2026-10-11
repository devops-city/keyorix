// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

func init() {
	registerEffectThenErrorExclusion("grpc_userservice_createuser_createuserwithrolegrants", effectThenErrorExclusion{op: "GRPC keyorix.v1.UserService.CreateUser", method: "CreateUserWithRoleGrants", tables: []string{"PasswordHistory"}})
}
