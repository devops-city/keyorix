// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

func init() {
	registerNonLoadBearingAuthzRead("put_auth_profile_getuserpermissions_1", nonLoadBearingException{op: "REST PUT /api/v1/auth/profile", method: "GetUserPermissions", nth: 1})
}
