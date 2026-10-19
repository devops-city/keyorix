// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

func init() {
	// #2839 item 3(c). PUT /api/v1/auth/profile: a faulted GetUserPermissions read
	// gives HTTP 200 with empty roles/permissions. Display-only; traced (re-verified
	// 2026-10-17 on main) from the call outward:
	//   - GetUserPermissions is reached only via core.GetUserIdentity, called by
	//     AuthHandler.userIdentity after UpdateOwnProfile has already succeeded; on
	//     error the handler substitutes empty slices (the fail-closed direction).
	//   - The result goes only into userProfileMap -> the JSON body. No middleware,
	//     handler or core call on this route reads it for an authorization decision;
	//     the route's authority is the session itself (self-scoped edit).
	//   - web: ProfilePage's onSuccess does setUser({...user, displayName, email});
	//     the PUT response's permissions never reach the auth store, and an empty
	//     set denies in useCan.
	// Scoped to the exact (op, method, nth); GET /auth/profile and other calls stay
	// violations (TestNonLoadBearingAuthzRead_ProfileUpdateGetUserPermissions).
	registerNonLoadBearingAuthzRead("put_auth_profile_getuserpermissions_1", nonLoadBearingException{op: "REST PUT /api/v1/auth/profile", method: "GetUserPermissions", nth: 1})
}
