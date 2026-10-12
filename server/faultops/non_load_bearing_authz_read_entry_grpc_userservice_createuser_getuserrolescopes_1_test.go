// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

func init() {
	// #3093 (triage: SESSION-FUZZ-FIX-3093; decided by design 2026-10-11).
	registerNonLoadBearingAuthzRead("grpc_userservice_createuser_getuserrolescopes_1", nonLoadBearingException{
		op: "GRPC keyorix.v1.UserService.CreateUser", method: "GetUserRoleScopes", nth: 1,
		designComment: "server/grpc/services/user_service.go CreateUser: authorization is authorizeGlobal(users.write) -> " +
			"AuthorizePrincipal, which denies on any error (conversions.go authorizeScoped) and reads no " +
			"GetUserRoleScopes; the only GetUserRoleScopes call is userToProto -> projectCounts (besteffort.Run) -> " +
			"ProjectMembershipCounts for the NEW user, after the create committed",
		provingTest: "server/grpc/services/TestCreateUser_RoleScopesFaultIsTargetEnrichmentOnly",
		why: "Call #1 is response enrichment for the created target user, not an authorization decision: the " +
			"caller was already authorized by a read path that fails closed (TestCreateUser_AuthzReadFaultFailsClosed). " +
			"A fault there leaves the committed create in place with zero project counts, which is projectCounts' " +
			"documented best-effort fallback; failing the RPC would report an already-committed create as failed.",
	})
}
