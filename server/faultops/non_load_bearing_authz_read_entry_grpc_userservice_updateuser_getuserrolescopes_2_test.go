// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

func init() {
	// #3093 (triage: SESSION-FUZZ-FIX-3093; decided by design 2026-10-11).
	// Call #1 on this op is the admin-rank ceiling read and stays load-bearing
	// (not exempted): a fault there refuses the update.
	registerNonLoadBearingAuthzRead("grpc_userservice_updateuser_getuserrolescopes_2", nonLoadBearingException{
		op: "GRPC keyorix.v1.UserService.UpdateUser", method: "GetUserRoleScopes", nth: 2,
		designComment: "internal/core/authz.go requireEqualOrGreaterAdminAuthority: the target's GetUserRoleScopes " +
			"(call #1) returns errCeilingResolutionFailed on error, so the update is refused; " +
			"server/grpc/services/user_service.go UpdateUser then reaches call #2 only via userToProto -> " +
			"projectCounts (besteffort.Run), after the update committed",
		provingTest: "server/grpc/services/TestUpdateUser_RoleScopesFaultFailsClosedOnCeilingOnly",
		why: "Call #2 is response enrichment for the updated target user, after authorization (users.write via " +
			"AuthorizePrincipal, and the ceiling read at call #1) has already failed closed or passed. A fault there " +
			"leaves the committed update in place with zero project counts, projectCounts' documented best-effort " +
			"fallback; the authorization-bearing call #1 is not exempted.",
	})
}
