// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

import "github.com/keyorixhq/keyorix/internal/faultstorage"

func init() {
	registerOracleAByDesign("post_auth_login_getuserroles", oracleAByDesignError{
		op: "REST POST /auth/login", method: "GetUserRoles", kind: faultstorage.KindError, nth: 1,
		tables: []string{"LoginAttempt"}, outcomeLogs: []string{"AuditEvent"},
		wrongCredentialResponse: wrongPasswordResponse,
		designComment:           loginPostVerdictDesign,
		provingTest:             "server/http/handlers/TestLogin_PostVerdictFaultCostsTheSameAsAWrongPassword/GetUserRoles/error",
		why:                     loginPostVerdictWhy,
	})
}
