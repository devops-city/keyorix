// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

import "github.com/keyorixhq/keyorix/internal/faultstorage"

func init() {
	registerOracleAByDesign("post_auth_login_getuserroles_effect_then_error", oracleAByDesignError{
		op: "REST POST /auth/login", method: "GetUserRoles", kind: faultstorage.KindEffectThenError, nth: 1,
		tables: []string{"LoginAttempt"}, outcomeLogs: []string{"AuditEvent"},
		wrongCredentialResponse: wrongPasswordResponse,
		designComment:           loginPostVerdictDesign,
		provingTest:             "server/http/handlers/TestLogin_PostVerdictFaultCostsTheSameAsAWrongPassword/GetUserRoles/effect-then-error",
		why:                     loginPostVerdictWhy,
	})
}
