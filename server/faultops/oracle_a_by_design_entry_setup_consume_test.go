// One file per op's row family (AUTH-2 item 1, #3298): every row below records
// the SAME decision, so they are generated from one tuple list rather than
// copied into ~50 near-identical files. New files only; never a shared list.
// See registry_entries_test.go.
package faultops

import (
	"fmt"
	"strings"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

// setupConsumeDeadLinkResponse is what a dead setup link gets on
// POST /auth/setup/consume. TestOracleAByDesign_WrongCredentialOutcomesAreReal
// re-derives it from a real dead-link run (setupConsumeDeadTokenRequest).
const setupConsumeDeadLinkResponse = "HTTP 400: {\"code\":400,\"error\":\"BadRequest\",\"message\":\"This setup link could not be completed. It may be invalid or expired — ask your administrator for a new one.\",\"success\":false}\n"

const (
	setupConsumeDesign = "internal/core/setup_consume.go completePasswordSetup: one WithTransaction for the token, " +
		"the password/state, the PAT revocation and the session or MFA challenge; reads before it; a failure after " +
		"the token was validated is ErrSetupPostVerdict (panics recovered into it). server/http/handlers/auth.go " +
		"ConsumeSetup answers it with the dead-link 400, keeps the per-IP slot (only a delivered consume returns " +
		"it, #2936) and audits setup_token.consume_error"
	setupConsumeWhy = "The token was valid, a storage fault refused the consume, and the transaction left nothing " +
		"behind: the token is still active, the password and PATs unchanged, no session or challenge. What remains " +
		"is exactly what a dead link costs: the same 400, the LoginAttempt slot kept, a failure audit. Answering " +
		"or charging it differently would tell the caller the token was valid. setup_token.consume_error lets an " +
		"operator tell the fault apart from a dead link."
	setupConsumeProvingTest = "internal/core/TestCompleteSetup_FaultAtAnyWriteLeavesNothingAndTheLinkStillWorks; " +
		"server/http/handlers/TestConsumeSetup_FailedConsumeLeavesTheLinkUsable"
)

// setupConsumeDecidedTuples are the (method, kinds) whose fault the exhaustive
// sweep (TestOpFaultSweep, every method x nth 1-5 x kind) found
// failing the consume after the token was validated. All are nth 1: each
// method runs once on this path. RecentPasswordHashes' error is swallowed by
// the history check, so only its panic refuses.
var setupConsumeDecidedTuples = map[string][]struct {
	method string
	kinds  []faultstorage.FaultKind
}{
	"REST POST /auth/setup/consume": {
		{"GetUser", allThreeKinds}, {"RecentPasswordHashes", panicOnly},
		{"GetUserRoles", allThreeKinds}, {"GetUserPermissions", allThreeKinds},
		{"WithTransaction", errorAndPanic}, {"MarkSetupTokenConsumed", allThreeKinds},
		{"SetPasswordHash", allThreeKinds}, {"SetAccountState", allThreeKinds},
		{"RevokeAllPersonalAccessTokensForUser", allThreeKinds}, {"CreateSession", allThreeKinds},
	},
}

var (
	allThreeKinds = []faultstorage.FaultKind{faultstorage.KindError, faultstorage.KindPanic, faultstorage.KindEffectThenError}
	errorAndPanic = []faultstorage.FaultKind{faultstorage.KindError, faultstorage.KindPanic}
	panicOnly     = []faultstorage.FaultKind{faultstorage.KindPanic}
)

func init() {
	for op, tuples := range setupConsumeDecidedTuples {
		slugOp := "setup_consume"
		for _, tu := range tuples {
			for _, kind := range tu.kinds {
				name := fmt.Sprintf("post_auth_%s_%s_%s", slugOp, strings.ToLower(tu.method),
					strings.ReplaceAll(kind.String(), "-", "_"))
				registerOracleAByDesign(name, oracleAByDesignError{
					op: op, method: tu.method, kind: kind, nth: 1,
					tables: []string{"LoginAttempt"}, outcomeLogs: []string{"AuditEvent"},
					wrongCredentialResponse: setupConsumeDeadLinkResponse,
					designComment:           setupConsumeDesign,
					provingTest:             setupConsumeProvingTest,
					why:                     setupConsumeWhy,
				})
			}
		}
	}
}
