package handlers

// #3277 follow-up: POST /auth/setup/consume answers every failure after the
// token was found valid with the same generic 400 a dead token gets (#2888),
// so the response cannot tell a caller whether the token was real. A PANIC in
// any storage call after that point used to reach the Recovery 500 instead:
// a dead or forged token never gets that far, so the 500 itself said "this
// token is valid". Setup consume is not in the server/faultops op catalog, so
// this file is its family guard: the population is measured from a fault-free
// consume (every storage method first called after the token lookup), and each
// is driven as an error and as a panic through the production
// middleware.Recovery.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// setupConsumeVerdictMethod is the token lookup: everything after it runs only
// for a token that exists and is active.
const setupConsumeVerdictMethod = "GetSetupTokenByHash"

type setupConsumeAnswer struct {
	status int
	body   string
}

// postSetupConsume serves one consume through the production Recovery.
func postSetupConsume(t *testing.T, h *AuthHandler, token string) setupConsumeAnswer {
	t.Helper()
	body := fmt.Sprintf(`{"token":%q,"password":%q}`, token, undeliveredSetupPassword+"x")
	req := httptest.NewRequest(http.MethodPost, "/auth/setup/consume", strings.NewReader(body))
	w := httptest.NewRecorder()
	throughProductionRecovery(h.ConsumeSetup).ServeHTTP(w, req)
	return setupConsumeAnswer{w.Code, w.Body.String()}
}

// postVerdictSetupCalls returns, for every storage method a fault-free consume
// calls after the token lookup, the call number (counted from arming) of its
// first call after that point.
func postVerdictSetupCalls(t *testing.T, h *AuthHandler, c *core.KeyorixCore, fs *faultstorage.FaultyStorage, adminID uint) map[string]int {
	t.Helper()
	token := issueSetupTokenForUserS11(t, c, adminID, "setupprofile@example.com", "setupprofile")
	start := len(fs.Calls())
	a := postSetupConsume(t, h, token)
	require.Equal(t, http.StatusOK, a.status, "calibration: a fault-free consume logs the user in: %s", a.body)
	calls := fs.Calls()[start:]
	verdict := slices.IndexFunc(calls, func(c faultstorage.CallRecord) bool { return c.Method == setupConsumeVerdictMethod })
	require.GreaterOrEqual(t, verdict, 0, "calibration: the consume must look the token up through %s", setupConsumeVerdictMethod)
	seen := map[string]int{}
	first := map[string]int{}
	for i, call := range calls {
		seen[call.Method]++
		if i > verdict {
			if _, ok := first[call.Method]; !ok {
				first[call.Method] = seen[call.Method]
			}
		}
	}
	return first
}

func TestConsumeSetup_PostVerdictPanicAnsweredLikeItsError(t *testing.T) {
	h, c, fs, _, adminID := newUndeliveredSetupFixture(t)

	dead := postSetupConsume(t, h, "kx_setup_not-a-real-token")
	require.Equal(t, http.StatusBadRequest, dead.status, "calibration: a dead token gets the generic 400: %s", dead.body)

	population := postVerdictSetupCalls(t, h, c, fs, adminID)
	// Calibration: the password write, the token consume and the session
	// insert are all after the lookup. Fewer means the profile went wrong and
	// this test would quietly check less.
	for _, m := range []string{"MarkSetupTokenConsumed", "SetPasswordHash", "CreateSession", "GetUserPermissions"} {
		require.Contains(t, population, m, "calibration: %s must run after the token lookup", m)
	}

	methods := make([]string, 0, len(population))
	for m := range population {
		methods = append(methods, m)
	}
	slices.Sort(methods)
	n := 0
	for _, m := range methods {
		nth := population[m]
		t.Run(fmt.Sprintf("%s#%d", m, nth), func(t *testing.T) {
			// A fresh fixture per drive: every failed consume keeps its per-IP
			// login-budget slot, so a shared one would start answering 429
			// before the fault is reached. The fixtures are identical, so the
			// profiled call numbers hold for each.
			var pst interface {
				DB() *gorm.DB
			}
			drive := func(kind faultstorage.FaultKind, name string) (setupConsumeAnswer, uint, bool) {
				dh, dc, dfs, dst, dadmin := newUndeliveredSetupFixture(t)
				pst = dst
				token := issueSetupTokenForUserS11(t, dc, dadmin, name+"@example.com", name)
				u, err := dc.GetUserByUsername(context.Background(), name)
				require.NoError(t, err)
				dfs.Arm(&faultstorage.FaultSpec{Method: m, NthCall: nth, Kind: kind, Err: errors.New("injected")})
				a := postSetupConsume(t, dh, token)
				fired := dfs.Fired()
				dfs.Arm(nil)
				return a, u.ID, fired
			}
			errA, _, errFired := drive(faultstorage.KindError, fmt.Sprintf("spverr%d", n))
			panicA, panicUser, panicFired := drive(faultstorage.KindPanic, fmt.Sprintf("spvpanic%d", n))
			st := pst
			n++
			if !errFired || !panicFired {
				// Reached only from a detached goroutine after the response was
				// written (the login audit, RecordLogin): it cannot change what
				// the caller is answered.
				t.Skipf("%s#%d did not fire before the response (error fired %v, panic fired %v): not on the response path",
					m, nth, errFired, panicFired)
			}
			assert.NotEqual(t, http.StatusInternalServerError, panicA.status,
				"a panic after the token was validated got the Recovery 500, which a dead token never gets: %s", panicA.body)
			if errA.status == http.StatusOK {
				// The call's error is swallowed (best-effort), so the error kind
				// still logs the user in. The panic may do the same, or fail
				// closed: inside the password-reset transaction (the PAT
				// revocation, the password-history read) it rolls the reset back,
				// and recovering it there to commit anyway would be fail-open. A
				// failure must then be the dead-token answer. (Bodies of two
				// successes differ by user, so only the status is compared.)
				if panicA.status != http.StatusOK {
					assert.Equal(t, dead, panicA, "a panic that fails the consume must be answered exactly like a dead token")
				}
			} else {
				assert.Equal(t, errA, panicA, "the panic must be answered exactly like the same call's error")
				assert.Equal(t, dead, panicA, "a failed consume must be answered exactly like a dead token")
				var sessions int64
				require.NoError(t, st.DB().Model(&models.Session{}).Where("user_id = ?", panicUser).Count(&sessions).Error)
				assert.Zero(t, sessions, "a failed consume must leave no session")
			}
		})
	}
}

// TestConsumeSetup_MFAChallengePanicAnsweredLikeItsError: for an account with
// a second factor the consume issues an MFA challenge instead of a session
// (CreateMFAChallengeHoldingLoginSlot). That write is after the token was
// validated too, so its panic must get the dead-token 400 like its error.
func TestConsumeSetup_MFAChallengePanicAnsweredLikeItsError(t *testing.T) {
	h, c, fs, st, adminID := newUndeliveredSetupFixture(t)
	dead := postSetupConsume(t, h, "kx_setup_not-a-real-token")

	for i, kind := range []faultstorage.FaultKind{faultstorage.KindError, faultstorage.KindPanic} {
		name := fmt.Sprintf("spvmfa%d", i)
		token := issueSetupTokenForUserS11(t, c, adminID, name+"@example.com", name)
		require.NoError(t, st.DB().Model(&models.User{}).Where("username = ?", name).Update("mfa_enabled", true).Error)
		fs.Arm(&faultstorage.FaultSpec{Method: "CreateMFAChallenge", NthCall: 1, Kind: kind, Err: errors.New("injected")})
		a := postSetupConsume(t, h, token)
		require.True(t, fs.Fired(), "%s: the challenge write must have been reached", kind)
		fs.Arm(nil)
		assert.Equal(t, dead, a, "%s: a failed challenge write after a valid token must be answered like a dead token", kind)
	}
}

// TestConsumeSetup_PreVerdictPanicIsNotAnOracle is the calibration for the
// boundary: a panic in the token lookup itself happens for every token, valid
// or not, so it is answered the same for both (the Recovery 500) and says
// nothing about the token.
func TestConsumeSetup_PreVerdictPanicIsNotAnOracle(t *testing.T) {
	h, c, fs, _, adminID := newUndeliveredSetupFixture(t)
	valid := issueSetupTokenForUserS11(t, c, adminID, "spvpre@example.com", "spvpre")
	answers := map[string]setupConsumeAnswer{}
	for name, token := range map[string]string{"valid": valid, "dead": "kx_setup_not-a-real-token"} {
		fs.Arm(&faultstorage.FaultSpec{Method: setupConsumeVerdictMethod, NthCall: 1, Kind: faultstorage.KindPanic, Err: errors.New("injected")})
		answers[name] = postSetupConsume(t, h, token)
		require.True(t, fs.Fired())
		fs.Arm(nil)
	}
	assert.Equal(t, answers["dead"], answers["valid"], "a lookup panic must not distinguish a valid token from a dead one")
}
