// refresh_fault_slot_test.go — what a storage fault does to the per-IP login
// budget slot on POST /auth/refresh (REFRESH-ROW-1/2; the #2880 rule applied to
// the refresh endpoint).
//
// The rule: a storage fault BEFORE the credential verdict must not spend budget
// (nothing was evaluated, so it was not a guess), and a storage fault AFTER the
// verdict keeps the slot (a valid token must never be cheaper than a wrong one).
// For refresh the "credential" is the session token, and the verdict is reached
// once the token's session has been found:
//
//	GetSessionAny   pre-verdict  (token not yet found or judged)
//	everything else post-verdict (GetUser -- the owner read runs after the token
//	                              matched a live session and the reuse/ceiling/
//	                              impersonation verdicts --, RotateSession, the
//	                              reuse-revocation calls, the DeleteSession of a
//	                              dead session)
//
// The table test derives the calls refresh really makes in three scenarios and
// fails on a method it has not classified, so a new storage call in
// RefreshSession cannot slip in unclassified.
package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

type refreshClass int

const (
	refreshPreVerdict  refreshClass = iota // slot must be released
	refreshPostVerdict                     // slot must stay counted, response unchanged
	refreshRateLimit                       // the budget's own bookkeeping, not driven here
)

// refreshStorageCalls classifies every storage method /auth/refresh can reach.
var refreshStorageCalls = map[string]refreshClass{
	"GetSessionAny":                  refreshPreVerdict,
	"GetUser":                        refreshPostVerdict,
	"RotateSession":                  refreshPostVerdict,
	"DeleteSession":                  refreshPostVerdict,
	"ListSessionTokenHashesByFamily": refreshPostVerdict,
	"DeleteSessionsByFamily":         refreshPostVerdict,
	"LogAuditEvent":                  refreshPostVerdict,
	"ReserveLoginAttempt":            refreshRateLimit,
	"ReleaseLoginAttempt":            refreshRateLimit,
	"CountRecentLoginAttempts":       refreshRateLimit,
	"RecordLoginAttempt":             refreshRateLimit,
	// UpdateLastLogin is the setup login's async RecordLogin, not a refresh call.
	"UpdateLastLogin":         refreshRateLimit,
	"CountLoginAttemptsSince": refreshRateLimit,
	"PruneLoginAttempts":      refreshRateLimit,
}

func (e *lockoutOracleEnv) loginToken(t *testing.T) string {
	t.Helper()
	w := e.postLogin(t, lockoutOracleTestPassword)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	// Login's audit event and last-login stamp are async: let them land, so they
	// are neither counted as calls refresh makes nor race an armed fault.
	require.Eventually(t, func() bool {
		var audits int64
		var u models.User
		return e.db.Model(&models.AuditEvent{}).Count(&audits).Error == nil && audits > 0 &&
			e.db.First(&u, 1).Error == nil && u.LastLoginAt != nil
	}, 5*time.Second, 5*time.Millisecond, "setup: login's async audit and last-login stamp")
	return tokenFrom(t, w)
}

func tokenFrom(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var resp struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.NotEmpty(t, resp.Data.Token, w.Body.String())
	return resp.Data.Token
}

func (e *lockoutOracleEnv) postRefresh(token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	e.h.RefreshToken(w, r)
	return w
}

func (e *lockoutOracleEnv) slots(t *testing.T) int64 {
	t.Helper()
	var n int64
	require.NoError(t, e.db.Model(&models.LoginAttempt{}).Where("ip = ?", lockoutOracleTestIP).Count(&n).Error)
	return n
}

// refreshScenario builds a fresh env and returns the token to present plus the
// expected outcome of an UNFAULTED refresh.
type refreshScenario struct {
	name      string
	delivered bool // an unfaulted refresh delivers a session
	setup     func(t *testing.T, e *lockoutOracleEnv) string
}

var refreshScenarios = []refreshScenario{
	{"valid-token", true, func(t *testing.T, e *lockoutOracleEnv) string { return e.loginToken(t) }},
	{"replayed-token", false, func(t *testing.T, e *lockoutOracleEnv) string {
		old := e.loginToken(t)
		require.Equal(t, http.StatusOK, e.postRefresh(old).Code, "setup: first refresh rotates the token away")
		return old
	}},
	{"suspended-account", false, func(t *testing.T, e *lockoutOracleEnv) string {
		tok := e.loginToken(t)
		require.NoError(t, e.db.Model(&models.User{}).Where("id = ?", 1).Update("account_state", "suspended").Error)
		return tok
	}},
}

// deadTokenControl is what a plainly wrong token gets: the shape and the cost
// every post-verdict refusal must match.
func deadTokenControl(t *testing.T) (code int, body string, slots int64) {
	t.Helper()
	e := newLockoutOracleEnv(t)
	w := e.postRefresh("not-a-real-session-token")
	return w.Code, w.Body.String(), e.slots(t)
}

func TestRefresh_StorageFaultSlotPolicy(t *testing.T) {
	ctrlCode, ctrlBody, ctrlSlots := deadTokenControl(t)
	require.Equal(t, http.StatusUnauthorized, ctrlCode)
	require.EqualValues(t, 1, ctrlSlots, "control: a wrong token spends one slot")

	for _, sc := range refreshScenarios {
		sc := sc
		// Derive the calls refresh really makes in this scenario.
		probe := newLockoutOracleEnv(t)
		tok := sc.setup(t, probe)
		before := len(probe.fs.Calls())
		w := probe.postRefresh(tok)
		if sc.delivered {
			require.Equal(t, http.StatusOK, w.Code, "%s: unfaulted refresh: %s", sc.name, w.Body.String())
		} else {
			require.Equal(t, http.StatusUnauthorized, w.Code, "%s: unfaulted refresh: %s", sc.name, w.Body.String())
		}
		type call struct {
			method string
			nth    int
		}
		seen := map[string]int{}
		var calls []call
		for _, c := range probe.fs.Calls()[before:] {
			seen[c.Method]++
			calls = append(calls, call{c.Method, seen[c.Method]})
		}
		require.NotEmpty(t, calls, "%s: refresh made no storage calls?", sc.name)

		for _, c := range calls {
			c := c
			class, ok := refreshStorageCalls[c.method]
			require.True(t, ok, "%s: refresh now calls storage method %s, which this table has not classified "+
				"as pre- or post-verdict (decide it by the #2880 rule and add it)", sc.name, c.method)
			if class == refreshRateLimit {
				continue
			}
			for _, kind := range []faultstorage.FaultKind{faultstorage.KindError, faultstorage.KindEffectThenError} {
				kind := kind
				t.Run(sc.name+"/"+c.method+"#"+string(rune('0'+c.nth))+"/"+kind.String(), func(t *testing.T) {
					e := newLockoutOracleEnv(t)
					tok := sc.setup(t, e)
					slotsBefore := e.slots(t)
					e.fs.Arm(&faultstorage.FaultSpec{Method: c.method, NthCall: c.nth, Kind: kind, Err: assert.AnError})
					w := e.postRefresh(tok)
					require.True(t, e.fs.Fired(), "the armed %s#%d fault must have fired", c.method, c.nth)
					e.fs.Arm(nil)
					spent := e.slots(t) - slotsBefore

					switch class {
					case refreshPreVerdict:
						require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
						assert.Equal(t, ctrlBody, w.Body.String(), "pre-verdict fault: same failure shape")
						assert.Zero(t, spent, "a storage fault before the token verdict must release the slot, not spend budget")
					case refreshPostVerdict:
						if w.Code == http.StatusOK {
							// The write landed despite the reported error and the session is
							// delivered (#2844 sessionWriteLanded): a delivered refresh returns its slot.
							require.Equal(t, faultstorage.KindEffectThenError, kind, "only an effect that landed may deliver")
							assert.Zero(t, spent, "a delivered refresh returns its slot")
							return
						}
						// The request is refused: same shape as a wrong token, same cost.
						require.Equal(t, ctrlCode, w.Code, w.Body.String())
						assert.Equal(t, ctrlBody, w.Body.String(), "post-verdict fault: same shape as a wrong token")
						assert.EqualValues(t, ctrlSlots, spent, "a storage fault after the token verdict keeps the slot, like a wrong token")
					}
				})
			}
		}
	}
}

// A pre-verdict fault must leave the token usable: the retry succeeds.
func TestRefresh_PreVerdictFaultLeavesTokenUsable(t *testing.T) {
	for _, m := range []string{"GetSessionAny"} {
		m := m
		t.Run(m, func(t *testing.T) {
			e := newLockoutOracleEnv(t)
			tok := e.loginToken(t)
			e.fs.Arm(&faultstorage.FaultSpec{Method: m, NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
			require.Equal(t, http.StatusUnauthorized, e.postRefresh(tok).Code)
			require.True(t, e.fs.Fired())
			e.fs.Arm(nil)
			require.Equal(t, http.StatusOK, e.postRefresh(tok).Code, "the session was not touched, so the retry must deliver")
			require.Zero(t, e.slots(t))
		})
	}
}

// The by-design row's handler proof: refresh with RotateSession#1 faulted keeps
// the slot and answers exactly like the non-fault failure (a wrong token).
// Pinned by server/faultops oracleAByDesignErrors
// (REST POST /auth/refresh, RotateSession#1/error).
func TestRefresh_RotateSessionFaultKeepsSlotAndMatchesFailureShape(t *testing.T) {
	ctrlCode, ctrlBody, ctrlSlots := deadTokenControl(t)

	e := newLockoutOracleEnv(t)
	tok := e.loginToken(t)
	require.Zero(t, e.slots(t), "setup: a delivered login leaves no slot")
	e.fs.Arm(&faultstorage.FaultSpec{Method: "RotateSession", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
	w := e.postRefresh(tok)
	require.True(t, e.fs.Fired(), "the RotateSession fault must have fired")

	assert.Equal(t, ctrlCode, w.Code)
	assert.Equal(t, ctrlBody, w.Body.String(), "response must match the non-fault failure shape byte for byte")
	assert.EqualValues(t, ctrlSlots, e.slots(t), "a storage fault after the token verdict keeps the per-IP slot (#2880)")
	assert.Empty(t, w.Result().Header.Get("Set-Cookie"), "no session cookie may be issued")
}

// The by-design row's handler proof for the owner read: GetUser runs AFTER
// GetSessionAny matched a live token and after the reuse/ceiling/impersonation
// verdicts, so a fault there keeps the slot and answers like a wrong token (a
// correct credential is never cheaper than a wrong one, #2880). Pinned by
// server/faultops oracleAByDesignErrors (REST POST /auth/refresh, GetUser#1/error).
func TestRefresh_GetUserFaultKeepsSlotAndMatchesFailureShape(t *testing.T) {
	ctrlCode, ctrlBody, ctrlSlots := deadTokenControl(t)

	e := newLockoutOracleEnv(t)
	tok := e.loginToken(t)
	require.Zero(t, e.slots(t), "setup: a delivered login leaves no slot")
	e.fs.Arm(&faultstorage.FaultSpec{Method: "GetUser", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
	w := e.postRefresh(tok)
	require.True(t, e.fs.Fired(), "the GetUser fault must have fired")
	e.fs.Arm(nil)

	assert.Equal(t, ctrlCode, w.Code)
	assert.Equal(t, ctrlBody, w.Body.String(), "response must match the non-fault failure shape byte for byte")
	assert.EqualValues(t, ctrlSlots, e.slots(t), "an owner-read fault after the token matched keeps the per-IP slot (#2880)")
	assert.Empty(t, w.Result().Header.Get("Set-Cookie"), "no session cookie may be issued")
	// Nothing was written to the session: the token is still usable on retry.
	assert.Equal(t, http.StatusOK, e.postRefresh(tok).Code)
}
