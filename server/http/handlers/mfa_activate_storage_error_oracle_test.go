// mfa_activate_storage_error_oracle_test.go — the blocking review finding on
// #2846, kept as a guard after the fix itself landed on main through #3023.
//
// #2744 split ActivateMFA's two outcomes apart for the AUDIT: a wrong code
// (mfa.failed) and a MarkTOTPStepUsed STORAGE failure (mfa.error). #2846's first
// version also split them for the CLIENT: the storage branch returned a wrapped
// sentinel, which writeMFAErr renders with clientSafe()'s generic internal-error
// message, while the wrong-code branch returns "invalid code". MarkTOTPStepUsed
// is reached only AFTER validateTOTPStep succeeded, so the two different bodies
// told the caller whether the code they submitted was CORRECT — a
// right-vs-wrong-code oracle available for as long as the DB fault lasts. That
// version never reached main; main's ActivateMFA returns the plain wrong-code
// error on the storage branch and audits mfa.error (#3023).
//
// This is a HANDLER-level test on purpose. The leak is not visible in core: the
// two branches there legitimately return different error VALUES (they must, so
// the audit can distinguish them), and a core-level test asserting that would
// pass in both the leaking and the fixed world. Only the rendered HTTP response
// — the thing the caller actually observes — can tell them apart. Same shape as
// "assert the effect, not the return value" in CLAUDE.md.
//
// It asserts byte-identity of the whole response, not just the message field,
// so a future divergence in status, error type, content-type or any added field
// (a request id, a retry hint, a details object on one branch only) fails here
// too. The one thing it deliberately does NOT claim to cover is timing: both
// branches return immediately after their audit call, but nothing in this test
// would catch a latency difference, and a latency oracle is a real variant of
// this finding. Stated rather than silently skipped.
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// activateMFAHTTP posts code+password to /auth/mfa/activate as user 1 and
// returns the recorder, so a caller can compare the FULL response (status,
// headers, body bytes) and not just one decoded field.
func activateMFAHTTP(t *testing.T, h *AuthHandler, code, password string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]string{"code": code, "password": password})
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/activate", bytes.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), middleware.GetUserContextKey(), &middleware.UserContext{UserID: 1}))
	w := httptest.NewRecorder()
	h.ActivateMFA(w, r)
	return w
}

// TestActivateMFA_StorageErrorResponseIsIdenticalToWrongCode asserts the two
// responses are indistinguishable to the client:
//
//	A. a WRONG code (validateTOTPStep fails; nothing is consumed), and
//	B. the CORRECT code plus a MarkTOTPStepUsed storage failure.
//
// Order matters: A runs first precisely because a wrong code consumes no step,
// so B can then submit the correct code for the same enrolment and the same
// clock step. If A consumed anything, B's correct code would be a replay —
// which returns "invalid code" through a THIRD branch (!fresh) and would make
// this test pass for the wrong reason, proving only that two wrong-code paths
// agree.
func TestActivateMFA_StorageErrorResponseIsIdenticalToWrongCode(t *testing.T) {
	h, fs, db, fixed := setupMFAVerifyStorageErrorTest(t)
	ctx := context.Background()

	_, secret, err := h.coreService.BeginMFAEnrollment(ctx, 1)
	require.NoError(t, err)
	good, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)

	// A: a wrong code. "000000" is only wrong if it is not what the fixed clock
	// step happens to produce — assert that rather than assume it, so the test
	// cannot silently degenerate into comparing two correct-code responses.
	const wrong = "000000"
	require.NotEqual(t, good, wrong, "the 'wrong' code collided with the real one for this step; pick another")
	wrongResp := activateMFAHTTP(t, h, wrong, mfaVerifyStorageErrorTestPassword)

	// B: the correct code, with MarkTOTPStepUsed failing. NthCall=1 lands on
	// ActivateMFA's own call: nothing before it in this request touches that
	// method, and the previous request never reached it at all (A failed at
	// validateTOTPStep, one line earlier).
	fs.Arm(&faultstorage.FaultSpec{Method: "MarkTOTPStepUsed", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
	storageResp := activateMFAHTTP(t, h, good, mfaVerifyStorageErrorTestPassword)
	require.True(t, fs.Fired(), "the armed MarkTOTPStepUsed fault never fired — the interleaving under test never happened")
	fs.Arm(nil)

	assert.Equal(t, wrongResp.Code, storageResp.Code,
		"a storage failure reached AFTER the code validated must not differ in STATUS from a wrong code (#2846)")
	assert.Equal(t, wrongResp.Body.String(), storageResp.Body.String(),
		"a storage failure reached AFTER the code validated must be byte-identical to a wrong code; any "+
			"difference tells the caller their code was CORRECT, for as long as the DB fault lasts (#2846)")
	assert.Equal(t, wrongResp.Header(), storageResp.Header(),
		"response headers must not distinguish the two either (#2846)")

	// Sanity: the shared body really is the wrong-code body, not some generic
	// message both branches happened to converge on (e.g. both rendered as
	// clientSafe()'s internal-error body).
	var decoded struct {
		Message string `json:"message"`
	}
	require.NoError(t, json.Unmarshal(storageResp.Body.Bytes(), &decoded))
	assert.Equal(t, "invalid code", decoded.Message,
		"the shared body must be the wrong-code body specifically — converging both branches onto the "+
			"generic internal-error message would hide a genuine wrong code behind an internal-error claim")

	// The effect that justifies the different error VALUES surviving in core:
	// the audit must still distinguish the two. Asserted here so a future
	// simplification that collapses the storage branch into the wrong-code
	// branch outright — satisfying every assertion above — goes red, since that
	// would re-open #2744 while closing #2846.
	assert.Equal(t, int64(1), mfaActivateAuditCount(t, db, "mfa.error"),
		"the storage failure must still be audited as mfa.error, not as a failed attempt (#2744)")
	assert.Equal(t, int64(1), mfaActivateAuditCount(t, db, "mfa.failed"),
		"exactly the wrong-code attempt — and not the storage failure — must be audited mfa.failed (#2744)")

	// And nothing was activated by either request.
	var u models.User
	require.NoError(t, db.First(&u, 1).Error)
	assert.False(t, u.MFAEnabled, "neither a wrong code nor a storage failure may enable MFA")
}

// mfaActivateAuditCount counts audit rows of one event type for user 1, scoped
// to the activate phase so an unrelated mfa.failed from another flow in the same
// fixture could not satisfy the assertions above.
func mfaActivateAuditCount(t *testing.T, db *gorm.DB, event string) int64 {
	t.Helper()
	var n int64
	require.NoError(t, db.Model(&models.AuditEvent{}).
		Where("event_type = ? AND user_id = ? AND description LIKE ?", event, 1, "%activate%").
		Count(&n).Error)
	return n
}
