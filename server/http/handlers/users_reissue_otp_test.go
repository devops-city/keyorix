package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// REISSUE-1: POST /api/v1/users/{id}/reissue-one-time-password.

type reissueEnvelope struct {
	Data struct {
		OneTimePassword struct {
			Email     string `json:"email"`
			Password  string `json:"one_time_password"`
			ExpiresAt string `json:"expires_at"`
		} `json:"one_time_password"`
	} `json:"data"`
}

func reissueCall(t *testing.T, uh *UserHandler, id string) *httptest.ResponseRecorder {
	t.Helper()
	req := withChiParam(withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/users/"+id+"/reissue-one-time-password", nil)), "id", id)
	w := httptest.NewRecorder()
	uh.ReissueOneTimePassword(w, req)
	return w
}

func newReissueTarget(t *testing.T, cs *core.KeyorixCore, name string) uint {
	t.Helper()
	u, err := cs.CreateUser(t.Context(), &core.CreateUserRequest{
		Username: name, Email: name + "@x.com", DisplayName: name, Password: "Tr1cky-Passphrase-For-Tests!",
	})
	require.NoError(t, err)
	return u.ID
}

func TestReissueOneTimePassword_Success_ReturnsPasswordOnceWithExpiry(t *testing.T) {
	uh, cs, db := freshUserHandlerS12(t)
	id := newReissueTarget(t, cs, "reissue-ok")

	before := time.Now()
	w := reissueCall(t, uh, strconv.FormatUint(uint64(id), 10))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var env reissueEnvelope
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env))
	otp := env.Data.OneTimePassword
	require.NotEmpty(t, otp.Password)
	assert.Equal(t, "reissue-ok@x.com", otp.Email)
	exp, err := time.Parse(time.RFC3339, otp.ExpiresAt)
	require.NoError(t, err, "expires_at is RFC 3339")
	assert.Equal(t, time.UTC, exp.Location())
	assert.False(t, exp.Before(before.Add(core.DefaultOneTimePasswordTTL).Add(-time.Second)))

	// Audited with actor and target, and the password is in no audit row.
	var logs []models.AuditEvent
	require.NoError(t, db.Find(&logs).Error)
	var found bool
	for _, e := range logs {
		assert.False(t, strings.Contains(e.Description, otp.Password), "audit event %q leaks the password", e.EventType)
		if e.EventType == core.EventUserOneTimePasswordReissued {
			found = true
		}
	}
	assert.True(t, found, "user.one_time_password_reissued is audited")
}

func TestReissueOneTimePassword_RefusesOwnAccount(t *testing.T) {
	uh, _, _ := freshUserHandlerS12(t)
	w := reissueCall(t, uh, "1") // withUserCtx is user 1
	assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	assert.NotContains(t, w.Body.String(), "one_time_password")
	assert.Contains(t, w.Body.String(), "recover-admin", "points the admin at the right tool")
}

func TestReissueOneTimePassword_RefusesSSOOnlyUserWith409(t *testing.T) {
	uh, cs, db := freshUserHandlerS12(t)
	id := newReissueTarget(t, cs, "reissue-sso")
	require.NoError(t, db.Exec("UPDATE users SET external_id = ? WHERE id = ?", "sso:corp:corp|1", id).Error)

	w := reissueCall(t, uh, strconv.FormatUint(uint64(id), 10))
	assert.Equal(t, http.StatusConflict, w.Code, w.Body.String())
	assert.NotContains(t, w.Body.String(), "\"one_time_password\"")
}

func TestReissueOneTimePassword_RefusesSuspendedUserWith409(t *testing.T) {
	uh, cs, _ := freshUserHandlerS12(t)
	id := newReissueTarget(t, cs, "reissue-susp")
	require.NoError(t, cs.SuspendUser(t.Context(), 1, id))

	w := reissueCall(t, uh, strconv.FormatUint(uint64(id), 10))
	assert.Equal(t, http.StatusConflict, w.Code, w.Body.String())
}

func TestReissueOneTimePassword_NotFoundAndBadID(t *testing.T) {
	uh, _, _ := freshUserHandlerS12(t)
	assert.Equal(t, http.StatusNotFound, reissueCall(t, uh, "9999").Code)
	assert.Equal(t, http.StatusBadRequest, reissueCall(t, uh, "abc").Code)
}

func TestReissueOneTimePassword_RequiresAuthenticatedUser(t *testing.T) {
	uh, _, _ := freshUserHandlerS12(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/api/v1/users/2/reissue-one-time-password", nil), "id", "2")
	w := httptest.NewRecorder()
	uh.ReissueOneTimePassword(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// The 409 bodies are the fixed client texts, one per refusal (never err.Error()).
func TestReissueOneTimePassword_ConflictBodiesAreFixedMessages(t *testing.T) {
	uh, cs, db := freshUserHandlerS12(t)
	sso := newReissueTarget(t, cs, "reissue-sso-msg")
	require.NoError(t, db.Exec("UPDATE users SET external_id = ? WHERE id = ?", "sso:corp:corp|2", sso).Error)
	susp := newReissueTarget(t, cs, "reissue-susp-msg")
	require.NoError(t, cs.SuspendUser(t.Context(), 1, susp))

	for name, tc := range map[string]struct {
		id   uint
		want string
	}{
		"sso only":  {sso, core.ReissueExternalIdentityMessage},
		"suspended": {susp, core.ReissueAccountBlockedMessage},
	} {
		t.Run(name, func(t *testing.T) {
			w := reissueCall(t, uh, strconv.FormatUint(uint64(tc.id), 10))
			require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
			var body struct {
				Message string `json:"message"`
			}
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
			assert.Equal(t, tc.want, body.Message)
		})
	}
}

// A storage fault on the reissue's row lock is a 500, not the 404 a missing user
// gets (the admin must not be told "no such user" when the database failed).
func TestReissueOneTimePassword_LockFaultIs500Not404(t *testing.T) {
	_, cs, db := freshUserHandlerS12(t)
	id := newReissueTarget(t, cs, "reissue-fault")

	faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), &faultstorage.FaultSpec{
		Method: "LockUserForUpdate", NthCall: 1, Kind: faultstorage.KindError,
		Err: errors.New("injected: LockUserForUpdate"),
	})
	fuh, err := NewUserHandler(core.NewKeyorixCore(faulty))
	require.NoError(t, err)

	w := reissueCall(t, fuh, strconv.FormatUint(uint64(id), 10))
	require.True(t, faulty.Fired(), "the reissue's row lock must have been reached")
	assert.Equal(t, http.StatusInternalServerError, w.Code, w.Body.String())
	assert.NotContains(t, w.Body.String(), "\"one_time_password\"")
	assert.NotContains(t, w.Body.String(), "injected", "the storage error text never reaches the client")
}
