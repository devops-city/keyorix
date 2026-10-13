// passwordless_out_of_range_user_handle_test.go — #2846's blocking review point,
// still open on main after #3023.
//
// On the passwordless path the user handle is attacker-chosen (there is no first
// factor). A storage error loading the handle's user is treated as "never
// evaluated": audited auth.login_error, per-IP slot handed back. But not every
// lookup error is a storage outage. Postgres's driver cannot encode a user id
// above MaxInt64 (the column is int8) and returns
//
//	failed to encode args[0]: unable to encode 0xffffffffffffffff into binary
//	format for int8 (OID 20): 18446744073709551615 is greater than maximum
//	value for int64
//
// which is not ErrUserNotFound. So a crafted handle with the high bit set was
// classed as a storage failure: every such request kept no slot and wrote a
// "storage error" audit row instead of webauthn.failed — unlimited unthrottled
// requests, each one spoofing an outage in the audit trail.
//
// This fixture is SQLite (whose driver happens to turn such an id into a plain
// not-found), so pgEncodeUserIDStore reproduces the Postgres driver's answer for
// GetUser. That is the observed production behaviour, not an imagined one: the
// error text above is what store.GetUser returned against real Postgres 16 when
// this test was written. The store also records whether such a lookup happened
// at all: the guard is "an out-of-range handle never reaches storage", which
// holds whatever any driver does with the value.
package handlers

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// pgEncodeUserIDStore answers GetUser for ids Postgres cannot encode the way
// the Postgres driver does, and counts those calls.
type pgEncodeUserIDStore struct {
	corestorage.Storage
	outOfRangeLookups atomic.Int64
}

func (s *pgEncodeUserIDStore) GetUser(ctx context.Context, id uint) (*models.User, error) {
	if uint64(id) > math.MaxInt64 {
		s.outOfRangeLookups.Add(1)
		return nil, fmt.Errorf("Retrieval operation failed: failed to encode args[0]: unable to encode %#x into binary format for int8 (OID 20): %d is greater than maximum value for int64", uint64(id), uint64(id))
	}
	return s.Storage.GetUser(ctx, id)
}

// GetSessionAuthLiveness forwards the combined session cache-hit read to
// ComposeSessionAuthLiveness over this store, so the GetUser override above is
// what that read meets too (TestSessionAuthReadWrappersForwardTheCombinedRead).
func (s *pgEncodeUserIDStore) GetSessionAuthLiveness(ctx context.Context, userID, sessionID uint) (*corestorage.SessionAuthLiveness, error) {
	return corestorage.ComposeSessionAuthLiveness(ctx, s, userID, sessionID), nil
}

// passwordlessCredentialWithHandle is wcAssertionJSONWithUserHandle with the
// user handle replaced by handle.
func passwordlessCredentialWithHandle(t *testing.T, handle []byte) (json.RawMessage, string) {
	t.Helper()
	raw, challenge := wcAssertionJSONWithUserHandle(t, false)
	var body map[string]any
	require.NoError(t, json.Unmarshal(raw, &body))
	resp, ok := body["response"].(map[string]any)
	require.True(t, ok)
	resp["userHandle"] = base64.RawURLEncoding.EncodeToString(handle)
	out, err := json.Marshal(body)
	require.NoError(t, err)
	return out, challenge
}

func TestPasswordlessLogin_OutOfRangeUserHandleIsAFailedAttempt(t *testing.T) {
	// Control: a well-formed handle naming no user (alice deleted). A failed
	// attempt: webauthn.failed, slot kept.
	ccred, cchallenge := wcAssertionJSONWithUserHandle(t, false)
	ch, _, cdb := newWebAuthnCompletionEnv(t)
	require.NoError(t, cdb.Delete(&models.User{}, 1).Error)
	ctok := wcSeedCeremony(t, cdb, cchallenge, 0, "passwordless")
	cw := postJSONTo(t, ch.FinishWebAuthnPasswordlessLogin, "/auth/webauthn/passwordless/finish",
		map[string]any{"webauthn_session": ctok, "credential": ccred})
	require.Equal(t, http.StatusUnauthorized, cw.Code, cw.Body.String())
	require.EqualValues(t, 1, eventCount(t, cdb, "webauthn.failed"))
	require.EqualValues(t, 1, budgetSlots(t, cdb))

	handle := func(v uint64) []byte {
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, v)
		return b
	}
	for _, tc := range []struct {
		name   string
		handle []byte
	}{
		{"all ones", handle(math.MaxUint64)},
		{"MaxInt64+1", handle(math.MaxInt64 + 1)},
		{"zero", handle(0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var wrapped *pgEncodeUserIDStore
			h, _, db := newWebAuthnCompletionEnvOver(t, func(s corestorage.Storage) corestorage.Storage {
				wrapped = &pgEncodeUserIDStore{Storage: s}
				return wrapped
			})
			cred, challenge := passwordlessCredentialWithHandle(t, tc.handle)
			tok := wcSeedCeremony(t, db, challenge, 0, "passwordless")
			w := postJSONTo(t, h.FinishWebAuthnPasswordlessLogin, "/auth/webauthn/passwordless/finish",
				map[string]any{"webauthn_session": tok, "credential": cred})

			requireSameResponse(t, cw, w, "passwordless/"+tc.name)
			assert.Eventually(t, func() bool { return eventCount(t, db, "webauthn.failed") == 1 }, 5*time.Second, 10*time.Millisecond,
				"a handle naming no possible user is a failed attempt")
			// Give a wrongly-dispatched goSafe'd auth.login_error write time to land
			// before asserting it did not.
			time.Sleep(100 * time.Millisecond)
			assert.Zero(t, eventCount(t, db, "auth.login_error"), "and must not be audited as a storage error")
			assert.EqualValues(t, 1, budgetSlots(t, db), "and keeps its per-IP slot")
			assert.Zero(t, wrapped.outOfRangeLookups.Load(), "an out-of-range handle must be refused before any storage lookup")
		})
	}
}
