// audit_checkpoint_state_pin_mock_test.go — the branches of the checkpoint write
// that read the signed audit verification state (auditVerifyStateTruncation),
// driven against a mock store so each stored-row shape is exact: absent,
// garbled, signed under another key, authentic and consistent, authentic and
// proving a truncation, and unreadable.
//
// The SQLite/Postgres cases in audit_checkpoint_keyversion_launder_test.go prove
// the attack end to end; these pin the decision table, including the documented
// fail-open shapes (absent / garbled / foreign-key row re-baselines, because
// that is indistinguishable from a key change).
package core

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

var pinTestKey = []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1")

// pinTestStoredState encodes st the way saveAuditVerifyState stores it, signed
// under key.
func pinTestStoredState(t *testing.T, key []byte, st auditVerifyState) string {
	t.Helper()
	st.V = 1
	payload, err := json.Marshal(st)
	require.NoError(t, err)
	signer := NewKeyorixCore(new(MockStorage))
	signer.SetAuditCheckpointKey(key, "v1")
	return strings.Join([]string{"avs-v1", base64.RawURLEncoding.EncodeToString(payload), signer.signAuditVerifyState(payload)}, auditVerifyStateSep)
}

// pinTestCore returns a core over a mock whose chain verifies with 3 events
// (head id 1, hash "abc"), no checkpoint, mark or retention anchor, and whose
// state row read is stateRead.
func pinTestCore(t *testing.T, stateVal string, stateFound bool, stateErr error) (*KeyorixCore, *MockStorage) {
	t.Helper()
	ms := new(MockStorage)
	ms.On("GetSystemMetadata", mock.Anything, auditRetentionAnchorKey).Return("", false, nil)
	ms.On("VerifyAuditChain", mock.Anything, mock.Anything).Return(&storage.AuditChainVerification{
		Valid: true, ChainedEvents: 3, HeadID: 1, HeadHash: "abc",
	}, nil)
	ms.On("LatestAuditCheckpoint", mock.Anything).Return(nil, nil)
	ms.On("GetSystemMetadata", mock.Anything, auditHighWaterKey).Return("", false, nil)
	ms.On("GetSystemMetadata", mock.Anything, auditVerifyStateKey).Return(stateVal, stateFound, stateErr)
	ms.On("CreateAuditCheckpoint", mock.Anything, mock.Anything).Return(nil).Maybe()
	ms.On("SetSystemMetadata", mock.Anything, auditHighWaterKey, mock.Anything).Return(nil).Maybe()
	c := NewKeyorixCore(ms)
	c.SetAuditCheckpointKey(pinTestKey, "v1")
	return c, ms
}

func TestAuditCheckpointStatePin_Mock(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		state   func(t *testing.T) (string, bool, error)
		hash    func(ms *MockStorage) // AuditEntryHashByID expectation, if the case reaches it
		refused bool                  // refused as a proven truncation
		wantErr string                // any other error
	}{
		{
			name:  "no state row: legitimate first checkpoint proceeds",
			state: func(*testing.T) (string, bool, error) { return "", false, nil },
		},
		{
			name:  "garbled row (not avs-v1): documented fail-open, re-baselines",
			state: func(*testing.T) (string, bool, error) { return "garbage", true, nil },
		},
		{
			name: "undecodable payload: documented fail-open, re-baselines",
			state: func(*testing.T) (string, bool, error) {
				return strings.Join([]string{"avs-v1", "!!not-base64!!", "00"}, auditVerifyStateSep), true, nil
			},
		},
		{
			name: "signed under another key (a key change): re-baselines",
			state: func(t *testing.T) (string, bool, error) {
				return pinTestStoredState(t, []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb2"),
					auditVerifyState{Pin: &auditVerifyPin{Events: 10, HeadID: 10, HeadHash: "zzz"}}), true, nil
			},
		},
		{
			name: "authentic row, pin reached with the certified head: proceeds",
			state: func(t *testing.T) (string, bool, error) {
				return pinTestStoredState(t, pinTestKey,
					auditVerifyState{Pin: &auditVerifyPin{Events: 3, HeadID: 1, HeadHash: "abc"}}), true, nil
			},
			hash: func(ms *MockStorage) { ms.On("AuditEntryHashByID", mock.Anything, uint(1)).Return("abc", true, nil) },
		},
		{
			name: "authentic row certifies more events than remain: refused",
			state: func(t *testing.T) (string, bool, error) {
				return pinTestStoredState(t, pinTestKey,
					auditVerifyState{Pin: &auditVerifyPin{Events: 10, HeadID: 1, HeadHash: "abc"}}), true, nil
			},
			refused: true,
		},
		{
			name: "authentic row, certified head rewritten: refused",
			state: func(t *testing.T) (string, bool, error) {
				return pinTestStoredState(t, pinTestKey,
					auditVerifyState{Pin: &auditVerifyPin{Events: 3, HeadID: 1, HeadHash: "abc"}}), true, nil
			},
			hash:    func(ms *MockStorage) { ms.On("AuditEntryHashByID", mock.Anything, uint(1)).Return("other", true, nil) },
			refused: true,
		},
		{
			name: "authentic row, certified head row deleted and no retention anchor: refused",
			state: func(t *testing.T) (string, bool, error) {
				return pinTestStoredState(t, pinTestKey,
					auditVerifyState{Pin: &auditVerifyPin{Events: 3, HeadID: 1, HeadHash: "abc"}}), true, nil
			},
			hash:    func(ms *MockStorage) { ms.On("AuditEntryHashByID", mock.Anything, uint(1)).Return("", false, nil) },
			refused: true,
		},
		{
			name: "authentic row from before pins existed: the high-water bound alone refuses",
			state: func(t *testing.T) (string, bool, error) {
				return pinTestStoredState(t, pinTestKey,
					auditVerifyState{Bind: auditVerifyBinding{HighWater: 10}}), true, nil
			},
			refused: true,
		},
		{
			name:    "state row unreadable: the write fails, nothing is certified",
			state:   func(*testing.T) (string, bool, error) { return "", false, errors.New("db down") },
			wantErr: "db down",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			val, found, serr := tc.state(t)
			c, ms := pinTestCore(t, val, found, serr)
			if tc.hash != nil {
				tc.hash(ms)
			}
			cp, err := c.writeAuditCheckpointLocked(context.Background())
			switch {
			case tc.refused:
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrAuditCheckpointRefused)
				assert.ErrorIs(t, err, errAuditSignedStateTruncation)
				assert.Nil(t, cp)
				ms.AssertNotCalled(t, "CreateAuditCheckpoint", mock.Anything, mock.Anything)
			case tc.wantErr != "":
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				assert.False(t, errors.Is(err, errAuditSignedStateTruncation))
				assert.Nil(t, cp)
				ms.AssertNotCalled(t, "CreateAuditCheckpoint", mock.Anything, mock.Anything)
			default:
				require.NoError(t, err)
				require.NotNil(t, cp)
				assert.Equal(t, int64(3), cp.ChainedEvents)
				ms.AssertCalled(t, "CreateAuditCheckpoint", mock.Anything, mock.Anything)
			}
		})
	}
}
