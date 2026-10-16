// cross_replica_ops_oracle_test.go — calibration for FuzzCrossReplicaOps'
// oracle (c) (cross_replica_ops_fuzz_test.go), runnable without Postgres.
//
// Green: the exact history that flaked on CI (FLAKE-CROSSREPLICA-1, PR #3274
// run 38764382297: a grant committed first but returned after a revoke on the
// other replica, final DB state false) is accepted, as is the same shape on
// the rotate register. The old oracle sorted successes by Return time and
// rejected both.
//
// Red: planted lost updates, double writes, stale cross-replica reads and
// final-state mismatches are each rejected, so moving off Return order did
// not loosen the oracle.
package core

import (
	"testing"

	"github.com/anishathalye/porcupine"
)

func crGrantHist(ops ...porcupine.Operation) []porcupine.Operation { return ops }

func crG(client int, call, ret int64, in crGrantOp) porcupine.Operation {
	return porcupine.Operation{ClientId: client, Input: in, Call: call, Return: ret}
}

var (
	crSet      = crGrantOp{kind: crGrantSet}
	crClear    = crGrantOp{kind: crGrantClear}
	crSeesTrue = crGrantOp{kind: crGrantObserve, val: true}
	crSeesNone = crGrantOp{kind: crGrantObserve, val: false}
)

func TestCrossReplicaOracleC_RoleGrant(t *testing.T) {
	cases := []struct {
		name            string
		grants, revokes int
		final           bool
		hist            []porcupine.Operation
		wantErr         bool
	}{
		{
			// The CI flake: grant [0,100] committed before revoke [10,50]
			// deleted its row, but returned last. DB false is the only legal
			// outcome; Return-order replay wrongly expected true.
			name: "ci flake: grant commits first, returns last", grants: 1, revokes: 1, final: false,
			hist: crGrantHist(crG(0, 0, 100, crSet), crG(1, 10, 50, crClear), crG(9, 200, 200, crSeesNone)),
		},
		{
			name: "grant then refused grant then revoke", grants: 1, revokes: 1, final: false,
			hist: crGrantHist(crG(0, 0, 10, crSet), crG(1, 20, 30, crSeesTrue), crG(2, 40, 50, crClear), crG(9, 60, 60, crSeesNone)),
		},
		{
			name: "planted double grant", grants: 2, revokes: 0, final: true, wantErr: true,
			hist: crGrantHist(crG(0, 0, 10, crSet), crG(1, 5, 15, crSet), crG(9, 60, 60, crSeesTrue)),
		},
		{
			name: "planted lost revoke", grants: 1, revokes: 1, final: true, wantErr: true,
			hist: crGrantHist(crG(0, 0, 10, crSet), crG(1, 20, 30, crClear), crG(9, 60, 60, crSeesTrue)),
		},
		{
			// Counts are consistent; only real time exposes it: replica B
			// refused a revoke as "not assigned" after replica A's grant had
			// already returned, and nothing revoked in between.
			name: "planted stale cross-replica read", grants: 1, revokes: 0, final: true, wantErr: true,
			hist: crGrantHist(crG(0, 0, 10, crSet), crG(1, 20, 30, crSeesNone), crG(9, 60, 60, crSeesTrue)),
		},
		{
			name: "planted revoke before any grant", grants: 1, revokes: 1, final: false, wantErr: true,
			hist: crGrantHist(crG(1, 0, 10, crClear), crG(0, 20, 30, crSet), crG(9, 60, 60, crSeesNone)),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkGrantCommitOrderReplay(tc.grants, tc.revokes, tc.final)
			if err == nil {
				err = checkGrantRegisterLinearizable(tc.hist, t.Logf)
			}
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Fatalf("oracle (c) verdict = %v, want error=%v", err, tc.wantErr)
			}
		})
	}
}

func TestCrossReplicaOracleC_RotateSecret(t *testing.T) {
	const base = 5
	cases := []struct {
		name     string
		valueAt  map[int]string
		attempts []crRotateAttempt
		actual   string
		wantErr  bool
	}{
		{
			// Same shape as the role-grant flake: a committed first (v6) but
			// returned after b (v7). Final b is correct.
			name:    "first committer returns last",
			valueAt: map[int]string{5: "base", 6: "a", 7: "b"},
			attempts: []crRotateAttempt{
				{value: "a", callAt: 0, retAt: 100, ok: true},
				{value: "b", callAt: 10, retAt: 50, ok: true},
			},
			actual: "b",
		},
		{
			name:     "failed rotate kept its stored version",
			valueAt:  map[int]string{5: "base", 6: "a"},
			attempts: []crRotateAttempt{{value: "a", callAt: 0, retAt: 10, ok: false}},
			actual:   "a",
		},
		{
			name:    "planted lost update",
			valueAt: map[int]string{5: "base", 6: "b"},
			attempts: []crRotateAttempt{
				{value: "a", callAt: 0, retAt: 10, ok: true},
				{value: "b", callAt: 0, retAt: 10, ok: true},
			},
			actual: "b", wantErr: true,
		},
		{
			name:    "planted real-time inversion",
			valueAt: map[int]string{5: "base", 6: "b", 7: "a"},
			attempts: []crRotateAttempt{
				{value: "a", callAt: 0, retAt: 10, ok: true},
				{value: "b", callAt: 20, retAt: 30, ok: true},
			},
			actual: "a", wantErr: true,
		},
		{
			name:     "planted stale final read",
			valueAt:  map[int]string{5: "base", 6: "a"},
			attempts: []crRotateAttempt{{value: "a", callAt: 0, retAt: 10, ok: true}},
			actual:   "base", wantErr: true,
		},
		{
			name:     "planted phantom version",
			valueAt:  map[int]string{5: "base", 6: "a", 7: "zzz"},
			attempts: []crRotateAttempt{{value: "a", callAt: 0, retAt: 10, ok: true}},
			actual:   "zzz", wantErr: true,
		},
		{
			name:     "planted duplicated write",
			valueAt:  map[int]string{5: "base", 6: "a", 7: "a"},
			attempts: []crRotateAttempt{{value: "a", callAt: 0, retAt: 10, ok: true}},
			actual:   "a", wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkRotateCommitOrder(base, "base", tc.valueAt, tc.attempts, tc.actual)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Fatalf("oracle (c) verdict = %v, want error=%v", err, tc.wantErr)
			}
		})
	}
}
