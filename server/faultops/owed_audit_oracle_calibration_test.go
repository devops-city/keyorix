// owed_audit_oracle_calibration_test.go -- red/green calibration of the owed-audit rule
// in owed_audit_oracle_test.go (read its file comment first).
//
// A rule that accepts something is only as good as the cases it still refuses, so
// every case here runs a REAL driven fault case (driveFaultCase: reference world +
// faulted world over the real REST stack) and either feeds it to the rule untouched
// (GREEN) or damages the faulted world's state the way a regression would (RED), then
// re-snapshots and asks the real checkOraclesReporting. Nothing is hand-written state
// except where the case is "the state a different bug would leave".
//
//	GREEN  g1  group-member removal, LogAuditEvent#1: owed row + pending row, backfill converges
//	       g2  SSO callback, ClaimPendingAuditEvent#1 (the CI seed 5012b3d0b086d4a4)
//	       g3  group-member removal, CreatePendingAuditEvent#1: rule does NOT apply, state == reference
//	RED    i   neither an audit row nor a pending row
//	       i2  the pending record AND the direct audit write both failed (state: effect, no row, no record)
//	       ii  pending rows fewer than missing audit rows / a duplicated pending row
//	       iii backfill not run / does nothing / over-writes (duplicate audit row)
//	       iv  pending row present but the effect missing
//	       v   a fault outside the scope producing the same diff
//	       vi  an op outside auditTx3RevocationOps with the same diff
package faultops

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const owedCalOp = "REST DELETE /api/v1/groups/{id}/members/{userId}"

// owedCalTwoRowOp owes two audit rows (the sweep logs the ops that do).
const owedCalTwoRowOp = "REST POST /api/v1/projects/{id}/break-glass/{activationId}/revoke"

// owedCalDriveRaw drives one case WITHOUT convergence: the harness's own oracle call
// inside the drive must leave the faulted world in its pre-backfill state (see
// owedAuditDepsFor). The caller then runs the oracle (owedCalFindings) itself.
func owedCalDriveRaw(t *testing.T, op, method string, nth int, kind faultstorage.FaultKind) (oracleInput, driveOutcome, string) {
	t.Helper()
	saved := owedAuditDepsFor
	owedAuditDepsFor = func(*faultWorld) owedAuditDeps { return owedAuditDeps{} }
	defer func() { owedAuditDepsFor = saved }()
	return driveFaultCase(t, op, method, nth, kind)
}

func owedCalDrive(t *testing.T, op, method string, nth int, kind faultstorage.FaultKind) oracleInput {
	t.Helper()
	in, outcome, why := owedCalDriveRaw(t, op, method, nth, kind)
	require.Equal(t, driveObserved, outcome, "case %s %s#%d/%s was not observed: %s", op, method, nth, kind, why)
	require.NotNil(t, in.world, "the oracle input must carry the faulted world")
	require.True(t, in.result.Success, "%s must still succeed under %s#%d: %s", op, method, nth, in.result.Detail)
	return in
}

func owedCalFindings(t *testing.T, in oracleInput) []string {
	t.Helper()
	return oracleFindingsWithout(t, in, func() func() { return func() {} })
}

// owedCalResnapshot re-takes the faulted world's snapshot after the test damaged it.
func owedCalResnapshot(t *testing.T, in oracleInput) oracleInput {
	t.Helper()
	snap, err := snapshotDB(in.world.db)
	require.NoError(t, err)
	in.after = snap
	return in
}

// owedCalSplice returns base with the named tables replaced by from's, and the overall
// hash recomputed by snapshotDB's formula: the state "this run's audit tables, that
// run's everything else".
func owedCalSplice(base, from dbSnapshot, tables ...string) dbSnapshot {
	out := dbSnapshot{Tables: make(map[string]tableSnapshot, len(base.Tables))}
	maps.Copy(out.Tables, base.Tables)
	for _, name := range tables {
		out.Tables[name] = from.Tables[name]
	}
	var lines []string
	for _, ts := range out.Tables {
		lines = append(lines, ts.Table+":"+ts.Hash)
	}
	sort.Strings(lines)
	h := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	out.Hash = hex.EncodeToString(h[:])
	return out
}

func owedCalViolates(findings []string, rule bool) bool {
	for _, f := range findings {
		if strings.Contains(f, "ORACLE (a) VIOLATION") && strings.Contains(f, "owed-audit rule") == rule {
			return true
		}
	}
	return false
}

func owedSweepWide() bool { return os.Getenv("KEYORIX_OWED_SWEEP_WIDE") == "1" }

type owedCalRow struct{ name, expected, got string }

func TestOwedAuditOracle_Calibration(t *testing.T) {
	var rows []owedCalRow
	record := func(name, expected string, ok bool, got string) {
		if !ok {
			t.Errorf("%s: expected %s, got %s", name, expected, got)
		}
		rows = append(rows, owedCalRow{name, expected, got})
	}
	exec := func(in oracleInput, sql string, args ...any) {
		t.Helper()
		require.NoError(t, in.world.db.Exec(sql, args...).Error)
	}

	t.Run("GREEN", func(t *testing.T) {
		for _, c := range []struct {
			name, op, method string
			nth              int
		}{
			{"g1 owed outcome, LogAuditEvent#1, backfill converges", owedCalOp, "LogAuditEvent", 1},
			{"g2 SSO callback ClaimPendingAuditEvent#1 (seed 5012b3d0b086d4a4)", owedAuditSSOCallbackOp, "ClaimPendingAuditEvent", 1},
			{"g4 two owed rows (break-glass revoke), LogAuditEvent#1: both queued, backfill converges", owedCalTwoRowOp, "LogAuditEvent", 1},
		} {
			in := owedCalDrive(t, c.op, c.method, c.nth, faultstorage.KindError)
			require.NotEqual(t, in.refAfter.Hash, in.after.Hash, "premise: the owed outcome differs from the reference before the backfill")
			wantPending := 1
			if c.op == owedCalTwoRowOp {
				wantPending = 2
			}
			require.EqualValues(t, wantPending, len(in.after.Tables[owedAuditPendingTable].Rows), "premise: one pending record per owed row")
			d := owedAuditVerdict(in, owedAuditDepsFor(in.world))
			f := owedCalFindings(t, owedCalDriveAgain(t, c.op, c.method, c.nth))
			ok := d.engaged && d.violation == "" && len(f) == 0
			record(c.name, "accepted by the rule, no finding", ok, fmt.Sprintf("engaged=%t violation=%q findings=%v", d.engaged, d.violation, f))
		}

		// g3: the pending-record write fails too -> the rule does not apply; the
		// fallback (effect applied, row attempted directly) must equal the reference.
		in := owedCalDrive(t, owedCalOp, "CreatePendingAuditEvent", 1, faultstorage.KindError)
		d := owedAuditVerdict(in, owedAuditDepsFor(in.world))
		f := owedCalFindings(t, in)
		ok := !d.engaged && in.after.Hash == in.refAfter.Hash && len(f) == 0
		record("g3 CreatePendingAuditEvent#1: rule not applied, final state == reference (row written directly)",
			"state equals the reference, no finding", ok,
			fmt.Sprintf("engaged=%t sameAsReference=%t findings=%v", d.engaged, in.after.Hash == in.refAfter.Hash, f))
	})

	t.Run("RED", func(t *testing.T) {
		// i: neither an audit row nor a pending row.
		in := owedCalDrive(t, owedCalOp, "LogAuditEvent", 1, faultstorage.KindError)
		exec(in, "DELETE FROM pending_audit_events")
		in = owedCalResnapshot(t, in)
		f := owedCalFindings(t, in)
		record("i  neither audit row nor pending row", "violation (rule)", owedCalViolates(f, true), fmt.Sprint(f))

		// i2: the pending record and the direct write both failed: the effect stands,
		// no audit row, no record. Built on the CreatePendingAuditEvent case by removing
		// the row the fallback wrote directly.
		in = owedCalDrive(t, owedCalOp, "CreatePendingAuditEvent", 1, faultstorage.KindError)
		exec(in, "DELETE FROM audit_events WHERE id = (SELECT MAX(id) FROM audit_events)")
		in = owedCalResnapshot(t, in)
		f = owedCalFindings(t, in)
		record("i2 pending write AND direct audit write both failed ('NOT queued, record it by hand')", "violation (rule)",
			owedCalViolates(f, true), fmt.Sprint(f))

		// ii-c: two rows owed, only one of them queued (pending 1 < missing 2).
		in = owedCalDrive(t, owedCalTwoRowOp, "LogAuditEvent", 1, faultstorage.KindError)
		require.EqualValues(t, 2, len(in.after.Tables[owedAuditPendingTable].Rows), "premise: two pending records")
		exec(in, "DELETE FROM pending_audit_events WHERE id = (SELECT MAX(id) FROM pending_audit_events)")
		in = owedCalResnapshot(t, in)
		f = owedCalFindings(t, in)
		record("ii-c two rows owed, one pending record (pending 1 < missing 2)", "violation (rule)", owedCalViolates(f, true), fmt.Sprint(f))

		// ii-a: an audit row is lost in the same run as a queued record.
		in = owedCalDrive(t, owedCalOp, "LogAuditEvent", 1, faultstorage.KindError)
		exec(in, "DELETE FROM audit_events WHERE id = (SELECT MAX(id) FROM audit_events)")
		in = owedCalResnapshot(t, in)
		f = owedCalFindings(t, in)
		record("ii-a an audit row lost besides the queued one (cannot be attributed)", "violation (rule)", owedCalViolates(f, true), fmt.Sprint(f))

		// ii-b: a duplicated pending record for one event.
		in = owedCalDrive(t, owedCalOp, "LogAuditEvent", 1, faultstorage.KindError)
		exec(in, "INSERT INTO pending_audit_events (event_type, event, last_error, attempts, created_at, updated_at) "+
			"SELECT event_type, event, last_error, attempts, created_at, updated_at FROM pending_audit_events")
		in = owedCalResnapshot(t, in)
		f = owedCalFindings(t, in)
		record("ii-b two pending rows for one event", "violation (rule)", owedCalViolates(f, true), fmt.Sprint(f))

		// iii: convergence. The state is the real owed outcome; only the backfill step differs.
		in = owedCalDrive(t, owedCalOp, "LogAuditEvent", 1, faultstorage.KindError)
		d := owedAuditVerdict(in, owedAuditDeps{owedTypes: owedAuditProbeFor(in.world)})
		record("iii-a backfill not run", "violation", d.engaged && d.violation != "", fmt.Sprintf("%+v", d))
		in = owedCalDrive(t, owedCalOp, "LogAuditEvent", 1, faultstorage.KindError)
		require.EqualValues(t, 1, int64(len(in.after.Tables[owedAuditPendingTable].Rows)), "premise: pending record present")
		d = owedAuditVerdict(in, owedAuditDeps{owedTypes: owedAuditProbeFor(in.world), converge: func() (dbSnapshot, error) { return snapshotDB(in.world.db) }})
		record("iii-b backfill does nothing (pending row stays)", "violation", d.engaged && d.violation != "", fmt.Sprintf("%+v", d))
		in = owedCalDrive(t, owedCalOp, "LogAuditEvent", 1, faultstorage.KindError)
		d = owedAuditVerdict(in, owedAuditDeps{owedTypes: owedAuditProbeFor(in.world), converge: func() (dbSnapshot, error) {
			real := owedAuditConvergeFor(in.world)
			if _, err := real(); err != nil {
				return dbSnapshot{}, err
			}
			var ev models.AuditEvent
			if err := in.world.db.Order("id desc").First(&ev).Error; err != nil {
				return dbSnapshot{}, err
			}
			ev.ID = 0
			if err := in.world.db.Create(&ev).Error; err != nil { // the row written twice
				return dbSnapshot{}, err
			}
			return snapshotDB(in.world.db)
		}})
		record("iii-c backfill writes a row twice", "violation", d.engaged && d.violation != "", fmt.Sprintf("%+v", d))

		// iv: pending row present but the effect missing (audit tables of the owed
		// outcome, everything else as before the request).
		in = owedCalDrive(t, owedCalOp, "LogAuditEvent", 1, faultstorage.KindError)
		in.after = owedCalSplice(in.before, in.after, owedAuditAuditTable, owedAuditPendingTable)
		f = owedCalFindings(t, in)
		record("iv  pending row present, effect missing", "violation (rule)", owedCalViolates(f, true), fmt.Sprint(f))

		// v: a fault outside the scope producing the same diff.
		in = owedCalDrive(t, owedCalOp, "LogAuditEvent", 1, faultstorage.KindError)
		in.method = "GetSystemMetadata"
		d = owedAuditVerdict(in, owedAuditDepsFor(in.world))
		f = owedCalFindings(t, in)
		record("v   unrelated storage fault (GetSystemMetadata) with the owed diff", "violation (not the rule's), rule not engaged",
			!d.engaged && owedCalViolates(f, false), fmt.Sprintf("engaged=%t findings=%v", d.engaged, f))

		// vi: an op outside auditTx3RevocationOps with the same diff.
		in = owedCalDrive(t, owedCalOp, "LogAuditEvent", 1, faultstorage.KindError)
		in.op = "REST POST /api/v1/groups/"
		d = owedAuditVerdict(in, owedAuditDepsFor(in.world))
		f = owedCalFindings(t, in)
		record("vi  op outside auditTx3RevocationOps with the owed diff", "violation (not the rule's), rule not engaged",
			!d.engaged && owedCalViolates(f, false), fmt.Sprintf("engaged=%t findings=%v", d.engaged, f))
	})

	var b strings.Builder
	b.WriteString("\n| case | expected | got |\n|---|---|---|\n")
	for _, r := range rows {
		got := r.got
		if _, rest, ok := strings.Cut(got, "ORACLE (a) VIOLATION — "); ok {
			got = "ORACLE (a) VIOLATION — " + rest // drop the op/fault prefix every row repeats
		}
		if len(got) > 330 {
			got = got[:330] + "..."
		}
		fmt.Fprintf(&b, "| %s | %s | %s |\n", r.name, r.expected, strings.ReplaceAll(got, "|", "/"))
	}
	t.Log(b.String())
}

// owedCalDriveAgain re-drives a case for the full-oracle check: the first drive's world
// was already backfilled by the verdict call (it mutates the world, by design).
func owedCalDriveAgain(t *testing.T, op, method string, nth int) oracleInput {
	return owedCalDrive(t, op, method, nth, faultstorage.KindError)
}

// TestOwedAuditOracle_EmbeddedTimeNormalisation pins what the payload comparison ignores
// (a timestamp's value inside text) and what it still compares (everything else).
func TestOwedAuditOracle_EmbeddedTimeNormalisation(t *testing.T) {
	t.Parallel()
	canon := func(desc string) string {
		p, err := owedAuditCanon(map[string]any{"ID": 7, "EventType": "setup_token.issued", "Description": desc}, false)
		require.NoError(t, err)
		return p
	}
	const base = "setup token issued (purpose=invitation_accept, subject=a@example.com, expires=%s)"
	require.Equal(t, canon(fmt.Sprintf(base, "2026-10-21T14:57:33Z")), canon(fmt.Sprintf(base, "2026-10-21T14:57:34Z")),
		"a timestamp that differs by a second between two worlds is the same payload")
	require.Equal(t, canon(fmt.Sprintf(base, "2026-10-21T14:57:33Z")), canon(fmt.Sprintf(base, "2026-10-21T16:57:33.5+02:00")))
	require.NotEqual(t, canon(fmt.Sprintf(base, "2026-10-21T14:57:33Z")), canon("setup token issued (purpose=invitation_accept, subject=b@example.com, expires=2026-10-21T14:57:33Z)"),
		"a different subject is a different payload")
	require.NotEqual(t, canon(fmt.Sprintf(base, "2026-10-21T14:57:33Z")), canon("setup token revoked (purpose=invitation_accept, subject=a@example.com, expires=2026-10-21T14:57:33Z)"),
		"different text around the time is a different payload")
	require.NotEqual(t, canon(fmt.Sprintf(base, "2026-10-21T14:57:33Z")), canon(fmt.Sprintf(base, "tomorrow")),
		"a value that is not a timestamp is not normalised away")
}

// TestOwedAuditOracle_PendingEventSnapshotIgnoresOnlyTime pins the snapshot's handling
// of PendingAuditEvent.Event (typeScopedTimeInText): the event's wall-clock EventTime is
// ignored, and nothing else in the column is.
func TestOwedAuditOracle_PendingEventSnapshotIgnoresOnlyTime(t *testing.T) {
	t.Parallel()
	ev := func(at, desc string) *models.PendingAuditEvent {
		return &models.PendingAuditEvent{ID: 1, EventType: "group.member_removed", Attempts: 1,
			Event: fmt.Sprintf(`{"EventType":"group.member_removed","Description":%q,"EventTime":%q}`, desc, at)}
	}
	canon := func(p *models.PendingAuditEvent) string {
		s, err := canonicalRow(p)
		require.NoError(t, err)
		return s
	}
	require.Equal(t, canon(ev("2026-10-20T17:04:41.362827+02:00", "removed")), canon(ev("2026-10-20T17:04:49.083121+02:00", "removed")),
		"two worlds never share a clock reading")
	require.NotEqual(t, canon(ev("2026-10-20T17:04:41+02:00", "removed")), canon(ev("2026-10-20T17:04:41+02:00", "removed twice")),
		"a different payload is a different row")
}

// TestOwedAuditOracle_ScopeIsExact pins condition 1 without a world: only a SUCCESS,
// only the listed ops, only the listed faults engage the rule.
func TestOwedAuditOracle_ScopeIsExact(t *testing.T) {
	t.Parallel()
	require.True(t, owedAuditRuleOp(owedAuditSSOCallbackOp))
	for _, op := range auditTx3RevocationOps {
		require.True(t, owedAuditRuleOp(op), op)
	}
	for _, op := range auditTx3FailClosedOps {
		require.False(t, owedAuditRuleOp(op), "%s is a fail-closed op, not a revocation", op)
	}
	differing := func(op, method string, success bool) oracleInput {
		a := dbSnapshot{Hash: "a", Tables: map[string]tableSnapshot{"Secret": {Table: "Secret", Hash: "x"}}}
		r := dbSnapshot{Hash: "r", Tables: map[string]tableSnapshot{"Secret": {Table: "Secret", Hash: "y"}}}
		return oracleInput{op: op, method: method, result: opResult{Success: success}, after: a, refAfter: r, before: r}
	}
	require.False(t, owedAuditVerdict(differing(owedCalOp, "LogAuditEvent", false), owedAuditDeps{}).engaged, "an error result is not this rule's business")
	require.False(t, owedAuditVerdict(differing(owedCalOp, "GetUser", true), owedAuditDeps{}).engaged, "an unrelated fault")
	require.False(t, owedAuditVerdict(differing("REST POST /api/v1/groups/", "LogAuditEvent", true), owedAuditDeps{}).engaged, "an op outside the list")
	require.True(t, owedAuditVerdict(differing(owedCalOp, "CreatePendingAuditEvent", true), owedAuditDeps{}).violation != "",
		"a CreatePendingAuditEvent fault with a state difference is a violation, never accepted")
}

// TestOwedAuditOracle_SweepEveryScopedOp drives every in-scope op under each audit-path
// fault (error kind, first call; KEYORIX_OWED_SWEEP_WIDE=1 widens to three kinds and
// more call ordinals) through the real oracle: none may be reported. A fault that never
// fires for an op is counted, not failed.
func TestOwedAuditOracle_SweepEveryScopedOp(t *testing.T) {
	kinds := []faultstorage.FaultKind{faultstorage.KindError}
	nths := map[string]int{"LogAuditEvent": 1, "ClaimPendingAuditEvent": 1, "CreatePendingAuditEvent": 1}
	if owedSweepWide() {
		kinds = []faultstorage.FaultKind{faultstorage.KindError, faultstorage.KindPanic, faultstorage.KindEffectThenError}
		nths = map[string]int{"LogAuditEvent": 3, "ClaimPendingAuditEvent": 2, "CreatePendingAuditEvent": 2}
	}
	ops := append([]string{owedAuditSSOCallbackOp}, auditTx3RevocationOps...)
	var accepted, same, neverFired, notSuccess int
	var multiOwed []string
	for _, op := range ops {
		// Every scoped op must OWE at least one row. The rule takes the owed event types
		// from a probe (owedAuditProbeFor); a revocation regressed to a plain best-effort
		// row would owe nothing, the rule would stop engaging for it, and only this
		// assertion (and TestAuditTx3Revocation_AuditFailureDoesNotBlockAndRowIsOwed)
		// would notice.
		in, outcome, why := owedCalDriveRaw(t, op, "LogAuditEvent", 1, faultstorage.KindError)
		if outcome != driveObserved {
			t.Errorf("%s: LogAuditEvent#1 case not observed: %s", op, why)
		} else if types, err := owedAuditProbeFor(in.world)(op); err != nil {
			t.Errorf("%s: owed-type probe failed: %v", op, err)
		} else {
			total := 0
			for _, n := range types {
				total += n
			}
			if total == 0 {
				t.Errorf("%s owes no audit row (a refused first append queued nothing): it is not an owed-audit revocation any more", op)
			}
			if total > 1 {
				multiOwed = append(multiOwed, fmt.Sprintf("%s=%d", op, total))
			}
		}
		for method, maxNth := range nths {
			for nth := 1; nth <= maxNth; nth++ {
				for _, kind := range kinds {
					in, outcome, why := owedCalDriveRaw(t, op, method, nth, kind)
					switch outcome {
					case driveFaultNeverFired:
						neverFired++
						continue
					case driveObserved:
					default:
						t.Errorf("%s %s#%d/%s: not evaluated: %s", op, method, nth, kind, why)
						continue
					}
					if !in.result.Success {
						notSuccess++
					}
					if in.after.Hash == in.refAfter.Hash {
						same++
					}
					if f := owedCalFindings(t, in); len(f) > 0 {
						t.Errorf("%s %s#%d/%s: %v", op, method, nth, kind, f)
						continue
					}
					accepted++
				}
			}
		}
	}
	t.Logf("sweep: %d ops; cases with no finding: %d (of which state == reference: %d, reported errors: %d); fault never fired: %d",
		len(ops), accepted, same, notSuccess, neverFired)
	t.Logf("ops owing more than one audit row: %v", multiOwed)
}
