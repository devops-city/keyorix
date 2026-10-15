// local_readpath_prefetch.go — the node-stamp read of a machine-token secret
// read, widened to answer the next two statements of the request as well.
//
// getCachedSecret validates a warm node-cache entry with readLiveNodeStamp (the
// stamp and the trigger proof, one statement). When the request declared a
// ReadPathPrefetch (internal/core/storage/readpath_prefetch.go), this reads in
// that SAME statement:
//
//   - the stamp and the trigger proof, exactly readLiveNodeStamp's expressions;
//   - the machine's role ids at the cached node's scope and the role->permission
//     cache generation, machinePrincipalPermissionSQL's clauses verbatim;
//   - when asked, the schedule row and the versions generation,
//     scheduleAndVersionsSQL's clauses verbatim.
//
// The extra answers are PARKED on the carrier only when the node cache hit is
// confirmed (row found, trigger present, stamp equal to the cached generation).
// That is what makes the scope they were read for the node's scope: an unchanged
// stamp means no persisted column of the row (project, environment included)
// moved. On any other outcome nothing is parked and the request pays its usual
// statements, so a stale or contested node can never lend its scope to the
// permission read. The consumers (ResolveMachinePermissionAt,
// GetSecretScheduleAndLatestVersion) take a parked answer only for the same
// machine and scope / the same secret, once.
//
// Nothing about what is decided changes: the same role clauses, the same
// generation-keyed role->permission cache, the same live read of every fact on
// every request. Only the number of round trips does. If the combined statement
// errors (a fixture without system_metadata, a transient failure) the classic
// readLiveNodeStamp runs and nothing is parked.
package store

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// readPathPrefetchRow is one row of the combined statement: one per machine
// role (a single row, role_id NULL, when the machine holds none at the scope).
type readPathPrefetchRow struct {
	CacheEpoch     int64
	TriggerPresent bool
	RoleID         *uint
	Generation     *string
	// The scheduleAndVersionsRow columns, flat (gorm does not scan into an
	// embedded unexported type reliably); only selected when asked for.
	Cnt               int64
	MaxVer            int64
	SumRc             int64
	SchedID           *uint
	SchedSecretNodeID *uint
	SchedAllowedDays  *string
	SchedStartHour    *int
	SchedEndHour      *int
	SchedTimezone     *string
	SchedCreatedAt    *time.Time
	SchedUpdatedAt    *time.Time
}

func (r readPathPrefetchRow) scheduleAndVersions() scheduleAndVersionsRow {
	return scheduleAndVersionsRow{
		Cnt: r.Cnt, MaxVer: r.MaxVer, SumRc: r.SumRc,
		SchedID: r.SchedID, SchedSecretNodeID: r.SchedSecretNodeID, SchedAllowedDays: r.SchedAllowedDays,
		SchedStartHour: r.SchedStartHour, SchedEndHour: r.SchedEndHour, SchedTimezone: r.SchedTimezone,
		SchedCreatedAt: r.SchedCreatedAt, SchedUpdatedAt: r.SchedUpdatedAt,
	}
}

// readPathPrefetchParts is the node read's select list and joins, as text only.
// The node-stamp statement (readPathPrefetchSQL) puts them on FROM secret_nodes n;
// the credential statement (foldedCredentialSQL, local_folded_credential.go) on
// a LEFT JOIN of secret_nodes n, so both read exactly the same clauses.
//
// Binds, in text order: cols binds the trigger name; joins binds the machine id,
// the node's project and environment, the generation key and, schedule/version
// only, the secret id (readPathPrefetchJoinArgs).
type readPathPrefetchParts struct {
	cols  string
	joins string
}

func readPathPrefetchPartsFor(triggerExpr, genExpr string, wantScheduleVersion bool) readPathPrefetchParts {
	cols := "n.cache_epoch AS cache_epoch, " + triggerExpr + " AS trigger_present,\n" +
		" ids.role_id AS role_id, " + genExpr + " AS generation"
	if wantScheduleVersion {
		cols += ",\n v.cnt AS cnt, v.max_ver AS max_ver, v.sum_rc AS sum_rc," +
			" s.id AS sched_id, s.secret_node_id AS sched_secret_node_id, s.allowed_days AS sched_allowed_days," +
			" s.start_hour AS sched_start_hour, s.end_hour AS sched_end_hour, s.timezone AS sched_timezone," +
			" s.created_at AS sched_created_at, s.updated_at AS sched_updated_at"
	}
	joins := "LEFT JOIN (\n" +
		" SELECT DISTINCT machine_identity_roles.role_id AS role_id FROM machine_identity_roles\n" +
		"  LEFT JOIN projects ON projects.id = machine_identity_roles.project_id\n" +
		"  LEFT JOIN environments ON environments.id = machine_identity_roles.environment_id\n" +
		"  WHERE machine_identity_roles.machine_identity_id = ?\n" +
		"   AND (machine_identity_roles.project_id = 0 OR (machine_identity_roles.project_id = ? AND projects.deleted_at IS NULL))\n" +
		"   AND (machine_identity_roles.environment_id = 0 OR (machine_identity_roles.environment_id = ? AND environments.deleted_at IS NULL))\n" +
		") ids ON 1 = 1\n" +
		"LEFT JOIN system_metadata gen ON gen.key = ?"
	if wantScheduleVersion {
		joins += "\nLEFT JOIN (SELECT COUNT(*) AS cnt, COALESCE(MAX(version_number), 0) AS max_ver, COALESCE(SUM(read_count), 0) AS sum_rc" +
			" FROM secret_versions WHERE secret_node_id = ?) v ON 1 = 1\n" +
			"LEFT JOIN secret_access_schedules s ON s.secret_node_id = n.id"
	}
	return readPathPrefetchParts{cols: cols, joins: joins}
}

// readPathPrefetchJoinArgs appends the binds of readPathPrefetchParts.joins.
func readPathPrefetchJoinArgs(args []any, pf *storage.ReadPathPrefetch, id uint, node *models.SecretNode) []any {
	args = append(args, pf.MachineID, node.ProjectID, node.EnvironmentID, rolePermissionsGenerationKey)
	if pf.WantScheduleVersion {
		args = append(args, id)
	}
	return args
}

// readPathPrefetchSQLKey selects one of the read-path statements' texts: they
// depend only on the statement (node-stamp or folded credential), the dialect
// (the trigger proof expression) and whether the schedule/version columns are
// asked for.
type readPathPrefetchSQLKey struct {
	folded              bool
	triggerExpr         string
	genExpr             string
	wantScheduleVersion bool
}

// readPathPrefetchSQLs holds each text once built, so the per-request cost is a
// map lookup instead of rebuilding the same string.
var readPathPrefetchSQLs sync.Map // readPathPrefetchSQLKey -> string

func cachedReadPathSQL(key readPathPrefetchSQLKey, build func(readPathPrefetchParts) string) string {
	if q, ok := readPathPrefetchSQLs.Load(key); ok {
		return q.(string)
	}
	q := build(readPathPrefetchPartsFor(key.triggerExpr, key.genExpr, key.wantScheduleVersion))
	readPathPrefetchSQLs.Store(key, q)
	return q
}

// readPathPrefetchSQL returns the node-stamp statement. Its bind order is: the
// trigger name, the machine id, the node's project and environment, the
// generation key, the secret id (schedule/version only) and the secret id.
func readPathPrefetchSQL(triggerExpr, genExpr string, wantScheduleVersion bool) string {
	key := readPathPrefetchSQLKey{triggerExpr: triggerExpr, genExpr: genExpr, wantScheduleVersion: wantScheduleVersion}
	return cachedReadPathSQL(key, func(p readPathPrefetchParts) string {
		return "SELECT " + p.cols + "\nFROM secret_nodes n\n" + p.joins + "\nWHERE n.id = ? AND n.deleted_at IS NULL"
	})
}

// readPathPrefetchArgs is readPathPrefetchSQL's binds, in its bind order.
func readPathPrefetchArgs(pf *storage.ReadPathPrefetch, id uint, node *models.SecretNode) []any {
	args := make([]any, 0, 7)
	return append(readPathPrefetchJoinArgs(append(args, SecretNodeCacheEpochTrigger), pf, id, node), id)
}

// readPathPrefetchTail scans the node read's columns after cache_epoch and
// trigger_present, in select-list order. Times go through sql.NullTime, which
// database/sql converts exactly as it does a *time.Time destination. Use one
// per row: finish points the row's times into it.
type readPathPrefetchTail struct {
	createdAt, updatedAt sql.NullTime
}

func (t *readPathPrefetchTail) dest(dst []any, r *readPathPrefetchRow, wantScheduleVersion bool) []any {
	dst = append(dst, &r.RoleID, &r.Generation)
	if wantScheduleVersion {
		dst = append(dst, &r.Cnt, &r.MaxVer, &r.SumRc,
			&r.SchedID, &r.SchedSecretNodeID, &r.SchedAllowedDays,
			&r.SchedStartHour, &r.SchedEndHour, &r.SchedTimezone,
			&t.createdAt, &t.updatedAt)
	}
	return dst
}

func (t *readPathPrefetchTail) finish(r *readPathPrefetchRow) {
	if t.createdAt.Valid {
		r.SchedCreatedAt = &t.createdAt.Time
	}
	if t.updatedAt.Valid {
		r.SchedUpdatedAt = &t.updatedAt.Time
	}
}

// scanReadPathPrefetchRows reads every row of the node-stamp statement into
// named variables, in select-list order. It replaces gorm's Raw(...).Scan(&rows),
// which on every call re-rendered the whole statement with its arguments
// inlined (a regexp pass, for a log line nobody reads) and matched columns to
// fields by reflection.
func scanReadPathPrefetchRows(rows rowScanner, wantScheduleVersion bool) ([]readPathPrefetchRow, error) {
	var out []readPathPrefetchRow
	for rows.Next() {
		var r readPathPrefetchRow
		var tail readPathPrefetchTail
		dest := tail.dest([]any{&r.CacheEpoch, &r.TriggerPresent}, &r, wantScheduleVersion)
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		tail.finish(&r)
		out = append(out, r)
	}
	return out, rows.Err()
}

// readNodeStampPrefetching is readLiveNodeStamp widened per the file header. It
// returns the stamp and the rows to park (nil when nothing may be parked).
func (ls *LocalStorage) readNodeStampPrefetching(ctx context.Context, pf *storage.ReadPathPrefetch, id uint, node *models.SecretNode) (nodeStampRead, *storage.PrefetchedPermission, *storage.PrefetchedScheduleVersion, bool) {
	q := readPathPrefetchSQL(nodeTriggerExistsExpr(ls.db), rolePermGenerationExpr(ls.db, "gen"), pf.WantScheduleVersion)
	rows, err := ls.readPathPrefetchRows(ctx, q, readPathPrefetchArgs(pf, id, node), pf.WantScheduleVersion)
	if err != nil {
		return nodeStampRead{}, nil, nil, false
	}
	if len(rows) == 0 {
		// No row (or soft-deleted): a miss for every caller, as readLiveNodeStamp.
		return nodeStampRead{}, nil, nil, true
	}
	stamp, perm, sched := readPathPrefetchFromRows(pf, id, node, rows)
	return stamp, perm, sched, true
}

// readPathPrefetchFromRows turns the node read's rows (at least one, node
// found) into the stamp and the answers to park.
func readPathPrefetchFromRows(pf *storage.ReadPathPrefetch, id uint, node *models.SecretNode, rows []readPathPrefetchRow) (nodeStampRead, *storage.PrefetchedPermission, *storage.PrefetchedScheduleVersion) {
	first := rows[0]
	stamp := nodeStampRead{
		generation: nodeGeneration{cacheEpoch: first.CacheEpoch},
		found:      true,
		trusted:    first.TriggerPresent,
	}

	permRows := make([]principalPermissionRow, 0, len(rows))
	for _, r := range rows {
		if r.RoleID == nil {
			continue
		}
		permRows = append(permRows, principalPermissionRow{RoleID: *r.RoleID, Generation: r.Generation})
	}
	perm := &storage.PrefetchedPermission{
		MachineID: pf.MachineID,
		Scope:     storage.Scope{ProjectID: node.ProjectID, EnvironmentID: node.EnvironmentID},
		Rows:      permRows,
	}
	var sched *storage.PrefetchedScheduleVersion
	if pf.WantScheduleVersion {
		// Every row repeats the one-row aggregate and the (unique) schedule row.
		s, gen := scheduleAndVersionsFromRow(first.scheduleAndVersions())
		sched = &storage.PrefetchedScheduleVersion{
			SecretID: id,
			State:    &prefetchedScheduleState{schedule: s, gen: gen},
		}
	}
	return stamp, perm, sched
}

// readPathPrefetchRows runs the node-stamp statement through gorm (so its
// callbacks, the statement counters and fault injection included, still see it)
// and scans the result with scanReadPathPrefetchRows. On Postgres it runs on the
// native pool, after the same callbacks (native_reads.go).
func (ls *LocalStorage) readPathPrefetchRows(ctx context.Context, q string, args []any, wantScheduleVersion bool) (_ []readPathPrefetchRow, err error) {
	if ls.nativeReads != nil {
		nrows, err := ls.queryNative(ctx, q, args)
		if err != nil {
			return nil, err
		}
		defer nrows.Close()
		return scanReadPathPrefetchRows(nrows, wantScheduleVersion)
	}
	rows, err := ls.db.WithContext(ctx).Raw(q, args...).Rows()
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	return scanReadPathPrefetchRows(rows, wantScheduleVersion)
}
