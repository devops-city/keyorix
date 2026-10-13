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
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const readPathNodeSelect = "SELECT n.cache_epoch AS cache_epoch, "

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

// readNodeStampPrefetching is readLiveNodeStamp widened per the file header. It
// returns the stamp and the rows to park (nil when nothing may be parked).
func (ls *LocalStorage) readNodeStampPrefetching(ctx context.Context, pf *storage.ReadPathPrefetch, id uint, node *models.SecretNode) (nodeStampRead, *storage.PrefetchedPermission, *storage.PrefetchedScheduleVersion, bool) {
	q := readPathNodeSelect + nodeTriggerExistsExpr(ls.db) + " AS trigger_present,\n" +
		" ids.role_id AS role_id, gen.value AS generation"
	args := []any{SecretNodeCacheEpochTrigger}
	if pf.WantScheduleVersion {
		q += ",\n v.cnt AS cnt, v.max_ver AS max_ver, v.sum_rc AS sum_rc," +
			" s.id AS sched_id, s.secret_node_id AS sched_secret_node_id, s.allowed_days AS sched_allowed_days," +
			" s.start_hour AS sched_start_hour, s.end_hour AS sched_end_hour, s.timezone AS sched_timezone," +
			" s.created_at AS sched_created_at, s.updated_at AS sched_updated_at"
	}
	q += "\nFROM secret_nodes n\n" +
		"LEFT JOIN (\n" +
		" SELECT DISTINCT machine_identity_roles.role_id AS role_id FROM machine_identity_roles\n" +
		"  LEFT JOIN projects ON projects.id = machine_identity_roles.project_id\n" +
		"  LEFT JOIN environments ON environments.id = machine_identity_roles.environment_id\n" +
		"  WHERE machine_identity_roles.machine_identity_id = ?\n" +
		"   AND (machine_identity_roles.project_id = 0 OR (machine_identity_roles.project_id = ? AND projects.deleted_at IS NULL))\n" +
		"   AND (machine_identity_roles.environment_id = 0 OR (machine_identity_roles.environment_id = ? AND environments.deleted_at IS NULL))\n" +
		") ids ON 1 = 1\n" +
		"LEFT JOIN system_metadata gen ON gen.key = ?"
	args = append(args, pf.MachineID, node.ProjectID, node.EnvironmentID, rolePermissionsGenerationKey)
	if pf.WantScheduleVersion {
		q += "\nLEFT JOIN (SELECT COUNT(*) AS cnt, COALESCE(MAX(version_number), 0) AS max_ver, COALESCE(SUM(read_count), 0) AS sum_rc" +
			" FROM secret_versions WHERE secret_node_id = ?) v ON 1 = 1\n" +
			"LEFT JOIN secret_access_schedules s ON s.secret_node_id = n.id"
		args = append(args, id)
	}
	q += "\nWHERE n.id = ? AND n.deleted_at IS NULL"
	args = append(args, id)

	var rows []readPathPrefetchRow
	if err := ls.db.WithContext(ctx).Raw(q, args...).Scan(&rows).Error; err != nil {
		return nodeStampRead{}, nil, nil, false
	}
	if len(rows) == 0 {
		// No row (or soft-deleted): a miss for every caller, as readLiveNodeStamp.
		return nodeStampRead{}, nil, nil, true
	}
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
	return stamp, perm, sched, true
}
