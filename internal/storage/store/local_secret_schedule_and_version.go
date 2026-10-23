// local_secret_schedule_and_version.go — GetSecretScheduleAndLatestVersion
// (PERF-FIX-4, collapse C5 of SESSION-PERF-FIX-3's plan).
//
// A latest-version value read (core getSecretValueForUser) used to issue two
// statements on the same secret after its guards: GetSecretAccessSchedule (the
// schedule row, or its generation probe on a warm entry) and
// GetLatestSecretVersion's versions-generation probe (liveVersionsGeneration).
// This reads both in ONE statement: the versions aggregate as a one-row derived
// table, LEFT JOIN the schedule row (secret_node_id is unique on that table).
// The version row itself is still read only when the version cache misses,
// after the generation, exactly as GetLatestSecretVersion does.
//
// Cache semantics kept from the two methods it replaces on this path:
//   - schedule: no cache read is needed (the whole row is read live), but the
//     cache is published and evicted with GetSecretAccessSchedule's rules, so
//     other callers of that method see the same cache state as before: a found
//     row is published under its own generation (read in the same statement)
//     unless an entry with that generation is already there, a missing row
//     evicts, and nothing is published from a transaction-scoped store.
//   - latest version: validated against the (count, max, sum) generation from
//     the combined statement, the same signal liveVersionsGeneration reads;
//     a miss reads the row and publishes under that generation
//     (readLatestSecretVersionRow, shared with GetLatestSecretVersion).
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

// scheduleAndVersionsSQL is the combined statement. The derived table always
// yields exactly one row (an aggregate without GROUP BY), so the LEFT JOIN
// yields exactly one row too: schedule columns NULL when there is no schedule.
// The aggregate expressions are liveVersionsGeneration's, verbatim.
const scheduleAndVersionsSQL = `SELECT v.cnt AS cnt, v.max_ver AS max_ver, v.sum_rc AS sum_rc, v.sum_ce AS sum_ce,
 s.id AS sched_id, s.secret_node_id AS sched_secret_node_id, s.allowed_days AS sched_allowed_days,
 s.start_hour AS sched_start_hour, s.end_hour AS sched_end_hour, s.timezone AS sched_timezone,
 s.created_at AS sched_created_at, s.updated_at AS sched_updated_at
FROM (SELECT ` + versionsAggregateSQL + `
 FROM secret_versions WHERE secret_node_id = ?) v
LEFT JOIN secret_access_schedules s ON s.secret_node_id = ?`

type scheduleAndVersionsRow struct {
	Cnt               int64
	MaxVer            int64
	SumRc             int64
	SumCe             int64
	SchedID           *uint
	SchedSecretNodeID *uint
	SchedAllowedDays  *string
	SchedStartHour    *int
	SchedEndHour      *int
	SchedTimezone     *string
	SchedCreatedAt    *time.Time
	SchedUpdatedAt    *time.Time
}

// readScheduleAndVersionsGeneration runs scheduleAndVersionsSQL. schedule is
// nil when the secret has no schedule row.
func readScheduleAndVersionsGeneration(ctx context.Context, db *gorm.DB, secretNodeID uint) (*models.SecretAccessSchedule, versionsGeneration, error) {
	var row scheduleAndVersionsRow
	res := db.WithContext(ctx).Raw(scheduleAndVersionsSQL, secretNodeID, secretNodeID).Scan(&row)
	if res.Error != nil {
		return nil, versionsGeneration{}, res.Error
	}
	if res.RowsAffected != 1 {
		// Cannot happen for an aggregate derived table; fail closed rather
		// than read a zero generation and a "no schedule" out of nothing.
		return nil, versionsGeneration{}, fmt.Errorf("schedule/version snapshot returned %d rows", res.RowsAffected)
	}
	sched, gen := scheduleAndVersionsFromRow(row)
	return sched, gen, nil
}

// scheduleAndVersionsFromRow decodes one scheduleAndVersionsSQL-shaped row.
func scheduleAndVersionsFromRow(row scheduleAndVersionsRow) (*models.SecretAccessSchedule, versionsGeneration) {
	gen := versionsGeneration{count: row.Cnt, maxVersionNumber: row.MaxVer, sumReadCount: row.SumRc, sumCacheEpoch: row.SumCe}
	if row.SchedID == nil {
		return nil, gen
	}
	sched := &models.SecretAccessSchedule{ID: *row.SchedID}
	if row.SchedSecretNodeID != nil {
		sched.SecretNodeID = *row.SchedSecretNodeID
	}
	if row.SchedAllowedDays != nil {
		sched.AllowedDays = *row.SchedAllowedDays
	}
	if row.SchedStartHour != nil {
		sched.StartHour = *row.SchedStartHour
	}
	if row.SchedEndHour != nil {
		sched.EndHour = *row.SchedEndHour
	}
	if row.SchedTimezone != nil {
		sched.Timezone = *row.SchedTimezone
	}
	if row.SchedCreatedAt != nil {
		sched.CreatedAt = *row.SchedCreatedAt
	}
	if row.SchedUpdatedAt != nil {
		sched.UpdatedAt = *row.SchedUpdatedAt
	}
	return sched, gen
}

// prefetchedScheduleState is what the node read parks for
// GetSecretScheduleAndLatestVersion (see readpath_prefetch.go).
type prefetchedScheduleState struct {
	schedule *models.SecretAccessSchedule
	gen      versionsGeneration
}

// GetSecretScheduleAndLatestVersion — see the storage.Storage doc comment and
// this file's header.
func (ls *LocalStorage) GetSecretScheduleAndLatestVersion(ctx context.Context, secretNodeID uint) (*storage.SecretScheduleAndLatestVersion, error) {
	var (
		sched   *models.SecretAccessSchedule
		liveGen versionsGeneration
		parked  bool
		err     error
	)
	if pf := storage.ReadPathPrefetchFrom(ctx); pf != nil {
		if taken := pf.TakeScheduleVersion(secretNodeID); taken != nil {
			if st, ok := taken.State.(*prefetchedScheduleState); ok {
				sched, liveGen, parked = st.schedule, st.gen, true
			}
		}
	}
	if !parked {
		// Nothing parked for this secret: the statement this method always ran.
		sched, liveGen, err = readScheduleAndVersionsGeneration(ctx, ls.db, secretNodeID)
	}
	if err != nil {
		// GetSecretAccessSchedule's error shape: the schedule is judged first,
		// so a failure of the shared statement is a schedule-read failure.
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	out := &storage.SecretScheduleAndLatestVersion{Schedule: sched}

	if sched == nil {
		ls.secretMetaCache.evictSchedule(secretNodeID)
	} else if ls.cacheEnabled {
		gen := scheduleGenerationOf(sched)
		if cached, ok := ls.secretMetaCache.getSchedule(secretNodeID); !ok || cached.generation != gen {
			cp := *sched
			ls.secretMetaCache.setSchedule(secretNodeID, secretScheduleCacheEntry{
				generation: gen, schedule: &cp,
			})
		}
	}

	if version, hit := ls.cachedLatestVersionAt(secretNodeID, liveGen); hit {
		if version == nil {
			out.LatestVersionErr = fmt.Errorf("%s: %w", i18n.T("ErrorVersionNotFound", nil), storage.ErrSecretVersionNotFound)
			return out, nil
		}
		out.LatestVersion = cloneSecretVersion(version)
		return out, nil
	}
	out.LatestVersion, out.LatestVersionErr = ls.readLatestSecretVersionRow(ctx, secretNodeID, liveGen, nil)
	return out, nil
}

// cachedLatestVersionAt is getCachedLatestVersion with the live generation
// already in hand (read by the combined statement instead of a probe of its own).
func (ls *LocalStorage) cachedLatestVersionAt(secretNodeID uint, liveGen versionsGeneration) (*models.SecretVersion, bool) {
	if !ls.cacheEnabled {
		return nil, false
	}
	cached, ok := ls.secretMetaCache.getVersion(secretNodeID)
	if !ok || liveGen != cached.generation {
		return nil, false
	}
	return cached.latestVersion, true
}
