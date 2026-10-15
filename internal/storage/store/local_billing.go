// local_billing.go — Per-project billing report query for LocalStorage.
//
// Covers: GetBillingReport
//
// All operations use direct GORM queries.
// For the remote (HTTP) equivalent see remote_billing.go.
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// maxBillingReportProjectIDs bounds the caller-supplied project_id filter list —
// without a cap, a large externally-supplied list is interpolated directly into
// a SQL "project_id IN (...)" clause on every aggregation query in this file (#G44).
const maxBillingReportProjectIDs = 1000

// selectProjectCount is the shared "GROUP BY project_id" count projection
// used by every per-project aggregation query below.
const selectProjectCount = "project_id, COUNT(*) AS count"

// billingCounts accumulates the raw per-project aggregates that feed
// storage.BillingProjectStat before the zero-activity filter is applied.
type billingCounts struct {
	SecretCount     int64
	SecretReads     int64
	SecretWrites    int64
	SecretRotations int64
	UniqueUsers     int
	MachineReads    int64
}

// GetBillingReport returns per-project usage stats for the half-open interval
// [from, to). When projectIDs is nil or empty, stats are returned for all
// non-deleted projects that have at least one active secret or any audit
// activity in the window. Projects with no secrets and no activity are omitted
// to keep the report concise.
func (ls *LocalStorage) GetBillingReport(ctx context.Context, from, to time.Time, projectIDs []uint) (*storage.BillingReport, error) {
	if len(projectIDs) > maxBillingReportProjectIDs {
		return nil, fmt.Errorf("project_id filter accepts at most %d ids, got %d", maxBillingReportProjectIDs, len(projectIDs))
	}
	if len(projectIDs) == 0 {
		var err error
		if projectIDs, err = ls.allProjectIDs(ctx); err != nil {
			return nil, err
		}
	}
	if len(projectIDs) == 0 {
		return &storage.BillingReport{
			From:        from,
			To:          to,
			GeneratedAt: time.Now().UTC(),
			Projects:    []storage.BillingProjectStat{},
		}, nil
	}

	nameMap, err := ls.projectNames(ctx, projectIDs)
	if err != nil {
		return nil, err
	}

	statsMap, err := ls.billingCountsByProject(ctx, from, to, projectIDs)
	if err != nil {
		return nil, err
	}

	stats, totals := buildBillingStats(projectIDs, nameMap, statsMap)

	return &storage.BillingReport{
		From:        from,
		To:          to,
		GeneratedAt: time.Now().UTC(),
		Projects:    stats,
		Totals:      totals,
	}, nil
}

func (ls *LocalStorage) allProjectIDs(ctx context.Context) ([]uint, error) {
	type idRow struct{ ID uint }
	var rows []idRow
	if err := ls.db.WithContext(ctx).
		Table("projects").
		Select("id").
		Where("deleted_at IS NULL").
		Scan(&rows).Error; err != nil {
		return nil, err
	}
	ids := make([]uint, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.ID)
	}
	return ids, nil
}

func (ls *LocalStorage) projectNames(ctx context.Context, projectIDs []uint) (map[uint]string, error) {
	type projectRow struct {
		ID   uint
		Name string
	}
	var rows []projectRow
	if err := ls.db.WithContext(ctx).
		Table("projects").
		Select("id, name").
		Where("id IN ?", projectIDs).
		Scan(&rows).Error; err != nil {
		return nil, err
	}
	nameMap := make(map[uint]string, len(rows))
	for _, p := range rows {
		nameMap[p.ID] = p.Name
	}
	return nameMap, nil
}

// countByProject runs a "COUNT(*) GROUP BY project_id" aggregation over table
// filtered by where/args, returning a project_id -> count map.
func (ls *LocalStorage) countByProject(ctx context.Context, table, where string, args ...any) (map[uint]int64, error) {
	type row struct {
		ProjectID uint
		Count     int64
	}
	var rows []row
	if err := ls.db.WithContext(ctx).
		Table(table).
		Select(selectProjectCount).
		Where(where, args...).
		Group("project_id").
		Scan(&rows).Error; err != nil {
		return nil, err
	}
	m := make(map[uint]int64, len(rows))
	for _, r := range rows {
		m[r.ProjectID] = r.Count
	}
	return m, nil
}

func (ls *LocalStorage) distinctUsersByProject(ctx context.Context, projectIDs []uint, from, to time.Time) (map[uint]int, error) {
	type row struct {
		ProjectID uint
		Count     int
	}
	var rows []row
	if err := ls.db.WithContext(ctx).
		Table("audit_events").
		Select("project_id, COUNT(DISTINCT user_id) AS count").
		Where("project_id IN ? AND actor_type = ? AND event_time >= ? AND event_time < ?",
			projectIDs, "user", from, to).
		Group("project_id").
		Scan(&rows).Error; err != nil {
		return nil, err
	}
	m := make(map[uint]int, len(rows))
	for _, r := range rows {
		m[r.ProjectID] = r.Count
	}
	return m, nil
}

// billingCountsByProject runs each of the SecretCount / SecretReads /
// SecretWrites / SecretRotations / UniqueUsers / MachineReads aggregations
// and merges them into one map keyed by project ID.
func (ls *LocalStorage) billingCountsByProject(ctx context.Context, from, to time.Time, projectIDs []uint) (map[uint]*billingCounts, error) {
	// G81 (third recurrence, read side): normalize internally rather than trusting
	// the caller — see GetAuditLogs. GenerateBillingReport already normalizes
	// today, but every event_time comparison below would otherwise silently
	// depend on that staying true forever.
	from, to = from.UTC(), to.UTC()

	secretCounts, err := ls.countByProject(ctx, "secret_nodes",
		"project_id IN ? AND is_secret = ? AND deleted_at IS NULL", projectIDs, true)
	if err != nil {
		return nil, err
	}
	reads, err := ls.countByProject(ctx, "audit_events",
		"project_id IN ? AND event_type = ? AND success = ? AND event_time >= ? AND event_time < ?",
		projectIDs, "secret.read", true, from, to)
	if err != nil {
		return nil, err
	}
	writes, err := ls.countByProject(ctx, "audit_events",
		"project_id IN ? AND event_type IN ? AND success = ? AND event_time >= ? AND event_time < ?",
		projectIDs, []string{"secret.create", "secret.update", "secret.rotate"}, true, from, to)
	if err != nil {
		return nil, err
	}
	rotations, err := ls.countByProject(ctx, "audit_events",
		"project_id IN ? AND event_type = ? AND success = ? AND event_time >= ? AND event_time < ?",
		projectIDs, "secret.rotate", true, from, to)
	if err != nil {
		return nil, err
	}
	users, err := ls.distinctUsersByProject(ctx, projectIDs, from, to)
	if err != nil {
		return nil, err
	}
	// "machine_identity" (models.AuditEvent.ActorType / core.ActorTypeMachine), not
	// "machine" — this previously used the wrong literal, so MachineReads always
	// reported 0 regardless of real machine-identity read activity; caught by
	// GetBillingReport's first real (non-zero-coverage) test.
	machineReads, err := ls.countByProject(ctx, "audit_events",
		"project_id IN ? AND event_type = ? AND success = ? AND actor_type = ? AND event_time >= ? AND event_time < ?",
		projectIDs, "secret.read", true, "machine_identity", from, to)
	if err != nil {
		return nil, err
	}

	statsMap := make(map[uint]*billingCounts, len(projectIDs))
	for _, id := range projectIDs {
		statsMap[id] = &billingCounts{
			SecretCount:     secretCounts[id],
			SecretReads:     reads[id],
			SecretWrites:    writes[id],
			SecretRotations: rotations[id],
			UniqueUsers:     users[id],
			MachineReads:    machineReads[id],
		}
	}
	return statsMap, nil
}

// buildBillingStats converts the raw per-project counts into the report's
// stat list and totals, omitting projects with no secrets and no activity.
func buildBillingStats(projectIDs []uint, nameMap map[uint]string, statsMap map[uint]*billingCounts) ([]storage.BillingProjectStat, storage.BillingTotals) {
	var stats []storage.BillingProjectStat
	var totals storage.BillingTotals

	for _, id := range projectIDs {
		c := statsMap[id]
		if c.SecretCount == 0 && c.SecretReads == 0 && c.SecretWrites == 0 {
			continue
		}
		stat := storage.BillingProjectStat{
			ProjectID:       id,
			ProjectName:     nameMap[id],
			SecretCount:     c.SecretCount,
			SecretReads:     c.SecretReads,
			SecretWrites:    c.SecretWrites,
			SecretRotations: c.SecretRotations,
			UniqueUsers:     c.UniqueUsers,
			MachineReads:    c.MachineReads,
		}
		stats = append(stats, stat)

		totals.SecretCount += c.SecretCount
		totals.SecretReads += c.SecretReads
		totals.SecretWrites += c.SecretWrites
		totals.SecretRotations += c.SecretRotations
		totals.UniqueUsers += c.UniqueUsers
		totals.MachineReads += c.MachineReads
	}
	totals.Projects = len(stats)

	if stats == nil {
		stats = []storage.BillingProjectStat{}
	}
	return stats, totals
}
