// local_audit.go — Audit log and anomaly alert operations for LocalStorage.
//
// Covers: LogAuditEvent, CreateSecretAccessLog, ListSecretAccessLogs,
//
//	GetAuditLogs,
//	CreateAnomalyAlert, ListAnomalyAlerts, AcknowledgeAnomalyAlert.
//
// All operations use direct GORM queries.
// For the remote (HTTP) equivalent see remote_audit.go.
package store

import (
	"context"
	"database/sql/driver"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (ls *LocalStorage) CreateSecretAccessLog(ctx context.Context, log *models.SecretAccessLog) error {
	return ls.db.WithContext(ctx).Create(log).Error
}

// maxSecretAccessLogRows caps how many rows a single ListSecretAccessLogs call can
// return (#101). Without a cap, a secret read continuously over a long window (a busy
// CI pipeline, or an attacker deliberately hammering reads to bloat the log) makes the
// anomaly detector — which calls this per secret, per pass, over a 30-day window —
// load an unbounded result set into memory, a self-inflicted latency/OOM vector.
// Ordered newest-first so a capped result keeps the most recent (most relevant) rows.
const maxSecretAccessLogRows = 50_000

func (ls *LocalStorage) ListSecretAccessLogs(ctx context.Context, secretID uint, since time.Time) ([]models.SecretAccessLog, error) {
	// G81 (SecretAccessLog.AccessTime): normalize internally — see GetAuditLogs.
	var logs []models.SecretAccessLog
	result := ls.db.WithContext(ctx).
		Where("secret_node_id = ? AND access_time >= ?", secretID, since.UTC()).
		Order("access_time DESC").
		Limit(maxSecretAccessLogRows).
		Find(&logs)
	return logs, result.Error
}

// CountSecretReadsBySecretIDs returns, for every secret in secretIDs with at least
// one qualifying row, the number of "read" access-log entries at or after since —
// aggregated in SQL (GROUP BY + COUNT), not one ListSecretAccessLogs call (plus a
// Go-side action=="read" filter) per secret. Used by the rotation planner's
// risk-scoring batch (#409) instead of one such call per candidate secret. A
// secret absent from the result had zero qualifying reads.
func (ls *LocalStorage) CountSecretReadsBySecretIDs(ctx context.Context, secretIDs []uint, since time.Time) (map[uint]int, error) {
	// G81 (SecretAccessLog.AccessTime): normalize internally — see GetAuditLogs.
	since = since.UTC()
	out := make(map[uint]int, len(secretIDs))
	if len(secretIDs) == 0 {
		return out, nil
	}
	type row struct {
		SecretNodeID uint
		Count        int
	}
	var rows []row
	q := ls.db.WithContext(ctx).Model(&models.SecretAccessLog{}).
		Select("secret_node_id, COUNT(*) AS count").
		Where("secret_node_id IN ? AND action = ?", secretIDs, "read")
	// A zero `since` means "all time" (the lifetime count, total_reads). Leaving the
	// always-true bound out lets the planner answer from (secret_node_id, action)
	// alone instead of range-scanning (secret_node_id, access_time) with a heap
	// lookup per row to check action.
	if !since.IsZero() {
		q = q.Where("access_time >= ?", since)
	}
	err := q.Group("secret_node_id").Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
	}
	for _, r := range rows {
		out[r.SecretNodeID] = r.Count
	}
	return out, nil
}

// PrincipalSecretFirstSeen returns, for every (principal, secret) pair with at least one
// access log row at or after `since`, the EARLIEST access time in that range —
// aggregated in SQL (GROUP BY + MIN), not loaded as full log rows, so this stays cheap
// regardless of per-secret read volume (#101).
//
// G81: this comment previously claimed the WHERE boundary was safe unnormalized because
// every caller here is date-scale (7d/30d), "never hour-scale" — that claim was false:
// RunDetection's hour-scale window (minDetectionLookback = time.Hour, anomaly.go) feeds
// this same query path via ListSecretAccessLogs, using a UTC `now` against an AccessTime
// written as bare (local) time.Now() — exactly the narrow-relative-to-now mismatch this
// comment said didn't happen. Fixed properly now: AccessTime is normalized to UTC at
// write time (models.SecretAccessLog.BeforeSave) and `since` is normalized here, so every
// caller's WHERE boundary compares like-for-like regardless of scale.
func (ls *LocalStorage) PrincipalSecretFirstSeen(ctx context.Context, since time.Time) (map[string]map[uint]time.Time, error) {
	since = since.UTC()
	type row struct {
		AccessedBy   string
		SecretNodeID uint
		FirstSeen    scanTime
	}
	var rows []row
	err := ls.db.WithContext(ctx).
		Model(&models.SecretAccessLog{}).
		Select("accessed_by, secret_node_id, MIN(access_time) AS first_seen").
		Where("access_time >= ? AND accessed_by != ''", since).
		Group("accessed_by, secret_node_id").
		Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make(map[string]map[uint]time.Time, len(rows))
	for _, r := range rows {
		if r.FirstSeen.t == nil {
			continue
		}
		if out[r.AccessedBy] == nil {
			out[r.AccessedBy] = make(map[uint]time.Time)
		}
		out[r.AccessedBy][r.SecretNodeID] = *r.FirstSeen.t
	}
	return out, nil
}

// ListSecretIDsAccessedSince returns the distinct secret IDs with at least one
// access-log row at or after since — every action and every accessor (including an
// empty accessed_by), deliberately unlike PrincipalSecretFirstSeen's accessed_by != ”
// filter: the anomaly detector uses this to decide which secrets to evaluate at all,
// and its off_hours/frequency_spike/cumulative_rate rules fire on rows regardless of
// accessor, so narrowing it here would silently drop detections. Served by
// idx_secret_access_logs_access_time.
func (ls *LocalStorage) ListSecretIDsAccessedSince(ctx context.Context, since time.Time) ([]uint, error) {
	// G81 (SecretAccessLog.AccessTime): normalize internally — see GetAuditLogs.
	//
	// The unary plus in `DISTINCT +secret_node_id` is deliberate (a no-op on both
	// dialects): with a bare `DISTINCT secret_node_id`, SQLite's stats-less planner
	// prefers a full scan of idx_secret_access_logs_secret_time (already ordered by
	// secret_node_id, so DISTINCT needs no sort) over a range scan of
	// idx_secret_access_logs_access_time — reading the whole append-only table every
	// pass. The expression hides that ordering, so the range scan wins.
	// TestAnomalyQueries_UseTheirIndexes pins the resulting plan.
	var ids []uint
	err := ls.db.WithContext(ctx).
		Raw("SELECT DISTINCT +secret_node_id AS secret_node_id FROM secret_access_logs WHERE access_time >= ?", since.UTC()).
		Scan(&ids).Error
	if err != nil {
		return nil, err
	}
	return ids, nil
}

// scanTime portably scans a SQL timestamp that some drivers return as time.Time
// (Postgres) and others as a string from an aggregate like MAX() (SQLite).
type scanTime struct{ t *time.Time }

// Value satisfies driver.Valuer so GORM treats scanTime as a scalar field
// (not a relation); the queries are read-only so it is never actually written.
func (s scanTime) Value() (driver.Value, error) {
	if s.t == nil {
		return nil, nil
	}
	return *s.t, nil
}

func (s *scanTime) Scan(value any) error {
	if value == nil {
		return nil
	}
	switch v := value.(type) {
	case time.Time:
		t := v
		s.t = &t
		return nil
	case []byte:
		return s.parse(string(v))
	case string:
		return s.parse(v)
	default:
		return fmt.Errorf("scanTime: unsupported type %T", value)
	}
}

func (s *scanTime) parse(str string) error {
	// time.Time.String() appends a monotonic-clock reading (" m=+0.204177834"
	// or " m=-...") when the value still carries one (e.g. derived from
	// time.Now() without a Round(0)/Truncate). modernc.org/sqlite (ADR-048)
	// returns MIN()/MAX() aggregates over a time.Time column via this String()
	// representation, monotonic suffix included; it isn't a parseable layout
	// element (Parse has no directive for it), so strip it before matching
	// against the layouts below.
	if idx := strings.Index(str, " m="); idx != -1 {
		str = str[:idx]
	}
	for _, layout := range []string{
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05-07:00",
		time.RFC3339Nano,
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
		// modernc.org/sqlite (ADR-048) returns an aggregate MAX()/MIN() over a
		// time.Time column as text in Go's own time.Time.String() format —
		// space before the offset, plus a trailing zone abbreviation — rather
		// than one of the layouts above (which is what mattn/go-sqlite3
		// produced). This is exactly that format (not a named time.* constant;
		// time.Time.String()'s own layout isn't exposed as one).
		"2006-01-02 15:04:05.999999999 -0700 MST",
	} {
		if t, err := time.Parse(layout, str); err == nil {
			s.t = &t
			return nil
		}
	}
	return fmt.Errorf("scanTime: cannot parse %q", str)
}

// MostAccessedSecrets ranks secrets by read count in the window, joining
// secret_nodes for the name/environment. Reads are the usage signal, so only
// access logs with action="read" are counted. When environmentID is non-nil
// the result is further confined to that single environment within the
// project — matching the {project, environment} scope the HTTP route
// authorizes against (ScopeFromQuery), so a caller authorized for only one
// environment cannot receive the whole project's aggregate usage data.
func (ls *LocalStorage) MostAccessedSecrets(ctx context.Context, projectID, environmentID *uint, since time.Time, limit int) ([]storage.SecretUsageStat, error) {
	// G81 (SecretAccessLog.AccessTime): normalize internally — see GetAuditLogs.
	since = since.UTC()
	if limit <= 0 {
		limit = 10
	}
	limit = clampPageSize(limit)
	q := ls.db.WithContext(ctx).
		Table("secret_access_logs AS l").
		Select("l.secret_node_id AS secret_id, s.name AS secret_name, s.environment_id AS environment_id, COUNT(*) AS read_count, MAX(l.access_time) AS last_read").
		Joins("JOIN secret_nodes s ON s.id = l.secret_node_id AND s.deleted_at IS NULL").
		Where(sqlWhereIsSecret, true).
		Where("l.action = ?", "read").
		Where("l.access_time >= ?", since).
		Group("l.secret_node_id, s.name, s.environment_id").
		Order("read_count DESC, last_read DESC").
		Limit(limit)
	if projectID != nil {
		q = q.Where("s.project_id = ?", *projectID)
	}
	if environmentID != nil {
		q = q.Where("s.environment_id = ?", *environmentID)
	}

	type row struct {
		SecretID      uint
		SecretName    string
		EnvironmentID uint
		ReadCount     int64
		LastRead      scanTime
	}
	var rows []row
	if err := q.Scan(&rows).Error; err != nil {
		return nil, err
	}

	stats := make([]storage.SecretUsageStat, 0, len(rows))
	for _, r := range rows {
		stats = append(stats, storage.SecretUsageStat{
			SecretID: r.SecretID, SecretName: r.SecretName, EnvironmentID: r.EnvironmentID,
			ReadCount: r.ReadCount, LastRead: r.LastRead.t,
		})
	}
	return stats, nil
}

// UnusedSecrets returns secrets whose most recent read is older than
// notReadSince (or that have never been read), ordered never-read first. Only
// real secrets (is_secret) are considered, not folder nodes. When
// environmentID is non-nil the result is further confined to that single
// environment within the project — matching the {project, environment} scope
// the HTTP route authorizes against (ScopeFromQuery), so a caller authorized
// for only one environment cannot receive the whole project's aggregate
// usage data.
func (ls *LocalStorage) UnusedSecrets(ctx context.Context, projectID, environmentID *uint, notReadSince time.Time) ([]storage.UnusedSecretStat, error) {
	// G81 (SecretAccessLog.AccessTime): normalize internally — see GetAuditLogs.
	notReadSince = notReadSince.UTC()
	q := ls.db.WithContext(ctx).
		Table("secret_nodes AS s").
		Select("s.id AS secret_id, s.name AS secret_name, s.environment_id AS environment_id, MAX(l.access_time) AS last_read").
		Joins("LEFT JOIN secret_access_logs l ON l.secret_node_id = s.id AND l.action = ?", "read").
		Where(sqlWhereIsSecret, true).
		Where("s.deleted_at IS NULL").
		Group("s.id, s.name, s.environment_id").
		Having("MAX(l.access_time) IS NULL OR MAX(l.access_time) < ?", notReadSince).
		Order("(MAX(l.access_time) IS NULL) DESC, last_read ASC").
		Limit(maxUnboundedListRows)
	if projectID != nil {
		q = q.Where("s.project_id = ?", *projectID)
	}
	if environmentID != nil {
		q = q.Where("s.environment_id = ?", *environmentID)
	}

	type row struct {
		SecretID      uint
		SecretName    string
		EnvironmentID uint
		LastRead      scanTime
	}
	var rows []row
	if err := q.Scan(&rows).Error; err != nil {
		return nil, err
	}

	stats := make([]storage.UnusedSecretStat, 0, len(rows))
	for _, r := range rows {
		stats = append(stats, storage.UnusedSecretStat{
			SecretID: r.SecretID, SecretName: r.SecretName, EnvironmentID: r.EnvironmentID,
			LastRead: r.LastRead.t,
		})
	}
	return stats, nil
}

// CountUnusedSecretsByProject returns, for every project in projectIDs, the count
// of secrets qualifying under the same "not read since notReadSince (or never
// read)" definition UnusedSecrets uses, via a single grouped query — the
// deployment-wide counterpart used by the hygiene rollup (#393) instead of calling
// UnusedSecrets once per project. Two aggregation levels are needed (UnusedSecrets'
// own per-secret MAX(access_time)/HAVING, then a COUNT(*) of the qualifying secrets
// per project), so the per-secret query runs as a FROM subquery. A project with no
// unused secrets is simply absent from the returned map.
func (ls *LocalStorage) CountUnusedSecretsByProject(ctx context.Context, projectIDs []uint, notReadSince time.Time) (map[uint]int, error) {
	// G81 (SecretAccessLog.AccessTime): normalize internally — see GetAuditLogs.
	notReadSince = notReadSince.UTC()
	counts := make(map[uint]int)
	if len(projectIDs) == 0 {
		return counts, nil
	}

	perSecret := ls.db.WithContext(ctx).
		Table("secret_nodes AS s").
		Select("s.project_id AS project_id").
		Joins("LEFT JOIN secret_access_logs l ON l.secret_node_id = s.id AND l.action = ?", "read").
		Where(sqlWhereIsSecret, true).
		Where("s.deleted_at IS NULL").
		Where("s.project_id IN ?", projectIDs).
		Group("s.id, s.project_id").
		Having("MAX(l.access_time) IS NULL OR MAX(l.access_time) < ?", notReadSince)

	type row struct {
		ProjectID uint
		N         int64
	}
	var rows []row
	err := ls.db.WithContext(ctx).
		Table("(?) AS unused", perSecret).
		Select("project_id, COUNT(*) AS n").
		Group("project_id").
		Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		counts[r.ProjectID] = int(r.N)
	}
	return counts, nil
}

// DeleteAuditLogsBefore hard-deletes the longest contiguous id prefix of
// audit_events whose rows ALL have event_time before cutoff (INV-STORE-22,
// #2633): every row with id < B, where B is the lowest id whose event_time is
// NOT before cutoff. It returns the number of rows deleted, plus a re-anchor
// candidate (storage.AuditChainAnchor) when the delete reached into the
// chained (post-ADR-029) hash-chain region rather than just the pre-ADR-029
// unchained legacy prefix: the new earliest surviving row's own
// id/prev_hash/entry_hash. That row's prev_hash still points at its
// now-deleted predecessor — without authenticating and persisting this as a
// retention anchor, VerifyAuditChain can never again walk past this row (see
// the ADR-029 retention-purge finding this closes). The caller
// (core.PurgeAuditLogs) is responsible for HMAC-signing and persisting it,
// inside the same transaction as this delete, via SetSystemMetadata.
//
// Why a prefix and not simply `event_time < cutoff`: the chain is ordered by
// id, the cutoff by event_time, and the two disagree whenever a higher-id row
// carries an older event_time (LogAuditEvent stamps event_time before taking
// the append lock, so concurrent writers can commit out of timestamp order;
// HA replicas with skewed clocks do the same at a larger scale). Deleting by
// event_time alone then removes a row from the MIDDLE of the chain — its
// successor's prev_hash dangles and VerifyAuditChain reports tampering, which
// a single re-anchor on the earliest survivor cannot repair. The delete keeps
// the `event_time < cutoff` predicate as well as `id < B`, so the deleted set
// is always a subset of what the pre-#2633 purge deleted: a row out of order
// is retained (until a later purge whose cutoff passes it), never removed
// early.
//
// The whole sequence (find B, delete, read the new head) runs under the
// KEYAUDIT advisory lock (auditAdvisoryLockKey) LogAuditEvent appends under,
// taken transaction-scoped so it is held until the enclosing transaction
// (core.PurgeAuditLogs') commits — after the re-anchor is persisted. No
// replica can append between the purge choosing its prefix and recording the
// anchor. As in the append path, that lock is Postgres-only; on SQLite the
// enclosing transaction's writer lock already excludes every appender (and
// auditChainMu is deliberately NOT taken here: LogAuditEvent acquires it
// BEFORE opening its transaction, while this runs inside a transaction that,
// under the production DSN's _txlock=immediate, already holds SQLite's writer
// lock — taking the mutex here would invert that order and stall a concurrent
// append until its write deadline drops it).
//
// candidate is nil when nothing was deleted, the table is now empty, or the
// new earliest surviving row already legitimately starts at genesis (the
// purge only removed the unchained legacy prefix) — nothing to re-anchor.
// Otherwise its PurgedEvents is the number of chained rows this delete
// removed (#3257).
func (ls *LocalStorage) DeleteAuditLogsBefore(ctx context.Context, cutoff time.Time) (int64, *storage.AuditChainAnchor, error) {
	var (
		deleted int64
		anchor  *storage.AuditChainAnchor
	)
	// A nested Transaction is a SAVEPOINT inside the caller's transaction; a
	// transaction-scoped advisory lock taken in it is still held until the
	// OUTER transaction ends. Called outside any transaction, this is the
	// transaction the lock is scoped to.
	err := ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if tx.Dialector.Name() == "postgres" {
			if err := tx.Exec("SELECT pg_advisory_xact_lock(?)", int64(auditAdvisoryLockKey)).Error; err != nil {
				return err
			}
			// The purge can empty the table, which moves the head; make the
			// flusher re-read it rather than spend a flight finding out
			// (AUDIT-1FLIGHT-1).
			ls.invalidateAuditChainHead()
		}

		// B: the first row (by id) the pre-#2633 predicate would have kept —
		// the exact complement of `event_time < cutoff` under SQL's three-valued
		// logic, NULL included.
		var boundary []uint
		if err := tx.Model(&models.AuditEvent{}).
			Where("event_time >= ? OR event_time IS NULL", cutoff).
			Order("id ASC").
			Limit(1).
			Pluck("id", &boundary).Error; err != nil {
			return err
		}

		prefix := func(q *gorm.DB) *gorm.DB {
			q = q.Where("event_time < ?", cutoff)
			if len(boundary) > 0 {
				q = q.Where("id < ?", boundary[0])
			}
			return q
		}
		// #3257: count the CHAINED rows about to go (legacy rows carry an empty
		// entry_hash and were never part of a certified count), under the same
		// lock and predicate as the delete, so the caller can sign the
		// cumulative purged count into the anchor.
		var chainedDeleted int64
		if err := prefix(tx.Model(&models.AuditEvent{})).
			Where("entry_hash IS NOT NULL AND entry_hash <> ''").
			Count(&chainedDeleted).Error; err != nil {
			return err
		}
		result := prefix(tx).Delete(&models.AuditEvent{})
		deleted = result.RowsAffected
		if result.Error != nil || result.RowsAffected == 0 {
			return result.Error
		}

		var head struct {
			ID        uint
			PrevHash  string
			EntryHash string
		}
		if err := tx.Model(&models.AuditEvent{}).
			Select("id, prev_hash, entry_hash").
			Order("id ASC").
			Limit(1).
			Scan(&head).Error; err != nil {
			return err
		}
		if head.ID == 0 || head.PrevHash == "" || head.PrevHash == auditGenesisHash {
			// Table now empty, or the surviving prefix already legitimately starts at
			// genesis (the purge only removed pre-ADR-029 legacy/unchained rows, or
			// the next append will restart the chain from genesis) — no re-anchor
			// needed; VerifyAuditChain's normal genesis walk already handles this.
			return nil
		}
		anchor = &storage.AuditChainAnchor{
			RowID:        head.ID,
			PrevHash:     head.PrevHash,
			EntryHash:    head.EntryHash,
			PurgedEvents: chainedDeleted,
		}
		return nil
	})
	if err != nil {
		// The (sub)transaction rolled the delete back: nothing was removed.
		return 0, nil, err
	}
	return deleted, anchor, nil
}

// AuditRetentionStats returns the total audit event count plus the oldest and
// newest event_time in a single aggregate query. Keyorix applies no retention
// cap, so MIN(event_time) is the true start of the trail — the basis for the
// retention-coverage report. Oldest/Newest stay nil on an empty table.
func (ls *LocalStorage) AuditRetentionStats(ctx context.Context) (*storage.AuditRetentionStats, error) {
	type row struct {
		Total  int64
		Oldest scanTime
		Newest scanTime
	}
	var r row
	if err := ls.db.WithContext(ctx).
		Model(&models.AuditEvent{}).
		Select("COUNT(*) AS total, MIN(event_time) AS oldest, MAX(event_time) AS newest").
		Scan(&r).Error; err != nil {
		return nil, err
	}
	return &storage.AuditRetentionStats{
		TotalEvents: r.Total,
		Oldest:      r.Oldest.t,
		Newest:      r.Newest.t,
	}, nil
}

// GetAuditLogs retrieves audit events with optional filtering and pagination.
func (ls *LocalStorage) GetAuditLogs(ctx context.Context, filter *storage.AuditFilter) ([]*models.AuditEvent, int64, error) { // NOSONAR -- cognitive complexity 38, suppress go:S3776
	query := ls.db.WithContext(ctx).Model(&models.AuditEvent{})
	page, pageSize := 1, 20

	if filter != nil {
		if filter.ProjectID != nil {
			query = query.Where("project_id = ?", *filter.ProjectID)
		}
		if filter.UserID != nil {
			query = query.Where("user_id = ?", *filter.UserID)
		}
		if filter.SecretID != nil {
			query = query.Where("secret_node_id = ?", *filter.SecretID)
		}
		if filter.Action != nil {
			query = query.Where("event_type = ?", *filter.Action)
		}
		if len(filter.Actions) > 0 {
			query = query.Where("event_type IN ?", filter.Actions)
		}
		if filter.StartTime != nil {
			// G81 (third recurrence, read side): normalize here rather than trusting
			// every caller to pass UTC, mirroring ListExpiredActiveLeases. event_time
			// is now always stored in UTC (models.AuditEvent.BeforeSave); a bound in
			// any other Location denotes the same instant but, on SQLite, compares as
			// a different string, silently mismatching rows that are actually in range.
			query = query.Where("event_time >= ?", filter.StartTime.UTC())
		}
		if filter.EndTime != nil {
			query = query.Where("event_time <= ?", filter.EndTime.UTC())
		}
		if filter.Success != nil {
			query = query.Where("success = ?", *filter.Success)
		}
		if filter.ActorType != nil {
			// The displayed kind, not the raw column (#2951): one rule shared with
			// the HTTP/gRPC views, storage.AuditActorKind.
			cond, args := storage.AuditActorKindWhere(*filter.ActorType)
			query = query.Where(cond, args...)
		}
		if filter.AfterID != nil {
			query = query.Where("id > ?", *filter.AfterID)
		}
		if filter.IPAddress != nil {
			query = query.Where("ip_address = ?", *filter.IPAddress)
		}
		if filter.ActorUsername != nil {
			// Resolve username → user_id via a subquery so we stay on the
			// audit_events table (no JOIN needed for the count query too).
			// escapeLIKE sanitises % and _ in the caller-supplied username so
			// a value like "admin%" doesn't turn into a wildcard prefix scan
			// covering all usernames (#r124 LIKE injection).
			// LOWER on both sides: LIKE is case-insensitive (ASCII) on SQLite but
			// case-sensitive on Postgres, so without it the same search returned
			// different rows per backend.
			cond := `user_id IN (SELECT id FROM users WHERE LOWER(username) LIKE LOWER(?) ESCAPE '\' AND deleted_at IS NULL)`
			args := []any{"%" + escapeLIKE(*filter.ActorUsername) + "%"}
			// Rows of kind "system" are displayed with actor "system" (#2951), so a
			// term that is part of "system" (ASCII case-insensitive, e.g. "sys") also
			// finds exactly those rows: the same rule as actor_type=system
			// (storage.AuditSystemActorWhere). A failed login has no user but is
			// kind "user", so it is not pulled in here.
			if term := strings.ToLower(*filter.ActorUsername); term != "" && strings.Contains("system", term) {
				sysCond, sysArgs := storage.AuditSystemActorWhere()
				cond = "(" + cond + " OR " + sysCond + ")"
				args = append(args, sysArgs...)
			}
			query = query.Where(cond, args...)
		}
		if filter.ResourceType != nil {
			// event_type is "resource_type.action" — match rows whose event_type
			// starts with "<resource_type>." so "secret" catches "secret.read",
			// "secret.created", etc. escapeLIKE prevents a caller-supplied
			// resource_type containing % or _ from matching unintended event types.
			query = query.Where(`event_type LIKE ? ESCAPE '\'`, escapeLIKE(*filter.ResourceType)+".%")
		}
		if filter.Page > 1 {
			page = filter.Page
		}
		if filter.PageSize > 0 {
			pageSize = filter.PageSize
		}
	}
	pageSize = clampPageSize(pageSize)
	page = clampPage(page)

	var total int64
	query.Count(&total)

	// Cursor mode (SIEM export): ascending by id, no page offset — the caller
	// advances by passing the last seen id as AfterID on the next request.
	if filter != nil && filter.Ascending {
		var events []*models.AuditEvent
		if err := query.Order("id ASC").Limit(pageSize).Find(&events).Error; err != nil {
			return nil, 0, fmt.Errorf("failed to get audit logs: %w", err)
		}
		return events, total, nil
	}

	var events []*models.AuditEvent
	offset := (page - 1) * pageSize
	if err := query.Order("event_time DESC").Limit(pageSize).Offset(offset).Find(&events).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to get audit logs: %w", err)
	}
	return events, total, nil
}

// GetSecretReadCounts aggregates "secret.read" audit events for the given secret
// in [since, until), returning the top-N actors sorted by read count descending.
// Actor identity is taken from user_id; a LEFT JOIN on users resolves usernames.
// Machine-identity reads (actor_type="machine_identity") have no user row — their
// username column is empty in the result, consistent with the description column.
func (ls *LocalStorage) GetSecretReadCounts(ctx context.Context, secretID uint, since, until time.Time, limit int) ([]storage.SecretReadEntry, error) {
	// G81 (third recurrence, read side): normalize internally — see GetAuditLogs.
	since, until = since.UTC(), until.UTC()
	type row struct {
		ActorID       string
		ActorUsername string
		ReadCount     int64
		LastReadAt    scanTime
	}
	var rows []row
	err := ls.db.WithContext(ctx).
		Table("audit_events ae").
		Select("CAST(ae.user_id AS TEXT) AS actor_id, COALESCE(u.username, '') AS actor_username, COUNT(*) AS read_count, MAX(ae.event_time) AS last_read_at").
		Joins("LEFT JOIN users u ON u.id = ae.user_id AND u.deleted_at IS NULL").
		// success: a refused read (secret.read, success=false, #3273) is not a read.
		Where("ae.secret_node_id = ? AND ae.event_type = ? AND (ae.success IS NULL OR ae.success = ?) AND ae.event_time >= ? AND ae.event_time < ?", secretID, "secret.read", true, since, until).
		// Postgres enforces the SQL standard's GROUP BY functional-dependency
		// rule strictly: every selected column must either be aggregated or
		// appear in GROUP BY, and it does NOT infer that u.username depends on
		// ae.user_id through the join condition (that inference only applies
		// when GROUP BY names the JOINED table's own primary key, u.id -- not
		// a column of the other table that merely equals it). SQLite has no
		// such check at all (it silently picks an arbitrary row's value for
		// any ungrouped column), so this passed there and 500ed only on
		// Postgres ("column \"u.username\" must appear in the GROUP BY clause
		// or be used in an aggregate function") -- found by SESSION-I's
		// fresh-install API smoke driver running the identical flow against
		// both backends. u.id is a primary key and the join condition
		// (u.id = ae.user_id) means at most one users row matches per
		// ae.user_id, so grouping by both columns changes nothing about the
		// result -- it only satisfies the stricter validator.
		Group("ae.user_id, u.username").
		Order("read_count DESC").
		Limit(clampPageSize(limit)).
		Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("GetSecretReadCounts: %w", err)
	}

	out := make([]storage.SecretReadEntry, 0, len(rows))
	for _, r := range rows {
		var lastReadAt time.Time
		if r.LastReadAt.t != nil {
			lastReadAt = *r.LastReadAt.t
		}
		out = append(out, storage.SecretReadEntry{
			ActorID:       r.ActorID,
			ActorUsername: r.ActorUsername,
			ReadCount:     r.ReadCount,
			LastReadAt:    lastReadAt,
		})
	}
	return out, nil
}

// CountImpersonatedActions counts impersonated audit events for actingAs by
// impersonator since `since`, excluding the impersonation.start/.end markers.
func (ls *LocalStorage) CountImpersonatedActions(ctx context.Context, actingAs, impersonator uint, since time.Time) (int64, error) {
	// G81 (third recurrence, read side): normalize internally — see GetAuditLogs.
	var n int64
	err := ls.db.WithContext(ctx).Model(&models.AuditEvent{}).
		Where("impersonation = ? AND acting_as = ? AND impersonated_by = ? AND event_time >= ?", true, actingAs, impersonator, since.UTC()).
		Where("event_type NOT IN ?", []string{"impersonation.start", "impersonation.end"}).
		Count(&n).Error
	return n, err
}

// --- Anomaly alerts ---

// anomalyDedupWindow bounds how long an equivalent alert suppresses duplicates.
// It matches RunDetection's 1-hour analysis window: re-running detection over
// the same window must not re-insert identical alerts, but a genuine later
// recurrence (a new access in a new window) still produces a fresh alert.
const anomalyDedupWindow = time.Hour

// CreateAnomalyAlert inserts an alert, idempotently. If an equivalent alert
// (same secret, type, actor, and IP) was already recorded within the dedup
// window, the insert is skipped and nil is returned — so re-running detection
// over the same window does not pile up duplicates.
func (ls *LocalStorage) CreateAnomalyAlert(ctx context.Context, alert *models.AnomalyAlert) error {
	// G81 (AnomalyAlert.DetectedAt): cutoff derives from alert.DetectedAt as given
	// by the caller, BEFORE the BeforeSave hook (fired later, inside tx.Create
	// below) normalizes it — so .UTC() it explicitly here too, defensively,
	// even though every real caller already passes a UTC value today.
	cutoff := alert.DetectedAt.UTC()
	if cutoff.IsZero() {
		cutoff = time.Now().UTC()
	}
	cutoff = cutoff.Add(-anomalyDedupWindow)

	// #G21: the dedup check and the insert run inside ONE transaction — two
	// concurrent detection runs processing the same access event could
	// otherwise both observe existing==0 before either commits, producing
	// duplicate alerts. SQLite's single-writer model holds this transaction's
	// exclusive write lock for its whole duration, so a concurrent insert of
	// the same (secret, type, actor, ip) tuple cannot land in between the
	// count and this insert.
	return ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var existing int64
		if err := tx.Model(&models.AnomalyAlert{}).
			Where("secret_node_id = ? AND alert_type = ? AND accessed_by = ? AND ip_address = ? AND detected_at > ?",
				alert.SecretNodeID, alert.AlertType, alert.AccessedBy, alert.IPAddress, cutoff).
			Count(&existing).Error; err != nil {
			return err
		}
		if existing > 0 {
			return nil
		}
		return tx.Create(alert).Error
	})
}

// ListAnomalyAlerts returns alerts newest-first. acknowledged filters by state:
// nil returns all, &true only acknowledged, &false only unacknowledged.
func (ls *LocalStorage) ListAnomalyAlerts(ctx context.Context, acknowledged *bool) ([]models.AnomalyAlert, error) {
	var alerts []models.AnomalyAlert
	query := ls.db.WithContext(ctx)
	if acknowledged != nil {
		query = query.Where("acknowledged = ?", *acknowledged)
	}
	result := query.Order("detected_at DESC").Find(&alerts)
	return alerts, result.Error
}

func (ls *LocalStorage) AcknowledgeAnomalyAlert(ctx context.Context, id, actorID uint, at time.Time) error {
	res := ls.db.WithContext(ctx).Model(&models.AnomalyAlert{}).Where("id = ?", id).Updates(map[string]any{
		"acknowledged":    true,
		"acknowledged_by": actorID,
		"acknowledged_at": at,
	})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("anomaly alert not found")
	}
	return nil
}

func (ls *LocalStorage) ListUnalertedAnomalyAlerts(ctx context.Context) ([]models.AnomalyAlert, error) {
	var rows []models.AnomalyAlert
	if err := ls.db.WithContext(ctx).Where("alerted = ?", false).Order("detected_at ASC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("failed to list unalerted anomaly alerts: %w", err)
	}
	return rows, nil
}

func (ls *LocalStorage) MarkAnomalyAlertAlerted(ctx context.Context, id uint) error {
	return ls.db.WithContext(ctx).Model(&models.AnomalyAlert{}).Where("id = ?", id).Update("alerted", true).Error
}

// GetDistinctActiveUserIDs returns the IDs of users who have logged in since the given time.
func (ls *LocalStorage) GetDistinctActiveUserIDs(ctx context.Context, since time.Time) ([]uint, error) {
	// G81 (third recurrence, read side): normalize internally — see GetAuditLogs.
	var ids []uint
	err := ls.db.WithContext(ctx).
		Model(&models.AuditEvent{}).
		Where("event_type = ? AND event_time >= ?", "auth.login", since.UTC()).
		Distinct("user_id").
		Pluck("user_id", &ids).Error
	return ids, err
}
