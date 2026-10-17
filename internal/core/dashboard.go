package core

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ExpiringSecret represents a secret that is expiring soon or has already expired.
type ExpiringSecret struct {
	ID          uint      `json:"id"`
	Name        string    `json:"name"`
	Environment string    `json:"environment"`
	ExpiresAt   time.Time `json:"expiresAt"`
	DaysLeft    int       `json:"daysLeft"` // negative = already expired N days ago
	Expired     bool      `json:"expired"`  // true when expiration is in the past
}

// StatTrend contains trend data for a dashboard stat.
type StatTrend struct {
	Value      float64 `json:"value"`      // % change vs previous snapshot
	IsPositive bool    `json:"isPositive"` // true = grew, false = shrank
}

// DashboardStats contains summary statistics for the dashboard.
//
// #394: every deployment-wide sub-check gated behind hasAuditRead below (and the
// expiring-secrets rollup) is queried best-effort so one failing signal doesn't
// abort the whole dashboard — but a query failure must never read the same as
// "checked, genuinely zero" (e.g. FailedAuthAttempts24h=0 on an audit-log query
// error looks identical to a clean 24h window and could mask an ongoing
// incident or audit-log outage). Degraded + DegradedReasons make a partial
// snapshot detectable instead of indistinguishable from a fully-clean one,
// mirroring the CompliancePosture.Degraded convention (compliance_posture.go).
type DashboardStats struct {
	TotalSecrets        int64 `json:"totalSecrets"`
	SharedSecrets       int   `json:"sharedSecrets"`
	SecretsSharedWithMe int   `json:"secretsSharedWithMe"`
	ActiveUsers         int64 `json:"activeUsers"`
	AuditEvents30d      int64 `json:"auditEvents30d"`
	AuditLogins30d      int64 `json:"auditLogins30d"`
	AuditSecretReads30d int64 `json:"auditSecretReads30d"`
	// FailedAuthAttempts24h counts failed LOGINS (auth.login_failed) in the last 24h;
	// the name is kept for API compatibility. Refused secret reads are counted apart.
	FailedAuthAttempts24h      int64            `json:"failedAuthAttempts24h"`
	RefusedSecretReads24h      int64            `json:"refusedSecretReads24h"`
	InactiveUsers              int64            `json:"inactiveUsers"`
	PrevTotalSecrets           *int64           `json:"prevTotalSecrets,omitempty"`
	TotalSecretsTrend          *StatTrend       `json:"totalSecretsTrend,omitempty"`
	SharedSecretsTrend         *StatTrend       `json:"sharedSecretsTrend,omitempty"`
	SharedWithMeTrend          *StatTrend       `json:"sharedWithMeTrend,omitempty"`
	PrevActiveUsers            *int64           `json:"prevActiveUsers,omitempty"`
	ActiveUsersTrend           *StatTrend       `json:"activeUsersTrend,omitempty"`
	PrevAuditEvents30d         *int64           `json:"prevAuditEvents30d,omitempty"`
	AuditEvents30dTrend        *StatTrend       `json:"auditEvents30dTrend,omitempty"`
	PrevAuditLogins30d         *int64           `json:"prevAuditLogins30d,omitempty"`
	AuditLogins30dTrend        *StatTrend       `json:"auditLogins30dTrend,omitempty"`
	PrevAuditSecretReads30d    *int64           `json:"prevAuditSecretReads30d,omitempty"`
	AuditSecretReads30dTrend   *StatTrend       `json:"auditSecretReads30dTrend,omitempty"`
	PrevFailedAuthAttempts24h  *int64           `json:"prevFailedAuthAttempts24h,omitempty"`
	FailedAuthAttempts24hTrend *StatTrend       `json:"failedAuthAttempts24hTrend,omitempty"`
	PrevInactiveUsers          *int64           `json:"prevInactiveUsers,omitempty"`
	InactiveUsersTrend         *StatTrend       `json:"inactiveUsersTrend,omitempty"`
	ExpiringSecrets            []ExpiringSecret `json:"expiringSecrets,omitempty"`
	RecentActivity             []ActivityItem   `json:"recentActivity"`
	// Degraded is true when one or more sub-checks above could not be queried —
	// the zero/empty values they carry are UNKNOWN, not verified-clean. A
	// consumer must treat a degraded snapshot as incomplete, not as a clean
	// read (e.g. FailedAuthAttempts24h=0 does NOT mean "no failed auth" when
	// Degraded is true).
	Degraded bool `json:"degraded"`
	// DegradedReasons names each failed sub-check with its underlying error.
	DegradedReasons []string `json:"degradedReasons,omitempty"`
}

// degrade records that a dashboard sub-check could not be queried: it flips
// Degraded and appends a human-readable reason, so a consumer can tell "queried,
// genuinely zero" apart from "query failed, treat as unknown" — mirroring
// CompliancePosture.degrade (compliance_posture.go).
func (s *DashboardStats) degrade(area string, err error) {
	s.Degraded = true
	s.DegradedReasons = append(s.DegradedReasons, fmt.Sprintf("%s: %v", area, err))
}

// ActivityItem represents a single entry in the activity feed.
type ActivityItem struct {
	ID         uint      `json:"id"`
	Type       string    `json:"type"`
	SecretName string    `json:"secretName"`
	Timestamp  time.Time `json:"timestamp"`
	Actor      string    `json:"actor"`
	// EventType is the raw audit event type (e.g. "secret.dependency_invalidated"),
	// always present. Type is the dashboard's short category for the events it
	// styles ("accessed", "created", ...) and the raw type for the rest. Label is
	// the readable phrase to show after the actor (ActivityLabel); clients show it
	// instead of a raw type and keep EventType for a tooltip or JSON.
	EventType string `json:"eventType"`
	Label     string `json:"label"`
}

// ActivityFeed is the paginated response for the activity endpoint.
type ActivityFeed struct {
	Items    []ActivityItem `json:"items"`
	Total    int64          `json:"total"`
	Page     int            `json:"page"`
	PageSize int            `json:"pageSize"`
}

// GetDashboardStats returns summary counts and recent activity for the authenticated
// principal. userID/username are used for the human-oriented sub-checks below (owned
// secrets, outgoing/incoming shares, per-user trend snapshot) and are 0/"" for a
// machine-identity caller, exactly as before — those sub-checks remain human-only,
// unchanged by this fix.
//
// principalID is the caller's actual RBAC identity: the machine identity ID for a
// machine-token request, otherwise the same as userID (see UserContext.PrincipalID).
// It exists ONLY to resolve the audit.read gate below correctly for a machine caller.
//
// G33: this used to call the user-only Authorize(ctx, userID, "audit.read", Scope{})
// for the deployment-wide-aggregates gate. A machine identity always has userID==0
// (see UserContext.PrincipalID's doc), so that call resolved zero roles regardless
// of any audit.read role the machine actually holds via machine_identity_roles —
// under-privileging a machine identity relative to an equivalent human user, the
// same "helper written for humans, never updated for machines" shape as connect.go's
// actorRoleIDs. AuthorizePrincipal (already the actor-aware entrypoint used by the
// HTTP router's own RequirePermission gate on this endpoint) fixes it.
func (c *KeyorixCore) GetDashboardStats(ctx context.Context, userID uint, username string, principalID uint) (*DashboardStats, error) {
	stats := &DashboardStats{}

	// TOTAL SECRETS is the number of secrets this caller CAN READ — the count of
	// what GET /api/v1/secrets returns them, computed by the same function
	// (CountReadableSecrets -> ListReadableSecrets, secret_readable_listing.go), so
	// the tile and the list cannot disagree.
	//
	// #2780: this used to count secrets the caller had AUTHORED
	// (SecretFilter{CreatedBy: &username}). A project member who had created nothing
	// — the ordinary case for someone handed read access to one service — was shown
	// "TOTAL SECRETS 0 … Create your first secret to get started" while reading five
	// of them. That is worse than an error: it is confidently wrong, and it invites
	// an action that will fail. Authorship is not readability and was never what this
	// tile claimed to show.
	//
	// A caller with audit.read still gets the DEPLOYMENT-wide total instead, further
	// down (fetchAdminDashboardStats) — unchanged.
	total, exact, err := c.CountReadableSecrets(ctx, userID, principalID)
	switch {
	case err != nil:
		total = 0
		stats.degrade("total_secrets", err)
	case !exact:
		// The listing hit its per-scope bound, so `total` is a floor. Degrade rather
		// than show it as a count: a number that is quietly short is the same defect
		// this tile was fixed for, just smaller. Degraded is exactly the signal for
		// "treat this as incomplete".
		stats.degrade("total_secrets", errUnexactReadableSecretCount)
	}

	outgoing, err := c.storage.ListSharesByOwner(ctx, userID, c.shareEffectiveNow())
	sharedSecrets := 0
	if err == nil {
		sharedSecrets, err = c.countSharesVisibleToPAT(ctx, outgoing)
	}
	if err != nil {
		stats.degrade("shared_secrets", err)
	}

	incoming, err := c.storage.ListSharesByUser(ctx, userID, c.shareEffectiveNow())
	sharedWithMe := 0
	if err == nil {
		sharedWithMe, err = c.countSharesVisibleToPAT(ctx, incoming)
	}
	if err != nil {
		stats.degrade("shared_with_me", err)
	}

	// GetDashboardStats is reachable by any caller holding at least the universal
	// system_viewer baseline (system.read is enforced in the router) — every regular
	// user's own home dashboard. Only a genuinely elevated caller (audit.read:
	// system_admin/system_auditor) may see the DEPLOYMENT-WIDE aggregates mixed into
	// this same payload (active-user count, audit-event counts, failed-auth count,
	// inactive-user count): a zero-project-membership baseline account has no
	// legitimate route to org-wide numbers otherwise (#272). Recent activity gets the
	// same treatment, scoped to the caller's own events when they lack audit.read, so
	// the dashboard never leaks secret names/actions from projects the caller can't
	// read.
	hasAuditRead, _ := c.AuthorizePrincipal(ctx, actorTypeFromContext(ctx), principalID, "audit.read", Scope{})

	var events []*models.AuditEvent
	if hasAuditRead {
		// audit.read (honoured through AuthorizePrincipal, so a restricted PAT has it
		// only at global scope) authorizes the deployment-wide log, as on GET /audit.
		events, _, err = c.storage.GetAuditLogs(ctx, &storage.AuditFilter{Page: 1, PageSize: dashboardRecentActivity, Count: storage.AuditCountNone})
	} else {
		events, err = c.ownRecentActivity(ctx, userID)
	}
	if err != nil {
		stats.degrade("recent_activity", err)
	}
	recent := c.activityItems(ctx, events)

	expiringSecrets, err := c.getExpiringSecrets(ctx, username)
	if err != nil {
		stats.degrade("expiring_secrets", err)
	}

	var activeUsers, auditCount, auditLogins, auditSecretReads, failedAuth24h, inactiveUsers, deploymentTotalSecrets int64
	if hasAuditRead {
		activeUsers, auditCount, auditLogins, auditSecretReads, failedAuth24h, inactiveUsers, deploymentTotalSecrets = c.fetchAdminDashboardStats(ctx, stats)
		// Mirror ActiveUsers/AuditEvents: a caller with audit.read sees the
		// deployment-wide secret count, not just secrets they personally created.
		total = deploymentTotalSecrets
	}

	stats.TotalSecrets = total
	stats.SharedSecrets = sharedSecrets
	stats.SecretsSharedWithMe = sharedWithMe
	stats.ActiveUsers = activeUsers
	stats.AuditEvents30d = auditCount
	stats.AuditLogins30d = auditLogins
	stats.AuditSecretReads30d = auditSecretReads
	stats.FailedAuthAttempts24h = failedAuth24h
	stats.InactiveUsers = inactiveUsers
	stats.RecentActivity = recent
	stats.ExpiringSecrets = expiringSecrets

	if hasAuditRead {
		c.saveDeploymentSnapshot(ctx, stats)
	}
	// The per-user snapshot is the user's trend baseline. A restricted PAT's numbers
	// describe only its restriction, so saving them would skew the user's own trend.
	// It still reads the baseline for its trend arrows.
	c.saveUserSnapshot(ctx, userID, stats, total, sharedSecrets, sharedWithMe, patRestrictionFromContext(ctx) == nil)

	return stats, nil
}

// saveDeploymentSnapshot persists today's admin-level stats and back-fills trend fields.
func (c *KeyorixCore) saveDeploymentSnapshot(ctx context.Context, stats *DashboardStats) {
	todayDate := time.Now().UTC().Truncate(24 * time.Hour)
	prevSnap, snapErr := c.storage.GetPreviousDeploymentStatsSnapshot(ctx)
	if snapErr != nil {
		return // best-effort; tolerate failure
	}
	newSnap := &models.DeploymentStatsSnapshot{
		ActiveUsers:           stats.ActiveUsers,
		AuditEvents30d:        stats.AuditEvents30d,
		AuditLogins30d:        stats.AuditLogins30d,
		AuditSecretReads30d:   stats.AuditSecretReads30d,
		FailedAuthAttempts24h: stats.FailedAuthAttempts24h,
		InactiveUsers:         stats.InactiveUsers,
		SnapshotDate:          todayDate,
	}
	_ = c.storage.SaveDeploymentStatsSnapshot(ctx, newSnap)
	if prevSnap != nil {
		stats.PrevActiveUsers = &prevSnap.ActiveUsers
		stats.ActiveUsersTrend = computeTrend(float64(prevSnap.ActiveUsers), float64(stats.ActiveUsers))
		stats.PrevAuditEvents30d = &prevSnap.AuditEvents30d
		stats.AuditEvents30dTrend = computeTrend(float64(prevSnap.AuditEvents30d), float64(stats.AuditEvents30d))
		stats.PrevAuditLogins30d = &prevSnap.AuditLogins30d
		stats.AuditLogins30dTrend = computeTrend(float64(prevSnap.AuditLogins30d), float64(stats.AuditLogins30d))
		stats.PrevAuditSecretReads30d = &prevSnap.AuditSecretReads30d
		stats.AuditSecretReads30dTrend = computeTrend(float64(prevSnap.AuditSecretReads30d), float64(stats.AuditSecretReads30d))
		stats.PrevFailedAuthAttempts24h = &prevSnap.FailedAuthAttempts24h
		stats.FailedAuthAttempts24hTrend = computeTrend(float64(prevSnap.FailedAuthAttempts24h), float64(stats.FailedAuthAttempts24h))
		stats.PrevInactiveUsers = &prevSnap.InactiveUsers
		stats.InactiveUsersTrend = computeTrend(float64(prevSnap.InactiveUsers), float64(stats.InactiveUsers))
	}
}

// saveUserSnapshot persists per-user stats and back-fills trend fields.
func (c *KeyorixCore) saveUserSnapshot(ctx context.Context, userID uint, stats *DashboardStats, total int64, sharedSecrets, sharedWithMe int, persist bool) {
	prev, err := c.storage.GetPreviousStatsSnapshot(ctx, userID)
	if err == nil && prev != nil {
		stats.TotalSecretsTrend = computeTrend(float64(prev.TotalSecrets), float64(total))
		stats.SharedSecretsTrend = computeTrend(float64(prev.SharedSecrets), float64(sharedSecrets))
		stats.SharedWithMeTrend = computeTrend(float64(prev.SecretsSharedWithMe), float64(sharedWithMe))
		stats.PrevTotalSecrets = &prev.TotalSecrets
	}
	if !persist {
		return
	}
	today := time.Now().UTC().Truncate(24 * time.Hour)
	existing, _ := c.storage.GetPreviousStatsSnapshot(ctx, userID)
	if existing == nil || existing.SnapshotDate.Before(today) {
		_ = c.storage.SaveStatsSnapshot(ctx, &models.StatsSnapshot{
			UserID:              userID,
			TotalSecrets:        total,
			SharedSecrets:       sharedSecrets,
			SecretsSharedWithMe: sharedWithMe,
			SnapshotDate:        today,
		})
	}
}

// fetchAdminDashboardStats fetches the deployment-wide aggregates visible only to
// callers holding audit.read (active-user count, audit-event counts, failed-auth
// count, inactive-user count). Errors degrade the stats struct; all counts default
// to 0. Extracted from GetDashboardStats to reduce its cognitive complexity.
func (c *KeyorixCore) fetchAdminDashboardStats(ctx context.Context, stats *DashboardStats) (activeUsers, auditCount, auditLogins, auditSecretReads, failedAuth24h, inactiveUsers, totalSecrets int64) {
	if storageStats, err := c.storage.GetStats(ctx); err == nil {
		activeUsers = storageStats.TotalUsers
		totalSecrets = storageStats.TotalSecrets
	} else {
		stats.degrade("active_users", err)
	}
	thirtyDaysAgo := time.Now().UTC().Add(-30 * 24 * time.Hour)
	var auditErr error
	_, auditCount, auditErr = c.storage.GetAuditLogs(ctx, &storage.AuditFilter{StartTime: &thirtyDaysAgo, Page: 1, PageSize: 1})
	if auditErr != nil {
		stats.degrade("audit_count", auditErr)
	}
	authAction := "auth.login"
	_, auditLogins, auditErr = c.storage.GetAuditLogs(ctx, &storage.AuditFilter{StartTime: &thirtyDaysAgo, Action: &authAction, Page: 1, PageSize: 1})
	if auditErr != nil {
		stats.degrade("audit_logins", auditErr)
	}
	secretReadAction := "secret.read"
	// Success: a refused read is a secret.read with success=false (#3273), not a read.
	readSucceeded := true
	_, auditSecretReads, auditErr = c.storage.GetAuditLogs(ctx, &storage.AuditFilter{StartTime: &thirtyDaysAgo, Action: &secretReadAction, Success: &readSucceeded, Page: 1, PageSize: 1})
	if auditErr != nil {
		stats.degrade("audit_secret_reads", auditErr)
	}
	twentyFourHoursAgo := time.Now().UTC().Add(-24 * time.Hour)
	successFalse := false
	// Failed logins and refused secret reads are counted apart: since #3274 a refused
	// read is an audit event with success=false, so counting every success=false event
	// as a "failed auth attempt" mixed authorization refusals into the brute-force signal.
	failedLoginAction := "auth.login_failed"
	_, failedAuth24h, auditErr = c.storage.GetAuditLogs(ctx, &storage.AuditFilter{StartTime: &twentyFourHoursAgo, Action: &failedLoginAction, Success: &successFalse, Page: 1, PageSize: 1})
	if auditErr != nil {
		stats.degrade("failed_logins_24h", auditErr)
	}
	_, stats.RefusedSecretReads24h, auditErr = c.storage.GetAuditLogs(ctx, &storage.AuditFilter{StartTime: &twentyFourHoursAgo, Action: &secretReadAction, Success: &successFalse, Page: 1, PageSize: 1})
	if auditErr != nil {
		stats.degrade("refused_secret_reads_24h", auditErr)
	}
	inactiveCutoff := thirtyDaysAgo
	_, inactiveUsers, auditErr = c.storage.ListUsers(ctx, &storage.UserFilter{InactiveSince: &inactiveCutoff, Page: 1, PageSize: 1})
	if auditErr != nil {
		stats.degrade("inactive_users", auditErr)
	}
	return
}

// GetActivityFeed returns a paginated, deployment-wide activity feed. userID is
// unused here (kept for signature symmetry with GetDashboardStats/call sites): the
// router's audit.read gate on GET /dashboard/activity is what authorizes seeing
// every user's events, so this function itself applies no per-caller scoping.
func (c *KeyorixCore) GetActivityFeed(ctx context.Context, userID uint, username string, page, pageSize int) (*ActivityFeed, error) {
	_ = userID
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 10
	}

	events, total, err := c.storage.GetAuditLogs(ctx, &storage.AuditFilter{
		Page:     page,
		PageSize: pageSize,
	})
	if err != nil {
		return &ActivityFeed{Items: []ActivityItem{}, Total: 0, Page: page, PageSize: pageSize}, nil
	}

	items := c.activityItems(ctx, events)

	return &ActivityFeed{Items: items, Total: total, Page: page, PageSize: pageSize}, nil
}

// getExpiringSecrets returns secrets expiring within 30 days OR already expired,
// sorted by expiration ascending (expired first, then soonest-expiring). The
// returned error (non-nil only when a page fails to load) signals that the
// result may be truncated — the caller (#394) must surface this as a degraded
// snapshot rather than silently treating a partial (or empty) list as complete.
func (c *KeyorixCore) getExpiringSecrets(ctx context.Context, username string) ([]ExpiringSecret, error) { // NOSONAR -- cognitive complexity 17, suppress go:S3776
	now := time.Now().UTC()
	cutoff := now.Add(30 * 24 * time.Hour)

	// Build environment name lookup once
	envNames := map[uint]string{}
	if envs, err := c.storage.ListEnvironments(ctx); err == nil {
		for _, e := range envs {
			envNames[e.ID] = e.Name
		}
	}

	// Page through every matching secret — a user with many secrets must not have
	// an expiring one silently dropped from the dashboard warning. The expiration
	// filter (expiration < cutoff) keeps the matched set small and does the
	// expired/expiring selection in the query.
	const pageSize = 200
	var result []ExpiringSecret
	var pageErr error
	scanned := 0
	for page := 1; ; page++ {
		secrets, total, err := c.storage.ListSecrets(ctx, &storage.SecretFilter{
			CreatedBy:     &username,
			ExpiresBefore: &cutoff,
			Page:          page,
			PageSize:      pageSize,
		})
		if err != nil {
			pageErr = err
			break
		}
		scanned += len(secrets)
		for _, s := range secrets {
			if s.Expiration == nil {
				continue // defensive; the filter already excludes nulls
			}
			if !patAllowsSecretRead(ctx, s) {
				continue // names a secret outside the PAT restriction (PAT-GUARD-1)
			}
			exp := s.Expiration.UTC()
			envName := envNames[s.EnvironmentID]
			if envName == "" {
				envName = "unknown"
			}
			result = append(result, ExpiringSecret{
				ID:          s.ID,
				Name:        s.Name,
				Environment: envName,
				ExpiresAt:   exp,
				DaysLeft:    int(exp.Sub(now).Hours() / 24), // negative when expired
				Expired:     exp.Before(now),
			})
		}
		if len(secrets) < pageSize || int64(scanned) >= total {
			break
		}
	}

	// Sort: expired first (most overdue first), then soonest-expiring
	sort.Slice(result, func(i, j int) bool {
		return result[i].ExpiresAt.Before(result[j].ExpiresAt)
	})

	return result, pageErr
}

// computeTrend calculates percentage change between previous and current values.
func computeTrend(prev, current float64) *StatTrend {
	if prev == 0 {
		if current == 0 {
			return nil
		}
		return &StatTrend{Value: 100, IsPositive: true}
	}
	change := ((current - prev) / prev) * 100
	if change == 0 {
		return nil
	}
	return &StatTrend{
		Value:      math.Round(math.Abs(change)*10) / 10,
		IsPositive: change > 0,
	}
}

// mapAuditEventToActivity maps a raw audit event to an ActivityItem.
//
// Type mapping — what the frontend receives:
//
//	secret.read     → "accessed"
//	secret.versions_listed → "versions_listed" (a listing, not a value read)
//	secret.metadata_read → "metadata_read" (a by-name lookup, not a value read)
//	secret.created  → "created"
//	secret.updated  → "updated"
//	secret.deleted  → "deleted"
//	secret.rotated  → "rotated"
//	secret.shared   → "shared"
//	share.revoked   → "share_revoked"
//	auth.login      → "login"      (secretName intentionally empty)
//	auth.logout     → "logout"     (secretName intentionally empty)
//	auth.*          → "auth"       (secretName intentionally empty)
//	<other>         → raw EventType, secretName empty
//
// SecretName is extracted from the Description for secret/share events.
// Auth and system events are not secret-related so secretName is left empty.
func mapAuditEventToActivity(e *models.AuditEvent, actor string) ActivityItem {
	var eventType, secretName string

	switch e.EventType {
	// Secret events — extract secret name from description
	case "secret.read":
		if e.Success != nil && !*e.Success {
			// A refused read (#3273). No name from the description: a refusal
			// before authorization names only what the caller typed, and the row
			// carries no SecretNodeID then, so "not found" and "forbidden" look
			// the same in the caller's own activity.
			eventType = activityTypeReadRefused
			break
		}
		eventType = "accessed"
		secretName = extractSecretName(e.Description)
	case EventSecretVersionsListed:
		eventType = "versions_listed"
		secretName = extractSecretName(e.Description)
	case EventSecretMetadataRead:
		eventType = "metadata_read"
		secretName = extractSecretName(e.Description)
	case "secret.created":
		eventType = "created"
		secretName = extractSecretName(e.Description)
	case "secret.updated":
		eventType = "updated"
		secretName = extractSecretName(e.Description)
	case "secret.deleted":
		eventType = "deleted"
		secretName = extractSecretName(e.Description)
	case "secret.rotated":
		eventType = "rotated"
		secretName = extractSecretName(e.Description)
	case "secret.shared":
		eventType = "shared"
		secretName = extractSecretName(e.Description)
	case "share.revoked":
		eventType = "share_revoked"
		secretName = extractSecretName(e.Description)

	// Auth events — not secret-related, leave secretName empty
	case "auth.login":
		eventType = "login"
	case "auth.logout":
		eventType = "logout"
	case "auth.password_reset":
		eventType = "password_reset"

	// Fallback: pass event type through, no secret name
	default:
		eventType = e.EventType
	}

	if activityNameFromSubject[e.EventType] {
		secretName = "" // the description does not end in the secret's name; the feed looks it up
	}

	label := ActivityLabel(e.EventType)
	if eventType == activityTypeReadRefused {
		label = activityLabelReadRefused
	}
	return ActivityItem{
		ID:         e.ID,
		Type:       eventType,
		SecretName: secretName,
		Timestamp:  e.EventTime,
		Actor:      actor,
		EventType:  e.EventType,
		Label:      label,
	}
}

// activityTypeReadRefused / activityLabelReadRefused are the dashboard row of a
// refused secret read (secret.read, success=false, #3273), which must not read
// as "accessed secret".
const (
	activityTypeReadRefused  = "read_refused"
	activityLabelReadRefused = "was refused a secret read"
)

// activityItems maps audit events to dashboard rows. Each row names the
// principal that acted (system for events with no user), not the viewer, and
// carries the subject secret's name where the event has one. Both are display
// lookups; the audit rows are not touched.
func (c *KeyorixCore) activityItems(ctx context.Context, events []*models.AuditEvent) []ActivityItem { // nosemgrep: keyorix-unbounded-bulk-slice-param -- events is an already-paginated GetAuditLogs result (PageSize-bounded), not a raw client-supplied array; the only per-item work is in-memory mapping, the lookups are batched
	actors := c.ResolveUsernames(ctx, events)
	secretNames := c.activitySecretNames(ctx, events)
	items := make([]ActivityItem, 0, len(events))
	for _, e := range events {
		var uid uint
		if e.UserID != nil {
			uid = *e.UserID
		}
		item := mapAuditEventToActivity(e, actors[uid])
		if e.SecretNodeID != nil && (item.SecretName == "" || activityNameFromSubject[e.EventType]) {
			if name := secretNames[*e.SecretNodeID]; name != "" {
				item.SecretName = name
			}
		}
		items = append(items, item)
	}
	return items
}

// activityNameFromSubject lists event types whose description is not of the form
// "... secret <name>", so extractSecretName would return junk (or nothing); the
// name comes from the event's SecretNodeID instead.
var activityNameFromSubject = map[string]bool{
	"secret.restored":               true,
	"secret.dependency_added":       true,
	"secret.dependency_removed":     true,
	"secret.dependency_invalidated": true,
	"secret.dependency_restored":    true,
}

// activitySecretNames batch-resolves the secret names for the events that have a
// SecretNodeID. A secret that is gone (soft-deleted) simply has no entry.
func (c *KeyorixCore) activitySecretNames(ctx context.Context, events []*models.AuditEvent) map[uint]string { // nosemgrep: keyorix-unbounded-bulk-slice-param -- events is an already-paginated GetAuditLogs result (PageSize-bounded), not a raw client-supplied array; the lookup is one batched GetSecretsByIDs call, not a per-item round trip
	var ids []uint
	seen := map[uint]bool{}
	for _, e := range events {
		if e.SecretNodeID != nil && !seen[*e.SecretNodeID] {
			seen[*e.SecretNodeID] = true
			ids = append(ids, *e.SecretNodeID)
		}
	}
	names := map[uint]string{}
	if len(ids) == 0 {
		return names
	}
	secrets, err := c.storage.GetSecretsByIDs(ctx, ids)
	if err != nil {
		return names
	}
	for _, s := range secrets {
		names[s.ID] = s.Name
	}
	return names
}

// extractSecretName pulls the secret name from audit description strings.
// Descriptions follow the pattern: "User <actor> <verb> secret <name>"
// e.g. "User admin deleted secret test bulk 1" → "test bulk 1"
// Returns empty string if the pattern is not found.
func extractSecretName(description string) string {
	const marker = " secret "
	// A secret.deleted description ends in a soft-delete note (softDeleteNoteMarker)
	// that is not part of the name, and may itself contain " secret ".
	if i := strings.Index(description, softDeleteNoteMarker); i >= 0 {
		description = description[:i]
	}
	if idx := lastIndex(description, marker); idx >= 0 {
		return description[idx+len(marker):]
	}
	return ""
}

// lastIndex returns the index of the last occurrence of substr in s,
// or -1 if not present. Avoids importing strings package.
func lastIndex(s, substr string) int {
	if len(substr) == 0 {
		return len(s)
	}
	last := -1
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			last = i
		}
	}
	return last
}
