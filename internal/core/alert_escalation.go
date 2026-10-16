// alert_escalation.go — automatic escalation of unacknowledged anomaly alerts
// (ISO 27001 A.5.5 / NIS2 detection & response). When an AnomalyAlert exceeds
// the EscalateAfterMinutes threshold without being acknowledged, it is dispatched
// to the NotificationChannels listed in the matching AlertEscalationPolicy.
package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/netutil"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// severityOrder maps severity label to a numeric rank for comparison.
// low < medium < high < critical.
var severityOrder = map[string]int{
	"low":      0,
	"medium":   1,
	"high":     2,
	"critical": 3,
}

// severityAtLeast reports whether alertSeverity is at or above minSeverity.
func severityAtLeast(alertSeverity, minSeverity string) bool {
	aRank, aOK := severityOrder[alertSeverity]
	mRank, mOK := severityOrder[minSeverity]
	if !aOK || !mOK {
		return false
	}
	return aRank >= mRank
}

// EscalationResult summarises a single RunAlertEscalation pass.
type EscalationResult struct {
	Evaluated int // alerts checked
	Escalated int // alerts dispatched to at least one channel
	Skipped   int // already acknowledged or no matching policy
}

// activePolicies filters policies to those that are enabled with a positive delay.
func activePolicies(policies []models.AlertEscalationPolicy) []models.AlertEscalationPolicy {
	var active []models.AlertEscalationPolicy
	for _, p := range policies {
		if p.Enabled && p.EscalateAfterMinutes > 0 {
			active = append(active, p)
		}
	}
	return active
}

// minEscalateDelay returns the smallest EscalateAfterMinutes across active policies.
// Caller must ensure active is non-empty.
func minEscalateDelay(active []models.AlertEscalationPolicy) int {
	min := active[0].EscalateAfterMinutes
	for _, p := range active[1:] {
		if p.EscalateAfterMinutes < min {
			min = p.EscalateAfterMinutes
		}
	}
	return min
}

// dispatchPolicyChannels delivers an escalation to every enabled channel in policy.
// Returns true if at least one channel received the notification successfully.
func (c *KeyorixCore) dispatchPolicyChannels(ctx context.Context, alert *models.AnomalyAlert, policy *models.AlertEscalationPolicy) bool {
	sent := false
	for _, cidStr := range splitChannelIDs(policy.ChannelIDs) {
		cid64, err := strconv.ParseUint(cidStr, 10, strconv.IntSize)
		if err != nil {
			log.Printf("alert escalation: policy %d: invalid channel ID %q: %v", policy.ID, cidStr, err)
			continue
		}
		cid := uint(cid64) // safe: parsed with the platform's uint bit width
		// GetNotificationChannel (the core-layer wrapper), not c.storage.GetNotificationChannel
		// directly (#2433): the raw storage row's URL is encrypted (URLEnc/URLMeta) --
		// only the wrapper decrypts it into ch.URL, which dispatchToChannel below needs
		// to actually dial.
		ch, err := c.GetNotificationChannel(ctx, cid)
		if err != nil {
			log.Printf("alert escalation: policy %d: channel %d: %v", policy.ID, cid, err)
			continue
		}
		if !ch.Enabled {
			continue
		}
		if derr := c.dispatchToChannel(ctx, ch, alert, policy); derr != nil {
			log.Printf("alert escalation: policy %d: channel %d: dispatch failed: %v", policy.ID, cid, derr)
		} else {
			sent = true
		}
	}
	return sent
}

// escalateAlert checks alert against every active policy and dispatches to matching channels.
// Returns true if alert was dispatched to at least one channel.
func (c *KeyorixCore) escalateAlert(ctx context.Context, alert *models.AnomalyAlert, active []models.AlertEscalationPolicy, age time.Duration) bool {
	dispatched := false
	for _, policy := range active {
		if age < time.Duration(policy.EscalateAfterMinutes)*time.Minute {
			continue
		}
		if !severityAtLeast(alert.Severity, policy.MinSeverity) {
			continue
		}
		if c.dispatchPolicyChannels(ctx, alert, &policy) {
			dispatched = true
		}
	}
	return dispatched
}

// RunAlertEscalation scans unacknowledged AnomalyAlerts, matches them against
// enabled AlertEscalationPolicies, and delivers to configured NotificationChannels.
// It is safe to call repeatedly (idempotent at the delivery layer; each call
// re-dispatches matching alerts — no "escalated" flag is set on the alert row).
func (c *KeyorixCore) RunAlertEscalation(ctx context.Context) (*EscalationResult, error) {
	policies, err := c.storage.ListAlertEscalationPolicies(ctx)
	if err != nil {
		return nil, fmt.Errorf("alert escalation: list policies: %w", err)
	}

	active := activePolicies(policies)
	if len(active) == 0 {
		auditCtx, userID := adminJobAuditContext(ctx)
		c.writeAuditEvent(auditCtx, "admin_job.run_alert_escalation_run", userID, nil,
			"run-alert-escalation job ran: 0 active escalation policies")
		return &EscalationResult{}, nil
	}

	// Determine the earliest threshold: the minimum EscalateAfterMinutes across all
	// active policies. Any alert older than that threshold is a candidate for at least
	// one policy.
	minDelay := minEscalateDelay(active)
	threshold := c.now().Add(-time.Duration(minDelay) * time.Minute)

	alerts, err := c.storage.ListUnacknowledgedAnomalyAlertsBefore(ctx, threshold)
	if err != nil {
		return nil, fmt.Errorf("alert escalation: list alerts: %w", err)
	}

	result := &EscalationResult{Evaluated: len(alerts)}
	for _, alert := range alerts {
		age := c.now().Sub(alert.DetectedAt)
		if c.escalateAlert(ctx, &alert, active, age) {
			result.Escalated++
		} else {
			result.Skipped++
		}
	}
	// Alerts evaluated but with no matching policy also count as skipped.
	// (result.Evaluated already covers them; Skipped + Escalated should equal
	// the number of candidates returned by the store query.)
	// Written unconditionally: this job otherwise leaves no audit trail at all
	// of its own (F4, audit-completeness campaign) -- per-channel dispatch
	// failures are logged, not audited, and a run with zero candidate alerts
	// would leave no trace it ran.
	auditCtx, userID := adminJobAuditContext(ctx)
	c.writeAuditEvent(auditCtx, "admin_job.run_alert_escalation_run", userID, nil,
		fmt.Sprintf("run-alert-escalation job ran: %d evaluated, %d escalated, %d skipped",
			result.Evaluated, result.Escalated, result.Skipped))
	return result, nil
}

// splitChannelIDs splits a comma-separated channel-ID string into trimmed, non-empty tokens.
func splitChannelIDs(ids string) []string {
	var out []string
	for s := range strings.SplitSeq(ids, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// dispatchToChannel delivers an escalation notification to a single
// NotificationChannel. For webhook and slack types it performs an HTTP POST with
// a JSON payload; for other types (email, teams) it logs — full delivery
// integration for those types is left to the existing NotificationSink pipeline.
func (c *KeyorixCore) dispatchToChannel(ctx context.Context, ch *models.NotificationChannel, alert *models.AnomalyAlert, policy *models.AlertEscalationPolicy) error {
	switch ch.Type {
	case "webhook", "slack":
		// accessed_by and ip_address are intentionally omitted: PII must not be
		// forwarded to an external webhook receiver. The server-side audit log
		// already captures this data for incident investigation.
		//
		// #G30: several alert types (new_ip, new_user, ml_outlier,
		// principal_breadth) embed the SAME accessed_by/IP values as free text
		// in Description, which used to bypass the redaction above — scrub any
		// occurrence of this alert's own accessed_by/IP before it leaves too.
		return c.postJSONToURL(ctx, ch.URL, map[string]any{
			"event":       "anomaly.escalated",
			"alert_id":    alert.ID,
			"severity":    alert.Severity,
			"alert_type":  alert.AlertType,
			"description": redactAlertDescription(alert),
			"secret_name": alert.SecretName,
			"detected_at": alert.DetectedAt.Format(time.RFC3339),
			"policy_name": policy.Name,
			"channel":     ch.Name,
		})
	default:
		// email / teams: log and treat as delivered (best-effort for non-webhook types)
		log.Printf("alert escalation: channel %q (type=%s): escalation for alert %d logged (full delivery via notification sink)", ch.Name, ch.Type, alert.ID)
		return nil
	}
}

// redactAlertDescription strips any occurrence of the alert's own AccessedBy/
// IPAddress from its free-text Description before it leaves the deployment via
// an external webhook/Slack payload. Several alert types (new_ip, new_user,
// ml_outlier, principal_breadth) embed these exact values as free text, which
// would otherwise carry the same PII the structured accessed_by/ip_address
// fields are deliberately omitted for on this path.
func redactAlertDescription(alert *models.AnomalyAlert) string {
	desc := alert.Description
	if alert.AccessedBy != "" {
		desc = strings.ReplaceAll(desc, alert.AccessedBy, "[redacted]")
	}
	if alert.IPAddress != "" {
		desc = strings.ReplaceAll(desc, alert.IPAddress, "[redacted]")
	}
	return desc
}

// noEscalationRedirect refuses all HTTP redirects from webhook endpoints. An
// attacker-controlled endpoint cannot bounce the POST to an internal host (e.g.
// cloud IMDS at 169.254.169.254) via a 3xx response (SSRF-004).
func noEscalationRedirect(_ *http.Request, _ []*http.Request) error {
	return fmt.Errorf("alert escalation: redirect refused (SSRF prevention)")
}

// escalationTransport dial-time-validates every webhook/Slack escalation POST
// against the same disallow policy (isChannelDisallowedIP) validateWebhookURL
// applies once at NotificationChannel create/update time.
//
// G48: ch.URL is validated ONLY when the channel is created or updated
// (validateWebhookURL in notification_channels.go); postJSONToURL below is
// called on every escalation, reusing a fresh (or injected) *http.Client each
// time whose dial performs its own independent DNS resolution. A DNS-
// rebinding attacker (a name that resolves to a public IP when the channel is
// saved, then to a private/link-local address by the time an alert escalates)
// would otherwise bypass that one-time check entirely. Resolving and
// re-validating on every dial — then connecting to the specific IP just
// checked, never the hostname again — closes that gap.
var escalationTransport = &http.Transport{DialContext: (&netutil.Dialer{
	Disallow: isChannelDisallowedIP,
	// Reuse the SAME overridable resolver validateWebhookURL uses at channel
	// create/update time (channelLookupIPAddr, notification_channels.go)
	// rather than netutil's real-DNS default, so a DNS-rebind between channel
	// save and alert escalation is directly testable end-to-end through the
	// identical seam.
	Resolve: func(ctx context.Context, host string) ([]net.IPAddr, error) { return channelLookupIPAddr(ctx, host) },
}).DialContext}

// postJSONToURL marshals payload to JSON and sends a best-effort HTTP POST to rawURL.
func (c *KeyorixCore) postJSONToURL(_ context.Context, rawURL string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}
	client := c.httpClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second, Transport: escalationTransport, CheckRedirect: noEscalationRedirect}
	}
	// Compute a redacted form of the URL for use in error messages so that
	// embedded credentials (e.g. https://token:secret@hooks.example.com) are
	// never written to logs (CWE-312).
	redactedURL := rawURL
	if u, perr := url.Parse(rawURL); perr == nil {
		redactedURL = u.Redacted()
	}
	// Send-time re-validation (#1209): the create/update-time check can be stale
	// and c.httpClient may not carry the dial-time guard.
	if verr := validateWebhookSendTimeURL(rawURL); verr != nil {
		return fmt.Errorf("POST %s: refused: %w", redactedURL, verr)
	}
	resp, err := client.Post(rawURL, "application/json", bytes.NewReader(body)) // #nosec G107 -- URL is operator-configured; SSRF-guarded at write time
	if err != nil {
		return fmt.Errorf("POST %s: %w", redactedURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("POST %s: unexpected status %d", redactedURL, resp.StatusCode)
	}
	return nil
}

// --- CRUD for AlertEscalationPolicy ---

// Alert-escalation-policy audit event types (F4, audit-completeness
// campaign) -- same convention as notification_channels.go's
// EventNotificationChannelCreated/Updated/Deleted, its sibling feature in the
// same alerting-config domain. CreateAlertEscalationPolicy/
// UpdateAlertEscalationPolicy/DeleteAlertEscalationPolicy take no actor
// parameter (many pre-existing tests construct them directly with no caller
// identity in scope), so these are standalone methods the REST handler calls
// explicitly once it has the actor -- same reasoning as LogRoleCreated/
// LogRoleUpdated/LogRoleDeleted (audit.go).
const (
	EventAlertEscalationPolicyCreated = "alert_escalation_policy.created"
	EventAlertEscalationPolicyUpdated = "alert_escalation_policy.updated"
	EventAlertEscalationPolicyDeleted = "alert_escalation_policy.deleted"
)

// alertEscalationPolicyAuditView is the audit-safe projection of an
// AlertEscalationPolicy (coordinator review, PR #2249): ChannelIDs names the
// specific NotificationChannels this policy dispatches to, which can be
// webhook/Slack/Teams endpoints whose URL embeds a secret token
// (dispatchToChannel/postJSONToURL above); logging the raw struct as the
// audit before/after state -- as writeConfigChangeAuditEvent's callers
// otherwise do verbatim -- would let a policy's wiring topology, and via
// cross-reference with a channel's own audit trail its target, leak into
// audit rows, SIEM exports, and evidence packs. Every other field is safe
// (no secrets), so this allowlists them and reports only a channel COUNT in
// place of the raw ChannelIDs.
type alertEscalationPolicyAuditView struct {
	ID                   uint   `json:"id"`
	Name                 string `json:"name"`
	MinSeverity          string `json:"min_severity"`
	EscalateAfterMinutes int    `json:"escalate_after_minutes"`
	ChannelCount         int    `json:"channel_count"`
	Enabled              bool   `json:"enabled"`
}

func newAlertEscalationPolicyAuditView(p *models.AlertEscalationPolicy) alertEscalationPolicyAuditView {
	return alertEscalationPolicyAuditView{
		ID:                   p.ID,
		Name:                 p.Name,
		MinSeverity:          p.MinSeverity,
		EscalateAfterMinutes: p.EscalateAfterMinutes,
		ChannelCount:         len(splitChannelIDs(p.ChannelIDs)),
		Enabled:              p.Enabled,
	}
}

func (c *KeyorixCore) LogAlertEscalationPolicyCreated(ctx context.Context, actorID uint, p *models.AlertEscalationPolicy) {
	c.writeConfigChangeAuditEvent(ctx, EventAlertEscalationPolicyCreated, actorID,
		fmt.Sprintf("alert escalation policy %d (%q) created", p.ID, p.Name), nil, newAlertEscalationPolicyAuditView(p))
}

// LogAlertEscalationPolicyUpdated audits an update. before is the policy's
// state as read prior to the mutation (coordinator review, PR #2249: the
// prior version of this function hardcoded a nil before, losing the diff
// entirely) -- the caller must fetch it before calling
// UpdateAlertEscalationPolicy, since that call mutates the row in place.
func (c *KeyorixCore) LogAlertEscalationPolicyUpdated(ctx context.Context, actorID uint, before, after *models.AlertEscalationPolicy) {
	var beforeView any
	if before != nil {
		beforeView = newAlertEscalationPolicyAuditView(before)
	}
	c.writeConfigChangeAuditEvent(ctx, EventAlertEscalationPolicyUpdated, actorID,
		fmt.Sprintf("alert escalation policy %d (%q) updated", after.ID, after.Name), beforeView, newAlertEscalationPolicyAuditView(after))
}

func (c *KeyorixCore) LogAlertEscalationPolicyDeleted(ctx context.Context, actorID, policyID uint) {
	c.writeAuditEvent(ctx, EventAlertEscalationPolicyDeleted, actorPtr(actorID), nil,
		fmt.Sprintf("alert escalation policy %d deleted", policyID))
}

// CreateAlertEscalationPolicy validates and persists a new escalation policy.
func (c *KeyorixCore) CreateAlertEscalationPolicy(ctx context.Context, p *models.AlertEscalationPolicy) (*models.AlertEscalationPolicy, error) {
	if err := validateEscalationPolicy(p); err != nil {
		return nil, err
	}
	now := c.now().UTC()
	p.CreatedAt = now
	p.UpdatedAt = now
	if err := c.storage.CreateAlertEscalationPolicy(ctx, p); err != nil {
		return nil, err
	}
	return p, nil
}

// GetAlertEscalationPolicy returns the policy with the given id.
func (c *KeyorixCore) GetAlertEscalationPolicy(ctx context.Context, id uint) (*models.AlertEscalationPolicy, error) {
	return c.storage.GetAlertEscalationPolicy(ctx, id)
}

// ListAlertEscalationPolicies returns all escalation policies.
func (c *KeyorixCore) ListAlertEscalationPolicies(ctx context.Context) ([]models.AlertEscalationPolicy, error) {
	return c.storage.ListAlertEscalationPolicies(ctx)
}

// UpdateAlertEscalationPolicy applies field updates to the policy identified by id.
func (c *KeyorixCore) UpdateAlertEscalationPolicy(ctx context.Context, id uint, updates map[string]any) (*models.AlertEscalationPolicy, error) {
	p, err := c.storage.GetAlertEscalationPolicy(ctx, id)
	if err != nil {
		return nil, err
	}
	if v, ok := updates["name"].(string); ok && v != "" {
		p.Name = v
	}
	if v, ok := updates["min_severity"].(string); ok && v != "" {
		p.MinSeverity = v
	}
	if v, ok := updates["escalate_after_minutes"].(float64); ok {
		p.EscalateAfterMinutes = int(v)
	}
	if v, ok := updates["channel_ids"].(string); ok {
		p.ChannelIDs = v
	}
	if v, ok := updates["enabled"].(bool); ok {
		p.Enabled = v
	}
	if err := validateEscalationPolicy(p); err != nil {
		return nil, err
	}
	p.UpdatedAt = c.now().UTC()
	if err := c.storage.UpdateAlertEscalationPolicy(ctx, p); err != nil {
		return nil, err
	}
	return p, nil
}

// DeleteAlertEscalationPolicy permanently removes the policy with the given id.
func (c *KeyorixCore) DeleteAlertEscalationPolicy(ctx context.Context, id uint) error {
	return c.storage.DeleteAlertEscalationPolicy(ctx, id)
}

// validateEscalationPolicy enforces invariants for create and update paths.
func validateEscalationPolicy(p *models.AlertEscalationPolicy) error {
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("alert escalation policy name is required")
	}
	if _, ok := severityOrder[p.MinSeverity]; !ok {
		return fmt.Errorf("invalid min_severity %q: must be one of low, medium, high, critical", p.MinSeverity)
	}
	if p.EscalateAfterMinutes <= 0 {
		return fmt.Errorf("escalate_after_minutes must be a positive integer")
	}
	return nil
}
