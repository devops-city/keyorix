//go:build e2e

package e2e

import (
	"fmt"
	"time"
)

// groupNotifications exercises list + read-all (safe/idempotent regardless
// of whether any notification exists yet) and, if this run's earlier
// actions (secret-access-request, share, invitation) generated any, the
// per-id mark-read route too.
func groupNotifications(ctx *smokeCtx) {
	c := ctx.c
	listResp := c.callExpect("GET", "GET /api/v1/notifications", "/api/v1/notifications", nil, 200)
	var list struct {
		Notifications []idOnly `json:"notifications"`
	}
	c.unmarshalData(listResp, &list, "list notifications")
	if len(list.Notifications) > 0 {
		c.callExpect("POST", "POST /api/v1/notifications/{id}/read",
			fmt.Sprintf("/api/v1/notifications/%d/read", list.Notifications[0].ID), nil, 200)
	} else {
		ctx.c.skip("POST /api/v1/notifications/{id}/read")
	}
	c.callExpect("POST", "POST /api/v1/notifications/read-all", "/api/v1/notifications/read-all", nil, 200)
}

// groupNotificationChannels exercises create/list/get/update/delete for a
// webhook channel (no real delivery attempted -- creating and configuring a
// channel persists rows and validates config without ever dispatching to
// the URL) plus its retry-policy sub-resource.
func groupNotificationChannels(ctx *smokeCtx) {
	c := ctx.c
	created := c.callExpect("POST", "POST /api/v1/notification-channels", "/api/v1/notification-channels", map[string]interface{}{
		"name": "e2e-smoke-channel", "type": "webhook", "url": "https://www.example.com/e2e-smoke-webhook",
		"events": "secret.created",
	}, 200, 201)
	var ch idOnly
	c.unmarshalData(created, &ch, "create notification channel")
	nc := fmt.Sprintf("/api/v1/notification-channels/%d", ch.ID)

	c.callExpect("GET", "GET /api/v1/notification-channels", "/api/v1/notification-channels", nil, 200)
	c.callExpect("GET", "GET /api/v1/notification-channels/{id}", nc, nil, 200)
	c.callExpect("PUT", "PUT /api/v1/notification-channels/{id}", nc, map[string]interface{}{
		"name": "e2e-smoke-channel", "type": "webhook", "url": "https://www.example.com/e2e-smoke-webhook-2",
		"events": "secret.created",
	}, 200)
	c.callExpect("GET", "GET /api/v1/notification-channels/{id}/retry-policy", nc+"/retry-policy", nil, 200)
	c.callExpect("PUT", "PUT /api/v1/notification-channels/{id}/retry-policy", nc+"/retry-policy",
		map[string]interface{}{"max_retries": 3, "retry_backoff_ms": 1000}, 200)
	c.callExpect("DELETE", "DELETE /api/v1/notification-channels/{id}", nc, nil, 200, 204)
}

// groupAlertEscalationPolicies exercises create/list/get/update/delete for
// an escalation policy referencing no real channel IDs (channel_ids is a
// free-form string field per the handler's own contract -- an empty policy
// still persists and round-trips cleanly).
func groupAlertEscalationPolicies(ctx *smokeCtx) {
	c := ctx.c
	created := c.callExpect("POST", "POST /api/v1/alert-escalation-policies", "/api/v1/alert-escalation-policies", map[string]interface{}{
		"name": "e2e-smoke-escalation", "min_severity": "high", "escalate_after_minutes": 30, "channel_ids": "",
	}, 200, 201)
	var pol idOnly
	c.unmarshalData(created, &pol, "create alert escalation policy")
	ap := fmt.Sprintf("/api/v1/alert-escalation-policies/%d", pol.ID)

	c.callExpect("GET", "GET /api/v1/alert-escalation-policies", "/api/v1/alert-escalation-policies", nil, 200)
	c.callExpect("GET", "GET /api/v1/alert-escalation-policies/{id}", ap, nil, 200)
	c.callExpect("PUT", "PUT /api/v1/alert-escalation-policies/{id}", ap, map[string]interface{}{
		"name": "e2e-smoke-escalation", "min_severity": "critical", "escalate_after_minutes": 15, "channel_ids": "",
	}, 200)
	c.callExpect("DELETE", "DELETE /api/v1/alert-escalation-policies/{id}", ap, nil, 200, 204)
}

// groupAudit sweeps every read-only audit endpoint (this smoke run's own
// create/update/delete calls have already generated real audit events by
// this point) plus the two safe mutating ones (checkpoint, anomaly
// acknowledge-if-any). migrate-chain-encoding is a one-way, irreversible
// storage-format migration on the live chain -- skipped, see coverage.go.
func groupAudit(ctx *smokeCtx) {
	c := ctx.c
	c.callExpect("GET", "GET /api/v1/audit/logs", "/api/v1/audit/logs?page_size=10", nil, 200)
	c.callExpect("GET", "GET /api/v1/audit/rbac-logs", "/api/v1/audit/rbac-logs?page_size=10", nil, 200, 404)
	c.callExpect("GET", "GET /api/v1/audit/search", "/api/v1/audit/search?q=e2e-smoke", nil, 200, 400)
	c.callExpect("GET", "GET /api/v1/audit/retention", "/api/v1/audit/retention", nil, 200)
	c.callExpect("GET", "GET /api/v1/audit/verify", "/api/v1/audit/verify", nil, 200)
	// ?full=true (docs/specs/audit-incremental-verification.md): a background full
	// walk, 202 + a job id to poll; 200 = no signing key, the walk ran inline.
	full := c.callExpect("GET", "GET /api/v1/audit/verify", "/api/v1/audit/verify?full=true", nil, 202, 200)
	if full.StatusCode == 202 {
		var job struct {
			JobID  string `json:"job_id"`
			State  string `json:"state"`
			Result *struct {
				Status string `json:"status"`
			} `json:"result"`
		}
		c.unmarshalData(full, &job, "start full audit verification")
		id := job.JobID
		for deadline := time.Now().Add(60 * time.Second); ; {
			env := c.callExpect("GET", "GET /api/v1/audit/verify/jobs/{id}", "/api/v1/audit/verify/jobs/"+id, nil, 200)
			c.unmarshalData(env, &job, "audit verification job")
			if job.State != "running" || time.Now().After(deadline) {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		if job.State != "succeeded" || job.Result == nil || job.Result.Status != "valid" {
			c.t.Fatalf("full audit verification job %s: state=%q result=%+v", id, job.State, job.Result)
		}
	} else {
		c.skip("GET /api/v1/audit/verify/jobs/{id}")
	}
	c.callExpect("GET", "GET /api/v1/audit/export", "/api/v1/audit/export?page_size=10", nil, 200)
	c.callExpect("GET", "GET /api/v1/audit/export.csv", "/api/v1/audit/export.csv", nil, 200)
	c.callExpect("POST", "POST /api/v1/audit/checkpoint", "/api/v1/audit/checkpoint", nil, 200, 201)

	anomalies := c.callExpect("GET", "GET /api/v1/audit/anomalies", "/api/v1/audit/anomalies", nil, 200)
	var alerts struct {
		Alerts []idOnly `json:"alerts"`
	}
	c.unmarshalData(anomalies, &alerts, "list anomalies")
	if len(alerts.Alerts) > 0 {
		c.callExpect("POST", "POST /api/v1/audit/anomalies/{id}/acknowledge",
			fmt.Sprintf("/api/v1/audit/anomalies/%d/acknowledge", alerts.Alerts[0].ID), nil, 200)
	} else {
		c.skip("POST /api/v1/audit/anomalies/{id}/acknowledge")
	}
}

func groupDashboard(ctx *smokeCtx) {
	c := ctx.c
	c.callExpect("GET", "GET /api/v1/dashboard/stats", "/api/v1/dashboard/stats", nil, 200)
	c.callExpect("GET", "GET /api/v1/dashboard/activity", "/api/v1/dashboard/activity", nil, 200)
}

// groupSoD exercises the segregation-of-duties policy CRUD and the
// (necessarily empty on a fresh install) violations report.
func groupSoD(ctx *smokeCtx) {
	c := ctx.c
	created := c.callExpect("POST", "POST /api/v1/sod/policies", "/api/v1/sod/policies", map[string]string{
		"name": "e2e-smoke-sod-policy", "description": "SESSION-I smoke",
		"permission_a": "secrets.write", "permission_b": "secrets.delete",
	}, 200, 201)
	var envelope struct {
		Policy idOnly `json:"policy"`
	}
	c.unmarshalData(created, &envelope, "create sod policy")

	c.callExpect("GET", "GET /api/v1/sod/policies", "/api/v1/sod/policies", nil, 200)
	c.callExpect("GET", "GET /api/v1/sod/violations", "/api/v1/sod/violations", nil, 200)
	if envelope.Policy.ID != 0 {
		c.callExpect("DELETE", "DELETE /api/v1/sod/policies/{id}", fmt.Sprintf("/api/v1/sod/policies/%d", envelope.Policy.ID), nil, 200, 204)
	}
}

// groupCompliance sweeps every read-only compliance report endpoint;
// snapshots create is the one write in this group.
func groupCompliance(ctx *smokeCtx) {
	c := ctx.c
	reads := []string{
		"credential-trends", "posture", "rotation-by-backend", "controls",
		"controls.csv", "digest", "evidence", "permission-baseline",
		"permission-baseline.csv", "permission-changes", "snapshots",
	}
	for _, seg := range reads {
		c.call("GET", fmt.Sprintf("GET /api/v1/compliance/%s", seg), "/api/v1/compliance/"+seg, nil)
	}
	c.callExpect("POST", "POST /api/v1/compliance/snapshots", "/api/v1/compliance/snapshots", nil, 200, 201)
	c.callExpect("POST", "POST /api/v1/compliance/digest/send", "/api/v1/compliance/digest/send", nil, 200, 400)
	c.callExpect("POST", "POST /api/v1/compliance/evidence/verify", "/api/v1/compliance/evidence/verify",
		map[string]interface{}{}, 200, 400)
}

func groupLicense(ctx *smokeCtx) {
	ctx.c.callExpect("GET", "GET /api/v1/license/status", "/api/v1/license/status", nil, 200)
}
