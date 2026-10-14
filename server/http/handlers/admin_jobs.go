// admin_jobs.go — on-demand triggers for the notification/alert jobs that
// otherwise only run on their background schedulers (anomaly alerting, rotation and
// expiry reminders, the compliance digest). After an incident or a config change an
// operator often needs to dispatch these immediately rather than wait for the next
// tick. All are deployment-wide admin actions; F1 (ADR-110 follow-up) split the
// router's gate per route — the pure notification/reminder triggers are gated on
// alerts.write, RunRoleExpiryCheck and RunReadQuotaCheck included (verified to only
// emit Notification rows, never revoke/block anything); RunAnomalyAlerts and
// RunComplianceDigest stay on system.write despite being notification-only, since
// either could be used to exfiltrate anomaly/compliance data via an operator-
// controlled notification channel; SuspendInactiveUsers, PurgeAuditLogsJob (in
// audit_retention_handler.go), and RecordHygieneSnapshot (in hygiene_trends.go)
// also stay on system.write, the account/data mutations. See router.go's
// /admin/jobs route group for the exact split.
package handlers

import (
	"log"
	"net/http"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// AdminJobsHandler exposes the scheduled jobs as manual triggers.
type AdminJobsHandler struct {
	coreService *core.KeyorixCore
}

// NewAdminJobsHandler creates a new AdminJobsHandler.
func NewAdminJobsHandler(coreService *core.KeyorixCore) *AdminJobsHandler {
	return &AdminJobsHandler{coreService: coreService}
}

// RunAnomalyAlerts handles POST /api/v1/admin/jobs/anomaly-alerts — broadcast alerts
// for any new (unalerted) anomaly findings now. Returns {alerted}.
func (h *AdminJobsHandler) RunAnomalyAlerts(w http.ResponseWriter, r *http.Request) {
	u := middleware.GetUserFromContext(r.Context())
	if u == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	n, err := h.coreService.AlertNewAnomalies(core.WithAuditActor(r.Context(), u.UserID))
	if err != nil {
		log.Printf("Error running anomaly alerts job: %v", err)
		sendError(w, "Error", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]any{"alerted": n}, "")
}

// RunRotationReminders handles POST /api/v1/admin/jobs/rotation-reminders — send
// rotation-due reminders now. Returns {sent}.
func (h *AdminJobsHandler) RunRotationReminders(w http.ResponseWriter, r *http.Request) {
	u := middleware.GetUserFromContext(r.Context())
	if u == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	n, err := h.coreService.SendRotationReminders(core.WithAuditActor(r.Context(), u.UserID))
	if err != nil {
		log.Printf("Error running rotation reminders job: %v", err)
		sendError(w, "Error", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]any{"sent": n}, "")
}

// RunExpiryReminders handles POST /api/v1/admin/jobs/expiry-reminders?lead_days=N —
// send expiry reminders for secrets expiring within the lead window (default 14 when
// lead_days is omitted or non-positive). Returns {sent}.
func (h *AdminJobsHandler) RunExpiryReminders(w http.ResponseWriter, r *http.Request) {
	u := middleware.GetUserFromContext(r.Context())
	if u == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	leadDays := 0 // core applies the default when <= 0
	if v := r.URL.Query().Get("lead_days"); v != "" {
		if d, perr := strconv.Atoi(v); perr == nil {
			leadDays = d
		}
	}
	n, err := h.coreService.SendExpiryReminders(core.WithAuditActor(r.Context(), u.UserID), leadDays)
	if err != nil {
		log.Printf("Error running expiry reminders job: %v", err)
		sendError(w, "Error", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]any{"sent": n}, "")
}

// RunComplianceDigest handles POST /api/v1/admin/jobs/compliance-digest — broadcast the
// compliance digest now. Returns {sent} (false when there were no recipients/changes).
func (h *AdminJobsHandler) RunComplianceDigest(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	sent, err := h.coreService.SendComplianceDigest(r.Context(), userCtx.UserID)
	if err != nil {
		log.Printf("Error running compliance digest job: %v", err)
		sendError(w, "Error", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]any{"sent": sent}, "")
}

// RunRoleExpiryCheck handles POST /api/v1/system/admin/jobs/role-expiry-check —
// scans all time-bound role grants and emits in-app notifications for those
// expiring within 7 days (warning) or 1 day (critical). Returns {warnings, criticals}.
// Requires system.write (enforced by the router).
func (h *AdminJobsHandler) RunRoleExpiryCheck(w http.ResponseWriter, r *http.Request) {
	u := middleware.GetUserFromContext(r.Context())
	if u == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	result, err := h.coreService.CheckRoleExpiry(core.WithAuditActor(r.Context(), u.UserID))
	if err != nil {
		log.Printf("Error running role-expiry-check job: %v", err)
		sendError(w, "Error", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]any{"warnings": result.Warnings, "criticals": result.Criticals}, "")
}

// RunReadQuotaCheck handles POST /api/v1/system/admin/jobs/check-read-quotas —
// scans all secrets with MaxReads > 0 and emits in-app notifications for those
// approaching or reaching their read limit. Returns {warnings, criticals, exhausted, checked}.
// Requires system.write (enforced by the router).
func (h *AdminJobsHandler) RunReadQuotaCheck(w http.ResponseWriter, r *http.Request) {
	u := middleware.GetUserFromContext(r.Context())
	if u == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	result, err := h.coreService.CheckReadQuotas(core.WithAuditActor(r.Context(), u.UserID))
	if err != nil {
		log.Printf("Error running check-read-quotas job: %v", err)
		sendError(w, "Error", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]any{
		"warnings":  result.Warnings,
		"criticals": result.Criticals,
		"exhausted": result.Exhausted,
		"checked":   result.Checked,
	}, "")
}

// RunTokenExpiryCheck handles POST /api/v1/system/admin/jobs/token-expiry-check —
// scans all PersonalAccessTokens and MachineIdentityCredentials and emits in-app
// notifications for those expiring within 7 days (warning) or 1 day (critical).
// Returns {pat_warnings, pat_criticals, machine_warnings, machine_criticals}.
// Requires system.write (enforced by the router).
func (h *AdminJobsHandler) RunTokenExpiryCheck(w http.ResponseWriter, r *http.Request) {
	u := middleware.GetUserFromContext(r.Context())
	if u == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	result, err := h.coreService.CheckTokenExpiry(core.WithAuditActor(r.Context(), u.UserID))
	if err != nil {
		log.Printf("Error running token-expiry-check job: %v", err)
		sendError(w, "Error", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]any{
		"pat_warnings":      result.PATWarnings,
		"pat_criticals":     result.PATCriticals,
		"machine_warnings":  result.MachineWarnings,
		"machine_criticals": result.MachineCriticals,
	}, "")
}
