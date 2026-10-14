// read_quota.go — quota-report handler for secrets approaching their MaxReads cap.
//
// Route (under /api/v1/secrets):
//
//	GET /quota-report — list of secrets with MaxReads set, showing usage %, status
package handlers

import (
	"net/http"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// QuotaReportRow is one entry in the GET /secrets/quota-report response.
type QuotaReportRow struct {
	SecretID   uint   `json:"secret_id"`
	SecretName string `json:"secret_name"`
	ReadCount  int    `json:"read_count"`
	MaxReads   int    `json:"max_reads"`
	UsagePct   int    `json:"usage_pct"`
	Status     string `json:"status"` // "ok" | "warning" | "critical" | "exhausted"
}

// GetQuotaReport handles GET /api/v1/secrets/quota-report — returns every live
// secret with MaxReads > 0 and its current usage percentage and status.
// Requires audit.read (enforced by the router) — it's a report-viewing
// endpoint (usage %/status metadata, no secret values), not secret-value
// access, so it belongs in the audit-report disclosure family, not
// secrets.read (G16).
func (h *SecretHandler) GetQuotaReport(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	secrets, err := h.coreService.ListSecretsWithQuota(r.Context())
	if err != nil {
		h.sendError(w, "InternalError", "Failed to fetch quota report", http.StatusInternalServerError, nil)
		return
	}

	rows := make([]QuotaReportRow, 0, len(secrets))
	for _, s := range secrets {
		// storage.ListSecretsWithQuota guarantees MaxReads IS NOT NULL AND > 0.
		pct := core.QuotaUsagePct(s.ReadCount, *s.MaxReads)
		status := quotaStatus(pct)
		rows = append(rows, QuotaReportRow{
			SecretID:   s.ID,
			SecretName: s.Name,
			ReadCount:  s.ReadCount,
			MaxReads:   *s.MaxReads,
			UsagePct:   pct,
			Status:     status,
		})
	}

	h.sendSuccess(w, map[string]any{"secrets": rows}, "")
}

// quotaStatus maps a usage percentage to a human-readable status label.
func quotaStatus(pct int) string {
	switch {
	case pct >= 100:
		return "exhausted"
	case pct >= 95:
		return "critical"
	case pct >= 80:
		return "warning"
	default:
		return "ok"
	}
}
